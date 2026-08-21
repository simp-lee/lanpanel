//go:build linux

package control

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func RunPrivateProbe(args []string) error {
	if len(args) != 0 || os.Geteuid() == 0 || os.Getenv("LANPANEL_HEADSCALE_CANDIDATE") != "private-v1" || os.Getenv("LANPANEL_HEADSCALE_CONTROL_DOMAIN") == "" {
		return fmt.Errorf("headscale private probe requires its fixed non-root PID1 invocation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var last error
	for {
		last = probePrivateEndpoints(ctx, os.Getenv("LANPANEL_HEADSCALE_CONTROL_DOMAIN"))
		if last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.Join(last, ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func probePrivateEndpoints(ctx context.Context, controlDomain string) error {
	if err := probeHTTP(ctx, ControlBackend, "/health", controlDomain, false); err != nil {
		return err
	}
	if err := probeHTTP(ctx, MetricsBackend, "/metrics", "metrics.invalid", true); err != nil {
		return err
	}
	if err := probeAdminSocket(); err != nil {
		return err
	}
	return probeSTUN(ctx)
}

func probeAdminSocket() error {
	info, err := os.Lstat(FixedPaths().AdminSocket)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("headscale admin Unix socket metadata is unsafe")
	}
	stat, ok := info.Sys().(*unix.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) {
		return fmt.Errorf("headscale admin Unix socket owner changed")
	}
	address, err := net.ResolveUnixAddr("unix", FixedPaths().AdminSocket)
	if err != nil {
		return err
	}
	connection, err := net.DialUnix("unix", nil, address)
	if err != nil {
		return fmt.Errorf("headscale private admin endpoint: %w", err)
	}
	defer func(ignore func() error) { _ = ignore() }(connection.Close)
	raw, err := connection.SyscallConn()
	if err != nil {
		return err
	}
	var peer *unix.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) { peer, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return err
	}
	if socketErr != nil || peer == nil || peer.Pid <= 0 || peer.Uid != uint32(os.Geteuid()) || peer.Gid != uint32(os.Getegid()) {
		return fmt.Errorf("headscale admin Unix peer identity changed")
	}
	return nil
}

func probeHTTP(ctx context.Context, address, path, host string, allowBody bool) error {
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, ResponseHeaderTimeout: 3 * time.Second}
	defer transport.CloseIdleConnections()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+path, nil)
	request.Host = host
	response, err := transport.RoundTrip(request)
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(response.Body.Close)
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil || response.StatusCode != http.StatusOK || !allowBody && len(strings.TrimSpace(string(body))) > 4096 || allowBody && !strings.Contains(string(body), "#") {
		return fmt.Errorf("headscale private HTTP probe rejected endpoint %s", address)
	}
	return nil
}

func probeSTUN(ctx context.Context) error {
	transaction := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, transaction); err != nil {
		return err
	}
	packet := make([]byte, 20)
	binary.BigEndian.PutUint16(packet[0:2], 0x0001)
	binary.BigEndian.PutUint32(packet[4:8], 0x2112a442)
	copy(packet[8:], transaction)
	connection, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "udp", "127.0.0.1:3478")
	if err != nil {
		clear(transaction)
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(connection.Close)
	deadline, _ := ctx.Deadline()
	_ = connection.SetDeadline(deadline)
	if _, err := connection.Write(packet); err != nil {
		clear(transaction)
		return err
	}
	response := make([]byte, 2048)
	n, err := connection.Read(response)
	valid := err == nil && n >= 20 && binary.BigEndian.Uint32(response[4:8]) == 0x2112a442 && string(response[8:20]) == string(transaction) && (binary.BigEndian.Uint16(response[0:2]) == 0x0101 || binary.BigEndian.Uint16(response[0:2]) == 0x0111)
	clear(transaction)
	clear(packet)
	if !valid {
		return fmt.Errorf("headscale private STUN probe failed")
	}
	return nil
}
