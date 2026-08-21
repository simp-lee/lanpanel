//go:build linux

// Package relay implements the fixed same-binary per-resource Unix relay.
package relay

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const fixedBackend = "/backend/http.sock"

func Run(args []string) error {
	if len(args) != 0 || os.Geteuid() == 0 || os.Getenv("LANPANEL_RELAY_BACKEND") != fixedBackend || !validResourceID(os.Getenv("LANPANEL_RESOURCE_ID")) {
		return fmt.Errorf("relay requires its fixed non-root PID1 invocation")
	}
	if err := requireNoProc(); err != nil {
		return err
	}
	listeners, err := inheritedListeners()
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(listeners[0].Close)
	ctx, cancel := signalContext()
	defer cancel()
	for {
		if err := listeners[0].SetDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
			return err
		}
		connection, err := listeners[0].AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if value, ok := err.(net.Error); ok && value.Timeout() {
				continue
			}
			return err
		}
		go relayConnection(ctx, connection)
	}
}

func relayConnection(ctx context.Context, frontend *net.UnixConn) {
	defer func(ignore func() error) { _ = ignore() }(frontend.Close)
	var before unix.Stat_t
	if unix.Lstat(fixedBackend, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFSOCK || before.Uid == uint32(os.Geteuid()) || before.Mode&0o777 != 0o660 || before.Nlink != 1 {
		return
	}
	backend, err := (&net.Dialer{}).DialContext(ctx, "unix", fixedBackend)
	if err != nil {
		return
	}
	defer func(ignore func() error) { _ = ignore() }(backend.Close)
	var after unix.Stat_t
	if unix.Lstat(fixedBackend, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Ctim != after.Ctim {
		return
	}
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		_, _ = io.Copy(backend, frontend)
		if value, ok := backend.(*net.UnixConn); ok {
			_ = value.CloseWrite()
		}
	}()
	go func() { defer wait.Done(); _, _ = io.Copy(frontend, backend); _ = frontend.CloseWrite() }()
	wait.Wait()
}

func inheritedListeners() ([]*net.UnixListener, error) {
	pid, err := strconv.Atoi(os.Getenv("LISTEN_PID"))
	if err != nil || pid != os.Getpid() || os.Getenv("LISTEN_FDS") != "1" {
		return nil, fmt.Errorf("relay requires exactly one PID1 socket")
	}
	if err := os.Unsetenv("LISTEN_PID"); err != nil {
		return nil, err
	}
	if err := os.Unsetenv("LISTEN_FDS"); err != nil {
		return nil, err
	}
	file := os.NewFile(3, "relay-frontend")
	if file == nil {
		return nil, fmt.Errorf("relay socket descriptor missing")
	}
	listener, err := net.FileListener(file)
	_ = file.Close()
	if err != nil {
		return nil, err
	}
	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		_ = listener.Close()
		return nil, fmt.Errorf("relay frontend is not AF_UNIX")
	}
	return []*net.UnixListener{unixListener}, nil
}

func requireNoProc() error {
	var stat unix.Stat_t
	err := unix.Stat("/proc/self", &stat)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("relay proc confinement observation failed: %w", err)
	}
	return fmt.Errorf("relay confinement exposes proc")
}

func validResourceID(value string) bool {
	if len(value) != 36 || !strings.HasPrefix(value, "res_") {
		return false
	}
	_, err := hex.DecodeString(value[4:])
	return err == nil
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
}
