//go:build linux

package control

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func RunControlRelay(args []string) error {
	if len(args) != 0 || os.Geteuid() == 0 || os.Getenv("LANPANEL_HEADSCALE_RELAY") != "control-v1" {
		return fmt.Errorf("headscale control relay requires fixed non-root PID1 invocation")
	}
	if err := requireSocketActivation("headscale-control", 1); err != nil {
		return err
	}
	address, err := unix.Getsockname(3)
	unixAddress, ok := address.(*unix.SockaddrUnix)
	accepting, acceptErr := unix.GetsockoptInt(3, unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
	if err != nil || !ok || unixAddress.Name != FixedPaths().ControlSocket || acceptErr != nil || accepting != 1 {
		return fmt.Errorf("headscale control relay listener identity changed")
	}
	var listenerStat unix.Stat_t
	if unix.Lstat(FixedPaths().ControlSocket, &listenerStat) != nil || listenerStat.Uid == 0 || listenerStat.Mode&unix.S_IFMT != unix.S_IFSOCK || listenerStat.Mode&0o7777 != 0o600 {
		return fmt.Errorf("headscale control relay listener owner invalid")
	}
	file := os.NewFile(3, "headscale-control")
	listener, err := net.FileListener(file)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		if listener != nil {
			_ = listener.Close()
		}
		return errors.Join(err, closeErr)
	}
	frontend, ok := listener.(*net.UnixListener)
	if !ok {
		_ = listener.Close()
		return fmt.Errorf("headscale control relay frontend is not Unix")
	}
	defer func(ignore func() error) { _ = ignore() }(frontend.Close)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	for {
		_ = frontend.SetDeadline(time.Now().Add(250 * time.Millisecond))
		connection, err := frontend.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if temporary, ok := err.(net.Error); ok && temporary.Timeout() {
				continue
			}
			return err
		}
		if !unixPeerUID(connection, listenerStat.Uid) {
			_ = connection.Close()
			continue
		}
		go relayControlConnection(ctx, connection)
	}
}

func relayControlConnection(ctx context.Context, frontend *net.UnixConn) {
	defer func(ignore func() error) { _ = ignore() }(frontend.Close)
	backend, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp4", ControlBackend)
	if err != nil {
		return
	}
	defer func(ignore func() error) { _ = ignore() }(backend.Close)
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		_, _ = io.Copy(backend, frontend)
		if tcp, ok := backend.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	go func() { defer wait.Done(); _, _ = io.Copy(frontend, backend); _ = frontend.CloseWrite() }()
	wait.Wait()
}

func RunSTUNRelay(args []string) error {
	if len(args) != 0 || os.Geteuid() == 0 || os.Getenv("LANPANEL_HEADSCALE_RELAY") != "stun-v1" {
		return fmt.Errorf("headscale STUN relay requires fixed non-root PID1 invocation")
	}
	if err := requireSocketActivation("headscale-stun", 1); err != nil {
		return err
	}
	address, err := unix.Getsockname(3)
	inet, ok := address.(*unix.SockaddrInet4)
	if err != nil || !ok || inet.Port != 3478 || inet.Addr != [4]byte{} {
		return fmt.Errorf("headscale STUN listener identity changed")
	}
	file := os.NewFile(3, "headscale-stun")
	packet, err := net.FilePacketConn(file)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		if packet != nil {
			_ = packet.Close()
		}
		return errors.Join(err, closeErr)
	}
	defer func(ignore func() error) { _ = ignore() }(packet.Close)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	semaphore := make(chan struct{}, 64)
	buffer := make([]byte, 4096)
	for {
		_ = packet.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, peer, err := packet.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if temporary, ok := err.(net.Error); ok && temporary.Timeout() {
				continue
			}
			return err
		}
		payload := append([]byte(nil), buffer[:n]...)
		select {
		case semaphore <- struct{}{}:
			go relaySTUNPacket(ctx, packet, peer, payload, semaphore)
		default:
			clear(payload)
		}
	}
}

func relaySTUNPacket(ctx context.Context, frontend net.PacketConn, peer net.Addr, payload []byte, semaphore chan struct{}) {
	defer func() { clear(payload); <-semaphore }()
	backend, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "udp4", "127.0.0.1:3478")
	if err != nil {
		return
	}
	defer func(ignore func() error) { _ = ignore() }(backend.Close)
	_ = backend.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := backend.Write(payload); err != nil {
		return
	}
	response := make([]byte, 4096)
	n, err := backend.Read(response)
	if err == nil && rewriteSTUNMappedAddress(response[:n], payload, peer) == nil {
		_, _ = frontend.WriteTo(response[:n], peer)
	}
	clear(response)
}

func rewriteSTUNMappedAddress(response, request []byte, peer net.Addr) error {
	udp, ok := peer.(*net.UDPAddr)
	if !ok {
		return fmt.Errorf("STUN peer is not UDP")
	}
	address := udp.IP.To4()
	if address == nil || udp.Port <= 0 || len(request) < 20 || len(response) < 20 || request[4] != 0x21 || request[5] != 0x12 || request[6] != 0xa4 || request[7] != 0x42 || !bytes.Equal(request[4:8], response[4:8]) || !bytes.Equal(request[8:20], response[8:20]) {
		return fmt.Errorf("STUN transaction identity changed")
	}
	declared := int(response[2])<<8 | int(response[3])
	if declared+20 != len(response) || declared%4 != 0 {
		return fmt.Errorf("STUN response envelope changed")
	}
	mapped, fingerprintOffset := false, -1
	for offset := 20; offset+4 <= len(response); {
		kind := uint16(response[offset])<<8 | uint16(response[offset+1])
		length := int(response[offset+2])<<8 | int(response[offset+3])
		end := offset + 4 + length
		if end > len(response) {
			return fmt.Errorf("STUN attribute envelope changed")
		}
		if kind == 0x0008 || kind == 0x001c {
			return fmt.Errorf("authenticated STUN response cannot be rewritten")
		}
		if kind == 0x8028 {
			if length != 4 || fingerprintOffset >= 0 {
				return fmt.Errorf("STUN fingerprint envelope changed")
			}
			fingerprintOffset = offset
		}
		if (kind == 0x0020 || kind == 0x0001) && length == 8 && response[offset+5] == 0x01 {
			if mapped {
				return fmt.Errorf("STUN mapped-address response is ambiguous")
			}
			mapped = true
			port := uint16(udp.Port)
			copy(response[offset+8:offset+12], address)
			if kind == 0x0020 {
				port ^= 0x2112
				for index, value := range []byte{0x21, 0x12, 0xa4, 0x42} {
					response[offset+8+index] ^= value
				}
			}
			response[offset+6], response[offset+7] = byte(port>>8), byte(port)
		}
		offset = (end + 3) &^ 3
	}
	if !mapped {
		return fmt.Errorf("STUN mapped-address response missing")
	}
	if fingerprintOffset >= 0 {
		binary.BigEndian.PutUint32(response[fingerprintOffset+4:fingerprintOffset+8], crc32.ChecksumIEEE(response[:fingerprintOffset])^0x5354554e)
	}
	return nil
}

func requireSocketActivation(name string, count int) error {
	if os.Getenv("LISTEN_PID") != fmt.Sprint(os.Getpid()) || os.Getenv("LISTEN_FDS") != fmt.Sprint(count) || os.Getenv("LISTEN_FDNAMES") != name {
		return fmt.Errorf("headscale relay socket activation authority changed")
	}
	for _, name := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
		if err := os.Unsetenv(name); err != nil {
			return err
		}
	}
	return nil
}

func unixPeerUID(connection *net.UnixConn, uid uint32) bool {
	raw, err := connection.SyscallConn()
	if err != nil {
		return false
	}
	var credential *unix.Ucred
	var socketErr error
	if raw.Control(func(fd uintptr) {
		credential, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}) != nil || socketErr != nil || credential == nil {
		return false
	}
	return credential.Uid == uid
}
