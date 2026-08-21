//go:build linux

package goaccess

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func RunRelay(args []string) error {
	if len(args) != 0 || os.Geteuid() == 0 || os.Getenv("LANPANEL_GOACCESS_BACKEND") != Backend || !validInstallationID(os.Getenv("LANPANEL_INSTALLATION_ID")) || !validResourceID(os.Getenv("LANPANEL_RESOURCE_ID")) {
		return fmt.Errorf("GoAccess relay requires fixed non-root PID1 invocation")
	}
	generation, genErr := strconv.ParseUint(os.Getenv("LANPANEL_GOACCESS_GENERATION"), 10, 64)
	paths, pathErr := DerivePaths(os.Getenv("LANPANEL_RESOURCE_ID"), generation)
	if genErr != nil || pathErr != nil {
		return fmt.Errorf("GoAccess relay generation invalid")
	}
	pid, err := strconv.Atoi(os.Getenv("LISTEN_PID"))
	if err != nil || pid != os.Getpid() || os.Getenv("LISTEN_FDS") != "1" || os.Getenv("LISTEN_FDNAMES") != "goaccess" {
		return fmt.Errorf("GoAccess relay requires one PID1 socket")
	}
	_ = os.Unsetenv("LISTEN_PID")
	_ = os.Unsetenv("LISTEN_FDS")
	_ = os.Unsetenv("LISTEN_FDNAMES")
	socketAddress, addressErr := unix.Getsockname(3)
	unixAddress, addressOK := socketAddress.(*unix.SockaddrUnix)
	accepting, acceptErr := unix.GetsockoptInt(3, unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
	if addressErr != nil || !addressOK || unixAddress.Name != paths.Endpoint || acceptErr != nil || accepting != 1 {
		return fmt.Errorf("GoAccess relay listener identity invalid")
	}
	file := os.NewFile(3, "goaccess-frontend")
	if file == nil {
		return fmt.Errorf("GoAccess relay listener missing")
	}
	listener, err := net.FileListener(file)
	_ = file.Close()
	if err != nil {
		return err
	}
	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		_ = listener.Close()
		return fmt.Errorf("GoAccess relay frontend is not Unix")
	}
	defer func(ignore func() error) { _ = ignore() }(unixListener.Close)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	for {
		if err = unixListener.SetDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
			return err
		}
		frontend, acceptErr := unixListener.AcceptUnix()
		if acceptErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			if value, ok := acceptErr.(net.Error); ok && value.Timeout() {
				continue
			}
			return acceptErr
		}
		go relayOne(ctx, frontend)
	}
}

func relayOne(ctx context.Context, frontend *net.UnixConn) {
	defer func(ignore func() error) { _ = ignore() }(frontend.Close)
	backend, err := (&net.Dialer{}).DialContext(ctx, "tcp4", Backend)
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
