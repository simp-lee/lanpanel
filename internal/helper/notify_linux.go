//go:build linux

package helper

import (
	"fmt"
	"net"
	"os"
	"strings"
)

func notifyReady() error {
	path, present := os.LookupEnv("NOTIFY_SOCKET")
	if !present {
		return fmt.Errorf("helper systemd readiness socket is missing")
	}
	if err := os.Unsetenv("NOTIFY_SOCKET"); err != nil {
		return err
	}
	return notifySystemd(path)
}

func notifySystemd(path string) error {
	if len(path) == 0 || len(path) > 107 || path[0] != '/' && path[0] != '@' || strings.ContainsAny(path, "\x00\r\n") {
		return fmt.Errorf("systemd readiness socket authority is invalid")
	}
	connection, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer connection.Close()
	payload := []byte("READY=1")
	written, err := connection.Write(payload)
	if err != nil || written != len(payload) {
		return fmt.Errorf("send systemd readiness notification: wrote %d: %w", written, err)
	}
	return nil
}
