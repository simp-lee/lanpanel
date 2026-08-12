//go:build linux

package bootstrap

import (
	"bufio"
	"fmt"
	"lanpanel/internal/helper"
	"net"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

func verifyActivationPostconditions(journal Journal) error {
	connection, err := net.DialTimeout("tcp4", net.JoinHostPort(journal.Authority.Address, strconv.Itoa(int(journal.Authority.Port))), time.Second)
	if err != nil {
		return fmt.Errorf("Management socket activation did not reserve the exact authority: %w", err)
	}
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	_, writeErr := connection.Write([]byte("PING"))
	response, readErr := bufio.NewReader(connection).ReadString('\n')
	_ = connection.Close()
	if writeErr != nil || readErr != nil || response != "LPUI "+journal.GenerationID+"\n" {
		return fmt.Errorf("Management UI inherited-listener generation handshake failed")
	}
	var stat syscall.Stat_t
	if err := syscall.Lstat(helper.FixedSocketPath, &stat); err != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFSOCK || stat.Uid != 0 {
		return fmt.Errorf("helper protected socket postcondition is missing")
	}
	if data, err := readCommittedArtifact(filepath.Join(journal.Paths.InstallationRoot, "bundle.json"), MaximumJournalBytes, 0o600); err != nil || len(data) == 0 {
		return fmt.Errorf("UI installation authority postcondition is missing")
	}
	return nil
}
