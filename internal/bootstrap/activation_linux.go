//go:build linux

package bootstrap

import (
	"fmt"
	"io"
	"lanpanel/internal/helper"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

func verifyActivationPostconditions(journal Journal) error {
	authority := net.JoinHostPort(journal.Authority.Address, strconv.Itoa(int(journal.Authority.Port)))
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return fmt.Errorf("management probe redirect is forbidden")
	}}
	request, _ := http.NewRequest(http.MethodGet, "http://"+authority+"/", nil)
	request.Host = authority
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("management socket activation did not reserve the exact authority: %w", err)
	}
	defer func(ignore func() error) { _ = ignore() }(response.Body.Close)
	_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if readErr != nil || response.StatusCode != http.StatusOK || response.Header.Get("Content-Security-Policy") == "" || response.Header.Get("Cache-Control") != "no-store, private" {
		return fmt.Errorf("management UI inherited-listener HTTP handshake failed")
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
