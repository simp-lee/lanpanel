//go:build linux

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	aptGetExecutable          = "/usr/bin/apt-get"
	aptMetadataRefreshTimeout = 5 * time.Minute
	maximumAPTRefreshOutput   = 64 << 10
)

type aptRefreshOutput struct {
	mu        sync.Mutex
	data      []byte
	truncated bool
}

func (output *aptRefreshOutput) Write(value []byte) (int, error) {
	output.mu.Lock()
	defer output.mu.Unlock()
	remaining := maximumAPTRefreshOutput - len(output.data)
	if remaining <= 0 {
		output.truncated = true
		return len(value), nil
	}
	if len(value) > remaining {
		output.data = append(output.data, value[:remaining]...)
		output.truncated = true
		return len(value), nil
	}
	output.data = append(output.data, value...)
	return len(value), nil
}

func (output *aptRefreshOutput) snapshot() (string, bool) {
	output.mu.Lock()
	defer output.mu.Unlock()
	return string(output.data), output.truncated
}

type aptMetadataUpdateFunc func(context.Context, io.Writer, io.Writer) error

// refreshAPTMetadata refreshes only the host's signed APT indexes. It never
// installs or upgrades packages; the transaction engine performs the exact
// release-bound package operation later.
func refreshAPTMetadata(parent context.Context) error {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return fmt.Errorf("APT metadata refresh requires root")
	}
	if err := validateAPTRefreshPaths(); err != nil {
		return err
	}
	return refreshAPTMetadataWith(parent, runAPTMetadataUpdate)
}

func refreshAPTMetadataWith(parent context.Context, update aptMetadataUpdateFunc) error {
	return refreshAPTMetadataWithOutput(parent, update, os.Stdout, os.Stderr)
}

func refreshAPTMetadataWithOutput(parent context.Context, update aptMetadataUpdateFunc, stdout, stderr io.Writer) error {
	if update == nil {
		return fmt.Errorf("APT metadata refresh command is missing")
	}
	fmt.Fprintln(stderr, "LanPanel: refreshing signed APT repository metadata...")
	ctx, cancel := context.WithTimeout(parent, aptMetadataRefreshTimeout)
	defer cancel()
	var output aptRefreshOutput
	progressStdout := io.MultiWriter(stdout, &output)
	progressStderr := io.MultiWriter(stderr, &output)
	if err := update(ctx, progressStdout, progressStderr); err != nil {
		rawDetail, truncated := output.snapshot()
		detail := strings.TrimSpace(rawDetail)
		if truncated {
			detail += "\n[APT output truncated]"
		}
		if detail == "" {
			detail = "no APT diagnostic output"
		}
		return fmt.Errorf("APT metadata refresh failed; check the system clock and configured signed repositories, then retry: %w: %s", err, detail)
	}
	return nil
}

func validateAPTRefreshPaths() error {
	var executable unix.Stat_t
	if err := unix.Lstat(aptGetExecutable, &executable); err != nil || executable.Mode&unix.S_IFMT != unix.S_IFREG || executable.Uid != 0 || executable.Gid != 0 || executable.Mode&0o6022 != 0 || executable.Mode&0o111 == 0 {
		return fmt.Errorf("APT metadata refresh executable is not a safe root-owned regular file: %s", aptGetExecutable)
	}
	for current := filepath.Dir(aptGetExecutable); ; current = filepath.Dir(current) {
		var directory unix.Stat_t
		if err := unix.Lstat(current, &directory); err != nil || directory.Mode&unix.S_IFMT != unix.S_IFDIR || directory.Uid != 0 || directory.Gid != 0 || directory.Mode&0o6022 != 0 {
			return fmt.Errorf("APT metadata refresh executable parent is unsafe: %s", current)
		}
		if current == "/" {
			break
		}
	}
	for current := "/var/lib/apt/lists"; ; current = filepath.Dir(current) {
		var directory unix.Stat_t
		if err := unix.Lstat(current, &directory); err != nil || directory.Mode&unix.S_IFMT != unix.S_IFDIR || directory.Uid != 0 || directory.Gid != 0 || directory.Mode&0o6022 != 0 {
			return fmt.Errorf("APT metadata refresh list path is unsafe: %s", current)
		}
		if current == "/" {
			break
		}
	}
	return nil
}

func runAPTMetadataUpdate(ctx context.Context, stdout, stderr io.Writer) error {
	command := exec.Command(aptGetExecutable, "update")
	command.Env = []string{
		"DEBIAN_FRONTEND=noninteractive",
		"LANG=C",
		"LC_ALL=C",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
	}
	command.Stdout = stdout
	command.Stderr = stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := command.Start(); err != nil {
		return err
	}
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	select {
	case err := <-wait:
		return err
	case <-ctx.Done():
		killErr := unix.Kill(-command.Process.Pid, unix.SIGKILL)
		waitErr := <-wait
		if killErr != nil && !errors.Is(killErr, unix.ESRCH) {
			return errors.Join(ctx.Err(), killErr, waitErr)
		}
		return ctx.Err()
	}
}
