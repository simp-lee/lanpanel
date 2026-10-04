//go:build linux

package bootstrap

import (
	"encoding/json"
	"fmt"
	"io"
	"lanpanel/internal/packages"
	"os"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const maximumInstallerLogBytes = 1 << 20

type installerProgressOutput struct {
	terminal        io.Writer
	mu              sync.Mutex
	log             *os.File
	written         int64
	terminalWritten int64
	started         time.Time
}

func newInstallerProgressOutput(terminal io.Writer) *installerProgressOutput {
	return &installerProgressOutput{terminal: terminal, started: time.Now()}
}

// Write is deliberately best effort: progress must never turn a successful
// transaction into a failed one because a terminal or diagnostic log closed.
// Raw child output and structured events have separate framing and share a
// bounded terminal/log sink.
func (output *installerProgressOutput) Write(value []byte) (int, error) {
	if output == nil {
		return len(value), nil
	}
	output.mu.Lock()
	defer output.mu.Unlock()
	output.openLogLocked()
	output.writeTerminalLocked(sanitizeTerminal(value))
	if output.log != nil {
		encoded, err := json.Marshal(string(value))
		if err == nil {
			output.writeLogLocked(append([]byte("LanPanel output: "), append(encoded, '\n')...))
		}
	}
	return len(value), nil
}

// ReportProgress emits human-readable progress to the terminal and a distinct
// JSON record to the protected log. Raw APT/dpkg output and structured events
// use separate terminal/log paths and framing.
func (output *installerProgressOutput) ReportProgress(event packages.ProgressEvent) {
	if output == nil {
		return
	}
	output.mu.Lock()
	defer output.mu.Unlock()
	if event.Timestamp == "" {
		event.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	if event.ElapsedSeconds == 0 {
		event.ElapsedSeconds = int64(time.Since(output.started) / time.Second)
	}
	message := fmt.Sprintf("LanPanel: [%s] %s", event.Stage, string(sanitizeTerminal([]byte(event.Message))))
	if event.Current != 0 || event.Total != 0 {
		message += fmt.Sprintf(" (%d/%d)", event.Current, event.Total)
	}
	if event.ElapsedSeconds != 0 {
		message += fmt.Sprintf(" +%ds", event.ElapsedSeconds)
	}
	message += "\n"
	output.openLogLocked()
	output.writeTerminalLocked([]byte(message))
	if output.log != nil {
		data, err := json.Marshal(event)
		if err == nil {
			output.writeLogLocked(append([]byte("LanPanel progress: "), append(data, '\n')...))
		}
	}
}

func (output *installerProgressOutput) openLogLocked() {
	if output.log != nil || output.written >= maximumInstallerLogBytes {
		return
	}
	const directory = "/var/log/lanpanel"
	if err := ensureInstallerLogDirectory(directory); err != nil {
		return
	}
	fd, err := unix.Open(directory+"/install.log", unix.O_WRONLY|unix.O_CREAT|unix.O_APPEND|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return
	}
	file := os.NewFile(uintptr(fd), "lanpanel-install-log")
	if file == nil {
		_ = unix.Close(fd)
		return
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 || stat.Mode&0o022 != 0 {
		_ = file.Close()
		return
	}
	if stat.Size > maximumInstallerLogBytes {
		output.written = maximumInstallerLogBytes
		_ = file.Close()
		return
	}
	_ = file.Chmod(0o600)
	output.written = stat.Size
	output.log = file
}

func sanitizeTerminal(value []byte) []byte {
	clean := make([]byte, 0, len(value))
	for len(value) != 0 {
		runeValue, size := utf8.DecodeRune(value)
		if runeValue == utf8.RuneError && size == 1 {
			value = value[1:]
			continue
		}
		value = value[size:]
		switch {
		case runeValue == '\n' || runeValue == '\t':
			clean = utf8.AppendRune(clean, runeValue)
		case runeValue == '\r':
			clean = append(clean, '\n')
		case runeValue < 0x20 || runeValue == 0x7f || runeValue >= 0x80 && runeValue <= 0x9f:
		default:
			clean = utf8.AppendRune(clean, runeValue)
		}
	}
	return clean
}

func (output *installerProgressOutput) writeTerminalLocked(value []byte) {
	if output.terminal == nil || output.terminalWritten >= maximumInstallerLogBytes {
		return
	}
	remaining := int64(maximumInstallerLogBytes) - output.terminalWritten
	if int64(len(value)) > remaining {
		value = value[:remaining]
	}
	_, _ = output.terminal.Write(value)
	output.terminalWritten += int64(len(value))
}

func (output *installerProgressOutput) writeLogLocked(value []byte) {
	if output.log == nil || output.written >= maximumInstallerLogBytes {
		return
	}
	remaining := int64(maximumInstallerLogBytes) - output.written
	if int64(len(value)) > remaining {
		value = value[:remaining]
	}
	if count, err := output.log.Write(value); err == nil {
		output.written += int64(count)
	}
	if output.written >= maximumInstallerLogBytes {
		_ = output.log.Sync()
	}
}

func ensureInstallerLogDirectory(path string) error {
	for _, parent := range []string{"/var", "/var/log"} {
		var parentStat unix.Stat_t
		if err := unix.Lstat(parent, &parentStat); err != nil || parentStat.Mode&unix.S_IFMT != unix.S_IFDIR || parentStat.Uid != 0 {
			return os.ErrPermission
		}
		if parent == "/var/log" {
			if parentStat.Mode&0o002 != 0 {
				return os.ErrPermission
			}
		} else if parentStat.Mode&0o022 != 0 {
			return os.ErrPermission
		}
	}
	var stat unix.Stat_t
	created := false
	if err := unix.Lstat(path, &stat); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		if err := unix.Mkdir(path, 0o711); err != nil {
			if !os.IsExist(err) {
				return err
			}
		} else {
			created = true
		}
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	if created {
		if err := unix.Fchown(fd, 0, 0); err != nil {
			return err
		}
		if err := unix.Fchmod(fd, 0o711); err != nil {
			return err
		}
	}
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0o022 != 0 {
		return os.ErrPermission
	}
	if stat.Mode&0o7777 != 0o711 {
		if err := unix.Fchmod(fd, 0o711); err != nil {
			return err
		}
	}
	return nil
}

func (output *installerProgressOutput) Close() error {
	if output == nil {
		return nil
	}
	output.mu.Lock()
	defer output.mu.Unlock()
	if output.log == nil {
		return nil
	}
	_ = output.log.Sync()
	err := output.log.Close()
	output.log = nil
	return err
}
