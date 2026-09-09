//go:build linux

package qualification

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/bootstrap"
	"lanpanel/internal/release"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/unix"
)

const sshOperationTimeout = 30 * time.Second

type SSHClient struct {
	client     *ssh.Client
	sftp       *sftp.Client
	connection net.Conn
	ioMu       sync.Mutex
	closed     atomic.Bool
}

func OpenSSH(ctx context.Context, authority SSHAuthority) (*SSHClient, error) {
	address, err := canonicalSSHAddress(authority.Address)
	if err != nil || authority.User != "root" || !release.ValidDigest(authority.HostKeySHA256) {
		return nil, fmt.Errorf("SSH authority is invalid")
	}
	authMethod, closeCredential, err := resolveSSHCredential(authority.CredentialRef)
	if err != nil {
		return nil, err
	}
	defer closeCredential()
	config := &ssh.ClientConfig{
		User:            authority.User,
		Auth:            []ssh.AuthMethod{authMethod},
		HostKeyCallback: pinnedHostKey(authority.HostKeySHA256),
		Timeout:         sshOperationTimeout,
	}
	dialer := net.Dialer{Timeout: sshOperationTimeout, KeepAlive: -1}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	var clientConnection ssh.Conn
	var channels <-chan ssh.NewChannel
	var requests <-chan *ssh.Request
	if err := performConnIO(ctx, connection, sshOperationTimeout, func() error {
		var handshakeErr error
		clientConnection, channels, requests, handshakeErr = ssh.NewClientConn(connection, address, config)
		return handshakeErr
	}); err != nil {
		_ = connection.Close()
		return nil, err
	}
	client := ssh.NewClient(clientConnection, channels, requests)
	var fileClient *sftp.Client
	if err := performConnIO(ctx, connection, sshOperationTimeout, func() error {
		var sftpErr error
		fileClient, sftpErr = sftp.NewClient(client, sftp.MaxPacket(32<<10), sftp.UseConcurrentReads(false), sftp.UseConcurrentWrites(false))
		return sftpErr
	}); err != nil {
		_ = connection.Close()
		_ = client.Close()
		return nil, err
	}
	return &SSHClient{client: client, sftp: fileClient, connection: connection}, nil
}

// performConnIO binds one blocking connection operation to both the caller's
// cancellation and a fixed upper bound. Cancellation closes the transport so
// protocol handshakes and reads that do not otherwise observe Context unblock.
// It never waits for the cancellation callback to finish.
func performConnIO(ctx context.Context, connection net.Conn, maximum time.Duration, operation func() error) error {
	if ctx == nil || connection == nil || maximum <= 0 || operation == nil {
		return fmt.Errorf("connection operation authority is invalid")
	}
	if err := ctx.Err(); err != nil {
		_ = connection.Close()
		return err
	}
	deadline := time.Now().Add(maximum)
	contextDeadline, hasContextDeadline := ctx.Deadline()
	if hasContextDeadline && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		_ = connection.Close()
		return err
	}
	stopClose := context.AfterFunc(ctx, func() { _ = connection.Close() })
	operationErr := operation()
	contextErr := ctx.Err()
	if contextErr == nil && hasContextDeadline && !time.Now().Before(contextDeadline) {
		contextErr = context.DeadlineExceeded
	}
	stopped := stopClose()
	if contextErr == nil {
		contextErr = ctx.Err()
	}
	if contextErr != nil {
		_ = connection.Close()
		return errors.Join(operationErr, contextErr)
	}
	if !stopped {
		return errors.Join(operationErr, fmt.Errorf("connection cancellation state is indeterminate"))
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		_ = connection.Close()
		return errors.Join(operationErr, err)
	}
	var networkErr net.Error
	if errors.As(operationErr, &networkErr) && networkErr.Timeout() {
		_ = connection.Close()
	}
	return operationErr
}

func (client *SSHClient) withIOContext(ctx context.Context, operation func() error) error {
	return client.withConnectionContext(ctx, sshOperationTimeout, operation)
}

// Remote qualification commands use the caller's bounded step deadline; SSH
// protocol handshakes, SFTP requests, and tunnel opens use sshOperationTimeout.
func (client *SSHClient) withCommandContext(ctx context.Context, operation func() error) error {
	maximum := sshOperationTimeout
	if deadline, present := ctx.Deadline(); present {
		maximum = time.Until(deadline)
		if maximum <= 0 {
			return ctx.Err()
		}
	}
	return client.withConnectionContext(ctx, maximum, operation)
}

func (client *SSHClient) withConnectionContext(ctx context.Context, maximum time.Duration, operation func() error) error {
	if client == nil || client.connection == nil || ctx == nil || maximum <= 0 {
		return fmt.Errorf("SSH connection is unavailable")
	}
	client.ioMu.Lock()
	defer client.ioMu.Unlock()
	err := performConnIO(ctx, client.connection, maximum, operation)
	var networkErr net.Error
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.As(err, &networkErr) && networkErr.Timeout() {
		client.closed.Store(true)
	}
	return err
}

func (client *SSHClient) closeSessionContext(ctx context.Context, session *ssh.Session) error {
	if client == nil || client.connection == nil || session == nil || ctx == nil {
		return fmt.Errorf("SSH session is unavailable")
	}
	client.ioMu.Lock()
	defer client.ioMu.Unlock()
	err := performConnIO(ctx, client.connection, sshOperationTimeout, session.Close)
	var networkErr net.Error
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, net.ErrClosed) || errors.As(err, &networkErr) && networkErr.Timeout() {
		client.closed.Store(true)
	}
	return err
}

func (client *SSHClient) usable() bool {
	return client != nil && client.connection != nil && !client.closed.Load()
}

func (client *SSHClient) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" || address == "" {
		return nil, fmt.Errorf("SSH tunnel destination is invalid")
	}
	var connection net.Conn
	err := client.withIOContext(ctx, func() error {
		var dialErr error
		connection, dialErr = client.client.Dial(network, address)
		return dialErr
	})
	if err != nil && connection != nil {
		_ = connection.Close()
		connection = nil
	}
	return connection, err
}

func (client *SSHClient) Close() error {
	if client == nil {
		return nil
	}
	// Close the transport first so protocol-level Close calls cannot wait on a
	// stalled peer. Their resulting transport errors are expected and ignored.
	client.closed.Store(true)
	var closeErr error
	if client.connection != nil {
		closeErr = client.connection.Close()
		if errors.Is(closeErr, net.ErrClosed) {
			closeErr = nil
		}
	}
	if client.sftp != nil {
		_ = client.sftp.Close()
	}
	if client.client != nil {
		_ = client.client.Close()
	}
	return closeErr
}

func (client *SSHClient) PrepareStaging(ctx context.Context, runID string) (string, error) {
	if !strings.HasPrefix(runID, "run_") || len(runID) != 68 || !lowerHex(strings.TrimPrefix(runID, "run_")) {
		return "", fmt.Errorf("qualification staging run identity is invalid")
	}
	base := "/var/lib/lanpanel-qualification"
	if _, err := client.sftpLstat(ctx, base); err == nil || !os.IsNotExist(err) {
		return "", fmt.Errorf("qualification staging base prior state is not absent")
	}
	if err := client.sftpMkdir(ctx, base); err != nil {
		return "", err
	}
	if err := client.sftpChmod(ctx, base, 0o700); err != nil {
		return "", err
	}
	if err := client.ensureRemoteDirectory(ctx, base, false); err != nil {
		return "", err
	}
	root := base + "/" + runID
	if _, err := client.sftpLstat(ctx, root); err == nil || !os.IsNotExist(err) {
		return "", fmt.Errorf("qualification staging root already exists or is ambiguous")
	}
	if err := client.sftpMkdir(ctx, root); err != nil {
		return "", err
	}
	if err := client.sftpChmod(ctx, root, 0o700); err != nil {
		return "", err
	}
	if err := client.ensureRemoteDirectory(ctx, root, false); err != nil {
		return "", err
	}
	return root, nil
}

func (client *SSHClient) UploadStagingFile(ctx context.Context, root, name string, data []byte, mode os.FileMode) (string, error) {
	if !validRemoteRunPath(root) || !release.ValidRelativePath(name) || len(data) == 0 || len(data) > 512<<20 || mode != 0o400 && mode != 0o500 && mode != 0o600 {
		return "", fmt.Errorf("qualification staging file authority is invalid")
	}
	parts := strings.Split(name, "/")
	parent := root
	for _, component := range parts[:len(parts)-1] {
		parent += "/" + component
		if err := client.ensureRemoteDirectory(ctx, parent, true); err != nil {
			return "", err
		}
	}
	path := root + "/" + name
	var file *sftp.File
	if err := client.withIOContext(ctx, func() error {
		var openErr error
		file, openErr = client.sftp.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
		return openErr
	}); err != nil {
		return "", err
	}
	written := 0
	var writeErr error
	const uploadChunkBytes = 32 << 10
	for written < len(data) {
		end := min(written+uploadChunkBytes, len(data))
		chunkWritten := 0
		writeErr = client.withIOContext(ctx, func() error {
			var err error
			chunkWritten, err = file.Write(data[written:end])
			return err
		})
		if writeErr != nil || chunkWritten <= 0 || chunkWritten > end-written {
			break
		}
		written += chunkWritten
	}
	closeErr := client.withIOContext(ctx, file.Close)
	if writeErr != nil || closeErr != nil || written != len(data) {
		return "", errors.Join(writeErr, closeErr, fmt.Errorf("qualification staging upload was incomplete"))
	}
	if err := client.sftpChmod(ctx, path, mode); err != nil {
		return "", err
	}
	info, err := client.sftpLstat(ctx, path)
	if err != nil || info == nil || !info.Mode().IsRegular() || fileUID(info) != 0 || fileGID(info) != 0 || info.Mode().Perm() != mode || info.Size() != int64(len(data)) {
		return "", fmt.Errorf("qualification staging upload identity is unsafe: %w", err)
	}
	return path, nil
}

func (client *SSHClient) RemoveStaging(ctx context.Context, root string, files []string) error {
	if !validRemoteRunPath(root) {
		return fmt.Errorf("qualification staging cleanup root is invalid")
	}
	paths := append([]string(nil), files...)
	slices.SortFunc(paths, func(left, right string) int { return strings.Compare(right, left) })
	directories := map[string]bool{root: true}
	for _, path := range paths {
		if !strings.HasPrefix(path, root+"/") || filepath.Clean(path) != path {
			return fmt.Errorf("qualification staging cleanup escaped its root")
		}
		if err := client.sftpRemove(ctx, path); err != nil && !os.IsNotExist(err) {
			return err
		}
		for parent := filepath.Dir(path); strings.HasPrefix(parent, root); parent = filepath.Dir(parent) {
			directories[parent] = true
			if parent == root {
				break
			}
		}
	}
	directoryPaths := make([]string, 0, len(directories))
	for directory := range directories {
		directoryPaths = append(directoryPaths, directory)
	}
	slices.SortFunc(directoryPaths, func(left, right string) int {
		if len(left) != len(right) {
			return len(right) - len(left)
		}
		return strings.Compare(right, left)
	})
	for _, directory := range directoryPaths {
		entries, err := client.sftpReadDir(ctx, directory)
		if err != nil {
			return err
		}
		if len(entries) != 0 {
			return fmt.Errorf("qualification staging cleanup found unexplained residue")
		}
		if err := client.sftpRemoveDirectory(ctx, directory); err != nil {
			return err
		}
	}
	base := "/var/lib/lanpanel-qualification"
	entries, err := client.sftpReadDir(ctx, base)
	if err != nil || len(entries) != 0 {
		return fmt.Errorf("qualification staging base cleanup found residue: %w", err)
	}
	if err := client.sftpRemoveDirectory(ctx, base); err != nil {
		return err
	}
	return nil
}

func (client *SSHClient) ensureRemoteDirectory(ctx context.Context, path string, create bool) error {
	info, err := client.sftpLstat(ctx, path)
	if os.IsNotExist(err) && create {
		if err := client.sftpMkdir(ctx, path); err != nil {
			return err
		}
		if err := client.sftpChmod(ctx, path, 0o700); err != nil {
			return err
		}
		info, err = client.sftpLstat(ctx, path)
	}
	if err != nil || info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || fileUID(info) != 0 || fileGID(info) != 0 || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("qualification staging directory authority is unsafe: %w", err)
	}
	return nil
}

func (client *SSHClient) sftpLstat(ctx context.Context, path string) (os.FileInfo, error) {
	var info os.FileInfo
	err := client.withIOContext(ctx, func() error {
		var operationErr error
		info, operationErr = client.sftp.Lstat(path)
		return operationErr
	})
	return info, err
}

func (client *SSHClient) sftpMkdir(ctx context.Context, path string) error {
	return client.withIOContext(ctx, func() error { return client.sftp.Mkdir(path) })
}

func (client *SSHClient) sftpChmod(ctx context.Context, path string, mode os.FileMode) error {
	return client.withIOContext(ctx, func() error { return client.sftp.Chmod(path, mode) })
}

func (client *SSHClient) sftpRemove(ctx context.Context, path string) error {
	return client.withIOContext(ctx, func() error { return client.sftp.Remove(path) })
}

func (client *SSHClient) sftpReadDir(ctx context.Context, path string) ([]os.FileInfo, error) {
	var entries []os.FileInfo
	err := client.withIOContext(ctx, func() error {
		var operationErr error
		entries, operationErr = client.sftp.ReadDir(path)
		return operationErr
	})
	return entries, err
}

func (client *SSHClient) sftpRemoveDirectory(ctx context.Context, path string) error {
	return client.withIOContext(ctx, func() error { return client.sftp.RemoveDirectory(path) })
}

func (client *SSHClient) sftpReadLink(ctx context.Context, path string) (string, error) {
	var target string
	err := client.withIOContext(ctx, func() error {
		var operationErr error
		target, operationErr = client.sftp.ReadLink(path)
		return operationErr
	})
	return target, err
}

func (client *SSHClient) ObserveQualificationHost(ctx context.Context, expected release.OSProfile) (string, string, error) {
	machineID, err := client.readRemoteRegular(ctx, "/etc/machine-id", 4096)
	if err != nil {
		return "", "", err
	}
	value := strings.TrimSpace(string(machineID))
	if len(value) != 32 || !lowerHex(value) {
		return "", "", fmt.Errorf("remote machine identity is invalid")
	}
	sum := sha256.Sum256([]byte(value))
	fingerprint := "host_" + hex.EncodeToString(sum[:16])
	if err := client.verifyPlatform(ctx, expected); err != nil {
		return "", "", err
	}
	inventory, err := client.observeBeforeInventory(ctx)
	if err != nil {
		return "", "", err
	}
	return fingerprint, inventory, nil
}

func VerifyRemotePreflight(ctx context.Context, prepared Prepared) error {
	client, err := OpenSSH(ctx, prepared.Input.SSH)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	fingerprint, inventory, err := client.ObserveQualificationHost(ctx, prepared.Install.Identity().Profile)
	if err != nil {
		return err
	}
	if fingerprint != prepared.Input.SSH.MachineFingerprint {
		return fmt.Errorf("remote machine fingerprint differs from protected authority")
	}
	plan, err := release.DecodeLiveSideEffectPlan(prepared.PlanBytes)
	if err != nil {
		return err
	}
	for _, mutation := range plan.Mutations {
		if mutation.ID != "clean_install" {
			continue
		}
		expectedPrior := release.QualificationCleanInstallPriorState(fingerprint, inventory, prepared.Input.RunID)
		if mutation.PriorState != expectedPrior || mutation.PriorStateDigest != release.DigestBytes([]byte(expectedPrior)) {
			return fmt.Errorf("remote clean-host inventory or staging absence differs from immutable side-effect plan")
		}
		for _, path := range []string{"/var/lib/lanpanel-qualification", remoteStagingRoot(prepared.Input.RunID)} {
			if _, err := client.sftpLstat(ctx, path); err == nil || !os.IsNotExist(err) {
				return fmt.Errorf("remote qualification staging prior state is not absent")
			}
		}
		return nil
	}
	return fmt.Errorf("immutable side-effect plan omits clean installation")
}

func (client *SSHClient) verifyPlatform(ctx context.Context, expected release.OSProfile) error {
	osRelease, err := client.readRemoteOSRelease(ctx, 1<<20)
	if err != nil {
		return err
	}
	values := parseOSRelease(osRelease)
	if values["ID"] != expected.Family || values["VERSION_ID"] != expected.Release {
		return fmt.Errorf("remote OS release differs from qualification target profile")
	}
	stdout, _, err := client.runFixed(ctx, "/usr/bin/uname -m")
	if err != nil || strings.TrimSpace(string(stdout)) != "x86_64" {
		return fmt.Errorf("remote architecture differs from amd64: %w", err)
	}
	stdout, _, err = client.runFixed(ctx, "/usr/bin/systemd --version")
	if err != nil {
		return fmt.Errorf("remote systemd identity is unavailable: %w", err)
	}
	fields := strings.Fields(strings.SplitN(string(stdout), "\n", 2)[0])
	if len(fields) < 2 || fields[0] != "systemd" || fields[1] != expected.SystemdVersion {
		return fmt.Errorf("remote systemd version differs from qualification target profile")
	}
	return nil
}

func (client *SSHClient) observeBeforeInventory(ctx context.Context) (string, error) {
	hasher := sha256.New()
	for _, path := range bootstrap.BeforeInventoryPaths(bootstrap.FixedPaths()) {
		info, err := client.sftpLstat(ctx, path)
		if err != nil {
			if os.IsNotExist(err) {
				_, _ = fmt.Fprintf(hasher, "absent:%s\n", path)
				continue
			}
			return "", err
		}
		if info == nil {
			return "", fmt.Errorf("remote path observation is incomplete")
		}
		command := "/usr/bin/stat --format=%u:%g:%f:%d:%i:%s -- " + shellQuoteFixedPath(path)
		stdout, _, err := client.runFixed(ctx, command)
		if err != nil {
			return "", err
		}
		parts := strings.Split(strings.TrimSpace(string(stdout)), ":")
		if len(parts) != 6 {
			return "", fmt.Errorf("remote stat output is invalid")
		}
		uid, e1 := strconv.ParseUint(parts[0], 10, 32)
		gid, e2 := strconv.ParseUint(parts[1], 10, 32)
		mode, e3 := strconv.ParseUint(parts[2], 16, 32)
		device, e4 := strconv.ParseUint(parts[3], 10, 64)
		inode, e5 := strconv.ParseUint(parts[4], 10, 64)
		size, e6 := strconv.ParseInt(parts[5], 10, 64)
		if errors.Join(e1, e2, e3, e4, e5, e6) != nil || uint32(uid) != fileUID(info) || uint32(gid) != fileGID(info) || size != info.Size() || !remoteModeMatches(uint32(mode), info.Mode()) {
			return "", fmt.Errorf("remote path changed while observing clean inventory")
		}
		_, _ = fmt.Fprintf(hasher, "present:%s:%d:%d:%o:%d:%d:%d\n", path, uid, gid, mode, device, inode, size)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func (client *SSHClient) readRemoteVirtual(ctx context.Context, path string, maximum int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || maximum <= 0 {
		return nil, fmt.Errorf("remote virtual path is invalid")
	}
	info, err := client.sftpLstat(ctx, path)
	if err != nil || info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || fileUID(info) != 0 || info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("remote virtual file metadata is unsafe: %w", err)
	}
	var file *sftp.File
	if err := client.withIOContext(ctx, func() error {
		var openErr error
		file, openErr = client.sftp.Open(path)
		return openErr
	}); err != nil {
		return nil, err
	}
	var data []byte
	readErr := client.withIOContext(ctx, func() error {
		var operationErr error
		data, operationErr = io.ReadAll(io.LimitReader(file, maximum+1))
		return operationErr
	})
	closeErr := client.withIOContext(ctx, file.Close)
	if readErr != nil || closeErr != nil || len(data) == 0 || int64(len(data)) > maximum {
		return nil, errors.Join(readErr, closeErr, fmt.Errorf("remote virtual file is unreadable or unbounded"))
	}
	return data, nil
}

func (client *SSHClient) readRemoteOSRelease(ctx context.Context, maximum int64) ([]byte, error) {
	const aliasPath = "/etc/os-release"
	const aliasTarget = "../usr/lib/os-release"
	const targetPath = "/usr/lib/os-release"

	info, err := client.sftpLstat(ctx, aliasPath)
	if err != nil {
		return nil, err
	}
	if info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
		return client.readRemoteRegular(ctx, aliasPath, maximum)
	}
	if info == nil || info.Mode()&os.ModeSymlink == 0 {
		return nil, fmt.Errorf("remote OS release alias metadata is unsafe")
	}
	target, err := client.sftpReadLink(ctx, aliasPath)
	if err != nil {
		return nil, fmt.Errorf("read remote OS release alias: %w", err)
	}
	if target != aliasTarget {
		return nil, fmt.Errorf("remote OS release alias is nonstandard")
	}
	data, err := client.readRemoteRegular(ctx, targetPath, maximum)
	if err != nil {
		return nil, err
	}
	after, err := client.sftpLstat(ctx, aliasPath)
	if err != nil || after == nil || after.Mode()&os.ModeSymlink == 0 || after.Size() != info.Size() || after.Mode() != info.Mode() || after.ModTime() != info.ModTime() || fileUID(after) != fileUID(info) || fileGID(after) != fileGID(info) {
		return nil, fmt.Errorf("remote OS release alias changed while reading")
	}
	afterTarget, err := client.sftpReadLink(ctx, aliasPath)
	if err != nil || afterTarget != aliasTarget {
		return nil, fmt.Errorf("remote OS release alias changed while reading")
	}
	return data, nil
}

func (client *SSHClient) readRemoteRegular(ctx context.Context, path string, maximum int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || maximum <= 0 {
		return nil, fmt.Errorf("remote protected path is invalid")
	}
	info, err := client.sftpLstat(ctx, path)
	if err != nil {
		return nil, err
	}
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maximum || fileUID(info) != 0 || info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("remote protected file metadata is unsafe")
	}
	var file *sftp.File
	if err := client.withIOContext(ctx, func() error {
		var openErr error
		file, openErr = client.sftp.Open(path)
		return openErr
	}); err != nil {
		return nil, err
	}
	var data []byte
	readErr := client.withIOContext(ctx, func() error {
		var operationErr error
		data, operationErr = io.ReadAll(io.LimitReader(file, maximum+1))
		return operationErr
	})
	closeErr := client.withIOContext(ctx, file.Close)
	if readErr != nil || closeErr != nil || int64(len(data)) != info.Size() {
		return nil, errors.Join(readErr, closeErr, fmt.Errorf("remote protected file changed while reading"))
	}
	after, err := client.sftpLstat(ctx, path)
	if err != nil || after == nil || after.Size() != info.Size() || after.Mode() != info.Mode() || after.ModTime() != info.ModTime() || fileUID(after) != fileUID(info) || fileGID(after) != fileGID(info) {
		return nil, fmt.Errorf("remote protected file changed while reading")
	}
	return data, nil
}

func (client *SSHClient) runFixed(ctx context.Context, command string) ([]byte, []byte, error) {
	return client.runFixedInput(ctx, command, nil, 1<<20)
}

func (client *SSHClient) RunAgent(ctx context.Context, remoteBinary string, request AgentRequest) (AgentResponse, error) {
	if !validRemoteAgentPath(remoteBinary, request.Action) {
		return AgentResponse{}, fmt.Errorf("remote qualification candidate path is invalid")
	}
	data, err := release.MarshalCanonical(request)
	if err != nil {
		return AgentResponse{}, err
	}
	stdout, stderr, err := client.runFixedInput(ctx, shellQuoteFixedPath(remoteBinary)+" qualification-agent", data, 4<<20)
	if err != nil {
		return AgentResponse{}, fmt.Errorf("remote qualification agent failed: %w: %s", err, stderr)
	}
	return DecodeAgentResponse(stdout, request.RunID, request.Action)
}

func (client *SSHClient) runFixedInput(ctx context.Context, command string, input []byte, maximum int) ([]byte, []byte, error) {
	if command == "" || len(command) > 4096 || strings.ContainsAny(command, "\x00\r\n") || maximum <= 0 || maximum > 8<<20 {
		return nil, nil, fmt.Errorf("fixed SSH command is invalid")
	}
	var session *ssh.Session
	if err := client.withIOContext(ctx, func() error {
		var sessionErr error
		session, sessionErr = client.client.NewSession()
		return sessionErr
	}); err != nil {
		return nil, nil, err
	}
	var stdout, stderr boundedBuffer
	stdout.maximum, stderr.maximum = maximum, maximum
	session.Stdout, session.Stderr = &stdout, &stderr
	if input != nil {
		session.Stdin = bytes.NewReader(input)
	}
	runErr := client.withCommandContext(ctx, func() error { return session.Run(command) })
	// The close is itself bounded. If cancellation already closed the transport,
	// withIOContext returns immediately instead of waiting for a session goroutine.
	_ = client.closeSessionContext(ctx, session)
	if stdout.exceeded || stderr.exceeded {
		return nil, nil, errors.Join(runErr, fmt.Errorf("fixed SSH command output exceeded its bound"))
	}
	return stdout.Bytes(), stderr.Bytes(), runErr
}

type boundedBuffer struct {
	bytes.Buffer
	maximum  int
	exceeded bool
}

func (buffer *boundedBuffer) Write(data []byte) (int, error) {
	original := len(data)
	remaining := buffer.maximum - buffer.Len()
	if remaining <= 0 {
		buffer.exceeded = true
		return original, nil
	}
	if len(data) > remaining {
		data = data[:remaining]
		buffer.exceeded = true
	}
	_, _ = buffer.Buffer.Write(data)
	return original, nil
}

func resolveSSHCredential(reference string) (ssh.AuthMethod, func(), error) {
	switch {
	case strings.HasPrefix(reference, "file:"):
		path := strings.TrimPrefix(reference, "file:")
		data, _, err := readProtectedFile(path, 1<<20, false)
		if err != nil {
			return nil, func() {}, err
		}
		signer, err := ssh.ParsePrivateKey(data)
		clearBytes(data)
		if err != nil {
			return nil, func() {}, fmt.Errorf("parse unencrypted SSH private key: %w", err)
		}
		return ssh.PublicKeys(signer), func() {}, nil
	case strings.HasPrefix(reference, "agent:"):
		spec := strings.TrimPrefix(reference, "agent:")
		path, digest, present := strings.Cut(spec, "#")
		if !present || !filepath.IsAbs(path) || filepath.Clean(path) != path || !strings.HasPrefix(digest, "sha256:") || !release.ValidDigest(strings.TrimPrefix(digest, "sha256:")) {
			return nil, func() {}, fmt.Errorf("SSH agent reference is invalid")
		}
		connection, err := openOwnedAgent(path)
		if err != nil {
			return nil, func() {}, err
		}
		client := agent.NewClient(connection)
		signers, err := client.Signers()
		if err != nil {
			_ = connection.Close()
			return nil, func() {}, err
		}
		selected := []ssh.Signer{}
		for _, signer := range signers {
			if release.DigestBytes(signer.PublicKey().Marshal()) == strings.TrimPrefix(digest, "sha256:") {
				selected = append(selected, signer)
			}
		}
		if len(selected) != 1 {
			_ = connection.Close()
			return nil, func() {}, fmt.Errorf("SSH agent did not expose exactly one pinned signer")
		}
		return ssh.PublicKeys(selected[0]), func() { _ = connection.Close() }, nil
	default:
		return nil, func() {}, fmt.Errorf("SSH credential reference kind is not implemented")
	}
}

func openOwnedAgent(path string) (net.Conn, error) {
	var stat unix.Stat_t
	if unix.Lstat(path, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFSOCK || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o077 != 0 {
		return nil, fmt.Errorf("SSH agent socket authority is unsafe")
	}
	return net.DialTimeout("unix", path, 5*time.Second)
}

func pinnedHostKey(expected string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if release.DigestBytes(key.Marshal()) != expected {
			return fmt.Errorf("SSH host key differs from pinned authority")
		}
		return nil
	}
}

func canonicalSSHAddress(value string) (string, error) {
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" || port == "" {
		return "", fmt.Errorf("SSH address must be an exact IP:port")
	}
	address, err := netip.ParseAddr(host)
	parsedPort, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || portErr != nil || !address.Is4() || address.String() != host || parsedPort == 0 || strconv.FormatUint(parsedPort, 10) != port {
		return "", fmt.Errorf("SSH address must be a canonical IPv4:port")
	}
	return net.JoinHostPort(host, port), nil
}

func validRemoteAgentPath(value string, action AgentAction) bool {
	return validRemoteRunPath(value) || value == bootstrap.FixedPaths().BinaryPath && action == AgentFinalInventory
}

func validRemoteRunPath(value string) bool {
	const prefix = "/var/lib/lanpanel-qualification/run_"
	if !strings.HasPrefix(value, prefix) || filepath.Clean(value) != value || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	rest := strings.TrimPrefix(value, prefix)
	runID, _, _ := strings.Cut(rest, "/")
	return len(runID) == 64 && lowerHex(runID)
}

func shellQuoteFixedPath(path string) string {
	return "'" + strings.ReplaceAll(path, "'", "'\\''") + "'"
}

func parseOSRelease(data []byte) map[string]string {
	result := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, present := strings.Cut(line, "=")
		if !present || key != "ID" && key != "VERSION_ID" {
			continue
		}
		value = strings.Trim(value, "\"")
		result[key] = value
	}
	return result
}

func remoteModeMatches(mode uint32, observed os.FileMode) bool {
	if mode&0o7777 != uint32(observed.Perm()) {
		return false
	}
	switch mode & syscall.S_IFMT {
	case syscall.S_IFREG:
		return observed.IsRegular()
	case syscall.S_IFDIR:
		return observed.IsDir()
	case syscall.S_IFLNK:
		return observed&os.ModeSymlink != 0
	case syscall.S_IFSOCK:
		return observed&os.ModeSocket != 0
	default:
		return observed.Type() != 0
	}
}

func fileUID(info os.FileInfo) uint32 {
	if stat, ok := info.Sys().(*sftp.FileStat); ok {
		return stat.UID
	}
	return ^uint32(0)
}

func fileGID(info os.FileInfo) uint32 {
	if stat, ok := info.Sys().(*sftp.FileStat); ok {
		return stat.GID
	}
	return ^uint32(0)
}

func lowerHex(value string) bool {
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
