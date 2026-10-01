//go:build linux

package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/helper"
	"lanpanel/internal/identity"
	"lanpanel/internal/locks"
	"lanpanel/internal/nginx"
	"lanpanel/internal/ownership"
	"lanpanel/internal/persist"
	"lanpanel/internal/release"
	"lanpanel/internal/safety"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const fixedTimerPeriod = "5min"

func renderArtifacts(journal Journal) (map[string][]byte, error) {
	binary := journal.Paths.BinaryPath
	accounts := map[identity.AccountRole]identity.AccountIdentity{}
	for _, value := range journal.Accounts.Identities {
		accounts[value.Role] = value
	}
	for _, role := range []identity.AccountRole{identity.RoleUI, identity.RoleTimer, identity.RoleRecovery} {
		if accounts[role].UID == 0 {
			return nil, fmt.Errorf("systemd assets require verified numeric identities")
		}
	}
	authority := fmt.Sprintf("%s:%d", journal.Authority.Address, journal.Authority.Port)
	socketGeneration := journal.GenerationID
	nginxPaths := nginx.FixedPaths()
	if journal.Paths != FixedPaths() {
		nginxPaths = testNginxPaths(journal.Paths)
	}
	artifacts := map[string][]byte{
		filepath.Join(journal.Paths.SystemdRoot, "lanpanel-management.socket"): []byte("[Unit]\nDescription=LanPanel reserved Management authority\nBefore=lanpanel-ui.service\nAfter=lanpanel-runtime.service\nRequires=lanpanel-runtime.service\n\n[Socket]\nListenStream=" + authority + "\nFileDescriptorName=lanpanel-management-" + socketGeneration + "\nSocketMode=0600\nRemoveOnStop=no\nService=lanpanel-ui.service\n\n[Install]\nWantedBy=sockets.target\n"),
		filepath.Join(journal.Paths.SystemdRoot, "lanpanel-ui.service"):        []byte(serviceUnit("LanPanel Management UI", accounts[identity.RoleUI], binary+" ui", "LANPANEL_SOCKET_GENERATION="+socketGeneration, "lanpanel-management.socket")),
		filepath.Join(journal.Paths.SystemdRoot, "lanpanel-runtime.service"):   []byte("[Unit]\nDescription=LanPanel volatile runtime directory\nBefore=lanpanel-helper.service lanpanel-management.socket\n\n[Service]\nType=oneshot\nExecStart=" + binary + " runtime-guard\nRemainAfterExit=yes\n\n[Install]\nWantedBy=multi-user.target\n"),
		filepath.Join(journal.Paths.SystemdRoot, "lanpanel-helper.service"):    []byte("[Unit]\nDescription=LanPanel privileged helper\nConditionPathExists=" + journal.Paths.CommitPath + "\nAfter=local-fs.target lanpanel-runtime.service\nRequires=lanpanel-runtime.service\n\n[Service]\nType=notify\nNotifyAccess=main\nExecStart=" + binary + " helper\nExecStopPost=+" + binary + " process-boot-clear\nUser=root\nGroup=root\nKillMode=control-group\nDelegate=yes\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nReadWritePaths=/var/lib/lanpanel /var/lib/lanpanel.bootstrap-journal /var/log/lanpanel /run/lanpanel /run/lanpanel-goaccess /etc/lanpanel /etc/lanpanel-public /etc/systemd/system /etc/sysusers.d /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/.pwd.lock /etc/apt /etc/dpkg /var/lib/apt /var/cache/apt /var/lib/dpkg /usr /opt /lib /lib64 /boot /etc\nRestart=on-failure\n\n[Install]\nWantedBy=multi-user.target\n"),
		filepath.Join(journal.Paths.SystemdRoot, "lanpanel-timer.service"):     []byte(timerServiceUnit(accounts[identity.RoleTimer], binary+" timer")),
		filepath.Join(journal.Paths.SystemdRoot, "lanpanel-timer.timer"):       []byte("[Unit]\nDescription=LanPanel persistent timer\n\n[Timer]\nOnBootSec=2min\nOnUnitActiveSec=" + fixedTimerPeriod + "\nPersistent=true\nUnit=lanpanel-timer.service\n\n[Install]\nWantedBy=timers.target\n"),
		filepath.Join(journal.Paths.SystemdRoot, "lanpanel-recovery.service"):  []byte("[Unit]\nDescription=LanPanel startup contraction recovery\nConditionPathExists=" + journal.Paths.CommitPath + "\nAfter=local-fs.target lanpanel-helper.service\nRequires=lanpanel-helper.service\nBefore=lanpanel-nginx.service\n\n[Service]\nType=oneshot\nExecStart=" + binary + " startup-recovery\nUser=" + fmt.Sprint(accounts[identity.RoleRecovery].UID) + "\nGroup=" + fmt.Sprint(accounts[identity.RoleRecovery].GID) + "\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=yes\nRestrictSUIDSGID=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nRestrictAddressFamilies=AF_UNIX\nUMask=0077\nRemainAfterExit=yes\n\n[Install]\nWantedBy=multi-user.target\n"),
		filepath.Join(journal.Paths.SystemdRoot, "lanpanel-nginx.service"):     []byte("[Unit]\nDescription=LanPanel closed Nginx master\nConditionPathExists=" + journal.Paths.CommitPath + "\nAfter=network.target lanpanel-helper.service lanpanel-recovery.service\nRequires=lanpanel-helper.service lanpanel-recovery.service\nConflicts=nginx.service\n\n[Service]\nType=simple\nPIDFile=" + nginxPaths.PIDPath + "\nExecStart=" + binary + " startup-guard\nExecReload=" + binary + " reload-guard\nExecStop=" + binary + " reload-guard stop\nTimeoutStartSec=60s\nTimeoutStopSec=60s\nKillMode=control-group\nDelegate=yes\nRestart=no\nUser=root\nGroup=root\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nReadWritePaths=" + nginxPaths.ConfigRoot + " " + nginxPaths.StateRoot + " " + filepath.Dir(nginxPaths.PIDPath) + " " + nginxPaths.AuditPath + " /var/lib/lanpanel.bootstrap-journal /var/lib/lanpanel/locks /var/lib/lanpanel/safety /var/lib/lanpanel/state /var/lib/lanpanel/ownership /var/lib/lanpanel/certificates /var/log/lanpanel/goaccess\nCapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_KILL CAP_SETGID CAP_SETUID CAP_SETPCAP CAP_NET_BIND_SERVICE\nAmbientCapabilities=\n\n[Install]\nWantedBy=multi-user.target\n"),
	}
	return artifacts, nil
}

func timerServiceUnit(account identity.AccountIdentity, command string) string {
	return strings.Replace(serviceUnit("LanPanel timer dispatcher", account, command, "", ""), "After=local-fs.target\n", "After=local-fs.target lanpanel-helper.service\nRequires=lanpanel-helper.service\n", 1)
}

func serviceUnit(description string, account identity.AccountIdentity, command, environment, socket string) string {
	var output strings.Builder
	fmt.Fprintf(&output, "[Unit]\nDescription=%s\nConditionPathExists=/var/lib/lanpanel/bootstrap-commit.json\nAfter=local-fs.target", description)
	if socket != "" {
		fmt.Fprintf(&output, " %s", socket)
	}
	output.WriteString("\n\n[Service]\nType=simple\nExecStart=" + command + "\n")
	fmt.Fprintf(&output, "User=%d\nGroup=%d\n", account.UID, account.GID)
	if environment != "" {
		output.WriteString("Environment=" + environment + "\n")
	}
	if socket != "" {
		output.WriteString("Sockets=lanpanel-management.socket\nStateDirectory=lanpanel-management-audit\nStateDirectoryMode=0700\n")
	}
	output.WriteString("NoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=yes\nRestrictSUIDSGID=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nLockPersonality=yes\nRestrictRealtime=yes\nUMask=0077\n")
	if socket != "" {
		output.WriteString("RestrictAddressFamilies=AF_INET AF_UNIX\nPrivateDevices=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectKernelLogs=yes\n")
	}
	output.WriteString("Restart=on-failure\n\n[Install]\nWantedBy=multi-user.target\n")
	return output.String()
}

func ensureDirectory(path string, owner filetxn.Owner, mode uint32) (bool, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return false, fmt.Errorf("bootstrap directory path is invalid")
	}
	parent := filepath.Dir(path)
	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, err
	}
	defer func() { _ = unix.Close(parentFD) }()
	var parentStat unix.Stat_t
	if err := unix.Fstat(parentFD, &parentStat); err != nil || parentStat.Mode&unix.S_IFMT != unix.S_IFDIR || parentStat.Uid != 0 || parentStat.Mode&0o022 != 0 && (path != "/var/log/lanpanel" || parentStat.Mode&0o002 != 0) {
		return false, fmt.Errorf("bootstrap directory parent is unsafe for %q", path)
	}
	created := false
	if err := unix.Mkdirat(parentFD, filepath.Base(path), mode); errors.Is(err, unix.EEXIST) {
	} else if err != nil {
		return false, err
	} else {
		created = true
	}
	fd, err := unix.Openat(parentFD, filepath.Base(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, err
	}
	defer func() { _ = unix.Close(fd) }()
	if created {
		if err := unix.Fchown(fd, int(owner.UID), int(owner.GID)); err != nil {
			return false, err
		}
		if err := unix.Fchmod(fd, mode); err != nil {
			return false, err
		}
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != owner.UID || stat.Gid != owner.GID || stat.Mode&0o7777 != mode {
		return false, fmt.Errorf("bootstrap directory identity differs for %q (owner=%d:%d mode=%04o)", path, owner.UID, owner.GID, mode)
	}
	if created && unix.Fsync(parentFD) != nil {
		return false, fmt.Errorf("sync bootstrap directory")
	}
	return created, nil
}

func ensureRuntimeDirectory(path string, owner filetxn.Owner) (bool, error) {
	created, err := ensureDirectory(path, owner, 0o711)
	if err == nil {
		return created, nil
	}
	parent := filepath.Dir(path)
	parentFD, parentErr := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if parentErr != nil {
		return false, errors.Join(err, parentErr)
	}
	defer func() { _ = unix.Close(parentFD) }()
	fd, openErr := unix.Openat(parentFD, filepath.Base(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if openErr != nil {
		return false, errors.Join(err, openErr)
	}
	defer func() { _ = unix.Close(fd) }()
	var stat unix.Stat_t
	if statErr := unix.Fstat(fd, &stat); statErr != nil {
		return false, errors.Join(err, statErr)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != owner.UID || stat.Gid != owner.GID || stat.Mode&0o7777 != 0o710 {
		return false, err
	}
	if chmodErr := unix.Fchmod(fd, 0o711); chmodErr != nil {
		return false, errors.Join(err, chmodErr)
	}
	if syncErr := unix.Fsync(parentFD); syncErr != nil {
		return false, errors.Join(err, syncErr)
	}
	return false, nil
}

func targetStaging(path string) (string, error) {
	directory := filepath.Dir(path)
	staging := filepath.Join(directory, ".lanpanel-filetxn")
	_, err := ensureDirectory(staging, filetxn.Owner{UID: 0, GID: 0}, 0o700)
	return staging, err
}

func putRootGroupFileWithOptions(ctx context.Context, path string, data []byte, gid uint32, mode os.FileMode, options filetxn.Options) error {
	parent := filepath.Dir(path)
	staging := filepath.Join(parent, ".lanpanel-filetxn")
	if _, err := ensureDirectory(staging, filetxn.Owner{UID: 0, GID: 0}, 0o700); err != nil {
		return err
	}
	root := filetxn.Owner{UID: 0, GID: 0}
	parents := filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{root, {UID: 0, GID: gid}}, AllowedMode: 0o755}
	store, err := filetxn.Open(filetxn.Config{RootPath: "/", Root: filetxn.Metadata{Owner: root, Mode: 0o755}, StagingPath: staging, Staging: filetxn.Metadata{Owner: root, Mode: 0o700}, StagingParents: parents}, options)
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(store.Close)
	metadata := filetxn.Metadata{Owner: filetxn.Owner{UID: 0, GID: gid}, Mode: mode}
	_, err = store.Put(ctx, filetxn.Request{Path: path, Parents: parents, Existing: &metadata, New: metadata, MaxBytes: int64(len(data))}, data, filetxn.CreateOnly)
	return err
}

func putOrVerifyStartupAuthority(ctx context.Context, path string, expected StartupAuthority, gid uint32) error {
	return putOrVerifyStartupAuthorityWithOptions(ctx, path, expected, gid, filetxn.Options{})
}

func putOrVerifyStartupAuthorityWithOptions(ctx context.Context, path string, expected StartupAuthority, gid uint32, options filetxn.Options) error {
	data, err := encodeCanonical(expected)
	if err != nil {
		return err
	}
	if err := putRootGroupFileWithOptions(ctx, path, data, gid, 0o640, options); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return finalizeStartupAuthorityFile(path, expected, 0, gid)
}

func finalizeStartupAuthorityFile(path string, expected StartupAuthority, uid, gid uint32) error {
	if err := verifyStartupAuthorityFile(path, expected, uid, gid); err != nil {
		return err
	}
	return syncParentDirectory(path)
}

func verifyStartupAuthorityFile(path string, expected StartupAuthority, uid, gid uint32) error {
	if expected.SchemaVersion != "lanpanel.startup-authority.v1" || !identity.ValidateAttemptID(expected.AttemptID) || !identity.ValidateInstallationID(expected.InstallationID) || !identity.ValidateGenerationID(expected.GenerationID) || identity.ValidateManagementAuthority(expected.Management) != nil || !release.ValidDigest(expected.CommitDigest) {
		return fmt.Errorf("expected startup authority binding is invalid")
	}
	data, err := encodeCanonical(expected)
	if err != nil {
		return err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("startup authority descriptor is invalid")
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Uid != uid || before.Gid != gid || before.Mode&0o777 != 0o640 || before.Size != int64(len(data)) {
		return fmt.Errorf("existing startup authority metadata is foreign")
	}
	actual, readErr := io.ReadAll(io.LimitReader(file, int64(len(data))+1))
	if readErr != nil || !bytes.Equal(actual, data) || unix.Fstat(fd, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || before.Mode != after.Mode || before.Nlink != after.Nlink || before.Uid != after.Uid || before.Gid != after.Gid {
		return fmt.Errorf("existing startup authority bytes or metadata are foreign or changed")
	}
	var decoded StartupAuthority
	if decodeCanonical(actual, &decoded) != nil || !reflect.DeepEqual(decoded, expected) {
		return fmt.Errorf("existing startup authority binding is foreign")
	}
	return nil
}

func syncParentDirectory(path string) error {
	parent := filepath.Dir(path)
	fd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	syncErr := unix.Fsync(fd)
	closeErr := unix.Close(fd)
	return errors.Join(syncErr, closeErr)
}

func putOrVerifyTargetFile(ctx context.Context, path string, data []byte, mode os.FileMode) error {
	staging, err := targetStaging(path)
	if err != nil {
		return err
	}
	if filepath.Dir(path) == "/var/log/lanpanel" {
		return putOrVerifyRootFileWithMode(ctx, "/var/log/lanpanel", 0o711, staging, path, data, mode)
	}
	return putOrVerifyRootFile(ctx, "/", staging, path, data, mode)
}

func putOrVerifyRootFile(ctx context.Context, root, staging, path string, data []byte, mode os.FileMode) error {
	rootMode := os.FileMode(0o700)
	if root == "/" {
		rootMode = 0o755
	}
	return putOrVerifyRootFileWithMode(ctx, root, rootMode, staging, path, data, mode)
}

func putOrVerifyRootFileWithMode(ctx context.Context, root string, rootMode os.FileMode, staging, path string, data []byte, mode os.FileMode) error {
	err := putRootFileWithRootMode(ctx, root, rootMode, staging, path, data, mode, filetxn.CreateOnly)
	if !errors.Is(err, os.ErrExist) {
		return err
	}
	actual, readErr := readCommittedArtifact(path, int64(max(len(data), 1)), uint32(mode.Perm()))
	if readErr != nil || !bytes.Equal(actual, data) {
		return fmt.Errorf("existing bootstrap artifact %q is foreign", path)
	}
	return nil
}

func putRootFile(ctx context.Context, root, staging, path string, data []byte, mode os.FileMode, disposition filetxn.Disposition) error {
	rootMode := os.FileMode(0o700)
	if root == "/" {
		rootMode = 0o755
	}
	return putRootFileWithRootMode(ctx, root, rootMode, staging, path, data, mode, disposition)
}

func putRootFileWithRootMode(ctx context.Context, root string, rootMode os.FileMode, staging, path string, data []byte, mode os.FileMode, disposition filetxn.Disposition) error {
	owner := filetxn.Owner{UID: 0, GID: 0}
	parentsMode := os.FileMode(0o755)
	if root != "/" {
		parentsMode = rootMode
	}
	store, err := filetxn.Open(filetxn.Config{RootPath: root, Root: filetxn.Metadata{Owner: owner, Mode: rootMode}, StagingPath: staging, Staging: filetxn.Metadata{Owner: owner, Mode: 0o700}, StagingParents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: parentsMode}}, filetxn.Options{})
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(store.Close)
	metadata := filetxn.Metadata{Owner: owner, Mode: mode}
	_, err = store.Put(ctx, filetxn.Request{Path: path, Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o755}, Existing: &metadata, New: metadata, MaxBytes: max(int64(len(data)), 1)}, data, disposition)
	return err
}

func copyOrVerifyPolicyBytes(data []byte, expected release.AssetIdentity, paths Paths) error {
	if uint64(len(data)) != expected.Bytes || digestBytes(data) != expected.Digest {
		return fmt.Errorf("package no-autostart policy bytes differ")
	}
	destination := "/usr/sbin/policy-rc.d"
	if paths != FixedPaths() {
		if _, err := ensureDirectory(paths.PersistentRoot, filetxn.Owner{UID: 0, GID: 0}, 0o711); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		destination = filepath.Join(paths.PersistentRoot, "sbin", "policy-rc.d")
		if _, err := ensureDirectory(filepath.Dir(destination), filetxn.Owner{UID: 0, GID: 0}, 0o755); err != nil {
			return err
		}
	}
	return putOrVerifyTargetFile(context.Background(), destination, data, 0o755)
}

func copyOrVerifyBinaryBytes(data []byte, paths Paths, expected releaseBinary) error {
	if uint64(len(data)) != expected.Bytes || digestBytes(data) != expected.Digest {
		return fmt.Errorf("bootstrap binary bytes differ")
	}
	return putOrVerifyTargetFile(context.Background(), paths.BinaryPath, data, 0o755)
}

func removeBootstrapPolicy(expected release.AssetIdentity, paths Paths) error {
	return removeBootstrapPolicyWithSync(expected, paths, unix.Fsync, syncParentDirectory)
}

func removeBootstrapPolicyWithSync(expected release.AssetIdentity, paths Paths, syncOpen func(int) error, syncAbsent func(string) error) error {
	if syncOpen == nil || syncAbsent == nil {
		return fmt.Errorf("package no-autostart policy sync authority is unavailable")
	}
	path := "/usr/sbin/policy-rc.d"
	uid, gid := uint32(0), uint32(0)
	if paths != FixedPaths() {
		path = filepath.Join(paths.PersistentRoot, "sbin", "policy-rc.d")
		uid, gid = uint32(os.Geteuid()), uint32(os.Getegid())
	}
	data, identity, err := readExactRegularFile(path, int64(expected.Bytes), uid, gid, 0o755)
	if errors.Is(err, os.ErrNotExist) {
		return syncAbsent(path)
	}
	if err != nil || uint64(len(data)) != expected.Bytes || digestBytes(data) != expected.Digest {
		return fmt.Errorf("package no-autostart policy changed before cleanup")
	}
	parent := filepath.Dir(path)
	fd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	var current unix.Stat_t
	if err := unix.Fstatat(fd, filepath.Base(path), &current, unix.AT_SYMLINK_NOFOLLOW); err != nil || current.Dev != identity.Dev || current.Ino != identity.Ino || current.Ctim != identity.Ctim || current.Mode != identity.Mode || current.Nlink != identity.Nlink || current.Uid != identity.Uid || current.Gid != identity.Gid || current.Size != identity.Size {
		return fmt.Errorf("package no-autostart policy identity changed before cleanup")
	}
	if err := unix.Unlinkat(fd, filepath.Base(path), 0); err != nil {
		return err
	}
	return syncOpen(fd)
}

func readExactRegularFile(path string, maximum int64, uid, gid uint32, mode uint32) ([]byte, unix.Stat_t, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, unix.Stat_t{}, err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return nil, unix.Stat_t{}, fmt.Errorf("exact regular file descriptor is invalid")
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Uid != uid || before.Gid != gid || before.Mode&0o777 != mode || before.Size <= 0 || before.Size > maximum {
		return nil, unix.Stat_t{}, fmt.Errorf("exact regular file metadata is foreign")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	if readErr != nil || int64(len(data)) != before.Size || unix.Fstat(fd, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || before.Mode != after.Mode || before.Nlink != after.Nlink || before.Uid != after.Uid || before.Gid != after.Gid {
		return nil, unix.Stat_t{}, fmt.Errorf("exact regular file changed while reading")
	}
	return data, after, nil
}

type releaseBinary struct {
	Digest string
	Bytes  uint64
}

func initializeStores(ctx context.Context, journal Journal) error {
	owner := filetxn.Owner{UID: 0, GID: 0}
	for _, directory := range []string{journal.Paths.LockRoot, journal.Paths.StateRoot, filepath.Join(journal.Paths.StateRoot, ".filetxn"), journal.Paths.OwnershipRoot, filepath.Join(journal.Paths.OwnershipRoot, ".filetxn"), filepath.Join(journal.Paths.OwnershipRoot, "records"), journal.Paths.SafetyRoot, filepath.Join(journal.Paths.SafetyRoot, ".filetxn")} {
		if _, err := ensureDirectory(directory, owner, 0o700); err != nil {
			return err
		}
	}
	manager, err := locks.Open(locks.Config{RootPath: journal.Paths.LockRoot, Owner: 0, Group: 0, Mode: 0o700})
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(manager.Close)
	exposure, err := manager.Acquire(ctx, locks.Exposure)
	if err != nil {
		return err
	}
	ownershipStore, err := ownership.Open(ownership.Config{RootPath: journal.Paths.OwnershipRoot, StagingPath: filepath.Join(journal.Paths.OwnershipRoot, ".filetxn"), RecordsPath: filepath.Join(journal.Paths.OwnershipRoot, "records"), Owner: owner, Policy: ownership.FixedPolicy(), LockAuthority: manager.Authority()})
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(ownershipStore.Close)
	emergencyPath := filepath.Join(journal.Paths.SafetyRoot, "emergency")
	emergency, err := safety.CreateEmergency(emergencyPath, owner, safety.EmergencyOptions{LockAuthority: manager.Authority()})
	if errors.Is(err, os.ErrExist) {
		emergency, err = safety.OpenEmergency(emergencyPath, owner, safety.EmergencyOptions{LockAuthority: manager.Authority()})
	}
	if err != nil {
		_ = exposure.Release()
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(emergency.Close)
	safetyStore, err := safety.OpenStore(safety.StoreConfig{RootPath: journal.Paths.SafetyRoot, StagingPath: filepath.Join(journal.Paths.SafetyRoot, ".filetxn"), StatePath: filepath.Join(journal.Paths.SafetyRoot, "state.json"), Owner: owner, Emergency: emergency, LockAuthority: manager.Authority(), Ownership: ownershipStore})
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(safetyStore.Close)
	if _, err := safetyStore.Read(); errors.Is(err, safety.ErrSafetyStateMissing) {
		if _, err := safetyStore.Initialize(ctx, exposure); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := exposure.Release(); err != nil {
		return err
	}
	normal, err := persist.Open(persist.Config{RootPath: journal.Paths.StateRoot, StagingPath: filepath.Join(journal.Paths.StateRoot, ".filetxn"), StatePath: filepath.Join(journal.Paths.StateRoot, "normal.json"), Owner: owner, LockAuthority: manager.Authority()})
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(normal.Close)
	admission, err := manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return err
	}
	if _, err := normal.Read(); errors.Is(err, persist.ErrMissing) {
		if _, err := normal.Initialize(ctx, admission); err != nil {
			_ = admission.Release()
			return err
		}
	} else if err != nil {
		_ = admission.Release()
		return err
	}
	installation := domain.Installation{SchemaVersion: domain.InstallationSchemaVersion, InstallationID: journal.InstallationID, Management: domain.ManagementAuthority{Address: journal.Authority.Address, Port: journal.Authority.Port, ManagedPaths: []string{journal.Paths.InstallationRoot}}}
	if err := domain.ValidateInstallation(installation); err != nil {
		return err
	}
	document, err := normal.Read()
	if err != nil {
		return err
	}
	if _, present := document.Entries["installations/current"]; !present {
		raw, _ := persist.EncodeEntry(installation)
		if _, _, err := normal.Update(ctx, admission, document.Revision, func(transaction *persist.Transaction) error { return transaction.Create("installations/current", raw) }); err != nil {
			_ = admission.Release()
			return err
		}
	} else {
		var installed domain.Installation
		raw := document.Entries["installations/current"]
		if json.Unmarshal(raw, &installed) != nil || installed.InstallationID != installation.InstallationID || !reflect.DeepEqual(installed.Management, installation.Management) {
			_ = admission.Release()
			return fmt.Errorf("normal installation state differs from bootstrap authority")
		}
	}
	return admission.Release()
}

func artifactInventoryDigest(values map[string]string) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	hasher := sha256.New()
	for _, key := range keys {
		_, _ = fmt.Fprintf(hasher, "%d:%s:%s\n", len(key), key, values[key])
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

var (
	_ = bytes.Equal
	_ = helper.FixedIdentityConfigPath
)
