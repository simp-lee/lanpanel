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
	"lanpanel/internal/child"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/helper"
	"lanpanel/internal/identity"
	"lanpanel/internal/locks"
	"lanpanel/internal/ownership"
	"lanpanel/internal/persist"
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
	artifacts := map[string][]byte{
		filepath.Join(journal.Paths.SystemdRoot, "lanpanel-management.socket"): []byte("[Unit]\nDescription=LanPanel reserved Management authority\nBefore=lanpanel-ui.service\nAfter=lanpanel-runtime.service\nRequires=lanpanel-runtime.service\n\n[Socket]\nListenStream=" + authority + "\nFileDescriptorName=lanpanel-management-" + socketGeneration + "\nSocketMode=0600\nRemoveOnStop=no\nService=lanpanel-ui.service\n\n[Install]\nWantedBy=sockets.target\n"),
		filepath.Join(journal.Paths.SystemdRoot, "lanpanel-ui.service"):        []byte(serviceUnit("LanPanel Management UI", accounts[identity.RoleUI], binary+" ui", "LANPANEL_SOCKET_GENERATION="+socketGeneration, "lanpanel-management.socket")),
		filepath.Join(journal.Paths.SystemdRoot, "lanpanel-runtime.service"):   []byte("[Unit]\nDescription=LanPanel volatile runtime directory\nBefore=lanpanel-helper.service lanpanel-management.socket\n\n[Service]\nType=oneshot\nExecStart=" + binary + " runtime-guard\nRemainAfterExit=yes\n\n[Install]\nWantedBy=multi-user.target\n"),
		filepath.Join(journal.Paths.SystemdRoot, "lanpanel-helper.service"):    []byte("[Unit]\nDescription=LanPanel privileged helper\nConditionPathExists=" + journal.Paths.CommitPath + "\nAfter=local-fs.target lanpanel-runtime.service\nRequires=lanpanel-runtime.service\n\n[Service]\nType=simple\nExecStart=" + binary + " helper\nUser=root\nGroup=root\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nReadWritePaths=/var/lib/lanpanel /run/lanpanel /etc/lanpanel /etc/systemd/system /etc/apt /etc/dpkg /var/lib/apt /var/cache/apt /var/lib/dpkg /usr /opt /lib /lib64 /boot\nRestart=on-failure\n\n[Install]\nWantedBy=multi-user.target\n"),
		filepath.Join(journal.Paths.SystemdRoot, "lanpanel-timer.service"):     []byte(serviceUnit("LanPanel timer dispatcher", accounts[identity.RoleTimer], binary+" timer", "", "")),
		filepath.Join(journal.Paths.SystemdRoot, "lanpanel-timer.timer"):       []byte("[Unit]\nDescription=LanPanel persistent timer\n\n[Timer]\nOnBootSec=2min\nOnUnitActiveSec=" + fixedTimerPeriod + "\nPersistent=true\nUnit=lanpanel-timer.service\n\n[Install]\nWantedBy=timers.target\n"),
		filepath.Join(journal.Paths.SystemdRoot, "lanpanel-recovery.service"):  []byte(serviceUnit("LanPanel startup recovery", accounts[identity.RoleRecovery], binary+" startup-guard", "", "")),
	}
	return artifacts, nil
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
		output.WriteString("Sockets=lanpanel-management.socket\n")
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
	defer unix.Close(parentFD)
	var parentStat unix.Stat_t
	if err := unix.Fstat(parentFD, &parentStat); err != nil || parentStat.Mode&unix.S_IFMT != unix.S_IFDIR || parentStat.Uid != 0 || parentStat.Mode&0o022 != 0 {
		return false, fmt.Errorf("bootstrap directory parent is unsafe")
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
	defer unix.Close(fd)
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
		return false, fmt.Errorf("bootstrap directory identity differs")
	}
	if created && unix.Fsync(parentFD) != nil {
		return false, fmt.Errorf("sync bootstrap directory")
	}
	return created, nil
}

func targetStaging(path string) (string, error) {
	directory := filepath.Dir(path)
	staging := filepath.Join(directory, ".lanpanel-filetxn")
	_, err := ensureDirectory(staging, filetxn.Owner{UID: 0, GID: 0}, 0o700)
	return staging, err
}
func putRootGroupFile(ctx context.Context, path string, data []byte, gid uint32, mode os.FileMode) error {
	parent := filepath.Dir(path)
	staging := filepath.Join(parent, ".lanpanel-filetxn")
	if _, err := ensureDirectory(staging, filetxn.Owner{UID: 0, GID: 0}, 0o700); err != nil {
		return err
	}
	root := filetxn.Owner{UID: 0, GID: 0}
	parents := filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{root, {UID: 0, GID: gid}}, AllowedMode: 0o755}
	store, err := filetxn.Open(filetxn.Config{RootPath: "/", Root: filetxn.Metadata{Owner: root, Mode: 0o755}, StagingPath: staging, Staging: filetxn.Metadata{Owner: root, Mode: 0o700}, StagingParents: parents}, filetxn.Options{})
	if err != nil {
		return err
	}
	defer store.Close()
	metadata := filetxn.Metadata{Owner: filetxn.Owner{UID: 0, GID: gid}, Mode: mode}
	_, err = store.Put(ctx, filetxn.Request{Path: path, Parents: parents, Existing: &metadata, New: metadata, MaxBytes: int64(len(data))}, data, filetxn.CreateOnly)
	return err
}

func putOrVerifyTargetFile(ctx context.Context, path string, data []byte, mode os.FileMode) error {
	staging, err := targetStaging(path)
	if err != nil {
		return err
	}
	return putOrVerifyRootFile(ctx, "/", staging, path, data, mode)
}

func putOrVerifyRootFile(ctx context.Context, root, staging, path string, data []byte, mode os.FileMode) error {
	err := putRootFile(ctx, root, staging, path, data, mode, filetxn.CreateOnly)
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
	owner := filetxn.Owner{UID: 0, GID: 0}
	rootMode := os.FileMode(0o700)
	if root == "/" {
		rootMode = 0o755
	}
	store, err := filetxn.Open(filetxn.Config{RootPath: root, Root: filetxn.Metadata{Owner: owner, Mode: rootMode}, StagingPath: staging, Staging: filetxn.Metadata{Owner: owner, Mode: 0o700}, StagingParents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o755}}, filetxn.Options{})
	if err != nil {
		return err
	}
	defer store.Close()
	metadata := filetxn.Metadata{Owner: owner, Mode: mode}
	_, err = store.Put(ctx, filetxn.Request{Path: path, Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o755}, Existing: &metadata, New: metadata, MaxBytes: max(int64(len(data)), 1)}, data, disposition)
	return err
}

func verifySourceBinary(source string, expected releaseBinary) error {
	fd, err := unix.Open(source, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(source))
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("source binary descriptor is invalid")
	}
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Size != int64(expected.Bytes) || stat.Mode&0o111 == 0 || stat.Mode&0o022 != 0 {
		return fmt.Errorf("source binary identity is unsafe")
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(expected.Bytes)+1))
	if err != nil || uint64(len(data)) != expected.Bytes || digestBytes(data) != expected.Digest {
		return fmt.Errorf("source binary bytes differ from selected release")
	}
	return nil
}

func copyOrVerifyBinary(source string, paths Paths, expected releaseBinary) error {
	staging, stagingErr := targetStaging(paths.BinaryPath)
	if stagingErr != nil {
		return stagingErr
	}
	err := copyVerifiedBinary(source, "/", staging, paths.BinaryPath, expected)
	if !errors.Is(err, os.ErrExist) {
		return err
	}
	actual, readErr := readCommittedArtifact(paths.BinaryPath, int64(expected.Bytes), 0o755)
	if readErr != nil || uint64(len(actual)) != expected.Bytes || digestBytes(actual) != expected.Digest {
		return fmt.Errorf("existing installed binary is foreign")
	}
	return nil
}

func copyVerifiedBinary(source, destinationRoot, staging, destination string, expected releaseBinary) error {
	fd, err := unix.Open(source, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(source))
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("source binary descriptor is invalid")
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Size != int64(expected.Bytes) || stat.Mode&0o111 == 0 || stat.Mode&0o022 != 0 {
		return fmt.Errorf("source binary identity is unsafe")
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(expected.Bytes)+1))
	if err != nil || uint64(len(data)) != expected.Bytes || digestBytes(data) != expected.Digest {
		return fmt.Errorf("source binary bytes differ from selected release")
	}
	if child.FixedLanPanelExecutable != destination {
		return fmt.Errorf("bootstrap binary destination is not release-fixed")
	}
	return putRootFile(context.Background(), destinationRoot, staging, destination, data, 0o755, filetxn.CreateOnly)
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
	defer manager.Close()
	exposure, err := manager.Acquire(ctx, locks.Exposure)
	if err != nil {
		return err
	}
	ownershipStore, err := ownership.Open(ownership.Config{RootPath: journal.Paths.OwnershipRoot, StagingPath: filepath.Join(journal.Paths.OwnershipRoot, ".filetxn"), RecordsPath: filepath.Join(journal.Paths.OwnershipRoot, "records"), Owner: owner, Policy: ownership.Policy{ManagedRoots: []string{"/etc/lanpanel", "/var/lib/lanpanel"}}, LockAuthority: manager.Authority()})
	if err != nil {
		return err
	}
	defer ownershipStore.Close()
	emergencyPath := filepath.Join(journal.Paths.SafetyRoot, "emergency")
	emergency, err := safety.CreateEmergency(emergencyPath, owner, safety.EmergencyOptions{LockAuthority: manager.Authority()})
	if errors.Is(err, os.ErrExist) {
		emergency, err = safety.OpenEmergency(emergencyPath, owner, safety.EmergencyOptions{LockAuthority: manager.Authority()})
	}
	if err != nil {
		_ = exposure.Release()
		return err
	}
	defer emergency.Close()
	safetyStore, err := safety.OpenStore(safety.StoreConfig{RootPath: journal.Paths.SafetyRoot, StagingPath: filepath.Join(journal.Paths.SafetyRoot, ".filetxn"), StatePath: filepath.Join(journal.Paths.SafetyRoot, "state.json"), Owner: owner, Emergency: emergency, LockAuthority: manager.Authority(), Ownership: ownershipStore})
	if err != nil {
		return err
	}
	defer safetyStore.Close()
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
	defer normal.Close()
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
		fmt.Fprintf(hasher, "%d:%s:%s\n", len(key), key, values[key])
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

var _ = bytes.Equal
var _ = helper.FixedIdentityConfigPath
