//go:build linux

package headscale

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	managedarchive "lanpanel/internal/archive"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/release"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

var ErrForeignEvidence = errors.New("foreign_database_evidence")

type Paths struct {
	Root           string
	Staging        string
	Journal        string
	JournalStaging string
	Executable     string
	IdentityParent string
	IdentityName   string
	SQLite         string
}

func FixedPaths() Paths {
	return Paths{Root: "/", Staging: "/usr/lib/lanpanel/dependencies/.filetxn", Journal: "/var/lib/lanpanel/headscale-initialize.json", JournalStaging: "/var/lib/lanpanel/.bootstrap-filetxn", Executable: "/usr/lib/lanpanel/dependencies/headscale", IdentityParent: "/var/lib/lanpanel/headscale", IdentityName: "identity", SQLite: "/var/lib/lanpanel/headscale/db.sqlite"}
}

func EnsureLayout(paths Paths, owner filetxn.Owner) error {
	for _, item := range []struct {
		path string
		mode uint32
	}{{filepath.Dir(paths.Executable), 0o755}, {paths.Staging, 0o700}} {
		if err := ensureDirectory(item.path, owner, item.mode); err != nil {
			return err
		}
	}
	return nil
}

func EnsureIdentityLayout(paths Paths, owner filetxn.Owner) error {
	return ensureDirectory(paths.IdentityParent, owner, 0o700)
}

func ensureDirectory(path string, owner filetxn.Owner, mode uint32) error {
	parentFD, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	var parent unix.Stat_t
	if unix.Fstat(parentFD, &parent) != nil || parent.Mode&unix.S_IFMT != unix.S_IFDIR || parent.Uid != owner.UID || parent.Gid != owner.GID || parent.Mode&0o022 != 0 {
		return fmt.Errorf("Headscale directory parent is unsafe")
	}
	if err := unix.Mkdirat(parentFD, filepath.Base(path), mode); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	fd, err := unix.Openat(parentFD, filepath.Base(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Uid != owner.UID || stat.Gid != owner.GID || stat.Mode&0o7777 != mode {
		return fmt.Errorf("Headscale managed directory is foreign")
	}
	return unix.Fsync(parentFD)
}

func ValidateInitializationEvidence(installationID string, candidate domain.HeadscaleDomain, installed release.InstallIdentity, snapshot []byte, paths Paths, owner filetxn.Owner, fresh bool) error {
	if err := ValidateAccountInitializationEvidence(installationID, candidate.ID, fresh); err != nil {
		return fmt.Errorf("%w: %v", ErrForeignEvidence, err)
	}
	for _, path := range []string{rooted(paths.Root, "/etc/lanpanel/headscale"), paths.SQLite, paths.SQLite + "-wal", paths.SQLite + "-shm", paths.SQLite + "-journal"} {
		if err := verifyAbsent(path); err != nil {
			return fmt.Errorf("%w: %s", ErrForeignEvidence, filepath.Base(path))
		}
	}
	var executable release.AssetIdentity
	for _, member := range installed.Headscale.Members {
		if member.Asset.Path == installed.Headscale.ExecutableAsset {
			executable = member.Asset
		}
	}
	if fresh {
		for _, path := range []string{paths.Executable, paths.IdentityParent} {
			if err := verifyAbsent(path); err != nil {
				return fmt.Errorf("%w: foreign managed path %s", ErrForeignEvidence, filepath.Base(path))
			}
		}
		return nil
	}
	if err := verifyRegular(paths.Executable, owner, 0o755, executable.Digest, int64(executable.Bytes)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: resumable executable changed: %v", ErrForeignEvidence, err)
	}
	fd, err := unix.Open(paths.IdentityParent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(paths.IdentityParent))
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("Headscale identity directory descriptor unavailable")
	}
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Uid != owner.UID || stat.Gid != owner.GID || stat.Mode&0o7777 != 0o700 {
		return fmt.Errorf("%w: identity directory metadata changed", ErrForeignEvidence)
	}
	entries, err := file.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() != paths.IdentityName && entry.Name() != "."+paths.IdentityName+".lanpanel-staging" {
			return fmt.Errorf("%w: foreign identity inventory entry %s", ErrForeignEvidence, entry.Name())
		}
	}
	identityRequest := filetxn.DirectoryRequest{ParentPath: paths.IdentityParent, Parent: filetxn.Metadata{Owner: owner, Mode: 0o700}, TargetName: paths.IdentityName, Directory: filetxn.Metadata{Owner: owner, Mode: 0o700}, Members: []filetxn.DirectoryMember{{Name: "database-uuid", Data: []byte(candidate.Database.UUID + "\n"), Owner: owner, Mode: 0o600, Maximum: 128}, {Name: "snapshot.json", Data: snapshot, Owner: owner, Mode: 0o600, Maximum: 1 << 20}}}
	if _, err := filetxn.VerifyDirectory(identityRequest); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: resumable identity differs: %v", ErrForeignEvidence, err)
	}
	return nil
}

func ValidateCommittedInitialization(installationID string, candidate domain.HeadscaleDomain, installed release.InstallIdentity, paths Paths, owner filetxn.Owner) error {
	artifact, err := ArtifactIdentity(installed)
	if err != nil || candidate.Artifact != artifact {
		return fmt.Errorf("committed Headscale release authority changed")
	}
	if _, err := ValidateAccount(installationID, candidate.ID); err != nil {
		return err
	}
	var executable release.AssetIdentity
	for _, member := range installed.Headscale.Members {
		if member.Asset.Path == installed.Headscale.ExecutableAsset {
			executable = member.Asset
		}
	}
	if err := verifyRegular(paths.Executable, owner, 0o755, executable.Digest, int64(executable.Bytes)); err != nil {
		return fmt.Errorf("committed Headscale executable changed: %w", err)
	}
	snapshot := IdentitySnapshot{SchemaVersion: IdentitySnapshotSchema, InstallationID: installationID, HeadscaleID: candidate.ID, ControlDomain: candidate.ControlDomain, MagicDNSNamespace: candidate.MagicDNSNamespace, Policy: candidate.Policy, Artifact: candidate.Artifact, DatabaseUUID: candidate.Database.UUID, SQLitePath: candidate.Database.SQLitePath, DatabaseGeneration: candidate.Database.Generation, DesiredConfigDigest: candidate.DesiredDigest}
	snapshotBytes, err := json.Marshal(snapshot)
	if err != nil || VerifySnapshot(candidate, snapshotBytes) != nil {
		return fmt.Errorf("committed Headscale identity snapshot changed")
	}
	directoryRequest := filetxn.DirectoryRequest{ParentPath: paths.IdentityParent, Parent: filetxn.Metadata{Owner: owner, Mode: 0o700}, TargetName: paths.IdentityName, Directory: filetxn.Metadata{Owner: owner, Mode: 0o700}, Members: []filetxn.DirectoryMember{{Name: "database-uuid", Data: []byte(candidate.Database.UUID + "\n"), Owner: owner, Mode: 0o600, Maximum: 128}, {Name: "snapshot.json", Data: snapshotBytes, Owner: owner, Mode: 0o600, Maximum: 1 << 20}}}
	if _, err := filetxn.VerifyDirectory(directoryRequest); err != nil {
		return fmt.Errorf("committed Headscale identity files changed: %w", err)
	}
	if candidate.Database.Phase == domain.HeadscaleIdentityCommitted {
		if err := rejectDatabaseEvidence(paths, owner); err != nil {
			return err
		}
	}
	return nil
}

type InstallRequest struct {
	Paths         Paths
	Owner         filetxn.Owner
	Release       release.InstallIdentity
	Candidate     domain.HeadscaleDomain
	SnapshotBytes []byte
	ArchiveBytes  []byte
}

func Install(ctx context.Context, request InstallRequest) error {
	if err := validateInstallRequest(request); err != nil {
		return err
	}
	if err := rejectDatabaseEvidence(request.Paths, request.Owner); err != nil {
		return err
	}
	if err := verifyOrInstallExecutable(ctx, request); err != nil {
		return err
	}
	return verifyOrCommitIdentity(ctx, request)
}

func validateInstallRequest(request InstallRequest) error {
	if request.Paths.Root == "" || !filepath.IsAbs(request.Paths.Root) || request.Paths.Staging == "" || request.Paths.Executable == "" || request.Paths.IdentityParent == "" || request.Paths.IdentityName != "identity" || request.Paths.SQLite == "" || request.Candidate.Database.SQLitePath != "/var/lib/lanpanel/headscale/db.sqlite" {
		return fmt.Errorf("Headscale host paths are invalid")
	}
	if err := release.ValidateInstallIdentity(request.Release); err != nil {
		return err
	}
	if err := VerifySnapshot(request.Candidate, request.SnapshotBytes); err != nil {
		return err
	}
	if request.Candidate.Artifact.BaselineDigest != "sha256:"+request.Release.DependencyBaseline.Digest || request.Candidate.Artifact.ArchiveDigest != "sha256:"+request.Release.Headscale.Archive.Digest || request.Candidate.Artifact.ConfigContractDigest != "sha256:"+request.Release.Headscale.ConfigContractDigest || request.Candidate.Artifact.Version != request.Release.Headscale.Version || request.Candidate.Artifact.ConfigContract != request.Release.Headscale.ConfigContract || request.Paths.Executable != rooted(request.Paths.Root, request.Release.Headscale.InstallPath) || request.Paths.SQLite != rooted(request.Paths.Root, "/var/lib/lanpanel/headscale/db.sqlite") {
		return fmt.Errorf("Headscale candidate differs from installed release authority")
	}
	sum := sha256.Sum256(request.ArchiveBytes)
	if uint64(len(request.ArchiveBytes)) != request.Release.Headscale.Archive.Bytes || hex.EncodeToString(sum[:]) != request.Release.Headscale.Archive.Digest {
		return fmt.Errorf("Headscale archive bytes differ from installed release authority")
	}
	return nil
}

func verifyOrInstallExecutable(ctx context.Context, request InstallRequest) error {
	authority := request.Release.Headscale
	members := make([]managedarchive.Member, 0, len(authority.Members))
	for _, member := range authority.Members {
		members = append(members, managedarchive.Member{Path: member.Path, MaximumBytes: int64(member.Asset.Bytes), MaximumPhysicalBytes: int64(authority.MaximumExtractedBytes), Destination: member.Destination, Metadata: filetxn.Metadata{Owner: request.Owner, Mode: os.FileMode(member.Mode)}})
	}
	extracted, err := managedarchive.Extract(request.ArchiveBytes, managedarchive.Spec{Format: managedarchive.Format(authority.ArchiveFormat), MaximumArchiveBytes: int64(authority.MaximumExtractedBytes), MaximumExtractedBytes: int64(authority.MaximumExtractedBytes), MaximumMembers: len(members), Members: members})
	if err != nil {
		return err
	}
	var executable []byte
	var executableIdentity release.AssetIdentity
	for _, member := range authority.Members {
		if member.Asset.Path == authority.ExecutableAsset {
			executable = extracted[member.Path]
			executableIdentity = member.Asset
		}
	}
	if len(executable) == 0 || uint64(len(executable)) != executableIdentity.Bytes {
		return fmt.Errorf("Headscale executable member is missing")
	}
	if err := verifyRegular(request.Paths.Executable, request.Owner, 0o755, executableIdentity.Digest, int64(executableIdentity.Bytes)); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("existing Headscale executable is foreign: %w", err)
	}
	rootMode, err := directoryMode(request.Paths.Root, request.Owner)
	if err != nil {
		return err
	}
	store, err := filetxn.Open(filetxn.Config{RootPath: request.Paths.Root, Root: filetxn.Metadata{Owner: request.Owner, Mode: rootMode}, StagingPath: request.Paths.Staging, Staging: filetxn.Metadata{Owner: request.Owner, Mode: 0o700}, StagingParents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{request.Owner}, AllowedMode: 0o755}}, filetxn.Options{})
	if err != nil {
		return err
	}
	defer store.Close()
	metadata := filetxn.Metadata{Owner: request.Owner, Mode: 0o755}
	_, err = store.Put(ctx, filetxn.Request{Path: request.Paths.Executable, Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{request.Owner}, AllowedMode: 0o755}, New: metadata, MaxBytes: int64(executableIdentity.Bytes)}, executable, filetxn.CreateOnly)
	return err
}

func verifyOrCommitIdentity(ctx context.Context, request InstallRequest) error {
	directoryRequest := filetxn.DirectoryRequest{ParentPath: request.Paths.IdentityParent, Parent: filetxn.Metadata{Owner: request.Owner, Mode: 0o700}, TargetName: request.Paths.IdentityName, Directory: filetxn.Metadata{Owner: request.Owner, Mode: 0o700}, Members: []filetxn.DirectoryMember{{Name: "database-uuid", Data: []byte(request.Candidate.Database.UUID + "\n"), Owner: request.Owner, Mode: 0o600, Maximum: 128}, {Name: "snapshot.json", Data: request.SnapshotBytes, Owner: request.Owner, Mode: 0o600, Maximum: 1 << 20}}}
	_, err := filetxn.CommitNewDirectory(ctx, directoryRequest)
	if errors.Is(err, os.ErrExist) {
		_, err = filetxn.VerifyDirectory(directoryRequest)
	}
	if err != nil {
		return fmt.Errorf("Headscale initialized identity is foreign or incomplete: %w", err)
	}
	return nil
}

func rejectDatabaseEvidence(paths Paths, owner filetxn.Owner) error {
	for _, path := range []string{paths.SQLite, paths.SQLite + "-wal", paths.SQLite + "-shm", paths.SQLite + "-journal"} {
		if err := verifyAbsent(path); err != nil {
			return fmt.Errorf("%w: %s", ErrForeignEvidence, filepath.Base(path))
		}
	}
	identity := filepath.Join(paths.IdentityParent, paths.IdentityName)
	var stat unix.Stat_t
	if err := unix.Lstat(identity, &stat); err == nil && (stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != owner.UID || stat.Gid != owner.GID || stat.Mode&0o7777 != 0o700) {
		return fmt.Errorf("Headscale initialized identity path is unsafe")
	} else if err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return nil
}

func verifyAbsent(path string) error {
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return err
	}
	return fmt.Errorf("path exists")
}

func verifyRegular(path string, owner filetxn.Owner, mode uint32, digest string, bytes int64) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return os.ErrNotExist
		}
		return err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("descriptor unavailable")
	}
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != owner.UID || stat.Gid != owner.GID || stat.Mode&0o7777 != mode || stat.Size != bytes {
		return fmt.Errorf("type or metadata mismatch")
	}
	data := make([]byte, bytes)
	if _, err := file.ReadAt(data, 0); err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != digest {
		return fmt.Errorf("digest mismatch")
	}
	return nil
}

func directoryMode(path string, owner filetxn.Owner) (os.FileMode, error) {
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != owner.UID || stat.Gid != owner.GID || stat.Mode&0o022 != 0 {
		return 0, fmt.Errorf("Headscale transaction root is unsafe (uid=%d gid=%d mode=%#o)", stat.Uid, stat.Gid, stat.Mode&0o7777)
	}
	return os.FileMode(stat.Mode & 0o7777), nil
}

func rooted(root, path string) string {
	if root == "/" {
		return path
	}
	return filepath.Join(root, strings.TrimPrefix(path, "/"))
}
