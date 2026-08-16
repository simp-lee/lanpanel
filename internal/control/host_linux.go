//go:build linux

package control

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/certificates"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/identity"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// PrivateRuntime is implemented by the fixed PID1/systemd boundary. It may
// operate only the candidate service inside its private network namespace.
type PrivateRuntime interface {
	RequireAbsent(context.Context, Candidate, identity.AccountIdentity) error
	InitializeDatabase(context.Context, Rendered, identity.AccountIdentity) (DatabaseEvidence, error)
	StartAndProbe(context.Context, Rendered, identity.AccountIdentity) (ServiceEvidence, error)
	StopAndVerify(context.Context, Candidate, identity.AccountIdentity) error
}

type LinuxCandidateHost struct {
	account identity.AccountIdentity
	runtime PrivateRuntime
}

func NewLinuxCandidateHost(account identity.AccountIdentity, runtime PrivateRuntime) (*LinuxCandidateHost, error) {
	if account.Role != identity.RoleHeadscale || account.UID == 0 || account.GID == 0 || runtime == nil {
		return nil, fmt.Errorf("Headscale Linux candidate host authority is invalid")
	}
	return &LinuxCandidateHost{account: account, runtime: runtime}, nil
}

func (host *LinuxCandidateHost) ValidateFreshCandidate(_ context.Context, rendered Rendered) error {
	if host == nil || VerifyRendered(rendered) != nil {
		return fmt.Errorf("Headscale fresh candidate authority is invalid")
	}
	bundle, err := certificates.BundlePath(rendered.Candidate.CertificateID, 1)
	if err != nil {
		return err
	}
	pointer, err := certificates.ActivePointerPath(rendered.Candidate.CertificateID)
	if err != nil {
		return err
	}
	for _, path := range []string{rendered.Candidate.Paths.ConfigRoot, rendered.Candidate.Paths.Unit, rendered.Candidate.Paths.RuntimeRoot, rendered.Candidate.Paths.JournalRoot, bundle, pointer, filepath.Join("/var/lib/lanpanel/certificates/chroot", rendered.Candidate.CertificateID), filepath.Join("/var/lib/lanpanel/certificates/webroot", rendered.Candidate.CertificateID)} {
		var stat unix.Stat_t
		if err := unix.Lstat(path, &stat); errors.Is(err, unix.ENOENT) {
			continue
		} else if err != nil {
			return err
		}
		return fmt.Errorf("Headscale first-deploy output already exists: %s", filepath.Base(path))
	}
	return nil
}

func (host *LinuxCandidateHost) CommitFreshBoundary(ctx context.Context, rendered Rendered) error {
	if host == nil || VerifyRendered(rendered) != nil {
		return fmt.Errorf("Headscale fresh boundary authority is invalid")
	}
	return host.runtime.RequireAbsent(ctx, rendered.Candidate, host.account)
}

func (host *LinuxCandidateHost) InitializeDatabase(ctx context.Context, rendered Rendered) (DatabaseEvidence, error) {
	if host == nil || VerifyRendered(rendered) != nil {
		return DatabaseEvidence{}, fmt.Errorf("Headscale database candidate is invalid")
	}
	if err := ensureFixedDirectory(rendered.Candidate.Paths.RuntimeRoot, filetxn.Owner{UID: host.account.UID, GID: host.account.GID}, 0o700); err != nil {
		return DatabaseEvidence{}, err
	}
	if err := host.commitCandidateFiles(ctx, rendered); err != nil {
		return DatabaseEvidence{}, err
	}
	evidence, err := host.runtime.InitializeDatabase(ctx, rendered, host.account)
	if err != nil {
		return DatabaseEvidence{}, err
	}
	journal := Journal{Candidate: rendered.Candidate, Database: &evidence}
	if !validDatabase(journal) {
		return DatabaseEvidence{}, fmt.Errorf("Headscale database runtime evidence mismatched")
	}
	return evidence, nil
}

func (host *LinuxCandidateHost) StagePrivateService(ctx context.Context, rendered Rendered, database DatabaseEvidence) (ServiceEvidence, error) {
	if host == nil || VerifyRendered(rendered) != nil || !validDatabase(Journal{Candidate: rendered.Candidate, Database: &database}) {
		return ServiceEvidence{}, fmt.Errorf("Headscale private service authority is invalid")
	}
	if err := host.verifyCandidateFiles(ctx, rendered); err != nil {
		return ServiceEvidence{}, err
	}
	evidence, err := host.runtime.StartAndProbe(ctx, rendered, host.account)
	if err != nil {
		return ServiceEvidence{}, err
	}
	if !validService(Journal{Candidate: rendered.Candidate, Service: &evidence}) {
		return ServiceEvidence{}, fmt.Errorf("Headscale private service probe mismatched or exposed public STUN")
	}
	return evidence, nil
}

func (host *LinuxCandidateHost) StopPrivateService(ctx context.Context, candidate Candidate) error {
	if host == nil || Validate(candidate) != nil {
		return fmt.Errorf("Headscale candidate stop authority is invalid")
	}
	return host.runtime.StopAndVerify(ctx, candidate, host.account)
}

func (host *LinuxCandidateHost) commitCandidateFiles(ctx context.Context, rendered Rendered) error {
	paths := rendered.Candidate.Paths
	root := filetxn.Owner{UID: 0, GID: 0}
	service := filetxn.Owner{UID: host.account.UID, GID: host.account.GID}
	if err := ensureFixedDirectory(paths.ConfigRoot, filetxn.Owner{UID: 0, GID: host.account.GID}, 0o710); err != nil {
		return err
	}
	staging := filepath.Join(paths.ConfigRoot, ".lanpanel-filetxn")
	if err := ensureFixedDirectory(staging, root, 0o700); err != nil {
		return err
	}
	store, err := filetxn.Open(filetxn.Config{RootPath: "/", Root: filetxn.Metadata{Owner: root, Mode: 0o755}, StagingPath: staging, Staging: filetxn.Metadata{Owner: root, Mode: 0o700}, StagingParents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{root}, AllowedMode: 0o710}}, filetxn.Options{})
	if err != nil {
		return err
	}
	defer store.Close()
	files := []struct {
		path  string
		data  []byte
		owner filetxn.Owner
		mode  os.FileMode
	}{{paths.Config, rendered.Config, service, 0o600}, {paths.Policy, rendered.Policy, service, 0o600}, {paths.Unit, rendered.Unit, root, 0o644}}
	for _, value := range files {
		request := filetxn.Request{Path: value.path, Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{root}, AllowedMode: 0o755}, New: filetxn.Metadata{Owner: value.owner, Mode: value.mode}, MaxBytes: int64(len(value.data))}
		if value.path == paths.Config || value.path == paths.Policy {
			request.Parents.AllowedMode = 0o710
		}
		if _, err := store.Put(ctx, request, value.data, filetxn.CreateOnly); err != nil {
			if !errors.Is(err, os.ErrExist) {
				return err
			}
			request.Existing = &filetxn.Metadata{Owner: value.owner, Mode: value.mode}
			actual, readErr := store.Read(ctx, request)
			if readErr != nil || !bytes.Equal(actual, value.data) {
				return fmt.Errorf("Headscale candidate file differs from exact authority")
			}
		}
	}
	return nil
}

func (host *LinuxCandidateHost) verifyCandidateFiles(ctx context.Context, rendered Rendered) error {
	paths := rendered.Candidate.Paths
	root := filetxn.Owner{UID: 0, GID: 0}
	staging := filepath.Join(paths.ConfigRoot, ".lanpanel-filetxn")
	store, err := filetxn.Open(filetxn.Config{RootPath: "/", Root: filetxn.Metadata{Owner: root, Mode: 0o755}, StagingPath: staging, Staging: filetxn.Metadata{Owner: root, Mode: 0o700}, StagingParents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{root}, AllowedMode: 0o710}}, filetxn.Options{})
	if err != nil {
		return err
	}
	defer store.Close()
	service := filetxn.Owner{UID: host.account.UID, GID: host.account.GID}
	for _, value := range []struct {
		path  string
		data  []byte
		owner filetxn.Owner
		mode  os.FileMode
	}{{paths.Config, rendered.Config, service, 0o600}, {paths.Policy, rendered.Policy, service, 0o600}, {paths.Unit, rendered.Unit, root, 0o644}} {
		parents := filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{root}, AllowedMode: 0o755}
		if value.path == paths.Config || value.path == paths.Policy {
			parents.AllowedMode = 0o710
		}
		actual, err := store.Read(ctx, filetxn.Request{Path: value.path, Parents: parents, Existing: &filetxn.Metadata{Owner: value.owner, Mode: value.mode}, MaxBytes: int64(len(value.data))})
		if err != nil || !bytes.Equal(actual, value.data) {
			return fmt.Errorf("Headscale candidate file verification failed")
		}
	}
	return nil
}

func ensureFixedDirectory(path string, owner filetxn.Owner, mode uint32) error {
	parent, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	name := filepath.Base(path)
	created := false
	if err := unix.Mkdirat(parent, name, mode); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return err
		}
	} else {
		created = true
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if created {
		if err := unix.Fchown(fd, int(owner.UID), int(owner.GID)); err != nil {
			return err
		}
		if err := unix.Fchmod(fd, mode); err != nil {
			return err
		}
		if err := unix.Fsync(fd); err != nil {
			return err
		}
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != owner.UID || stat.Gid != owner.GID || stat.Mode&0o7777 != mode {
		return fmt.Errorf("Headscale fixed directory metadata is unsafe")
	}
	return unix.Fsync(parent)
}
