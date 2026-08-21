//go:build linux

package headscale

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/child"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/identity"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func ValidateAccount(installationID, headscaleID string) (identity.AccountIdentity, error) {
	set, err := identity.HeadscaleAccounts(installationID, headscaleID)
	if err != nil {
		return identity.AccountIdentity{}, err
	}
	data, err := identity.RenderSysusers(set)
	if err != nil {
		return identity.AccountIdentity{}, err
	}
	present, identities, err := identity.InspectAccounts(set)
	if err != nil || !present {
		return identity.AccountIdentity{}, fmt.Errorf("headscale account is absent or invalid: %w", err)
	}
	if err := verifyAccountAuthority("/etc/sysusers.d/lanpanel-headscale.conf", data); err != nil {
		return identity.AccountIdentity{}, err
	}
	value, ok := identity.IdentityFor(identity.AccountSet{Identities: identities}, identity.RoleHeadscale)
	if !ok {
		return identity.AccountIdentity{}, fmt.Errorf("headscale numeric account identity is missing")
	}
	return value, nil
}

func ValidateAccountInitializationEvidence(installationID, headscaleID string, fresh bool) error {
	set, err := identity.HeadscaleAccounts(installationID, headscaleID)
	if err != nil {
		return err
	}
	data, err := identity.RenderSysusers(set)
	if err != nil {
		return err
	}
	complete, identities, err := identity.InspectPartialAccounts(set)
	if err != nil {
		return err
	}
	found, err := identity.PartialAccountEvidencePresent(set)
	if err != nil {
		return err
	}
	authorityErr := verifyAccountAuthority("/etc/sysusers.d/lanpanel-headscale.conf", data)
	if fresh {
		if complete || found || len(identities) != 0 || !errors.Is(authorityErr, unix.ENOENT) {
			return fmt.Errorf("foreign Headscale account evidence exists")
		}
		return nil
	}
	if authorityErr == nil {
		return nil
	}
	if errors.Is(authorityErr, unix.ENOENT) && !complete && !found && len(identities) == 0 {
		return nil
	}
	return fmt.Errorf("headscale account evidence differs from initialization authority")
}

func EnsureAccount(ctx context.Context, installationID, headscaleID string) (identity.AccountIdentity, error) {
	set, err := identity.HeadscaleAccounts(installationID, headscaleID)
	if err != nil {
		return identity.AccountIdentity{}, err
	}
	path := "/etc/sysusers.d/lanpanel-headscale.conf"
	data, err := identity.RenderSysusers(set)
	if err != nil {
		return identity.AccountIdentity{}, err
	}
	present, identities, err := identity.InspectPartialAccounts(set)
	if err != nil {
		return identity.AccountIdentity{}, err
	}
	found, err := identity.PartialAccountEvidencePresent(set)
	if err != nil {
		return identity.AccountIdentity{}, err
	}
	if present {
		if err := verifyAccountAuthority(path, data); err != nil {
			return identity.AccountIdentity{}, err
		}
		value, ok := identity.IdentityFor(identity.AccountSet{Identities: identities}, identity.RoleHeadscale)
		if !ok {
			return identity.AccountIdentity{}, fmt.Errorf("headscale numeric account identity is missing")
		}
		return value, nil
	}
	staging := filepath.Join(filepath.Dir(path), ".lanpanel-filetxn")
	if err := ensureDirectory(staging, filetxn.Owner{UID: 0, GID: 0}, 0o700); err != nil {
		return identity.AccountIdentity{}, err
	}
	owner := filetxn.Owner{UID: 0, GID: 0}
	if err := verifyAccountAuthority(path, data); err == nil {
		// Exact authority and any exact partial account subset are reusable.
	} else if !errors.Is(err, unix.ENOENT) || found || len(identities) != 0 {
		return identity.AccountIdentity{}, err
	} else {
		store, err := filetxn.Open(filetxn.Config{RootPath: "/", Root: filetxn.Metadata{Owner: owner, Mode: 0o755}, StagingPath: staging, Staging: filetxn.Metadata{Owner: owner, Mode: 0o700}, StagingParents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o755}}, filetxn.Options{})
		if err != nil {
			return identity.AccountIdentity{}, err
		}
		metadata := filetxn.Metadata{Owner: owner, Mode: 0o600}
		_, putErr := store.Put(ctx, filetxn.Request{Path: path, Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o755}, New: metadata, MaxBytes: int64(len(data))}, data, filetxn.CreateOnly)
		closeErr := store.Close()
		if putErr != nil || closeErr != nil {
			return identity.AccountIdentity{}, fmt.Errorf("commit Headscale account authority: %v %v", putErr, closeErr)
		}
	}
	launcher, err := child.NewLauncher(child.FixedLanPanelExecutable, child.Identities{})
	if err != nil {
		return identity.AccountIdentity{}, err
	}
	result, err := launcher.RunInvocation(ctx, child.ProfileHeadscaleAccounts, child.Invocation{Headscale: &child.HeadscaleInvocation{HeadscaleID: headscaleID}}, nil)
	if err != nil || result.ExitCode != 0 || result.OutputCutOff {
		return identity.AccountIdentity{}, fmt.Errorf("fixed Headscale account creation failed")
	}
	present, identities, err = identity.InspectAccounts(set)
	if err != nil || !present {
		return identity.AccountIdentity{}, fmt.Errorf("headscale account postcondition failed: %w", err)
	}
	value, ok := identity.IdentityFor(identity.AccountSet{Identities: identities}, identity.RoleHeadscale)
	if !ok {
		return identity.AccountIdentity{}, fmt.Errorf("headscale numeric account identity is missing")
	}
	return value, nil
}

func verifyAccountAuthority(path string, expected []byte) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("headscale account authority descriptor unavailable")
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0o7777 != 0o600 || stat.Size != int64(len(expected)) {
		return fmt.Errorf("headscale account authority metadata changed")
	}
	actual := make([]byte, len(expected))
	if _, err := file.ReadAt(actual, 0); err != nil || !bytes.Equal(actual, expected) {
		return fmt.Errorf("headscale account authority changed")
	}
	return nil
}
