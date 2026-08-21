//go:build linux

package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/identity"
	"lanpanel/internal/packages"
	"lanpanel/internal/preflight"
	"lanpanel/internal/release"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

const (
	installerInputSchema       = "lanpanel.installer.input.v2"
	maximumInstallerInputBytes = 32 << 20
)

type installerInput struct {
	SchemaVersion                              string              `json:"schema_version"`
	Kind                                       release.InstallKind `json:"kind"`
	ACMEAccountContact                         string              `json:"acme_account_contact"`
	ExpectedReleaseManifestDigest              string              `json:"expected_release_manifest_digest,omitempty"`
	ExpectedQualificationInstallManifestDigest string              `json:"expected_qualification_install_manifest_digest,omitempty"`
	ReleaseManifest                            []byte              `json:"release_manifest,omitempty"`
	QualificationInstallManifest               []byte              `json:"qualification_install_manifest,omitempty"`
	QualificationTargetProfile                 []byte              `json:"qualification_target_profile,omitempty"`
	LiveSideEffectPlan                         []byte              `json:"live_side_effect_plan,omitempty"`
	QualificationDependencyAuthority           []byte              `json:"qualification_dependency_authority,omitempty"`
	Checksums                                  []byte              `json:"checksums,omitempty"`
	AssetPaths                                 map[string]string   `json:"asset_paths"`
	PackagePlan                                packages.Plan       `json:"package_plan"`
	PackagePreflight                           preflight.Result    `json:"package_preflight"`
}

// RunInstallerRole accepts no mutable argv. Release tooling supplies one
// bounded canonical authority document on inherited fd 3.
func RunInstallerRole(args []string, stdout io.Writer) error {
	if len(args) != 0 || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return fmt.Errorf("installer requires its fixed root invocation")
	}
	file := os.NewFile(3, "installer-authority")
	if file == nil {
		return fmt.Errorf("installer release authority descriptor is missing")
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	data, err := io.ReadAll(io.LimitReader(file, maximumInstallerInputBytes+1))
	if err != nil || len(data) == 0 || len(data) > maximumInstallerInputBytes {
		return fmt.Errorf("installer release authority is missing or unbounded")
	}
	var input installerInput
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return fmt.Errorf("installer release authority is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("installer release authority has trailing data")
	}
	canonical, _ := json.Marshal(input)
	if !bytes.Equal(canonical, data) || input.SchemaVersion != installerInputSchema || input.ACMEAccountContact == "" {
		return fmt.Errorf("installer release authority is noncanonical")
	}
	assets, err := readInstallerAssets(input.AssetPaths)
	if err != nil {
		return err
	}
	actualHost, err := observeHostFingerprint()
	if err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Second)
	var authority *release.InstallAuthority
	switch input.Kind {
	case release.InstallPublicRelease:
		if len(input.QualificationInstallManifest) != 0 || len(input.QualificationTargetProfile) != 0 || len(input.LiveSideEffectPlan) != 0 || len(input.QualificationDependencyAuthority) != 0 || input.ExpectedQualificationInstallManifestDigest != "" {
			return fmt.Errorf("public installer input carries qualification authority")
		}
		authority, err = release.VerifyPublicInstallAuthority(input.ExpectedReleaseManifestDigest, input.ReleaseManifest, input.Checksums, assets, release.PublicInstallObservation{HostFingerprint: actualHost, ObservedAt: now})
	case release.InstallQualification:
		if len(input.ReleaseManifest) != 0 || len(input.Checksums) != 0 || input.ExpectedReleaseManifestDigest != "" {
			return fmt.Errorf("qualification installer input carries public release authority")
		}
		candidateBytes, present := assets["lanpanel"]
		if !present {
			return fmt.Errorf("qualification candidate binary bytes are missing")
		}
		authority, err = release.VerifyQualificationInstallAuthority(input.ExpectedQualificationInstallManifestDigest, input.QualificationInstallManifest, input.QualificationTargetProfile, input.LiveSideEffectPlan, input.QualificationDependencyAuthority, candidateBytes, assets, release.QualificationInstallObservation{HostFingerprint: actualHost, ObservedAt: now})
	default:
		return fmt.Errorf("installer release kind is invalid")
	}
	if err != nil {
		return err
	}
	resumeAttempt, err := journalExists(FixedPaths().Journal)
	if err != nil {
		return err
	}
	if resumeAttempt {
		store, journal, openErr := openJournal(FixedPaths().Journal, 0, 0)
		if openErr != nil {
			return openErr
		}
		closeErr := store.close()
		if closeErr != nil {
			return closeErr
		}
		authority, err = release.BindResumeInstallAuthority(authority, journal.Release)
		if err != nil {
			return err
		}
	}
	identityValue := authority.Identity()
	if input.Kind == release.InstallQualification && !resumeAttempt {
		beforeInventory, inventoryErr := observeBeforeInventory(FixedPaths())
		if inventoryErr != nil {
			return inventoryErr
		}
		plan, decodeErr := release.DecodeLiveSideEffectPlan(input.LiveSideEffectPlan)
		if decodeErr != nil {
			return decodeErr
		}
		bound := false
		for _, mutation := range plan.Mutations {
			if mutation.ID == "clean_install" && mutation.PriorStateDigest == beforeInventory {
				bound = true
			}
		}
		if !bound {
			return fmt.Errorf("qualification side-effect plan does not bind the actual preinstall inventory")
		}
	}

	preflightEvaluator := func(ctx context.Context, management identity.ManagementAuthority, generation uint64) (preflight.ExpansionRequest, preflight.Result, error) {
		profileAuthority := preflight.ProfileAuthority{Kind: preflight.FinalSupportedProfile, Digest: "sha256:" + identityValue.ProfileDigest, LiveQualified: true}
		if input.Kind == release.InstallQualification {
			profileAuthority = preflight.ProfileAuthority{Kind: preflight.QualificationTarget, Digest: "sha256:" + identityValue.ProfileDigest, CandidateDigest: "sha256:" + identityValue.CandidateDigest, InstallManifestDigest: "sha256:" + identityValue.QualificationInstallManifestDigest, SideEffectPlanDigest: "sha256:" + identityValue.SideEffectPlanDigest, HostFingerprint: identityValue.HostFingerprint, RunID: identityValue.RunID}
		}
		paths := FixedPaths()
		confinement := identityValue.Profile.ManagedConfinement
		request := preflight.ExpansionRequest{Scope: preflight.ExpansionBootstrap, Target: "installation", Generation: generation, Profile: preflight.ExpectedProfile{ID: identityValue.Profile.Family, VersionID: identityValue.Profile.Release, Architecture: "amd64", SystemdVersion: identityValue.Profile.SystemdVersion, NginxVersion: identityValue.Profile.NginxVersion, PackageSnapshotDigest: "sha256:" + identityValue.Profile.PackageSnapshotDigest, ManagedConfinement: preflight.ManagedConfinementProfile{SchemaVersion: confinement.SchemaVersion, KernelRelease: confinement.KernelRelease, CgroupMode: confinement.CgroupMode, BindListenPolicy: confinement.BindListenPolicy, ConnectPolicy: confinement.ConnectPolicy, FilesystemPolicy: confinement.FilesystemPolicy, ProtectedDestinations: append([]string(nil), confinement.ProtectedDestinations...), QualificationDigest: "sha256:" + confinement.QualificationDigest}, Authority: profileAuthority}, BootstrapListeners: []preflight.ListenerRequirement{{Protocol: "tcp", Address: management.Address, Port: management.Port, Purpose: "management"}}, ManagedPaths: FixedManagedPathRequirements(paths), Disks: FixedDiskRequirements(paths), LastTrustedWall: identityValue.AuthorityCreatedAt}
		observer, err := preflight.NewLinuxObserver(func(ctx context.Context) (preflight.PackageObservation, error) {
			return preflight.ObserveBootstrapReadiness(ctx)
		})
		if err != nil {
			return preflight.ExpansionRequest{}, preflight.Result{}, err
		}
		observed, err := observer.ObserveExpansion(ctx, request)
		if err != nil {
			return preflight.ExpansionRequest{}, preflight.Result{}, err
		}
		result, err := preflight.EvaluateExpansion(request, observed)
		return request, result, err
	}
	legoBytes, present := assets[identityValue.Lego.Path]
	if !present || release.DigestBytes(legoBytes) != identityValue.Lego.Digest || uint64(len(legoBytes)) != identityValue.Lego.Bytes {
		return fmt.Errorf("selected lego asset missing or mismatched")
	}
	tailscaleBytes, present := assets[identityValue.Tailscale.Path]
	if !present || release.DigestBytes(tailscaleBytes) != identityValue.Tailscale.Digest || uint64(len(tailscaleBytes)) != identityValue.Tailscale.Bytes {
		return fmt.Errorf("selected Tailscale asset missing or mismatched")
	}
	return Install(context.Background(), Request{ReleaseAuthority: authority, Preflight: preflightEvaluator, PackagePlan: input.PackagePlan, PackagePreflight: input.PackagePreflight, PackageTransaction: packages.ExecuteFixedInstallerTransaction, SourceBinary: assets["lanpanel"], ACMEAccountContact: input.ACMEAccountContact, LegoBytes: legoBytes, TailscaleBytes: tailscaleBytes, Now: func() time.Time { return time.Now().UTC() }, Paths: FixedPaths(), Output: stdout, TTY: ControllingTTY{}})
}

func readInstallerAssets(paths map[string]string) (map[string][]byte, error) {
	if len(paths) == 0 || len(paths) > 128 {
		return nil, fmt.Errorf("installer asset path inventory is invalid")
	}
	assets := make(map[string][]byte, len(paths))
	var total int64
	for name, path := range paths {
		if !release.ValidRelativePath(name) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, fmt.Errorf("installer asset reference is invalid")
		}
		for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
			var stat unix.Stat_t
			if unix.Lstat(parent, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o022 != 0 {
				return nil, fmt.Errorf("installer asset parent is unsafe")
			}
			if parent == "/" {
				break
			}
		}
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		file := os.NewFile(uintptr(fd), name)
		if file == nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("installer asset descriptor invalid")
		}
		var before, after unix.Stat_t
		if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Mode&0o022 != 0 || before.Size <= 0 || before.Size > 1<<30 || name == "lanpanel" && before.Mode&0o111 == 0 {
			_ = file.Close()
			return nil, fmt.Errorf("installer asset metadata is unsafe")
		}
		data, readErr := io.ReadAll(io.LimitReader(file, (1<<30)+1))
		statErr := unix.Fstat(fd, &after)
		closeErr := file.Close()
		if readErr != nil || statErr != nil || closeErr != nil || int64(len(data)) != before.Size || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim {
			return nil, fmt.Errorf("installer asset changed while reading")
		}
		total += int64(len(data))
		if total > 1536<<20 {
			return nil, fmt.Errorf("installer asset inventory exceeds bound")
		}
		assets[name] = data
	}
	return assets, nil
}

type ControllingTTY struct{}

func (ControllingTTY) Attached() bool {
	fd, err := unix.Open("/dev/tty", unix.O_WRONLY|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer func() { _ = unix.Close(fd) }()
	var out, tty unix.Stat_t
	return unix.Fstat(int(os.Stdout.Fd()), &out) == nil && unix.Fstat(fd, &tty) == nil && out.Rdev == tty.Rdev && out.Mode&unix.S_IFMT == unix.S_IFCHR
}

func (ControllingTTY) WriteToken(token []byte) error {
	fd, err := unix.Open("/dev/tty", unix.O_WRONLY|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "controlling-tty")
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("controlling TTY is unavailable")
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	if _, err := file.Write([]byte("LanPanel admin token: ")); err != nil {
		return err
	}
	if _, err := file.Write(token); err != nil {
		return err
	}
	_, err = file.Write([]byte("\n"))
	return err
}
