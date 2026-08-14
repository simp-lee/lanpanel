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
	"lanpanel/internal/preflight"
	"lanpanel/internal/release"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

const installerInputSchema = "lanpanel.installer.input.v1"
const maximumInstallerInputBytes = 32 << 20

type installerInput struct {
	SchemaVersion                       string                           `json:"schema_version"`
	Kind                                release.EnvelopeKind             `json:"kind"`
	ExpectedEnvelopeDigest              string                           `json:"expected_envelope_digest"`
	ExpectedManifestDigest              string                           `json:"expected_manifest_digest,omitempty"`
	ExpectedQualificationManifestDigest string                           `json:"expected_qualification_manifest_digest,omitempty"`
	Envelope                            []byte                           `json:"envelope"`
	Manifest                            []byte                           `json:"manifest,omitempty"`
	QualificationManifest               []byte                           `json:"qualification_manifest,omitempty"`
	Checksums                           []byte                           `json:"checksums"`
	Assets                              map[string][]byte                `json:"assets"`
	ObservedCandidate                   release.QualificationObservation `json:"observed_candidate"`
	ObservedFinal                       release.FinalInstallObservation  `json:"observed_final"`
	SourceBinaryPath                    string                           `json:"source_binary_path"`
}

// RunInstallerRole accepts no mutable argv. The release tooling supplies one
// bounded canonical authority document on inherited fd 3.
func RunInstallerRole(args []string, stdout io.Writer) error {
	if len(args) != 0 || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return fmt.Errorf("installer requires its fixed root invocation")
	}
	file := os.NewFile(3, "installer-authority")
	if file == nil {
		return fmt.Errorf("installer release authority descriptor is missing")
	}
	defer file.Close()
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
	if !bytes.Equal(canonical, data) || input.SchemaVersion != installerInputSchema {
		return fmt.Errorf("installer release authority is noncanonical")
	}
	var authority *release.InstallAuthority
	switch input.Kind {
	case release.EnvelopeQualificationCandidate:
		input.ObservedCandidate.ObservedAt = time.Now().UTC().Truncate(time.Second)
		authority, err = release.VerifyCandidateInstallAuthority(input.ExpectedEnvelopeDigest, input.ExpectedQualificationManifestDigest, input.Envelope, input.Checksums, input.QualificationManifest, input.Assets, input.ObservedCandidate)
	case release.EnvelopeFinal:
		input.ObservedFinal.ObservedAt = time.Now().UTC().Truncate(time.Second)
		authority, err = release.VerifyFinalInstallAuthority(input.ExpectedManifestDigest, input.ExpectedEnvelopeDigest, input.Manifest, input.Envelope, input.Checksums, input.Assets, input.ObservedFinal)
	default:
		return fmt.Errorf("installer release kind is invalid")
	}
	if err != nil {
		return err
	}
	identityValue := authority.Identity()

	actualHost, err := observeHostFingerprint()
	if err != nil {
		return err
	}
	if actualHost != identityValue.HostFingerprint {
		return fmt.Errorf("installer host fingerprint differs from release authority")
	}
	beforeInventory, err := observeBeforeInventory(FixedPaths())
	if err != nil {
		return err
	}
	if !filepath.IsAbs(input.SourceBinaryPath) || filepath.Clean(input.SourceBinaryPath) != input.SourceBinaryPath || filepath.Base(input.SourceBinaryPath) != filepath.Base(identityValue.Binary.Path) {
		return fmt.Errorf("installer binary source is not the selected release asset")
	}
	qualification := release.QualificationManifest{}
	if input.Kind == release.EnvelopeQualificationCandidate {
		verified, err := release.DecodeQualificationManifest(input.QualificationManifest, input.ExpectedQualificationManifestDigest)
		if err != nil {
			return err
		}
		qualification = verified.Value()
		if qualification.BeforeInventoryDigest != beforeInventory || qualification.AuthorizedHostFingerprint != actualHost {
			return fmt.Errorf("qualification manifest before-inventory or host differs from actual observation")
		}
	}
	preflightEvaluator := func(ctx context.Context, management identity.ManagementAuthority, generation uint64) (preflight.ExpansionRequest, preflight.Result, error) {
		profileAuthority := preflight.ProfileAuthority{Kind: preflight.FinalSupportedProfile, Digest: "sha256:" + identityValue.ProfileDigest, LiveQualified: true}
		if input.Kind == release.EnvelopeQualificationCandidate {
			profileAuthority = preflight.ProfileAuthority{Kind: preflight.QualificationCandidate, Digest: "sha256:" + identityValue.ProfileDigest, CandidateDigest: "sha256:" + identityValue.CandidateDigest, ManifestDigest: "sha256:" + identityValue.QualificationManifest, HostFingerprint: identityValue.HostFingerprint, CaseID: identityValue.CaseID}
		}
		paths := FixedPaths()
		confinement := identityValue.Profile.ManagedConfinement
		request := preflight.ExpansionRequest{Scope: preflight.ExpansionBootstrap, Target: "installation", Generation: generation, Profile: preflight.ExpectedProfile{ID: identityValue.Profile.Family, VersionID: identityValue.Profile.Release, Architecture: "amd64", SystemdVersion: identityValue.Profile.SystemdVersion, NginxVersion: identityValue.Profile.NginxVersion, PackageSnapshotDigest: "sha256:" + identityValue.Profile.PackageSnapshotDigest, ManagedConfinement: preflight.ManagedConfinementProfile{SchemaVersion: confinement.SchemaVersion, KernelRelease: confinement.KernelRelease, CgroupMode: confinement.CgroupMode, BindListenPolicy: confinement.BindListenPolicy, ConnectPolicy: confinement.ConnectPolicy, FilesystemPolicy: confinement.FilesystemPolicy, ProtectedDestinations: append([]string(nil), confinement.ProtectedDestinations...), QualificationDigest: "sha256:" + confinement.QualificationDigest}, Authority: profileAuthority}, BootstrapListeners: []preflight.ListenerRequirement{{Protocol: "tcp", Address: management.Address, Port: management.Port, Purpose: "management"}}, ManagedPaths: FixedManagedPathRequirements(paths), Disks: FixedDiskRequirements(paths), LastTrustedWall: identityValue.AuthorityCreatedAt}
		packageRead := func(ctx context.Context) (preflight.PackageObservation, error) {
			return preflight.ObserveBootstrapReadiness(ctx)
		}
		observer, err := preflight.NewLinuxObserver(packageRead)
		if err != nil {
			return preflight.ExpansionRequest{}, preflight.Result{}, err
		}
		observed, err := observer.ObserveExpansion(ctx, request)
		if err != nil {
			return preflight.ExpansionRequest{}, preflight.Result{}, err
		}
		if input.Kind == release.EnvelopeQualificationCandidate && (qualification.AuthorizedHostFingerprint != actualHost || qualification.BeforeInventoryDigest != beforeInventory || qualification.Operation != "bootstrap_install") {
			return preflight.ExpansionRequest{}, preflight.Result{}, fmt.Errorf("qualification manifest bootstrap host or operation mismatched")
		}
		result, err := preflight.EvaluateExpansion(request, observed)
		return request, result, err
	}
	legoBytes, present := input.Assets[identityValue.Lego.Path]
	if !present {
		return fmt.Errorf("selected lego asset missing")
	}
	return Install(context.Background(), Request{ReleaseAuthority: authority, Preflight: preflightEvaluator, SourceBinaryPath: input.SourceBinaryPath, LegoBytes: legoBytes, Now: func() time.Time { return time.Now().UTC() }, Paths: FixedPaths(), Output: stdout, TTY: ControllingTTY{}})
}

type ControllingTTY struct{}

func (ControllingTTY) Attached() bool {
	fd, err := unix.Open("/dev/tty", unix.O_WRONLY|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer unix.Close(fd)
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
	defer file.Close()
	if _, err := file.Write([]byte("LanPanel admin token: ")); err != nil {
		return err
	}
	if _, err := file.Write(token); err != nil {
		return err
	}
	_, err = file.Write([]byte("\n"))
	return err
}
