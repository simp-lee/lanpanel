//go:build linux

package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"lanpanel/internal/acmeaccount"
	"lanpanel/internal/identity"
	"lanpanel/internal/packages"
	"lanpanel/internal/preflight"
	"lanpanel/internal/release"
	"os"
	"path/filepath"
	"time"
)

func runPublicInstaller(args []string, stdout io.Writer) error {
	bundleDir, contact, expectedDigest, err := parsePublicInstallerArgs(args)
	if err != nil {
		return err
	}
	resuming, err := journalExists(FixedPaths().Journal)
	if err != nil {
		return err
	}
	if resuming {
		data, journalPhase, err := readPublicInstallerInputFromJournal()
		if err != nil {
			return err
		}
		if err := validatePublicInstallerResume(journalPhase, data); err != nil {
			return err
		}
		var input installerInput
		if err := json.Unmarshal(data, &input); err != nil || input.Kind != release.InstallPublicRelease || input.ACMEAccountContact != contact || input.ExpectedReleaseManifestDigest != expectedDigest {
			return fmt.Errorf("public installer resume authority does not match the requested release, digest, or ACME contact")
		}
		return runInstallerAuthority(data, stdout)
	}
	data, material, err := buildPublicInstallerInput(bundleDir, contact, expectedDigest)
	if err != nil {
		return err
	}
	defer material.Destroy()
	if err := runInstallerAuthorityWithMaterial(data, stdout, &material); err != nil {
		return err
	}
	return nil
}

func parsePublicInstallerArgs(args []string) (string, string, string, error) {
	var bundleDir, contact, expectedDigest string
	seenBundle, seenContact, seenDigest := false, false, false
	for index := 0; index < len(args); index += 2 {
		if index+1 >= len(args) {
			return "", "", "", fmt.Errorf("public installer requires --bundle-dir, --release-digest, and --acme-account-contact")
		}
		value := args[index+1]
		switch args[index] {
		case "--bundle-dir":
			if seenBundle {
				return "", "", "", fmt.Errorf("public installer bundle directory was specified twice")
			}
			seenBundle, bundleDir = true, value
		case "--release-digest":
			if seenDigest {
				return "", "", "", fmt.Errorf("public installer release digest was specified twice")
			}
			seenDigest, expectedDigest = true, value
		case "--acme-account-contact":
			if seenContact {
				return "", "", "", fmt.Errorf("public installer ACME contact was specified twice")
			}
			seenContact, contact = true, value
		default:
			return "", "", "", fmt.Errorf("unknown public installer option %q", args[index])
		}
	}
	if !filepath.IsAbs(bundleDir) || filepath.Clean(bundleDir) != bundleDir || bundleDir == "/" || !release.ValidDigest(expectedDigest) || !acmeaccount.ValidContact(contact) {
		return "", "", "", fmt.Errorf("public installer bundle directory, release digest, or ACME contact is invalid")
	}
	return bundleDir, contact, expectedDigest, nil
}

func buildPublicInstallerInput(bundleDir, contact, expectedDigest string) ([]byte, identity.Material, error) {
	manifestAssets, err := readInstallerAssets(map[string]string{"release.json": filepath.Join(bundleDir, "release.json")})
	if err != nil {
		return nil, identity.Material{}, err
	}
	manifestBytes := manifestAssets["release.json"]
	manifest, err := release.DecodeReleaseManifest(manifestBytes)
	if err != nil {
		return nil, identity.Material{}, fmt.Errorf("public release manifest is invalid: %w", err)
	}
	if release.DigestBytes(manifestBytes) != expectedDigest {
		return nil, identity.Material{}, fmt.Errorf("public release manifest differs from the selected digest")
	}
	runningBinary, err := readCurrentExecutable(manifest.Manifest().Binary.Bytes)
	if err != nil || uint64(len(runningBinary)) != manifest.Manifest().Binary.Bytes || release.DigestBytes(runningBinary) != manifest.Manifest().Binary.Digest {
		return nil, identity.Material{}, fmt.Errorf("running installer binary differs from the selected release")
	}
	paths, err := release.InstallAssetPaths(manifest.Manifest())
	if err != nil {
		return nil, identity.Material{}, err
	}
	assetPaths := make(map[string]string, len(paths)-2)
	for _, path := range paths {
		if path == "release.json" || path == "SHA256SUMS" {
			continue
		}
		assetPaths[path] = filepath.Join(bundleDir, filepath.FromSlash(path))
	}
	assets, err := readInstallerAssets(assetPaths)
	if err != nil {
		return nil, identity.Material{}, err
	}
	checksums, err := readInstallerAssets(map[string]string{"SHA256SUMS": filepath.Join(bundleDir, "SHA256SUMS")})
	if err != nil {
		return nil, identity.Material{}, err
	}
	actualHost, err := observeHostFingerprint()
	if err != nil {
		return nil, identity.Material{}, err
	}
	observedAt := time.Now().UTC().Truncate(time.Second)
	authority, err := release.VerifyPublicInstallAuthority(release.DigestBytes(manifestBytes), manifestBytes, checksums["SHA256SUMS"], assets, release.PublicInstallObservation{HostFingerprint: actualHost, ObservedAt: observedAt})
	if err != nil {
		return nil, identity.Material{}, err
	}
	packageTemplateBytes, present := assets["package-template.json"]
	if !present {
		return nil, identity.Material{}, fmt.Errorf("public release package template is missing")
	}
	var packageTemplate packages.Plan
	if err := release.DecodeCanonical(packageTemplateBytes, &packageTemplate); err != nil {
		return nil, identity.Material{}, fmt.Errorf("public package template is invalid: %w", err)
	}
	material, err := identity.Generate(rand.Reader)
	if err != nil {
		return nil, identity.Material{}, err
	}
	identityValue := authority.Identity()
	preflightEvaluator := newPublicPreflightEvaluator(identityValue)
	packagePreflightRequest, packagePreflight, err := preflightEvaluator(context.Background(), material.Authority, material.SafetyGeneration)
	if err != nil {
		material.Destroy()
		return nil, identity.Material{}, err
	}
	packagePlan, err := bindPublicPackagePlan(packageTemplate, identityValue, material, packagePreflightRequest, packagePreflight, time.Now().UTC(), release.DigestBytes(manifestBytes))
	if err != nil {
		material.Destroy()
		return nil, identity.Material{}, err
	}
	input := installerInput{SchemaVersion: installerInputSchema, Kind: release.InstallPublicRelease, ACMEAccountContact: contact, ExpectedReleaseManifestDigest: release.DigestBytes(manifestBytes), ReleaseManifest: manifestBytes, Checksums: checksums["SHA256SUMS"], AssetPaths: assetPaths, PackagePlan: packagePlan, PackagePreflight: packagePreflight}
	data, err := json.Marshal(input)
	if err != nil || len(data) == 0 || len(data) > maximumPublicInstallerInputBytes {
		material.Destroy()
		return nil, identity.Material{}, fmt.Errorf("public installer authority is invalid or unbounded")
	}
	return data, material, nil
}

func bindPublicPackagePlan(template packages.Plan, identityValue release.InstallIdentity, material identity.Material, request preflight.ExpansionRequest, result preflight.Result, now time.Time, releaseDigest string) (packages.Plan, error) {
	if template.Mode != packages.DistroRepository || packages.ValidatePlan(template) != nil {
		return packages.Plan{}, fmt.Errorf("public package template is not a valid distro repository plan")
	}
	if !identity.ValidateAttemptID(material.AttemptID) || material.SafetyGeneration == 0 || request.Scope != preflight.ExpansionBootstrap || request.Target != "installation" || request.Generation != material.SafetyGeneration || len(request.BootstrapListeners) != 1 || request.BootstrapListeners[0].Address != material.Authority.Address || request.BootstrapListeners[0].Port != material.Authority.Port || preflight.RequireExpansionResultForRequest(result, request, now.UTC()) != nil {
		return packages.Plan{}, fmt.Errorf("public package Plan preflight does not match installation material")
	}
	resultDigest, err := result.Digest()
	if err != nil {
		return packages.Plan{}, err
	}
	plan := template
	plan.TransactionID = "pkg_" + release.DigestBytes([]byte(material.AttemptID+"\x00package"))
	plan.JobID = "job_" + release.DigestBytes([]byte(material.AttemptID+"\x00job"))
	plan.IntentGeneration = result.Generation
	plan.Deadline = now.UTC().Add(plan.TotalTimeout)
	plan.OSProfileDigest = identityValue.ProfileDigest
	plan.NoAutostartPolicyDigest = identityValue.Binary.Digest
	plan.PreflightDigest = resultDigest
	plan.PreflightRequestDigest = result.RequestDigest
	plan.Authority = packages.QualificationAuthority{Kind: packages.FinalSupportedProfile, ReleaseAuthorityDigest: releaseDigest, BinaryDigest: identityValue.Binary.Digest, HostFingerprint: identityValue.HostFingerprint, Operation: "package_transaction", TargetOSProfileDigest: identityValue.ProfileDigest, FrozenClosureDigest: identityValue.Profile.PackageClosureDigest}
	if err := packages.ValidatePlan(plan); err != nil {
		return packages.Plan{}, err
	}
	return plan, nil
}

func newPublicPreflightEvaluator(identityValue release.InstallIdentity) func(context.Context, identity.ManagementAuthority, uint64) (preflight.ExpansionRequest, preflight.Result, error) {
	return func(ctx context.Context, management identity.ManagementAuthority, generation uint64) (preflight.ExpansionRequest, preflight.Result, error) {
		profileAuthority := preflight.ProfileAuthority{Kind: preflight.FinalSupportedProfile, Digest: "sha256:" + identityValue.ProfileDigest, LiveQualified: true}
		confinement := identityValue.Profile.ManagedConfinement
		request := preflight.ExpansionRequest{Scope: preflight.ExpansionBootstrap, Target: "installation", Generation: generation, Profile: preflight.ExpectedProfile{ID: identityValue.Profile.Family, VersionID: identityValue.Profile.Release, Architecture: "amd64", SystemdVersion: identityValue.Profile.SystemdVersion, NginxVersion: identityValue.Profile.NginxVersion, PackageSnapshotDigest: "sha256:" + identityValue.Profile.PackageSnapshotDigest, ManagedConfinement: preflight.ManagedConfinementProfile{SchemaVersion: confinement.SchemaVersion, KernelRelease: confinement.KernelRelease, CgroupMode: confinement.CgroupMode, BindListenPolicy: confinement.BindListenPolicy, ConnectPolicy: confinement.ConnectPolicy, FilesystemPolicy: confinement.FilesystemPolicy, ProtectedDestinations: append([]string(nil), confinement.ProtectedDestinations...), QualificationDigest: "sha256:" + confinement.QualificationDigest}, Authority: profileAuthority}, BootstrapListeners: []preflight.ListenerRequirement{{Protocol: "tcp", Address: management.Address, Port: management.Port, Purpose: "management"}}, ManagedPaths: FixedManagedPathRequirements(FixedPaths()), Disks: FixedDiskRequirements(FixedPaths()), LastTrustedWall: identityValue.AuthorityCreatedAt}
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
}

func readCurrentExecutable(maximum uint64) ([]byte, error) {
	file, err := os.Open("/proc/self/exe")
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || uint64(len(data)) > maximum {
		return nil, fmt.Errorf("current installer executable is unreadable or exceeds the selected release size")
	}
	return data, nil
}

func validatePublicInstallerResume(phase Phase, data []byte) error {
	if phase == PhaseActivated {
		return fmt.Errorf("installation is already activated")
	}
	if len(data) == 0 {
		return fmt.Errorf("public installer resume authority is missing from the bootstrap journal")
	}
	return nil
}

func readPublicInstallerInputFromJournal() ([]byte, Phase, error) {
	store, journal, err := openJournal(FixedPaths().Journal, 0, 0)
	if err != nil {
		return nil, "", fmt.Errorf("public installer resume journal is unreadable: %w", err)
	}
	closeErr := store.close()
	if closeErr != nil {
		return nil, "", closeErr
	}
	return append([]byte(nil), journal.InstallerInput...), journal.Phase, nil
}
