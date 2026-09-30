//go:build linux

package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"lanpanel/internal/identity"
	"lanpanel/internal/packages"
	"lanpanel/internal/preflight"
	"lanpanel/internal/release"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

func observePublicPlatform() (preflight.PlatformInfo, error) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return preflight.PlatformInfo{}, fmt.Errorf("read host OS profile: %w", err)
	}
	platform := preflight.ParseOSRelease(string(data))
	if platform.ID == "" {
		return preflight.PlatformInfo{}, fmt.Errorf("host platform identity is incomplete")
	}
	return platform, nil
}

func runPublicInstaller(args []string, stdout io.Writer) error {
	if len(args) != 0 {
		return fmt.Errorf("public install accepts no options; unpack the official release and run ./lanpanel install")
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
		if journalPhase == PhaseActivated {
			bundleDir, err := currentArtifactDirectory()
			if err != nil {
				return err
			}
			material, packagePlan, packagePreflight, err := readPublicInstallerReplayAuthority()
			if err != nil {
				return err
			}
			data, material, err := buildPublicInstallerInputWithMaterial(bundleDir, material, &packagePlan, &packagePreflight)
			if err != nil {
				return err
			}
			defer material.Destroy()
			return runInstallerAuthority(data, stdout)
		}
		return runInstallerAuthority(data, stdout)
	}
	bundleDir, err := currentArtifactDirectory()
	if err != nil {
		return err
	}
	data, material, err := buildPublicInstallerInput(bundleDir)
	if err != nil {
		return err
	}
	defer material.Destroy()
	if err := runInstallerAuthorityWithMaterial(data, stdout, &material); err != nil {
		return err
	}
	return nil
}

func currentArtifactDirectory() (string, error) {
	executable, err := os.Readlink("/proc/self/exe")
	if err != nil || !filepath.IsAbs(executable) || filepath.Clean(executable) != executable || filepath.Base(executable) != "lanpanel" {
		return "", fmt.Errorf("public install must run from the official lanpanel artifact")
	}
	return filepath.Dir(executable), nil
}

func buildPublicInstallerInput(bundleDir string) ([]byte, identity.Material, error) {
	material, err := identity.Generate(rand.Reader)
	if err != nil {
		return nil, identity.Material{}, err
	}
	data, built, err := buildPublicInstallerInputWithMaterial(bundleDir, material, nil, nil)
	if err != nil {
		material.Destroy()
	}
	return data, built, err
}

func buildPublicInstallerInputWithMaterial(bundleDir string, material identity.Material, packagePlanOverride *packages.Plan, packagePreflightOverride *preflight.Result) ([]byte, identity.Material, error) {
	manifestAssets, err := readInstallerAssets(map[string]string{"release.json": filepath.Join(bundleDir, "release.json")})
	if err != nil {
		return nil, identity.Material{}, err
	}
	manifestBytes := manifestAssets["release.json"]
	manifest, err := release.DecodeReleaseManifest(manifestBytes)
	if err != nil {
		return nil, identity.Material{}, fmt.Errorf("public release manifest is invalid: %w", err)
	}
	runningBinary, err := readCurrentExecutable(manifest.Manifest().Binary.Bytes)
	if err != nil || uint64(len(runningBinary)) != manifest.Manifest().Binary.Bytes || release.DigestBytes(runningBinary) != manifest.Manifest().Binary.Digest {
		return nil, identity.Material{}, fmt.Errorf("running installer binary differs from the selected release")
	}
	paths, err := release.InstallAssetPaths(manifest.Manifest())
	if err != nil {
		return nil, identity.Material{}, err
	}
	if err := validateArtifactDirectory(bundleDir, paths); err != nil {
		return nil, identity.Material{}, err
	}
	assetPaths := make(map[string]string, len(paths)-3)
	for _, path := range paths {
		if path == "release.json" || path == "SHA256SUMS" || path == release.ReleaseSignaturePath {
			continue
		}
		assetPaths[path] = filepath.Join(bundleDir, filepath.FromSlash(path))
	}
	assets, err := readInstallerAssets(assetPaths)
	if err != nil {
		return nil, identity.Material{}, err
	}
	checksums, err := readInstallerAssets(map[string]string{"SHA256SUMS": filepath.Join(bundleDir, "SHA256SUMS"), release.ReleaseSignaturePath: filepath.Join(bundleDir, release.ReleaseSignaturePath)})
	if err != nil {
		return nil, identity.Material{}, err
	}
	actualHost, err := observeHostFingerprint()
	if err != nil {
		return nil, identity.Material{}, err
	}
	platform, err := observePublicPlatform()
	if err != nil {
		return nil, identity.Material{}, err
	}
	observedAt := time.Now().UTC().Truncate(time.Second)
	authority, err := release.VerifyPublicInstallAuthority(release.DigestBytes(manifestBytes), manifestBytes, checksums[release.ReleaseSignaturePath], checksums["SHA256SUMS"], assets, release.PublicInstallObservation{HostFingerprint: actualHost, ObservedAt: observedAt, OSID: platform.ID, OSVersionID: platform.VersionID, Architecture: runtime.GOARCH})
	if err != nil {
		return nil, identity.Material{}, err
	}
	selectedProfile, err := release.SelectSupportedProfile(manifestBytes, platform.ID, platform.VersionID, runtime.GOARCH)
	if err != nil {
		return nil, identity.Material{}, err
	}
	packageTemplateBytes, present := assets[selectedProfile.PackageTemplate.Path]
	if !present {
		return nil, identity.Material{}, fmt.Errorf("public release package template is missing")
	}
	var packageTemplate packages.Plan
	if err := release.DecodeCanonical(packageTemplateBytes, &packageTemplate); err != nil {
		return nil, identity.Material{}, fmt.Errorf("public package template is invalid: %w", err)
	}
	identityValue := authority.Identity()
	var packagePlan packages.Plan
	var packagePreflight preflight.Result
	if packagePlanOverride != nil || packagePreflightOverride != nil {
		if packagePlanOverride == nil || packagePreflightOverride == nil {
			material.Destroy()
			return nil, identity.Material{}, fmt.Errorf("public installer package replay authority is incomplete")
		}
		packagePlan = *packagePlanOverride
		packagePreflight = *packagePreflightOverride
	} else {
		preflightEvaluator := newInstallerPreflightEvaluator(identityValue)
		packagePreflightRequest, evaluatedPreflight, err := preflightEvaluator(context.Background(), material.Authority, material.SafetyGeneration)
		if err != nil {
			material.Destroy()
			return nil, identity.Material{}, err
		}
		packagePlan, err = bindPublicPackagePlan(packageTemplate, identityValue, material, packagePreflightRequest, evaluatedPreflight, time.Now().UTC(), release.DigestBytes(manifestBytes))
		if err != nil {
			material.Destroy()
			return nil, identity.Material{}, err
		}
		packagePreflight = evaluatedPreflight
	}
	input := installerInput{SchemaVersion: installerInputSchema, Kind: release.InstallPublicRelease, ExpectedReleaseManifestDigest: release.DigestBytes(manifestBytes), ReleaseManifest: manifestBytes, ReleaseSignature: checksums[release.ReleaseSignaturePath], Checksums: checksums["SHA256SUMS"], AssetPaths: assetPaths, PackagePlan: packagePlan, PackagePreflight: packagePreflight}
	data, err := json.Marshal(input)
	if err != nil || len(data) == 0 || len(data) > maximumPublicInstallerInputBytes {
		material.Destroy()
		return nil, identity.Material{}, fmt.Errorf("public installer authority is invalid or unbounded")
	}
	return data, material, nil
}

func bindPublicPackagePlan(template packages.Plan, identityValue release.InstallIdentity, material identity.Material, request preflight.ExpansionRequest, result preflight.Result, now time.Time, releaseDigest string) (packages.Plan, error) {
	if packages.ValidatePublicReleasePlan(template) != nil {
		return packages.Plan{}, fmt.Errorf("public package template is not a valid distro repository plan")
	}
	requireErr := preflight.RequireExpansionResultForRequest(result, request, now.UTC())
	if !identity.ValidateAttemptID(material.AttemptID) || material.SafetyGeneration == 0 || request.Scope != preflight.ExpansionBootstrap || request.Target != "installation" || request.Generation != material.SafetyGeneration || len(request.BootstrapListeners) != 1 || request.BootstrapListeners[0].Address != material.Authority.Address || request.BootstrapListeners[0].Port != material.Authority.Port || requireErr != nil {
		return packages.Plan{}, fmt.Errorf("public package Plan preflight does not match installation material: attempt=%q safety=%d scope=%q target=%q generation=%d authority=%s:%d listeners=%#v result_generation=%d result_request=%q now=%s require=%v allowed=%t findings=%#v valid_until=%s", material.AttemptID, material.SafetyGeneration, request.Scope, request.Target, request.Generation, material.Authority.Address, material.Authority.Port, request.BootstrapListeners, result.Generation, result.RequestDigest, now.UTC().Format(time.RFC3339), requireErr, result.Allowed, result.Findings, result.ValidUntil.UTC().Format(time.RFC3339))
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
	plan.CapabilityContractDigest = identityValue.ProfileDigest
	plan.OSProfileDigest = identityValue.ProfileDigest
	plan.NoAutostartPolicyDigest = identityValue.Binary.Digest
	plan.PreflightDigest = resultDigest
	plan.PreflightRequestDigest = result.RequestDigest
	plan.Authority = packages.Authority{Kind: packages.PreviewProfile, ReleaseAuthorityDigest: releaseDigest, BinaryDigest: identityValue.Binary.Digest, HostFingerprint: identityValue.HostFingerprint, TargetCapabilityContractDigest: identityValue.ProfileDigest, TargetOSProfileDigest: identityValue.ProfileDigest}
	if err := packages.ValidatePlan(plan); err != nil {
		return packages.Plan{}, err
	}
	return plan, nil
}

func validateArtifactDirectory(root string, expected []string) error {
	allowed := map[string]bool{"release.json": true}
	for _, path := range expected {
		allowed[path] = true
	}
	seen := make(map[string]bool, len(allowed))
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || !release.ValidRelativePath(filepath.ToSlash(relative)) {
			return fmt.Errorf("public release artifact path is unsafe")
		}
		relative = filepath.ToSlash(relative)
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() || !allowed[relative] || seen[relative] {
			return fmt.Errorf("public release artifact contains an unexpected or duplicate asset %q", relative)
		}
		seen[relative] = true
		return nil
	})
	if err != nil {
		return err
	}
	for path := range allowed {
		if !seen[path] && path != "release.json" {
			return fmt.Errorf("public release artifact asset %q is missing", path)
		}
	}
	return nil
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
		return nil
	}
	if len(data) == 0 {
		return fmt.Errorf("public installer resume authority is missing from the bootstrap journal")
	}
	return nil
}

func readPublicInstallerReplayAuthority() (identity.Material, packages.Plan, preflight.Result, error) {
	store, journal, err := openJournal(FixedPaths().Journal, 0, 0)
	if err != nil {
		return identity.Material{}, packages.Plan{}, preflight.Result{}, err
	}
	if closeErr := store.close(); closeErr != nil {
		return identity.Material{}, packages.Plan{}, preflight.Result{}, closeErr
	}
	if journal.Phase != PhaseActivated {
		return identity.Material{}, packages.Plan{}, preflight.Result{}, fmt.Errorf("public installer replay journal is not activated")
	}
	return identity.Material{AttemptID: journal.AttemptID, InstallationID: journal.InstallationID, GenerationID: journal.GenerationID, SafetyGeneration: journal.SafetyGeneration, Authority: journal.Authority}, journal.PackagePlan, journal.PackagePreflight, nil
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
