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
	"time"
)

const qualificationInstallerInputSchema = "lanpanel.qualification.installer-input.v1"

type QualificationInstallerAuthority struct {
	ACMEAccountContact            string            `json:"acme_account_contact"`
	InstallManifest               []byte            `json:"qualification_install_manifest"`
	TargetProfile                 []byte            `json:"qualification_target_profile"`
	SideEffectPlan                []byte            `json:"live_side_effect_plan"`
	DependencyAuthority           []byte            `json:"qualification_dependency_authority"`
	ExpectedInstallManifestDigest string            `json:"expected_qualification_install_manifest_digest"`
	RemoteAssetPaths              map[string]string `json:"asset_paths"`
	PackageTemplate               []byte            `json:"package_template"`
}

type qualificationInstallerInput struct {
	SchemaVersion string `json:"schema_version"`
	QualificationInstallerAuthority
}

func BuildQualificationInstallerAuthority(authority QualificationInstallerAuthority) ([]byte, error) {
	data, err := json.Marshal(qualificationInstallerInput{qualificationInstallerInputSchema, authority})
	if err != nil || len(data) == 0 || len(data) > maximumInstallerInputBytes {
		return nil, fmt.Errorf("qualification installer authority is invalid or unbounded")
	}
	return data, nil
}

// RunQualificationInstallerAuthority prepares and installs in one fixed agent
// invocation. Both fresh preflights use the same generated installation material;
// the existing bound-input installer independently revalidates before journaling.
func RunQualificationInstallerAuthority(data []byte, runID, candidateDigest string, stdout io.Writer) (preflight.Result, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return preflight.Result{}, fmt.Errorf("qualification installer requires root")
	}
	var input qualificationInstallerInput
	if len(data) == 0 || len(data) > maximumInstallerInputBytes || release.DecodeCanonical(data, &input) != nil || input.SchemaVersion != qualificationInstallerInputSchema {
		return preflight.Result{}, fmt.Errorf("qualification installer input is invalid or noncanonical")
	}
	manifest, err := release.DecodeQualificationInstallManifest(input.InstallManifest)
	if err != nil || manifest.RunID != runID || manifest.CandidateBinary.Digest != candidateDigest || manifest.ACMEAccountContact != input.ACMEAccountContact {
		return preflight.Result{}, fmt.Errorf("qualification installer input differs from agent authority")
	}
	assets, err := readInstallerAssets(input.RemoteAssetPaths)
	if err != nil {
		return preflight.Result{}, err
	}
	host, err := observeHostFingerprint()
	if err != nil {
		return preflight.Result{}, err
	}
	authority, err := release.VerifyQualificationInstallAuthority(input.ExpectedInstallManifestDigest, input.InstallManifest, input.TargetProfile, input.SideEffectPlan, input.DependencyAuthority, assets["lanpanel"], assets, release.QualificationInstallObservation{HostFingerprint: host, ObservedAt: time.Now().UTC().Truncate(time.Second)})
	if err != nil {
		return preflight.Result{}, err
	}
	present, err := journalExists(FixedPaths().Journal)
	if err != nil {
		return preflight.Result{}, err
	}
	if present {
		return preflight.Result{}, fmt.Errorf("qualification install cannot replay an existing bootstrap attempt; runner recovery is cleanup-only")
	}
	installed := authority.Identity()
	return runPreparedQualificationInstaller(input, manifest.PackageTemplateDigest, installed, stdout, newInstallerPreflightEvaluator(installed), rand.Reader, time.Now, runInstallerAuthorityWithMaterial)
}

func runPreparedQualificationInstaller(input qualificationInstallerInput, templateDigest string, installed release.InstallIdentity, stdout io.Writer, evaluate PreflightEvaluator, random io.Reader, now func() time.Time, runInstaller func([]byte, io.Writer, *identity.Material) error) (preflight.Result, error) {
	plan, result, material, err := prepareQualificationPackagePlan(context.Background(), input.PackageTemplate, templateDigest, installed, evaluate, random, now)
	if err != nil {
		return result, err
	}
	defer material.Destroy()
	bound := installerInput{
		SchemaVersion: installerInputSchema, Kind: release.InstallQualification, ACMEAccountContact: input.ACMEAccountContact,
		ExpectedQualificationInstallManifestDigest: input.ExpectedInstallManifestDigest,
		QualificationInstallManifest:               input.InstallManifest, QualificationTargetProfile: input.TargetProfile,
		LiveSideEffectPlan: input.SideEffectPlan, QualificationDependencyAuthority: input.DependencyAuthority,
		AssetPaths: input.RemoteAssetPaths, PackagePlan: plan, PackagePreflight: result,
	}
	boundBytes, err := json.Marshal(bound)
	if err != nil || len(boundBytes) > maximumInstallerInputBytes {
		return result, fmt.Errorf("bound qualification installer input is invalid or unbounded")
	}
	return result, runInstaller(boundBytes, stdout, &material)
}

func prepareQualificationPackagePlan(ctx context.Context, templateBytes []byte, templateDigest string, installed release.InstallIdentity, evaluate PreflightEvaluator, random io.Reader, now func() time.Time) (packages.Plan, preflight.Result, identity.Material, error) {
	var template packages.Plan
	if installed.Kind != release.InstallQualification || release.ValidateInstallIdentity(installed) != nil || release.DigestBytes(templateBytes) != templateDigest || release.DecodeCanonical(templateBytes, &template) != nil {
		return packages.Plan{}, preflight.Result{}, identity.Material{}, fmt.Errorf("qualification package template or install authority changed")
	}
	if err := release.ValidateQualificationPackageTemplate(template, installed.Profile); err != nil {
		return packages.Plan{}, preflight.Result{}, identity.Material{}, err
	}
	material, err := identity.Generate(random)
	if err != nil {
		return packages.Plan{}, preflight.Result{}, identity.Material{}, err
	}
	request, result, err := evaluate(ctx, material.Authority, material.SafetyGeneration)
	if err == nil {
		err = validateBootstrapPreflight(installed, material.Authority, material.SafetyGeneration, request, result, now().UTC())
	}
	if err != nil {
		material.Destroy()
		return packages.Plan{}, result, identity.Material{}, err
	}
	resultDigest, err := result.Digest()
	if err != nil {
		material.Destroy()
		return packages.Plan{}, result, identity.Material{}, err
	}
	plan := template
	plan.TransactionID = "pkg_" + release.DigestBytes([]byte(material.AttemptID+"\x00package"))
	plan.JobID = "job_" + release.DigestBytes([]byte(material.AttemptID+"\x00job"))
	plan.IntentGeneration = material.SafetyGeneration
	plan.Deadline = now().UTC().Add(plan.TotalTimeout)
	plan.OSProfileDigest = installed.ProfileDigest
	plan.NoAutostartPolicyDigest = installed.CandidateDigest
	plan.PreflightDigest = resultDigest
	plan.PreflightRequestDigest = result.RequestDigest
	plan.Authority = packages.QualificationAuthority{Kind: packages.QualificationTarget, ReleaseAuthorityDigest: installed.QualificationInstallManifestDigest, BinaryDigest: installed.CandidateDigest, RunID: installed.RunID, InstallManifestDigest: installed.QualificationInstallManifestDigest, SideEffectPlanDigest: installed.SideEffectPlanDigest, HostFingerprint: installed.HostFingerprint, Operation: "package_transaction", TargetOSProfileDigest: installed.ProfileDigest, FrozenClosureDigest: installed.Profile.PackageClosureDigest}
	if _, err := validateInstallerPackageAuthority(installed, plan, result); err != nil {
		material.Destroy()
		return packages.Plan{}, result, identity.Material{}, err
	}
	return plan, result, material, nil
}
