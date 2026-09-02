package qualification

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"lanpanel/internal/packages"
	"lanpanel/internal/preflight"
	"lanpanel/internal/release"
	"strings"
	"time"
)

func validateQualificationPackageTemplate(template packages.Plan, profile release.OSProfile) error {
	if template.Mode != packages.DistroRepository || template.Proxy != nil || !template.FirstNginxInstall {
		return fmt.Errorf("qualification package template must be a first-install distro repository plan")
	}
	profileDigest, err := release.ProfileDigest(profile)
	if err != nil {
		return err
	}
	zeroDigest := strings.Repeat("0", 64)
	oneDigest := strings.Repeat("1", 64)
	candidate := template
	candidate.TransactionID = "pkg_" + zeroDigest
	candidate.JobID = "job_" + oneDigest
	candidate.IntentGeneration = 1
	candidate.Deadline = time.Unix(4102444800, 0).UTC()
	candidate.OSProfileDigest = profileDigest
	candidate.NoAutostartPolicyDigest = zeroDigest
	candidate.PreflightDigest = "sha256:" + zeroDigest
	candidate.PreflightRequestDigest = "sha256:" + oneDigest
	candidate.Authority = packages.QualificationAuthority{Kind: packages.QualificationTarget, ReleaseAuthorityDigest: zeroDigest, BinaryDigest: zeroDigest, RunID: "run_template", InstallManifestDigest: zeroDigest, SideEffectPlanDigest: zeroDigest, HostFingerprint: "host-template", Operation: "package_transaction", TargetOSProfileDigest: profileDigest, FrozenClosureDigest: profile.PackageClosureDigest}
	if err := packages.ValidatePlan(candidate); err != nil {
		return fmt.Errorf("qualification package template is invalid: %w", err)
	}
	if len(candidate.Packages) != len(profile.Packages) {
		return fmt.Errorf("qualification package template closure differs from target profile")
	}
	for index, pkg := range candidate.Packages {
		want := profile.Packages[index]
		if pkg.Name != want.Name || pkg.Version != want.Version || pkg.Architecture != want.Architecture {
			return fmt.Errorf("qualification package template tuple differs from target profile")
		}
	}
	if len(candidate.Repositories) != 1 {
		return fmt.Errorf("qualification package template repository is incomplete")
	}
	repositoryDigest, err := release.RepositoryAuthorityDigest(candidate.Repositories[0])
	if err != nil || repositoryDigest != profile.RepositoryAuthorityDigest {
		return fmt.Errorf("qualification package template repository authority differs from target profile")
	}
	return nil
}

func BindQualificationPackagePlan(template packages.Plan, manifest release.QualificationInstallManifest, sideEffects release.LiveSideEffectPlan, profile release.OSProfile, result preflight.Result, now time.Time) (packages.Plan, error) {
	if now.IsZero() || manifest.RunID != sideEffects.RunID || manifest.SideEffectPlanDigest == "" || result.Generation == 0 {
		return packages.Plan{}, fmt.Errorf("qualification package binding authority is invalid")
	}
	now = now.UTC()
	profileDigest, err := release.ProfileDigest(profile)
	if err != nil || manifest.TargetProfileDigest != profileDigest {
		return packages.Plan{}, fmt.Errorf("qualification package target profile changed")
	}
	if err := validateQualificationPackageTemplate(template, profile); err != nil {
		return packages.Plan{}, err
	}
	if err := preflight.ValidateFreshResult(result, now); err != nil || result.Scope != string(preflight.ExpansionBootstrap) || result.Target != "installation" {
		return packages.Plan{}, fmt.Errorf("qualification package preflight is not fresh and exact: %w", err)
	}
	preflightDigest, err := result.Digest()
	if err != nil {
		return packages.Plan{}, err
	}
	closureDigest, err := packages.ClosureDigest(template.Packages)
	if err != nil || closureDigest != profile.PackageClosureDigest {
		return packages.Plan{}, fmt.Errorf("qualification package template closure differs from target profile")
	}
	manifestBytes, err := release.MarshalCanonical(manifest)
	if err != nil {
		return packages.Plan{}, err
	}
	manifestDigest := release.DigestBytes(manifestBytes)
	plan := template
	plan.TransactionID = "pkg_" + qualificationPlanID(manifest.RunID, "transaction")
	plan.JobID = "job_" + qualificationPlanID(manifest.RunID, "job")
	plan.IntentGeneration = result.Generation
	plan.Deadline = now.Add(plan.TotalTimeout)
	plan.OSProfileDigest = profileDigest
	plan.NoAutostartPolicyDigest = manifest.CandidateBinary.Digest
	plan.PreflightDigest = preflightDigest
	plan.PreflightRequestDigest = result.RequestDigest
	plan.Authority = packages.QualificationAuthority{
		Kind: packages.QualificationTarget, ReleaseAuthorityDigest: manifestDigest, BinaryDigest: manifest.CandidateBinary.Digest,
		RunID: manifest.RunID, InstallManifestDigest: manifestDigest, SideEffectPlanDigest: manifest.SideEffectPlanDigest,
		HostFingerprint: manifest.AuthorizedHostFingerprint, Operation: "package_transaction", TargetOSProfileDigest: profileDigest, FrozenClosureDigest: closureDigest,
	}
	if err := packages.ValidatePlan(plan); err != nil {
		return packages.Plan{}, err
	}
	return plan, nil
}

func qualificationPlanID(runID, kind string) string {
	digest := sha256.Sum256([]byte("lanpanel.qualification.package-plan.v1\x00" + runID + "\x00" + kind))
	return hex.EncodeToString(digest[:])
}
