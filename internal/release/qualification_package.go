package release

import (
	"fmt"
	"lanpanel/internal/packages"
	"strings"
	"time"
)

// ValidateQualificationPackageTemplate checks immutable package/profile authority
// without manufacturing a runtime bootstrap preflight or installation identity.
func ValidateQualificationPackageTemplate(template packages.Plan, profile OSProfile) error {
	if template.Mode != packages.DistroRepository || template.Proxy != nil || !template.FirstNginxInstall {
		return fmt.Errorf("qualification package template must be a first-install distro repository plan")
	}
	profileDigest, err := ProfileDigest(profile)
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
	repositoryDigest, err := RepositoryAuthorityDigest(candidate.Repositories[0])
	if err != nil || repositoryDigest != profile.RepositoryAuthorityDigest {
		return fmt.Errorf("qualification package template repository authority differs from target profile")
	}
	return nil
}
