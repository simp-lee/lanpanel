//go:build linux

package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"io"
	"lanpanel/internal/identity"
	"lanpanel/internal/packages"
	"lanpanel/internal/preflight"
	"lanpanel/internal/release"
	"lanpanel/internal/sources"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestQualificationPreparationAndInstallerShareManagementMaterial(t *testing.T) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		t.Skip("requires isolated root for the installer's real account inventory observation")
	}
	t.Run("production_handoff", testQualificationProductionHandoff)
	t.Run("bound_resume", testQualificationBoundResume)
}

func testQualificationProductionHandoff(t *testing.T) {
	root := filepath.Join(t.TempDir(), "fresh")
	installed, template, now := qualificationPackageFixture(t, root)
	templateBytes, err := release.MarshalCanonical(template)
	if err != nil {
		t.Fatal(err)
	}
	var observed []identity.ManagementAuthority
	var generations []uint64
	secondCheck := errors.New("second fresh bootstrap check refused before journaling")
	evaluate := func(_ context.Context, management identity.ManagementAuthority, generation uint64) (preflight.ExpansionRequest, preflight.Result, error) {
		observed = append(observed, management)
		generations = append(generations, generation)
		request := installerPreflightRequest(installed, management, generation)
		result := qualificationPreflightResult(t, request, now)
		if len(observed) == 2 {
			return request, result, secondCheck
		}
		return request, result, nil
	}
	runInstaller := func(data []byte, _ io.Writer, material *identity.Material) error {
		var bound installerInput
		if err := release.DecodeCanonical(data, &bound); err != nil {
			t.Fatal(err)
		}
		if material == nil || len(observed) != 1 || observed[0] != material.Authority || generations[0] != material.SafetyGeneration || bound.PackagePlan.IntentGeneration != material.SafetyGeneration {
			t.Fatal("production handoff lost generated Management authority and generation")
		}
		authority, err := release.RehydrateInstallAuthority(installed)
		if err != nil {
			t.Fatal(err)
		}
		request := Request{
			ReleaseAuthority: authority, Material: material, Paths: testPaths(root), Preflight: evaluate, PackagePlan: bound.PackagePlan, PackagePreflight: bound.PackagePreflight,
			SourceBinary: []byte("candidate"), LegoBytes: []byte("lego"), TailscaleBytes: []byte("tailscale"), ACMEAccountContact: bound.ACMEAccountContact,
			Now: func() time.Time { return now }, PackageTransaction: func(context.Context, packages.Plan, preflight.Result) (packages.Journal, error) {
				t.Fatal("package mutation preceded the second fresh preflight")
				return packages.Journal{}, nil
			},
		}
		return install(t.Context(), request, false)
	}
	input := qualificationInstallerInput{qualificationInstallerInputSchema, QualificationInstallerAuthority{ACMEAccountContact: installed.ACMEAccountContact, PackageTemplate: templateBytes}}
	result, err := runPreparedQualificationInstaller(input, release.DigestBytes(templateBytes), installed, io.Discard, evaluate, qualificationMaterialReader(), func() time.Time { return now }, runInstaller)
	if !errors.Is(err, secondCheck) || !result.Allowed {
		t.Fatalf("production handoff did not reach independent second preflight: %v", err)
	}
	if len(observed) != 2 || observed[0] != observed[1] || generations[0] != generations[1] {
		t.Fatalf("preparation/installation changed material: %v %v", observed, generations)
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bootstrap files were created before both preflights passed: %v", err)
	}
}

func testQualificationBoundResume(t *testing.T) {
	root := t.TempDir()
	installed, template, now := qualificationPackageFixture(t, root)
	data, err := release.MarshalCanonical(template)
	if err != nil {
		t.Fatal(err)
	}
	evaluate := func(_ context.Context, management identity.ManagementAuthority, generation uint64) (preflight.ExpansionRequest, preflight.Result, error) {
		request := installerPreflightRequest(installed, management, generation)
		return request, qualificationPreflightResult(t, request, now), nil
	}
	plan, result, material, err := prepareQualificationPackagePlan(t.Context(), data, release.DigestBytes(data), installed, evaluate, qualificationMaterialReader(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer material.Destroy()
	journal := testJournal(root)
	journal.Release, journal.Authority, journal.SafetyGeneration = installed, material.Authority, material.SafetyGeneration
	journal.AttemptID, journal.InstallationID, journal.GenerationID = material.AttemptID, material.InstallationID, material.GenerationID
	journal.PreflightRequest = installerPreflightRequest(installed, material.Authority, material.SafetyGeneration)
	journal.PreflightDigest = result.RequestDigest
	journal.PackageTransactionID, journal.PackagePlan, journal.PackagePreflight = plan.TransactionID, plan, result
	journal.PackagePlanDigest, err = packages.PlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	journal.PackageInputPlanDigest = journal.PackagePlanDigest
	journal.Accounts, err = identity.InstallationAccounts(material.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	journal.ArtifactDigests["release_binary"] = installed.Binary.Digest
	store, err := createJournal(journal.Paths.Journal, 0, 0, journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(journal.Paths.Journal)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := release.RehydrateInstallAuthority(installed)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	resumeCheck := errors.New("resume observed persisted Management authority")
	request := Request{
		ReleaseAuthority: authority, Material: &material, Random: errorReader{}, Paths: journal.Paths, PackagePlan: plan, PackagePreflight: result,
		SourceBinary: []byte("candidate"), LegoBytes: []byte("lego"), TailscaleBytes: []byte("tailscale"), ACMEAccountContact: installed.ACMEAccountContact,
		Now: func() time.Time { return now },
		Preflight: func(_ context.Context, management identity.ManagementAuthority, generation uint64) (preflight.ExpansionRequest, preflight.Result, error) {
			calls++
			if management != journal.Authority || generation != journal.SafetyGeneration {
				t.Fatal("resume regenerated Management material")
			}
			return journal.PreflightRequest, result, resumeCheck
		},
		PackageTransaction: func(context.Context, packages.Plan, preflight.Result) (packages.Journal, error) {
			t.Fatal("package mutation preceded resume preflight")
			return packages.Journal{}, nil
		},
	}
	if err := install(t.Context(), request, false); err == nil || !strings.Contains(err.Error(), "fresh installation material") || calls != 0 {
		t.Fatalf("fresh material resumed an existing attempt: %v, calls %d", err, calls)
	}
	request.Material = nil
	if err := install(t.Context(), request, false); !errors.Is(err, resumeCheck) || calls != 1 {
		t.Fatalf("bound nil-material resume did not use its journal: %v, calls %d", err, calls)
	}
	after, err := os.ReadFile(journal.Paths.Journal)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("refused fresh/resume checks changed the journal")
	}
}

func TestQualificationPackagePreparationBindsGeneratedManagement(t *testing.T) {
	root := filepath.Join(t.TempDir(), "fresh")
	installed, template, now := qualificationPackageFixture(t, root)
	data, err := release.MarshalCanonical(template)
	if err != nil {
		t.Fatal(err)
	}
	var observed identity.ManagementAuthority
	var generation uint64
	evaluate := func(_ context.Context, management identity.ManagementAuthority, value uint64) (preflight.ExpansionRequest, preflight.Result, error) {
		observed, generation = management, value
		request := installerPreflightRequest(installed, management, value)
		return request, qualificationPreflightResult(t, request, now), nil
	}
	plan, result, material, err := prepareQualificationPackagePlan(t.Context(), data, release.DigestBytes(data), installed, evaluate, qualificationMaterialReader(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer material.Destroy()
	if identity.ValidateManagementAuthority(observed) != nil || observed != material.Authority || generation != material.SafetyGeneration || plan.IntentGeneration != generation || generation == 1 {
		t.Fatal("preparation did not bind its generated Management authority and generation")
	}
	if _, err := validateInstallerPackageAuthority(installed, plan, result); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("package preparation created bootstrap files: %v", err)
	}
}

func TestQualificationPreparationRejectsTemplateDriftBeforePreflight(t *testing.T) {
	for _, change := range []string{"digest", "noncanonical", "closure", "repository", "profile", "not_first_install", "entropy"} {
		t.Run(change, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "fresh")
			installed, template, now := qualificationPackageFixture(t, root)
			switch change {
			case "closure":
				template.Packages[0].ArtifactDigest = strings.Repeat("e", 64)
				template.Packages[0].Source.Artifact.Digest = template.Packages[0].ArtifactDigest
			case "repository":
				template.Repositories[0].MetadataDigest = strings.Repeat("e", 64)
			case "profile":
				installed.Profile.SystemdVersion = "999.0"
			case "not_first_install":
				template.FirstNginxInstall = false
			}
			data, err := release.MarshalCanonical(template)
			if err != nil {
				t.Fatal(err)
			}
			digest := release.DigestBytes(data)
			if change == "digest" {
				digest = strings.Repeat("f", 64)
			}
			if change == "noncanonical" {
				data = append(data, '\n')
				digest = release.DigestBytes(data)
			}
			evaluate := func(context.Context, identity.ManagementAuthority, uint64) (preflight.ExpansionRequest, preflight.Result, error) {
				t.Fatal("invalid input reached preflight")
				return preflight.ExpansionRequest{}, preflight.Result{}, nil
			}
			var reader io.Reader = qualificationMaterialReader()
			if change == "entropy" {
				reader = errorReader{}
			}
			plan, _, material, err := prepareQualificationPackagePlan(t.Context(), data, digest, installed, evaluate, reader, func() time.Time { return now })
			defer material.Destroy()
			if err == nil || plan.TransactionID != "" || material.AttemptID != "" {
				t.Fatal("invalid preparation produced a bound installation")
			}
			if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid preparation wrote bootstrap state: %v", err)
			}
		})
	}
}

func TestQualificationPreparationRejectsUnrelatedPreflight(t *testing.T) {
	for _, change := range []string{"missing_listener", "address", "generation", "profile", "denied", "failed", "stale"} {
		t.Run(change, func(t *testing.T) {
			installed, template, now := qualificationPackageFixture(t, t.TempDir())
			data, err := release.MarshalCanonical(template)
			if err != nil {
				t.Fatal(err)
			}
			evaluate := func(_ context.Context, management identity.ManagementAuthority, generation uint64) (preflight.ExpansionRequest, preflight.Result, error) {
				request := installerPreflightRequest(installed, management, generation)
				result := qualificationPreflightResult(t, request, now)
				switch change {
				case "missing_listener":
					request.BootstrapListeners = nil
				case "address":
					request.BootstrapListeners[0].Port++
					result = qualificationPreflightResult(t, request, now)
				case "generation":
					request.Generation++
					result = qualificationPreflightResult(t, request, now)
				case "profile":
					request.Profile.Authority.Digest = "sha256:" + strings.Repeat("f", 64)
					result = qualificationPreflightResult(t, request, now)
				case "denied":
					result.Allowed = false
					result.Findings[0].Disposition = preflight.FindingBlocked
				case "failed":
					return request, result, errors.New("observer failed")
				case "stale":
					result.ObservedAt = now.Add(-2 * preflight.MaximumAge)
					result.ValidUntil = result.ObservedAt.Add(preflight.MaximumAge)
				}
				return request, result, nil
			}
			plan, _, material, err := prepareQualificationPackagePlan(t.Context(), data, release.DigestBytes(data), installed, evaluate, qualificationMaterialReader(), func() time.Time { return now })
			defer material.Destroy()
			if err == nil || plan.TransactionID != "" || material.AttemptID != "" {
				t.Fatal("unrelated or failed preflight produced a bound installation")
			}
		})
	}
}

func qualificationMaterialReader() *bytes.Reader {
	return bytes.NewReader(bytes.Repeat([]byte{1}, 128))
}

func qualificationPreflightResult(t *testing.T, request preflight.ExpansionRequest, now time.Time) preflight.Result {
	t.Helper()
	digest, err := preflight.ExpansionRequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	return preflight.Result{SchemaVersion: preflight.SchemaVersion, Scope: string(request.Scope), Target: request.Target, Generation: request.Generation, RequestDigest: digest, Allowed: true, ObservedAt: now, ValidUntil: now.Add(preflight.MaximumAge), Findings: []preflight.Finding{{Code: "fixture", Disposition: preflight.FindingPassed, Summary: "fixture bootstrap observation", Identity: "fixture"}}}
}

func qualificationPackageFixture(t *testing.T, root string) (release.InstallIdentity, packages.Plan, time.Time) {
	t.Helper()
	installed := testJournal(root).Release
	installed.Kind = release.InstallQualification
	installed.ReleaseManifestDigest = ""
	installed.QualificationInstallManifestDigest = strings.Repeat("a", 64)
	installed.SideEffectPlanDigest = strings.Repeat("b", 64)
	installed.ProtectedAuthorityDigest = strings.Repeat("c", 64)
	installed.ACMEAccountContact = "admin@example.test"
	installed.RunID = "run-fixture"
	installed.Binary = release.AssetIdentity{Path: "lanpanel", Digest: release.DigestBytes([]byte("candidate")), Bytes: uint64(len("candidate"))}
	installed.CandidateDigest = installed.Binary.Digest
	installed.Lego = release.AssetIdentity{Path: "lego", Digest: release.DigestBytes([]byte("lego")), Bytes: uint64(len("lego"))}
	installed.Tailscale = release.AssetIdentity{Path: "tailscale", Digest: release.DigestBytes([]byte("tailscale")), Bytes: uint64(len("tailscale"))}
	profile := &installed.Profile
	pkg := packages.Package{Name: "nginx", Version: profile.NginxVersion, Architecture: "amd64", ArtifactDigest: strings.Repeat("d", 64), ArtifactBytes: 1, MaximumInstalledFileBytes: 1 << 20, AffectedUnits: []string{"nginx.service"}, PossibleListeners: []string{"tcp/443", "tcp/80"}, Source: sources.Source{Kind: sources.OfficialDistro, Artifact: sources.Artifact{Name: "nginx", Version: profile.NginxVersion, OperatingOS: "linux", Architecture: "amd64", Digest: strings.Repeat("d", 64)}}}
	repository := packages.Repository{ID: "debian", URI: profile.RepositorySource, Suite: "trixie", Components: []string{"main"}, KeyringPath: "/etc/apt/keyrings/lanpanel.gpg", KeyringDigest: profile.RepositoryKeyFingerprint, MetadataDigest: profile.RepositoryMetadataDigest, CutoffDigest: profile.RepositoryCutoffDigest}
	var packageValues []packages.Package
	profile.Packages = nil
	for _, tuple := range []release.PackageTuple{{Name: "apache2-utils", Version: "2.4.62-1", Architecture: "amd64"}, {Name: "goaccess", Version: "1.9.3-1", Architecture: "amd64"}, {Name: "nginx", Version: profile.NginxVersion, Architecture: "amd64"}} {
		value := pkg
		value.Name, value.Version = tuple.Name, tuple.Version
		value.Source.Artifact.Name, value.Source.Artifact.Version = tuple.Name, tuple.Version
		if tuple.Name != "nginx" {
			value.AffectedUnits, value.PossibleListeners = []string{}, []string{}
		}
		packageValues = append(packageValues, value)
		profile.Packages = append(profile.Packages, tuple)
	}
	var err error
	profile.PackageClosureDigest, err = packages.ClosureDigest(packageValues)
	if err != nil {
		t.Fatal(err)
	}
	profile.RepositoryAuthorityDigest, err = release.RepositoryAuthorityDigest(repository)
	if err != nil {
		t.Fatal(err)
	}
	installed.ProfileDigest, err = release.ProfileDigest(*profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := release.ValidateInstallIdentity(installed); err != nil {
		t.Fatal(err)
	}
	template := packages.Plan{Mode: packages.DistroRepository, Packages: packageValues, Repositories: []packages.Repository{repository}, FirstNginxInstall: true, LockWait: 30 * time.Second, ConnectTimeout: 15 * time.Second, ReadTimeout: 30 * time.Second, TotalTimeout: time.Minute}
	if err := release.ValidateQualificationPackageTemplate(template, installed.Profile); err != nil {
		t.Fatal(err)
	}
	return installed, template, installed.AuthorityCreatedAt
}
