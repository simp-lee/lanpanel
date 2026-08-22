//go:build linux

package qualification

import (
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/bootstrap"
	"lanpanel/internal/helperproto"
	"lanpanel/internal/packages"
	"lanpanel/internal/release"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"time"
)

type LiveExecutor struct {
	prepared         Prepared
	plan             release.LiveSideEffectPlan
	journey          JourneySpec
	target           *SSHClient
	management       *ManagementClient
	cloudflare       *cloudflareClient
	vantage          VantageAuthority
	state            liveState
	states           liveStateStore
	basicPassword    []byte
	externalPassword []byte
	preauthKey       []byte
}

func RunLive(ctx context.Context, inputPath string) (Prepared, release.LiveCleanupReport, error) {
	prepared, err := Prepare(inputPath)
	if err != nil {
		return Prepared{}, release.LiveCleanupReport{}, err
	}
	plan, err := release.DecodeLiveSideEffectPlan(prepared.PlanBytes)
	if err != nil {
		return prepared, release.LiveCleanupReport{}, err
	}
	journeyBytes, _, err := readProtectedFile(prepared.Input.Artifacts.JourneySpecification, 4<<20, true)
	if err != nil {
		return prepared, release.LiveCleanupReport{}, err
	}
	journey, err := DecodeJourneySpec(journeyBytes)
	if err != nil {
		return prepared, release.LiveCleanupReport{}, err
	}
	lock, err := acquireRunLock(prepared.Input.Artifacts.CleanupReport + ".lock")
	if err != nil {
		return prepared, release.LiveCleanupReport{}, err
	}
	defer func() { _ = lock.Close() }()
	reports := ProtectedReportStore{Path: prepared.Input.Artifacts.CleanupReport}
	persisted, reportPresent, err := reports.Read()
	if err != nil {
		return prepared, release.LiveCleanupReport{}, err
	}
	if reportPresent {
		if persisted.RunID != prepared.Input.RunID || persisted.SideEffectPlanDigest != prepared.PlanDigest || persisted.QualificationInstallManifestDigest != prepared.InstallManifestDigest || persisted.ProtectedInputDigest != prepared.InputDigest || persisted.JourneySucceeded {
			return prepared, release.LiveCleanupReport{}, fmt.Errorf("persisted live journey authority differs or is already terminal")
		}
	} else if err := VerifyRemotePreflight(ctx, prepared); err != nil {
		return prepared, release.LiveCleanupReport{}, err
	}
	target, err := OpenSSH(ctx, prepared.Input.SSH)
	if err != nil {
		return prepared, release.LiveCleanupReport{}, err
	}
	if reportPresent {
		fingerprint, _, observeErr := target.ObserveQualificationHost(ctx, prepared.Install.Identity().Profile)
		if observeErr != nil || fingerprint != prepared.Input.SSH.MachineFingerprint {
			_ = target.Close()
			return prepared, release.LiveCleanupReport{}, errors.Join(observeErr, fmt.Errorf("resume target identity differs"))
		}
	}
	vantage, vantageDigest, err := LoadVantageAuthority(prepared.Input.ExternalVantageRef)
	if err != nil {
		_ = target.Close()
		return prepared, release.LiveCleanupReport{}, err
	}
	if vantageDigest != prepared.ExternalVantageDigest || vantage.ExpectedSourceIPv4 == journey.PublicIPv4 {
		_ = target.Close()
		return prepared, release.LiveCleanupReport{}, fmt.Errorf("external vantage authority differs or is not independent")
	}
	provider, err := openCloudflare(prepared.Input.DNS)
	if err != nil {
		_ = target.Close()
		return prepared, release.LiveCleanupReport{}, err
	}
	states := liveStateStore{path: prepared.Input.Artifacts.CleanupReport + ".state"}
	state, _, err := states.Read(prepared.Input.RunID, prepared.InputDigest)
	if err != nil {
		provider.Close()
		_ = target.Close()
		return prepared, release.LiveCleanupReport{}, err
	}
	executor := &LiveExecutor{prepared: prepared, plan: plan, journey: journey, target: target, cloudflare: provider, vantage: vantage, state: state, states: states}
	defer func() { _ = executor.Close() }()
	runner := Runner{
		RunID: prepared.Input.RunID, Plan: plan, PlanDigest: prepared.PlanDigest, InstallManifestDigest: prepared.InstallManifestDigest, ProtectedInputDigest: prepared.InputDigest,
		Executor: executor, Reports: reports, Attestor: executor,
		Attestations: ProtectedAttestationStore{Path: prepared.Input.Artifacts.ExecutorAttestation}, Now: func() time.Time { return time.Now().UTC() }, ExecutionTimeout: 20 * time.Minute, CleanupTimeout: 5 * time.Minute,
	}
	report, runErr := runner.Run(ctx)
	return prepared, report, runErr
}

func (executor *LiveExecutor) Close() error {
	if executor == nil {
		return nil
	}
	clearBytes(executor.basicPassword)
	clearBytes(executor.externalPassword)
	clearBytes(executor.preauthKey)
	if executor.management != nil {
		executor.management.Close()
	}
	if executor.cloudflare != nil {
		executor.cloudflare.Close()
	}
	if executor.target == nil {
		return nil
	}
	return executor.target.Close()
}

func (executor *LiveExecutor) Observe(ctx context.Context, step string) (PriorObservation, error) {
	planned, present := executor.planned(step)
	if !present {
		return PriorObservation{}, fmt.Errorf("live executor step is not in immutable plan")
	}
	if step == "clean_install" {
		fingerprint, inventory, err := executor.target.ObserveQualificationHost(ctx, executor.prepared.Install.Identity().Profile)
		if err != nil {
			return PriorObservation{}, err
		}
		expectedPrior := "bootstrap-inventory/" + inventory
		if fingerprint != executor.prepared.Input.SSH.MachineFingerprint || planned.PriorState != expectedPrior {
			return PriorObservation{}, fmt.Errorf("clean installation prior state differs from immutable authority")
		}
		stagingRoot := remoteStagingRoot(executor.prepared.Input.RunID)
		if _, err := executor.target.sftp.Lstat(stagingRoot); err == nil || !os.IsNotExist(err) {
			return PriorObservation{}, fmt.Errorf("qualification staging prior state is not absent")
		}
	} else {
		if err := executor.ensureManagement(ctx); err != nil {
			return PriorObservation{}, err
		}
		switch step {
		case "ui_startup_session_restart":
			if _, err := executor.target.readRemoteRegular("/var/lib/lanpanel/bootstrap-commit.json", 4<<20); err != nil {
				return PriorObservation{}, err
			}
		case "local_http_websocket":
			if executor.state.ResourceID != "" {
				return PriorObservation{}, fmt.Errorf("local qualification resource prior state is not empty")
			}
		case "temporary_public_http":
			if executor.state.TemporaryResourceID != "" || executor.state.ResourceID == "" {
				return PriorObservation{}, fmt.Errorf("temporary HTTP prior state is not exact")
			}
		case "domain_https_controls":
			for _, base := range []string{"/srv/lanpanel-qualification", "/etc/lanpanel-qualification"} {
				if _, err := executor.target.sftp.Lstat(base); err == nil || !os.IsNotExist(err) {
					return PriorObservation{}, fmt.Errorf("qualification fixture base prior state is not absent")
				}
			}
			for _, name := range []string{executor.journey.AppDomain, executor.journey.AppAlias} {
				for _, kind := range []string{"A", "AAAA", "CNAME"} {
					if records, err := executor.cloudflare.List(ctx, name, kind); err != nil || len(records) != 0 {
						return PriorObservation{}, fmt.Errorf("domain publication DNS prior state is not empty: %w", err)
					}
				}
			}
			if _, err := executor.management.Post(ctx, "/api/actions/status?resource_id="+url.QueryEscape(executor.state.ResourceID), struct{}{}, &helperproto.ResourceResult{}); err != nil {
				return PriorObservation{}, err
			}
		case "app_http01":
			if executor.state.ResourceID == "" {
				return PriorObservation{}, fmt.Errorf("app HTTP-01 prior resource is absent")
			}
		case "headscale_initialize_http01":
			if records, err := executor.cloudflare.List(ctx, executor.journey.HeadscaleDomain, "A"); err != nil || len(records) != 0 {
				return PriorObservation{}, fmt.Errorf("headscale DNS prior state is not empty: %w", err)
			}
			if executor.state.HeadscaleUserID != "" {
				return PriorObservation{}, fmt.Errorf("headscale entity prior state is not empty")
			}
		case "headscale_entities":
			if executor.state.HeadscaleUserID != "" || executor.state.PreauthKeyID != "" {
				return PriorObservation{}, fmt.Errorf("headscale entity prior state is not empty")
			}
		case "connector_assisted_login":
			if executor.state.PreauthKeyID == "" || executor.state.ConnectorBound || executor.state.ConnectorDeviceID != "" {
				return PriorObservation{}, fmt.Errorf("connector prior state is not exact")
			}
		case "dns01":
			if err := executor.cloudflare.RequireNoTXT(ctx, "_acme-challenge."+executor.journey.DNS01Domain); err != nil {
				return PriorObservation{}, err
			}
		case "tailnet_http_websocket":
			if executor.state.TailnetResourceID != "" {
				return PriorObservation{}, fmt.Errorf("tailnet resource prior state is not empty")
			}
			if executor.journey.TailnetLiveEnabled {
				if records, err := executor.cloudflare.List(ctx, executor.journey.TailnetDomain, "A"); err != nil || len(records) != 0 {
					return PriorObservation{}, fmt.Errorf("tailnet DNS prior state is not empty: %w", err)
				}
			}
		case "delete_diagnostics_export_close_reboot":
			if executor.state.ResourceID == "" || executor.state.FinalCleanupComplete {
				return PriorObservation{}, fmt.Errorf("management cleanup prior state is not exact")
			}
		case "final_cleanup_inventory":
			if !executor.state.ResourceDeleted || executor.state.TemporaryResourceID != "" || executor.state.TailnetResourceID != "" {
				return PriorObservation{}, fmt.Errorf("final cleanup prior state is incomplete")
			}
		}
	}
	return PriorObservation{Scope: []byte(planned.Scope), PriorState: []byte(planned.PriorState), PlannedMutation: []byte(planned.PlannedMutation), Selector: []byte(planned.Selector)}, nil
}

func (executor *LiveExecutor) Execute(ctx context.Context, step string) (MutationObservation, error) {
	if step == "clean_install" {
		return executor.executeCleanInstall(ctx)
	}
	return executor.executeStep(ctx, step)
}

func (executor *LiveExecutor) Recover(_ context.Context, step string) (MutationObservation, error) {
	if step != "clean_install" {
		if executor.state.RunID == executor.prepared.Input.RunID && executor.recoverableStepState(step) {
			return MutationObservation{Identity: "step/" + step + "/" + executor.prepared.Input.RunID, Evidence: []byte("recovered exact live step state")}, nil
		}
		return MutationObservation{}, fmt.Errorf("live executor cannot recover an exact identity for submitted step %q", step)
	}
	if _, err := executor.target.sftp.Lstat("/var/lib/lanpanel/bootstrap-commit.json"); err == nil {
		return MutationObservation{Identity: "installation/" + executor.prepared.Input.RunID, Evidence: []byte("recovered committed qualification installation")}, nil
	}
	root := remoteStagingRoot(executor.prepared.Input.RunID)
	if _, err := executor.target.sftp.Lstat(root); err == nil {
		return MutationObservation{Identity: "staging/" + executor.prepared.Input.RunID, Evidence: []byte("recovered qualification staging")}, nil
	}
	return MutationObservation{}, fmt.Errorf("clean installation submitted state has no exact recoverable identity")
}

func (executor *LiveExecutor) Cleanup(ctx context.Context, step string, observation MutationObservation, policy string) (release.CleanupResult, error) {
	if step == "clean_install" {
		if policy != "retain_authorized" {
			return "", fmt.Errorf("clean installation cleanup policy changed")
		}
		files, err := executor.remoteStagingFiles()
		if err != nil {
			return "", err
		}
		root := remoteStagingRoot(executor.prepared.Input.RunID)
		if _, err := executor.target.sftp.Lstat(root); err == nil {
			if err := executor.target.RemoveStaging(root, files); err != nil {
				return "", err
			}
		} else if !os.IsNotExist(err) {
			return "", err
		}
		if _, err := executor.target.sftp.Lstat("/var/lib/lanpanel-qualification"); err == nil || !os.IsNotExist(err) {
			return "", fmt.Errorf("qualification staging base remains after cleanup")
		}
		if _, err := executor.target.readRemoteRegular("/var/lib/lanpanel/bootstrap-commit.json", 4<<20); err != nil {
			return "", fmt.Errorf("authorized qualification installation is not durably retained: %w", err)
		}
		return release.CleanupRetained, ctx.Err()
	}
	if !executor.state.FinalCleanupComplete {
		if err := executor.cleanupLiveEffects(ctx); err != nil {
			return "", err
		}
		executor.state.FinalCleanupComplete = true
		if err := executor.states.Write(executor.state); err != nil {
			return "", err
		}
	}
	if policy == "retain_authorized" {
		return release.CleanupRetained, nil
	}
	if policy == "delete_exact" {
		return release.CleanupCleaned, nil
	}
	return "", fmt.Errorf("trusted live executor cleanup policy for %q is invalid", step)
}

func (executor *LiveExecutor) Attest(_ context.Context, report release.LiveCleanupReport) ([]byte, error) {
	steps := make([]release.AttestedJourneyStep, 0, len(report.Steps))
	for _, step := range report.Steps {
		if step.Outcome != release.StepPassed || !release.ValidDigest(step.EvidenceDigest) {
			return nil, fmt.Errorf("trusted executor cannot attest a non-passed step")
		}
		steps = append(steps, release.AttestedJourneyStep{MutationID: step.MutationID, EvidenceDigest: step.EvidenceDigest})
	}
	identity := executor.prepared.Install.Identity()
	tailnetStatus := "not_live_tested"
	if executor.prepared.TailnetPeerDigest != "" {
		tailnetStatus = "live_tested"
	}
	return release.MarshalCanonical(release.LiveExecutorAttestation{
		SchemaVersion: release.LiveExecutorAttestationSchemaVersion, ExecutorIdentity: "lanpanel-trusted-live-executor-v1", RunID: executor.prepared.Input.RunID,
		CandidateDigest: identity.CandidateDigest, TargetProfileDigest: identity.ProfileDigest, SideEffectPlanDigest: executor.prepared.PlanDigest,
		QualificationInstallManifestDigest: executor.prepared.InstallManifestDigest, ProtectedInputDigest: executor.prepared.InputDigest, TargetHostFingerprint: executor.prepared.Input.SSH.MachineFingerprint,
		ExternalVantageDigest: executor.prepared.ExternalVantageDigest, DNSProvider: executor.prepared.Input.DNS.Provider, DNSLiveTested: true,
		TailnetLiveStatus: tailnetStatus, Steps: steps, Cleanup: append([]release.CleanupItem(nil), report.Items...), CompletedAt: report.UpdatedAt,
	})
}

func (executor *LiveExecutor) executeCleanInstall(ctx context.Context) (MutationObservation, error) {
	root, err := executor.target.PrepareStaging(executor.prepared.Input.RunID)
	if err != nil {
		return MutationObservation{}, err
	}
	candidatePath, err := executor.target.UploadStagingFile(root, "lanpanel", executor.prepared.CandidateBytes, 0o500)
	if err != nil {
		return MutationObservation{Identity: "staging/" + executor.prepared.Input.RunID}, err
	}
	targetBytes, manifestBytes, dependencyBytes, packageTemplate, assetBytes, err := executor.readInstallArtifacts()
	if err != nil {
		return MutationObservation{Identity: "staging/" + executor.prepared.Input.RunID}, err
	}
	remoteAssets := map[string]string{"lanpanel": candidatePath}
	for name, data := range assetBytes {
		path, uploadErr := executor.target.UploadStagingFile(root, "assets/"+name, data, 0o400)
		if uploadErr != nil {
			return MutationObservation{Identity: "staging/" + executor.prepared.Input.RunID}, uploadErr
		}
		remoteAssets[name] = path
	}
	preflightResponse, err := executor.target.RunAgent(ctx, candidatePath, AgentRequest{SchemaVersion: AgentRequestSchemaVersion, RunID: executor.prepared.Input.RunID, Action: AgentPackagePreflight, CandidateDigest: release.DigestBytes(executor.prepared.CandidateBytes), TargetProfile: targetBytes, InstallManifest: manifestBytes, SideEffectPlan: executor.prepared.PlanBytes})
	if err != nil || !preflightResponse.Succeeded {
		return MutationObservation{Identity: "staging/" + executor.prepared.Input.RunID, Evidence: []byte(preflightResponse.Evidence)}, errors.Join(err, fmt.Errorf("remote package preflight did not pass: %s", preflightResponse.ErrorCode))
	}
	manifest, _ := release.DecodeQualificationInstallManifest(manifestBytes)
	packagePlan, err := BindQualificationPackagePlan(packageTemplate, manifest, executor.plan, executor.prepared.Install.Identity().Profile, preflightResponse.Preflight, time.Now().UTC())
	if err != nil {
		return MutationObservation{Identity: "staging/" + executor.prepared.Input.RunID, Evidence: []byte(preflightResponse.Evidence)}, err
	}
	installerBytes, err := bootstrap.BuildQualificationInstallerAuthority(bootstrap.QualificationInstallerAuthority{ACMEAccountContact: executor.prepared.Input.ACME.Contact, InstallManifest: manifestBytes, TargetProfile: targetBytes, SideEffectPlan: executor.prepared.PlanBytes, DependencyAuthority: dependencyBytes, ExpectedInstallManifestDigest: executor.prepared.InstallManifestDigest, RemoteAssetPaths: remoteAssets, PackagePlan: packagePlan, PackagePreflight: preflightResponse.Preflight})
	if err != nil {
		return MutationObservation{Identity: "staging/" + executor.prepared.Input.RunID, Evidence: []byte(preflightResponse.Evidence)}, err
	}
	response, err := executor.target.RunAgent(ctx, candidatePath, AgentRequest{SchemaVersion: AgentRequestSchemaVersion, RunID: executor.prepared.Input.RunID, Action: AgentInstall, CandidateDigest: release.DigestBytes(executor.prepared.CandidateBytes), InstallerAuthority: installerBytes})
	evidence, _ := release.MarshalCanonical(struct {
		SchemaVersion    string `json:"schema_version"`
		PackagePreflight string `json:"package_preflight"`
		Installer        string `json:"installer"`
	}{"lanpanel.qualification.clean-install-evidence.v1", preflightResponse.Evidence, response.Evidence})
	if err != nil || !response.Succeeded {
		return MutationObservation{Identity: "installation/" + executor.prepared.Input.RunID, Evidence: evidence}, errors.Join(err, fmt.Errorf("qualification clean installation failed: %s", response.ErrorCode))
	}
	return MutationObservation{Identity: "installation/" + executor.prepared.Input.RunID, Evidence: evidence}, nil
}

func (executor *LiveExecutor) readInstallArtifacts() ([]byte, []byte, []byte, packages.Plan, map[string][]byte, error) {
	target, _, err := readProtectedFile(executor.prepared.Input.Artifacts.TargetProfile, 4<<20, true)
	if err != nil {
		return nil, nil, nil, packages.Plan{}, nil, err
	}
	manifest, _, err := readProtectedFile(executor.prepared.Input.Artifacts.InstallManifest, 4<<20, true)
	if err != nil {
		return nil, nil, nil, packages.Plan{}, nil, err
	}
	dependency, _, err := readProtectedFile(executor.prepared.Input.Artifacts.DependencyAuthority, 4<<20, true)
	if err != nil {
		return nil, nil, nil, packages.Plan{}, nil, err
	}
	templateBytes, _, err := readProtectedFile(executor.prepared.Input.Artifacts.PackageTemplate, 4<<20, true)
	if err != nil {
		return nil, nil, nil, packages.Plan{}, nil, err
	}
	var template packages.Plan
	if err := release.DecodeCanonical(templateBytes, &template); err != nil {
		return nil, nil, nil, packages.Plan{}, nil, err
	}
	manifestValue, err := release.DecodeQualificationInstallManifest(manifest)
	if err != nil || manifestValue.PackageTemplateDigest != release.DigestBytes(templateBytes) {
		return nil, nil, nil, packages.Plan{}, nil, fmt.Errorf("qualification package template digest changed: %w", err)
	}
	assets := make(map[string][]byte, len(executor.prepared.Input.Artifacts.DependencyAssets))
	for name, path := range executor.prepared.Input.Artifacts.DependencyAssets {
		data, _, readErr := readProtectedFile(path, 512<<20, true)
		if readErr != nil {
			return nil, nil, nil, packages.Plan{}, nil, readErr
		}
		assets[name] = data
	}
	return target, manifest, dependency, template, assets, nil
}

func (executor *LiveExecutor) remoteStagingFiles() ([]string, error) {
	root := remoteStagingRoot(executor.prepared.Input.RunID)
	files := []string{root + "/lanpanel"}
	for name := range executor.prepared.Input.Artifacts.DependencyAssets {
		if !release.ValidRelativePath(name) {
			return nil, fmt.Errorf("qualification dependency asset name changed")
		}
		files = append(files, root+"/assets/"+filepath.ToSlash(name))
	}
	return files, nil
}

func (executor *LiveExecutor) recoverableStepState(step string) bool {
	if slices.Contains(executor.state.CompletedSteps, step) {
		return true
	}
	switch step {
	case "local_http_websocket":
		return executor.state.ResourceID != ""
	case "temporary_public_http":
		return executor.state.TemporaryResourceID != ""
	case "domain_https_controls":
		return executor.state.FixtureCreated || executor.state.BasicCredentialID != "" || len(executor.state.CloudflareRecords) != 0 || len(executor.state.DNSCreateIntents) != 0
	case "headscale_initialize_http01":
		return len(executor.state.CloudflareRecords) != 0
	case "headscale_entities":
		return executor.state.HeadscaleUserID != "" || executor.state.PreauthKeyID != ""
	case "connector_assisted_login":
		return executor.state.ConnectorBound || executor.state.ConnectorDeviceID != ""
	case "tailnet_http_websocket":
		return executor.state.TailnetResourceID != "" || !executor.journey.TailnetLiveEnabled
	case "dns01":
		return executor.state.DNSProfileCreated || len(executor.state.DNSCreateIntents) != 0
	case "delete_diagnostics_export_close_reboot":
		return executor.state.CloseAllCommitted || executor.state.ResourceDeleted
	case "final_cleanup_inventory":
		return executor.state.FinalCleanupComplete
	case "app_http01":
		return slices.Contains(executor.state.CompletedSteps, "domain_https_controls")
	}
	return false
}

func (executor *LiveExecutor) planned(step string) (release.PlannedMutation, bool) {
	for _, mutation := range executor.plan.Mutations {
		if mutation.ID == step {
			return mutation, true
		}
	}
	return release.PlannedMutation{}, false
}

func remoteStagingRoot(runID string) string { return "/var/lib/lanpanel-qualification/" + runID }
