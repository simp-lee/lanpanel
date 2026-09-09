//go:build linux

package qualification

import (
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/bootstrap"
	"lanpanel/internal/packages"
	"lanpanel/internal/release"
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
	if runErr == nil && report.JourneySucceeded {
		if err := sealProtectedFile(prepared.Input.Artifacts.CleanupReport); err != nil {
			return prepared, report, fmt.Errorf("seal terminal live cleanup report: %w", err)
		}
	}
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

func (executor *LiveExecutor) Execute(ctx context.Context, step string) (MutationObservation, error) {
	if step == "clean_install" {
		return executor.executeCleanInstall(ctx)
	}
	return executor.executeStep(ctx, step)
}

func (executor *LiveExecutor) Recover(ctx context.Context, step string) (MutationObservation, error) {
	if step != "clean_install" {
		if executor.state.RunID == executor.prepared.Input.RunID {
			if err := executor.ensureManagement(ctx); err != nil {
				return MutationObservation{}, err
			}
			if err := executor.reconcilePendingState(ctx); err != nil {
				return MutationObservation{}, err
			}
			if executor.recoverableStepState(step) {
				return MutationObservation{Identity: "step/" + step + "/" + executor.prepared.Input.RunID, Evidence: []byte("recovered exact live step state")}, nil
			}
		}
		return MutationObservation{}, fmt.Errorf("live executor cannot recover an exact identity for submitted step %q", step)
	}
	if err := executor.ensureTarget(ctx); err != nil {
		return MutationObservation{}, err
	}
	if _, err := executor.target.sftpLstat(ctx, "/var/lib/lanpanel/bootstrap-commit.json"); err == nil {
		return MutationObservation{Identity: "installation/" + executor.prepared.Input.RunID, Evidence: []byte("recovered committed qualification installation")}, nil
	}
	root := remoteStagingRoot(executor.prepared.Input.RunID)
	if _, err := executor.target.sftpLstat(ctx, root); err == nil {
		return MutationObservation{Identity: "staging/" + executor.prepared.Input.RunID, Evidence: []byte("recovered qualification staging")}, nil
	}
	return MutationObservation{}, fmt.Errorf("clean installation submitted state has no exact recoverable identity")
}

func (executor *LiveExecutor) Cleanup(ctx context.Context, step string, observation MutationObservation, policy string) (release.CleanupResult, error) {
	if step == "clean_install" {
		if policy != "retain_authorized" {
			return "", fmt.Errorf("clean installation cleanup policy changed")
		}
		if err := executor.ensureTarget(ctx); err != nil {
			return "", err
		}
		files, err := executor.remoteStagingFiles()
		if err != nil {
			return "", err
		}
		root := remoteStagingRoot(executor.prepared.Input.RunID)
		if _, err := executor.target.sftpLstat(ctx, root); err == nil {
			if err := executor.target.RemoveStaging(ctx, root, files); err != nil {
				return "", err
			}
		} else if !os.IsNotExist(err) {
			return "", err
		}
		if _, err := executor.target.sftpLstat(ctx, "/var/lib/lanpanel-qualification"); err == nil || !os.IsNotExist(err) {
			return "", fmt.Errorf("qualification staging base remains after cleanup")
		}
		if _, err := executor.target.readRemoteRegular(ctx, "/var/lib/lanpanel/bootstrap-commit.json", 4<<20); err != nil {
			return "", fmt.Errorf("authorized qualification installation is not durably retained: %w", err)
		}
		return release.CleanupRetained, ctx.Err()
	}
	if !executor.state.FinalCleanupComplete {
		if err := executor.cleanupLiveEffects(ctx); err != nil {
			return "", err
		}
		// An interrupted prefix may never have created App certificates or
		// Headscale. Cleanup proves the effects actually recorded, not effects
		// from unattempted steps. Successful final inventory and attestation
		// still require the complete retained/deleted certificate authority.
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

func (executor *LiveExecutor) Attest(ctx context.Context, report release.LiveCleanupReport) ([]byte, error) {
	terminalEvidence, err := executor.observeTerminalCleanup(ctx)
	if err != nil {
		return nil, err
	}
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
		TailnetLiveStatus: tailnetStatus, Steps: steps, Cleanup: append([]release.CleanupItem(nil), report.Items...), TerminalEvidence: terminalEvidence, CompletedAt: time.Now().UTC().Truncate(time.Second),
	})
}

func (executor *LiveExecutor) observeTerminalCleanup(ctx context.Context) ([]byte, error) {
	if err := executor.ensureTarget(ctx); err != nil {
		return nil, err
	}
	if _, err := executor.target.sftpLstat(ctx, "/var/lib/lanpanel-qualification"); err == nil || !os.IsNotExist(err) {
		return nil, fmt.Errorf("terminal qualification staging is not absent")
	}
	identity := executor.prepared.Install.Identity()
	installedPath := bootstrap.FixedPaths().BinaryPath
	installedBytes, err := executor.target.readRemoteRegular(ctx, installedPath, 256<<20)
	if err != nil || release.DigestBytes(installedBytes) != identity.CandidateDigest {
		return nil, errors.Join(err, fmt.Errorf("terminal installed binary differs from exact candidate"))
	}
	if executor.state.RetainedCertificate == nil || !executor.state.CertificateCleanupComplete || len(executor.state.CertificateCleanup) == 0 {
		return nil, fmt.Errorf("terminal certificate cleanup inventory is incomplete")
	}
	final, err := executor.target.RunAgent(ctx, installedPath, AgentRequest{SchemaVersion: AgentRequestSchemaVersion, RunID: executor.prepared.Input.RunID, Action: AgentFinalInventory, CandidateDigest: identity.CandidateDigest, Certificates: []qualificationCertificateArtifact{*executor.state.RetainedCertificate}})
	if err != nil || !final.Succeeded || !sameObservedPackageTuple(final.ObservedPackageTuple, identity.Profile.Packages) {
		return nil, errors.Join(err, fmt.Errorf("terminal host/package inventory failed: %s", final.ErrorCode))
	}
	nonRetained := []string{executor.journey.AppDomain, executor.journey.AppAlias, executor.journey.DNS01Domain}
	if executor.journey.TailnetLiveEnabled {
		nonRetained = append(nonRetained, executor.journey.TailnetDomain)
	}
	for _, name := range nonRetained {
		for _, kind := range []string{"A", "AAAA", "CNAME"} {
			if records, err := executor.cloudflare.List(ctx, name, kind); err != nil || len(records) != 0 {
				return nil, fmt.Errorf("terminal provider DNS residue remains for %s %s: %w", kind, name, err)
			}
		}
		if err := waitAuthoritativeAbsent(ctx, executor.journey.AuthoritativeZone, name); err != nil {
			return nil, err
		}
	}
	for _, domainName := range []string{executor.journey.AppDomain, executor.journey.DNS01Domain} {
		owner := "_acme-challenge." + domainName
		if err := executor.cloudflare.RequireNoTXT(ctx, owner); err != nil {
			return nil, err
		}
		if err := waitAuthoritativeNoTXT(ctx, executor.journey.AuthoritativeZone, owner); err != nil {
			return nil, err
		}
	}
	if err := exactAuthoritativeA(ctx, executor.journey.AuthoritativeZone, []string{executor.journey.HeadscaleDomain}, executor.journey.PublicIPv4); err != nil {
		return nil, err
	}
	records, err := executor.cloudflare.List(ctx, executor.journey.HeadscaleDomain, "A")
	if err != nil || len(records) != 1 || records[0].Content != executor.journey.PublicIPv4 || records[0].Proxied {
		return nil, fmt.Errorf("terminal retained Headscale DNS differs: %w", err)
	}
	certificateEvidence, err := certificateInventoryEvidence(executor.state)
	if err != nil {
		return nil, err
	}
	return evidenceWithObservations("terminal-cleanup", map[string]string{"acme_txt": "provider-and-authoritative-absent", "candidate_digest": identity.CandidateDigest, "host_fingerprint": executor.prepared.Input.SSH.MachineFingerprint, "installed_binary": installedPath, "nonretained_certificates": "absent", "nonretained_dns": "provider-and-authoritative-absent", "profile_digest": identity.ProfileDigest, "provider": executor.prepared.Input.DNS.Provider, "retained_certificate": "exact", "retained_certificate_id": executor.state.RetainedCertificate.CertificateID, "retained_headscale_domain": executor.journey.HeadscaleDomain, "staging": "absent"}, map[string][]byte{"certificate_inventory": certificateEvidence}, final.ObservedPackageTuple)
}

func (executor *LiveExecutor) executeCleanInstall(ctx context.Context) (MutationObservation, error) {
	root, err := executor.target.PrepareStaging(ctx, executor.prepared.Input.RunID)
	if err != nil {
		return MutationObservation{}, err
	}
	candidatePath, err := executor.target.UploadStagingFile(ctx, root, "lanpanel", executor.prepared.CandidateBytes, 0o500)
	if err != nil {
		return MutationObservation{Identity: "staging/" + executor.prepared.Input.RunID}, err
	}
	targetBytes, manifestBytes, dependencyBytes, packageTemplate, assetBytes, err := executor.readInstallArtifacts()
	if err != nil {
		return MutationObservation{Identity: "staging/" + executor.prepared.Input.RunID}, err
	}
	remoteAssets := map[string]string{"lanpanel": candidatePath}
	for name, data := range assetBytes {
		path, uploadErr := executor.target.UploadStagingFile(ctx, root, "assets/"+name, data, 0o400)
		if uploadErr != nil {
			return MutationObservation{Identity: "staging/" + executor.prepared.Input.RunID}, uploadErr
		}
		remoteAssets[name] = path
	}
	templateBytes, err := release.MarshalCanonical(packageTemplate)
	if err != nil {
		return MutationObservation{Identity: "staging/" + executor.prepared.Input.RunID}, err
	}
	installerBytes, err := bootstrap.BuildQualificationInstallerAuthority(bootstrap.QualificationInstallerAuthority{ACMEAccountContact: executor.prepared.Input.ACME.Contact, InstallManifest: manifestBytes, TargetProfile: targetBytes, SideEffectPlan: executor.prepared.PlanBytes, DependencyAuthority: dependencyBytes, ExpectedInstallManifestDigest: executor.prepared.InstallManifestDigest, RemoteAssetPaths: remoteAssets, PackageTemplate: templateBytes})
	if err != nil {
		return MutationObservation{Identity: "staging/" + executor.prepared.Input.RunID}, err
	}
	response, err := executor.target.RunAgent(ctx, candidatePath, AgentRequest{SchemaVersion: AgentRequestSchemaVersion, RunID: executor.prepared.Input.RunID, Action: AgentInstall, CandidateDigest: release.DigestBytes(executor.prepared.CandidateBytes), InstallerAuthority: installerBytes})
	values := map[string]string{"candidate_digest": release.DigestBytes(executor.prepared.CandidateBytes), "target_profile_digest": executor.prepared.Install.Identity().ProfileDigest}
	if response.Evidence != "" {
		values["installer"] = response.Evidence
	}
	if preflightDigest, digestErr := response.Preflight.Digest(); digestErr == nil {
		values["package_preflight"] = preflightDigest
	}
	if response.ErrorCode != "" {
		values["error_code"] = response.ErrorCode
	}
	installEvidence, evidenceErr := evidenceWithObservations("clean-install", values, nil, response.ObservedPackageTuple)
	if evidenceErr != nil {
		return MutationObservation{Identity: "installation/" + executor.prepared.Input.RunID}, errors.Join(err, evidenceErr)
	}
	if err != nil || !response.Succeeded {
		return MutationObservation{Identity: "installation/" + executor.prepared.Input.RunID, Evidence: installEvidence}, errors.Join(err, fmt.Errorf("qualification clean installation failed: %s", response.ErrorCode))
	}
	return MutationObservation{Identity: "installation/" + executor.prepared.Input.RunID, Evidence: installEvidence}, nil
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
		return executor.state.ResourceID != "" || executor.state.PendingResourceCreate != nil
	case "temporary_public_http":
		return executor.state.TemporaryResourceID != "" || executor.state.PendingResourceCreate != nil
	case "domain_https_controls":
		return executor.state.FixtureCreated || executor.state.BasicCredentialID != "" || executor.state.PendingRegistration != nil || len(executor.state.CloudflareRecords) != 0 || len(executor.state.DNSCreateIntents) != 0
	case "headscale_initialize_http01":
		return len(executor.state.CloudflareRecords) != 0
	case "headscale_entities":
		return executor.state.HeadscaleUserID != "" || executor.state.PreauthKeyID != "" || executor.state.PendingHeadscaleUserCreate != nil || executor.state.PendingPreauthKeyCreate != nil
	case "connector_assisted_login":
		return executor.state.ConnectorBound || executor.state.ConnectorDeviceID != "" || executor.state.PendingConnectorDevice != nil
	case "tailnet_http_websocket":
		return executor.state.TailnetResourceID != "" || executor.state.PendingResourceCreate != nil || !executor.journey.TailnetLiveEnabled
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
