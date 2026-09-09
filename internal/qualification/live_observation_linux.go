//go:build linux

package qualification

import (
	"context"
	"fmt"
	"lanpanel/internal/application"
	"lanpanel/internal/bootstrap"
	"lanpanel/internal/certificates"
	"lanpanel/internal/domain"
	managedheadscale "lanpanel/internal/headscale"
	"lanpanel/internal/release"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// Observe reconstructs scope/action/selector authority from protected inputs
// and prior-state text from fresh remote/provider observations. No comparison
// value is copied from the immutable plan.
func (executor *LiveExecutor) Observe(ctx context.Context, step string) (PriorObservation, error) {
	if _, present := executor.planned(step); !present {
		return PriorObservation{}, fmt.Errorf("live executor step is not in immutable plan")
	}

	cleanInventory := ""
	var prior string
	if step == "clean_install" {
		fingerprint, inventory, err := executor.target.ObserveQualificationHost(ctx, executor.prepared.Install.Identity().Profile)
		if err != nil {
			return PriorObservation{}, err
		}
		baseState, err := executor.remotePathState(ctx, "/var/lib/lanpanel-qualification")
		if err != nil {
			return PriorObservation{}, err
		}
		rootState, err := executor.remotePathState(ctx, remoteStagingRoot(executor.prepared.Input.RunID))
		if err != nil {
			return PriorObservation{}, err
		}
		cleanInventory = inventory
		prior = "step=clean_install;fresh_observation=host_fingerprint=" + fingerprint + ",bootstrap_inventory_digest=" + inventory + ",staging_base=/var/lib/lanpanel-qualification:" + baseState + ",staging_root=" + remoteStagingRoot(executor.prepared.Input.RunID) + ":" + rootState
	} else {
		if err := executor.ensureManagement(ctx); err != nil {
			return PriorObservation{}, err
		}
		observed, err := executor.observeManagedPrior(ctx, step)
		if err != nil {
			return PriorObservation{}, err
		}
		prior = observed
	}

	authority, err := executor.reconstructedSideEffectAuthority(step, cleanInventory)
	if err != nil {
		return PriorObservation{}, err
	}
	return PriorObservation{
		Scope:           []byte(authority.Scope),
		PriorState:      []byte(prior),
		PlannedMutation: []byte(authority.PlannedMutation),
		Selector:        []byte(authority.Selector),
	}, nil
}

func (executor *LiveExecutor) reconstructedSideEffectAuthority(step, cleanInventory string) (sideEffectAuthority, error) {
	journeyBytes, err := release.MarshalCanonical(executor.journey)
	if err != nil {
		return sideEffectAuthority{}, err
	}
	profileDigest, err := release.ProfileDigest(executor.prepared.Install.Identity().Profile)
	if err != nil {
		return sideEffectAuthority{}, err
	}
	var peer TailnetPeerAuthority
	if step == "tailnet_http_websocket" && executor.journey.TailnetLiveEnabled {
		var peerDigest string
		peer, peerDigest, err = loadTailnetPeer(executor.prepared.Input.TailnetPeerRef)
		if err != nil || peerDigest != executor.prepared.TailnetPeerDigest {
			return sideEffectAuthority{}, fmt.Errorf("tailnet peer authority changed: %w", err)
		}
	}
	input := GenerationInput{
		CleanInstallInventoryDigest: cleanInventory,
		SSH:                         executor.prepared.Input.SSH,
		ACME:                        executor.prepared.Input.ACME,
		DNS:                         executor.prepared.Input.DNS,
		Journey:                     executor.journey,
	}
	authority, present := sideEffectAuthorities(executor.prepared.Input.RunID, input, peer, executor.vantage, executor.prepared.Install.Identity().CandidateDigest, profileDigest, release.DigestBytes(journeyBytes), cleanInventory)[step]
	if !present {
		return sideEffectAuthority{}, fmt.Errorf("live executor step authority is unavailable")
	}
	return authority, nil
}

func (executor *LiveExecutor) observeManagedPrior(ctx context.Context, step string) (string, error) {
	localName := "qualification-local-" + executor.prepared.Input.RunID[4:16]
	temporaryName := "qualification-temporary-" + executor.prepared.Input.RunID[4:16]
	tailnetName := "qualification-tailnet-" + executor.prepared.Input.RunID[4:16]

	switch step {
	case "ui_startup_session_restart":
		commitBytes, err := executor.target.readRemoteRegular(ctx, bootstrap.FixedPaths().CommitPath, bootstrap.MaximumJournalBytes)
		if err != nil {
			return "", err
		}
		var commit bootstrap.Commit
		if release.DecodeCanonical(commitBytes, &commit) != nil || commit.SchemaVersion != bootstrap.CommitSchemaVersion || commit.BundleDigest == "" || commit.ArtifactDigest == "" {
			return "", fmt.Errorf("qualification bootstrap commit prior state is invalid")
		}
		token, err := executor.target.readRemoteRegular(ctx, "/var/lib/lanpanel/installation/admin-token", 4096)
		if err != nil || len(token) == 0 {
			clearBytes(token)
			return "", fmt.Errorf("qualification admin token prior state is unavailable: %w", err)
		}
		clearBytes(token)
		return priorState(step, "bootstrap_commit=present", "management_session=authenticated", "admin_token=present"), nil

	case "local_http_websocket":
		installation, err := executor.observeInstallation(ctx)
		if err != nil {
			return "", err
		}
		selector, err := resourceNameState(installation, localName)
		if err != nil {
			return "", err
		}
		return priorState(step,
			fmt.Sprintf("configuration.resources=%d", len(installation.Resources)),
			fmt.Sprintf("configuration.credentials=%d", len(installation.Credentials)),
			fmt.Sprintf("configuration.static_roots=%d", len(installation.StaticRoots)),
			"resource[name="+localName+"]="+selector), nil

	case "temporary_public_http":
		installation, err := executor.observeInstallation(ctx)
		if err != nil {
			return "", err
		}
		if _, err := exactResource(installation, executor.state.ResourceID, localName); err != nil {
			return "", err
		}
		selector, err := resourceNameState(installation, temporaryName)
		if err != nil {
			return "", err
		}
		listeners, err := executor.observeIPv4ListenerConflictCount(ctx, executor.journey.PublicIPv4, executor.journey.TemporaryHTTPPort)
		if err != nil {
			return "", err
		}
		return priorState(step,
			fmt.Sprintf("configuration.resources=%d", len(installation.Resources)),
			"local_resource[name="+localName+"]=present",
			"resource[name="+temporaryName+"]="+selector,
			fmt.Sprintf("listener[%s:%d].conflicts=%d", executor.journey.PublicIPv4, executor.journey.TemporaryHTTPPort, listeners)), nil

	case "domain_https_controls":
		installation, err := executor.observeInstallation(ctx)
		if err != nil {
			return "", err
		}
		if _, err := exactResource(installation, executor.state.ResourceID, localName); err != nil {
			return "", err
		}
		srvState, err := executor.remotePathState(ctx, "/srv/lanpanel-qualification")
		if err != nil {
			return "", err
		}
		etcState, err := executor.remotePathState(ctx, "/etc/lanpanel-qualification")
		if err != nil {
			return "", err
		}
		appRecords, err := executor.providerRecordCount(ctx, []string{executor.journey.AppDomain}, []string{"A", "AAAA", "CNAME"})
		if err != nil {
			return "", err
		}
		aliasRecords, err := executor.providerRecordCount(ctx, []string{executor.journey.AppAlias}, []string{"A", "AAAA", "CNAME"})
		if err != nil {
			return "", err
		}
		return priorState(step,
			fmt.Sprintf("configuration.resources=%d", len(installation.Resources)),
			fmt.Sprintf("configuration.credentials=%d", len(installation.Credentials)),
			fmt.Sprintf("configuration.static_roots=%d", len(installation.StaticRoots)),
			"local_resource[name="+localName+"]=present",
			"fixture_base=/srv/lanpanel-qualification:"+srvState,
			"fixture_config_base=/etc/lanpanel-qualification:"+etcState,
			fmt.Sprintf("dns[%s,A|AAAA|CNAME].records=%d", executor.journey.AppDomain, appRecords),
			fmt.Sprintf("dns[%s,A|AAAA|CNAME].records=%d", executor.journey.AppAlias, aliasRecords)), nil

	case "app_http01":
		installation, err := executor.observeInstallation(ctx)
		if err != nil {
			return "", err
		}
		resource, err := exactResource(installation, executor.state.ResourceID, localName)
		if err != nil {
			return "", err
		}
		if err := exactRegistration(installation, executor.state.ExternalCredentialID, "credential"); err != nil {
			return "", err
		}
		if err := exactRegistration(installation, executor.state.StaticRootID, "static_root"); err != nil {
			return "", err
		}
		certificateState := "absent"
		if resource.PublicationRecord.LastAppliedBundle != nil && resource.PublicationRecord.LastAppliedBundle.DomainHTTPS != nil && resource.PublicationRecord.LastAppliedBundle.DomainHTTPS.Certificate.Fingerprint != "" {
			certificateState = "present"
		}
		return priorState(step,
			fmt.Sprintf("configuration.resources=%d", len(installation.Resources)),
			fmt.Sprintf("configuration.credentials=%d", len(installation.Credentials)),
			fmt.Sprintf("configuration.static_roots=%d", len(installation.StaticRoots)),
			"resource[name="+localName+"]="+string(resource.PublicationRecord.State),
			"certificate["+executor.journey.AppDomain+"]="+certificateState,
			"app_ingress="+map[bool]string{true: "open", false: "closed"}[resource.PublicationRecord.State == domain.PublicationPublished]), nil

	case "headscale_initialize_http01":
		installation, err := executor.observeInstallation(ctx)
		if err != nil {
			return "", err
		}
		headscaleState := "absent"
		if installation.Headscale != nil {
			headscaleState = "present"
		}
		records, err := executor.providerRecordCount(ctx, []string{executor.journey.HeadscaleDomain}, []string{"A", "AAAA", "CNAME"})
		if err != nil {
			return "", err
		}
		entityState := "absent"
		if executor.state.HeadscaleUserID != "" {
			entityState = "present"
		}
		return priorState(step, "headscale="+headscaleState, "headscale_user_result="+entityState, fmt.Sprintf("dns[%s,A|AAAA|CNAME].records=%d", executor.journey.HeadscaleDomain, records)), nil

	case "headscale_entities":
		installation, err := executor.observeInstallation(ctx)
		if err != nil {
			return "", err
		}
		headscaleState := "absent"
		if installation.Headscale != nil && installation.Headscale.Enabled && installation.Headscale.Applied != nil {
			headscaleState = "initialized"
		}
		users, keys, devices, err := executor.observeHeadscaleEntities(ctx)
		if err != nil {
			return "", err
		}
		userState := "absent"
		for _, user := range users {
			if user.Name == "qualification" {
				userState = "present"
			}
		}
		return priorState(step,
			"headscale="+headscaleState,
			fmt.Sprintf("headscale.users=%d", len(users)),
			fmt.Sprintf("headscale.preauth_keys=%d", len(keys)),
			fmt.Sprintf("headscale.devices=%d", len(devices)),
			"user[name=qualification]="+userState), nil

	case "connector_assisted_login":
		installation, err := executor.observeInstallation(ctx)
		if err != nil {
			return "", err
		}
		users, keys, devices, err := executor.observeHeadscaleEntities(ctx)
		if err != nil {
			return "", err
		}
		userID, keyID, err := executor.requireExactHeadscaleResults(users, keys, true, time.Now().UTC())
		if err != nil {
			return "", err
		}
		connectorState := "absent"
		if installation.Connector != nil {
			connectorState = "present"
		}
		return priorState(step,
			fmt.Sprintf("headscale.users=%d", len(users)),
			fmt.Sprintf("headscale.preauth_keys=%d", len(keys)),
			fmt.Sprintf("headscale.devices=%d", len(devices)),
			"connector="+connectorState,
			"user=result:headscale_entities.user_id:"+map[bool]string{true: "present", false: "absent"}[userID != 0],
			"preauth_key=result:headscale_entities.preauth_key_id:"+map[bool]string{true: "active", false: "absent"}[keyID != 0]), nil

	case "tailnet_http_websocket":
		if !executor.journey.TailnetLiveEnabled {
			installation, err := executor.observeInstallation(ctx)
			if err != nil {
				return "", err
			}
			selector, err := resourceNameState(installation, tailnetName)
			if err != nil {
				return "", err
			}
			return priorState(step, "live_test=disabled", fmt.Sprintf("configuration.resources=%d", len(installation.Resources)), "tailnet_resource="+selector), nil
		}
		installation, err := executor.observeInstallation(ctx)
		if err != nil {
			return "", err
		}
		if _, err := exactResource(installation, executor.state.ResourceID, localName); err != nil {
			return "", err
		}
		selector, err := resourceNameState(installation, tailnetName)
		if err != nil {
			return "", err
		}
		records, err := executor.providerRecordCount(ctx, []string{executor.journey.TailnetDomain}, []string{"A", "AAAA", "CNAME"})
		if err != nil {
			return "", err
		}
		return priorState(step,
			"live_test=enabled",
			fmt.Sprintf("configuration.resources=%d", len(installation.Resources)),
			"local_resource[name="+localName+"]=present",
			"resource[name="+tailnetName+"]="+selector,
			fmt.Sprintf("dns[%s,A|AAAA|CNAME].records=%d", executor.journey.TailnetDomain, records)), nil

	case "dns01":
		installation, err := executor.observeInstallation(ctx)
		if err != nil {
			return "", err
		}
		if _, err := exactResource(installation, executor.state.ResourceID, localName); err != nil {
			return "", err
		}
		paths, err := FixedQualificationFixturePaths(executor.prepared.Input.RunID)
		if err != nil {
			return "", err
		}
		profileState, err := executor.remotePathState(ctx, paths.DNSProfile)
		if err != nil {
			return "", err
		}
		records, err := executor.providerRecordCount(ctx, []string{executor.journey.DNS01Domain}, []string{"A", "AAAA", "CNAME"})
		if err != nil {
			return "", err
		}
		txt, err := executor.providerRecordCount(ctx, []string{"_acme-challenge." + executor.journey.DNS01Domain}, []string{"TXT"})
		if err != nil {
			return "", err
		}
		return priorState(step,
			fmt.Sprintf("configuration.resources=%d", len(installation.Resources)),
			"dns_profile="+profileState,
			fmt.Sprintf("dns[%s,A|AAAA|CNAME].records=%d", executor.journey.DNS01Domain, records),
			fmt.Sprintf("dns[_acme-challenge.%s,TXT].records=%d", executor.journey.DNS01Domain, txt),
			"resource[name="+localName+"]=present"), nil

	case "delete_diagnostics_export_close_reboot":
		installation, err := executor.observeInstallation(ctx)
		if err != nil {
			return "", err
		}
		resource, err := exactResource(installation, executor.state.ResourceID, localName)
		if err != nil {
			return "", err
		}
		if executor.journey.TailnetLiveEnabled {
			if _, err := exactResource(installation, executor.state.TailnetResourceID, tailnetName); err != nil {
				return "", err
			}
		}
		users, keys, devices, err := executor.observeHeadscaleEntities(ctx)
		if err != nil {
			return "", err
		}
		userID, _, err := executor.requireExactHeadscaleResults(users, keys, false, time.Time{})
		if err != nil {
			return "", err
		}
		deviceID, deviceErr := strconv.ParseUint(executor.state.ConnectorDeviceID, 10, 64)
		deviceMatches := 0
		for _, device := range devices {
			if device.ID == deviceID && device.UserID == userID {
				deviceMatches++
			}
		}
		if deviceErr != nil || deviceID == 0 || deviceMatches != 1 {
			return "", fmt.Errorf("connector device result reference does not resolve exactly")
		}
		recordNames := []string{executor.journey.AppDomain, executor.journey.AppAlias, executor.journey.HeadscaleDomain, executor.journey.DNS01Domain}
		if executor.journey.TailnetLiveEnabled {
			recordNames = append(recordNames, executor.journey.TailnetDomain)
		}
		records, err := executor.providerTrackedARecordCount(ctx, recordNames)
		if err != nil {
			return "", err
		}
		forbiddenRecords, err := executor.providerRecordCount(ctx, recordNames, []string{"AAAA", "CNAME"})
		if err != nil {
			return "", err
		}
		paths, err := FixedQualificationFixturePaths(executor.prepared.Input.RunID)
		if err != nil {
			return "", err
		}
		fixtureState, err := executor.remotePathsState(ctx, []string{paths.StaticFile, paths.HTPasswd})
		if err != nil {
			return "", err
		}
		profileState, err := executor.remotePathsState(ctx, []string{paths.DNSProfile, paths.DNSToken})
		if err != nil {
			return "", err
		}
		return priorState(step,
			fmt.Sprintf("configuration.resources=%d", len(installation.Resources)),
			"resource=result:local_http_websocket.resource_id:present",
			"app_ingress="+string(resource.PublicationRecord.State),
			fmt.Sprintf("headscale.users=%d", len(users)),
			fmt.Sprintf("headscale.preauth_keys=%d", len(keys)),
			fmt.Sprintf("headscale.devices=%d", len(devices)),
			"connector_device=result:connector_assisted_login.device_id:present",
			"preauth_key=result:headscale_entities.preauth_key_id:present",
			"fixture="+fixtureState,
			"dns_profile="+profileState,
			fmt.Sprintf("run_owned_A_records=%d", records),
			fmt.Sprintf("run_owned_AAAA_CNAME_records=%d", forbiddenRecords),
			fmt.Sprintf("pending_dns_create_intents=%d", len(executor.state.DNSCreateIntents)),
			fmt.Sprintf("final_cleanup_complete=%t", executor.state.FinalCleanupComplete)), nil

	case "final_cleanup_inventory":
		installation, err := executor.observeInstallation(ctx)
		if err != nil {
			return "", err
		}
		localState, err := resourceNameState(installation, localName)
		if err != nil {
			return "", err
		}
		temporaryState, err := resourceNameState(installation, temporaryName)
		if err != nil {
			return "", err
		}
		tailnetState, err := resourceNameState(installation, tailnetName)
		if err != nil {
			return "", err
		}
		nonRetained := []string{executor.journey.AppDomain, executor.journey.AppAlias, executor.journey.DNS01Domain}
		if executor.journey.TailnetLiveEnabled {
			nonRetained = append(nonRetained, executor.journey.TailnetDomain)
		}
		nonRetainedRecords, err := executor.providerRecordCount(ctx, nonRetained, []string{"A", "AAAA", "CNAME"})
		if err != nil {
			return "", err
		}
		retainedRecords, err := executor.providerTrackedARecordCount(ctx, []string{executor.journey.HeadscaleDomain})
		if err != nil {
			return "", err
		}
		retainedForbiddenRecords, err := executor.providerRecordCount(ctx, []string{executor.journey.HeadscaleDomain}, []string{"AAAA", "CNAME"})
		if err != nil {
			return "", err
		}
		paths, err := FixedQualificationFixturePaths(executor.prepared.Input.RunID)
		if err != nil {
			return "", err
		}
		fixtureState, err := executor.remotePathsState(ctx, []string{paths.StaticFile, paths.StaticRoot, paths.HTPasswd, paths.SrvRunRoot, paths.EtcRunRoot, "/srv/lanpanel-qualification", "/etc/lanpanel-qualification"})
		if err != nil {
			return "", err
		}
		profileState, err := executor.remotePathsState(ctx, []string{paths.DNSProfile, paths.DNSToken})
		if err != nil {
			return "", err
		}
		users, keys, devices, err := executor.observeHeadscaleEntities(ctx)
		if err != nil {
			return "", err
		}
		userID, keyID, err := executor.requireExactHeadscaleResults(users, keys, false, time.Time{})
		if err != nil {
			return "", err
		}
		if err := confirmRevokedPreauthKey(keys, keyID, time.Now().UTC()); err != nil {
			return "", err
		}
		deviceID, err := strconv.ParseUint(executor.state.ConnectorDeviceID, 10, 64)
		if err != nil || deviceID == 0 {
			return "", fmt.Errorf("connector device result reference is unavailable")
		}
		if err := confirmExpiredConnectorDevice(devices, deviceID, userID, time.Now().UTC()); err != nil {
			return "", err
		}
		connectorState := "absent"
		if installation.Connector != nil && installation.Connector.ControlURL == "https://"+executor.journey.HeadscaleDomain {
			connectorState = "present"
		}
		if !executor.state.CertificateCleanupComplete || len(executor.state.CertificateCleanup) == 0 || executor.state.RetainedCertificate == nil || installation.Headscale == nil || installation.Headscale.Certificate == nil {
			return "", fmt.Errorf("final certificate inventory authority is incomplete")
		}
		retained, err := executor.certificateArtifact(*installation.Headscale.Certificate)
		if err != nil || retained != *executor.state.RetainedCertificate {
			return "", fmt.Errorf("retained Headscale certificate identity changed: %w", err)
		}
		nonRetainedCertificatePaths := make([]string, 0, 2*len(executor.state.CertificateCleanup))
		for _, artifact := range executor.state.CertificateCleanup {
			bundle, _ := certificates.BundlePath(artifact.CertificateID, artifact.Generation)
			pointer, _ := certificates.ActivePointerPath(artifact.CertificateID)
			nonRetainedCertificatePaths = append(nonRetainedCertificatePaths, bundle, pointer)
		}
		nonRetainedCertificateState, err := executor.remotePathsState(ctx, nonRetainedCertificatePaths)
		if err != nil {
			return "", err
		}
		retainedBundle, _ := certificates.BundlePath(retained.CertificateID, retained.Generation)
		retainedPointer, _ := certificates.ActivePointerPath(retained.CertificateID)
		retainedCertificateState, err := executor.remotePathsState(ctx, []string{retainedBundle, retainedPointer})
		if err != nil {
			return "", err
		}
		return priorState(step,
			fmt.Sprintf("configuration.resources=%d", len(installation.Resources)),
			fmt.Sprintf("configuration.credentials=%d", len(installation.Credentials)),
			fmt.Sprintf("configuration.static_roots=%d", len(installation.StaticRoots)),
			"nonretained_certificate_pointers_and_bundles="+nonRetainedCertificateState,
			"retained_headscale_certificate_pointer_and_bundle="+retainedCertificateState,
			fmt.Sprintf("run_owned_nonretained_A_records=%d", nonRetainedRecords),
			fmt.Sprintf("retained_headscale_A_records=%d", retainedRecords),
			fmt.Sprintf("retained_headscale_AAAA_CNAME_records=%d", retainedForbiddenRecords),
			fmt.Sprintf("resource_deleted=%t", executor.state.ResourceID != "" && localState == "absent"),
			"temporary_resource="+temporaryState,
			"tailnet_resource="+tailnetState,
			"fixture="+fixtureState,
			"dns_profile="+profileState,
			fmt.Sprintf("headscale.users=%d", len(users)),
			fmt.Sprintf("headscale.preauth_keys=%d", len(keys)),
			fmt.Sprintf("headscale.devices=%d", len(devices)),
			"headscale_user_result=present",
			"preauth_key_result=inactive",
			"connector_device_result=expired",
			"connector_binding="+connectorState,
			fmt.Sprintf("pending_dns_create_intents=%d", len(executor.state.DNSCreateIntents)),
			fmt.Sprintf("final_cleanup_complete=%t", executor.state.FinalCleanupComplete)), nil
	}
	return "", fmt.Errorf("trusted live executor step is unknown")
}

func (executor *LiveExecutor) observeInstallation(ctx context.Context) (domain.Installation, error) {
	configuration, err := executor.configurationInventory(ctx)
	if err != nil {
		return domain.Installation{}, err
	}
	return configuration.Installation, nil
}

func (executor *LiveExecutor) observeHeadscaleEntities(ctx context.Context) ([]managedheadscale.User, []managedheadscale.PreauthKey, []managedheadscale.Device, error) {
	var users application.HeadscaleUsersResult
	var keys application.HeadscaleKeysResult
	var devices application.HeadscaleDevicesResult
	if _, err := executor.management.Post(ctx, "/api/actions/headscale_user_list", struct{}{}, &users); err != nil {
		return nil, nil, nil, err
	}
	if _, err := executor.management.Post(ctx, "/api/actions/preauth_key_list", struct{}{}, &keys); err != nil {
		return nil, nil, nil, err
	}
	if _, err := executor.management.Post(ctx, "/api/actions/device_list", struct{}{}, &devices); err != nil {
		return nil, nil, nil, err
	}
	if _, err := userIDs(users.Users); err != nil {
		return nil, nil, nil, err
	}
	if _, err := preauthKeyIDs(keys.Keys); err != nil {
		return nil, nil, nil, err
	}
	if _, err := deviceIDs(devices.Devices); err != nil {
		return nil, nil, nil, err
	}
	return users.Users, keys.Keys, devices.Devices, nil
}

func (executor *LiveExecutor) requireExactHeadscaleResults(users []managedheadscale.User, keys []managedheadscale.PreauthKey, requireActiveKey bool, observedAt time.Time) (uint64, uint64, error) {
	userID, err := strconv.ParseUint(executor.state.HeadscaleUserID, 10, 64)
	if err != nil || userID == 0 {
		return 0, 0, fmt.Errorf("qualification Headscale user result reference is unavailable")
	}
	keyID, err := strconv.ParseUint(executor.state.PreauthKeyID, 10, 64)
	if err != nil || keyID == 0 {
		return 0, 0, fmt.Errorf("qualification preauth key result reference is unavailable")
	}
	userMatches, keyMatches := 0, 0
	for _, user := range users {
		if user.ID == userID && user.Name == "qualification" {
			userMatches++
		}
	}
	for _, key := range keys {
		active := !key.Used && !observedAt.IsZero() && key.Expiration.After(observedAt)
		if key.ID == keyID && key.UserID == userID && (!requireActiveKey || active) && key.Expiration.After(key.CreatedAt) {
			keyMatches++
		}
	}
	if userMatches != 1 || keyMatches != 1 {
		return 0, 0, fmt.Errorf("headscale result references do not resolve to exact active entities")
	}
	return userID, keyID, nil
}

func (executor *LiveExecutor) providerRecordCount(ctx context.Context, names, kinds []string) (int, error) {
	count := 0
	for _, name := range names {
		for _, kind := range kinds {
			records, err := executor.cloudflare.List(ctx, name, kind)
			if err != nil {
				return 0, err
			}
			count += len(records)
		}
	}
	return count, nil
}

func (executor *LiveExecutor) providerTrackedARecordCount(ctx context.Context, names []string) (int, error) {
	if len(executor.state.CloudflareRecords) != len(names) {
		return 0, fmt.Errorf("tracked provider A-record result inventory contains unexpected objects")
	}
	expected := make(map[string]cloudflareRecord, len(names))
	selected := make(map[string]bool, len(names))
	for _, name := range names {
		if selected[name] {
			return 0, fmt.Errorf("provider record selector is duplicated")
		}
		selected[name] = true
	}
	for _, record := range executor.state.CloudflareRecords {
		if !selected[record.Name] {
			continue
		}
		if _, present := expected[record.Name]; present || record.Type != "A" || record.Content != executor.journey.PublicIPv4 || record.Proxied {
			return 0, fmt.Errorf("tracked provider A-record result is ambiguous")
		}
		expected[record.Name] = record
	}
	if len(expected) != len(names) {
		return 0, fmt.Errorf("tracked provider A-record result inventory is incomplete")
	}
	for _, name := range names {
		records, err := executor.cloudflare.List(ctx, name, "A")
		if err != nil {
			return 0, err
		}
		if len(records) != 1 || records[0] != expected[name] {
			return 0, fmt.Errorf("provider A-record result reference does not resolve exactly")
		}
	}
	return len(names), nil
}

func (executor *LiveExecutor) observeIPv4ListenerConflictCount(ctx context.Context, expectedAddress string, port uint16) (int, error) {
	expected, err := netip.ParseAddr(expectedAddress)
	if err != nil || !expected.Is4() {
		return 0, fmt.Errorf("qualification listener address is invalid")
	}
	data, err := executor.target.readRemoteVirtual(ctx, "/proc/net/tcp", 4<<20)
	if err != nil {
		return 0, err
	}
	count := 0
	for index, line := range strings.Split(string(data), "\n") {
		if index == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			return 0, fmt.Errorf("remote IPv4 listener inventory is invalid")
		}
		addressText, portText, present := strings.Cut(fields[1], ":")
		addressValue, addressErr := strconv.ParseUint(addressText, 16, 32)
		observedPort, portErr := strconv.ParseUint(portText, 16, 16)
		if !present || addressErr != nil || portErr != nil || len(addressText) != 8 {
			return 0, fmt.Errorf("remote IPv4 listener selector is invalid")
		}
		address := netip.AddrFrom4([4]byte{byte(addressValue), byte(addressValue >> 8), byte(addressValue >> 16), byte(addressValue >> 24)})
		if fields[3] == "0A" && uint16(observedPort) == port && (address.IsUnspecified() || address == expected) {
			count++
		}
	}
	return count, nil
}

func (executor *LiveExecutor) remotePathsState(ctx context.Context, paths []string) (string, error) {
	present := 0
	for _, path := range paths {
		state, err := executor.remotePathState(ctx, path)
		if err != nil {
			return "", err
		}
		if state == "present" {
			present++
		}
	}
	switch present {
	case 0:
		return "absent", nil
	case len(paths):
		return "present", nil
	default:
		return "partial", nil
	}
}

func (executor *LiveExecutor) remotePathState(ctx context.Context, path string) (string, error) {
	if _, err := executor.target.sftpLstat(ctx, path); err == nil {
		return "present", nil
	} else if os.IsNotExist(err) {
		return "absent", nil
	} else {
		return "", err
	}
}

func resourceNameState(installation domain.Installation, name string) (string, error) {
	matches := 0
	for _, resource := range installation.Resources {
		if resource.Name == name {
			matches++
		}
	}
	if matches > 1 {
		return "", fmt.Errorf("qualification resource selector is ambiguous")
	}
	if matches == 1 {
		return "present", nil
	}
	return "absent", nil
}

func exactResource(installation domain.Installation, id, name string) (domain.AppResource, error) {
	matches := 0
	var selected domain.AppResource
	for _, resource := range installation.Resources {
		if resource.ID == id && resource.Name == name {
			matches++
			selected = resource
		}
	}
	if id == "" || matches != 1 {
		return domain.AppResource{}, fmt.Errorf("qualification resource result reference does not resolve exactly")
	}
	return selected, nil
}

func exactRegistration(installation domain.Installation, id, kind string) error {
	matches := 0
	if kind == "credential" {
		for _, credential := range installation.Credentials {
			if credential.ID == id {
				matches++
			}
		}
	} else {
		for _, root := range installation.StaticRoots {
			if root.ID == id {
				matches++
			}
		}
	}
	if id == "" || matches != 1 {
		return fmt.Errorf("qualification registration result reference does not resolve exactly")
	}
	return nil
}
