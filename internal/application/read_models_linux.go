//go:build linux

package application

import (
	"bytes"
	"context"
	"fmt"
	"lanpanel/internal/certificates"
	"lanpanel/internal/closure"
	"lanpanel/internal/control"
	manageddiagnostics "lanpanel/internal/diagnostics"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/identity"
	"lanpanel/internal/jobs"
	"lanpanel/internal/nginx"
	"lanpanel/internal/preflight"
	"lanpanel/internal/safety"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"
)

type ResourceStatus struct {
	ResourceID       string                       `json:"resource_id"`
	Name             string                       `json:"name"`
	TargetKind       domain.AppTargetKind         `json:"target_kind"`
	Publication      domain.PublicationState      `json:"publication"`
	ProcessRequested domain.ProcessRequestedState `json:"process_requested,omitempty"`
	ObservedStatus   string                       `json:"observed_status"`
	Reason           string                       `json:"reason,omitempty"`
}

type SystemStatus struct {
	ObservedAt      time.Time        `json:"observed_at"`
	InstallationID  string           `json:"installation_id"`
	NginxStatus     string           `json:"nginx_status"`
	NginxEntryCount int              `json:"nginx_entry_count"`
	SafetyChecksum  string           `json:"safety_checksum"`
	ManagementHTTPS string           `json:"management_https"`
	Headscale       string           `json:"headscale"`
	Connector       string           `json:"connector"`
	Resources       []ResourceStatus `json:"resources"`
}

type DiagnosticIssue struct {
	Code           string `json:"code"`
	Responsibility string `json:"responsibility"`
	Summary        string `json:"summary"`
	Guidance       string `json:"guidance"`
}
type DiagnosticsResult struct {
	ObservedAt   time.Time         `json:"observed_at"`
	SystemStatus SystemStatus      `json:"system_status"`
	Issues       []DiagnosticIssue `json:"issues"`
}
type ConfigurationExport struct {
	SchemaVersion string              `json:"schema_version"`
	ExportedAt    time.Time           `json:"exported_at"`
	Installation  domain.Installation `json:"installation"`
}
type JobsResult struct {
	Jobs []jobs.Record `json:"jobs"`
}
type JobResult struct {
	Job jobs.Record `json:"job"`
}

func observeHeadscaleStatus(ctx context.Context, installation domain.Installation, state safety.State) error {
	if installation.Headscale == nil || !installation.Headscale.Enabled || installation.Headscale.Applied == nil || installation.Headscale.Certificate == nil {
		return fmt.Errorf("headscale lifecycle authority is incomplete")
	}
	journal, err := control.NewStore(control.FixedPaths(), filetxn.Owner{UID: 0, GID: 0}).Read()
	if err != nil {
		return fmt.Errorf("committed Headscale control journal is unavailable: %w", err)
	}
	if journal.Phase != control.PhaseCommitted || journal.InstallationID != installation.InstallationID || journal.Certificate == nil {
		return fmt.Errorf("committed Headscale control journal is incomplete")
	}
	candidate := journal.Candidate
	expectedApplied, err := control.AppliedIdentity(candidate)
	if err != nil || !reflect.DeepEqual(*installation.Headscale.Applied, expectedApplied) || candidate.HeadscaleID != installation.Headscale.ID || journal.Certificate.ID != candidate.CertificateID || !certificateBundleMatches(*installation.Headscale.Certificate, journal.Certificate.ID, journal.Certificate.Generation, certificates.BundleIdentityFor(*journal.Certificate)) {
		return fmt.Errorf("headscale durable identity differs from the committed control journal")
	}
	if err := certificates.VerifyBundleIdentity(journal.Certificate.ID, journal.Certificate.Generation, certificates.BundleIdentityFor(*journal.Certificate)); err != nil {
		return err
	}
	bundlePath, err := certificates.BundlePath(journal.Certificate.ID, journal.Certificate.Generation)
	if err != nil {
		return err
	}
	pointer, err := certificates.ObservePointer(journal.Certificate.ID)
	if err != nil {
		return fmt.Errorf("headscale served certificate pointer is unavailable: %w", err)
	}
	if pointer != bundlePath {
		return fmt.Errorf("headscale served certificate pointer is not current")
	}
	accounts, err := identity.HeadscaleAccounts(installation.InstallationID, installation.Headscale.ID)
	if err != nil {
		return err
	}
	present, identities, err := identity.InspectAccounts(accounts)
	if err != nil {
		return fmt.Errorf("headscale service account observation failed: %w", err)
	}
	if !present || len(identities) != 1 {
		return fmt.Errorf("headscale service account observation is incomplete")
	}
	account := identities[0]
	config, err := os.ReadFile(candidate.Paths.Config)
	if err != nil {
		return err
	}
	policy, err := os.ReadFile(candidate.Paths.Policy)
	if err != nil {
		return err
	}
	unit, err := os.ReadFile(candidate.Paths.Unit)
	if err != nil {
		return err
	}
	rendered := control.Rendered{Candidate: candidate, Config: config, Policy: policy, Unit: unit}
	if err := control.VerifyRendered(rendered); err != nil {
		return err
	}
	activationBundle, err := control.BuildActivation(installation.InstallationID, candidate, *journal.Certificate)
	if err != nil {
		return err
	}
	privateProbe, err := os.ReadFile(activationBundle.Paths.PrivateProbeUnit)
	if err != nil {
		return err
	}
	if !bytes.Equal(privateProbe, activationBundle.PrivateProbe) {
		return fmt.Errorf("headscale private probe unit differs from activation authority")
	}
	runtime, err := control.NewSystemdRuntime()
	if err != nil {
		return err
	}
	if _, err := runtime.ObserveCommitted(ctx, rendered, account); err != nil {
		return err
	}
	activationHost, err := control.NewActivationHost()
	if err != nil {
		return err
	}
	if err := activationHost.ObserveCommittedActivation(ctx, activationBundle); err != nil {
		return err
	}
	if err := runtime.ProbePrivate(ctx, candidate); err != nil {
		return err
	}
	if err := verifyLiveHeadscaleCertificate(ctx, installation.InstallationID, candidate, *journal.Certificate); err != nil {
		return err
	}
	if !activeCertificateMatchesExpected(state.Headscale.ActiveCertificate, &safety.ActiveCertificateAuthority{Generation: journal.Certificate.Generation, Fingerprint: journal.Certificate.Fingerprint, Binding: journal.Certificate.BindingIdentity, NotAfter: journal.Certificate.NotAfter, LastTrustedWall: journal.Certificate.LastTrustedWall}) {
		return fmt.Errorf("headscale active certificate safety authority differs")
	}
	return nil
}

func ReadSystemStatus(ctx context.Context) (SystemStatus, error) {
	service, err := OpenFixed()
	if err != nil {
		return SystemStatus{}, err
	}
	defer func(ignore func() error) { _ = ignore() }(service.Close)
	document, err := service.normal.Read()
	if err != nil {
		return SystemStatus{}, err
	}
	installation, err := domain.DecodeInstallation(document.Entries["installations/current"])
	if err != nil {
		return SystemStatus{}, err
	}
	state, err := service.safety.Read()
	if err != nil {
		return SystemStatus{}, err
	}
	installed, releaseErr := loadInstalledReleaseIdentity()
	profileErr := releaseErr
	if releaseErr == nil {
		profileErr = verifyInstalledPackageProfile(ctx, installed.Profile)
	}
	manifest, auditErr := nginx.Audit(nginx.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
	nginxStatus := "unknown"
	if preflight.IsProfileDrift(profileErr) {
		nginxStatus = "package_identity_drift"
	}
	runtimeHealthy := false
	if profileErr == nil && auditErr == nil {
		listeners := expectedNginxRuntimeListeners(manifest)
		snapshot, observeErr := (closure.ProcObserver{UnitCgroup: "/system.slice/lanpanel-nginx.service", Executable: "/usr/sbin/nginx", ExpectedArgv: "/usr/sbin/nginx\x00-c\x00/etc/lanpanel/nginx/nginx.conf\x00-p\x00/var/lib/lanpanel/nginx/\x00-g\x00daemon off;", PIDPath: nginx.FixedPaths().PIDPath, Generation: manifest.GenerationID, OwnedListeners: listeners}).Observe(ctx)
		runtimeHealthy = observeErr == nil && closure.VerifyServing(snapshot, manifest.GenerationID, listeners) == nil
		if runtimeHealthy {
			ownershipAuthority, ownershipErr := fixedOwnershipAuthority(service.ownership)
			runtimeHealthy = ownershipErr == nil && nginx.Guard(nginx.GuardInput{Action: nginx.GuardStart, Manifest: manifest, Safety: state, Installation: &installation, Ownership: ownershipAuthority, Now: time.Now().UTC()}).Allowed
		}
		if runtimeHealthy {
			nginxStatus = "healthy"
		} else {
			nginxStatus = "disk_verified_runtime_unknown"
		}
	}
	observedAt := time.Now().UTC()
	managementHTTPSStatus := observeManagementHTTPSStatus(installation, state, manifest, runtimeHealthy, observedAt)
	result := SystemStatus{ObservedAt: observedAt, InstallationID: installation.InstallationID, NginxStatus: nginxStatus, NginxEntryCount: len(manifest.Entries), SafetyChecksum: state.Checksum, ManagementHTTPS: managementHTTPSStatus, Headscale: "not_configured", Connector: "not_configured", Resources: []ResourceStatus{}}
	if installation.Headscale != nil {
		result.Headscale = "configured"
		if state.Headscale.CertificateExpiry != nil {
			result.Headscale = "closed_certificate_expired"
		} else if installation.Headscale.Enabled && state.Headscale.ActiveCertificate != nil {
			if err := observeHeadscaleStatus(ctx, installation, state); err == nil {
				result.Headscale = "healthy"
			} else {
				result.Headscale = "configured_runtime_unknown"
			}
		} else {
			result.Headscale = "inactive_or_unknown"
		}
	}
	if installation.Connector != nil {
		result.Connector = "unknown"
		if _, verifyErr := VerifyConnector(ctx, nil, nil); verifyErr == nil {
			result.Connector = "verified"
		}
	}
	normalResources := make(map[string]bool, len(installation.Resources))
	safetyResources := make(map[string]safety.ResourceSafety, len(state.Resources))
	for _, resource := range installation.Resources {
		normalResources[resource.ID] = true
	}
	for _, resource := range state.Resources {
		safetyResources[resource.ResourceID] = resource
	}
	for _, resource := range installation.Resources {
		item := ResourceStatus{ResourceID: resource.ID, Name: resource.Name, TargetKind: resource.Target.Kind, Publication: resource.PublicationRecord.State, ObservedStatus: "unknown"}
		if resource.ManagedProcess != nil {
			item.ProcessRequested = resource.ManagedProcess.Requested
		}
		independent, present := safetyResources[resource.ID]
		if !present {
			item.ObservedStatus = "one_sided_authority"
			item.Reason = "normal resource lacks independent safety/ownership authority; keep ingress closed and use configuration export and clean-host rebuild"
			result.Resources = append(result.Resources, item)
			continue
		}
		if independent.Ownership == safety.OwnershipOrphan {
			item.ObservedStatus = "ownership_orphan"
			item.Reason = "independent ownership orphan blocks publication; do not adopt or delete it; use configuration export and clean-host rebuild"
			result.Resources = append(result.Resources, item)
			continue
		}
		item = observeResourceRuntimeStatus(ctx, resource, item, runtimeHealthy, manifest, fixedResourceStatusObservers())
		result.Resources = append(result.Resources, item)
	}
	for _, independent := range state.Resources {
		if normalResources[independent.ResourceID] {
			continue
		}
		status := "one_sided_authority"
		reason := "resource exists only in independent safety/ownership inventory; publication is blocked; keep ingress closed and use configuration export and clean-host rebuild"
		if independent.Ownership == safety.OwnershipOrphan {
			status = "ownership_orphan"
			reason = "independent ownership orphan has no normal resource authority; publication is blocked; do not adopt or delete it; use configuration export and clean-host rebuild"
		}
		result.Resources = append(result.Resources, ResourceStatus{ResourceID: independent.ResourceID, ObservedStatus: status, Reason: reason})
	}
	sort.Slice(result.Resources, func(i, j int) bool { return result.Resources[i].ResourceID < result.Resources[j].ResourceID })
	return result, nil
}

func observeNginxStatusForResource(ctx context.Context, service *FixedService, installation domain.Installation) (nginx.Manifest, bool, domain.ResourceFailureCategory, bool) {
	if service == nil {
		return nginx.Manifest{}, false, domain.FailureAuthorityMissing, false
	}
	state, err := service.safety.Read()
	if err != nil {
		return nginx.Manifest{}, false, domain.FailureAuthorityMissing, false
	}
	installed, err := loadInstalledReleaseIdentity()
	if err != nil {
		return nginx.Manifest{}, false, domain.FailureAuthorityMissing, false
	}
	if err := verifyInstalledPackageProfile(ctx, installed.Profile); err != nil {
		return nginx.Manifest{}, false, domain.FailureAuthorityConflict, false
	}
	manifest, err := nginx.Audit(nginx.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
	if err != nil {
		return manifest, false, domain.FailureEvidenceMismatch, false
	}
	listeners := expectedNginxRuntimeListeners(manifest)
	snapshot, err := (closure.ProcObserver{UnitCgroup: "/system.slice/lanpanel-nginx.service", Executable: "/usr/sbin/nginx", ExpectedArgv: "/usr/sbin/nginx\x00-c\x00/etc/lanpanel/nginx/nginx.conf\x00-p\x00/var/lib/lanpanel/nginx/\x00-g\x00daemon off;", PIDPath: nginx.FixedPaths().PIDPath, Generation: manifest.GenerationID, OwnedListeners: listeners}).Observe(ctx)
	if err != nil || closure.VerifyServing(snapshot, manifest.GenerationID, listeners) != nil {
		return manifest, false, domain.FailureEvidenceMismatch, false
	}
	ownershipAuthority, err := fixedOwnershipAuthority(service.ownership)
	if err != nil {
		return manifest, false, domain.FailureAuthorityConflict, false
	}
	decision := nginx.Guard(nginx.GuardInput{Action: nginx.GuardStart, Manifest: manifest, Safety: state, Installation: &installation, Ownership: ownershipAuthority, Now: time.Now().UTC()})
	if !decision.Allowed {
		reason := strings.ToLower(decision.Reason)
		if strings.Contains(reason, "fence") || strings.Contains(reason, "contraction") || strings.Contains(reason, "closing") || strings.Contains(reason, "deleting") {
			return manifest, false, domain.FailurePublication, true
		}
		return manifest, false, domain.FailureEvidenceMismatch, false
	}
	return manifest, true, domain.FailureNone, false
}

func observeManagementHTTPSStatus(installation domain.Installation, state safety.State, manifest nginx.Manifest, runtimeHealthy bool, now time.Time) string {
	config := installation.ManagementHTTPS
	if config == nil {
		return "not_configured"
	}
	if config.Phase != domain.ManagementHTTPSActive {
		return string(config.Phase)
	}
	if config.CertificateBundle == nil || state.ManagementHTTPS.ActiveCertificate == nil {
		return "configured_runtime_unknown"
	}
	certificate := state.ManagementHTTPS.ActiveCertificate
	if !now.Before(certificate.NotAfter) || state.ManagementHTTPS.CertificateExpiry != nil && !now.Before(state.ManagementHTTPS.CertificateExpiry.Deadline) {
		return "expired"
	}
	entry, err := nginx.BuildManagementEntry(installation)
	if err != nil || entry.Digest != state.ManagementHTTPS.EntryDigest || !runtimeHealthy {
		return "configured_runtime_unknown"
	}
	for _, observed := range manifest.Entries {
		if observed.Kind == nginx.EntryManagement && observed.Relative == entry.Relative && observed.Digest == entry.Digest && observed.Generation == entry.Generation {
			return "healthy"
		}
	}
	return "configured_runtime_unknown"
}

func expectedNginxRuntimeListeners(manifest nginx.Manifest) []string {
	listeners := []string{"tcp:0.0.0.0:80", "tcp:0.0.0.0:443", "tcp::::80", "tcp::::443"}
	for _, entry := range manifest.Entries {
		for _, listener := range entry.Listeners {
			listeners = append(listeners, strings.Replace(listener, "tcp:[::]:", "tcp::::", 1))
		}
	}
	sort.Strings(listeners)
	return slices.Compact(listeners)
}

func manifestContainsResource(manifest nginx.Manifest, resourceID string) bool {
	for _, entry := range manifest.Entries {
		if entry.ResourceID == resourceID {
			return true
		}
	}
	return false
}

func manifestMatchesResource(manifest nginx.Manifest, resource domain.AppResource) bool {
	bundle := resource.PublicationRecord.LastAppliedBundle
	if bundle == nil || resource.PublicationRecord.LastAppliedDigest == nil || *resource.PublicationRecord.LastAppliedDigest != bundle.ConfigDigest || bundle.SiteIdentity == "" || bundle.Generation == 0 {
		return false
	}
	kind := nginx.EntryApp
	if bundle.Kind == domain.PublicationTemporaryHTTP {
		kind = nginx.EntryTemporary
	}
	for _, entry := range manifest.Entries {
		if entry.ResourceID == resource.ID && entry.Kind == kind && entry.Digest == bundle.SiteIdentity && entry.Generation == bundle.Generation {
			return true
		}
	}
	return false
}

func ReadDiagnostics(ctx context.Context) (DiagnosticsResult, error) {
	status, err := ReadSystemStatus(ctx)
	if err != nil {
		return DiagnosticsResult{}, err
	}
	observation := manageddiagnostics.Observation{ObservedAt: status.ObservedAt, Nginx: status.NginxStatus, Headscale: status.Headscale, Connector: status.Connector}
	for _, resource := range status.Resources {
		observation.Resources = append(observation.Resources, manageddiagnostics.ResourceObservation{ResourceID: resource.ResourceID, Status: resource.ObservedStatus, Reason: resource.Reason})
	}
	issues := manageddiagnostics.Build(observation)
	result := DiagnosticsResult{ObservedAt: status.ObservedAt, SystemStatus: status, Issues: make([]DiagnosticIssue, len(issues))}
	for index, issue := range issues {
		result.Issues[index] = DiagnosticIssue{Code: issue.Code, Responsibility: issue.Responsibility, Summary: issue.Summary, Guidance: issue.Guidance}
	}
	return result, nil
}

func ExportConfiguration(context.Context) (ConfigurationExport, error) {
	service, err := OpenFixed()
	if err != nil {
		return ConfigurationExport{}, err
	}
	defer func(ignore func() error) { _ = ignore() }(service.Close)
	document, err := service.normal.Read()
	if err != nil {
		return ConfigurationExport{}, err
	}
	installation, err := domain.DecodeInstallation(document.Entries["installations/current"])
	if err != nil {
		return ConfigurationExport{}, err
	}
	for index := range installation.Resources {
		installation.Resources[index].PublicationRecord.RuntimeObservation = nil
		if installation.Resources[index].ManagedProcess != nil {
			installation.Resources[index].ManagedProcess.RuntimeObservation = nil
		}
	}
	return ConfigurationExport{SchemaVersion: "lanpanel.configuration-export.v1", ExportedAt: time.Now().UTC(), Installation: installation}, nil
}

func ListJobs(context.Context) (JobsResult, error) {
	service, err := OpenFixed()
	if err != nil {
		return JobsResult{}, err
	}
	defer func(ignore func() error) { _ = ignore() }(service.Close)
	document, err := service.normal.Read()
	if err != nil {
		return JobsResult{}, err
	}
	result := JobsResult{Jobs: []jobs.Record{}}
	for key := range document.Entries {
		if !strings.HasPrefix(key, "jobs/") {
			continue
		}
		id := strings.TrimPrefix(key, "jobs/")
		record, loadErr := jobs.LoadEntries(document.Entries, id)
		if loadErr != nil {
			return JobsResult{}, loadErr
		}
		result.Jobs = append(result.Jobs, record)
	}
	sort.Slice(result.Jobs, func(i, j int) bool {
		if result.Jobs[i].StartedAt.Equal(result.Jobs[j].StartedAt) {
			return result.Jobs[i].ID < result.Jobs[j].ID
		}
		return result.Jobs[i].StartedAt.After(result.Jobs[j].StartedAt)
	})
	if len(result.Jobs) > 512 {
		result.Jobs = result.Jobs[:512]
	}
	return result, nil
}

func ReadJob(_ context.Context, id string) (JobResult, error) {
	if id == "" {
		return JobResult{}, fmt.Errorf("job ID missing")
	}
	service, err := OpenFixed()
	if err != nil {
		return JobResult{}, err
	}
	defer func(ignore func() error) { _ = ignore() }(service.Close)
	store, err := jobs.NewStore(service.normal, jobs.Options{})
	if err != nil {
		return JobResult{}, err
	}
	record, err := store.Read(id)
	return JobResult{Job: record}, err
}
