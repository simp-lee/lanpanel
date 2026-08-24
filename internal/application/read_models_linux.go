//go:build linux

package application

import (
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/closure"
	manageddiagnostics "lanpanel/internal/diagnostics"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/jobs"
	"lanpanel/internal/nginx"
	managedprocess "lanpanel/internal/process"
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
	ObservedAt time.Time         `json:"observed_at"`
	Issues     []DiagnosticIssue `json:"issues"`
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
	manifest, auditErr := nginx.Audit(nginx.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
	nginxStatus := "unknown"
	runtimeHealthy := false
	if auditErr == nil {
		listeners := []string{}
		for _, entry := range manifest.Entries {
			listeners = append(listeners, entry.Listeners...)
		}
		sort.Strings(listeners)
		listeners = slices.Compact(listeners)
		snapshot, observeErr := (closure.ProcObserver{UnitCgroup: "/system.slice/lanpanel-nginx.service", Executable: "/usr/sbin/nginx", ExpectedArgv: "/usr/sbin/nginx\x00-c\x00/etc/lanpanel/nginx/nginx.conf\x00-p\x00/var/lib/lanpanel/nginx/\x00-g\x00daemon off;", PIDPath: nginx.FixedPaths().PIDPath, Generation: manifest.GenerationID, OwnedListeners: listeners}).Observe(ctx)
		runtimeHealthy = observeErr == nil && snapshot.Complete && snapshot.Master != nil
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
	result := SystemStatus{ObservedAt: time.Now().UTC(), InstallationID: installation.InstallationID, NginxStatus: nginxStatus, NginxEntryCount: len(manifest.Entries), SafetyChecksum: state.Checksum, Headscale: "not_configured", Connector: "not_configured", Resources: []ResourceStatus{}}
	if installation.Headscale != nil {
		result.Headscale = "configured"
		if state.Headscale.CertificateExpiry != nil {
			result.Headscale = "closed_certificate_expired"
		} else if installation.Headscale.Enabled && state.Headscale.ActiveCertificate != nil {
			result.Headscale = "configured_runtime_unknown"
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
	for _, resource := range installation.Resources {
		item := ResourceStatus{ResourceID: resource.ID, Name: resource.Name, TargetKind: resource.Target.Kind, Publication: resource.PublicationRecord.State, ObservedStatus: "unknown"}
		if resource.ManagedProcess != nil {
			item.ProcessRequested = resource.ManagedProcess.Requested
		}
		if resource.PublicationRecord.State == domain.PublicationUnpublished {
			item.ObservedStatus = "runtime_unknown"
			item.Reason = "unpublished configuration has no fresh runtime closure proof"
			if runtimeHealthy && !manifestContainsResource(manifest, resource.ID) {
				item.ObservedStatus = "closed"
				item.Reason = "fresh Nginx graph and runtime exclude the unpublished resource"
			}
			result.Resources = append(result.Resources, item)
			continue
		}
		_, targetErr := probeResourceTarget(ctx, resource)
		processErr := error(nil)
		if resource.ManagedProcess != nil && resource.ManagedProcess.Requested == domain.ProcessRequestedRunning {
			if resource.ManagedProcess.Applied == nil {
				processErr = fmt.Errorf("managed process applied identity missing")
			} else {
				endpointKind := domain.LocalEndpointKind("")
				if resource.Target.LocalHTTP != nil {
					endpointKind = resource.Target.LocalHTTP.EndpointKind
				}
				observation, observeErr := managedprocess.Observe(ctx, "/sys/fs/cgroup", *resource.ManagedProcess.Applied, endpointKind, []string{"/proc/net/tcp", "/proc/net/tcp6"})
				processErr = errors.Join(observeErr, managedprocess.VerifyRunning(observation))
			}
		}
		bundle := resource.PublicationRecord.LastAppliedBundle
		switch {
		case bundle == nil:
			item.Reason = "published resource has no applied bundle"
		case bundle.Kind == domain.PublicationTemporaryHTTP:
			if runtimeHealthy && manifestContainsResource(manifest, resource.ID) && targetErr == nil && processErr == nil {
				item.ObservedStatus = "healthy"
				item.Reason = "fresh target, process, Nginx graph, and runtime evidence match"
			} else if targetErr != nil || processErr != nil {
				item.Reason = errors.Join(targetErr, processErr).Error()
			} else {
				item.Reason = "temporary publication runtime evidence is incomplete"
			}
		case bundle.Kind == domain.PublicationDomainHTTPS:
			status, statusErr := ObserveDomainLiveSources(resource.ID)
			if statusErr != nil {
				item.Reason = statusErr.Error()
				break
			}
			item.ObservedStatus = status.Status
			item.Reason = status.Reason
			if status.Status == "source_verified_runtime_unknown" && runtimeHealthy && manifestContainsResource(manifest, resource.ID) && targetErr == nil && processErr == nil {
				item.ObservedStatus = "healthy"
				item.Reason = "fresh source, target, process, Nginx graph, and runtime evidence match"
			} else if targetErr != nil || processErr != nil {
				item.Reason = errors.Join(targetErr, processErr).Error()
			}
		default:
			item.Reason = "applied publication kind is unsupported"
		}
		result.Resources = append(result.Resources, item)
	}
	return result, nil
}

func manifestContainsResource(manifest nginx.Manifest, resourceID string) bool {
	for _, entry := range manifest.Entries {
		if entry.ResourceID == resourceID {
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
	result := DiagnosticsResult{ObservedAt: status.ObservedAt, Issues: make([]DiagnosticIssue, len(issues))}
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
