//go:build linux

package application

import (
	"context"
	"lanpanel/internal/domain"
)

// ResourceStatusReadModel is the observational application seam used by the
// Management UI. Implementations return the closed typed status contract; a
// caller never supplies a raw resource document or a probe result as JSON.
type ResourceStatusReadModel interface {
	ResourceStatus(context.Context, string) (domain.ResourceStatusResult, error)
	ResourceStatusCatalog(context.Context) (domain.ResourceStatusCatalog, error)
}

// ResourceProbe is kept separate from the read model so deterministic tests
// can provide connector, route, and target observations without starting a
// process, logging in a connector, or opening ingress.
type ResourceProbe interface {
	ProbeResource(context.Context, string) (ResourceStatusEvidence, error)
}

// JobReadModel is the read-only seam for operation feedback. Job records are
// typed application results and never carry secret output.
type JobReadModel interface {
	ListJobs(context.Context) (JobsResult, error)
	ReadJob(context.Context, string) (JobResult, error)
}

// SideEffectCounts reports calls crossing boundaries that fixture reads and
// actions must not invoke implicitly.
type SideEffectCounts struct {
	ProcessStart      int32 `json:"process_start"`
	ProcessStop       int32 `json:"process_stop"`
	ACMERequests      int32 `json:"acme_requests"`
	DNSRequests       int32 `json:"dns_requests"`
	TailscaleCommands int32 `json:"tailscale_commands"`
	RemoteCommands    int32 `json:"remote_commands"`
	ConnectorLogins   int32 `json:"connector_logins"`
	ConnectorVerifies int32 `json:"connector_verifies"`
}

// SideEffectCounter is a fixture/preview seam. Production status reads do not
// depend on it; fixture tests use it to prove that observation and remote
// registration paths have no hidden lifecycle side effects.
type SideEffectCounter interface {
	SideEffectCounts(context.Context) (SideEffectCounts, error)
}

// ReadModelSeams groups injectable typed observation and operation-feedback
// boundaries for the application/helper service.
type ReadModelSeams struct {
	Status   ResourceStatusReadModel
	Probe    ResourceProbe
	Jobs     JobReadModel
	Counters SideEffectCounter
}

func FixedReadModelSeams() ReadModelSeams {
	return ReadModelSeams{
		Status: fixedStatusReadModel{},
		Jobs:   fixedJobReadModel{},
	}
}

type fixedStatusReadModel struct{}

func (fixedStatusReadModel) ResourceStatus(ctx context.Context, resourceID string) (domain.ResourceStatusResult, error) {
	return ReadResourceStatus(ctx, resourceID)
}

func (fixedStatusReadModel) ResourceStatusCatalog(ctx context.Context) (domain.ResourceStatusCatalog, error) {
	return ReadResourceStatusCatalog(ctx)
}

type fixedJobReadModel struct{}

func (fixedJobReadModel) ListJobs(ctx context.Context) (JobsResult, error) { return ListJobs(ctx) }
func (fixedJobReadModel) ReadJob(ctx context.Context, id string) (JobResult, error) {
	return ReadJob(ctx, id)
}
