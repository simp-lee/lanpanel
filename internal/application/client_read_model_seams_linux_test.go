//go:build linux

package application

import (
	"context"
	"fmt"
	"lanpanel/internal/domain"
	"lanpanel/internal/helperproto"
	"lanpanel/internal/jobs"
	"testing"
	"time"
)

type seamStatusReadModel struct {
	statusCalls  int
	catalogCalls int
	status       domain.ResourceStatusResult
}

func (model *seamStatusReadModel) ResourceStatus(context.Context, string) (domain.ResourceStatusResult, error) {
	model.statusCalls++
	return model.status, nil
}

func (model *seamStatusReadModel) ResourceStatusCatalog(context.Context) (domain.ResourceStatusCatalog, error) {
	model.catalogCalls++
	return domain.ResourceStatusCatalog{InstallationID: "ins_00000000000000000000000000000001", Resources: []domain.ResourceStatusResult{model.status}, ObservedAt: model.status.ObservedAt}, nil
}

type seamProbe struct{ calls int }

func (probe *seamProbe) ProbeResource(context.Context, string) (ResourceStatusEvidence, error) {
	probe.calls++
	return ResourceStatusEvidence{TargetObservation: &domain.TargetObservation{PortConnected: true, HTTPReady: true, HTTPStatus: 200, Validity: domain.EvidenceFresh, ObservedAt: time.Now().UTC(), Failure: domain.FailureNone}}, nil
}

type seamJobs struct{ record jobs.Record }

func (model *seamJobs) ListJobs(context.Context) (JobsResult, error) {
	return JobsResult{Jobs: []jobs.Record{model.record}}, nil
}

func (model *seamJobs) ReadJob(context.Context, string) (JobResult, error) {
	return JobResult{Job: model.record}, nil
}

func seamTestStatus(now time.Time) domain.ResourceStatusResult {
	resourceID := "res_00000000000000000000000000000001"
	configDigest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	return domain.ResourceStatusResult{
		ResourceID: resourceID, Name: "Seam app", TargetKind: domain.AppTargetLocalHTTP,
		OverallStatus: domain.ResourceStatusClosed, ConfigurationStatus: domain.ConfigurationComplete,
		ProcessRequestedStatus: domain.ProcessRequestedStop, ProcessObservedStatus: domain.ProcessStopped, ProcessStatus: domain.ProcessStopped,
		PublicationStatus: domain.PublicationStatusUnpublished, ConnectorStatus: domain.EvidenceNotApplicable, RouteStatus: domain.EvidenceNotApplicable, TargetStatus: domain.EvidenceUnknown,
		FailureCategory: domain.FailureNone, AllowedActions: []domain.ResourceAction{domain.ResourceActionRefresh}, ClosureVerified: true, ClosureDigest: configDigest, ClosureObservedAt: now,
		AffectedObject: "resource/" + resourceID, NextStep: "refresh status", ConfigDigest: configDigest, AuthorityDigest: domain.ResourceStatusAuthorityDigest(resourceID, configDigest), ObservedAt: now,
		TargetObservation: &domain.TargetObservation{Validity: domain.EvidenceUnknown, ObservedAt: now, Failure: domain.FailureEvidenceMissing},
	}
}

func TestHelperServiceUsesInjectedTypedReadModelAndProbeSeams(t *testing.T) {
	now := time.Now().UTC()
	statusModel := &seamStatusReadModel{status: seamTestStatus(now)}
	jobID := "job_" + fmt.Sprintf("%064x", 1)
	ended := now
	jobModel := &seamJobs{record: jobs.Record{SchemaVersion: jobs.SchemaVersion, ID: jobID, Operation: string(domain.OperationProcessStart), Target: "resource/" + statusModel.status.ResourceID, ActorIdentity: "fixture/ui", StartedAt: now, EndedAt: &ended, Status: jobs.StatusTerminal, Result: jobs.ResultSucceeded, ModifiedPaths: []string{}, Postconditions: []jobs.Postcondition{{Kind: "fixture", Status: jobs.PostconditionVerified, Identity: "resource/" + statusModel.status.ResourceID}}}}
	probe := &seamProbe{}
	resourceCalls := 0
	resourceClient := func(_ context.Context, operation helperproto.Operation, _ helperproto.ResourcePayload, target string) (HelperReply, error) {
		resourceCalls++
		if operation != helperproto.OperationPublicationActivate || target != "resource/"+statusModel.status.ResourceID {
			return HelperReply{}, fmt.Errorf("unexpected resource operation %q %q", operation, target)
		}
		return HelperReply{Action: &helperproto.ActionResult{JobID: jobID, JobResult: "succeeded"}}, nil
	}
	service, err := HelperServiceWithResourcesAndSeams(func(context.Context, helperproto.Operation, helperproto.ActionPayload) (HelperReply, error) {
		t.Fatal("fallback helper client was called")
		return HelperReply{}, nil
	}, resourceClient, ReadModelSeams{Status: statusModel, Probe: probe, Jobs: jobModel})
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{Kind: ActorUI, Identity: "fixture/ui", Generation: 1}
	result, err := service.Invoke(context.Background(), actor, Call{Operation: domain.OperationStatus, Target: domain.OperationTarget{Kind: domain.OperationTargetResource, ID: statusModel.status.ResourceID}, Payload: DomainStatusPayload{}})
	if err != nil || result.Payload.(domain.ResourceStatusResult).ResourceID != statusModel.status.ResourceID || statusModel.statusCalls != 1 {
		t.Fatalf("typed status seam was not used: result=%#v error=%v calls=%d", result, err, statusModel.statusCalls)
	}
	result, err = service.Invoke(context.Background(), actor, Call{Operation: domain.OperationJobList, Target: domain.OperationTarget{Kind: domain.OperationTargetInstallation}, Payload: EmptyPayload{}})
	if err != nil || len(result.Payload.(JobsResult).Jobs) != 1 {
		t.Fatalf("typed Job list seam was not used: result=%#v error=%v", result, err)
	}
	result, err = service.Invoke(context.Background(), actor, Call{Operation: domain.OperationJobDetail, Target: domain.OperationTarget{Kind: domain.OperationTargetJob, ID: jobID}, Payload: EmptyPayload{}})
	if err != nil || result.Payload.(JobResult).Job.ID != jobID {
		t.Fatalf("typed Job detail seam was not used: result=%#v error=%v", result, err)
	}
	result, err = service.Invoke(context.Background(), actor, Call{Operation: domain.OperationPublish, Target: domain.OperationTarget{Kind: domain.OperationTargetResource, ID: statusModel.status.ResourceID}, Payload: ConfirmationPayload{PlanID: "plan_fixture", Confirmation: "publish"}})
	if err != nil || result.JobID != jobID || probe.calls != 1 || resourceCalls != 1 {
		t.Fatalf("typed probe/resource seams were not used: result=%#v error=%v probes=%d resource_calls=%d", result, err, probe.calls, resourceCalls)
	}
}
