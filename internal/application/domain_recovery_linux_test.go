//go:build linux

package application

import (
	"lanpanel/internal/domain"
	"lanpanel/internal/ownership"
	"lanpanel/internal/plans"
	"lanpanel/internal/publication"
	"lanpanel/internal/safety"
	"testing"
	"time"
)

func TestCertificateHandoffCarriesInstallationAndActivationDeadline(t *testing.T) {
	deadline := time.Now().UTC().Add(time.Minute)
	source := &CertificateExecution{InstallationID: "ins_00000000000000000000000000000001", JobID: "job", Plan: plans.Plan{ID: "plan"}}
	execution := publicationExecutionFromCertificate(source, publication.Candidate{}, safety.State{}, ownership.Record{}, deadline)
	if execution.InstallationID != source.InstallationID || !execution.ActivationDeadline.Equal(deadline) || execution.JobID != "job" {
		t.Fatalf("handoff lost runtime authority: %+v", execution)
	}
}

func TestInterruptedDomainActivationContractionWinsWithFreshGeneration(t *testing.T) {
	item := safety.ResourceSafety{ResourceID: "res_one", GenerationSequence: 7, Reactivating: &safety.Reactivating{PlanID: "plan_one", Generation: 7}}
	intent := domain.ActivationIntent{PlanID: "plan_one", Generation: 7}
	next, generation, changed, err := interruptDomainSafety(item, intent)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || generation != 8 || next.Reactivating != nil || next.Closing == nil || next.Closing.Generation != 8 || next.Closing.Reason != "interrupted_domain_activation" {
		t.Fatalf("unexpected contraction marker: %#v", next)
	}
}
func TestInterruptedDomainActivationRejectsStaleAuthority(t *testing.T) {
	item := safety.ResourceSafety{GenerationSequence: 7, Reactivating: &safety.Reactivating{PlanID: "plan_old", Generation: 7}}
	if _, _, _, err := interruptDomainSafety(item, domain.ActivationIntent{PlanID: "plan_new", Generation: 7}); err == nil {
		t.Fatal("stale reactivating authority accepted")
	}
}
func TestInterruptedDomainClosingResumesWithoutGenerationReuse(t *testing.T) {
	item := safety.ResourceSafety{GenerationSequence: 8, Closing: &safety.GenerationMarker{Kind: safety.MarkerClosing, Generation: 8, Reason: "interrupted_domain_activation"}}
	next, generation, changed, err := interruptDomainSafety(item, domain.ActivationIntent{})
	if err != nil {
		t.Fatal(err)
	}
	if changed || generation != 8 || next.Closing == nil {
		t.Fatalf("closing was not resumed: %#v", next)
	}
}
func TestStickyUnpublishedDomainRecoveryDoesNotReopen(t *testing.T) {
	item := safety.ResourceSafety{GenerationSequence: 8, StickyUnpublished: &safety.GenerationMarker{Kind: safety.MarkerStickyUnpublished, Generation: 8, Reason: "interrupted_domain_activation"}}
	if _, _, _, err := interruptDomainSafety(item, domain.ActivationIntent{}); err == nil {
		t.Fatal("sticky unpublished state reopened")
	}
}
