//go:build linux

package application

import (
	"context"
	"errors"
	"lanpanel/internal/domain"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/operations"
	"lanpanel/internal/persist"
	managedprocess "lanpanel/internal/process"
	"testing"
	"time"
)

func TestPendingProcessRecoveryRequiresMatchingPersistedAuthority(t *testing.T) {
	for _, start := range []bool{true, false} {
		name := "stop"
		if start {
			name = "start"
		}
		t.Run(name, func(t *testing.T) {
			testPendingProcessRecoveryAuthority(t, start)
		})
	}
}

func testPendingProcessRecoveryAuthority(t *testing.T, start bool) {
	t.Helper()
	app := recoveryLocalResource(t)
	candidateBundle := cloneBundleForProcess(app.ManagedProcess.Applied)
	app.ManagedProcess.Applied = nil
	app.ManagedProcess.LastOperation = ""
	app.ManagedProcess.LastOperationResult = ""
	app.ManagedProcess.LastJobID = ""
	fixture := newResourceRecoveryFixture(t, recoveryResourceInstallation(&app))
	service := fixture.open(t)
	defer func() { _ = service.Close() }()
	setupSet, setupMutation, setupExposure := fixture.acquire(t, service, "resource/"+app.ID)
	writeRecoveryOwnershipAndSafety(t, service, setupExposure, app.ID)
	if err := errors.Join(operations.ReleaseExposure(setupMutation, setupExposure), setupSet.Close()); err != nil {
		t.Fatal(err)
	}
	admitter, err := service.resourceAdmitter()
	if err != nil {
		t.Fatal(err)
	}
	document, err := service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	admission, err := service.manager.Acquire(context.Background(), locks.MutationAdmission)
	if err != nil {
		t.Fatal(err)
	}
	job, err := admitter.Admit(context.Background(), admission, operations.AdmitRequest{Operation: operations.ProcessStart, Target: "resource/" + app.ID, ActorIdentity: "ui/session/generation/1", Source: operations.AdmissionUI, SafetyBinding: operations.SafetyBinding{ResourceID: app.ID}, ExpectedRevision: document.Revision})
	releaseErr := admission.Release()
	if err != nil || releaseErr != nil {
		t.Fatal(errors.Join(err, releaseErr))
	}
	set, mutation, exposure := fixture.acquire(t, service, "resource/"+app.ID)
	defer func() { _ = errors.Join(operations.ReleaseExposure(mutation, exposure), set.Close()) }()
	document, err = service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	intent, err := admitter.BeginUI(context.Background(), mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: document.Revision, IntentGeneration: document.Revision + 1})
	if err != nil {
		t.Fatal(err)
	}
	document, err = service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}

	operationName := "process_start"
	journalApplied := (*domain.ProcessBundle)(nil)
	if !start {
		operationName = "process_stop"
		journalApplied = cloneBundleForProcess(candidateBundle)
		intent.Operation = operations.ProcessStop
		intentRaw, err := persist.EncodeEntry(intent)
		if err != nil {
			t.Fatal(err)
		}
		document.Entries["intents/"+job.ID] = intentRaw
		runningJob, err := jobs.LoadEntries(document.Entries, job.ID)
		if err != nil {
			t.Fatal(err)
		}
		runningJob.Operation = operationName
		jobRaw, err := persist.EncodeEntry(runningJob)
		if err != nil {
			t.Fatal(err)
		}
		document.Entries["jobs/"+job.ID] = jobRaw
		installation, err := installationFromDocument(document)
		if err != nil {
			t.Fatal(err)
		}
		managed := findNormalResource(installation, app.ID).ManagedProcess
		managed.Requested = domain.ProcessRequestedRunning
		managed.Applied = cloneBundleForProcess(candidateBundle)
		managed.RuntimeObservation = &domain.RuntimeObservation{Status: domain.RuntimeHealthy, ObservedAt: time.Unix(1_700_000_000, 0).UTC().Format(time.RFC3339), Reason: "running"}
		managed.LastOperation = domain.OperationProcessStart
		managed.LastOperationResult = domain.OperationSucceeded
		managed.LastJobID = "job_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		installationRaw, err := persist.EncodeEntry(installation)
		if err != nil {
			t.Fatal(err)
		}
		document.Entries["installations/current"] = installationRaw
	}

	journal := managedprocess.Journal{SchemaVersion: "lanpanel.process.lifecycle.v1", JobID: job.ID, ResourceID: app.ID, Operation: operationName, Phase: "prepared", Applied: journalApplied}
	if err := validatePendingProcessRecovery(document, journal); err != nil {
		t.Fatalf("matching pre-commit process authority was rejected: %v", err)
	}
	mismatched := journal
	if start {
		mismatched.Operation = "process_stop"
	} else {
		mismatched.Operation = "process_start"
	}
	if err := validatePendingProcessRecovery(document, mismatched); err == nil {
		t.Fatal("mismatched pending process operation was accepted")
	}

	installation, err := installationFromDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	managed := findNormalResource(installation, app.ID).ManagedProcess
	journal.Phase = "host_mutated"
	if start {
		journal.Applied = cloneBundleForProcess(candidateBundle)
		managed.Requested = domain.ProcessRequestedRunning
		managed.Applied = cloneBundleForProcess(candidateBundle)
		managed.RuntimeObservation = &domain.RuntimeObservation{Status: domain.RuntimeHealthy, ObservedAt: time.Unix(1_700_000_001, 0).UTC().Format(time.RFC3339), Reason: "running"}
		managed.LastOperation = domain.OperationProcessStart
	} else {
		managed.Requested = domain.ProcessRequestedStopped
		managed.RuntimeObservation = &domain.RuntimeObservation{Status: domain.RuntimeDegraded, ObservedAt: time.Unix(1_700_000_001, 0).UTC().Format(time.RFC3339), Reason: "stopped"}
		managed.LastOperation = domain.OperationProcessStop
	}
	managed.LastJobID = job.ID
	raw, err := persist.EncodeEntry(installation)
	if err != nil {
		t.Fatal(err)
	}
	document.Entries["installations/current"] = raw
	if err := validatePendingProcessRecovery(document, journal); err != nil {
		t.Fatalf("matching post-state/pre-terminal process authority was rejected: %v", err)
	}
	managed.RuntimeObservation.Reason = "unrelated"
	raw, err = persist.EncodeEntry(installation)
	if err != nil {
		t.Fatal(err)
	}
	document.Entries["installations/current"] = raw
	if err := validatePendingProcessRecovery(document, journal); err == nil {
		t.Fatal("mismatched post-state process observation was accepted")
	}
}
