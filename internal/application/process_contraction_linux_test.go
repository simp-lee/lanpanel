//go:build linux

package application

import (
	"encoding/json"
	"errors"
	"lanpanel/internal/domain"
	"lanpanel/internal/persist"
	managedprocess "lanpanel/internal/process"
	"testing"
)

func TestStaleProcessViolationCannotAuthorizeReplacementContraction(t *testing.T) {
	resource := recoveryLocalResource(t)
	resource.ManagedProcess.Requested = domain.ProcessRequestedRunning
	cause := bindProcessRuntimeViolation(resource, managedprocess.NewRuntimeViolation(managedprocess.RuntimeViolationPolicyInvalid, errors.New("old probe")))
	var violation *processRuntimeViolation
	if !errors.As(cause, &violation) {
		t.Fatal("probe did not bind the applied process bundle")
	}
	// Model a stop/update/start completed after the publication probe read A.
	replacement := *resource.ManagedProcess.Applied
	replacement.Generation++
	replacement.PolicyDigest = deployTestDigest("replacement-policy")
	resource.ManagedProcess.Applied = &replacement
	raw, err := persist.EncodeEntry(recoveryResourceInstallation(&resource))
	if err != nil {
		t.Fatal(err)
	}
	document := persist.Document{Entries: map[string]json.RawMessage{"installations/current": raw}}
	for _, check := range []func() error{
		func() error { _, err := boundProcessViolationResource(document, *violation); return err },
		func() error { _, err := exactProcessViolationResource(document, *violation); return err },
	} {
		if err := check(); !errors.Is(err, errProcessViolationObsolete) || !obsoleteProcessViolation(err) {
			t.Fatalf("stale bundle authorized contraction instead of being obsolete: %v", err)
		}
	}
	fresh := *violation
	fresh.Bundle = replacement
	if _, err := exactProcessViolationResource(document, fresh); err != nil {
		t.Fatalf("matching replacement probe was rejected: %v", err)
	}
}
