//go:build linux

package control

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestActivationAuthorityFailurePrecedesPhysicalWork(t *testing.T) {
	rendered := testRendered(t)
	certificate := testCertificateIdentity(IssueRequest{JobID: "job_control", PlanID: "plan_control", IntentGeneration: 1, CertificateID: rendered.Candidate.CertificateID, BindingDigest: rendered.Candidate.CertificateBinding, Domain: rendered.Candidate.ControlDomain})
	bundle, err := BuildActivation("ins_00000000000000000000000000000001", rendered.Candidate, certificate)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	marker := filepath.Join(root, "unchanged")
	if err := os.WriteFile(marker, []byte("authority-bound"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := (&ActivationHost{}).Activate(context.Background(), bundle, ActivationAuthority{})
	if err == nil || !strings.Contains(err.Error(), "headscale activation runtime authority invalid") {
		t.Fatalf("invalid authority did not fail before host access: result=%+v err=%v", result, err)
	}
	data, readErr := os.ReadFile(marker)
	if readErr != nil || string(data) != "authority-bound" {
		t.Fatalf("authority failure changed physical state: %q %v", data, readErr)
	}
	entries, readDirErr := os.ReadDir(root)
	if readDirErr != nil || len(entries) != 1 {
		t.Fatalf("authority failure created physical output: entries=%v err=%v", entries, readDirErr)
	}
}

func TestActivationRollbackReloadDependsOnEntryRemovalAndNginxTest(t *testing.T) {
	removeFailure := errors.New("remove failed")
	testFailure := errors.New("test failed")
	for _, test := range []struct {
		name       string
		removeErr  error
		testErr    error
		wantCalls  []string
		wantErrors []error
	}{
		{name: "success", wantCalls: []string{"stop", "remove", "test", "reload", "restore"}},
		{name: "remove failure", removeErr: removeFailure, wantCalls: []string{"stop", "remove", "test", "restore"}, wantErrors: []error{removeFailure}},
		{name: "test failure", testErr: testFailure, wantCalls: []string{"stop", "remove", "test", "restore"}, wantErrors: []error{testFailure}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls []string
			record := func(name string, result error) func() error {
				return func() error {
					calls = append(calls, name)
					return result
				}
			}
			err := runActivationRollback(true, true, activationRollbackActions{
				stopSockets:    record("stop", nil),
				removeEntry:    record("remove", test.removeErr),
				testNginx:      record("test", test.testErr),
				reloadNginx:    record("reload", nil),
				restorePointer: record("restore", nil),
			})
			if !reflect.DeepEqual(calls, test.wantCalls) {
				t.Fatalf("rollback calls=%v want=%v", calls, test.wantCalls)
			}
			if len(test.wantErrors) == 0 && err != nil {
				t.Fatalf("successful rollback failed: %v", err)
			}
			for _, wanted := range test.wantErrors {
				if !errors.Is(err, wanted) {
					t.Fatalf("rollback error %v does not contain %v", err, wanted)
				}
			}
		})
	}
}
