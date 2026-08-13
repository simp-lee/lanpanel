package jobs

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSecretResultRejectsReplayableContent(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	record, _ := NewReserved(Spec{Operation: "admin_token_rotate", Target: "installation", ActorIdentity: "session"}, now, bytes.NewReader(make([]byte, 32)))
	record, _ = Start(record)
	record, err := Finish(record, Completion{Result: ResultSucceeded, Postconditions: []Postcondition{{Kind: "admin_token_source", Status: PostconditionVerified, Identity: "sha256:" + strings.Repeat("a", 64)}}, SecretResult: &SecretResult{Kind: "admin_token", ObjectID: "installation", Fingerprint: "plaintext-secret", DeliveryAttempted: true, Remedy: "read_protected_source"}}, now)
	if err == nil || record.ID != "" {
		t.Fatal("replayable secret result accepted")
	}
}

func TestDurableJobResultContract(t *testing.T) {
	t.Run("terminal_results_are_closed_and_noninterchangeable", func(t *testing.T) {
		now := time.Unix(1700000000, 0).UTC()
		record, err := NewReserved(Spec{Operation: "publish", Target: "resource/app-one", ActorIdentity: "session-one"}, now, bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
		if err != nil {
			t.Fatal(err)
		}
		record, err = Start(record)
		if err != nil {
			t.Fatal(err)
		}
		partial := Completion{Result: ResultPartial, ModifiedPaths: []string{"/var/lib/lanpanel/site"}, Postconditions: []Postcondition{{Kind: "ingress_closed", Status: PostconditionKnown, Identity: "app-one"}}, ErrorCode: "activation_contracted"}
		finished, err := Finish(record, partial, now.Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if finished.Result != ResultPartial || finished.Status != StatusTerminal {
			t.Fatalf("Finish()=%#v", finished)
		}
		if _, err := Finish(finished, partial, now.Add(2*time.Second)); err == nil {
			t.Fatal("terminal job was rewritten")
		}
		unknown := partial
		unknown.Result = ResultUnknown
		if _, err := Finish(record, unknown, now.Add(time.Second)); err == nil {
			t.Fatal("unknown accepted known-residual evidence")
		}
		unknown.Postconditions[0].Status = PostconditionUnobserved
		if _, err := Finish(record, unknown, now.Add(time.Second)); err != nil {
			t.Fatalf("valid unknown rejected: %v", err)
		}
	})

	t.Run("terminal_evidence_is_bounded_and_error_codes_are_closed", func(t *testing.T) {
		now := time.Unix(1700000000, 0).UTC()
		record, err := NewReserved(Spec{Operation: "publish", Target: "resource/app-one", ActorIdentity: "session-one"}, now, bytes.NewReader(bytes.Repeat([]byte{2}, 32)))
		if err != nil {
			t.Fatal(err)
		}
		record, err = Start(record)
		if err != nil {
			t.Fatal(err)
		}
		completion := Completion{Result: ResultFailed, Postconditions: []Postcondition{{Kind: "mutation_not_started", Status: PostconditionVerified, Identity: "app-one"}}, ErrorCode: "sentinel_secret_value"}
		if _, err := Finish(record, completion, now.Add(time.Second)); err == nil {
			t.Fatal("arbitrary secret-shaped error text entered durable job history")
		}
		completion.ErrorCode = "activation_contracted"
		for index := 0; index <= MaximumModifiedPaths; index++ {
			completion.ModifiedPaths = append(completion.ModifiedPaths, "/var/lib/lanpanel/path-"+string(rune('a'+index)))
		}
		if _, err := Finish(record, completion, now.Add(time.Second)); err == nil {
			t.Fatal("unbounded modified-path evidence entered durable job history")
		}
	})

	t.Run("interrupted_lifecycle_contraction_is_terminal", func(t *testing.T) {
		now := time.Unix(1700000000, 0).UTC()
		record, err := NewReserved(Spec{Operation: "process_start", Target: "resource/res_00000000000000000000000000000001", ActorIdentity: "ui/session/generation/1"}, now, bytes.NewReader(bytes.Repeat([]byte{3}, 32)))
		if err != nil {
			t.Fatal(err)
		}
		record, err = Start(record)
		if err != nil {
			t.Fatal(err)
		}
		record, err = Finish(record, Completion{Result: ResultInterrupted, Postconditions: []Postcondition{{Kind: "interrupted_lifecycle_contracted", Status: PostconditionKnown, Identity: record.ID}}, ErrorCode: "interrupted_lifecycle_contracted"}, now.Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if record.Status != StatusTerminal || record.Result != ResultInterrupted {
			t.Fatalf("record=%#v", record)
		}
	})

	t.Run("entropy_failure_prevents_job_creation", func(t *testing.T) {
		if _, err := NewReserved(Spec{Operation: "publish", Target: "resource/app", ActorIdentity: "session"}, time.Now(), errorReader{}); err == nil {
			t.Fatal("job ID entropy failure was ignored")
		}
	})
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }
