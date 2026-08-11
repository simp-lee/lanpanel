package jobs

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

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

	t.Run("entropy_failure_prevents_job_creation", func(t *testing.T) {
		if _, err := NewReserved(Spec{Operation: "publish", Target: "resource/app", ActorIdentity: "session"}, time.Now(), errorReader{}); err == nil {
			t.Fatal("job ID entropy failure was ignored")
		}
	})
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }
