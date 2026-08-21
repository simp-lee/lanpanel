package contraction

import (
	"context"
	"errors"
	"lanpanel/internal/closure"
	"strings"
	"testing"
	"time"
)

type traceAuthority struct {
	steps     []string
	fail      string
	committed bool
}

func (value *traceAuthority) PersistClosing(context.Context, closure.Inventory) error {
	return value.step("closing")
}

func (value *traceAuthority) CommitUnpublished(context.Context, closure.Inventory) error {
	return value.step("unpublished")
}

func (value *traceAuthority) PersistStopFence(context.Context, closure.Inventory) error {
	return value.step("fence")
}

func (value *traceAuthority) UpdateStopObservation(context.Context, closure.RuntimeSnapshot, bool) error {
	return value.step("stop_observation")
}

func (value *traceAuthority) FinalizeClosure(context.Context, closure.Inventory, string) error {
	return value.step("finalize")
}

func (value *traceAuthority) step(step string) error {
	value.steps = append(value.steps, step)
	if value.fail == step {
		if value.committed {
			return authorityCommittedError{err: errors.New(step)}
		}
		return errors.New(step)
	}
	return nil
}

type traceRuntime struct {
	steps   []string
	fail    string
	stopped bool
}

func (value *traceRuntime) ContractDisk(context.Context, closure.Inventory) ([]string, error) {
	value.steps = append(value.steps, "disk")
	if value.fail == "disk" {
		return nil, errors.New("disk")
	}
	return []string{"/etc/lanpanel/nginx/apps-enabled/app.conf"}, nil
}

func (value *traceRuntime) TestClosedGraph(context.Context) error {
	value.steps = append(value.steps, "test")
	if value.fail == "test" {
		return errors.New("test")
	}
	return nil
}

func (value *traceRuntime) ReloadAndDrain(context.Context) error {
	value.steps = append(value.steps, "reload_drain")
	if value.fail == "reload_drain" {
		return errors.New("drain")
	}
	return nil
}

func (value *traceRuntime) ProbeSelectiveClosure(context.Context, closure.Inventory) (string, error) {
	value.steps = append(value.steps, "probe")
	if value.fail == "probe" {
		return "", errors.New("probe")
	}
	return testDigest("closure"), nil
}

func (value *traceRuntime) Stop(context.Context) error {
	value.steps = append(value.steps, "stop")
	if value.fail == "stop" {
		return errors.New("stop")
	}
	value.stopped = true
	return nil
}

func (value *traceRuntime) Observe(context.Context) (closure.RuntimeSnapshot, error) {
	value.steps = append(value.steps, "observe")
	if value.fail == "observe" {
		return closure.RuntimeSnapshot{}, errors.New("observe")
	}
	snapshot := closure.RuntimeSnapshot{ObservedAt: time.Now(), Complete: true, Generation: "gen", Workers: []closure.ProcessIdentity{}, Listeners: []closure.ListenerIdentity{}}
	if !value.stopped {
		snapshot.Master = &closure.ProcessIdentity{PID: 2}
	}
	return snapshot, nil
}

func TestContractionOrdersAuthorityBeforeRuntimeAndClassifiesBranches(t *testing.T) {
	inventory := closure.Inventory{Complete: true, Digest: testDigest("inventory"), Identities: []closure.Identity{{ResourceID: "app-one", Kind: closure.IdentityResourceScope, Value: "app-one", Digest: testDigest("resource")}}}
	authority, runtime := &traceAuthority{}, &traceRuntime{}
	result, err := (Engine{Authority: authority, Runtime: runtime}).Run(context.Background(), inventory)
	if err != nil || result.Outcome != OutcomeSucceeded || !result.AccessClosed || strings.Join(authority.steps, ",") != "closing,unpublished,finalize" || strings.Join(runtime.steps, ",") != "disk,test,reload_drain,probe" {
		t.Fatalf("result=%#v authority=%v runtime=%v err=%v", result, authority.steps, runtime.steps, err)
	}

	authority, runtime = &traceAuthority{}, &traceRuntime{fail: "reload_drain"}
	result, err = (Engine{Authority: authority, Runtime: runtime}).Run(context.Background(), inventory)
	if result.Outcome != OutcomePartial || !result.AccessClosed || !result.SharedIngressDown || result.AccessMayRemain || strings.Join(authority.steps, ",") != "closing,unpublished,fence,stop_observation,finalize" || strings.Join(runtime.steps, ",") != "disk,test,reload_drain,stop,observe" {
		t.Fatalf("fallback result=%#v authority=%v runtime=%v err=%v", result, authority.steps, runtime.steps, err)
	}

	authority, runtime = &traceAuthority{}, &traceRuntime{fail: "stop"}
	result, _ = (Engine{Authority: authority, Runtime: runtime}).Run(context.Background(), closure.Inventory{Complete: false, Digest: testDigest("uncertain")})
	if result.Outcome != OutcomeUnknown || !result.AccessMayRemain || result.AccessClosed {
		t.Fatalf("unknown result=%#v", result)
	}

	authority, runtime = &traceAuthority{fail: "closing", committed: true}, &traceRuntime{}
	result, err = (Engine{Authority: authority, Runtime: runtime}).Run(context.Background(), inventory)
	if err == nil || result.Outcome != OutcomePartial || strings.Join(runtime.steps, ",") != "stop,observe" {
		t.Fatalf("committed marker failure result=%#v authority=%v runtime=%v err=%v", result, authority.steps, runtime.steps, err)
	}

	authority, runtime = &traceAuthority{fail: "fence"}, &traceRuntime{}
	result, err = (Engine{Authority: authority, Runtime: runtime}).Run(context.Background(), closure.Inventory{Complete: false, Digest: testDigest("uncertain")})
	if err == nil || result.Outcome != OutcomeUnknown || strings.Join(runtime.steps, ",") != "stop,observe" {
		t.Fatalf("fence failure skipped stop: result=%#v authority=%v runtime=%v err=%v", result, authority.steps, runtime.steps, err)
	}
}

func testDigest(seed string) string {
	return "sha256:" + strings.Repeat(string("abcdef0123456789"[len(seed)%16]), 64)
}
