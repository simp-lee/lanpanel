//go:build linux

package closure

import (
	"context"
	"testing"
	"time"
)

type sequenceObserver struct {
	snapshots []RuntimeSnapshot
	index     int
}

func (value *sequenceObserver) Observe(context.Context) (RuntimeSnapshot, error) {
	result := value.snapshots[value.index]
	if value.index < len(value.snapshots)-1 {
		value.index++
	}
	return result, nil
}

func TestPriorWorkerDrainBindsPIDStartAndCgroup(t *testing.T) {
	prior := ProcessIdentity{PID: 44, StartTicks: 100, Cgroup: "/system.slice/lanpanel-nginx.service"}
	master := ProcessIdentity{PID: 12, StartTicks: 10, Cgroup: prior.Cgroup}
	observer := &sequenceObserver{snapshots: []RuntimeSnapshot{
		{ObservedAt: time.Now(), Complete: true, Master: &master, Workers: []ProcessIdentity{{PID: 44, StartTicks: 100, Cgroup: prior.Cgroup}}},
		{ObservedAt: time.Now(), Complete: true, Master: &master, Workers: []ProcessIdentity{{PID: 44, StartTicks: 101, Cgroup: prior.Cgroup}}},
	}}
	result, err := WaitPriorWorkers(context.Background(), observer, []ProcessIdentity{prior}, time.Second)
	if err != nil || len(result.Workers) != 1 || result.Workers[0].StartTicks != 101 {
		t.Fatalf("drain=%#v,%v", result, err)
	}
}

func TestStoppedRequiresCompleteEmptyRuntime(t *testing.T) {
	if err := VerifyStopped(RuntimeSnapshot{ObservedAt: time.Now(), Complete: true, Generation: "gen", Workers: []ProcessIdentity{}, Listeners: []ListenerIdentity{}}); err != nil {
		t.Fatal(err)
	}
	if err := VerifyStopped(RuntimeSnapshot{ObservedAt: time.Now(), Complete: true, Generation: "gen", Listeners: []ListenerIdentity{{Protocol: "tcp", Address: "0.0.0.0", Port: 443, Inode: 1}}}); err == nil {
		t.Fatal("owned listener accepted as stopped")
	}
}
