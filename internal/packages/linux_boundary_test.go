//go:build linux

package packages

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCompletedPackageTransactionFilesAreRemoved(t *testing.T) {
	root := t.TempDir()
	transactionRoot := filepath.Join(root, "transactions")
	stagingRoot := filepath.Join(root, "staging")
	for _, path := range []string{transactionRoot, stagingRoot} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	plan := testPlan(t, OfflineDebs)
	for _, path := range []string{filepath.Join(transactionRoot, plan.TransactionID), filepath.Join(stagingRoot, plan.TransactionID)} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "artifact"), []byte("data"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := newTestTransactionFiles(transactionRoot, stagingRoot).Cleanup(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(transactionRoot, plan.TransactionID), filepath.Join(stagingRoot, plan.TransactionID)} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("completed package path remains: %s: %v", path, err)
		}
	}
}

func TestUnitMasksPreservePreexistingAndRemoveOnlyCreatedMasks(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", filepath.Join(directory, "existing.service")); err != nil {
		t.Fatal(err)
	}
	masks := newTestUnitMasks(directory)
	result, err := masks.Mask(context.Background(), []string{"created.service", "existing.service"}, func(MaskIdentity) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(createdMaskNames(result.Masks), ",") != "created.service" || result.Masks[1].Unit != "existing.service" || !result.Masks[1].Preexisting {
		t.Fatalf("mask result=%#v", result)
	}
	if err := masks.Unmask(context.Background(), createdMasks(result.Masks)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(directory, "created.service")); !os.IsNotExist(err) {
		t.Fatalf("created mask remains: %v", err)
	}
	if target, err := os.Readlink(filepath.Join(directory, "existing.service")); err != nil || target != "/dev/null" {
		t.Fatalf("preexisting mask changed: target=%q error=%v", target, err)
	}
}

func TestUnitMasksRefuseToRemoveReplacedMaskIdentity(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	masks := newTestUnitMasks(directory)
	result, err := masks.Mask(context.Background(), []string{"nginx.service"}, func(MaskIdentity) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "nginx.service")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	if err := os.Symlink("/dev/null", path); err != nil {
		t.Fatal(err)
	}
	if err := masks.Unmask(context.Background(), result.Masks); err == nil {
		t.Fatal("replaced package mask was removed using stale identity")
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("replacement mask was not preserved: %v", err)
	}
}

func TestUnitMasksCleanupIsIdempotentAfterExactRemoval(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	masks := newTestUnitMasks(directory)
	result, err := masks.Mask(context.Background(), []string{"nginx.service"}, func(MaskIdentity) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := masks.Unmask(context.Background(), result.Masks); err != nil {
		t.Fatal(err)
	}
	if err := masks.Unmask(context.Background(), result.Masks); err != nil {
		t.Fatalf("resume rejected already-cleaned exact mask: %v", err)
	}
}

func TestDistroArtifactStageReusesExactPersistedClosureOnResume(t *testing.T) {
	plan, stager, _, staged := distroStageFixture(t)
	before := map[string]os.FileInfo{}
	for _, pkg := range plan.Packages {
		path := filepath.Join(staged, pkg.ArtifactDigest+".deb")
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		before[path] = info
	}
	if err := stager.Stage(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	for path, original := range before {
		current, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(original, current) {
			t.Fatalf("exact staged distro artifact was replaced during recovery: %s", path)
		}
	}
}

func TestDistroArtifactStageRejectsChangedOrUnsafePersistedArtifact(t *testing.T) {
	tests := []struct {
		name   string
		change func(string, string, int64) error
	}{
		{name: "bytes", change: func(path, _ string, size int64) error {
			return os.WriteFile(path, []byte(strings.Repeat("x", int(size))), 0o600)
		}},
		{name: "mode", change: func(path, _ string, _ int64) error { return os.Chmod(path, 0o644) }},
		{name: "symlink", change: func(path, cache string, _ int64) error {
			if err := os.Remove(path); err != nil {
				return err
			}
			return os.Symlink(cache, path)
		}},
		{name: "hardlink", change: func(path, cache string, _ int64) error {
			return os.Link(path, filepath.Join(filepath.Dir(filepath.Dir(cache)), "staged-link"))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, stager, archives, staged := distroStageFixture(t)
			pkg := plan.Packages[0]
			path := filepath.Join(staged, pkg.ArtifactDigest+".deb")
			cache := filepath.Join(archives, pkg.Name+".deb")
			if err := test.change(path, cache, pkg.ArtifactBytes); err != nil {
				t.Fatal(err)
			}
			if err := stager.Stage(context.Background(), plan); err == nil {
				t.Fatal("changed or unsafe staged distro artifact was reused")
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("rejected staged artifact was speculatively removed: %v", err)
			}
		})
	}
}

func distroStageFixture(t *testing.T) (Plan, *ArtifactStager, string, string) {
	t.Helper()
	plan := testPlan(t, DistroRepository)
	payloads := [][]byte{[]byte("apache package"), []byte("nginx package")}
	for index, payload := range payloads {
		plan.Packages[index].ArtifactDigest = fmt.Sprintf("%x", sha256.Sum256(payload))
		plan.Packages[index].ArtifactBytes = int64(len(payload))
		plan.Packages[index].Source.Artifact.Digest = plan.Packages[index].ArtifactDigest
	}
	closure, err := ClosureDigest(plan.Packages)
	if err != nil {
		t.Fatal(err)
	}
	plan.Authority.FrozenClosureDigest = closure

	root := t.TempDir()
	transactions, staging := filepath.Join(root, "transactions"), filepath.Join(root, "staging")
	archives := filepath.Join(transactions, plan.TransactionID, "archives")
	staged := filepath.Join(staging, plan.TransactionID)
	for _, directory := range []string{transactions, staging, filepath.Dir(archives), archives, staged} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for index, pkg := range plan.Packages {
		for path, payload := range map[string][]byte{
			filepath.Join(archives, pkg.Name+".deb"):         payloads[index],
			filepath.Join(staged, pkg.ArtifactDigest+".deb"): payloads[index],
		} {
			if err := os.WriteFile(path, payload, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	stager := &ArtifactStager{Files: newTestTransactionFiles(transactions, staging), Launcher: &auditLauncher{}}
	return plan, stager, archives, staged
}

func TestTransactionFilesBindExactAPTConfigAndStagedClosure(t *testing.T) {
	plan := testPlan(t, OfflineDebs)
	payloads := [][]byte{[]byte("apache package"), []byte("nginx package")}
	for index, payload := range payloads {
		plan.Packages[index].ArtifactDigest = fmt.Sprintf("%x", sha256.Sum256(payload))
		plan.Packages[index].ArtifactBytes = int64(len(payload))
		plan.Packages[index].StagedIdentity = "sha256:" + plan.Packages[index].ArtifactDigest
		plan.Packages[index].Source.Artifact.Digest = plan.Packages[index].ArtifactDigest
		plan.Packages[index].Source.OfflinePath = "/var/lib/lanpanel/imports/" + plan.Packages[index].ArtifactDigest + ".deb"
	}
	closure, err := ClosureDigest(plan.Packages)
	if err != nil {
		t.Fatal(err)
	}
	plan.Authority.FrozenClosureDigest = closure
	root := t.TempDir()
	transactions, staging := filepath.Join(root, "transactions"), filepath.Join(root, "staging")
	for _, directory := range []string{transactions, staging, filepath.Join(staging, plan.TransactionID)} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for index, pkg := range plan.Packages {
		if err := os.WriteFile(filepath.Join(staging, plan.TransactionID, pkg.ArtifactDigest+".deb"), payloads[index], 0o600); err != nil {
			t.Fatal(err)
		}
	}
	files := newTestTransactionFiles(transactions, staging)
	config, sourceList, err := RenderAPTConfiguration(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := files.Prepare(context.Background(), plan, config, sourceList); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(transactions, plan.TransactionID, "unexpected"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := files.Prepare(context.Background(), plan, config, sourceList); err == nil {
		t.Fatal("unexpected package transaction file was accepted")
	}
}

func TestLinuxMonitorCancelsOnUnitOrListenerBypass(t *testing.T) {
	root := t.TempDir()
	cgroups := filepath.Join(root, "cgroups")
	proc := filepath.Join(root, "proc")
	if err := os.MkdirAll(filepath.Join(cgroups, "nginx.service"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(proc, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cgroups, "nginx.service", "cgroup.procs"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6"} {
		if err := os.WriteFile(filepath.Join(proc, name), []byte("  sl  local_address rem_address st\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	monitor := newTestLinuxMonitor(cgroups, proc, time.Millisecond)
	monitored, stop, err := monitor.Start(context.Background(), []string{"nginx.service"}, []string{"tcp/443"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cgroups, "nginx.service", "cgroup.procs"), []byte("123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-monitored.Done():
	case <-time.After(time.Second):
		t.Fatal("unit bypass did not cancel package child context")
	}
	if err := stop(); err == nil {
		t.Fatal("unit bypass monitor returned success")
	}
}
