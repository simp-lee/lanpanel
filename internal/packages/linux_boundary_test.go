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
