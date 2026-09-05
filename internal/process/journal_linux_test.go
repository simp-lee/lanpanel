//go:build linux

package process

import (
	"encoding/json"
	"lanpanel/internal/confinement"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/identity"
	"lanpanel/internal/resource"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReadProcessJournalRequiresCanonicalSafeFile(t *testing.T) {
	owner := filetxn.Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	resourceID := "res_00000000000000000000000000000001"
	value := Journal{
		SchemaVersion: processJournalSchema,
		JobID:         "job_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ResourceID:    resourceID,
		Operation:     "process_start",
		Phase:         "prepared",
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	newPath := func(data []byte) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), resourceID+".json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	if loaded, err := readProcessJournal(newPath(canonical), owner); err != nil || !reflect.DeepEqual(loaded, value) {
		t.Fatalf("canonical process journal rejected: loaded=%#v err=%v", loaded, err)
	}

	t.Run("fresh_relay_start", func(t *testing.T) {
		freshRelay := value
		freshRelay.RelayRequired = true
		data, err := json.Marshal(freshRelay)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := readProcessJournal(newPath(data), owner); err != nil {
			t.Fatalf("prepared first relay start was rejected: %v", err)
		}
	})

	t.Run("applied_bundle", func(t *testing.T) {
		app := domain.AppResource{ID: resourceID, CurrentConfigDigest: "sha256:" + strings.Repeat("a", 64), Target: domain.AppTarget{Kind: domain.AppTargetLocalHTTP, ReadinessPath: "/ready", AllowedHTTPStatuses: []uint16{200}, LocalHTTP: &domain.LocalHTTPTarget{EndpointKind: domain.LocalEndpointUnixSocketActivation}}, ManagedProcess: &domain.ManagedProcess{ID: "proc_00000000000000000000000000000001", Requested: domain.ProcessRequestedStopped, Service: domain.ManagedService{Executable: "/usr/local/bin/app", WorkingDirectory: "/srv/app", WritePaths: []string{}}}}
		accounts, err := identity.ResourceAccounts("ins_00000000000000000000000000000001", app.ID, false)
		if err != nil {
			t.Fatal(err)
		}
		accounts.Identities = []identity.AccountIdentity{{Role: accounts.Application.Role, User: accounts.Application.User, UID: 1200, Group: accounts.Application.Group, GID: 1200}}
		profile := confinement.Profile{SchemaVersion: confinement.SchemaVersion, KernelRelease: "6.12.1", CgroupMode: "unified_v2", BindListenPolicy: "systemd_bind_deny_bpf_lsm_listen_v1", ConnectPolicy: "systemd_cgroup_ip_deny_v1", FilesystemPolicy: "systemd_mount_namespace_v1", ProtectedDestinations: []string{"127.0.0.0/8"}, QualificationDigest: "sha256:" + strings.Repeat("b", 64)}
		evidence := resource.ReferenceEvidence{ExecutableDigest: "sha256:" + strings.Repeat("c", 64), WorkingDirectoryIdentity: "sha256:" + strings.Repeat("d", 64), WritePathIdentities: []string{}}
		units, err := Render("ins_00000000000000000000000000000001", app, accounts, profile, evidence, 33, map[string]struct{}{})
		if err != nil {
			t.Fatal(err)
		}
		applied := value
		applied.Phase = "activating"
		applied.BundleDigest = units.Bundle.PolicyDigest
		applied.Applied = &units.Bundle
		applied.Policy = units.Confinement
		applied.ApplicationUID = units.ApplicationUID
		applied.ApplicationGID = units.ApplicationGID
		data, err := json.Marshal(applied)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := readProcessJournal(newPath(data), owner); err != nil {
			t.Fatalf("valid applied process journal was rejected: %v", err)
		}

		reconfigured := applied
		reconfigured.Phase = "prepared"
		reconfigured.Policy = confinement.UnitPolicy{}
		reconfigured.RelayRequired = true
		data, err = json.Marshal(reconfigured)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := readProcessJournal(newPath(data), owner); err != nil {
			t.Fatalf("prepared start with a changed relay mode was rejected: %v", err)
		}

		foreign := applied
		foreign.ResourceID = "res_00000000000000000000000000000002"
		foreign.Operation = "process_stop"
		foreign.Phase = "prepared"
		foreign.Policy = confinement.UnitPolicy{}
		foreignPath := filepath.Join(t.TempDir(), foreign.ResourceID+".json")
		data, err = json.Marshal(foreign)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(foreignPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readProcessJournal(foreignPath, owner); err == nil {
			t.Fatal("process journal accepted another resource's applied bundle")
		}
	})

	t.Run("strict_schema", func(t *testing.T) {
		unknown := append(append([]byte(nil), canonical[:len(canonical)-1]...), []byte(`,"unknown":true}`)...)
		if _, err := readProcessJournal(newPath(unknown), owner); err == nil {
			t.Fatal("process journal with an unknown field was accepted")
		}
	})

	t.Run("canonical_encoding", func(t *testing.T) {
		withNewline := append(append([]byte(nil), canonical...), '\n')
		if _, err := readProcessJournal(newPath(withNewline), owner); err == nil {
			t.Fatal("noncanonical process journal was accepted")
		}
	})

	t.Run("semantic_validation", func(t *testing.T) {
		invalid := value
		invalid.Operation = "unsupported"
		data, err := json.Marshal(invalid)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := readProcessJournal(newPath(data), owner); err == nil {
			t.Fatal("process journal with an unsupported operation was accepted")
		}

		invalid = value
		invalid.Operation = "process_stop"
		invalid.Applied = &domain.ProcessBundle{}
		data, err = json.Marshal(invalid)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := readProcessJournal(newPath(data), owner); err == nil {
			t.Fatal("process journal with an invalid applied bundle was accepted")
		}
	})

	t.Run("mode", func(t *testing.T) {
		path := newPath(canonical)
		if err := os.Chmod(path, 0o640); err != nil {
			t.Fatal(err)
		}
		if _, err := readProcessJournal(path, owner); err == nil {
			t.Fatal("process journal with unsafe mode was accepted")
		}
	})

	t.Run("owner_and_group", func(t *testing.T) {
		path := newPath(canonical)
		wrong := filetxn.Owner{UID: owner.UID + 1, GID: owner.GID + 1}
		if _, err := readProcessJournal(path, wrong); err == nil {
			t.Fatal("process journal with unexpected owner and group was accepted")
		}
	})

	t.Run("hard_link", func(t *testing.T) {
		source := newPath(canonical)
		path := filepath.Join(t.TempDir(), resourceID+".json")
		if err := os.Link(source, path); err != nil {
			t.Fatal(err)
		}
		if _, err := readProcessJournal(path, owner); err == nil {
			t.Fatal("hard-linked process journal was accepted")
		}
	})

	t.Run("symbolic_link", func(t *testing.T) {
		target := newPath(canonical)
		path := filepath.Join(t.TempDir(), resourceID+".json")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := readProcessJournal(path, owner); err == nil {
			t.Fatal("symbolic-link process journal was accepted")
		}
	})

	t.Run("fifo", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), resourceID+".json")
		if err := unix.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readProcessJournal(path, owner); err == nil {
			t.Fatal("FIFO process journal was accepted")
		}
	})

	t.Run("resource_path_binding", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "res_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.json")
		if err := os.WriteFile(path, canonical, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readProcessJournal(path, owner); err == nil {
			t.Fatal("process journal stored under another resource name was accepted")
		}
	})
}
