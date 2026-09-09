//go:build linux

package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"lanpanel/internal/certificates"
	"lanpanel/internal/control"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/locks"
	"lanpanel/internal/safety"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type emptySafetyOwnership struct{}

func (emptySafetyOwnership) InventoryAuthority() (map[string]string, bool, error) {
	return map[string]string{}, true, nil
}

func headscaleExpiryTestAuthority(t *testing.T) (domain.Installation, control.Journal) {
	t.Helper()
	now := time.Unix(1_700_000_000, 123_456_789).UTC()
	identity := &certificates.Identity{ID: "cert_00000000000000000000000000000001", Generation: 2, Fingerprint: applicationTestDigest("certificate"), BindingIdentity: applicationTestDigest("binding"), SANIdentity: applicationTestDigest("san"), ChainIdentity: applicationTestDigest("chain"), IssuerIdentity: applicationTestDigest("issuer"), NotAfter: now.Add(time.Hour), LastTrustedWall: now}
	artifact := domain.HeadscaleArtifactIdentity{ExecutableDigest: applicationTestDigest("executable"), ConfigContract: control.ConfigContract}
	candidate := control.Candidate{SchemaVersion: control.CandidateSchema, HeadscaleID: "headscale_00000000000000000000000000000001", DatabaseUUID: "database-uuid", DatabaseGeneration: 1, Generation: 2, ControlDomain: "control.example.test", MagicDNSNamespace: "example.test", Artifact: artifact, ConfigDigest: applicationTestDigest("config"), PolicyDigest: applicationTestDigest("policy"), UnitDigest: applicationTestDigest("unit"), ServiceIdentity: applicationTestDigest("service"), ControlIdentity: applicationTestDigest("control"), CertificateID: identity.ID, CertificateBinding: applicationTestDigest("initial-binding"), Paths: control.FixedPaths(), ControlBackend: control.ControlBackend, AdminBackend: control.AdminBackend, MetricsBackend: control.MetricsBackend, STUNBackend: control.STUNBackend}
	applied, err := control.AppliedIdentity(candidate)
	if err != nil {
		t.Fatal(err)
	}
	headscale := &domain.HeadscaleDomain{ID: candidate.HeadscaleID, ControlDomain: candidate.ControlDomain, MagicDNSNamespace: candidate.MagicDNSNamespace, Artifact: artifact, Database: domain.HeadscaleDatabaseIdentity{UUID: candidate.DatabaseUUID, Generation: candidate.DatabaseGeneration}, Applied: &applied, Certificate: &domain.CertificateBundleIdentity{Generation: identity.Generation, Fingerprint: identity.Fingerprint, BindingIdentity: identity.BindingIdentity, SANIdentity: identity.SANIdentity, ChainIdentity: identity.ChainIdentity, IssuerIdentity: identity.IssuerIdentity, DirectoryIdentity: identity.DirectoryIdentity, NotAfter: identity.NotAfter.Format(time.RFC3339), LastTrustedWall: identity.LastTrustedWall.Format(time.RFC3339), Authority: &domain.CertificateAuthorityIdentity{CertificateID: identity.ID}}}
	installation := domain.Installation{InstallationID: "installation-current", Headscale: headscale}
	journal := control.Journal{InstallationID: installation.InstallationID, Candidate: candidate, Certificate: identity}
	return installation, journal
}

func TestHeadscaleExpiryJournalMatchesCommittedNormalCertificate(t *testing.T) {
	installation, journal := headscaleExpiryTestAuthority(t)
	if !headscaleExpiryJournalMatchesNormal(installation, journal) {
		t.Fatal("exact Headscale control and normal certificate authority did not match")
	}
	journal.Candidate.ControlIdentity = applicationTestDigest("other")
	if headscaleExpiryJournalMatchesNormal(installation, journal) {
		t.Fatal("mismatched Headscale applied control identity matched normal certificate")
	}
}

func TestHeadscaleCertificateContractionFenceCommitsEmergencyAuthorityFirst(t *testing.T) {
	ctx := context.Background()
	owner := filetxn.Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	lockRoot := t.TempDir()
	if err := os.Chmod(lockRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	manager, err := locks.Open(locks.Config{RootPath: lockRoot, Owner: owner.UID, Group: owner.GID, Mode: 0o700})
	if err != nil {
		t.Fatal(err)
	}
	defer func(ignore func() error) { _ = ignore() }(manager.Close)
	lease, err := manager.Acquire(ctx, locks.Exposure)
	if err != nil {
		t.Fatal(err)
	}
	defer func(ignore func() error) { _ = ignore() }(lease.Release)

	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(root, "staging")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	emergency, err := safety.CreateEmergency(filepath.Join(root, "emergency.slots"), owner, safety.EmergencyOptions{LockAuthority: manager.Authority()})
	if err != nil {
		t.Fatal(err)
	}
	defer func(ignore func() error) { _ = ignore() }(emergency.Close)
	store, err := safety.OpenStore(safety.StoreConfig{RootPath: root, StagingPath: staging, StatePath: filepath.Join(root, "state.json"), Owner: owner, Emergency: emergency, LockAuthority: manager.Authority(), Ownership: emptySafetyOwnership{}})
	if err != nil {
		t.Fatal(err)
	}
	defer func(ignore func() error) { _ = ignore() }(store.Close)
	if _, err := store.Initialize(ctx, lease); err != nil {
		t.Fatal(err)
	}
	current, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	binding := applicationTestDigest("binding")
	config := applicationTestDigest("config")
	base := headscaleBaseSnapshot(current.Headscale)
	pending := &safety.ChallengePending{Generation: 1, PlanID: "plan_headscale", Method: "http-01", ConfigDigest: config, SANIdentity: applicationTestDigest("san"), ACMEBinding: binding, CertificateIdentity: "cert_00000000000000000000000000000001", Host: "control.example.test", Hosts: []string{"control.example.test"}, Webroot: "/var/lib/lanpanel/certificates/webroot/cert_00000000000000000000000000000001", BootstrapIdentity: applicationTestDigest("bootstrap"), BaseMarkers: base}
	challenged := current
	challenged.Revision++
	challenged.Headscale.GenerationSequence = 1
	challenged.Headscale.ChallengePending = pending
	if _, err := store.Commit(ctx, lease, safety.RoleChallenge, current.Revision, challenged, safety.TransitionProof{}); err != nil {
		t.Fatal(err)
	}
	reactivating := &safety.HeadscaleReactivating{Generation: 1, PriorGeneration: 0, PlanID: pending.PlanID, ControlGeneration: 1, CertificateGeneration: 1, CertificateFingerprint: applicationTestDigest("certificate"), CandidateDigest: config, CandidateBundle: applicationTestDigest("bundle"), BaseMarkers: base, CertificateUntil: now.Add(time.Hour), CertificateLastTrustedWall: now}
	handoff := challenged
	handoff.Revision++
	handoff.Headscale.ChallengePending = nil
	handoff.Headscale.Reactivating = reactivating
	if _, err := store.Commit(ctx, lease, safety.RoleCertificateHandoff, challenged.Revision, handoff, safety.TransitionProof{}); err != nil {
		t.Fatal(err)
	}
	active := handoff
	active.Revision++
	active.Headscale.ControlEntryDigest = applicationTestDigest("control-entry")
	active.Headscale.ActiveCertificate = &safety.ActiveCertificateAuthority{Generation: 1, Fingerprint: reactivating.CertificateFingerprint, Binding: binding, LastTrustedWall: now, NotAfter: now.Add(time.Hour)}
	active.Headscale.Reactivating = nil
	proof := safety.HeadscaleConvergenceProof{PlanID: reactivating.PlanID, Generation: reactivating.Generation, ControlGeneration: reactivating.ControlGeneration, CertificateGeneration: reactivating.CertificateGeneration, CertificateFingerprint: reactivating.CertificateFingerprint, CandidateDigest: reactivating.CandidateDigest, CandidateBundle: reactivating.CandidateBundle, RuntimeClosureDigest: applicationTestDigest("runtime")}
	if _, err := store.Commit(ctx, lease, safety.RolePublish, handoff.Revision, active, safety.TransitionProof{Headscale: &proof}); err != nil {
		t.Fatal(err)
	}
	expired := active
	expired.Revision++
	expired.Headscale.GenerationSequence = 2
	expired.Headscale.CertificateExpiry = &safety.DeadlineMarker{Generation: 2, Deadline: now.Add(-time.Minute), Binding: binding}
	if _, err := store.Commit(ctx, lease, safety.RoleCertificateActivation, active.Revision, expired, safety.TransitionProof{}); err != nil {
		t.Fatal(err)
	}

	graph := applicationTestDigest("control-graph")
	observed := safety.StopObservation{ObservedAt: time.Now().UTC()}
	if err := commitHeadscaleCertificateContractionFence(ctx, lease, emergency, store, graph, observed, true); err != nil {
		t.Fatal(err)
	}
	persisted, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := emergency.Authority()
	if err != nil {
		t.Fatal(err)
	}
	if persisted.StopFence == nil || authority.StopFence == nil || persisted.StopFence.Kind != safety.StopFenceContraction || !safety.FenceMatchesEmergency(persisted.StopFence, *authority.StopFence) {
		t.Fatal("normal and emergency Headscale contraction fences did not converge")
	}

	stopped := safety.StopObservation{MasterStopped: true, WorkersStopped: true, ListenersStopped: true, ObservedAt: time.Now().UTC().Add(time.Second)}
	if err := updateHeadscaleCertificateContractionFence(ctx, lease, emergency, store, stopped, false); err != nil {
		t.Fatal(err)
	}
	persisted, err = store.Read()
	if err != nil {
		t.Fatal(err)
	}
	authority, err = emergency.Authority()
	if err != nil {
		t.Fatal(err)
	}
	if persisted.StopFence == nil || persisted.StopFence.AccessMayRemain || authority.StopFence == nil || authority.StopFence.AccessMayRemain || !safety.FenceMatchesEmergency(persisted.StopFence, *authority.StopFence) {
		t.Fatal("verified fallback stop observation was not durably projected")
	}
}

func applicationTestDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
