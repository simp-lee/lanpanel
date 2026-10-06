//go:build linux

package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"lanpanel/internal/acme"
	"lanpanel/internal/acmeaccount"
	"lanpanel/internal/activation"
	"lanpanel/internal/certificates"
	"lanpanel/internal/challenge"
	"lanpanel/internal/closure"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/nginx"
	"lanpanel/internal/operations"
	"lanpanel/internal/persist"
	"lanpanel/internal/safety"
	"testing"
	"time"
)

func TestManagementHTTPSDomainOwnerTracksActiveApplicationDomains(t *testing.T) {
	installation := domain.Installation{
		Resources: []domain.AppResource{{
			ID:                "res_app",
			Publication:       domain.AppPublication{DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "app.example.com", Aliases: []string{"www.app.example.com"}}},
			PublicationRecord: domain.PublicationRecord{State: domain.PublicationPublished},
		}},
	}
	if owner := managementHTTPSDomainOwner(installation, "www.app.example.com"); owner != "res_app" {
		t.Fatalf("active application alias owner = %q", owner)
	}
	installation.Resources[0].PublicationRecord.State = domain.PublicationUnpublished
	if owner := managementHTTPSDomainOwner(installation, "app.example.com"); owner != "res_app" {
		t.Fatalf("unpublished application owner = %q", owner)
	}
	installation.Resources[0].PublicationRecord.State = domain.PublicationActivating
	installation.Resources[0].Publication = domain.AppPublication{}
	installation.Resources[0].PublicationRecord.LastAppliedBundle = &domain.PublicationBundle{DomainHTTPS: &domain.DomainHTTPSBundleIdentity{ExactDomains: []string{"app.example.com"}}}
	if owner := managementHTTPSDomainOwner(installation, "app.example.com"); owner != "res_app" {
		t.Fatalf("activating application bundle owner = %q", owner)
	}
}

type managementHTTPSRecoveryFakeHost struct {
	runtime     closure.RuntimeSnapshot
	observeErr  error
	startErr    error
	reloadErr   error
	verifyErr   error
	stopErr     error
	startCalls  int
	reloadCalls int
	verifyCalls int
	stopCalls   int
}

func (host *managementHTTPSRecoveryFakeHost) RemoveChallenge(context.Context, challenge.Prepared, activation.ChallengeReloadAuthority) (activation.Result, error) {
	return activation.Result{}, nil
}

func (host *managementHTTPSRecoveryFakeHost) StopAndVerify(context.Context) (closure.RuntimeSnapshot, error) {
	host.stopCalls++
	return closure.RuntimeSnapshot{}, host.stopErr
}

func (host *managementHTTPSRecoveryFakeHost) ObserveRuntime(context.Context, nginx.Manifest) (closure.RuntimeSnapshot, error) {
	return host.runtime, host.observeErr
}

func (host *managementHTTPSRecoveryFakeHost) StartCertificate(context.Context, activation.ReloadAuthority) (closure.RuntimeSnapshot, error) {
	host.startCalls++
	return host.runtime, host.startErr
}

func (host *managementHTTPSRecoveryFakeHost) ReloadCertificate(context.Context, activation.ReloadAuthority) (closure.RuntimeSnapshot, error) {
	host.reloadCalls++
	return host.runtime, host.reloadErr
}

func (host *managementHTTPSRecoveryFakeHost) VerifyServedCertificate(context.Context, string, string) error {
	host.verifyCalls++
	return host.verifyErr
}

func (host *managementHTTPSRecoveryFakeHost) RestoreCertificate(context.Context, certificates.Pointer, string, string, string, activation.ReloadAuthority) error {
	return nil
}

func (host *managementHTTPSRecoveryFakeHost) ContractManagement(context.Context, nginx.Entry, activation.ReloadAuthority, bool) (activation.Result, error) {
	return activation.Result{}, nil
}

func TestManagementHTTPSReloadOrStartCheckpointMatrix(t *testing.T) {
	manifest := nginx.Manifest{SchemaVersion: nginx.ManifestSchema, GenerationID: "generation-management"}
	owner := filetxn.Owner{UID: 1000, GID: 1000}
	paths := nginx.Paths{ConfigRoot: t.TempDir(), StateRoot: t.TempDir(), CertificatePath: t.TempDir(), PrivateKeyPath: t.TempDir(), AuditPath: t.TempDir(), PIDPath: t.TempDir()}
	for _, test := range []struct {
		name       string
		master     bool
		observeErr error
		startErr   error
		reloadErr  error
		wantStart  int
		wantReload int
		wantErr    string
	}{
		{name: "start", wantStart: 1},
		{name: "reload", master: true, wantReload: 1},
		{name: "observe-failure", observeErr: errors.New("runtime observation failed"), wantErr: "runtime observation failed"},
		{name: "start-failure", startErr: errors.New("start failed"), wantStart: 1, wantErr: "start failed"},
		{name: "reload-failure", master: true, reloadErr: errors.New("reload failed"), wantReload: 1, wantErr: "reload failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			master := (*closure.ProcessIdentity)(nil)
			if test.master {
				value := closure.ProcessIdentity{PID: 41}
				master = &value
			}
			host := &managementHTTPSRecoveryFakeHost{runtime: closure.RuntimeSnapshot{Master: master}, observeErr: test.observeErr, startErr: test.startErr, reloadErr: test.reloadErr}
			runtime := defaultManagementHTTPSRuntime()
			runtime.Audit = func(nginx.Paths, filetxn.Owner) (nginx.Manifest, error) { return manifest, nil }
			runtime.NewHost = func() (managementHTTPSHost, nginx.Paths, filetxn.Owner, error) { return host, paths, owner, nil }
			err := reloadOrStartManagementHTTPS(context.Background(), runtime, host, paths, owner, activation.ReloadAuthority{})
			if test.wantErr != "" {
				if err == nil || err.Error() != test.wantErr {
					t.Fatalf("error=%v, want %q", err, test.wantErr)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if host.startCalls != test.wantStart || host.reloadCalls != test.wantReload {
				t.Fatalf("start calls=%d reload calls=%d, want %d/%d", host.startCalls, host.reloadCalls, test.wantStart, test.wantReload)
			}
		})
	}
}

func TestManagementHTTPSExpiryReplayCompletesAfterRestart(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	installation := managementHTTPSRecoveryInstallation("cert_00000000000000000000000000000001", 1)
	installation.ManagementHTTPS.CertificateBundle.NotAfter = now.Add(-time.Hour).Format(time.RFC3339)
	installation.ManagementHTTPS.CertificateBundle.LastTrustedWall = now.Add(-2 * time.Hour).Format(time.RFC3339)
	fixture := newResourceRecoveryFixture(t, installation)
	service := fixture.open(t)
	setupSet, setupMutation, setupExposure := fixture.acquire(t, service, "management_https")
	state, err := service.safety.ReadForRecovery(setupExposure)
	if err != nil {
		t.Fatal(err)
	}
	bundle := installation.ManagementHTTPS.CertificateBundle
	binding := acme.Binding{DirectoryURL: installation.ManagementHTTPS.Certificate.DirectoryURL, AccountKeyPath: acmeaccount.ManagedKeyPath, AccountKeyFingerprint: bundle.Authority.AccountKeyFingerprint, AccountEmail: installation.ManagementHTTPS.Certificate.AccountEmail, TermsAccepted: true, Method: acme.ChallengeHTTP01}
	prepared, err := challenge.Prepare(challenge.Request{ResourceID: "management_https", PlanID: bundle.Authority.CertificateID, Generation: 1, ConfigDigest: testApplicationDigest("management-config"), Domains: []string{installation.ManagementHTTPS.Domain}, Binding: binding, CertificateIdentity: bundle.Authority.CertificateID, Webroot: "/var/lib/lanpanel/certificates/webroot/" + bundle.Authority.CertificateID, BaseMarkers: managementHTTPSBaseSnapshot(state.ManagementHTTPS)})
	if err != nil {
		t.Fatal(err)
	}
	pending := state
	pending.Revision++
	pending.ManagementHTTPS.GenerationSequence = 1
	pending.ManagementHTTPS.ChallengePending = &prepared.Safety
	if _, err := service.safety.Commit(context.Background(), setupExposure, safety.RoleChallenge, state.Revision, pending, safety.TransitionProof{}); err != nil {
		t.Fatal(err)
	}
	state, err = service.safety.ReadForRecovery(setupExposure)
	if err != nil {
		t.Fatal(err)
	}
	next := state
	next.Revision++
	next.ManagementHTTPS.ActiveCertificate = &safety.ActiveCertificateAuthority{Generation: bundle.Generation, Fingerprint: bundle.Fingerprint, Binding: bundle.BindingIdentity, NotAfter: now.Add(-time.Hour), LastTrustedWall: now.Add(-2 * time.Hour)}
	next.ManagementHTTPS.EntryDigest = testApplicationDigest("management-entry")
	next.ManagementHTTPS.ChallengePending = nil
	if _, err := service.safety.Commit(context.Background(), setupExposure, safety.RoleCertificateActivation, state.Revision, next, safety.TransitionProof{}); err != nil {
		t.Fatal(err)
	}
	state, err = service.safety.ReadForRecovery(setupExposure)
	if err != nil {
		t.Fatal(err)
	}
	withExpiry := state
	withExpiry.Revision++
	withExpiry.ManagementHTTPS.GenerationSequence = 2
	withExpiry.ManagementHTTPS.CertificateExpiry = &safety.DeadlineMarker{Generation: 2, Deadline: now.Add(-time.Hour), Binding: bundle.BindingIdentity}
	if _, err := service.safety.Commit(context.Background(), setupExposure, safety.RoleCertificateActivation, state.Revision, withExpiry, safety.TransitionProof{}); err != nil {
		t.Fatal(err)
	}
	state = withExpiry
	closed := state
	closed.Revision++
	closed.ManagementHTTPS.EntryDigest = ""
	if _, err := service.safety.Commit(context.Background(), setupExposure, safety.RoleContraction, state.Revision, closed, safety.TransitionProof{}); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(operations.ReleaseExposure(setupMutation, setupExposure), setupSet.Close()); err != nil {
		t.Fatal(err)
	}
	admitter, err := service.TimerAdmitter()
	if err != nil {
		t.Fatal(err)
	}
	document, err := service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	admission, err := service.manager.Acquire(context.Background(), locks.MutationAdmission)
	if err != nil {
		t.Fatal(err)
	}
	deadline, err := time.Parse(time.RFC3339, bundle.NotAfter)
	if err != nil {
		t.Fatal(err)
	}
	job, err := admitter.Admit(context.Background(), admission, operations.AdmitRequest{Operation: operations.AutomaticReconciliation, Target: "journal/management-https-expiry-replay", ActorIdentity: "timer/management-https-expiry", Source: operations.AdmissionTimer, SafetyBinding: operations.SafetyBinding{ExpiryGeneration: 2, Deadline: deadline, CandidateBundle: bundle.BindingIdentity}, ExpectedRevision: document.Revision})
	if err != nil {
		_ = admission.Release()
		t.Fatal(err)
	}
	if err := admission.Release(); err != nil {
		t.Fatal(err)
	}
	mutationSet, mutation, exposure := fixture.acquire(t, service, "journal/management-https-expiry-replay")
	document, err = service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admitter.BeginPlanless(context.Background(), mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: document.Revision, IntentGeneration: document.Revision + 1}); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(operations.ReleaseExposure(mutation, exposure), mutationSet.Close(), service.Close()); err != nil {
		t.Fatal(err)
	}

	service = fixture.open(t)
	defer func() { _ = service.Close() }()
	runtime := defaultManagementHTTPSRuntime()
	runtime.NewHost = func() (managementHTTPSHost, nginx.Paths, filetxn.Owner, error) {
		return &managementHTTPSRecoveryFakeHost{}, nginx.Paths{}, filetxn.Owner{UID: uint32(1000), GID: uint32(1000)}, nil
	}
	runtime.Audit = func(nginx.Paths, filetxn.Owner) (nginx.Manifest, error) {
		return nginx.Manifest{SchemaVersion: nginx.ManifestSchema, GenerationID: "empty"}, nil
	}
	service.management = runtime
	if err := reconcileManagementHTTPSExpiryJobs(context.Background(), service); err != nil {
		t.Fatal(err)
	}
	document, err = service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := jobs.LoadEntries(document.Entries, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if terminal.Status != jobs.StatusTerminal || terminal.Result != jobs.ResultSucceeded {
		t.Fatalf("expiry replay job=%#v", terminal)
	}
	var recovered domain.Installation
	if err := json.Unmarshal(document.Entries["installations/current"], &recovered); err != nil {
		t.Fatal(err)
	}
	if recovered.ManagementHTTPS == nil || recovered.ManagementHTTPS.Phase != domain.ManagementHTTPSExpired {
		t.Fatalf("recovered management HTTPS=%#v", recovered.ManagementHTTPS)
	}
}

func TestManagementHTTPSExpiryReservedIntentIsRejectedAfterRestart(t *testing.T) {
	fixture := newResourceRecoveryFixture(t, recoveryResourceInstallation(nil))
	service := fixture.open(t)
	admission, err := service.manager.Acquire(context.Background(), locks.MutationAdmission)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	job, err := jobs.NewReserved(jobs.Spec{Operation: string(operations.AutomaticReconciliation), Target: "journal/management-https-expiry-replay", ActorIdentity: "timer/management-https-expiry"}, now, bytes.NewReader(bytes.Repeat([]byte{7}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	reservation := operations.Reservation{SchemaVersion: "lanpanel.operation.reservation.v1", JobID: job.ID, AdmissionSource: operations.AdmissionTimer, Operation: operations.AutomaticReconciliation, Target: "journal/management-https-expiry-replay", Phase: operations.PhaseReserved, SafetyDigest: testApplicationDigest("safety"), SafetyBinding: operations.SafetyBinding{ExpiryGeneration: 1, Deadline: now.Add(-time.Minute), CandidateBundle: testApplicationDigest("binding")}, CreatedAt: now}
	jobRaw, err := persist.EncodeEntry(job)
	if err != nil {
		t.Fatal(err)
	}
	reservationRaw, err := persist.EncodeEntry(reservation)
	if err != nil {
		t.Fatal(err)
	}
	document, err := service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.normal.Update(context.Background(), admission, document.Revision, func(transaction *persist.Transaction) error {
		if err := transaction.Create("jobs/"+job.ID, jobRaw); err != nil {
			return err
		}
		return transaction.Create("intents/"+job.ID, reservationRaw)
	}); err != nil {
		t.Fatal(err)
	}
	if err := admission.Release(); err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}

	service = fixture.open(t)
	defer func() { _ = service.Close() }()
	if err := reconcileManagementHTTPSExpiryJobs(context.Background(), service); err != nil {
		t.Fatal(err)
	}
	document, err = service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	var recovered operations.Reservation
	if err := json.Unmarshal(document.Entries["intents/"+job.ID], &recovered); err != nil {
		t.Fatal(err)
	}
	terminal, err := jobs.LoadEntries(document.Entries, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Phase != operations.PhaseRejected || terminal.Status != jobs.StatusTerminal || terminal.Result != jobs.ResultFailed || terminal.ErrorCode != "management_https_expiry_interrupted" {
		t.Fatalf("recovered reservation=%#v job=%#v", recovered, terminal)
	}
}

func TestManagementHTTPSCandidateActivationPendingBindsExactPersistedCandidate(t *testing.T) {
	installation := managementHTTPSRecoveryInstallation("cert_00000000000000000000000000000001", 2)
	raw, err := persist.EncodeEntry(installation)
	if err != nil {
		t.Fatal(err)
	}
	document := persist.Document{Entries: map[string]json.RawMessage{"installations/current": raw}}
	bundle := installation.ManagementHTTPS.CertificateBundle
	if bundle == nil {
		t.Fatal("test installation has no certificate bundle")
	}
	journal := operations.CertificateJournalIdentity{CertificateID: bundle.Authority.CertificateID, CandidateGeneration: bundle.Generation, CandidateBundleIdentity: certificates.BundleIdentity{Fingerprint: bundle.Fingerprint, SANIdentity: bundle.SANIdentity, ChainIdentity: bundle.ChainIdentity, IssuerIdentity: bundle.IssuerIdentity, BindingIdentity: bundle.BindingIdentity, DirectoryIdentity: bundle.DirectoryIdentity}}
	pending, err := managementHTTPSCandidateActivationPending(document, journal)
	if err != nil || !pending {
		t.Fatalf("exact candidate pending=%t err=%v", pending, err)
	}

	changed := journal
	changed.CandidateGeneration++
	pending, err = managementHTTPSCandidateActivationPending(document, changed)
	if err != nil || pending {
		t.Fatalf("changed generation pending=%t err=%v", pending, err)
	}
	installation.ManagementHTTPS.Phase = domain.ManagementHTTPSPending
	raw, err = persist.EncodeEntry(installation)
	if err != nil {
		t.Fatal(err)
	}
	document.Entries["installations/current"] = raw
	pending, err = managementHTTPSCandidateActivationPending(document, journal)
	if err != nil || pending {
		t.Fatalf("pending configuration pending=%t err=%v", pending, err)
	}
}

func TestManagementHTTPSBaseSnapshotPreservesOnlyIndependentMarkers(t *testing.T) {
	state := safety.ManagementHTTPSSafety{GenerationSequence: 4, CertificateExpiry: &safety.DeadlineMarker{Generation: 3, Deadline: time.Unix(1_800_000_000, 0).UTC(), Binding: testApplicationDigest("binding")}}
	markers := managementHTTPSBaseSnapshot(state)
	if len(markers) != 3 || markers[0].Kind != safety.MarkerStickyUnpublished || markers[1].Kind != safety.MarkerContraction || markers[2].Kind != safety.MarkerCertificateExpiry || markers[2].State != safety.SnapshotPresent || markers[2].Generation != 3 {
		t.Fatalf("markers=%#v", markers)
	}
	state.CertificateExpiry = nil
	markers = managementHTTPSBaseSnapshot(state)
	if markers[2].State != safety.SnapshotAbsent || markers[2].Generation != 0 {
		t.Fatalf("absent expiry markers=%#v", markers)
	}
}

func TestManagementHTTPSIssueDueRejectsOccupiedOrFencedSafety(t *testing.T) {
	config := managementHTTPSRecoveryInstallation("cert_00000000000000000000000000000001", 1).ManagementHTTPS
	config.Phase = domain.ManagementHTTPSPending
	config.CertificateBundle = nil
	state := safety.EmptyState()
	if !ManagementHTTPSIssueDue(config, state) {
		t.Fatal("valid pending configuration was not due")
	}
	state.ManagementHTTPS.ChallengePending = &safety.ChallengePending{Generation: 1, PlanID: "cert", CertificateIdentity: "cert_00000000000000000000000000000001", ACMEBinding: config.ACMEBinding}
	if ManagementHTTPSIssueDue(config, state) {
		t.Fatal("occupied challenge was considered due")
	}
	state = safety.EmptyState()
	state.StopFence = &safety.StopFence{Kind: safety.StopFenceIngressActivation, FenceGeneration: 1}
	if ManagementHTTPSIssueDue(config, state) {
		t.Fatal("stop-fenced configuration was considered due")
	}
}

func managementHTTPSRecoveryInstallation(certificateID string, generation uint64) domain.Installation {
	digest := testApplicationDigest("management-certificate")
	binding := acme.Binding{DirectoryURL: "https://acme.example.test/directory", AccountKeyPath: acmeaccount.ManagedKeyPath, AccountKeyFingerprint: digest, AccountEmail: "admin@example.test", TermsAccepted: true, Method: acme.ChallengeHTTP01}
	bindingDigest, _ := acme.BindingDigest(binding)
	now := time.Date(2029, time.January, 1, 0, 0, 0, 0, time.UTC)
	certificate := domain.CertificateBundleIdentity{PointerIdentity: "/var/lib/lanpanel/certificates/active/" + certificateID + ".current", BindingIdentity: bindingDigest, Generation: generation, Fingerprint: digest, SANIdentity: managementHTTPSRecoverySANDigest("panel.example.test"), NotAfter: now.Add(365 * 24 * time.Hour).Format(time.RFC3339), LastTrustedWall: now.Format(time.RFC3339), ChainIdentity: digest, IssuerIdentity: digest, DirectoryIdentity: digest, Authority: &domain.CertificateAuthorityIdentity{CertificateID: certificateID, DirectoryURL: binding.DirectoryURL, AccountKeyPath: binding.AccountKeyPath, AccountKeyFingerprint: binding.AccountKeyFingerprint, AccountEmail: binding.AccountEmail, TermsAccepted: binding.TermsAccepted, Method: string(binding.Method), CredentialFiles: []domain.CertificateCredentialIdentity{}}}
	return domain.Installation{SchemaVersion: domain.InstallationSchemaVersion, InstallationID: "ins_00000000000000000000000000000001", Management: domain.ManagementAuthority{Address: "127.23.45.67", Port: 23456}, ManagementHTTPS: &domain.ManagementHTTPSConfig{Domain: "panel.example.test", Certificate: domain.CertificateRequest{ChallengeMethod: "http-01", DirectoryURL: binding.DirectoryURL, AccountEmail: binding.AccountEmail, TermsAccepted: true}, ACMEBinding: bindingDigest, Phase: domain.ManagementHTTPSActive, Generation: generation, CertificateBundle: &certificate}}
}

func managementHTTPSRecoverySANDigest(domainName string) string {
	sum := sha256.Sum256([]byte(domainName))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func testApplicationDigest(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return "sha256:" + hex.EncodeToString(sum[:])
}
