//go:build linux

package activation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"lanpanel/internal/closure"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/nginx"
	"lanpanel/internal/safety"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func installCertificateReloadTestApp(t *testing.T, paths nginx.Paths, owner filetxn.Owner, authority *ReloadAuthoritySnapshot, notAfter time.Time) nginx.Entry {
	t.Helper()
	certificate := domain.CertificateBundleIdentity{
		PointerIdentity: "/var/lib/lanpanel/certificates/active/cert-reload",
		BindingIdentity: "binding-reload",
		Generation:      1,
		Fingerprint:     challengeTestDigest,
		SANIdentity:     challengeTestDigest,
		ChainIdentity:   challengeTestDigest,
		IssuerIdentity:  challengeTestDigest,
		NotAfter:        notAfter.Format(time.RFC3339),
		LastTrustedWall: notAfter.Add(-time.Hour).Format(time.RFC3339),
	}
	entry := nginx.Entry{
		Kind:       nginx.EntryApp,
		ResourceID: "res_reload",
		Relative:   nginx.AppsDirectory + "/res_reload.conf",
		Digest:     challengeTestDigest,
		Domains:    []string{"reload.example.test"},
		Listeners:  []string{"tcp:0.0.0.0:443", "tcp:0.0.0.0:80", "tcp:[::]:443", "tcp:[::]:80"},
		Generation: 1,
		Domain: &nginx.DomainSite{
			Hosts:              []string{"reload.example.test"},
			CertificatePointer: certificate.PointerIdentity,
			RejectionAuditPath: "/var/log/lanpanel/nginx-rejections.log",
			AuthMode:           "public",
			UpstreamNetwork:    "unix",
			UpstreamAddress:    "/run/lanpanel/res_reload.sock",
		},
	}
	manifest, _, err := nginx.InstallEntry(context.Background(), paths, owner, entry)
	if err != nil {
		t.Fatal(err)
	}
	for _, current := range manifest.Entries {
		if current.Kind == nginx.EntryApp && current.ResourceID == entry.ResourceID {
			entry = current
		}
	}
	bundle := domain.PublicationBundle{
		ID:               "bundle-reload",
		Generation:       entry.Generation,
		ConfigDigest:     challengeTestDigest,
		Kind:             domain.PublicationDomainHTTPS,
		EndpointIdentity: challengeTestDigest,
		SiteIdentity:     entry.Digest,
		ManagedPaths:     []string{},
		CredentialIDs:    []string{},
		Listeners:        []domain.BundleListenerIdentity{{Network: "tcp", Port: 80}, {Network: "tcp", Port: 443}},
		DomainHTTPS: &domain.DomainHTTPSBundleIdentity{
			ExactDomains: append([]string(nil), entry.Domains...),
			Certificate:  certificate,
			Auth:         domain.AuthBundleIdentity{Mode: domain.AppAccessPublic},
			Static:       domain.StaticBundleIdentity{Routes: []domain.StaticRouteBundleIdentity{}, RouteIdentities: []string{}},
			GoAccess:     domain.GoAccessBundleIdentity{Enabled: false},
		},
	}
	authority.Installation.Resources = append(authority.Installation.Resources, domain.AppResource{
		ID:          entry.ResourceID,
		Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: entry.Domains[0], AccessMode: domain.AppAccessPublic}},
		PublicationRecord: domain.PublicationRecord{
			State:             domain.PublicationPublished,
			LastAppliedBundle: &bundle,
		},
	})
	authority.Safety.Resources = append(authority.Safety.Resources, safety.ResourceSafety{
		ResourceID:         entry.ResourceID,
		GenerationSequence: entry.Generation,
		State:              safety.ResourceActive,
		Ownership:          safety.OwnershipOwned,
		OwnershipDigest:    challengeTestDigest,
		ActiveCertificate: &safety.ActiveCertificateAuthority{
			Generation:      certificate.Generation,
			Fingerprint:     certificate.Fingerprint,
			Binding:         certificate.BindingIdentity,
			LastTrustedWall: notAfter.Add(-time.Hour),
			NotAfter:        notAfter,
		},
	})
	authority.Ownership[entry.ResourceID] = challengeTestDigest
	return entry
}

func certificateReloadTestRuntime(manifest nginx.Manifest, beforeGuard func(), signals *int) certificateReloadRuntime {
	master := closure.ProcessIdentity{PID: 100}
	return certificateReloadRuntime{
		Audit: func(context.Context) (nginx.Manifest, error) { return manifest, nil },
		Observe: func(context.Context, nginx.Manifest) (closure.RuntimeSnapshot, error) {
			return closure.RuntimeSnapshot{Master: &master, Workers: []closure.ProcessIdentity{{PID: 101}}}, nil
		},
		Test: func(context.Context) error {
			if beforeGuard != nil {
				beforeGuard()
			}
			return nil
		},
		Signal: func(context.Context) error {
			(*signals)++
			return nil
		},
		Wait: func(context.Context, nginx.Manifest, []closure.ProcessIdentity) (closure.RuntimeSnapshot, error) {
			return closure.RuntimeSnapshot{Master: &master}, nil
		},
	}
}

func TestProbeServedCertificateAcceptsOnlyExactPeerFingerprint(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	sum := sha256.Sum256(server.Certificate().Raw)
	expected := "sha256:" + hex.EncodeToString(sum[:])
	if err := probeServedCertificateAt(context.Background(), server.Listener.Addr().String(), "panel.example.test", expected); err != nil {
		t.Fatalf("exact served certificate was rejected: %v", err)
	}
	if err := probeServedCertificateAt(context.Background(), server.Listener.Addr().String(), "panel.example.test", "sha256:"+strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong served certificate fingerprint was accepted")
	}
	if err := probeServedCertificateAt(context.Background(), "127.0.0.1:1", "panel.example.test", expected); err == nil {
		t.Fatal("unreachable served certificate endpoint was accepted")
	}
}

func TestChallengeRollbackReloadRefreshesTimeAndRejectsExpiredCertificate(t *testing.T) {
	paths, owner, prepared, prior := challengeTransactionFixture(t)
	if _, _, err := nginx.RemoveEntry(context.Background(), paths, owner, prior); err != nil {
		t.Fatal(err)
	}
	boundary := time.Unix(1_800_000_000, 0).UTC()
	authoritySnapshot := challengeReloadTestSnapshot(prepared)
	installCertificateReloadTestApp(t, paths, owner, &authoritySnapshot, boundary)
	snapshot, err := nginx.SnapshotActivation(paths, owner, *prepared.Entry)
	if err != nil {
		t.Fatal(err)
	}
	prospective, err := nginx.ProspectiveManifest(snapshot.Manifest, *prepared.Entry)
	if err != nil {
		t.Fatal(err)
	}
	refreshes := 0
	authority := challengeReloadAuthorityFromSnapshot(&authoritySnapshot, func() time.Time {
		refreshes++
		if refreshes >= 3 {
			return boundary
		}
		return boundary.Add(-time.Second)
	})
	activateErr := errors.New("injected challenge reload failure")
	restoredRuntime := false
	runtime := ChallengeGraphRuntime{
		Activate: func(context.Context, nginx.Manifest, func() error) error { return activateErr },
		Observe:  func(context.Context, nginx.Manifest) ([]closure.ProcessIdentity, error) { return nil, nil },
		Restore: func(_ context.Context, _ nginx.Manifest, _ []closure.ProcessIdentity, authorize func() error) error {
			if err := authorize(); err != nil {
				return err
			}
			restoredRuntime = true
			return nil
		},
	}
	_, err = CommitChallengeGraph(context.Background(), paths, owner, *prepared.Entry, snapshot, prospective, authority, func(ctx context.Context) (nginx.Manifest, []string, error) {
		return nginx.InstallEntry(ctx, paths, owner, *prepared.Entry)
	}, runtime)
	var failure *Failure
	if !errors.As(err, &failure) || failure.PriorRestored || restoredRuntime || !errors.Is(err, activateErr) || refreshes < 3 {
		t.Fatalf("rollback failure=%#v runtimeRestored=%t refreshes=%d err=%v", failure, restoredRuntime, refreshes, err)
	}
	assertChallengeSnapshotRestored(t, paths, owner, *prepared.Entry, snapshot)
}

func TestCertificateRestoreAfterChallengeRemovalRejectsNewlyExpiredCertificate(t *testing.T) {
	paths, owner, prepared, prior := challengeTransactionFixture(t)
	expected := challengePreparedForEntry(prepared, prior)
	boundary := time.Unix(1_800_000_000, 0).UTC()
	authoritySnapshot := challengeReloadTestSnapshot(expected)
	installCertificateReloadTestApp(t, paths, owner, &authoritySnapshot, boundary)
	currentTime := boundary.Add(-time.Second)
	authority := challengeReloadAuthorityFromSnapshot(&authoritySnapshot, func() time.Time { return currentTime })
	snapshot, err := nginx.SnapshotActivation(paths, owner, prior)
	if err != nil {
		t.Fatal(err)
	}
	prospective, err := nginx.ProspectiveRemoval(snapshot.Manifest, prior)
	if err != nil {
		t.Fatal(err)
	}
	challengeSignals := 0
	result, err := CommitChallengeGraph(context.Background(), paths, owner, prior, snapshot, prospective, authority, func(ctx context.Context) (nginx.Manifest, []string, error) {
		return nginx.RemoveEntry(ctx, paths, owner, prior)
	}, ChallengeGraphRuntime{
		Activate: func(_ context.Context, manifest nginx.Manifest, authorize func() error) error {
			if err := authorize(); err != nil {
				return err
			}
			challengeSignals++
			if !reflect.DeepEqual(manifest, prospective) {
				return fmt.Errorf("challenge removal manifest changed")
			}
			return nil
		},
		Observe: func(context.Context, nginx.Manifest) ([]closure.ProcessIdentity, error) { return nil, nil },
		Restore: func(context.Context, nginx.Manifest, []closure.ProcessIdentity, func() error) error {
			return fmt.Errorf("unexpected challenge rollback")
		},
	})
	if err != nil || challengeSignals != 1 || !reflect.DeepEqual(result.Manifest, prospective) {
		t.Fatalf("challenge removal result=%#v signals=%d err=%v", result, challengeSignals, err)
	}

	currentTime = boundary
	pointerRestored, probed, certificateSignals := false, false, 0
	restoreErr := restoreCertificateRuntime(context.Background(), func(context.Context) error {
		pointerRestored = true
		return nil
	}, func(reloadCtx context.Context) (closure.RuntimeSnapshot, error) {
		return reloadCertificateRuntime(reloadCtx, authority, certificateReloadTestRuntime(prospective, nil, &certificateSignals))
	}, func(context.Context) error {
		probed = true
		return nil
	})
	if restoreErr == nil || !pointerRestored || certificateSignals != 0 || probed {
		t.Fatalf("restore pointerRestored=%t signals=%d probed=%t err=%v", pointerRestored, certificateSignals, probed, restoreErr)
	}
}

func TestPriorPointerDirectReloadRejectsCertificateExpiringBeforeSignal(t *testing.T) {
	paths, owner, prepared, prior := challengeTransactionFixture(t)
	if _, _, err := nginx.RemoveEntry(context.Background(), paths, owner, prior); err != nil {
		t.Fatal(err)
	}
	boundary := time.Unix(1_800_000_000, 0).UTC()
	authoritySnapshot := challengeReloadTestSnapshot(prepared)
	installCertificateReloadTestApp(t, paths, owner, &authoritySnapshot, boundary)
	manifest, err := nginx.Audit(paths, owner)
	if err != nil {
		t.Fatal(err)
	}
	currentTime := boundary.Add(-time.Second)
	authority := challengeReloadAuthorityFromSnapshot(&authoritySnapshot, func() time.Time { return currentTime })
	signals := 0
	_, err = reloadCertificateRuntime(context.Background(), authority, certificateReloadTestRuntime(manifest, func() { currentTime = boundary }, &signals))
	if err == nil || signals != 0 {
		t.Fatalf("expired direct reload signals=%d err=%v", signals, err)
	}
}

func TestCertificateRecoveryReloadSucceedsWithCurrentAuthority(t *testing.T) {
	paths, owner, prepared, prior := challengeTransactionFixture(t)
	if _, _, err := nginx.RemoveEntry(context.Background(), paths, owner, prior); err != nil {
		t.Fatal(err)
	}
	boundary := time.Unix(1_800_000_000, 0).UTC()
	authoritySnapshot := challengeReloadTestSnapshot(prepared)
	installCertificateReloadTestApp(t, paths, owner, &authoritySnapshot, boundary)
	manifest, err := nginx.Audit(paths, owner)
	if err != nil {
		t.Fatal(err)
	}
	authority := challengeReloadAuthorityFromSnapshot(&authoritySnapshot, func() time.Time { return boundary.Add(-time.Second) })
	pointerRestored, probed, signals := false, false, 0
	err = restoreCertificateRuntime(context.Background(), func(context.Context) error {
		pointerRestored = true
		return nil
	}, func(reloadCtx context.Context) (closure.RuntimeSnapshot, error) {
		return reloadCertificateRuntime(reloadCtx, authority, certificateReloadTestRuntime(manifest, nil, &signals))
	}, func(context.Context) error {
		probed = true
		return nil
	})
	if err != nil || !pointerRestored || signals != 1 || !probed {
		t.Fatalf("legal recovery pointerRestored=%t signals=%d probed=%t err=%v", pointerRestored, signals, probed, err)
	}
}
