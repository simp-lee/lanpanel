//go:build linux

package qualification

import (
	"context"
	"encoding/json"
	"lanpanel/internal/application"
	"lanpanel/internal/certificates"
	"lanpanel/internal/domain"
	"lanpanel/internal/release"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestReconcileResourceCertificateAfterCloseAll(t *testing.T) {
	artifact := testQualificationCertificateArtifact("cert_00000000000000000000000000000001", "app")
	pointer, err := certificates.ActivePointerPath(artifact.CertificateID)
	if err != nil {
		t.Fatal(err)
	}
	resource := domain.AppResource{ID: "res_00000000000000000000000000000001", PublicationRecord: domain.PublicationRecord{State: domain.PublicationPublished, LastAppliedBundle: &domain.PublicationBundle{DomainHTTPS: &domain.DomainHTTPSBundleIdentity{Certificate: domain.CertificateBundleIdentity{
		PointerIdentity: pointer, Generation: artifact.Generation, Fingerprint: artifact.Bundle.Fingerprint, SANIdentity: artifact.Bundle.SANIdentity, ChainIdentity: artifact.Bundle.ChainIdentity, IssuerIdentity: artifact.Bundle.IssuerIdentity, BindingIdentity: artifact.Bundle.BindingIdentity, DirectoryIdentity: artifact.Bundle.DirectoryIdentity, Authority: &domain.CertificateAuthorityIdentity{CertificateID: artifact.CertificateID},
	}}}}}
	installation := domain.Installation{Resources: []domain.AppResource{resource}}
	var inventoryLock sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		inventoryLock.Lock()
		defer inventoryLock.Unlock()
		if request.URL.Path != "/api/actions/configuration_export" {
			t.Errorf("unexpected management action %s", request.URL.Path)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(writer).Encode(application.ConfigurationExport{SchemaVersion: "lanpanel.configuration-export.v1", Installation: installation})
	}))
	defer server.Close()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store := liveStateStore{path: filepath.Join(root, "state")}
	state, _, err := store.Read("run-one", release.DigestBytes([]byte("input")))
	if err != nil {
		t.Fatal(err)
	}
	state.ResourceID = resource.ID
	executor := &LiveExecutor{states: store, state: state, management: &ManagementClient{http: server.Client(), origin: server.URL}}
	if err := executor.rememberResourceCertificate(context.Background(), resource.ID); err != nil {
		t.Fatal(err)
	}
	// Close-all retains the applied bundle while changing publication state.
	inventoryLock.Lock()
	installation.Resources[0].PublicationRecord.State = domain.PublicationUnpublished
	inventoryLock.Unlock()
	if err := executor.reconcileCertificateInventory(context.Background(), installation); err != nil {
		t.Fatalf("closed resource prevented cleanup reconciliation: %v", err)
	}
	persisted, _, err := store.Read(state.RunID, state.ProtectedInputDigest)
	if err != nil || len(persisted.CertificateCleanup) != 1 || persisted.CertificateCleanup[0] != artifact {
		t.Fatalf("cleanup lost exact applied certificate: state=%+v err=%v", persisted, err)
	}
}

func TestInterruptedPrefixCleanupDoesNotRequireUncreatedCertificates(t *testing.T) {
	for _, issued := range []bool{false, true} {
		name := "before_app_issuance"
		if issued {
			name = "before_headscale_initialization"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			store := liveStateStore{path: filepath.Join(root, "state")}
			state, _, err := store.Read("run-one", release.DigestBytes([]byte("input")))
			if err != nil {
				t.Fatal(err)
			}
			if issued {
				state.CertificateCleanup = []qualificationCertificateArtifact{testQualificationCertificateArtifact("cert_00000000000000000000000000000001", "app")}
				state.CertificateCleanupComplete = true
			}
			state.FinalCleanupComplete = true
			if err := store.Write(state); err != nil {
				t.Fatalf("cleaned interrupted prefix cannot become terminal: %v", err)
			}
			persisted, _, err := store.Read(state.RunID, state.ProtectedInputDigest)
			if err != nil {
				t.Fatal(err)
			}
			executor := &LiveExecutor{state: persisted}
			result, err := executor.Cleanup(context.Background(), "app_http01", MutationObservation{}, "delete_exact")
			if err != nil || result != release.CleanupCleaned {
				t.Fatalf("resumed cleanup did not converge: result=%s err=%v", result, err)
			}
			if _, err := certificateInventoryEvidence(persisted); err == nil {
				t.Fatal("interrupted prefix became successful qualification evidence")
			}
		})
	}
}
