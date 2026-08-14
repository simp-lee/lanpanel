package closure

import (
	"lanpanel/internal/domain"
	"lanpanel/internal/nginx"
	"lanpanel/internal/ownership"
	"lanpanel/internal/safety"
	"strings"
	"testing"
)

func TestClosureInventoryUnionsPriorCandidateChallengeDiskAndOwnership(t *testing.T) {
	prior := bundle("prior", "app.example.test")
	candidate := bundle("candidate", "new.example.test")
	installation := domain.Installation{Resources: []domain.AppResource{{ID: "app-one", PublicationRecord: domain.PublicationRecord{State: domain.PublicationActivating, UnpublishedGeneration: 1, LastAppliedDigest: &prior.ConfigDigest, LastAppliedBundle: &prior, ActivationIntent: &domain.ActivationIntent{ID: "intent", JobID: "job-one", PlanID: "plan-one", Generation: 1, Candidate: candidate, PriorState: domain.PublicationPublished, Prior: &prior}}}}}
	state := safety.EmptyState()
	state.Resources = []safety.ResourceSafety{{ResourceID: "app-one", State: safety.ResourceActive, Ownership: safety.OwnershipOwned, OwnershipDigest: digestTest("owner"), ChallengePending: &safety.ChallengePending{Generation: 2, PlanID: "plan", Host: "new.example.test", TokenPath: "/var/lib/lanpanel/token", Webroot: "/var/lib/lanpanel/webroot", BootstrapIdentity: digestTest("bootstrap")}}}
	ownershipInventory := ownership.Inventory{Complete: true, Records: []ownership.Record{{ResourceID: "app-one", Paths: []ownership.OwnedPath{{Kind: ownership.PathSite, Path: "/etc/lanpanel/site.conf", IdentityDigest: digestTest("path")}}, Listeners: []ownership.OwnedListener{{Protocol: "tcp", Address: "0.0.0.0", Port: 443, IdentityDigest: digestTest("listener")}}}}}
	graph := nginx.Manifest{Entries: []nginx.Entry{{Kind: nginx.EntryApp, ResourceID: "app-one", Relative: "apps-enabled/app-one.conf", Digest: digestTest("graph"), Domains: []string{"app.example.test"}, Generation: 1}}}
	inventory, err := BuildInventory(Inputs{Installation: installation, Safety: &state, Ownership: ownershipInventory, Graph: &graph, ResourceIDs: []string{"app-one"}})
	if err != nil || !inventory.Complete {
		t.Fatalf("inventory=%#v error=%v", inventory, err)
	}
	seen := map[IdentityKind]bool{}
	for _, identity := range inventory.Identities {
		seen[identity.Kind] = true
	}
	for _, kind := range []IdentityKind{IdentityResourceScope, IdentityNormalPrior, IdentityNormalCandidate, IdentityDomain, IdentityListener, IdentityChallenge, IdentityOwnershipPath, IdentityOwnershipListener, IdentityDiskGraph} {
		if !seen[kind] {
			t.Fatalf("closure union omitted %q: %#v", kind, inventory.Identities)
		}
	}
}

func TestNeverPublishedResourceDoesNotRequirePrematureOwnership(t *testing.T) {
	installation := domain.Installation{Resources: []domain.AppResource{{ID: "app-one", PublicationRecord: domain.PublicationRecord{State: domain.PublicationUnpublished, UnpublishedGeneration: 1}}}}
	state := safety.EmptyState()
	state.Resources = []safety.ResourceSafety{{ResourceID: "app-one", State: safety.ResourceActive, Ownership: safety.OwnershipOwned, OwnershipDigest: digestTest("owner")}}
	graph := nginx.Manifest{Entries: []nginx.Entry{}}
	inventory, err := BuildInventory(Inputs{Installation: installation, Safety: &state, Ownership: ownership.Inventory{Complete: true}, Graph: &graph, ResourceIDs: []string{"app-one"}})
	if err != nil || !inventory.Complete {
		t.Fatalf("never-published inventory=%#v error=%v", inventory, err)
	}
}

func TestOwnershipListenerWithoutDurablePublicationIdentityForcesFallback(t *testing.T) {
	installation := domain.Installation{Resources: []domain.AppResource{{ID: "app-one", PublicationRecord: domain.PublicationRecord{State: domain.PublicationUnpublished, UnpublishedGeneration: 1}}}}
	state := safety.EmptyState()
	state.Resources = []safety.ResourceSafety{{ResourceID: "app-one", State: safety.ResourceActive, Ownership: safety.OwnershipOwned, OwnershipDigest: digestTest("owner")}}
	owned := ownership.Inventory{Complete: true, Records: []ownership.Record{{ResourceID: "app-one", Checksum: digestTest("owner"), Listeners: []ownership.OwnedListener{{Protocol: "tcp", Address: "0.0.0.0", Port: 9443, IdentityDigest: digestTest("listener")}}}}}
	graph := nginx.Manifest{Entries: []nginx.Entry{}}
	inventory, err := BuildInventory(Inputs{Installation: installation, Safety: &state, Ownership: owned, Graph: &graph, ResourceIDs: []string{"app-one"}})
	if err != nil || inventory.Complete {
		t.Fatalf("inventory=%#v error=%v", inventory, err)
	}
	found := false
	for _, uncertainty := range inventory.Uncertainties {
		found = found || uncertainty.Code == "listener_authority_contradiction"
	}
	if !found {
		t.Fatalf("missing ownership listener was not uncertainty: %#v", inventory.Uncertainties)
	}
}

func TestFallbackInventoryPreservesSelectedSafetyOwnershipAndListenerSuperset(t *testing.T) {
	state := safety.EmptyState()
	state.Resources = []safety.ResourceSafety{{ResourceID: "app-one", OwnershipDigest: digestTest("safety-owner")}, {ResourceID: "app-two", OwnershipDigest: digestTest("other-owner")}}
	owned := ownership.Inventory{FallbackRecords: []ownership.Record{{ResourceID: "app-one", Checksum: digestTest("record-owner"), Listeners: []ownership.OwnedListener{{Protocol: "tcp", Address: "0.0.0.0", Port: 9443}}}}}
	inventory := BuildFallbackInventory(Inputs{Safety: &state, Ownership: owned, ResourceIDs: []string{"app-one"}}, errFallbackTest{})
	if inventory.Complete || inventory.Digest == "" || inventory.ResourceOwnership["app-one"] != digestTest("safety-owner") || inventory.ResourceOwnership["app-two"] != "" {
		t.Fatalf("fallback inventory=%#v", inventory)
	}
	found := false
	for _, listener := range inventory.FallbackListeners {
		found = found || listener == "tcp:0.0.0.0:9443"
	}
	if !found {
		t.Fatalf("fallback listener superset=%v", inventory.FallbackListeners)
	}
}

type errFallbackTest struct{}

func (errFallbackTest) Error() string { return "inventory overflow" }

func TestMalformedOwnershipOrMissingGraphForcesFallbackInventory(t *testing.T) {
	installation := domain.Installation{Resources: []domain.AppResource{{ID: "app-one", PublicationRecord: domain.PublicationRecord{UnpublishedGeneration: 1}}}}
	inventory, err := BuildInventory(Inputs{Installation: installation, Ownership: ownership.Inventory{Complete: false, Issues: []ownership.Issue{{Name: "forged.json", Error: "symlink"}}}, ResourceIDs: []string{"app-one"}})
	if err != nil || inventory.Complete || len(inventory.Uncertainties) < 3 || inventory.UncertaintyDigest == "" {
		t.Fatalf("inventory=%#v error=%v", inventory, err)
	}
}

func bundle(id, domainName string) domain.PublicationBundle {
	digest := digestTest(id)
	return domain.PublicationBundle{Generation: 1, ID: id, ConfigDigest: digest, Kind: domain.PublicationDomainHTTPS, EndpointIdentity: "endpoint-" + id, SiteIdentity: "site-" + id, Listeners: []domain.BundleListenerIdentity{{Network: "tcp", Port: 443}}, DomainHTTPS: &domain.DomainHTTPSBundleIdentity{ExactDomains: []string{domainName}, Certificate: domain.CertificateBundleIdentity{PointerIdentity: "pointer", BindingIdentity: "binding", Generation: 1, Fingerprint: digestTest("fingerprint"), SANIdentity: digestTest("san"), ChainIdentity: digestTest("chain"), IssuerIdentity: digestTest("issuer"), NotAfter: "2030-01-01T00:00:00Z", LastTrustedWall: "2029-01-01T00:00:00Z"}, Auth: domain.AuthBundleIdentity{Mode: domain.AppAccessPublic}}}
}
func digestTest(seed string) string {
	return "sha256:" + strings.Repeat(string("abcdef0123456789"[len(seed)%16]), 64)
}
