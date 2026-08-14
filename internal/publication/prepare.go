// Package publication prepares complete typed ingress candidates without mutating host state.
package publication

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"lanpanel/internal/certificates"
	"lanpanel/internal/domain"
	"lanpanel/internal/nginx"
	"lanpanel/internal/ownership"
	"net"
	"path/filepath"
	"slices"
	"strings"
)

const PlaintextWarning = "Public plaintext HTTP; anyone can access it; never transmit credentials, cookies, or sensitive data. It remains open until explicit unpublish or close-all."

type Candidate struct {
	ResourceID               string
	Generation               uint64
	Bundle                   domain.PublicationBundle
	BundleDigest             string
	Entry                    nginx.Entry
	EntryBytes               []byte
	OwnershipPath            ownership.OwnedPath
	OwnershipListener        ownership.OwnedListener
	OwnershipListeners       []ownership.OwnedListener
	PublicURL                string
	CertificatePointer       *certificates.Pointer
	CertificateCandidatePath string
	PriorBundle              *domain.PublicationBundle
	PriorBundleDigest        string
}

func PrepareTemporary(resource domain.AppResource, generation uint64) (Candidate, error) {
	if resource.Lifecycle != domain.LifecycleActive || resource.Publication.Kind != domain.PublicationTemporaryHTTP || resource.Publication.TemporaryHTTP == nil || resource.Target.Kind != domain.AppTargetLocalHTTP || resource.Target.LocalHTTP == nil || resource.Target.WebSocket.Enabled || resource.ManagedProcess == nil || resource.ManagedProcess.Requested != domain.ProcessRequestedRunning || resource.ManagedProcess.Applied == nil || generation == 0 {
		return Candidate{}, fmt.Errorf("temporary publication prerequisite is incomplete")
	}
	applied := resource.ManagedProcess.Applied
	if applied.ConfigDigest != resource.CurrentConfigDigest {
		return Candidate{}, fmt.Errorf("running process bundle does not match current config")
	}
	publication := resource.Publication.TemporaryHTTP
	if err := domain.ValidateTemporaryPublicIPv4(publication.PublicIPv4); err != nil {
		return Candidate{}, err
	}
	upstreamNetwork, upstreamAddress := "unix", applied.FrontendEndpoint
	if applied.TCPAddress != "" {
		upstreamNetwork = "tcp"
		upstreamAddress = net.JoinHostPort(applied.TCPAddress, fmt.Sprint(applied.TCPPort))
	}
	relative := filepath.ToSlash(filepath.Join(nginx.TemporaryDirectory, resource.ID+".conf"))
	listener := fmt.Sprintf("tcp:0.0.0.0:%d", publication.Port)
	site := nginx.TemporarySite{PublicIPv4: publication.PublicIPv4, Port: publication.Port, HostAuthority: fmt.Sprintf("%s:%d", publication.PublicIPv4, publication.Port), UpstreamNetwork: upstreamNetwork, UpstreamAddress: upstreamAddress, ReadinessPath: resource.Target.ReadinessPath}
	entry := nginx.Entry{Kind: nginx.EntryTemporary, ResourceID: resource.ID, Relative: relative, Digest: "sha256:" + strings.Repeat("0", 64), Listeners: []string{listener}, Generation: generation, Temporary: &site}
	data, err := nginx.RenderEntry(entry)
	if err != nil {
		return Candidate{}, err
	}
	entry.Digest = digest(data)
	entryPath := filepath.Join(nginx.FixedPaths().ConfigRoot, filepath.FromSlash(relative))
	bundle := domain.PublicationBundle{ID: fmt.Sprintf("pub_%d_%s", generation, strings.TrimPrefix(resource.ID, "res_")), Generation: generation, ConfigDigest: resource.CurrentConfigDigest, Kind: domain.PublicationTemporaryHTTP, EndpointIdentity: applied.PolicyDigest, SiteIdentity: entry.Digest, ManagedPaths: []string{entryPath}, CredentialIDs: []string{}, Listeners: []domain.BundleListenerIdentity{{Network: "tcp", Port: publication.Port}}, TemporaryHTTP: &domain.TemporaryHTTPBundleIdentity{PublicIPv4: publication.PublicIPv4, Port: publication.Port, HostAuthority: site.HostAuthority, ListenerIdentity: listener}}
	raw, err := json.Marshal(bundle)
	if err != nil {
		return Candidate{}, err
	}
	bundleDigest := digest(raw)
	listenerOwnership := ownership.OwnedListener{Protocol: "tcp", Address: "0.0.0.0", Port: publication.Port, IdentityDigest: ownership.ListenerIdentity(resource.ID, "tcp", "0.0.0.0", publication.Port)}
	prior, priorDigest, err := priorPublication(resource)
	if err != nil {
		return Candidate{}, err
	}
	return Candidate{ResourceID: resource.ID, Generation: generation, Bundle: bundle, BundleDigest: bundleDigest, Entry: entry, EntryBytes: data, OwnershipPath: ownership.OwnedPath{Kind: ownership.PathSite, Path: entryPath, IdentityDigest: ownership.PathIdentity(resource.ID, ownership.PathSite, entryPath)}, OwnershipListener: listenerOwnership, OwnershipListeners: []ownership.OwnedListener{listenerOwnership}, PublicURL: "http://" + site.HostAuthority + "/", PriorBundle: prior, PriorBundleDigest: priorDigest}, nil
}

func PrepareDomain(resource domain.AppResource, generation uint64, certificate domain.CertificateBundleIdentity, credentialPath, credentialFingerprint string, staticRoutes []nginx.StaticRoute) (Candidate, error) {
	publication := resource.Publication.DomainHTTPS
	if resource.Lifecycle != domain.LifecycleActive || resource.Publication.Kind != domain.PublicationDomainHTTPS || publication == nil || certificate.Authority == nil || certificate.Authority.CertificateID == "" || resource.ManagedProcess == nil || resource.ManagedProcess.Requested != domain.ProcessRequestedRunning || resource.ManagedProcess.Applied == nil || resource.ManagedProcess.Applied.ConfigDigest != resource.CurrentConfigDigest || generation == 0 {
		return Candidate{}, fmt.Errorf("domain publication prerequisite incomplete")
	}
	hosts := append([]string{publication.CanonicalDomain}, publication.Aliases...)
	slices.Sort(hosts)
	authIdentity := ""
	if publication.AccessMode == domain.AppAccessBasic {
		if credentialPath == "" || credentialFingerprint == "" {
			return Candidate{}, fmt.Errorf("domain Basic authority missing")
		}
		authIdentity = digest([]byte(publication.CredentialID + "\x00" + credentialPath))
	} else if credentialPath != "" || credentialFingerprint != "" {
		return Candidate{}, fmt.Errorf("domain non-Basic carried credential authority")
	}
	applied := resource.ManagedProcess.Applied
	upstreamNetwork, upstreamAddress := "unix", applied.FrontendEndpoint
	if applied.TCPAddress != "" {
		upstreamNetwork = "tcp"
		upstreamAddress = net.JoinHostPort(applied.TCPAddress, fmt.Sprint(applied.TCPPort))
	}
	relative := filepath.ToSlash(filepath.Join(nginx.AppsDirectory, resource.ID+".conf"))
	site := nginx.DomainSite{Hosts: hosts, CertificatePointer: certificate.PointerIdentity, RejectionAuditPath: nginx.FixedPaths().AuditPath, AuthMode: string(publication.AccessMode), HTPasswdPath: credentialPath, CIDRs: append([]string(nil), publication.CIDRs...), UpstreamNetwork: upstreamNetwork, UpstreamAddress: upstreamAddress, WebSocket: resource.Target.WebSocket.Enabled, Static: append([]nginx.StaticRoute(nil), staticRoutes...)}
	entry := nginx.Entry{Kind: nginx.EntryApp, ResourceID: resource.ID, Relative: relative, Digest: "sha256:" + strings.Repeat("0", 64), Domains: hosts, Listeners: []string{"tcp:0.0.0.0:80", "tcp:0.0.0.0:443", "tcp:[::]:80", "tcp:[::]:443"}, Generation: generation, Domain: &site}
	slices.Sort(entry.Listeners)
	data, err := nginx.RenderEntry(entry)
	if err != nil {
		return Candidate{}, err
	}
	entry.Digest = digest(data)
	entryPath := filepath.Join(nginx.FixedPaths().ConfigRoot, filepath.FromSlash(relative))
	routeIdentities := make([]string, len(staticRoutes))
	routeBundles := make([]domain.StaticRouteBundleIdentity, len(staticRoutes))
	managedPaths := []string{entryPath, certificate.PointerIdentity}
	for index, route := range staticRoutes {
		routeIdentities[index] = digest([]byte(route.URLPath + "\x00" + route.SourcePath + "\x00" + fmt.Sprint(route.Directory) + "\x00" + route.Identity))
		routeBundles[index] = domain.StaticRouteBundleIdentity{URLPath: route.URLPath, RelativePath: route.RelativePath, SourcePath: route.SourcePath, Directory: route.Directory, Anonymous: route.Anonymous, Fingerprint: route.Identity}
	}
	credentialIDs := []string{}
	if publication.CredentialID != "" {
		credentialIDs = []string{publication.CredentialID}
	}
	bundle := domain.PublicationBundle{ID: fmt.Sprintf("pub_%d_%s", generation, strings.TrimPrefix(resource.ID, "res_")), Generation: generation, ConfigDigest: resource.CurrentConfigDigest, Kind: domain.PublicationDomainHTTPS, EndpointIdentity: applied.PolicyDigest, SiteIdentity: entry.Digest, ManagedPaths: managedPaths, CredentialIDs: credentialIDs, Listeners: []domain.BundleListenerIdentity{{Network: "tcp", Port: 80}, {Network: "tcp", Port: 443}}, DomainHTTPS: &domain.DomainHTTPSBundleIdentity{ExactDomains: hosts, Certificate: certificate, Auth: domain.AuthBundleIdentity{Mode: publication.AccessMode, CredentialIdentity: publication.CredentialID, ReferenceIdentity: authIdentity}, Static: domain.StaticBundleIdentity{RootID: publication.StaticRootID, Routes: routeBundles, RouteIdentities: routeIdentities}, GoAccess: domain.GoAccessBundleIdentity{Enabled: false}, EdgeOne: domain.EdgeOneBundleIdentity{Enabled: false}}}
	bundleDigest, err := BundleDigest(bundle)
	if err != nil {
		return Candidate{}, err
	}
	priorGeneration := uint64(0)
	if prior := resource.PublicationRecord.LastAppliedBundle; prior != nil && prior.DomainHTTPS != nil && prior.DomainHTTPS.Certificate.Authority != nil && prior.DomainHTTPS.Certificate.Authority.CertificateID == certificate.Authority.CertificateID {
		priorGeneration = prior.DomainHTTPS.Certificate.Generation
	}
	candidatePath, err := certificates.BundlePath(certificate.Authority.CertificateID, certificate.Generation)
	if err != nil {
		return Candidate{}, err
	}
	pointer := &certificates.Pointer{CertificateID: certificate.Authority.CertificateID, CandidateGeneration: certificate.Generation, ExpectedPriorGeneration: priorGeneration}
	prior, priorDigest, err := priorPublication(resource)
	if err != nil {
		return Candidate{}, err
	}
	return Candidate{ResourceID: resource.ID, Generation: generation, Bundle: bundle, BundleDigest: bundleDigest, Entry: entry, EntryBytes: data, OwnershipPath: ownership.OwnedPath{Kind: ownership.PathSite, Path: entryPath, IdentityDigest: ownership.PathIdentity(resource.ID, ownership.PathSite, entryPath)}, OwnershipListeners: []ownership.OwnedListener{}, PublicURL: "https://" + publication.CanonicalDomain + "/", CertificatePointer: pointer, CertificateCandidatePath: candidatePath, PriorBundle: prior, PriorBundleDigest: priorDigest}, nil
}
func priorPublication(resource domain.AppResource) (*domain.PublicationBundle, string, error) {
	if resource.PublicationRecord.LastAppliedBundle == nil {
		return nil, "", nil
	}
	bundle := *resource.PublicationRecord.LastAppliedBundle
	value, err := BundleDigest(bundle)
	if err != nil {
		return nil, "", err
	}
	return &bundle, value, nil
}

func BundleDigest(bundle domain.PublicationBundle) (string, error) {
	raw, err := json.Marshal(bundle)
	if err != nil {
		return "", err
	}
	return digest(raw), nil
}
func RequireBundleDigest(bundle domain.PublicationBundle, expected string) error {
	actual, err := BundleDigest(bundle)
	if err != nil {
		return err
	}
	if len(actual) != len(expected) || subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) != 1 {
		return fmt.Errorf("publication bundle digest mismatched")
	}
	return nil
}
func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
