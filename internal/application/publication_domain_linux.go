//go:build linux

package application

import (
	"encoding/json"
	"fmt"
	"lanpanel/internal/acme"
	"lanpanel/internal/domain"
	"lanpanel/internal/htpasswdref"
	"lanpanel/internal/nginx"
	"lanpanel/internal/plans"
	"lanpanel/internal/publication"
	staticcontent "lanpanel/internal/static"
	"os/user"
	"slices"
	"strconv"
	"time"
)

type DomainSourceStatus struct {
	ResourceID            string    `json:"resource_id"`
	Status                string    `json:"status"`
	AccessMayRemain       bool      `json:"access_may_remain"`
	CredentialFingerprint string    `json:"credential_fingerprint,omitempty"`
	CredentialChanged     bool      `json:"credential_changed,omitempty"`
	StaticFingerprint     string    `json:"static_fingerprint,omitempty"`
	StaticChanged         bool      `json:"static_changed,omitempty"`
	ObservedAt            time.Time `json:"observed_at"`
	Reason                string    `json:"reason"`
	AllowedActions        []string  `json:"allowed_actions"`
	CredentialIDs         []string  `json:"credential_ids,omitempty"`
}

func ObserveDomainLiveSources(resourceID string) (result DomainSourceStatus, resultErr error) {
	result = DomainSourceStatus{ResourceID: resourceID, Status: "healthy", ObservedAt: time.Now().UTC()}
	service, err := OpenFixed()
	if err != nil {
		return result, err
	}
	defer service.Close()
	document, err := service.normal.Read()
	if err != nil {
		return result, err
	}
	installation, resource, err := loadCertificateResource(document.Entries, resourceID)
	if err != nil {
		return result, err
	}
	for _, credential := range installation.Credentials {
		if credential.OwnerResourceID == resourceID {
			result.CredentialIDs = append(result.CredentialIDs, credential.ID)
		}
	}
	slices.Sort(result.CredentialIDs)
	if resource.PublicationRecord.State != domain.PublicationPublished || resource.PublicationRecord.LastAppliedBundle == nil || resource.PublicationRecord.LastAppliedBundle.DomainHTTPS == nil {
		result.Reason = "no applied domain publication"
		return result, nil
	}
	bundle := resource.PublicationRecord.LastAppliedBundle.DomainHTTPS
	if bundle.Auth.Mode == domain.AppAccessBasic {
		credentialID := bundle.Auth.CredentialIdentity
		var credential *domain.Credential
		for index := range installation.Credentials {
			if installation.Credentials[index].ID == credentialID {
				credential = &installation.Credentials[index]
			}
		}
		if credential == nil {
			return degradedDomainStatus(result, "applied credential missing"), nil
		}
		path := credential.ExternalPath
		if credential.Kind == "managed_basic" {
			path = credential.ManagedPath
		}
		gid, err := nginxGroupGID()
		if err != nil {
			return result, err
		}
		observed, err := htpasswdref.Validate(path, gid)
		if err != nil {
			return degradedDomainStatus(result, "applied htpasswd unsafe"), nil
		}
		if credential.Kind == "managed_basic" && observed.Mode != 0o640 {
			return degradedDomainStatus(result, "managed Basic mode changed"), nil
		}
		result.CredentialFingerprint = observed.Fingerprint
		result.CredentialChanged = observed.Fingerprint != credential.Fingerprint && credential.Kind == "external_htpasswd"
		expectedReference := shaDigest([]byte(credential.ID + "\x00" + path))
		if bundle.Auth.ReferenceIdentity != expectedReference {
			return degradedDomainStatus(result, "applied credential reference changed"), nil
		}
		if credential.Kind == "managed_basic" && observed.Fingerprint != credential.Fingerprint {
			return degradedDomainStatus(result, "managed Basic drift"), nil
		}

	}
	if len(bundle.Static.Routes) > 0 {
		var root *domain.StaticContentRoot
		for index := range installation.StaticRoots {
			if installation.StaticRoots[index].ID == bundle.Static.RootID {
				root = &installation.StaticRoots[index]
			}
		}
		if root == nil {
			return degradedDomainStatus(result, "applied static root missing"), nil
		}
		identity, err := staticcontent.Register(root.ID, root.Path, protectedStaticPaths(installation, root.Path))
		if err != nil || identity.Fingerprint != root.Fingerprint || identity.Device != root.Device {
			return degradedDomainStatus(result, "applied static root unsafe"), nil
		}
		mappings := make([]staticcontent.Mapping, len(bundle.Static.Routes))
		for index, route := range bundle.Static.Routes {
			mappings[index] = staticcontent.Mapping{URLPath: route.URLPath, RelativePath: route.RelativePath, Directory: route.Directory, Anonymous: route.Anonymous}
		}
		observed, err := staticcontent.ValidateMappings(identity, mappings)
		if err != nil {
			return degradedDomainStatus(result, "applied static source unsafe"), nil
		}
		identities := []string{}
		for index, value := range observed {
			if value.SourcePath != bundle.Static.Routes[index].SourcePath {
				return degradedDomainStatus(result, "applied static path changed"), nil
			}
			identities = append(identities, value.Fingerprint)
			result.StaticChanged = result.StaticChanged || value.Fingerprint != bundle.Static.Routes[index].Fingerprint
		}
		raw, _ := json.Marshal(identities)
		result.StaticFingerprint = shaDigest(raw)
		if result.StaticChanged {
			return degradedDomainStatus(result, "static source changed"), nil
		}
	}
	result.Reason = "source identities exact"
	if result.CredentialChanged {
		result.Reason = "external htpasswd fingerprint changed but remains valid"
	}
	return result, nil
}
func requireNoDegradedAppliedSource(resourceID string) error {
	service, err := OpenFixed()
	if err != nil {
		return err
	}
	document, err := service.normal.Read()
	_ = service.Close()
	if err != nil {
		return err
	}
	_, resource, err := loadCertificateResource(document.Entries, resourceID)
	if err != nil {
		return err
	}
	return requireAppliedDomainSourcesHealthy(resource)
}
func requireAppliedDomainSourcesHealthy(resource domain.AppResource) error {
	if resource.PublicationRecord.State != domain.PublicationPublished || resource.PublicationRecord.LastAppliedBundle == nil || resource.PublicationRecord.LastAppliedBundle.DomainHTTPS == nil {
		return nil
	}
	status, err := ObserveDomainLiveSources(resource.ID)
	if err != nil {
		return err
	}
	if status.Status != "healthy" || status.AccessMayRemain {
		return fmt.Errorf("applied domain source degraded; unpublish required")
	}
	return nil
}
func degradedDomainStatus(value DomainSourceStatus, reason string) DomainSourceStatus {
	value.Status = "degraded"
	value.AccessMayRemain = true
	value.Reason = reason
	value.AllowedActions = []string{"unpublish", "close_all"}
	return value
}

func observeDomainSources(service *FixedService, resource domain.AppResource) (plans.Evidence, error) {
	document, err := service.normal.Read()
	if err != nil {
		return plans.Evidence{}, err
	}
	installation, err := domain.DecodeInstallation(document.Entries["installations/current"])
	if err != nil {
		return plans.Evidence{}, err
	}
	publication := resource.Publication.DomainHTTPS
	if publication == nil {
		return plans.Evidence{}, fmt.Errorf("domain publication missing")
	}
	identities := []string{}
	if publication.AccessMode == domain.AppAccessBasic {
		gid, err := nginxGroupGID()
		if err != nil {
			return plans.Evidence{}, err
		}
		for _, credential := range installation.Credentials {
			if credential.ID != publication.CredentialID {
				continue
			}
			path := credential.ExternalPath
			if credential.Kind == "managed_basic" {
				path = credential.ManagedPath
			}
			observed, err := htpasswdref.Validate(path, gid)
			if err != nil {
				return plans.Evidence{}, err
			}
			if credential.Kind == "managed_basic" && observed.Mode != 0o640 {
				return plans.Evidence{}, fmt.Errorf("managed Basic mode changed")
			}
			if credential.Kind == "managed_basic" && observed.Fingerprint != credential.Fingerprint {
				return plans.Evidence{}, fmt.Errorf("managed Basic credential changed")
			}
			identities = append(identities, credential.ID, path, observed.Fingerprint)
		}
		if len(identities) == 0 {
			return plans.Evidence{}, fmt.Errorf("domain Basic credential missing")
		}
	}
	if publication.StaticRootID != "" {
		var root *domain.StaticContentRoot
		for index := range installation.StaticRoots {
			if installation.StaticRoots[index].ID == publication.StaticRootID {
				root = &installation.StaticRoots[index]
			}
		}
		if root == nil {
			return plans.Evidence{}, fmt.Errorf("static root authority missing")
		}
		identity, err := staticcontent.Register(root.ID, root.Path, protectedStaticPaths(installation, root.Path))
		if err != nil {
			return plans.Evidence{}, err
		}
		if identity.Fingerprint != root.Fingerprint || identity.Device != root.Device {
			return plans.Evidence{}, fmt.Errorf("static root identity changed")
		}
		mappings := make([]staticcontent.Mapping, len(publication.StaticMappings))
		for index, value := range publication.StaticMappings {
			mappings[index] = staticcontent.Mapping{URLPath: value.URLPath, RelativePath: value.RelativePath, Directory: value.Directory, Anonymous: value.Anonymous}
		}
		observed, err := staticcontent.ValidateMappings(identity, mappings)
		if err != nil {
			return plans.Evidence{}, err
		}
		identities = append(identities, root.ID, root.Path, root.Fingerprint)
		for _, value := range observed {
			identities = append(identities, value.Mapping.URLPath, value.SourcePath, value.Fingerprint)
		}
	}
	raw, err := json.Marshal(identities)
	if err != nil {
		return plans.Evidence{}, err
	}
	return plans.Evidence{Kind: "domain_sources", Identity: "resource/" + resource.ID, Generation: resource.PublicationRecord.UnpublishedGeneration, Digest: shaDigest(raw), ObservedAt: time.Now().UTC()}, nil
}

func candidateACMEBinding(resource domain.AppResource) (acme.Binding, string, error) {
	publication := resource.Publication.DomainHTTPS
	if publication == nil || publication.Certificate == nil {
		return acme.Binding{}, "", fmt.Errorf("domain certificate request missing")
	}
	request := publication.Certificate
	var binding acme.Binding
	var err error
	if request.ChallengeMethod == "http-01" {
		binding, err = acme.LoadHTTPBinding(request.DirectoryURL, request.AccountKeyPath, request.AccountEmail, request.TermsAccepted)
	} else {
		provider, parseErr := acme.ParseDNSProvider(request.DNSProvider)
		if parseErr != nil {
			return acme.Binding{}, "", parseErr
		}
		binding, err = acme.LoadDNSBinding(request.DirectoryURL, request.AccountKeyPath, request.AccountEmail, request.TermsAccepted, provider, request.ProviderProfilePath, request.AuthoritativeZone)
	}
	if err != nil {
		return acme.Binding{}, "", err
	}
	digest, err := acme.BindingDigest(binding)
	return binding, digest, err
}
func prepareDomainCandidate(service *FixedService, resource domain.AppResource, generation uint64, certificate domain.CertificateBundleIdentity) (publication.Candidate, error) {
	document, err := service.normal.Read()
	if err != nil {
		return publication.Candidate{}, err
	}
	raw, present := document.Entries["installations/current"]
	if !present {
		return publication.Candidate{}, fmt.Errorf("installation authority missing")
	}
	installation, err := domain.DecodeInstallation(raw)
	if err != nil {
		return publication.Candidate{}, err
	}
	publicationConfig := resource.Publication.DomainHTTPS
	if publicationConfig == nil {
		return publication.Candidate{}, fmt.Errorf("domain publication config missing")
	}
	credentialPath, credentialFingerprint := "", ""
	if publicationConfig.AccessMode == domain.AppAccessBasic {
		var credential *domain.Credential
		for index := range installation.Credentials {
			if installation.Credentials[index].ID == publicationConfig.CredentialID {
				credential = &installation.Credentials[index]
			}
		}
		if credential == nil {
			return publication.Candidate{}, fmt.Errorf("domain Basic credential missing")
		}
		credentialPath = credential.ExternalPath
		if credential.Kind == "managed_basic" {
			credentialPath = credential.ManagedPath
		}
		gid, err := nginxGroupGID()
		if err != nil {
			return publication.Candidate{}, err
		}
		observed, err := htpasswdref.Validate(credentialPath, gid)
		if err != nil {
			return publication.Candidate{}, err
		}
		if credential.Kind == "managed_basic" && observed.Mode != 0o640 {
			return publication.Candidate{}, fmt.Errorf("managed Basic mode changed")
		}
		if credential.Kind == "managed_basic" && observed.Fingerprint != credential.Fingerprint {
			return publication.Candidate{}, fmt.Errorf("managed Basic credential changed")
		}
		credentialFingerprint = observed.Fingerprint
	}
	routes := []nginx.StaticRoute{}
	if publicationConfig.StaticRootID != "" {
		var root *domain.StaticContentRoot
		for index := range installation.StaticRoots {
			if installation.StaticRoots[index].ID == publicationConfig.StaticRootID {
				root = &installation.StaticRoots[index]
			}
		}
		if root == nil {
			return publication.Candidate{}, fmt.Errorf("static root authority missing")
		}
		identity, err := staticcontent.Register(root.ID, root.Path, protectedStaticPaths(installation, root.Path))
		if err != nil {
			return publication.Candidate{}, err
		}
		if identity.Fingerprint != root.Fingerprint || identity.Device != root.Device {
			return publication.Candidate{}, fmt.Errorf("static root identity changed")
		}
		mappings := make([]staticcontent.Mapping, len(publicationConfig.StaticMappings))
		for index, value := range publicationConfig.StaticMappings {
			mappings[index] = staticcontent.Mapping{URLPath: value.URLPath, RelativePath: value.RelativePath, Directory: value.Directory, Anonymous: value.Anonymous}
		}
		slices.SortFunc(mappings, func(a, b staticcontent.Mapping) int {
			if a.URLPath < b.URLPath {
				return -1
			}
			if a.URLPath > b.URLPath {
				return 1
			}
			return 0
		})
		observed, err := staticcontent.ValidateMappings(identity, mappings)
		if err != nil {
			return publication.Candidate{}, err
		}
		for _, value := range observed {
			routes = append(routes, nginx.StaticRoute{URLPath: value.Mapping.URLPath, RelativePath: value.Mapping.RelativePath, SourcePath: value.SourcePath, Directory: value.Mapping.Directory, Anonymous: value.Mapping.Anonymous, Identity: value.Fingerprint})
		}
	}
	return publication.PrepareDomain(resource, generation, certificate, credentialPath, credentialFingerprint, routes)
}
func nginxGroupGID() (uint32, error) {
	group, err := user.LookupGroup("www-data")
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil || value == 0 {
		return 0, fmt.Errorf("Nginx group identity invalid")
	}
	return uint32(value), nil
}
func protectedStaticPaths(installation domain.Installation, excluded ...string) []string {
	paths := append([]string(nil), installation.ManagedPaths...)
	paths = append(paths, "/var/lib/lanpanel", "/run/lanpanel", "/etc/lanpanel", "/etc/lanpanel-public", "/usr/lib/lanpanel")
	for _, root := range installation.StaticRoots {
		if len(excluded) == 0 || root.Path != excluded[0] {
			paths = append(paths, root.Path)
		}
	}
	for _, credential := range installation.Credentials {
		if credential.ManagedPath != "" {
			paths = append(paths, credential.ManagedPath)
		}
		if credential.ExternalPath != "" {
			paths = append(paths, credential.ExternalPath)
		}
	}
	for _, resource := range installation.Resources {
		paths = append(paths, resource.ManagedPaths...)
		if resource.ManagedProcess != nil {
			paths = append(paths, resource.ManagedProcess.Service.Executable, resource.ManagedProcess.Service.EnvironmentFile)
			paths = append(paths, resource.ManagedProcess.Service.WritePaths...)
		}
	}
	return paths
}
