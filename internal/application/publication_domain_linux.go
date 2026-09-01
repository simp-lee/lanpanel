//go:build linux

package application

import (
	"context"
	"encoding/json"
	"fmt"
	"lanpanel/internal/acme"
	"lanpanel/internal/acmeaccount"
	"lanpanel/internal/domain"
	goaccessruntime "lanpanel/internal/goaccess"
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
	ResourceID                    string    `json:"resource_id"`
	Status                        string    `json:"status"`
	AccessMayRemain               bool      `json:"access_may_remain"`
	CredentialID                  string    `json:"credential_id,omitempty"`
	CredentialFingerprint         string    `json:"credential_fingerprint,omitempty"`
	CredentialChanged             bool      `json:"credential_changed,omitempty"`
	GoAccessCredentialID          string    `json:"goaccess_credential_id,omitempty"`
	GoAccessCredentialFingerprint string    `json:"goaccess_credential_fingerprint,omitempty"`
	GoAccessCredentialChanged     bool      `json:"goaccess_credential_changed,omitempty"`
	StaticFingerprint             string    `json:"static_fingerprint,omitempty"`
	StaticChanged                 bool      `json:"static_changed,omitempty"`
	ObservedAt                    time.Time `json:"observed_at"`
	Reason                        string    `json:"reason"`
	AllowedActions                []string  `json:"allowed_actions"`
	CredentialIDs                 []string  `json:"credential_ids,omitempty"`
	GoAccessRetirementJobID       string    `json:"goaccess_retirement_job_id,omitempty"`
	GoAccessRetirementGenerations []uint64  `json:"goaccess_retirement_generations,omitempty"`
}

func ObserveDomainLiveSources(resourceID string) (result DomainSourceStatus, resultErr error) {
	result = DomainSourceStatus{ResourceID: resourceID, Status: "unknown", ObservedAt: time.Now().UTC()}
	service, err := OpenFixed()
	if err != nil {
		return result, err
	}
	defer func(ignore func() error) { _ = ignore() }(service.Close)
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
	if len(resource.PublicationRecord.PendingGoAccessRetirements) > 0 {
		result.Status = "degraded"
		result.AccessMayRemain = true
		result.Reason = "GoAccess retirement pending"
		result.AllowedActions = []string{"unpublish", "close_all"}
		result.GoAccessRetirementJobID = resource.PublicationRecord.GoAccessRetirementSourceJobID
		for _, item := range resource.PublicationRecord.PendingGoAccessRetirements {
			result.GoAccessRetirementGenerations = append(result.GoAccessRetirementGenerations, item.Generation)
		}
		return result, nil
	}
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
		result.CredentialID = credential.ID
		result.CredentialFingerprint = observed.Fingerprint
		result.CredentialChanged = observed.Fingerprint != credential.Fingerprint && credential.Kind == "external_htpasswd"
		if credential.Kind == "managed_basic" && observed.Fingerprint != credential.Fingerprint {
			return degradedDomainStatus(result, "managed Basic drift"), nil
		}

	}
	if bundle.GoAccess.Enabled {
		var credential *domain.Credential
		for index := range installation.Credentials {
			if installation.Credentials[index].ID == bundle.GoAccess.CredentialIdentity {
				credential = &installation.Credentials[index]
			}
		}
		if credential == nil || credential.Kind != "external_htpasswd" {
			return degradedDomainStatus(result, "applied GoAccess credential missing"), nil
		}
		gid, groupErr := nginxGroupGID()
		if groupErr != nil {
			return result, groupErr
		}
		observed, observeErr := htpasswdref.Validate(credential.ExternalPath, gid)
		if observeErr != nil {
			return degradedDomainStatus(result, "applied GoAccess htpasswd unsafe"), nil
		}
		result.GoAccessCredentialID = credential.ID
		result.GoAccessCredentialFingerprint = observed.Fingerprint
		result.GoAccessCredentialChanged = observed.Fingerprint != credential.Fingerprint
		runtimeHost, hostErr := goaccessruntime.NewFixedHost()
		runtimeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if hostErr == nil {
			hostErr = func() error {
				candidate, candidateErr := goaccessruntime.ObserveCandidate(installation.InstallationID, resource.ID, gid, bundle.GoAccess)
				if candidateErr != nil {
					return candidateErr
				}
				return runtimeHost.Verify(runtimeCtx, candidate)
			}()
		}
		cancel()
		if hostErr != nil {
			return degradedDomainStatus(result, "applied GoAccess service unavailable"), nil
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
	result.Status = "source_verified_runtime_unknown"
	result.Reason = "source identities exact; runtime health is not proved by source verification"
	if result.CredentialChanged && result.GoAccessCredentialChanged {
		result.Reason = "App and GoAccess external htpasswd fingerprints changed but remain valid"
	} else if result.CredentialChanged {
		result.Reason = "App external htpasswd fingerprint changed but remains valid"
	} else if result.GoAccessCredentialChanged {
		result.Reason = "GoAccess external htpasswd fingerprint changed but remains valid"
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
	if status.Status == "degraded" || status.AccessMayRemain {
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

func requireGoAccessServiceTransition(resource domain.AppResource) error {
	configured := resource.Publication.DomainHTTPS
	applied := resource.PublicationRecord.LastAppliedBundle
	if configured == nil || !configured.GoAccess.Enabled || resource.PublicationRecord.State != domain.PublicationPublished || applied == nil || applied.DomainHTTPS == nil || !applied.DomainHTTPS.GoAccess.Enabled {
		return nil
	}
	goaccess := applied.DomainHTTPS.GoAccess
	if goaccess.CanonicalHost != configured.CanonicalDomain || goaccess.WebSocketPath != configured.GoAccess.WebSocketPath {
		return fmt.Errorf("active GoAccess service identity change requires an explicit disable publication first")
	}
	return nil
}

func requireGoAccessRetirementComplete(ctx context.Context, service *FixedService, resource domain.AppResource) error {
	if len(resource.PublicationRecord.PendingGoAccessRetirements) > 0 {
		return fmt.Errorf("GoAccess retirement reconciliation pending")
	}
	bundle := resource.PublicationRecord.LastAppliedBundle
	if bundle == nil || bundle.DomainHTTPS == nil || bundle.DomainHTTPS.GoAccess.RetiredGeneration == 0 {
		return nil
	}
	goaccess := bundle.DomainHTTPS.GoAccess
	host, err := goaccessruntime.NewFixedHost()
	if err != nil {
		return err
	}
	removeState := goaccess.RemovesRetiredState()
	complete, err := host.RetirementComplete(ctx, resource.ID, goaccess.RetiredGeneration, goaccess.RetiredStateGeneration, removeState)
	if err != nil {
		return err
	}
	if !complete {
		return fmt.Errorf("GoAccess retirement is incomplete")
	}
	return requireRetiredGoAccessOwnershipComplete(service, resource.ID, goaccess.RetiredGeneration, goaccess.RetiredStateGeneration, removeState)
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
	if publication.GoAccess.Enabled {
		gid, gidErr := nginxGroupGID()
		if gidErr != nil {
			return plans.Evidence{}, gidErr
		}
		found := false
		for _, credential := range installation.Credentials {
			if credential.ID != publication.GoAccess.CredentialID {
				continue
			}
			if credential.Kind != "external_htpasswd" || credential.OwnerResourceID != resource.ID {
				return plans.Evidence{}, fmt.Errorf("GoAccess credential authority changed")
			}
			observed, observeErr := htpasswdref.Validate(credential.ExternalPath, gid)
			if observeErr != nil {
				return plans.Evidence{}, observeErr
			}
			identities = append(identities, "goaccess", credential.ID, credential.ExternalPath, observed.Fingerprint)
			found = true
		}
		if !found {
			return plans.Evidence{}, fmt.Errorf("GoAccess external credential missing")
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
	accountContact, accountKeyFingerprint, contactErr := readManagedACMEAccountAuthority()
	if contactErr != nil {
		return acme.Binding{}, "", contactErr
	}
	var binding acme.Binding
	var err error
	if request.ChallengeMethod == "http-01" {
		binding, err = acme.LoadHTTPBinding(request.DirectoryURL, acmeaccount.ManagedKeyPath, accountContact, request.TermsAccepted)
	} else {
		provider, parseErr := acme.ParseDNSProvider(request.DNSProvider)
		if parseErr != nil {
			return acme.Binding{}, "", parseErr
		}
		binding, err = acme.LoadDNSBinding(request.DirectoryURL, acmeaccount.ManagedKeyPath, accountContact, request.TermsAccepted, provider, request.ProviderProfilePath, request.AuthoritativeZone)
	}
	if err != nil {
		return acme.Binding{}, "", err
	}
	if binding.AccountKeyFingerprint != accountKeyFingerprint {
		return acme.Binding{}, "", fmt.Errorf("managed ACME account key changed after installation verification")
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
	goaccessPath, goaccessFingerprint := "", ""
	var goaccessCandidate *goaccessruntime.Candidate
	if publicationConfig.GoAccess.Enabled {
		var credential *domain.Credential
		for index := range installation.Credentials {
			if installation.Credentials[index].ID == publicationConfig.GoAccess.CredentialID {
				credential = &installation.Credentials[index]
			}
		}
		if credential == nil || credential.Kind != "external_htpasswd" {
			return publication.Candidate{}, fmt.Errorf("GoAccess external htpasswd missing")
		}
		gid, groupErr := nginxGroupGID()
		if groupErr != nil {
			return publication.Candidate{}, groupErr
		}
		observed, observeErr := htpasswdref.Validate(credential.ExternalPath, gid)
		if observeErr != nil {
			return publication.Candidate{}, observeErr
		}
		candidate, renderErr := goaccessruntime.Render(installation.InstallationID, resource, gid, generation)
		if renderErr != nil {
			return publication.Candidate{}, renderErr
		}
		goaccessPath = credential.ExternalPath
		goaccessFingerprint = observed.Fingerprint
		goaccessCandidate = &candidate
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
	return publication.PrepareDomain(resource, generation, certificate, credentialPath, credentialFingerprint, goaccessPath, goaccessFingerprint, routes, goaccessCandidate)
}

func nginxGroupGID() (uint32, error) {
	group, err := user.LookupGroup("www-data")
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil || value == 0 {
		return 0, fmt.Errorf("nginx group identity invalid")
	}
	return uint32(value), nil
}

func protectedStaticPaths(installation domain.Installation, excluded ...string) []string {
	paths := append([]string(nil), installation.ManagedPaths...)
	paths = append(paths, "/var/lib/lanpanel", "/var/log/lanpanel/goaccess", "/run/lanpanel", "/run/lanpanel-goaccess", "/etc/lanpanel", "/etc/lanpanel-public", "/etc/systemd/system", "/etc/sysusers.d", "/usr/lib/lanpanel")
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
		if bundle := resource.PublicationRecord.LastAppliedBundle; bundle != nil {
			paths = append(paths, bundle.ManagedPaths...)
		}
		if intent := resource.PublicationRecord.ActivationIntent; intent != nil {
			paths = append(paths, intent.Candidate.ManagedPaths...)
			if intent.Prior != nil {
				paths = append(paths, intent.Prior.ManagedPaths...)
			}
		}
		if resource.ManagedProcess != nil {
			paths = append(paths, resource.ManagedProcess.Service.Executable, resource.ManagedProcess.Service.EnvironmentFile)
			paths = append(paths, resource.ManagedProcess.Service.WritePaths...)
		}
	}
	return paths
}
