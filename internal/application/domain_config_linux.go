//go:build linux

package application

import (
	"fmt"
	"lanpanel/internal/acmeaccount"
	"lanpanel/internal/domain"
	"lanpanel/internal/htpasswdref"
	"slices"
)

const DomainPublicationUpdateSchema = domain.DomainPublicationUpdateSchema

type DomainPublicationUpdate = domain.DomainPublicationUpdate

func DomainPublicationCandidate(update DomainPublicationUpdate) (domain.AppResource, error) {
	if err := domain.ValidateDomainPublicationUpdate(update); err != nil {
		return domain.AppResource{}, err
	}
	service, err := OpenFixed()
	if err != nil {
		return domain.AppResource{}, err
	}
	defer func(ignore func() error) { _ = ignore() }(service.Close)
	document, err := service.normal.Read()
	if err != nil {
		return domain.AppResource{}, err
	}
	installation, resource, err := loadCertificateResource(document.Entries, update.ResourceID)
	if err != nil {
		return domain.AppResource{}, err
	}
	if err := requireAppliedDomainSourcesHealthy(resource); err != nil {
		return domain.AppResource{}, err
	}
	if update.Publication.Certificate != nil && !acmeaccount.ValidContact(update.Publication.Certificate.AccountEmail) {
		return domain.AppResource{}, fmt.Errorf("ACME account contact is invalid")
	}
	priorCredential, priorGoAccessCredential := "", ""
	if resource.Publication.DomainHTTPS != nil {
		priorCredential = resource.Publication.DomainHTTPS.CredentialID
		priorGoAccessCredential = resource.Publication.DomainHTTPS.GoAccess.CredentialID
	}
	resource.Publication = domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &update.Publication}
	for _, prior := range []string{priorCredential, priorGoAccessCredential} {
		if prior != "" && prior != update.Publication.CredentialID && prior != update.Publication.GoAccess.CredentialID {
			resource.CredentialIDs = slices.DeleteFunc(resource.CredentialIDs, func(value string) bool { return value == prior })
		}
	}
	for _, candidate := range []string{update.Publication.CredentialID, update.Publication.GoAccess.CredentialID} {
		if candidate != "" && !slices.Contains(resource.CredentialIDs, candidate) {
			resource.CredentialIDs = append(resource.CredentialIDs, candidate)
		}
	}
	slices.Sort(resource.CredentialIDs)
	if update.Publication.GoAccess.Enabled {
		gid, gidErr := nginxGroupGID()
		if gidErr != nil {
			return domain.AppResource{}, gidErr
		}
		found := false
		for _, credential := range installation.Credentials {
			if credential.ID != update.Publication.GoAccess.CredentialID {
				continue
			}
			if credential.Kind != "external_htpasswd" || credential.OwnerResourceID != resource.ID || credential.ExternalPath == "" {
				return domain.AppResource{}, fmt.Errorf("GoAccess candidate credential authority invalid")
			}
			if _, validateErr := htpasswdref.Validate(credential.ExternalPath, gid); validateErr != nil {
				return domain.AppResource{}, validateErr
			}
			found = true
		}
		if !found {
			return domain.AppResource{}, fmt.Errorf("GoAccess candidate credential missing")
		}
	}
	return resource, nil
}
