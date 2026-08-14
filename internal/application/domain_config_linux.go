//go:build linux

package application

import (
	"fmt"
	"lanpanel/internal/domain"
	"slices"
)

const DomainPublicationUpdateSchema = "lanpanel.domain-publication.update.v1"

type DomainPublicationUpdate struct {
	SchemaVersion string                        `json:"schema_version"`
	ResourceID    string                        `json:"resource_id"`
	Publication   domain.DomainHTTPSPublication `json:"publication"`
}

func DomainPublicationCandidate(update DomainPublicationUpdate) (domain.AppResource, error) {
	if update.SchemaVersion != DomainPublicationUpdateSchema || update.ResourceID == "" {
		return domain.AppResource{}, fmt.Errorf("domain publication update invalid")
	}
	service, err := OpenFixed()
	if err != nil {
		return domain.AppResource{}, err
	}
	defer service.Close()
	document, err := service.normal.Read()
	if err != nil {
		return domain.AppResource{}, err
	}
	_, resource, err := loadCertificateResource(document.Entries, update.ResourceID)
	if err != nil {
		return domain.AppResource{}, err
	}
	if err := requireAppliedDomainSourcesHealthy(resource); err != nil {
		return domain.AppResource{}, err
	}
	priorCredential := ""
	if resource.Publication.DomainHTTPS != nil {
		priorCredential = resource.Publication.DomainHTTPS.CredentialID
	}
	resource.Publication = domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &update.Publication}
	if priorCredential != "" && priorCredential != update.Publication.CredentialID {
		resource.CredentialIDs = slices.DeleteFunc(resource.CredentialIDs, func(value string) bool { return value == priorCredential })
	}
	if update.Publication.CredentialID != "" && !slices.Contains(resource.CredentialIDs, update.Publication.CredentialID) {
		resource.CredentialIDs = append(resource.CredentialIDs, update.Publication.CredentialID)
	}
	slices.Sort(resource.CredentialIDs)
	return resource, nil
}
