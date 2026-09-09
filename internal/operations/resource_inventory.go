package operations

import (
	"bytes"
	"fmt"
	"lanpanel/internal/certificates"
	"lanpanel/internal/domain"
	"lanpanel/internal/jobs"
	"lanpanel/internal/ownership"
	"lanpanel/internal/persist"
	appresource "lanpanel/internal/resource"
	"reflect"
	"slices"
	"strings"
)

func validateResourceDeleteBinding(operation Type, safety SafetyBinding, binding *ResourceDeleteBinding) error {
	if operation != ResourceDelete {
		if binding != nil {
			return fmt.Errorf("resource deletion inventory on another operation")
		}
		return nil
	}
	if binding == nil || !strings.HasPrefix(binding.InstallationID, "ins_") || !validIdentityRef(binding.InstallationID) {
		return fmt.Errorf("resource deletion inventory missing")
	}
	resource := binding.Resource
	paths, err := appresource.DerivePaths(resource.ID)
	if err != nil {
		return err
	}
	digest, err := appresource.ConfigDigest(resource)
	owned := binding.Ownership
	if err != nil || resource.ID != safety.ResourceID || digest != resource.CurrentConfigDigest || digest != safety.CandidateDigest || resource.Lifecycle != domain.LifecycleActive || resource.PublicationRecord.State != domain.PublicationUnpublished || resource.PublicationRecord.ActivationIntent != nil || resource.PublicationRecord.ContractionIntent != nil || len(resource.PublicationRecord.PendingGoAccessRetirements) != 0 || resource.ManagedProcess != nil && resource.ManagedProcess.Requested != domain.ProcessRequestedStopped || owned.ResourceID != resource.ID || owned.Checksum != safety.CandidateBundle || owned.State != ownership.Owned || ownership.Validate(owned, ownership.FixedPolicy()) != nil || len(owned.Listeners) != 0 || len(owned.Paths) != 1 || owned.Paths[0].Kind != ownership.PathService || owned.Paths[0].Path != paths.ResourceRoot || owned.Paths[0].IdentityDigest != ownership.PathIdentity(resource.ID, ownership.PathService, paths.ResourceRoot) {
		return fmt.Errorf("resource deletion inventory differs from closed operation authority")
	}
	if err := certificates.ValidateArtifacts(resource.PublicationRecord.CertificateInventory); err != nil {
		return err
	}
	if bundle := resource.PublicationRecord.LastAppliedBundle; bundle != nil && bundle.DomainHTTPS != nil {
		certificate := bundle.DomainHTTPS.Certificate
		if certificate.Authority == nil {
			return fmt.Errorf("resource deletion certificate authority missing")
		}
		artifact := certificates.Artifact{CertificateID: certificate.Authority.CertificateID, Generation: certificate.Generation, Bundle: certificates.BundleIdentity{Fingerprint: certificate.Fingerprint, SANIdentity: certificate.SANIdentity, ChainIdentity: certificate.ChainIdentity, IssuerIdentity: certificate.IssuerIdentity, BindingIdentity: certificate.BindingIdentity, DirectoryIdentity: certificate.DirectoryIdentity}}
		if !slices.Contains(resource.PublicationRecord.CertificateInventory, artifact) {
			return fmt.Errorf("resource deletion certificate absent from owned inventory")
		}
	}
	return nil
}

// Do not reuse a removed resource's endpoints in the narrow cross-store
// deletion window. Its immutable intent still owns them until final cleanup.
// Contraction and read-only actions remain available.
func requireCompletedRemovedResourceDeletes(transaction *persist.Transaction) error {
	for _, key := range transaction.Keys("intents") {
		raw, _ := transaction.Get(key)
		intent, err := decodeReservation(raw)
		if err != nil {
			return err
		}
		if intent.Operation != ResourceDelete || intent.Phase == PhaseTerminal || intent.Phase == PhaseRejected {
			continue
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		present := false
		for _, resource := range installation.Resources {
			present = present || resource.ID == intent.SafetyBinding.ResourceID
		}
		if !present {
			return fmt.Errorf("resource deletion finalization is pending; endpoint allocation and expansion remain blocked")
		}
	}
	return nil
}

func matchResourceDeleteAdmission(installation domain.Installation, binding *ResourceDeleteBinding) error {
	if binding == nil || installation.InstallationID != binding.InstallationID {
		return fmt.Errorf("resource deletion installation changed")
	}
	for _, resource := range installation.Resources {
		if resource.ID == binding.Resource.ID && reflect.DeepEqual(resource, binding.Resource) {
			return nil
		}
	}
	return fmt.Errorf("resource deletion snapshot changed before admission")
}

func journalResourceArtifact(journal JournalRecord) (certificates.Artifact, bool) {
	if journal.Kind != JournalCertificateActivation || journal.Certificate == nil || (journal.Operation != Publish && journal.Operation != CertificateRenew) || len(journal.ResourceIDs) != 1 || journal.Target != "resource/"+journal.ResourceIDs[0] || certificates.ValidateBundleIdentity(journal.Certificate.CandidateBundleIdentity) != nil {
		return certificates.Artifact{}, false
	}
	return certificates.Artifact{CertificateID: journal.Certificate.CertificateID, Generation: journal.Certificate.CandidateGeneration, Bundle: journal.Certificate.CandidateBundleIdentity}, true
}

// Retain the candidate before StageIssued writes any bundle. This minimal
// ownership outlives bounded operation/job retention and survives unpublish.
func retainResourceCertificateArtifact(transaction *persist.Transaction, journal JournalRecord) error {
	artifact, applicable := journalResourceArtifact(journal)
	if !applicable {
		return nil
	}
	installation, err := loadInstallation(transaction)
	if err != nil {
		return err
	}
	for index := range installation.Resources {
		resource := &installation.Resources[index]
		if resource.ID != journal.ResourceIDs[0] {
			continue
		}
		if resource.Lifecycle != domain.LifecycleActive {
			return fmt.Errorf("cannot stage a certificate for a deleting resource")
		}
		if slices.Contains(resource.PublicationRecord.CertificateInventory, artifact) {
			return nil
		}
		resource.PublicationRecord.CertificateInventory = certificates.AddArtifact(resource.PublicationRecord.CertificateInventory, artifact)
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		return transaction.Replace("installations/current", raw)
	}
	return fmt.Errorf("certificate inventory resource missing")
}

func validateCertificateInventoryTransition(before, after persist.Document, prior, candidate domain.AppResource) error {
	expected := prior
	expected.PublicationRecord.CertificateInventory = candidate.PublicationRecord.CertificateInventory
	if prior.Lifecycle != domain.LifecycleActive || !reflect.DeepEqual(expected, candidate) {
		return fmt.Errorf("certificate inventory update changed unrelated resource authority")
	}
	for _, key := range persist.EntryKeys(after, "journals") {
		if bytes.Equal(before.Entries[key], after.Entries[key]) {
			continue
		}
		journal, err := loadJournalEntries(after.Entries, strings.TrimPrefix(key, "journals/"))
		if err != nil {
			return err
		}
		artifact, applicable := journalResourceArtifact(journal)
		if !applicable || journal.ResourceIDs[0] != prior.ID {
			continue
		}
		intent, err := loadReservationEntries(after.Entries, journal.JobID)
		if err != nil {
			return err
		}
		job, err := jobs.LoadEntries(after.Entries, journal.JobID)
		if err != nil {
			return err
		}
		if job.Status != jobs.StatusRunning || intent.Target != journal.Target || intent.Operation != journal.Operation || (intent.Phase != PhaseLocalIntent && intent.Phase != PhaseReentered) {
			continue
		}
		if slices.Equal(candidate.PublicationRecord.CertificateInventory, certificates.AddArtifact(prior.PublicationRecord.CertificateInventory, artifact)) {
			return nil
		}
	}
	return fmt.Errorf("certificate inventory update lacks exact running staging journal")
}
