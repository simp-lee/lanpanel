package nginx

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"lanpanel/internal/domain"
	"lanpanel/internal/safety"
	"lanpanel/internal/storeauthority"
	"slices"
	"strings"
	"time"
)

type GuardAction string

const (
	GuardStart  GuardAction = "start"
	GuardReload GuardAction = "reload"
)

type GuardInput struct {
	Action       GuardAction
	Manifest     Manifest
	Safety       safety.State
	Installation *domain.Installation
	Ownership    map[string]string
	Now          time.Time
}

type GuardDecision struct {
	Allowed bool
	Reason  string
}

// Guard evaluates only durable safety and the already audited disk manifest.
// It never normalizes, clears, or invents state.
func Guard(input GuardInput) GuardDecision {
	if input.Action != GuardStart && input.Action != GuardReload || input.Now.IsZero() || ValidateManifest(input.Manifest) != nil {
		return GuardDecision{Reason: "guard authority is invalid"}
	}
	if err := VerifyTailnetRoutes(input.Manifest); err != nil {
		return GuardDecision{Reason: err.Error()}
	}
	if err := safety.Validate(input.Safety); err != nil {
		return GuardDecision{Reason: "independent safety authority is invalid"}
	}
	if input.Installation == nil || input.Manifest.InstallationID != input.Installation.InstallationID {
		return GuardDecision{Reason: "disk graph installation identity does not exactly match normal authority; keep ingress closed and use configuration export and clean-host rebuild"}
	}
	if err := storeauthority.ValidateNormalSafetyOwnership(input.Installation, input.Safety, input.Ownership); err != nil {
		return GuardDecision{Reason: err.Error()}
	}
	if input.Safety.StopFence != nil {
		return GuardDecision{Reason: "stop fence blocks Nginx start and reload"}
	}
	for _, entry := range input.Manifest.Entries {
		if entry.Kind == EntryChallenge && entry.ResourceID == "headscale" {
			pending := input.Safety.Headscale.ChallengePending
			if pending == nil || pending.Generation != entry.Generation || !exactHTTPChallengeEntry(pending, entry) || !headscaleChallengeSnapshotMatches(pending.BaseMarkers, input.Safety.Headscale) {
				return GuardDecision{Reason: "Headscale challenge graph lacks exact authority"}
			}
			continue
		}
		if entry.Kind == EntryControl {
			if active := input.Safety.Headscale.Reactivating; active != nil {
				if entry.Domain == nil || active.ControlGeneration != entry.Generation || active.CertificateGeneration == 0 || active.CertificateFingerprint == "" || active.CandidateBundle == "" || active.ActivationDigest == "" || active.ControlEntryDigest != entry.Digest || input.Now.Before(active.CertificateLastTrustedWall) || !input.Now.Before(active.CertificateUntil) {
					return GuardDecision{Reason: "control ingress lacks exact Headscale reactivation authority"}
				}
				continue
			}
			certificate := input.Safety.Headscale.ActiveCertificate
			base := entry
			if entry.Challenge != nil {
				pending := input.Safety.Headscale.ChallengePending
				if !exactHTTPChallengeEntry(pending, entry) || !headscaleChallengeSnapshotMatches(pending.BaseMarkers, input.Safety.Headscale) {
					return GuardDecision{Reason: "Headscale control challenge authority changed"}
				}
				base.Challenge = nil
				base.Digest = "sha256:" + strings.Repeat("0", 64)
				digest, digestErr := DigestEntry(base)
				if digestErr != nil || digest != input.Safety.Headscale.ControlEntryDigest {
					return GuardDecision{Reason: "Headscale control base graph changed"}
				}
			} else if entry.Digest != input.Safety.Headscale.ControlEntryDigest {
				return GuardDecision{Reason: "Headscale committed control graph changed"}
			}
			if input.Installation == nil || input.Installation.Headscale == nil || !input.Installation.Headscale.Enabled || input.Installation.Headscale.Applied == nil || input.Installation.Headscale.Certificate == nil || entry.Domain == nil || entry.Generation != input.Installation.Headscale.Applied.Generation || certificate == nil || input.Safety.Headscale.CertificateExpiry != nil || certificate.Fingerprint != input.Installation.Headscale.Certificate.Fingerprint || certificate.Generation != input.Installation.Headscale.Certificate.Generation || input.Now.Before(certificate.LastTrustedWall) || !input.Now.Before(certificate.NotAfter) {
				return GuardDecision{Reason: "control ingress lacks valid committed Headscale certificate authority"}
			}
			continue
		}
		resource := findSafetyResource(input.Safety, entry.ResourceID)
		if resource == nil {
			return GuardDecision{Reason: fmt.Sprintf("disk graph resource %q lacks safety authority", entry.ResourceID)}
		}
		if input.Ownership == nil || input.Ownership[entry.ResourceID] != resource.OwnershipDigest {
			return GuardDecision{Reason: "App graph lacks exact ownership authority"}
		}
		if input.Safety.GlobalClose.Phase != safety.GlobalCloseNone || resource.Closing != nil || resource.State == safety.ResourceDeleting || resource.Ownership == safety.OwnershipOrphan {
			return GuardDecision{Reason: "higher-priority contraction blocks App graph"}
		}
		switch entry.Kind {
		case EntryChallenge:
			pending := resource.ChallengePending
			if pending == nil || pending.Generation != entry.Generation || !exactHTTPChallengeEntry(pending, entry) || pending.BootstrapIdentity == "" || !challengeSnapshotMatches(pending.BaseMarkers, *resource) {
				return GuardDecision{Reason: "challenge graph lacks exact durable HTTP-01 authority"}
			}
		case EntryApp, EntryTemporary:
			app := findInstallationResource(input.Installation, entry.ResourceID)
			if app == nil {
				return GuardDecision{Reason: "normal publication authority is unavailable"}
			}
			published := exactPublishedApp(*app, *resource, entry, input.Now)
			activating := exactActivatingApp(*app, *resource, entry, input.Now)
			prior := exactActivationPriorApp(*app, *resource, entry, input.Now)
			if !published && !activating && !prior {
				return GuardDecision{Reason: "App graph lacks exact published, activating, or rollback authority"}
			}
		default:
			return GuardDecision{Reason: "disk graph kind is unsupported"}
		}
	}
	return GuardDecision{Allowed: true, Reason: "exact durable safety and disk graph match"}
}

func exactHTTPChallengeEntry(pending *safety.ChallengePending, entry Entry) bool {
	if pending == nil || pending.Method != "http-01" || entry.Challenge == nil || pending.Token == "" || pending.TokenPath == "" || pending.KeyAuthorizationDigest == "" {
		return false
	}
	site := entry.Challenge
	return pending.Generation == site.Generation && pending.Host == site.Host && pending.Token == site.Token && pending.TokenPath == site.TokenPath && pending.KeyAuthorizationDigest == site.KeyAuthorizationDigest && pending.Webroot == site.Webroot && slices.Equal(entry.Domains, []string{pending.Host})
}

func findInstallationResource(installation *domain.Installation, id string) *domain.AppResource {
	if installation == nil {
		return nil
	}
	for index := range installation.Resources {
		if installation.Resources[index].ID == id {
			return &installation.Resources[index]
		}
	}
	return nil
}

func exactPublishedApp(app domain.AppResource, resource safety.ResourceSafety, entry Entry, now time.Time) bool {
	bundle := app.PublicationRecord.LastAppliedBundle
	if app.PublicationRecord.State != domain.PublicationPublished || bundle == nil || bundle.Generation != entry.Generation || bundle.SiteIdentity != entry.Digest || bundle.Kind != app.Publication.Kind || resource.State != safety.ResourceActive || resource.Ownership != safety.OwnershipOwned || resource.StickyUnpublished != nil || resource.Contraction != nil || resource.CertificateExpiry != nil || resource.Reactivating != nil {
		return false
	}
	if resource.ChallengePending != nil && !challengeSnapshotMatches(resource.ChallengePending.BaseMarkers, resource) {
		return false
	}
	return exactEntryBundle(entry, *bundle, resource.ActiveCertificate, now)
}

func exactActivatingApp(app domain.AppResource, resource safety.ResourceSafety, entry Entry, now time.Time) bool {
	intent := app.PublicationRecord.ActivationIntent
	active := resource.Reactivating
	if !exactReactivationAuthority(app, resource, intent, active) || intent.Candidate.Generation != entry.Generation || intent.Candidate.SiteIdentity != entry.Digest || active.Generation != entry.Generation {
		return false
	}
	return exactEntryBundle(entry, intent.Candidate, nil, now)
}

func exactActivationPriorApp(app domain.AppResource, resource safety.ResourceSafety, entry Entry, now time.Time) bool {
	intent := app.PublicationRecord.ActivationIntent
	active := resource.Reactivating
	if !exactReactivationAuthority(app, resource, intent, active) || intent.PriorState != domain.PublicationPublished || intent.Prior == nil || intent.Prior.Generation > active.PriorGeneration || intent.Prior.Generation != entry.Generation || intent.Prior.SiteIdentity != entry.Digest {
		return false
	}
	return exactEntryBundle(entry, *intent.Prior, resource.ActiveCertificate, now)
}

func exactReactivationAuthority(app domain.AppResource, resource safety.ResourceSafety, intent *domain.ActivationIntent, active *safety.Reactivating) bool {
	if app.PublicationRecord.State != domain.PublicationActivating || intent == nil || active == nil || resource.ChallengePending != nil || resource.State != safety.ResourceActive || resource.Ownership != safety.OwnershipOwned || intent.Generation != active.Generation || intent.Candidate.Kind != app.Publication.Kind || active.Generation != intent.Candidate.Generation || active.PlanID != intent.PlanID || active.CandidateDigest != intent.Candidate.ConfigDigest || !challengeSnapshotMatches(active.BaseMarkers, resource) {
		return false
	}
	digest, err := publicationBundleDigest(intent.Candidate)
	return err == nil && digest == active.CandidateBundle && active.TemporaryHTTP == (intent.Candidate.Kind == domain.PublicationTemporaryHTTP)
}

func exactEntryBundle(entry Entry, bundle domain.PublicationBundle, authority *safety.ActiveCertificateAuthority, now time.Time) bool {
	switch entry.Kind {
	case EntryTemporary:
		return bundle.Kind == domain.PublicationTemporaryHTTP && bundle.TemporaryHTTP != nil && entry.Temporary != nil && bundle.TemporaryHTTP.PublicIPv4 == entry.Temporary.PublicIPv4 && bundle.TemporaryHTTP.Port == entry.Temporary.Port && bundle.TemporaryHTTP.HostAuthority == entry.Temporary.HostAuthority
	case EntryApp:
		if bundle.Kind != domain.PublicationDomainHTTPS || bundle.DomainHTTPS == nil || entry.Domain == nil || !slices.Equal(bundle.DomainHTTPS.ExactDomains, entry.Domains) || !slices.Equal(bundle.DomainHTTPS.ExactDomains, entry.Domain.Hosts) || bundle.DomainHTTPS.Certificate.PointerIdentity != entry.Domain.CertificatePointer {
			return false
		}
		if authority == nil {
			deadline, deadlineErr := time.Parse(time.RFC3339, bundle.DomainHTTPS.Certificate.NotAfter)
			wall, wallErr := time.Parse(time.RFC3339, bundle.DomainHTTPS.Certificate.LastTrustedWall)
			return deadlineErr == nil && wallErr == nil && !now.Before(wall) && now.Before(deadline)
		}
		certificate := bundle.DomainHTTPS.Certificate
		return authority.Generation == certificate.Generation && authority.Fingerprint == certificate.Fingerprint && authority.Binding == certificate.BindingIdentity && !now.Before(authority.LastTrustedWall) && now.Before(authority.NotAfter)
	default:
		return false
	}
}

func publicationBundleDigest(bundle domain.PublicationBundle) (string, error) {
	raw, err := json.Marshal(bundle)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func headscaleChallengeSnapshotMatches(snapshot []safety.MarkerSnapshot, headscale safety.HeadscaleSafety) bool {
	if len(snapshot) != 3 {
		return false
	}
	seen := map[safety.MarkerKind]bool{}
	for _, marker := range snapshot {
		if seen[marker.Kind] {
			return false
		}
		seen[marker.Kind] = true
		present := false
		generation := uint64(0)
		if marker.Kind == safety.MarkerCertificateExpiry && headscale.CertificateExpiry != nil {
			present = true
			generation = headscale.CertificateExpiry.Generation
		}
		if marker.State == safety.SnapshotPresent {
			if !present || marker.Generation != generation {
				return false
			}
		} else if marker.State != safety.SnapshotAbsent || present {
			return false
		}
	}
	return seen[safety.MarkerStickyUnpublished] && seen[safety.MarkerContraction] && seen[safety.MarkerCertificateExpiry]
}

func challengeSnapshotMatches(snapshot []safety.MarkerSnapshot, resource safety.ResourceSafety) bool {
	current := map[safety.MarkerKind]uint64{}
	if resource.StickyUnpublished != nil {
		current[safety.MarkerStickyUnpublished] = resource.StickyUnpublished.Generation
	}
	if resource.Contraction != nil {
		current[safety.MarkerContraction] = resource.Contraction.Generation
	}
	if resource.CertificateExpiry != nil {
		current[safety.MarkerCertificateExpiry] = resource.CertificateExpiry.Generation
	}
	if len(snapshot) != 3 {
		return false
	}
	for _, marker := range snapshot {
		generation, present := current[marker.Kind]
		if marker.State == safety.SnapshotPresent {
			if !present || generation != marker.Generation {
				return false
			}
		} else if marker.State != safety.SnapshotAbsent || present {
			return false
		}
	}
	return true
}

func findSafetyResource(state safety.State, id string) *safety.ResourceSafety {
	for index := range state.Resources {
		if state.Resources[index].ResourceID == id {
			return &state.Resources[index]
		}
	}
	return nil
}
