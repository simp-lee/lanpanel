// Package closure builds exact contraction inventories and runtime evidence.
package closure

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"lanpanel/internal/domain"
	"lanpanel/internal/nginx"
	"lanpanel/internal/ownership"
	"lanpanel/internal/safety"
	"slices"
	"sort"
	"strings"
)

const MaximumIdentities = 4096

type IdentityKind string

const (
	IdentityResourceScope          IdentityKind = "resource_scope"
	IdentityNormalPrior            IdentityKind = "normal_prior"
	IdentityNormalCandidate        IdentityKind = "normal_candidate"
	IdentityContractionPrior       IdentityKind = "contraction_prior"
	IdentityContractionCandidate   IdentityKind = "contraction_candidate"
	IdentityPublicationKind        IdentityKind = "publication_kind"
	IdentityDomain                 IdentityKind = "domain"
	IdentityPreservedControlDomain IdentityKind = "preserved_control_domain"
	IdentityListener               IdentityKind = "listener"
	IdentityTemporaryListener      IdentityKind = "temporary_listener"
	IdentityChallenge              IdentityKind = "challenge"
	IdentityOwnershipPath          IdentityKind = "ownership_path"
	IdentityOwnershipListener      IdentityKind = "ownership_listener"
	IdentityDiskGraph              IdentityKind = "disk_graph"
)

type Identity struct {
	ResourceID string       `json:"resource_id"`
	Kind       IdentityKind `json:"kind"`
	Value      string       `json:"value"`
	Digest     string       `json:"digest"`
}

type Uncertainty struct {
	Code  string `json:"code"`
	Value string `json:"value"`
}

type Inventory struct {
	Identities          []Identity        `json:"identities"`
	Uncertainties       []Uncertainty     `json:"uncertainties"`
	Complete            bool              `json:"complete"`
	IdentityDigest      string            `json:"identity_digest"`
	OwnershipDigest     string            `json:"ownership_digest"`
	FullOwnershipDigest string            `json:"full_ownership_digest"`
	ResourceOwnership   map[string]string `json:"resource_ownership"`
	FallbackListeners   []string          `json:"fallback_listeners"`
	UncertaintyDigest   string            `json:"uncertainty_digest"`
	Digest              string            `json:"digest"`
}

type Inputs struct {
	Installation      domain.Installation
	NormalUnavailable bool
	Safety            *safety.State
	Ownership         ownership.Inventory
	Graph             *nginx.Manifest
	ResourceIDs       []string
}

func BuildInventory(input Inputs) (Inventory, error) {
	selected := map[string]bool{}
	for _, id := range input.ResourceIDs {
		if id == "" || selected[id] {
			return Inventory{}, fmt.Errorf("closure resource selection is invalid")
		}
		selected[id] = true
	}
	all := len(selected) == 0
	result := Inventory{Complete: true, Identities: []Identity{}, Uncertainties: []Uncertainty{}}
	if input.NormalUnavailable {
		result.Uncertainties = append(result.Uncertainties, Uncertainty{Code: "normal_state_unavailable", Value: "installation"})
	}
	add := func(resourceID string, kind IdentityKind, value, identityDigest string) error {
		if (!all && !selected[resourceID]) || resourceID == "" || value == "" || !validDigest(identityDigest) {
			if all || selected[resourceID] {
				return fmt.Errorf("closure identity is incomplete")
			}
			return nil
		}
		result.Identities = append(result.Identities, Identity{ResourceID: resourceID, Kind: kind, Value: value, Digest: identityDigest})
		return nil
	}
	addBundle := func(resourceID string, kind IdentityKind, bundle *domain.PublicationBundle) error {
		if bundle == nil {
			return nil
		}
		data, err := json.Marshal(bundle)
		if err != nil {
			return err
		}
		if err := add(resourceID, IdentityPublicationKind, string(bundle.Kind), digest([]byte("publication_kind\x00"+string(bundle.Kind)))); err != nil {
			return err
		}
		if err := add(resourceID, kind, bundle.SiteIdentity, digest(data)); err != nil {
			return err
		}
		if bundle.DomainHTTPS != nil {
			for _, domainName := range bundle.DomainHTTPS.ExactDomains {
				if err := add(resourceID, IdentityDomain, domainName, digest([]byte("domain\x00"+domainName))); err != nil {
					return err
				}
			}
		}
		for _, listener := range bundle.Listeners {
			value := fmt.Sprintf("%s:0.0.0.0:%d", listener.Network, listener.Port)
			if err := add(resourceID, IdentityListener, value, digest([]byte("listener\x00"+value))); err != nil {
				return err
			}
			if bundle.Kind == domain.PublicationTemporaryHTTP {
				if err := add(resourceID, IdentityTemporaryListener, value, digest([]byte("temporary_listener\x00"+value))); err != nil {
					return err
				}
			}
		}
		return nil
	}
	installed := map[string]bool{}
	requiresOwnership := map[string]bool{}
	for _, resource := range input.Installation.Resources {
		installed[resource.ID] = true
		if !all && !selected[resource.ID] {
			continue
		}
		if resource.PublicationRecord.LastAppliedBundle != nil || resource.PublicationRecord.ActivationIntent != nil || resource.PublicationRecord.ContractionIntent != nil {
			requiresOwnership[resource.ID] = true
		}
		if err := add(resource.ID, IdentityResourceScope, resource.ID, digest([]byte("resource\x00"+resource.ID))); err != nil {
			return Inventory{}, err
		}
		if err := addBundle(resource.ID, IdentityNormalPrior, resource.PublicationRecord.LastAppliedBundle); err != nil {
			return Inventory{}, err
		}
		if resource.PublicationRecord.ActivationIntent != nil {
			if err := addBundle(resource.ID, IdentityNormalCandidate, &resource.PublicationRecord.ActivationIntent.Candidate); err != nil {
				return Inventory{}, err
			}
			if err := addBundle(resource.ID, IdentityNormalPrior, resource.PublicationRecord.ActivationIntent.Prior); err != nil {
				return Inventory{}, err
			}
		}
		if resource.PublicationRecord.ContractionIntent != nil {
			if err := addBundle(resource.ID, IdentityContractionPrior, resource.PublicationRecord.ContractionIntent.Prior); err != nil {
				return Inventory{}, err
			}
			if err := addBundle(resource.ID, IdentityContractionCandidate, resource.PublicationRecord.ContractionIntent.Candidate); err != nil {
				return Inventory{}, err
			}
		}
	}
	if !all {
		for id := range selected {
			if !installed[id] {
				result.Uncertainties = append(result.Uncertainties, Uncertainty{Code: "normal_resource_missing", Value: id})
			}
		}
	}
	if input.Safety == nil {
		result.Uncertainties = append(result.Uncertainties, Uncertainty{Code: "safety_unavailable", Value: "independent_safety"})
	} else {
		for _, resource := range input.Safety.Resources {
			if !all && !selected[resource.ResourceID] {
				continue
			}
			if resource.ChallengePending != nil {
				requiresOwnership[resource.ResourceID] = true
				challenge := resource.ChallengePending
				value := strings.Join([]string{challenge.Host, challenge.TokenPath, challenge.Webroot}, "\x00")
				if err := add(resource.ResourceID, IdentityChallenge, value, challenge.BootstrapIdentity); err != nil {
					return Inventory{}, err
				}
			}
		}
	}
	ownershipChecksums := map[string]string{}
	fullOwnershipChecksums := map[string]string{}
	fallbackListeners := map[string]bool{"tcp:0.0.0.0:80": true, "tcp:0.0.0.0:443": true, "tcp::::80": true, "tcp::::443": true}
	for _, record := range input.Ownership.FallbackRecords {
		fullOwnershipChecksums[record.ResourceID] = record.Checksum
		for _, listener := range record.Listeners {
			fallbackListeners[fmt.Sprintf("%s:%s:%d", listener.Protocol, listener.Address, listener.Port)] = true
		}
	}
	if !input.Ownership.Complete {
		result.Uncertainties = append(result.Uncertainties, Uncertainty{Code: "ownership_inventory_incomplete", Value: "records"})
	}
	for _, issue := range input.Ownership.Issues {
		result.Uncertainties = append(result.Uncertainties, Uncertainty{Code: "ownership_issue", Value: issue.Name + ":" + issue.Error})
	}
	ownedResources := map[string]bool{}
	for _, record := range input.Ownership.Records {
		fullOwnershipChecksums[record.ResourceID] = record.Checksum
		for _, listener := range record.Listeners {
			fallbackListeners[fmt.Sprintf("%s:%s:%d", listener.Protocol, listener.Address, listener.Port)] = true
		}
		if !all && !selected[record.ResourceID] {
			continue
		}
		ownershipChecksums[record.ResourceID] = record.Checksum
		ownedResources[record.ResourceID] = true
		for _, path := range record.Paths {
			if err := add(record.ResourceID, IdentityOwnershipPath, string(path.Kind)+":"+path.Path, path.IdentityDigest); err != nil {
				return Inventory{}, err
			}
		}
		for _, listener := range record.Listeners {
			value := fmt.Sprintf("%s:%s:%d", listener.Protocol, listener.Address, listener.Port)
			if err := add(record.ResourceID, IdentityOwnershipListener, value, listener.IdentityDigest); err != nil {
				return Inventory{}, err
			}
		}
	}
	if input.Graph == nil {
		result.Uncertainties = append(result.Uncertainties, Uncertainty{Code: "disk_graph_unavailable", Value: "graph"})
	} else {
		for _, entry := range input.Graph.Entries {
			for _, listener := range entry.Listeners {
				fallbackListeners[listener] = true
			}
			if entry.Kind == nginx.EntryControl {
				if !all {
					continue
				}
				if err := add("headscale", IdentityDiskGraph, entry.Relative, entry.Digest); err != nil {
					return Inventory{}, err
				}
				for _, domainName := range entry.Domains {
					if err := add("headscale", IdentityPreservedControlDomain, domainName, digest([]byte("domain\x00"+domainName))); err != nil {
						return Inventory{}, err
					}
				}
				for _, listener := range entry.Listeners {
					if err := add("headscale", IdentityListener, listener, digest([]byte("listener\x00"+listener))); err != nil {
						return Inventory{}, err
					}
				}
				continue
			}
			if entry.ResourceID == "" || !all && !selected[entry.ResourceID] {
				continue
			}
			requiresOwnership[entry.ResourceID] = true
			if err := add(entry.ResourceID, IdentityDiskGraph, entry.Relative, entry.Digest); err != nil {
				return Inventory{}, err
			}
			for _, domainName := range entry.Domains {
				if err := add(entry.ResourceID, IdentityDomain, domainName, digest([]byte("domain\x00"+domainName))); err != nil {
					return Inventory{}, err
				}
			}
			for _, listener := range entry.Listeners {
				if err := add(entry.ResourceID, IdentityListener, listener, digest([]byte("listener\x00"+listener))); err != nil {
					return Inventory{}, err
				}
				if entry.Kind == nginx.EntryTemporary {
					if err := add(entry.ResourceID, IdentityTemporaryListener, listener, digest([]byte("temporary_listener\x00"+listener))); err != nil {
						return Inventory{}, err
					}
				}
			}
		}
	}
	for resourceID := range requiresOwnership {
		if !ownedResources[resourceID] {
			result.Uncertainties = append(result.Uncertainties, Uncertainty{Code: "ownership_resource_missing", Value: resourceID})
		}
	}
	if len(result.Identities) > MaximumIdentities || len(result.Uncertainties) > MaximumIdentities {
		return Inventory{}, fmt.Errorf("closure inventory exceeds its fixed bound")
	}
	result.Identities = canonicalIdentities(result.Identities)
	for _, resourceID := range selectedResources(result.Identities) {
		if uncertainty := inventoryContradiction(resourceID, result.Identities); uncertainty != nil {
			result.Uncertainties = append(result.Uncertainties, *uncertainty)
		}
	}
	result.Uncertainties = canonicalUncertainties(result.Uncertainties)
	result.Complete = len(result.Uncertainties) == 0
	identityBytes, _ := json.Marshal(result.Identities)
	uncertaintyBytes, _ := json.Marshal(result.Uncertainties)
	result.IdentityDigest = digest(identityBytes)
	result.ResourceOwnership = ownershipChecksums
	result.OwnershipDigest = safety.OwnershipInventoryDigest(ownershipChecksums)
	result.FullOwnershipDigest = safety.OwnershipInventoryDigest(fullOwnershipChecksums)
	for listener := range fallbackListeners {
		result.FallbackListeners = append(result.FallbackListeners, listener)
	}
	sort.Strings(result.FallbackListeners)
	result.UncertaintyDigest = digest(uncertaintyBytes)
	bound := struct {
		Identity      string   `json:"identity"`
		Ownership     string   `json:"ownership"`
		FullOwnership string   `json:"full_ownership"`
		Fallback      []string `json:"fallback"`
		Uncertainty   string   `json:"uncertainty"`
		Complete      bool     `json:"complete"`
	}{result.IdentityDigest, result.OwnershipDigest, result.FullOwnershipDigest, result.FallbackListeners, result.UncertaintyDigest, result.Complete}
	data, _ := json.Marshal(bound)
	result.Digest = digest(data)
	return result, nil
}

func selectedResources(values []Identity) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, value := range values {
		if !seen[value.ResourceID] {
			seen[value.ResourceID] = true
			result = append(result, value.ResourceID)
		}
	}
	sort.Strings(result)
	return result
}

func inventoryContradiction(resourceID string, values []Identity) *Uncertainty {
	domains := map[string]bool{}
	listeners, ownershipListeners := map[string]bool{}, map[string]bool{}
	domainPublication := false
	for _, value := range values {
		if value.ResourceID != resourceID {
			continue
		}
		switch value.Kind {
		case IdentityPublicationKind:
			domainPublication = domainPublication || value.Value == string(domain.PublicationDomainHTTPS)
		case IdentityDomain:
			domains[value.Value] = true
		case IdentityListener:
			listeners[value.Value] = true
		case IdentityOwnershipListener:
			ownershipListeners[value.Value] = true
		}
	}
	// Every externally owned listener must remain in the closure union. Missing
	// normal evidence is uncertainty rather than permission to narrow it.
	for value := range ownershipListeners {
		if !listeners[value] {
			return &Uncertainty{Code: "listener_authority_contradiction", Value: resourceID + ":" + value}
		}
	}
	if domainPublication && len(domains) == 0 {
		return &Uncertainty{Code: "domain_authority_missing", Value: resourceID}
	}
	return nil
}

func BuildFallbackInventory(input Inputs, cause error) Inventory {
	result := Inventory{Identities: []Identity{}, Uncertainties: []Uncertainty{{Code: "inventory_build_failed", Value: "opaque"}}, Complete: false, ResourceOwnership: map[string]string{}, FallbackListeners: []string{"tcp:0.0.0.0:80", "tcp:0.0.0.0:443", "tcp::::80", "tcp::::443"}}
	if cause == nil {
		result.Uncertainties[0].Code = "inventory_forced_fallback"
	}
	fallback := map[string]bool{}
	for _, value := range result.FallbackListeners {
		fallback[value] = true
	}
	checksums := map[string]string{}
	for _, record := range input.Ownership.FallbackRecords {
		if validDigest(record.Checksum) {
			checksums[record.ResourceID] = record.Checksum
			result.ResourceOwnership[record.ResourceID] = record.Checksum
		}
		for _, listener := range record.Listeners {
			fallback[fmt.Sprintf("%s:%s:%d", listener.Protocol, listener.Address, listener.Port)] = true
		}
	}
	for _, record := range input.Ownership.Records {
		if validDigest(record.Checksum) {
			checksums[record.ResourceID] = record.Checksum
			result.ResourceOwnership[record.ResourceID] = record.Checksum
		}
		for _, listener := range record.Listeners {
			fallback[fmt.Sprintf("%s:%s:%d", listener.Protocol, listener.Address, listener.Port)] = true
		}
	}
	selected := map[string]bool{}
	for _, resourceID := range input.ResourceIDs {
		selected[resourceID] = true
	}
	if input.Safety != nil {
		for _, resource := range input.Safety.Resources {
			if len(selected) != 0 && !selected[resource.ResourceID] || !validDigest(resource.OwnershipDigest) {
				continue
			}
			checksums[resource.ResourceID] = resource.OwnershipDigest
			result.ResourceOwnership[resource.ResourceID] = resource.OwnershipDigest
		}
	}
	result.FullOwnershipDigest = safety.OwnershipInventoryDigest(checksums)
	result.OwnershipDigest = result.FullOwnershipDigest
	result.FallbackListeners = result.FallbackListeners[:0]
	for value := range fallback {
		result.FallbackListeners = append(result.FallbackListeners, value)
	}
	sort.Strings(result.FallbackListeners)
	identityBytes, _ := json.Marshal(result.Identities)
	uncertaintyBytes, _ := json.Marshal(result.Uncertainties)
	result.IdentityDigest = digest(identityBytes)
	result.UncertaintyDigest = digest(uncertaintyBytes)
	bound := struct {
		Identity      string   `json:"identity"`
		Ownership     string   `json:"ownership"`
		FullOwnership string   `json:"full_ownership"`
		Fallback      []string `json:"fallback"`
		Uncertainty   string   `json:"uncertainty"`
		Complete      bool     `json:"complete"`
	}{result.IdentityDigest, result.OwnershipDigest, result.FullOwnershipDigest, result.FallbackListeners, result.UncertaintyDigest, false}
	data, _ := json.Marshal(bound)
	result.Digest = digest(data)
	return result
}

func ForceUncertain(inventory Inventory, code, value string) (Inventory, error) {
	if inventory.Digest == "" || code == "" || value == "" {
		return Inventory{}, fmt.Errorf("closure uncertainty authority is invalid")
	}
	inventory.Uncertainties = canonicalUncertainties(append(inventory.Uncertainties, Uncertainty{Code: code, Value: value}))
	inventory.Complete = false
	uncertaintyBytes, err := json.Marshal(inventory.Uncertainties)
	if err != nil {
		return Inventory{}, err
	}
	inventory.UncertaintyDigest = digest(uncertaintyBytes)
	bound := struct {
		Identity      string   `json:"identity"`
		Ownership     string   `json:"ownership"`
		FullOwnership string   `json:"full_ownership"`
		Fallback      []string `json:"fallback"`
		Uncertainty   string   `json:"uncertainty"`
		Complete      bool     `json:"complete"`
	}{inventory.IdentityDigest, inventory.OwnershipDigest, inventory.FullOwnershipDigest, inventory.FallbackListeners, inventory.UncertaintyDigest, false}
	data, err := json.Marshal(bound)
	if err != nil {
		return Inventory{}, err
	}
	inventory.Digest = digest(data)
	return inventory, nil
}

func canonicalIdentities(values []Identity) []Identity {
	result := append([]Identity(nil), values...)
	sort.Slice(result, func(left, right int) bool {
		if result[left].ResourceID != result[right].ResourceID {
			return result[left].ResourceID < result[right].ResourceID
		}
		if result[left].Kind != result[right].Kind {
			return result[left].Kind < result[right].Kind
		}
		if result[left].Value != result[right].Value {
			return result[left].Value < result[right].Value
		}
		return result[left].Digest < result[right].Digest
	})
	return slices.Compact(result)
}

func canonicalUncertainties(values []Uncertainty) []Uncertainty {
	result := append([]Uncertainty(nil), values...)
	sort.Slice(result, func(left, right int) bool {
		if result[left].Code == result[right].Code {
			return result[left].Value < result[right].Value
		}
		return result[left].Code < result[right].Code
	})
	return slices.Compact(result)
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil
}
