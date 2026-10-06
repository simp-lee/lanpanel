// Package reservations provides the in-memory transactional conflict authority
// used before later persistence and host-mutation steps are admitted.
package reservations

import (
	"errors"
	"fmt"
	"lanpanel/internal/domain"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type Kind string

const (
	KindResourceName      Kind = "resource_name"
	KindExactDomain       Kind = "exact_domain"
	KindMagicDNSNamespace Kind = "magicdns_namespace"
	KindListener          Kind = "listener"
	KindCredential        Kind = "credential"
	KindCredentialUse     Kind = "credential_use"
	KindManagedPath       Kind = "managed_path"
)

type Claim struct {
	Kind  Kind   `json:"kind"`
	Value string `json:"value"`
	Owner string `json:"owner"`
}

type ConflictError struct {
	Left  Claim
	Right Claim
}

func (err ConflictError) Error() string {
	return fmt.Sprintf("%s %q owned by %q conflicts with %s owned by %q", err.Right.Kind, err.Right.Value, err.Right.Owner, err.Left.Kind, err.Left.Owner)
}

type Registry struct {
	mu         sync.Mutex
	generation uint64
	claims     []Claim
}

func NewRegistry() *Registry { return &Registry{} }

func (registry *Registry) Begin() *Transaction {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	return &Transaction{
		registry:       registry,
		baseGeneration: registry.generation,
		claims:         append([]Claim(nil), registry.claims...),
	}
}

func (registry *Registry) Snapshot() (uint64, []Claim) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	return registry.generation, append([]Claim(nil), registry.claims...)
}

type Transaction struct {
	registry       *Registry
	baseGeneration uint64
	claims         []Claim
	closed         bool
}

func (transaction *Transaction) ReplaceOwner(owner string, claims []Claim) error {
	if transaction == nil || transaction.registry == nil || transaction.closed {
		return fmt.Errorf("reservation transaction is not open")
	}
	if strings.TrimSpace(owner) == "" || owner != strings.TrimSpace(owner) {
		return fmt.Errorf("reservation owner must be nonempty and trimmed")
	}
	candidate := make([]Claim, 0, len(transaction.claims)+len(claims))
	for _, claim := range transaction.claims {
		if claim.Owner != owner {
			candidate = append(candidate, claim)
		}
	}
	for _, claim := range claims {
		if claim.Owner != owner {
			transaction.closed = true
			return fmt.Errorf("claim owner %q does not match replacement owner %q", claim.Owner, owner)
		}
		candidate = append(candidate, claim)
	}
	if err := validateClaims(candidate); err != nil {
		transaction.closed = true
		return err
	}
	transaction.claims = candidate
	return nil
}

func (transaction *Transaction) Commit() error {
	if transaction == nil || transaction.registry == nil || transaction.closed {
		return fmt.Errorf("reservation transaction is not open")
	}
	if err := validateClaims(transaction.claims); err != nil {
		return err
	}
	registry := transaction.registry
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.generation != transaction.baseGeneration {
		transaction.closed = true
		return fmt.Errorf("reservation transaction is stale: base generation %d, current generation %d", transaction.baseGeneration, registry.generation)
	}
	claims := append([]Claim(nil), transaction.claims...)
	sort.Slice(claims, func(left, right int) bool {
		if claims[left].Kind != claims[right].Kind {
			return claims[left].Kind < claims[right].Kind
		}
		if claims[left].Value != claims[right].Value {
			return claims[left].Value < claims[right].Value
		}
		return claims[left].Owner < claims[right].Owner
	})
	registry.claims = claims
	registry.generation++
	transaction.closed = true
	return nil
}

func BuildClaims(installation domain.Installation) ([]Claim, error) {
	if err := domain.ValidateInstallation(installation); err != nil {
		if installation.Headscale != nil && errors.Is(err, domain.ErrHeadscaleDomainConflict) {
			owner := "installation:" + installation.InstallationID + ":headscale:" + installation.Headscale.ID
			return nil, ConflictError{Left: Claim{Kind: KindExactDomain, Value: installation.Headscale.ControlDomain, Owner: owner}, Right: Claim{Kind: KindMagicDNSNamespace, Value: installation.Headscale.MagicDNSNamespace, Owner: owner}}
		}
		return nil, err
	}
	claims := make([]Claim, 0)
	installationOwner := "installation:" + installation.InstallationID
	for _, path := range installation.ManagedPaths {
		claims = append(claims, Claim{Kind: KindManagedPath, Value: path, Owner: installationOwner})
	}
	managementOwner := installationOwner + ":management"
	claims = append(claims, Claim{Kind: KindListener, Value: listenerValue("tcp", installation.Management.Port), Owner: managementOwner})
	if installation.ManagementHTTPS != nil {
		claims = append(claims, Claim{Kind: KindExactDomain, Value: installation.ManagementHTTPS.Domain, Owner: managementOwner})
	}
	for _, path := range installation.Management.ManagedPaths {
		claims = append(claims, Claim{Kind: KindManagedPath, Value: path, Owner: managementOwner})
	}
	sharedIngress := false
	if installation.Headscale != nil {
		owner := installationOwner + ":headscale:" + installation.Headscale.ID
		controlDomain := Claim{Kind: KindExactDomain, Value: installation.Headscale.ControlDomain, Owner: owner}
		magicDNS := Claim{Kind: KindMagicDNSNamespace, Value: installation.Headscale.MagicDNSNamespace, Owner: owner}
		claims = append(claims,
			controlDomain,
			magicDNS,
			Claim{Kind: KindListener, Value: listenerValue("udp", 3478), Owner: owner},
		)
		for _, path := range installation.Headscale.ManagedPaths {
			claims = append(claims, Claim{Kind: KindManagedPath, Value: path, Owner: owner})
		}
		sharedIngress = true
	}
	if installation.Connector != nil {
		for _, path := range installation.Connector.ManagedPaths {
			claims = append(claims, Claim{Kind: KindManagedPath, Value: path, Owner: installationOwner + ":connector:" + installation.Connector.ID})
		}
	}
	for _, credential := range installation.Credentials {
		owner := installationOwner + ":credential:" + credential.ID
		claims = append(claims, Claim{Kind: KindCredential, Value: credential.ID, Owner: owner})
		if credential.ManagedPath != "" {
			claims = append(claims, Claim{Kind: KindManagedPath, Value: credential.ManagedPath, Owner: owner})
		}
	}
	for _, root := range installation.StaticRoots {
		claims = append(claims, Claim{Kind: KindManagedPath, Value: root.Path, Owner: installationOwner + ":static:" + root.ID})
	}
	for _, resource := range installation.Resources {
		owner := installationOwner + ":resource:" + resource.ID
		claims = append(claims, Claim{Kind: KindResourceName, Value: normalizeName(resource.Name), Owner: owner})
		for _, path := range resource.ManagedPaths {
			claims = append(claims, Claim{Kind: KindManagedPath, Value: path, Owner: owner})
		}
		for _, credentialID := range resource.CredentialIDs {
			claims = append(claims, Claim{Kind: KindCredentialUse, Value: credentialID, Owner: owner})
		}
		if resource.Target.Kind == domain.AppTargetLocalHTTP && resource.Target.LocalHTTP.EndpointKind == domain.LocalEndpointTCPSocketActivation {
			claims = append(claims, Claim{Kind: KindListener, Value: listenerValue("tcp", resource.Target.LocalHTTP.TCPPort), Owner: owner})
		}
		switch resource.Publication.Kind {
		case domain.PublicationDomainHTTPS:
			sharedIngress = true
			claims = append(claims, Claim{Kind: KindExactDomain, Value: resource.Publication.DomainHTTPS.CanonicalDomain, Owner: owner})
			for _, alias := range resource.Publication.DomainHTTPS.Aliases {
				claims = append(claims, Claim{Kind: KindExactDomain, Value: alias, Owner: owner})
			}
		case domain.PublicationTemporaryHTTP:
			claims = append(claims, Claim{Kind: KindListener, Value: listenerValue("tcp", resource.Publication.TemporaryHTTP.Port), Owner: owner})
		}
		bundles := []*domain.PublicationBundle{resource.PublicationRecord.LastAppliedBundle}
		if resource.PublicationRecord.ActivationIntent != nil {
			bundles = append(bundles, &resource.PublicationRecord.ActivationIntent.Candidate, resource.PublicationRecord.ActivationIntent.Prior)
		}
		for _, bundle := range bundles {
			if bundle != nil {
				claims = append(claims, bundleClaims(owner, *bundle)...)
				if bundle.DomainHTTPS != nil {
					sharedIngress = true
				}
			}
		}
	}
	if sharedIngress {
		owner := installationOwner + ":shared-domain-ingress"
		claims = append(claims,
			Claim{Kind: KindListener, Value: listenerValue("tcp", 80), Owner: owner},
			Claim{Kind: KindListener, Value: listenerValue("tcp", 443), Owner: owner},
		)
	}
	claims = dedupeClaims(claims)
	if err := validateClaims(claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func bundleClaims(owner string, bundle domain.PublicationBundle) []Claim {
	claims := make([]Claim, 0)
	for _, path := range bundle.ManagedPaths {
		claims = append(claims, Claim{Kind: KindManagedPath, Value: path, Owner: owner})
	}
	for _, credentialID := range bundle.CredentialIDs {
		claims = append(claims, Claim{Kind: KindCredentialUse, Value: credentialID, Owner: owner})
	}
	for _, listener := range bundle.Listeners {
		if bundle.DomainHTTPS != nil && (listener.Port == 80 || listener.Port == 443) {
			continue
		}
		claims = append(claims, Claim{Kind: KindListener, Value: listenerValue(listener.Network, listener.Port), Owner: owner})
	}
	if bundle.DomainHTTPS != nil {
		for _, exactDomain := range bundle.DomainHTTPS.ExactDomains {
			claims = append(claims, Claim{Kind: KindExactDomain, Value: exactDomain, Owner: owner})
		}
	}
	if bundle.TemporaryHTTP != nil {
		claims = append(claims, Claim{Kind: KindListener, Value: listenerValue("tcp", bundle.TemporaryHTTP.Port), Owner: owner})
	}
	return claims
}

func dedupeClaims(claims []Claim) []Claim {
	type key struct {
		kind  Kind
		value string
		owner string
	}
	seen := make(map[key]struct{}, len(claims))
	result := make([]Claim, 0, len(claims))
	for _, claim := range claims {
		claimKey := key{kind: claim.Kind, value: claim.Value, owner: claim.Owner}
		if _, duplicate := seen[claimKey]; duplicate {
			continue
		}
		seen[claimKey] = struct{}{}
		result = append(result, claim)
	}
	return result
}

func validateClaims(claims []Claim) error {
	for index, claim := range claims {
		if err := validateClaim(claim); err != nil {
			return fmt.Errorf("claim[%d]: %w", index, err)
		}
		for priorIndex := range index {
			if claimsConflict(claims[priorIndex], claim) {
				return ConflictError{Left: claims[priorIndex], Right: claim}
			}
		}
	}
	return nil
}

func validateClaim(claim Claim) error {
	if strings.TrimSpace(claim.Owner) == "" || claim.Owner != strings.TrimSpace(claim.Owner) {
		return fmt.Errorf("owner must be nonempty and trimmed")
	}
	if strings.TrimSpace(claim.Value) == "" || claim.Value != strings.TrimSpace(claim.Value) {
		return fmt.Errorf("value must be nonempty and trimmed")
	}
	switch claim.Kind {
	case KindResourceName:
		if claim.Value != normalizeName(claim.Value) {
			return fmt.Errorf("resource_name must be normalized")
		}
	case KindExactDomain, KindMagicDNSNamespace:
		if err := domain.ValidateExactDomain(claim.Value); err != nil {
			return fmt.Errorf("domain claim must be canonical and exact: %w", err)
		}
	case KindListener:
		parts := strings.Split(claim.Value, ":")
		if len(parts) != 2 || (parts[0] != "tcp" && parts[0] != "udp") {
			return fmt.Errorf("listener must be tcp:<port> or udp:<port>")
		}
		port, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil || port == 0 {
			return fmt.Errorf("listener port must be in 1..65535")
		}
	case KindCredential, KindCredentialUse:
		if !strings.HasPrefix(claim.Value, "cred_") {
			return fmt.Errorf("credential claim must use a stable credential ID")
		}
	case KindManagedPath:
		if !filepath.IsAbs(claim.Value) || filepath.Clean(claim.Value) != claim.Value || claim.Value == "/" {
			return fmt.Errorf("managed_path must be clean, absolute, and non-root")
		}
	default:
		return fmt.Errorf("kind %q is not supported", claim.Kind)
	}
	return nil
}

func claimsConflict(left, right Claim) bool {
	if left.Owner == right.Owner {
		return false
	}
	if left.Kind == right.Kind {
		switch left.Kind {
		case KindManagedPath:
			return pathsOverlap(left.Value, right.Value)
		default:
			return left.Value == right.Value
		}
	}
	if isDomainKind(left.Kind) && isDomainKind(right.Kind) {
		if left.Kind == KindMagicDNSNamespace || right.Kind == KindMagicDNSNamespace {
			return domainsOverlap(left.Value, right.Value)
		}
	}
	return false
}

func isDomainKind(kind Kind) bool {
	return kind == KindExactDomain || kind == KindMagicDNSNamespace
}

func domainsOverlap(left, right string) bool {
	return domain.DomainsOverlap(left, right)
}

func pathsOverlap(left, right string) bool {
	return left == right || strings.HasPrefix(left, right+string(filepath.Separator)) || strings.HasPrefix(right, left+string(filepath.Separator))
}

func normalizeName(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func listenerValue(network string, port uint16) string {
	return network + ":" + strconv.FormatUint(uint64(port), 10)
}
