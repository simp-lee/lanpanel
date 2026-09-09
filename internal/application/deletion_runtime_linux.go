//go:build linux

package application

import (
	"context"
	"fmt"
	"lanpanel/internal/certificates"
	"lanpanel/internal/closure"
	"lanpanel/internal/contraction"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/nginx"
	"lanpanel/internal/operations"
	"lanpanel/internal/ownership"
	"lanpanel/internal/safety"
	"time"
)

type resourceDeleteRuntime struct {
	closed  func(context.Context, operations.ResourceDeleteBinding, safety.State) (string, error)
	cleanup func(context.Context, domain.AppResource, domain.Installation) ([]string, error)
}

func fixedResourceDeleteRuntime() resourceDeleteRuntime {
	return resourceDeleteRuntime{closed: observeResourceDeleteClosure, cleanup: func(ctx context.Context, resource domain.AppResource, installation domain.Installation) ([]string, error) {
		removed, err := cleanupDeleteInventory(resource, installation)
		if err != nil {
			return removed, err
		}
		paths, err := certificates.CleanupArtifacts(ctx, resource.PublicationRecord.CertificateInventory)
		return append(removed, paths...), err
	}}
}

func observeResourceDeleteClosure(ctx context.Context, binding operations.ResourceDeleteBinding, state safety.State) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := verifyDeleteRuntimeClosed(ctx, binding.Resource); err != nil {
		return "", err
	}
	manifest, err := nginx.Audit(nginx.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
	if err != nil {
		return "", err
	}
	return verifyResourceDeleteIngress(ctx, binding, state, manifest, func(inventory closure.Inventory) (closure.RuntimeObserver, func(context.Context, closure.Inventory) (string, error), error) {
		host, err := contraction.FixedHost(inventory)
		if err != nil {
			return nil, nil, err
		}
		return host.Observer, host.Probe.Run, nil
	})
}

// The binding is historical identity only; no saved observation is accepted.
// This remains usable after normal/safety removal, without recreating either.
func verifyResourceDeleteIngress(ctx context.Context, binding operations.ResourceDeleteBinding, state safety.State, manifest nginx.Manifest, runtime func(closure.Inventory) (closure.RuntimeObserver, func(context.Context, closure.Inventory) (string, error), error)) (string, error) {
	if manifest.InstallationID != binding.InstallationID || manifestContainsResource(manifest, binding.Resource.ID) {
		return "", fmt.Errorf("deleting resource still has a Nginx graph entry or installation mismatch")
	}
	for _, resource := range state.Resources {
		if resource.ResourceID == binding.Resource.ID && (resource.Closing != nil || resource.Contraction != nil || resource.ChallengePending != nil || resource.Reactivating != nil) {
			return "", fmt.Errorf("resource deletion is blocked by pending ingress authority")
		}
	}
	inventory, err := closure.BuildInventory(closure.Inputs{Installation: domain.Installation{InstallationID: binding.InstallationID, Resources: []domain.AppResource{binding.Resource}}, Safety: &state, Ownership: ownership.Inventory{Complete: true, Records: []ownership.Record{binding.Ownership}}, Graph: &manifest, ResourceIDs: []string{binding.Resource.ID}})
	if err != nil || !inventory.Complete {
		return "", fmt.Errorf("resource deletion closure inventory incomplete: %w", err)
	}
	observer, probe, err := runtime(inventory)
	if err != nil {
		return "", err
	}
	started := time.Now().UTC()
	snapshot, err := observer.Observe(ctx)
	if err != nil || !snapshot.Complete || snapshot.ObservedAt.Before(started) || snapshot.Generation != manifest.GenerationID {
		return "", fmt.Errorf("resource deletion Nginx observation incomplete: %w", err)
	}
	stopped := closure.VerifyStopped(snapshot) == nil
	if !stopped {
		if err := closure.VerifyServing(snapshot, manifest.GenerationID, expectedNginxRuntimeListeners(manifest)); err != nil {
			return "", err
		}
	}
	for _, value := range inventory.Identities {
		if value.Kind != closure.IdentityTemporaryListener {
			continue
		}
		for _, listener := range snapshot.Listeners {
			if fmt.Sprintf("%s:%s:%d", listener.Protocol, listener.Address, listener.Port) == value.Value {
				return "", fmt.Errorf("deleted temporary listener remains")
			}
		}
	}
	probeInventory := inventory
	if stopped {
		// A newly verified stopped Nginx cannot perform a TLS handshake. Still
		// require exact connection refusal for every historical temporary port.
		probeInventory.Identities = nil
		for _, value := range inventory.Identities {
			if value.Kind == closure.IdentityTemporaryListener {
				probeInventory.Identities = append(probeInventory.Identities, value)
			}
		}
	}
	probeDigest, err := probe(ctx, probeInventory)
	if err != nil {
		return "", err
	}
	return digestLifecycle(struct {
		Binding   operations.ResourceDeleteBinding
		Inventory closure.Inventory
		Graph     nginx.Manifest
		Runtime   closure.RuntimeSnapshot
		Probe     string
	}{binding, inventory, manifest, snapshot, probeDigest}), nil
}
