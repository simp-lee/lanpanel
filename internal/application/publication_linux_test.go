//go:build linux

package application

import (
	"context"
	"errors"
	"lanpanel/internal/closure"
	"lanpanel/internal/domain"
	"lanpanel/internal/publication"
	"testing"
	"time"
)

type publicationFailureHostProbe struct {
	reloadErr     error
	exhaustReload bool
	stopCtxErr    error
	reloads       int
	stops         int
}

func (host *publicationFailureHostProbe) Reload(ctx context.Context) error {
	host.reloads++
	if host.exhaustReload {
		<-ctx.Done()
		return ctx.Err()
	}
	return host.reloadErr
}

func (host *publicationFailureHostProbe) StopAndVerify(ctx context.Context) (closure.RuntimeSnapshot, error) {
	host.stops++
	host.stopCtxErr = ctx.Err()
	return closure.RuntimeSnapshot{}, nil
}

func TestUnstagedRollbackPreservesReusedAppliedGoAccessOwnership(t *testing.T) {
	execution := PublicationExecution{Candidate: publication.Candidate{Generation: 5, Bundle: domain.PublicationBundle{DomainHTTPS: &domain.DomainHTTPSBundleIdentity{GoAccess: domain.GoAccessBundleIdentity{Enabled: true, Generation: 4, StateGeneration: 4}}}}}
	if err := execution.rollbackUnstagedGoAccessOwnership(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestFailedPublicationStopsNginxDespiteReloadOrContractionFailure(t *testing.T) {
	host := &publicationFailureHostProbe{exhaustReload: true}
	_, reloadErr, stopErr := shutdownFailedPublicationRuntime(host, nil, 10*time.Millisecond, time.Second)
	if !errors.Is(reloadErr, context.DeadlineExceeded) || stopErr != nil || host.stopCtxErr != nil || host.reloads != 1 || host.stops != 1 {
		t.Fatalf("reload deadline shutdown evidence: reload=%v stop=%v stop_context=%v calls=%d/%d", reloadErr, stopErr, host.stopCtxErr, host.reloads, host.stops)
	}
	host = &publicationFailureHostProbe{}
	contractErr := errors.New("contract failed")
	_, reloadErr, stopErr = shutdownFailedPublicationRuntime(host, contractErr, time.Second, time.Second)
	if reloadErr != nil || stopErr != nil || host.stopCtxErr != nil || host.reloads != 0 || host.stops != 1 {
		t.Fatalf("contraction failure shutdown evidence: reload=%v stop=%v stop_context=%v calls=%d/%d", reloadErr, stopErr, host.stopCtxErr, host.reloads, host.stops)
	}
}
