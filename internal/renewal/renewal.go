package renewal

import (
	"fmt"
	"lanpanel/internal/domain"
	"lanpanel/internal/safety"
	"time"
)

type Decision string

const (
	DecisionIdle     Decision = "idle"
	DecisionRenew    Decision = "renew"
	DecisionContract Decision = "contract"
)

type Input struct {
	Now         time.Time
	RenewBefore time.Duration
	Publication domain.PublicationRecord
	Safety      safety.State
	ResourceID  string
}

func Evaluate(input Input) (Decision, error) {
	if input.Now.IsZero() || input.RenewBefore <= 0 || input.ResourceID == "" {
		return "", fmt.Errorf("renewal clock authority incomplete")
	}
	if input.Safety.StopFence != nil || input.Safety.GlobalClose.Phase != safety.GlobalCloseNone {
		return DecisionIdle, nil
	}
	var resource *safety.ResourceSafety
	for index := range input.Safety.Resources {
		if input.Safety.Resources[index].ResourceID == input.ResourceID {
			resource = &input.Safety.Resources[index]
		}
	}
	if resource == nil {
		return "", fmt.Errorf("renewal safety resource missing")
	}
	if input.Publication.State != domain.PublicationPublished || input.Publication.LastAppliedBundle == nil || input.Publication.LastAppliedBundle.DomainHTTPS == nil {
		return DecisionIdle, nil
	}
	certificate := input.Publication.LastAppliedBundle.DomainHTTPS.Certificate
	deadline, deadlineErr := time.Parse(time.RFC3339, certificate.NotAfter)
	lastWall, wallErr := time.Parse(time.RFC3339, certificate.LastTrustedWall)
	active := resource.ActiveCertificate
	if deadlineErr != nil || wallErr != nil || active == nil || active.Generation != certificate.Generation || active.Fingerprint != certificate.Fingerprint || active.Binding != certificate.BindingIdentity || !active.NotAfter.Equal(deadline) || active.LastTrustedWall.Before(lastWall) || input.Now.Before(active.LastTrustedWall) || !deadline.After(input.Now) {
		return DecisionContract, nil
	}
	if resource.State != safety.ResourceActive || resource.Ownership != safety.OwnershipOwned || resource.StickyUnpublished != nil || resource.Closing != nil || resource.Contraction != nil || resource.CertificateExpiry != nil || resource.Reactivating != nil || resource.ChallengePending != nil {
		return DecisionIdle, nil
	}
	if !input.Now.Add(input.RenewBefore).Before(deadline) {
		return DecisionRenew, nil
	}
	return DecisionIdle, nil
}

func EvaluateManagementHTTPS(now time.Time, renewBefore time.Duration, config *domain.ManagementHTTPSConfig, state safety.State) (Decision, error) {
	if now.IsZero() || renewBefore <= 0 {
		return "", fmt.Errorf("management HTTPS renewal clock authority incomplete")
	}
	if config == nil || config.Phase != domain.ManagementHTTPSActive || config.CertificateBundle == nil {
		return DecisionIdle, nil
	}
	if state.StopFence != nil || state.GlobalClose.Phase != safety.GlobalCloseNone {
		return DecisionIdle, nil
	}
	certificate := config.CertificateBundle
	deadline, deadlineErr := time.Parse(time.RFC3339, certificate.NotAfter)
	lastWall, wallErr := time.Parse(time.RFC3339, certificate.LastTrustedWall)
	active := state.ManagementHTTPS.ActiveCertificate
	if deadlineErr != nil || wallErr != nil || active == nil || active.Generation != certificate.Generation || active.Fingerprint != certificate.Fingerprint || active.Binding != certificate.BindingIdentity || !active.NotAfter.Equal(deadline) || active.LastTrustedWall.Before(lastWall) || now.Before(active.LastTrustedWall) || !deadline.After(now) {
		return DecisionContract, nil
	}
	if state.ManagementHTTPS.CertificateExpiry != nil || state.ManagementHTTPS.ChallengePending != nil {
		return DecisionIdle, nil
	}
	if !now.Add(renewBefore).Before(deadline) {
		return DecisionRenew, nil
	}
	return DecisionIdle, nil
}

func EvaluateHeadscale(now time.Time, renewBefore time.Duration, headscale *domain.HeadscaleDomain, state safety.State) (Decision, error) {
	if now.IsZero() || renewBefore <= 0 {
		return "", fmt.Errorf("headscale renewal clock authority incomplete")
	}
	if headscale == nil || !headscale.Enabled || headscale.Applied == nil || headscale.Certificate == nil {
		return DecisionIdle, nil
	}
	if state.StopFence != nil || state.GlobalClose.Phase != safety.GlobalCloseNone {
		return DecisionIdle, nil
	}
	certificate := headscale.Certificate
	deadline, deadlineErr := time.Parse(time.RFC3339, certificate.NotAfter)
	wall, wallErr := time.Parse(time.RFC3339, certificate.LastTrustedWall)
	active := state.Headscale.ActiveCertificate
	if deadlineErr != nil || wallErr != nil || active == nil || active.Generation != certificate.Generation || active.Fingerprint != certificate.Fingerprint || active.Binding != certificate.BindingIdentity || !active.NotAfter.Equal(deadline) || active.LastTrustedWall.Before(wall) || now.Before(active.LastTrustedWall) || !deadline.After(now) {
		return DecisionContract, nil
	}
	if state.Headscale.CertificateExpiry != nil || state.Headscale.ChallengePending != nil || state.Headscale.Reactivating != nil {
		return DecisionIdle, nil
	}
	if !now.Add(renewBefore).Before(deadline) {
		return DecisionRenew, nil
	}
	return DecisionIdle, nil
}

func ExpiryMarker(resource safety.ResourceSafety, deadline time.Time, binding string) (safety.ResourceSafety, error) {
	if deadline.IsZero() || binding == "" {
		return safety.ResourceSafety{}, fmt.Errorf("certificate expiry authority incomplete")
	}
	next := resource
	next.GenerationSequence++
	next.CertificateExpiry = &safety.DeadlineMarker{Generation: next.GenerationSequence, Deadline: deadline, Binding: binding}
	return next, nil
}
