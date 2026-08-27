//go:build linux

package activation

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"lanpanel/internal/certificates"
	"lanpanel/internal/child"
	"lanpanel/internal/closure"
	"lanpanel/internal/nginx"
	"net"
	"time"
)

type CertificateActivationResult struct {
	Pointer certificates.PointerResult
	Runtime closure.RuntimeSnapshot
}

func (host Host) ActivateCertificate(ctx context.Context, pointer certificates.Pointer, serverName, candidateFingerprint, priorFingerprint string) (result CertificateActivationResult, resultErr error) {
	if host.Launcher == nil || serverName == "" || pointer.ExpectedPriorGeneration == 0 || !certificateFingerprint(candidateFingerprint) || !certificateFingerprint(priorFingerprint) || certificates.ValidateBundleIdentity(pointer.CandidateIdentity) != nil || certificates.ValidateBundleIdentity(pointer.ExpectedPriorIdentity) != nil || pointer.CandidateIdentity.Fingerprint != candidateFingerprint || pointer.ExpectedPriorIdentity.Fingerprint != priorFingerprint {
		return result, fmt.Errorf("certificate activation authority incomplete")
	}
	manifest, err := nginx.Audit(host.Paths, host.Owner)
	if err != nil {
		return result, err
	}
	prior, err := host.observer(manifest).Observe(ctx)
	if err != nil || prior.Master == nil {
		return result, fmt.Errorf("nginx unavailable for certificate activation")
	}
	pointerResult, err := certificates.ActivatePointer(ctx, pointer)
	result.Pointer = pointerResult
	if err != nil {
		if pointerResult.CandidateTarget == "" {
			return result, err
		}
		restoreErr := host.RestoreCertificate(context.WithoutCancel(ctx), pointer, pointerResult.CandidateTarget, serverName, priorFingerprint)
		return result, &Failure{Cause: errors.Join(err, restoreErr), PriorRestored: restoreErr == nil}
	}
	defer func() {
		if resultErr == nil {
			return
		}
		restoreErr := host.RestoreCertificate(context.WithoutCancel(ctx), pointer, pointerResult.CandidateTarget, serverName, priorFingerprint)
		resultErr = &Failure{Cause: errors.Join(resultErr, restoreErr), PriorRestored: restoreErr == nil}
	}()
	if err := host.run(ctx, child.ProfileNginxTest); err != nil {
		return result, err
	}
	if err := host.run(ctx, child.ProfileNginxReloadSignal); err != nil {
		return result, err
	}
	runtime, err := closure.WaitPriorWorkers(ctx, host.observer(manifest), prior.Workers, nginx.DefaultWorkerTimeout)
	if err != nil || runtime.Master == nil {
		return result, fmt.Errorf("certificate activation prior workers remain")
	}
	if err := probeServedCertificate(ctx, serverName, candidateFingerprint); err != nil {
		return result, err
	}
	result.Runtime = runtime
	return result, nil
}

func (host Host) RestoreCertificate(ctx context.Context, pointer certificates.Pointer, expectedCandidate, serverName, priorFingerprint string) error {
	if pointer.ExpectedPriorGeneration == 0 || !certificateFingerprint(priorFingerprint) || certificates.ValidateBundleIdentity(pointer.CandidateIdentity) != nil || certificates.ValidateBundleIdentity(pointer.ExpectedPriorIdentity) != nil || pointer.ExpectedPriorIdentity.Fingerprint != priorFingerprint {
		return fmt.Errorf("certificate restoration authority incomplete")
	}
	manifest, err := nginx.Audit(host.Paths, host.Owner)
	if err != nil {
		return err
	}
	prior, err := host.observer(manifest).Observe(ctx)
	if err != nil || prior.Master == nil {
		return fmt.Errorf("nginx unavailable for certificate restoration")
	}
	if err := certificates.RestorePointer(ctx, pointer, expectedCandidate); err != nil {
		return err
	}
	if err := host.Reload(ctx); err != nil {
		return err
	}
	runtime, err := closure.WaitPriorWorkers(ctx, host.observer(manifest), prior.Workers, nginx.DefaultWorkerTimeout)
	if err != nil || runtime.Master == nil {
		return fmt.Errorf("certificate restoration prior workers remain")
	}
	return probeServedCertificate(ctx, serverName, priorFingerprint)
}

func (host Host) VerifyServedCertificate(ctx context.Context, serverName, fingerprint string) error {
	if _, err := nginx.Audit(host.Paths, host.Owner); err != nil {
		return err
	}
	return probeServedCertificate(ctx, serverName, fingerprint)
}

func probeServedCertificate(ctx context.Context, serverName, expectedFingerprint string) error {
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}
	connection, err := dialer.DialContext(ctx, "tcp", "127.0.0.1:443")
	if err != nil {
		return fmt.Errorf("probe served certificate: %w", err)
	}
	defer func(ignore func() error) { _ = ignore() }(connection.Close)
	state := connection.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("served certificate missing")
	}
	sum := sha256.Sum256(state.PeerCertificates[0].Raw)
	observed := "sha256:" + hex.EncodeToString(sum[:])
	if observed != expectedFingerprint {
		return fmt.Errorf("served certificate fingerprint mismatched")
	}
	return nil
}

func certificateFingerprint(value string) bool {
	if len(value) != 71 || value[:7] != "sha256:" {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil
}
