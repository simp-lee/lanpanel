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

type certificateReloadRuntime struct {
	Audit   func(context.Context) (nginx.Manifest, error)
	Observe func(context.Context, nginx.Manifest) (closure.RuntimeSnapshot, error)
	Test    func(context.Context) error
	Signal  func(context.Context) error
	Wait    func(context.Context, nginx.Manifest, []closure.ProcessIdentity) (closure.RuntimeSnapshot, error)
}

func reloadCertificateRuntime(ctx context.Context, authority ReloadAuthority, runtime certificateReloadRuntime) (closure.RuntimeSnapshot, error) {
	if runtime.Audit == nil || runtime.Observe == nil || runtime.Test == nil || runtime.Signal == nil || runtime.Wait == nil {
		return closure.RuntimeSnapshot{}, fmt.Errorf("certificate reload runtime authority incomplete")
	}
	manifest, err := runtime.Audit(ctx)
	if err != nil {
		return closure.RuntimeSnapshot{}, err
	}
	prior, err := runtime.Observe(ctx, manifest)
	if err != nil {
		return closure.RuntimeSnapshot{}, fmt.Errorf("nginx unavailable for certificate reload: %w", err)
	}
	if prior.Master == nil {
		return closure.RuntimeSnapshot{}, fmt.Errorf("nginx unavailable for certificate reload")
	}
	if err := authority.CheckRuntime(); err != nil {
		return closure.RuntimeSnapshot{}, fmt.Errorf("certificate reload runtime package/profile identity changed: %w", err)
	}
	if err := runtime.Test(ctx); err != nil {
		return closure.RuntimeSnapshot{}, err
	}
	if _, err := authority.Current(); err != nil {
		return closure.RuntimeSnapshot{}, err
	}
	manifest, err = runtime.Audit(ctx)
	if err != nil {
		return closure.RuntimeSnapshot{}, err
	}
	if err := guardReload(manifest, authority); err != nil {
		return closure.RuntimeSnapshot{}, fmt.Errorf("certificate reload rejected: %w", err)
	}
	if err := runtime.Signal(ctx); err != nil {
		return closure.RuntimeSnapshot{}, err
	}
	current, err := runtime.Wait(ctx, manifest, prior.Workers)
	if err != nil {
		return closure.RuntimeSnapshot{}, fmt.Errorf("certificate reload prior workers remain: %w", err)
	}
	if current.Master == nil {
		return closure.RuntimeSnapshot{}, fmt.Errorf("certificate reload prior workers remain")
	}
	return current, nil
}

func restoreCertificateRuntime(ctx context.Context, restorePointer func(context.Context) error, reload func(context.Context) (closure.RuntimeSnapshot, error), probe func(context.Context) error) error {
	if restorePointer == nil || reload == nil || probe == nil {
		return fmt.Errorf("certificate restoration runtime authority incomplete")
	}
	if err := restorePointer(ctx); err != nil {
		return err
	}
	if _, err := reload(ctx); err != nil {
		return err
	}
	return probe(ctx)
}

func (host Host) ReloadCertificate(ctx context.Context, authority ReloadAuthority) (closure.RuntimeSnapshot, error) {
	return reloadCertificateRuntime(ctx, authority, certificateReloadRuntime{
		Audit: func(context.Context) (nginx.Manifest, error) {
			return nginx.Audit(host.Paths, host.Owner)
		},
		Observe: func(observeCtx context.Context, manifest nginx.Manifest) (closure.RuntimeSnapshot, error) {
			return host.observer(manifest).Observe(observeCtx)
		},
		Test: func(testCtx context.Context) error {
			return host.run(testCtx, child.ProfileNginxTest)
		},
		Signal: func(signalCtx context.Context) error {
			return host.run(signalCtx, child.ProfileNginxReloadSignal)
		},
		Wait: host.WaitForPriorWorkers,
	})
}

func (host Host) ActivateCertificate(ctx context.Context, pointer certificates.Pointer, serverName, candidateFingerprint, priorFingerprint string, authority, restoreAuthority ReloadAuthority) (result CertificateActivationResult, resultErr error) {
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
	if err := authority.CheckRuntime(); err != nil {
		return result, fmt.Errorf("certificate activation runtime package/profile identity changed: %w", err)
	}
	pointerResult, err := certificates.ActivatePointer(ctx, pointer)
	result.Pointer = pointerResult
	if err != nil {
		if pointerResult.CandidateTarget == "" {
			return result, err
		}
		restoreErr := host.RestoreCertificate(context.WithoutCancel(ctx), pointer, pointerResult.CandidateTarget, serverName, priorFingerprint, restoreAuthority)
		return result, &Failure{Cause: errors.Join(err, restoreErr), PriorRestored: restoreErr == nil}
	}
	defer func() {
		if resultErr == nil {
			return
		}
		restoreErr := host.RestoreCertificate(context.WithoutCancel(ctx), pointer, pointerResult.CandidateTarget, serverName, priorFingerprint, restoreAuthority)
		resultErr = &Failure{Cause: errors.Join(resultErr, restoreErr), PriorRestored: restoreErr == nil}
	}()
	runtime, err := host.ReloadCertificate(ctx, authority)
	if err != nil {
		return result, err
	}
	if err := probeServedCertificate(ctx, serverName, candidateFingerprint); err != nil {
		return result, err
	}
	result.Runtime = runtime
	return result, nil
}

func (host Host) RestoreCertificate(ctx context.Context, pointer certificates.Pointer, expectedCandidate, serverName, priorFingerprint string, authority ReloadAuthority) error {
	if pointer.ExpectedPriorGeneration == 0 || !certificateFingerprint(priorFingerprint) || certificates.ValidateBundleIdentity(pointer.CandidateIdentity) != nil || certificates.ValidateBundleIdentity(pointer.ExpectedPriorIdentity) != nil || pointer.ExpectedPriorIdentity.Fingerprint != priorFingerprint {
		return fmt.Errorf("certificate restoration authority incomplete")
	}
	return restoreCertificateRuntime(ctx, func(restoreCtx context.Context) error {
		return certificates.RestorePointer(restoreCtx, pointer, expectedCandidate)
	}, func(reloadCtx context.Context) (closure.RuntimeSnapshot, error) {
		return host.ReloadCertificate(reloadCtx, authority)
	}, func(probeCtx context.Context) error {
		return probeServedCertificate(probeCtx, serverName, priorFingerprint)
	})
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
