//go:build linux

package control

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	nginxactivation "lanpanel/internal/activation"
	"lanpanel/internal/certificates"
	"lanpanel/internal/challenge"
	"lanpanel/internal/child"
	"lanpanel/internal/closure"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/identity"
	"lanpanel/internal/nginx"
	"lanpanel/internal/safety"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"
)

type ActivationResult struct {
	NginxDigest       string
	RuntimeDigest     string
	CertificateTarget string
	PriorRestored     bool
}
type ActivationHost struct {
	launcher   *child.Launcher
	nginxPaths nginx.Paths
	owner      filetxn.Owner
}

func NewActivationHost() (*ActivationHost, error) {
	launcher, err := child.NewLauncher(child.FixedLanPanelExecutable, child.Identities{})
	if err != nil {
		return nil, err
	}
	return &ActivationHost{launcher: launcher, nginxPaths: nginx.FixedPaths(), owner: filetxn.Owner{UID: 0, GID: 0}}, nil
}

func (host *ActivationHost) Stage(ctx context.Context, bundle ActivationBundle) (returnErr error) {
	if host == nil || host.launcher == nil || ValidateActivation(bundle) != nil {
		return fmt.Errorf("headscale activation staging authority invalid")
	}
	root := filetxn.Owner{UID: 0, GID: 0}
	if err := ensureFixedDirectory(bundle.Paths.ControlRuntime, root, 0o711); err != nil {
		return err
	}
	staging := "/etc/systemd/system/.lanpanel-headscale-filetxn"
	if err := ensureFixedDirectory(staging, root, 0o700); err != nil {
		return err
	}
	store, err := filetxn.Open(filetxn.Config{RootPath: "/etc/systemd/system", Root: filetxn.Metadata{Owner: root, Mode: 0o755}, StagingPath: staging, Staging: filetxn.Metadata{Owner: root, Mode: 0o700}, StagingParents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{root}, AllowedMode: 0o755}}, filetxn.Options{})
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, store.Close()) }()
	for _, value := range []struct {
		path string
		data []byte
	}{{bundle.Paths.ControlSocketUnit, bundle.ControlSocket}, {bundle.Paths.ControlRelayUnit, bundle.ControlRelay}, {bundle.Paths.STUNSocketUnit, bundle.STUNSocket}, {bundle.Paths.STUNRelayUnit, bundle.STUNRelay}, {bundle.Paths.PrivateProbeUnit, bundle.PrivateProbe}} {
		req := filetxn.Request{Path: value.path, Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{root}, AllowedMode: 0o755}, New: filetxn.Metadata{Owner: root, Mode: 0o644}, MaxBytes: int64(len(value.data))}
		if _, err := store.Put(ctx, req, value.data, filetxn.CreateOnly); err != nil {
			if !errors.Is(err, os.ErrExist) {
				return err
			}
			req.Existing = &filetxn.Metadata{Owner: root, Mode: 0o644}
			actual, readErr := store.Read(ctx, req)
			if readErr != nil || !bytes.Equal(actual, value.data) {
				return fmt.Errorf("headscale activation unit differs from exact authority")
			}
		}
	}
	return host.run(ctx, child.ProfileSystemctl, child.Invocation{})
}

func (host *ActivationHost) Activate(ctx context.Context, bundle ActivationBundle, authority ActivationAuthority, reloadAuthority nginxactivation.ReloadAuthority) (result ActivationResult, resultErr error) {
	if err := ValidateActivation(bundle); err != nil {
		return result, err
	}
	if err := ValidateActivationAuthority(bundle, authority); err != nil {
		return result, err
	}
	if _, err := reloadAuthority.Current(); err != nil {
		return result, fmt.Errorf("headscale activation reload authority invalid: %w", err)
	}
	if err := reloadAuthority.CheckRuntime(); err != nil {
		return result, fmt.Errorf("headscale activation runtime package/profile identity changed: %w", err)
	}
	if host == nil || host.launcher == nil {
		return result, fmt.Errorf("headscale activation host authority unavailable")
	}
	activationSnapshot, err := nginx.SnapshotActivation(host.nginxPaths, host.owner, bundle.Entry)
	if err != nil {
		return result, err
	}
	priorManifest := activationSnapshot.Manifest
	candidateManifest, err := nginx.ProspectiveManifest(priorManifest, bundle.Entry)
	if err != nil {
		return result, err
	}
	if decision := nginx.Guard(nginx.GuardInput{Action: nginx.GuardReload, Manifest: candidateManifest, Safety: authority.Safety, Installation: &authority.Installation, Ownership: authority.Ownership, Now: authority.ObservedAt}); !decision.Allowed {
		return result, fmt.Errorf("headscale control pre-activation rejected: %s", decision.Reason)
	}
	runtimeHost, err := nginxactivation.NewFixedHost()
	if err != nil {
		return result, err
	}
	priorRuntime, err := runtimeHost.ObserveRuntime(ctx, priorManifest)
	if err != nil || priorRuntime.Master == nil {
		return result, fmt.Errorf("prior Nginx runtime unavailable: %w", err)
	}
	for _, entry := range priorManifest.Entries {
		if entry.Kind == nginx.EntryControl {
			return result, fmt.Errorf("foreign Headscale control ingress already exists")
		}
	}
	priorGeneration := uint64(0)
	priorIdentity := certificates.BundleIdentity{}
	if bundle.Prior != nil {
		if bundle.PriorCertificate == nil {
			return result, fmt.Errorf("headscale reactivation prior certificate identity missing")
		}
		priorGeneration = bundle.PriorCertificate.Generation
		priorIdentity = certificates.BundleIdentityFor(*bundle.PriorCertificate)
	}
	pointer := certificates.Pointer{CertificateID: bundle.Certificate.ID, CandidateGeneration: bundle.Certificate.Generation, CandidateIdentity: certificates.BundleIdentityFor(bundle.Certificate), ExpectedPriorGeneration: priorGeneration, ExpectedPriorIdentity: priorIdentity}
	pointerResult, pointerErr := certificates.ActivatePointer(ctx, pointer)
	if pointerResult.CandidateTarget == "" {
		if pointerErr == nil {
			pointerErr = fmt.Errorf("certificate pointer activation result is incomplete")
		}
		return result, pointerErr
	}
	result.CertificateTarget = pointerResult.CandidateTarget
	entryMutationAttempted := false
	socketMutationAttempted := false
	defer func() {
		if resultErr == nil {
			return
		}
		recovery := context.Background()
		cleanup := runActivationRollback(socketMutationAttempted, entryMutationAttempted, activationRollbackActions{
			stopSockets: func() error {
				return host.run(recovery, child.ProfileHeadscaleActivateStop, child.Invocation{Headscale: &child.HeadscaleInvocation{HeadscaleID: bundle.Candidate.HeadscaleID}})
			},
			removeEntry: func() error {
				_, restoreErr := nginx.RestoreActivation(recovery, host.nginxPaths, host.owner, bundle.Entry, activationSnapshot)
				return restoreErr
			},
			testNginx: func() error {
				return host.run(recovery, child.ProfileNginxTest, child.Invocation{})
			},
			reloadNginx: func() error {
				if _, authorityErr := reloadAuthority.Current(); authorityErr != nil {
					return authorityErr
				}
				currentManifest, auditErr := nginx.Audit(host.nginxPaths, host.owner)
				if auditErr != nil {
					return auditErr
				}
				currentRuntime, observeErr := runtimeHost.ObserveRuntime(recovery, currentManifest)
				if observeErr != nil {
					return observeErr
				}
				if guardErr := reloadAuthority.Guard(currentManifest); guardErr != nil {
					return fmt.Errorf("headscale control rollback reload rejected: %w", guardErr)
				}
				reloadErr := host.run(recovery, child.ProfileNginxReloadSignal, child.Invocation{})
				_, waitErr := runtimeHost.WaitForPriorWorkers(recovery, currentManifest, currentRuntime.Workers)
				return errors.Join(reloadErr, waitErr)
			},
			restorePointer: func() error {
				if pointer.ExpectedPriorGeneration == 0 {
					return certificates.RemovePointer(recovery, pointer, pointerResult.CandidateTarget)
				}
				return certificates.RestorePointer(recovery, pointer, pointerResult.CandidateTarget)
			},
		})
		result.PriorRestored = cleanup == nil
		resultErr = errors.Join(resultErr, cleanup)
	}()
	if pointerErr != nil {
		return result, pointerErr
	}
	entryMutationAttempted = true
	manifest, _, err := nginx.InstallEntry(ctx, host.nginxPaths, host.owner, bundle.Entry)
	if err != nil {
		return result, err
	}
	if decision := nginx.Guard(nginx.GuardInput{Action: nginx.GuardReload, Manifest: manifest, Safety: authority.Safety, Installation: &authority.Installation, Ownership: authority.Ownership, Now: authority.ObservedAt}); !decision.Allowed {
		return result, fmt.Errorf("headscale control reload rejected: %s", decision.Reason)
	}
	if err := host.runBoundedOutput(ctx, child.ProfileNginxDump, child.Invocation{}); err != nil {
		return result, err
	}
	if err := host.run(ctx, child.ProfileNginxTest, child.Invocation{}); err != nil {
		return result, err
	}
	invocation := child.Invocation{Headscale: &child.HeadscaleInvocation{HeadscaleID: bundle.Candidate.HeadscaleID}}
	socketMutationAttempted = true
	if err := host.run(ctx, child.ProfileHeadscaleActivateStart, invocation); err != nil {
		return result, err
	}
	if _, err := reloadAuthority.Current(); err != nil {
		return result, err
	}
	manifest, err = nginx.Audit(host.nginxPaths, host.owner)
	if err != nil {
		return result, err
	}
	if guardErr := reloadAuthority.Guard(manifest); guardErr != nil {
		return result, fmt.Errorf("headscale control reload rejected at signal: %w", guardErr)
	}
	if err := host.run(ctx, child.ProfileNginxReloadSignal, child.Invocation{}); err != nil {
		return result, err
	}
	if _, err := runtimeHost.WaitForPriorWorkers(ctx, manifest, priorRuntime.Workers); err != nil {
		return result, fmt.Errorf("headscale control Nginx generation unavailable: %w", err)
	}
	probeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	runtimeDigest, err := probeActivatedControl(probeCtx, bundle.Candidate.ControlDomain)
	if err != nil {
		return result, err
	}
	if err := probeSTUN(probeCtx); err != nil {
		return result, err
	}
	effectiveDigest, err := host.verifyEffectiveActivation(probeCtx, bundle, invocation, bundle.Prior != nil, true, true)
	if err != nil {
		return result, err
	}
	result.NginxDigest = manifest.MainDigest
	result.RuntimeDigest = hashBytes([]byte(bundle.Digest + "\x00" + manifest.GenerationID + "\x00" + runtimeDigest + "\x00stun-ok\x00" + effectiveDigest))
	return result, nil
}

func (host *ActivationHost) CommitBootActivation(ctx context.Context, bundle ActivationBundle, rendered Rendered, reloadAuthority nginxactivation.ReloadAuthority) error {
	return host.persistBootActivation(ctx, bundle, rendered, reloadAuthority, child.ProfileHeadscaleBootEnable, true)
}

func (host *ActivationHost) ObserveBootActivation(ctx context.Context, bundle ActivationBundle, rendered Rendered, reloadAuthority nginxactivation.ReloadAuthority) error {
	return host.persistBootActivation(ctx, bundle, rendered, reloadAuthority, "", false)
}

func (host *ActivationHost) ObserveCommittedActivation(ctx context.Context, bundle ActivationBundle) error {
	if host == nil || host.launcher == nil || ValidateActivation(bundle) != nil {
		return fmt.Errorf("headscale committed activation observation authority invalid")
	}
	invocation := child.Invocation{Headscale: &child.HeadscaleInvocation{HeadscaleID: bundle.Candidate.HeadscaleID}}
	_, err := host.verifyEffectiveActivation(ctx, bundle, invocation, true, true, false)
	return err
}

// ReconcileBootActivation is the startup-safe form of the same committed
// transition. --no-block avoids waiting on units ordered after the recovery
// service which is currently asking the helper to reconcile them.
func (host *ActivationHost) ReconcileBootActivation(ctx context.Context, bundle ActivationBundle, rendered Rendered, reloadAuthority nginxactivation.ReloadAuthority) error {
	return host.persistBootActivation(ctx, bundle, rendered, reloadAuthority, child.ProfileHeadscaleBootReconcile, false)
}

func (host *ActivationHost) persistBootActivation(ctx context.Context, bundle ActivationBundle, rendered Rendered, reloadAuthority nginxactivation.ReloadAuthority, profile child.ProfileID, requireActive bool) error {
	if host == nil || host.launcher == nil || ValidateActivation(bundle) != nil || VerifyRendered(rendered) != nil || !reflect.DeepEqual(bundle.Candidate, rendered.Candidate) || profile != "" && profile != child.ProfileHeadscaleBootEnable && profile != child.ProfileHeadscaleBootReconcile {
		return fmt.Errorf("headscale boot activation authority invalid")
	}
	current, err := reloadAuthority.Current()
	if err != nil {
		return fmt.Errorf("headscale boot activation guard authority invalid: %w", err)
	}
	if err := reloadAuthority.CheckRuntime(); err != nil {
		return fmt.Errorf("headscale boot activation runtime package/profile identity changed: %w", err)
	}
	manifest, err := nginx.Audit(host.nginxPaths, host.owner)
	if err != nil {
		return err
	}
	if err := validateCommittedBootActivation(bundle, current, manifest); err != nil {
		return err
	}
	decision := nginx.Guard(nginx.GuardInput{Action: nginx.GuardStart, Manifest: manifest, Safety: current.Safety, Installation: &current.Installation, Ownership: current.Ownership, Now: current.ObservedAt})
	if !decision.Allowed {
		if !expiredCommittedBootPersistenceAllowed(bundle, current, decision) {
			return fmt.Errorf("headscale boot activation rejected: %s", decision.Reason)
		}
		if profile == child.ProfileHeadscaleBootReconcile {
			// The original deploy still needs its exact terminal local commit, but
			// an expired certificate must not start data-plane units. Persist only
			// their boot links; the expiry owner closes control ingress separately.
			profile = child.ProfileHeadscaleBootPersist
		} else if profile != "" {
			return fmt.Errorf("headscale boot activation rejected: %s", decision.Reason)
		}
	}
	invocation := child.Invocation{Headscale: &child.HeadscaleInvocation{HeadscaleID: bundle.Candidate.HeadscaleID}}
	if profile != "" {
		if err := host.run(ctx, profile, invocation); err != nil {
			return err
		}
	}
	serviceState := headscaleServiceSettled
	if requireActive {
		serviceState = headscaleServiceActive
	}
	runtime := &SystemdRuntime{launcher: host.launcher}
	if _, err := runtime.observe(ctx, rendered, identity.AccountIdentity{Role: identity.RoleHeadscale, User: bundle.ServiceUser, Group: bundle.ServiceGroup}, serviceState, "enabled"); err != nil {
		return err
	}
	_, err = host.verifyEffectiveActivation(ctx, bundle, invocation, true, requireActive, requireActive)
	return err
}

func validateCommittedBootActivation(bundle ActivationBundle, current nginxactivation.ReloadAuthoritySnapshot, manifest nginx.Manifest) error {
	headscale := current.Installation.Headscale
	expectedApplied := AppliedFromActivation(bundle)
	if current.Installation.InstallationID != bundle.InstallationID || headscale == nil || !headscale.Enabled || headscale.DeployIntent != nil || headscale.Applied == nil || !reflect.DeepEqual(*headscale.Applied, expectedApplied) || headscale.ID != bundle.Candidate.HeadscaleID || headscale.ControlDomain != bundle.Candidate.ControlDomain || headscale.MagicDNSNamespace != bundle.Candidate.MagicDNSNamespace || headscale.Policy != "trusted_mesh" || !reflect.DeepEqual(headscale.Artifact, bundle.Candidate.Artifact) || headscale.Database.UUID != bundle.Candidate.DatabaseUUID || headscale.Database.Generation != bundle.Candidate.DatabaseGeneration || headscale.Database.SQLitePath != bundle.Candidate.Paths.Database || headscale.Certificate == nil || headscale.Certificate.Authority == nil {
		return fmt.Errorf("headscale committed boot authority changed")
	}
	certificate := headscale.Certificate
	if certificate.Authority.CertificateID != bundle.Certificate.ID || certificate.Generation != bundle.Certificate.Generation || certificate.Fingerprint != bundle.Certificate.Fingerprint || certificate.BindingIdentity != bundle.Certificate.BindingIdentity || certificate.SANIdentity != bundle.Certificate.SANIdentity || certificate.ChainIdentity != bundle.Certificate.ChainIdentity || certificate.IssuerIdentity != bundle.Certificate.IssuerIdentity || certificate.DirectoryIdentity != bundle.Certificate.DirectoryIdentity || !sameCertificateTime(certificate.NotAfter, bundle.Certificate.NotAfter) || !sameCertificateTime(certificate.LastTrustedWall, bundle.Certificate.LastTrustedWall) {
		return fmt.Errorf("headscale committed boot certificate authority changed")
	}
	active := current.Safety.Headscale.ActiveCertificate
	if current.Safety.Headscale.Reactivating != nil || active == nil || current.Safety.Headscale.ControlEntryDigest != bundle.Entry.Digest || active.Generation != bundle.Certificate.Generation || active.Fingerprint != bundle.Certificate.Fingerprint || active.Binding != bundle.Certificate.BindingIdentity || !active.NotAfter.Equal(bundle.Certificate.NotAfter) || active.LastTrustedWall.Before(bundle.Certificate.LastTrustedWall) {
		return fmt.Errorf("headscale committed boot safety authority changed")
	}
	matched := 0
	for _, entry := range manifest.Entries {
		if reflect.DeepEqual(entry, bundle.Entry) {
			matched++
		}
	}
	if matched != 1 {
		return fmt.Errorf("headscale committed boot control graph changed")
	}
	return nil
}

func expiredCommittedBootPersistenceAllowed(bundle ActivationBundle, current nginxactivation.ReloadAuthoritySnapshot, decision nginx.GuardDecision) bool {
	if decision.Reason != "control ingress lacks valid committed Headscale certificate authority" {
		return false
	}
	active := current.Safety.Headscale.ActiveCertificate
	if active == nil {
		return false
	}
	marker := current.Safety.Headscale.CertificateExpiry
	marked := marker != nil && marker.Binding == active.Binding
	return marked || !current.ObservedAt.Before(bundle.Certificate.NotAfter)
}

func sameCertificateTime(raw string, expected time.Time) bool {
	parsed, err := time.Parse(time.RFC3339, raw)
	return err == nil && parsed.Equal(expected.Truncate(time.Second))
}

type activationRollbackActions struct {
	stopSockets    func() error
	removeEntry    func() error
	testNginx      func() error
	reloadNginx    func() error
	restorePointer func() error
}

func runActivationRollback(socketMutationAttempted, entryMutationAttempted bool, actions activationRollbackActions) error {
	var rollbackErr error
	if socketMutationAttempted {
		rollbackErr = errors.Join(rollbackErr, actions.stopSockets())
	}
	var removeErr error
	if entryMutationAttempted {
		removeErr = actions.removeEntry()
		rollbackErr = errors.Join(rollbackErr, removeErr)
	}
	restoreErr := actions.restorePointer()
	rollbackErr = errors.Join(rollbackErr, restoreErr)
	if entryMutationAttempted {
		testErr := actions.testNginx()
		rollbackErr = errors.Join(rollbackErr, testErr)
		if removeErr == nil && restoreErr == nil && testErr == nil {
			rollbackErr = errors.Join(rollbackErr, actions.reloadNginx())
		}
	}
	return rollbackErr
}

func headscaleChallengeEntry(bundle ActivationBundle, prepared challenge.Prepared) (nginx.Entry, error) {
	if prepared.Entry == nil || prepared.Entry.ResourceID != "headscale" || prepared.Entry.Challenge == nil || prepared.Safety.Method != "http-01" || prepared.Safety.Host != bundle.Candidate.ControlDomain || len(prepared.Entry.Domains) != 1 || prepared.Entry.Domains[0] != bundle.Candidate.ControlDomain {
		return nginx.Entry{}, fmt.Errorf("headscale renewal challenge authority invalid")
	}
	entry := bundle.Entry
	challengeSite := *prepared.Entry.Challenge
	entry.Challenge = &challengeSite
	entry.Digest = controlZeroDigest()
	digest, err := nginx.DigestEntry(entry)
	if err != nil {
		return nginx.Entry{}, err
	}
	entry.Digest = digest
	return entry, nil
}

func sameNginxEntry(left, right nginx.Entry) bool {
	leftBytes, leftErr := json.Marshal(left)
	rightBytes, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func (host *ActivationHost) certificateChallengeRuntime(runtimeHost nginxactivation.Host, prior closure.RuntimeSnapshot) nginxactivation.ChallengeGraphRuntime {
	return nginxactivation.ChallengeGraphRuntime{
		Activate: func(runCtx context.Context, manifest nginx.Manifest, authorize func() error) error {
			if err := host.run(runCtx, child.ProfileNginxTest, child.Invocation{}); err != nil {
				return err
			}
			if err := authorize(); err != nil {
				return err
			}
			if err := host.run(runCtx, child.ProfileNginxReloadSignal, child.Invocation{}); err != nil {
				return err
			}
			_, err := runtimeHost.WaitForPriorWorkers(runCtx, manifest, prior.Workers)
			return err
		},
		Observe: func(observeCtx context.Context, manifest nginx.Manifest) ([]closure.ProcessIdentity, error) {
			current, err := runtimeHost.ObserveRuntime(observeCtx, manifest)
			return current.Workers, err
		},
		Restore: func(restoreCtx context.Context, manifest nginx.Manifest, workers []closure.ProcessIdentity, authorize func() error) error {
			if err := host.run(restoreCtx, child.ProfileNginxTest, child.Invocation{}); err != nil {
				return err
			}
			if err := authorize(); err != nil {
				return err
			}
			if err := host.run(restoreCtx, child.ProfileNginxReloadSignal, child.Invocation{}); err != nil {
				return err
			}
			_, err := runtimeHost.WaitForPriorWorkers(restoreCtx, manifest, workers)
			return err
		},
	}
}

func (host *ActivationHost) ActivateCertificateChallenge(ctx context.Context, bundle ActivationBundle, prepared challenge.Prepared, authority nginxactivation.ChallengeReloadAuthority) error {
	entry, err := headscaleChallengeEntry(bundle, prepared)
	if err != nil {
		return err
	}
	diskSnapshot, prospective, err := nginxactivation.PrepareChallengeExpansion(host.nginxPaths, host.owner, entry, authority)
	if err != nil {
		return fmt.Errorf("headscale challenge reload rejected: %w", err)
	}
	if !diskSnapshot.EntryPresent || !sameNginxEntry(diskSnapshot.Entry, bundle.Entry) && !sameNginxEntry(diskSnapshot.Entry, entry) {
		return fmt.Errorf("headscale challenge prior graph changed")
	}
	runtimeHost, err := nginxactivation.NewFixedHost()
	if err != nil {
		return err
	}
	priorRuntime, err := runtimeHost.ObserveRuntime(ctx, diskSnapshot.Manifest)
	if err != nil || priorRuntime.Master == nil {
		return fmt.Errorf("headscale challenge prior Nginx runtime unavailable: %w", err)
	}
	_, err = nginxactivation.CommitChallengeGraph(ctx, host.nginxPaths, host.owner, entry, diskSnapshot, prospective, authority, func(changeCtx context.Context) (nginx.Manifest, []string, error) {
		return nginx.InstallEntry(changeCtx, host.nginxPaths, host.owner, entry)
	}, host.certificateChallengeRuntime(runtimeHost, priorRuntime))
	return err
}

func prospectiveCertificateChallengeRemoval(snapshot nginx.ActivationSnapshot, bundle ActivationBundle, entry nginx.Entry) (nginx.Manifest, error) {
	if !snapshot.EntryPresent || !sameNginxEntry(snapshot.Entry, entry) && !sameNginxEntry(snapshot.Entry, bundle.Entry) {
		return nginx.Manifest{}, fmt.Errorf("headscale challenge graph changed before removal")
	}
	return nginx.ProspectiveManifest(snapshot.Manifest, bundle.Entry)
}

func (host *ActivationHost) RemoveCertificateChallenge(ctx context.Context, bundle ActivationBundle, prepared challenge.Prepared, authority nginxactivation.ChallengeReloadAuthority) error {
	authority = authority.ForContraction()
	entry, err := headscaleChallengeEntry(bundle, prepared)
	if err != nil {
		return err
	}
	diskSnapshot, err := nginx.SnapshotActivation(host.nginxPaths, host.owner, entry)
	if err != nil {
		return err
	}
	prospective, err := prospectiveCertificateChallengeRemoval(diskSnapshot, bundle, entry)
	if err != nil {
		return err
	}
	runtimeHost, err := nginxactivation.NewFixedHost()
	if err != nil {
		return err
	}
	priorRuntime, err := runtimeHost.ObserveRuntime(ctx, diskSnapshot.Manifest)
	if err != nil {
		return fmt.Errorf("headscale challenge prior Nginx runtime unavailable: %w", err)
	}
	running := priorRuntime.Master != nil
	if !running && (len(priorRuntime.Workers) != 0 || len(priorRuntime.Listeners) != 0) {
		return fmt.Errorf("stopped Headscale challenge Nginx runtime is inconsistent")
	}
	runtime := nginxactivation.StoppedChallengeGraphRuntime(runtimeHost.ObserveRuntime)
	if running {
		runtime = host.certificateChallengeRuntime(runtimeHost, priorRuntime)
	}
	_, err = nginxactivation.CommitChallengeGraph(ctx, host.nginxPaths, host.owner, entry, diskSnapshot, prospective, authority, func(changeCtx context.Context) (nginx.Manifest, []string, error) {
		return nginx.InstallEntry(changeCtx, host.nginxPaths, host.owner, bundle.Entry)
	}, runtime)
	return err
}

func (host *ActivationHost) CloseControl(ctx context.Context, bundle ActivationBundle) error {
	if host == nil || ValidateActivation(bundle) != nil {
		return fmt.Errorf("headscale control closure authority invalid")
	}
	runtimeHost, err := nginxactivation.NewFixedHost()
	if err != nil {
		return err
	}
	prior, err := nginx.Audit(host.nginxPaths, host.owner)
	if err != nil {
		return err
	}
	runtime, err := runtimeHost.ObserveRuntime(ctx, prior)
	if err != nil {
		return err
	}
	manifest, _, err := nginx.RemoveEntry(ctx, host.nginxPaths, host.owner, bundle.Entry)
	if err != nil {
		return err
	}
	if err := host.run(ctx, child.ProfileNginxTest, child.Invocation{}); err != nil {
		return err
	}
	if err := host.run(ctx, child.ProfileNginxReloadSignal, child.Invocation{}); err != nil {
		return err
	}
	if _, err := runtimeHost.WaitForPriorWorkers(ctx, manifest, runtime.Workers); err != nil {
		return err
	}
	inventory := closure.Inventory{Complete: true, Digest: bundle.Digest, Identities: []closure.Identity{{ResourceID: "headscale", Kind: closure.IdentityDomain, Value: bundle.Candidate.ControlDomain, Digest: bundle.Entry.Digest}}}
	probe := closure.NegativeProbe{TLSAddress: "127.0.0.1:443", DefaultCertFingerprint: manifest.DefaultCertFingerprint, AuditPath: host.nginxPaths.AuditPath, TargetObserved: func(context.Context, closure.Inventory, string, string) (bool, error) { return false, nil }}
	_, err = probe.Run(ctx, inventory)
	return err
}

func (host *ActivationHost) CloseControlCertificateRecovery(ctx context.Context, bundle ActivationBundle, authority nginxactivation.ReloadAuthority) error {
	if host == nil || ValidateActivation(bundle) != nil {
		return fmt.Errorf("headscale control certificate recovery authority invalid")
	}
	authority = authority.ForContraction()
	runtimeHost, err := nginxactivation.NewFixedHost()
	if err != nil {
		return err
	}
	prior, err := nginx.Audit(host.nginxPaths, host.owner)
	if err != nil {
		return err
	}
	runtime, err := runtimeHost.ObserveRuntime(ctx, prior)
	if err != nil || runtime.Master == nil {
		return fmt.Errorf("headscale control certificate recovery runtime unavailable: %w", err)
	}
	manifest, _, err := nginx.RemoveEntry(ctx, host.nginxPaths, host.owner, bundle.Entry)
	if err != nil {
		return err
	}
	if _, err := runtimeHost.ReloadCertificate(ctx, authority); err != nil {
		return err
	}
	inventory := closure.Inventory{Complete: true, Digest: bundle.Digest, Identities: []closure.Identity{{ResourceID: "headscale", Kind: closure.IdentityDomain, Value: bundle.Candidate.ControlDomain, Digest: bundle.Entry.Digest}}}
	probe := closure.NegativeProbe{TLSAddress: "127.0.0.1:443", DefaultCertFingerprint: manifest.DefaultCertFingerprint, AuditPath: host.nginxPaths.AuditPath, TargetObserved: func(context.Context, closure.Inventory, string, string) (bool, error) { return false, nil }}
	_, err = probe.Run(ctx, inventory)
	return err
}

func (host *ActivationHost) Contract(ctx context.Context, bundle ActivationBundle) error {
	if host == nil || ValidateActivation(bundle) != nil || bundle.Prior != nil {
		return fmt.Errorf("headscale activation host authority unavailable")
	}
	invocation := child.Invocation{Headscale: &child.HeadscaleInvocation{HeadscaleID: bundle.Candidate.HeadscaleID}}
	runtimeHost, runtimeHostErr := nginxactivation.NewFixedHost()
	priorManifest, auditErr := nginx.Audit(host.nginxPaths, host.owner)
	priorRuntime, observeRuntimeErr := runtimeHost.ObserveRuntime(context.WithoutCancel(ctx), priorManifest)
	disableErr := host.run(context.WithoutCancel(ctx), child.ProfileHeadscaleBootDisable, invocation)
	stopErr := host.run(context.WithoutCancel(ctx), child.ProfileHeadscaleActivateStop, invocation)
	manifest, _, removeErr := nginx.RemoveEntry(context.WithoutCancel(ctx), host.nginxPaths, host.owner, bundle.Entry)
	reloadErr := host.run(context.WithoutCancel(ctx), child.ProfileNginxTest, child.Invocation{})
	if reloadErr == nil {
		reloadErr = host.run(context.WithoutCancel(ctx), child.ProfileNginxReloadSignal, child.Invocation{})
	}
	var controlAbsentErr error
	if reloadErr == nil && runtimeHostErr == nil && auditErr == nil && observeRuntimeErr == nil {
		_, controlAbsentErr = runtimeHost.WaitForPriorWorkers(context.WithoutCancel(ctx), manifest, priorRuntime.Workers)
	}
	if controlAbsentErr == nil && (runtimeHostErr != nil || auditErr != nil || observeRuntimeErr != nil) {
		controlAbsentErr = errors.Join(runtimeHostErr, auditErr, observeRuntimeErr)
	}
	if controlAbsentErr == nil {
		controlAbsentErr = requireControlAbsent(context.WithoutCancel(ctx), bundle.Candidate.ControlDomain)
	}
	serviceErr := host.run(context.WithoutCancel(ctx), child.ProfileHeadscaleStop, invocation)
	pointer := certificates.Pointer{CertificateID: bundle.Certificate.ID, CandidateGeneration: bundle.Certificate.Generation, CandidateIdentity: certificates.BundleIdentityFor(bundle.Certificate)}
	current, observeErr := certificates.ObservePointer(bundle.Certificate.ID)
	var pointerErr error
	if observeErr == nil && current != "" {
		pointerErr = certificates.RemovePointer(context.WithoutCancel(ctx), pointer, current)
	}
	listenerErr := requirePublicSTUNAbsent()
	return errors.Join(disableErr, stopErr, removeErr, reloadErr, controlAbsentErr, serviceErr, observeErr, pointerErr, listenerErr)
}

func (host *ActivationHost) FallbackStop(ctx context.Context, bundle ActivationBundle) (safety.StopObservation, error) {
	observed := safety.StopObservation{ObservedAt: time.Now().UTC()}
	if host == nil || ValidateActivation(bundle) != nil {
		return observed, fmt.Errorf("headscale fallback-stop authority invalid")
	}
	invocation := child.Invocation{Headscale: &child.HeadscaleInvocation{HeadscaleID: bundle.Candidate.HeadscaleID}}
	disableErr := host.run(context.WithoutCancel(ctx), child.ProfileHeadscaleBootDisable, invocation)
	if err := host.run(context.WithoutCancel(ctx), child.ProfileHeadscaleFallbackStop, child.Invocation{}); err != nil {
		return observed, errors.Join(disableErr, err)
	}
	if _, err := os.Lstat(host.nginxPaths.PIDPath); !errors.Is(err, os.ErrNotExist) {
		return observed, fmt.Errorf("nginx PID authority remained after fallback stop: %w", err)
	}
	if err := requirePublicListenersAbsent(); err != nil {
		return observed, err
	}
	observed.MasterStopped, observed.WorkersStopped, observed.ListenersStopped = true, true, true
	return observed, disableErr
}

func (host *ActivationHost) runBoundedOutput(ctx context.Context, profile child.ProfileID, invocation child.Invocation) error {
	result, err := host.launcher.RunInvocation(ctx, profile, invocation, nil)
	if err != nil || result.ExitCode != 0 || result.OutputCutOff {
		return fmt.Errorf("fixed Headscale activation inspection failed: %w", err)
	}
	return nil
}

func (host *ActivationHost) run(ctx context.Context, profile child.ProfileID, invocation child.Invocation) error {
	result, err := host.launcher.RunInvocation(ctx, profile, invocation, nil)
	if err != nil || result.ExitCode != 0 || result.OutputCutOff || len(result.Stdout) != 0 {
		return fmt.Errorf("fixed Headscale activation action failed: %w", err)
	}
	return nil
}

func (host *ActivationHost) verifyEffectiveActivation(ctx context.Context, bundle ActivationBundle, invocation child.Invocation, enabled, requireSocketsActive, requireRelaysActive bool) (string, error) {
	result, err := host.launcher.RunInvocation(ctx, child.ProfileHeadscaleActivateShow, invocation, nil)
	if err != nil || result.ExitCode != 0 || result.OutputCutOff {
		return "", fmt.Errorf("observe effective Headscale activation units: %w", err)
	}
	units := map[string]map[string]string{}
	for _, block := range bytes.Split(bytes.TrimSpace(result.Stdout), []byte("\n\n")) {
		properties := map[string]string{}
		for _, line := range bytes.Split(block, []byte("\n")) {
			parts := bytes.SplitN(line, []byte("="), 2)
			if len(parts) != 2 {
				return "", fmt.Errorf("effective Headscale unit output malformed")
			}
			properties[string(parts[0])] = string(parts[1])
		}
		if properties["Id"] == "" || units[properties["Id"]] != nil {
			return "", fmt.Errorf("effective Headscale unit identity ambiguous")
		}
		units[properties["Id"]] = properties
	}
	expected := map[string]string{"lanpanel-headscale-control.socket": bundle.Paths.ControlSocketUnit, "lanpanel-headscale-control-relay.service": bundle.Paths.ControlRelayUnit, "lanpanel-headscale-stun.socket": bundle.Paths.STUNSocketUnit, "lanpanel-headscale-stun-relay.service": bundle.Paths.STUNRelayUnit}
	if len(units) != len(expected) {
		return "", fmt.Errorf("effective Headscale unit set changed")
	}
	for id, path := range expected {
		value := units[id]
		if value == nil || value["LoadState"] != "loaded" || value["FragmentPath"] != path || value["DropInPaths"] != "" {
			return "", fmt.Errorf("effective Headscale unit %s changed", id)
		}
		isSocket := strings.HasSuffix(id, ".socket")
		expectedUnitFileState := "static"
		if isSocket {
			expectedUnitFileState = "disabled"
			if enabled {
				expectedUnitFileState = "enabled"
			}
		}
		if value["UnitFileState"] != expectedUnitFileState {
			return "", fmt.Errorf("effective Headscale unit %s boot state changed", id)
		}
		active := value["ActiveState"] == "active"
		pending := value["ActiveState"] == "activating"
		requireActive := isSocket && requireSocketsActive || !isSocket && requireRelaysActive
		if requireActive && !active || !active && !pending && value["ActiveState"] != "inactive" {
			return "", fmt.Errorf("effective Headscale unit %s runtime state changed", id)
		}
		if isSocket {
			if active && value["SubState"] != "listening" || !active && value["SubState"] == "listening" || value["SocketMode"] != "0600" || value["RemoveOnStop"] != "yes" || value["FreeBind"] != "no" || value["ReusePort"] != "no" {
				return "", fmt.Errorf("headscale activation socket is not exact")
			}
			if id == "lanpanel-headscale-control.socket" && (value["SocketUser"] != "www-data" || value["SocketGroup"] != "www-data" || !strings.Contains(value["Listen"], bundle.Candidate.Paths.ControlSocket)) {
				return "", fmt.Errorf("headscale control socket identity changed")
			}
			if id == "lanpanel-headscale-stun.socket" && (value["SocketUser"] != bundle.ServiceUser || value["SocketGroup"] != bundle.ServiceGroup || !strings.Contains(value["Listen"], "0.0.0.0:3478")) {
				return "", fmt.Errorf("headscale STUN socket identity changed")
			}
		} else if active && value["SubState"] != "running" || !active && value["SubState"] == "running" || value["User"] != bundle.ServiceUser || value["Group"] != bundle.ServiceGroup || value["NoNewPrivileges"] != "yes" || value["PrivateNetwork"] != "yes" || !strings.Contains(value["JoinsNamespaceOf"], "lanpanel-headscale.service") || value["CapabilityBoundingSet"] != "" || value["AmbientCapabilities"] != "" || value["ProtectSystem"] != "strict" || value["ProtectHome"] != "yes" || value["ProtectProc"] != "invisible" || value["ProcSubset"] != "pid" || value["ProtectKernelTunables"] != "yes" || value["ProtectKernelModules"] != "yes" || value["ProtectControlGroups"] != "yes" || value["LockPersonality"] != "yes" || value["MemoryDenyWriteExecute"] != "yes" || value["SystemCallArchitectures"] != "native" || value["RestrictSUIDSGID"] != "yes" || value["KillMode"] != "control-group" || value["Restart"] != "no" || !strings.Contains(value["ExecStart"], "/usr/lib/lanpanel/lanpanel headscale-") {
			return "", fmt.Errorf("effective Headscale relay %s changed", id)
		}
	}
	return result.StdoutDigest, nil
}

func probeActivatedControl(ctx context.Context, domain string) (string, error) {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{ServerName: domain, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp4", "127.0.0.1:443")
	}}
	defer transport.CloseIdleConnections()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+domain+"/health", nil)
	request.Host = domain
	response, err := transport.RoundTrip(request)
	if err != nil {
		return "", err
	}
	defer func(ignore func() error) { _ = ignore() }(response.Body.Close)
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("headscale control HTTPS probe status %d", response.StatusCode)
	}
	return hashBytes([]byte(fmt.Sprintf("%s/%d/%s", domain, response.StatusCode, response.TLS.PeerCertificates[0].SerialNumber))), nil
}

func requireControlAbsent(ctx context.Context, domain string) error {
	deadline := time.Now().Add(12 * time.Second)
	consecutive := 0
	for time.Now().Before(deadline) {
		dialer := &net.Dialer{Timeout: time.Second}
		transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{ServerName: domain, MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", "127.0.0.1:443")
		}} // #nosec G402 -- local negative-observation probe deliberately accepts the rejection certificate.
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+domain+"/health", nil)
		request.Host = domain
		response, err := transport.RoundTrip(request)
		transport.CloseIdleConnections()
		if err == nil {
			_ = response.Body.Close()
		}
		if err == nil && response.StatusCode == http.StatusMisdirectedRequest {
			consecutive++
		} else {
			consecutive = 0
		}
		if consecutive >= 10 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return fmt.Errorf("headscale control ingress remained observable")
}

func requirePublicSTUNAbsent() error {
	return requireProcPortsAbsent(map[string]bool{"0D96": true}, []string{"/proc/net/udp", "/proc/net/udp6"})
}

func requirePublicListenersAbsent() error {
	return requireProcPortsAbsent(map[string]bool{"0050": true, "01BB": true, "0D96": true}, []string{"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"})
}

func requireProcPortsAbsent(ports map[string]bool, paths []string) error {
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 3 {
				if strings.Contains(path, "/tcp") && fields[3] != "0A" {
					continue
				}
				local := fields[1]
				if split := strings.LastIndexByte(local, ':'); split >= 0 && ports[local[split+1:]] {
					return fmt.Errorf("public listener remained on protected port")
				}
			}
		}
	}
	return nil
}
