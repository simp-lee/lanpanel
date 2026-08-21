//go:build linux

package control

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	nginxactivation "lanpanel/internal/activation"
	"lanpanel/internal/certificates"
	"lanpanel/internal/challenge"
	"lanpanel/internal/child"
	"lanpanel/internal/closure"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/nginx"
	"lanpanel/internal/safety"
	"net"
	"net/http"
	"os"
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
	}{{bundle.Paths.ControlSocketUnit, bundle.ControlSocket}, {bundle.Paths.ControlRelayUnit, bundle.ControlRelay}, {bundle.Paths.STUNSocketUnit, bundle.STUNSocket}, {bundle.Paths.STUNRelayUnit, bundle.STUNRelay}} {
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

func (host *ActivationHost) Activate(ctx context.Context, bundle ActivationBundle, authority ActivationAuthority) (result ActivationResult, resultErr error) {
	if err := ValidateActivation(bundle); err != nil {
		return result, err
	}
	priorManifest, err := nginx.Audit(host.nginxPaths, host.owner)
	if err != nil {
		return result, err
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
	if bundle.Prior != nil {
		if bundle.Certificate.Generation < 2 {
			return result, fmt.Errorf("headscale reactivation certificate generation invalid")
		}
		priorGeneration = bundle.Certificate.Generation - 1
	}
	pointer := certificates.Pointer{CertificateID: bundle.Certificate.ID, CandidateGeneration: bundle.Certificate.Generation, ExpectedPriorGeneration: priorGeneration}
	pointerResult, err := certificates.ActivatePointer(ctx, pointer)
	if err != nil {
		return result, err
	}
	result.CertificateTarget = pointerResult.CandidateTarget
	installed := false
	socketsStarted := false
	defer func() {
		if resultErr == nil {
			return
		}
		recovery := context.Background()
		var cleanup error
		if socketsStarted {
			cleanup = host.run(recovery, child.ProfileHeadscaleActivateStop, child.Invocation{Headscale: &child.HeadscaleInvocation{HeadscaleID: bundle.Candidate.HeadscaleID}})
		}
		if installed {
			_, _, removeErr := nginx.RemoveEntry(recovery, host.nginxPaths, host.owner, bundle.Entry)
			cleanup = errors.Join(cleanup, removeErr, host.run(recovery, child.ProfileNginxTest, child.Invocation{}), host.run(recovery, child.ProfileNginxReloadSignal, child.Invocation{}))
		}
		cleanup = errors.Join(cleanup, certificates.RestorePointer(recovery, pointer, pointerResult.CandidateTarget))
		result.PriorRestored = cleanup == nil
		resultErr = errors.Join(resultErr, cleanup)
	}()
	manifest, _, err := nginx.InstallEntry(ctx, host.nginxPaths, host.owner, bundle.Entry)
	if err != nil {
		return result, err
	}
	installed = true
	if err := ValidateActivationAuthority(bundle, authority); err != nil {
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
	if err := host.run(ctx, child.ProfileHeadscaleActivateStart, invocation); err != nil {
		return result, err
	}
	socketsStarted = true
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
	effectiveDigest, err := host.verifyEffectiveActivation(probeCtx, bundle, invocation)
	if err != nil {
		return result, err
	}
	result.NginxDigest = manifest.MainDigest
	result.RuntimeDigest = hashBytes([]byte(bundle.Digest + "\x00" + manifest.GenerationID + "\x00" + runtimeDigest + "\x00stun-ok\x00" + effectiveDigest))
	return result, nil
}

func headscaleChallengeEntry(bundle ActivationBundle, prepared challenge.Prepared) (nginx.Entry, error) {
	if prepared.Entry == nil || prepared.Entry.ResourceID != "headscale" || prepared.Safety.Method != "http-01" || len(prepared.Safety.Hosts) != 1 || prepared.Safety.Hosts[0] != bundle.Candidate.ControlDomain {
		return nginx.Entry{}, fmt.Errorf("headscale renewal challenge authority invalid")
	}
	entry := bundle.Entry
	entry.Challenge = &nginx.ChallengeSite{Hosts: append([]string(nil), prepared.Safety.Hosts...), Webroot: prepared.Safety.Webroot}
	entry.Digest = controlZeroDigest()
	digest, err := nginx.DigestEntry(entry)
	if err != nil {
		return nginx.Entry{}, err
	}
	entry.Digest = digest
	return entry, nil
}

func (host *ActivationHost) ActivateCertificateChallenge(ctx context.Context, bundle ActivationBundle, prepared challenge.Prepared, state safety.State, installation domain.Installation, ownershipAuthority map[string]string) error {
	entry, err := headscaleChallengeEntry(bundle, prepared)
	if err != nil {
		return err
	}
	prior, err := nginx.Audit(host.nginxPaths, host.owner)
	if err != nil {
		return err
	}
	runtimeHost, err := nginxactivation.NewFixedHost()
	if err != nil {
		return err
	}
	snapshot, err := runtimeHost.ObserveRuntime(ctx, prior)
	if err != nil {
		return err
	}
	manifest, _, err := nginx.InstallEntry(ctx, host.nginxPaths, host.owner, entry)
	if err != nil {
		return err
	}
	if decision := nginx.Guard(nginx.GuardInput{Action: nginx.GuardReload, Manifest: manifest, Safety: state, Installation: &installation, Ownership: ownershipAuthority, Now: time.Now().UTC()}); !decision.Allowed {
		return fmt.Errorf("headscale challenge reload rejected: %s", decision.Reason)
	}
	if err := host.run(ctx, child.ProfileNginxTest, child.Invocation{}); err != nil {
		return err
	}
	if err := host.run(ctx, child.ProfileNginxReloadSignal, child.Invocation{}); err != nil {
		return err
	}
	_, err = runtimeHost.WaitForPriorWorkers(ctx, manifest, snapshot.Workers)
	return err
}

func (host *ActivationHost) RemoveCertificateChallenge(ctx context.Context, bundle ActivationBundle, prepared challenge.Prepared) error {
	entry, err := headscaleChallengeEntry(bundle, prepared)
	if err != nil {
		return err
	}
	prior, err := nginx.Audit(host.nginxPaths, host.owner)
	if err != nil {
		return err
	}
	runtimeHost, err := nginxactivation.NewFixedHost()
	if err != nil {
		return err
	}
	snapshot, err := runtimeHost.ObserveRuntime(ctx, prior)
	if err != nil {
		return err
	}
	manifest, _, err := nginx.InstallEntry(ctx, host.nginxPaths, host.owner, bundle.Entry)
	if err != nil {
		return err
	}
	_ = entry
	if err := host.run(ctx, child.ProfileNginxTest, child.Invocation{}); err != nil {
		return err
	}
	if err := host.run(ctx, child.ProfileNginxReloadSignal, child.Invocation{}); err != nil {
		return err
	}
	_, err = runtimeHost.WaitForPriorWorkers(ctx, manifest, snapshot.Workers)
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

func (host *ActivationHost) Contract(ctx context.Context, bundle ActivationBundle) error {
	if host == nil || ValidateActivation(bundle) != nil {
		return fmt.Errorf("headscale activation host authority unavailable")
	}
	invocation := child.Invocation{Headscale: &child.HeadscaleInvocation{HeadscaleID: bundle.Candidate.HeadscaleID}}
	runtimeHost, runtimeHostErr := nginxactivation.NewFixedHost()
	priorManifest, auditErr := nginx.Audit(host.nginxPaths, host.owner)
	priorRuntime, observeRuntimeErr := runtimeHost.ObserveRuntime(context.WithoutCancel(ctx), priorManifest)
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
	pointer := certificates.Pointer{CertificateID: bundle.Certificate.ID, CandidateGeneration: bundle.Certificate.Generation, ExpectedPriorGeneration: 0}
	current, observeErr := certificates.ObservePointer(bundle.Certificate.ID)
	var pointerErr error
	if observeErr == nil && current != "" {
		pointerErr = certificates.RestorePointer(context.WithoutCancel(ctx), pointer, current)
	}
	listenerErr := requirePublicSTUNAbsent()
	return errors.Join(stopErr, removeErr, reloadErr, controlAbsentErr, serviceErr, observeErr, pointerErr, listenerErr)
}

func (host *ActivationHost) FallbackStop(ctx context.Context, bundle ActivationBundle) (safety.StopObservation, error) {
	observed := safety.StopObservation{ObservedAt: time.Now().UTC()}
	if host == nil || ValidateActivation(bundle) != nil {
		return observed, fmt.Errorf("headscale fallback-stop authority invalid")
	}
	if err := host.run(context.WithoutCancel(ctx), child.ProfileHeadscaleFallbackStop, child.Invocation{}); err != nil {
		return observed, err
	}
	if _, err := os.Lstat(host.nginxPaths.PIDPath); !errors.Is(err, os.ErrNotExist) {
		return observed, fmt.Errorf("nginx PID authority remained after fallback stop: %w", err)
	}
	if err := requirePublicListenersAbsent(); err != nil {
		return observed, err
	}
	observed.MasterStopped, observed.WorkersStopped, observed.ListenersStopped = true, true, true
	return observed, nil
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

func (host *ActivationHost) verifyEffectiveActivation(ctx context.Context, bundle ActivationBundle, invocation child.Invocation) (string, error) {
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
		if value == nil || value["LoadState"] != "loaded" || value["ActiveState"] != "active" || value["FragmentPath"] != path || value["DropInPaths"] != "" {
			return "", fmt.Errorf("effective Headscale unit %s changed", id)
		}
		if strings.HasSuffix(id, ".socket") {
			if value["SubState"] != "listening" || value["SocketMode"] != "0600" || value["RemoveOnStop"] != "yes" || value["FreeBind"] != "no" || value["ReusePort"] != "no" {
				return "", fmt.Errorf("headscale activation socket is not exact")
			}
			if id == "lanpanel-headscale-control.socket" && (value["SocketUser"] != "www-data" || value["SocketGroup"] != "www-data" || !strings.Contains(value["Listen"], bundle.Candidate.Paths.ControlSocket)) {
				return "", fmt.Errorf("headscale control socket identity changed")
			}
			if id == "lanpanel-headscale-stun.socket" && (value["SocketUser"] != bundle.ServiceUser || value["SocketGroup"] != bundle.ServiceGroup || !strings.Contains(value["Listen"], "0.0.0.0:3478")) {
				return "", fmt.Errorf("headscale STUN socket identity changed")
			}
		} else if value["SubState"] != "running" || value["User"] != bundle.ServiceUser || value["Group"] != bundle.ServiceGroup || value["NoNewPrivileges"] != "yes" || value["PrivateNetwork"] != "yes" || !strings.Contains(value["JoinsNamespaceOf"], "lanpanel-headscale.service") || value["CapabilityBoundingSet"] != "" || value["AmbientCapabilities"] != "" || value["ProtectSystem"] != "strict" || value["ProtectHome"] != "yes" || value["ProtectProc"] != "invisible" || value["ProcSubset"] != "pid" || value["ProtectKernelTunables"] != "yes" || value["ProtectKernelModules"] != "yes" || value["ProtectControlGroups"] != "yes" || value["LockPersonality"] != "yes" || value["MemoryDenyWriteExecute"] != "yes" || value["SystemCallArchitectures"] != "native" || value["RestrictSUIDSGID"] != "yes" || value["KillMode"] != "control-group" || value["Restart"] != "no" || !strings.Contains(value["ExecStart"], "/usr/lib/lanpanel/lanpanel headscale-") {
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
