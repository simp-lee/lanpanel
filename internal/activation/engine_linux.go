//go:build linux

// Package activation owns the bounded local Nginx activation critical section.
package activation

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/child"
	"lanpanel/internal/closure"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/nginx"
	"lanpanel/internal/publication"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Result struct {
	Manifest      nginx.Manifest
	ModifiedPaths []string
	RuntimeDigest string
}
type Failure struct {
	Cause         error
	PriorRestored bool
}

func (value *Failure) Error() string { return value.Cause.Error() }
func (value *Failure) Unwrap() error { return value.Cause }

type Host struct {
	Launcher *child.Launcher
	Paths    nginx.Paths
	Owner    filetxn.Owner
}

func NewFixedHost() (Host, error) {
	launcher, err := child.NewLauncher(child.FixedLanPanelExecutable, child.Identities{})
	return Host{Launcher: launcher, Paths: nginx.FixedPaths(), Owner: filetxn.Owner{UID: 0, GID: 0}}, err
}

func (host Host) Activate(ctx context.Context, candidate publication.Candidate, target domain.AppTarget) (result Result, resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if host.Launcher == nil || candidate.Entry.Kind != nginx.EntryTemporary {
		return Result{}, fmt.Errorf("activation host authority incomplete")
	}
	priorManifest, err := nginx.Audit(host.Paths, host.Owner)
	if err != nil {
		return Result{}, err
	}
	observer := host.observer(priorManifest)
	prior, err := observer.Observe(ctx)
	if err != nil || prior.Master == nil {
		return Result{}, fmt.Errorf("Nginx must be running before App activation: %w", err)
	}
	priorDisk, err := nginx.SnapshotActivation(host.Paths, host.Owner, candidate.Entry)
	if err != nil {
		return Result{}, err
	}
	mutated := true
	activeManifest := priorManifest
	defer func() {
		if resultErr == nil || !mutated {
			return
		}
		recoveryCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		loaded, observeCandidateErr := host.observer(activeManifest).Observe(recoveryCtx)
		candidateWorkers := currentWorkers(loaded)
		_, restoreErr := nginx.RestoreActivation(recoveryCtx, host.Paths, host.Owner, candidate.Entry, priorDisk)
		restoreErr = errors.Join(observeCandidateErr, restoreErr)
		if restoreErr == nil {
			restoreErr = host.Reload(recoveryCtx)
		}
		if restoreErr == nil {
			priorObserver := host.observer(priorDisk.Manifest)
			snapshot, observeErr := closure.WaitPriorWorkers(recoveryCtx, priorObserver, candidateWorkers, nginx.DefaultWorkerTimeout)
			restoreErr = errors.Join(observeErr, verifyPriorSnapshot(snapshot, priorDisk.Manifest))
		}
		priorRestored := restoreErr == nil
		resultErr = &Failure{Cause: errors.Join(resultErr, restoreErr), PriorRestored: priorRestored}
	}()
	manifest, paths, err := nginx.InstallEntry(ctx, host.Paths, host.Owner, candidate.Entry)
	activeManifest = manifest
	if err != nil {
		return Result{}, err
	}
	if err := host.run(ctx, child.ProfileNginxDump); err != nil {
		return Result{}, err
	}
	if err := host.run(ctx, child.ProfileNginxTest); err != nil {
		return Result{}, err
	}
	if err := host.run(ctx, child.ProfileNginxReloadSignal); err != nil {
		return Result{}, err
	}
	currentObserver := host.observer(manifest)
	snapshot, err := closure.WaitPriorWorkers(ctx, currentObserver, prior.Workers, nginx.DefaultWorkerTimeout)
	if err != nil || snapshot.Master == nil {
		return Result{}, fmt.Errorf("activated Nginx generation unavailable: %w", err)
	}
	runtimeDigest, err := probeTemporary(ctx, candidate, target, snapshot)
	if err != nil {
		return Result{}, err
	}
	return Result{Manifest: manifest, ModifiedPaths: paths, RuntimeDigest: runtimeDigest}, nil
}

func currentWorkers(snapshot closure.RuntimeSnapshot) []closure.ProcessIdentity {
	return append([]closure.ProcessIdentity(nil), snapshot.Workers...)
}
func verifyPriorSnapshot(snapshot closure.RuntimeSnapshot, manifest nginx.Manifest) error {
	if snapshot.Master == nil || snapshot.Generation != manifest.GenerationID {
		return fmt.Errorf("prior Nginx runtime generation not restored")
	}
	expected := map[string]bool{"tcp:0.0.0.0:80": true, "tcp:0.0.0.0:443": true, "tcp::::80": true, "tcp::::443": true}
	for _, entry := range manifest.Entries {
		for _, listener := range entry.Listeners {
			expected[listener] = true
		}
	}
	for _, listener := range snapshot.Listeners {
		delete(expected, fmt.Sprintf("%s:%s:%d", listener.Protocol, listener.Address, listener.Port))
	}
	if len(expected) != 0 {
		return fmt.Errorf("prior Nginx listeners not restored")
	}
	return nil
}
func (host Host) observer(manifest nginx.Manifest) closure.ProcObserver {
	listeners := []string{"tcp:0.0.0.0:80", "tcp:0.0.0.0:443", "tcp::::80", "tcp::::443"}
	for _, entry := range manifest.Entries {
		listeners = append(listeners, entry.Listeners...)
	}
	slices.Sort(listeners)
	listeners = slices.Compact(listeners)
	return closure.ProcObserver{UnitCgroup: "/system.slice/lanpanel-nginx.service", Executable: "/usr/sbin/nginx", ExpectedArgv: "/usr/sbin/nginx\x00-c\x00/etc/lanpanel/nginx/nginx.conf\x00-p\x00/var/lib/lanpanel/nginx/\x00-g\x00daemon off;", PIDPath: host.Paths.PIDPath, Generation: manifest.GenerationID, OwnedListeners: listeners}
}
func (host Host) StopAndVerify(ctx context.Context) (closure.RuntimeSnapshot, error) {
	if err := host.run(ctx, child.ProfileSystemctlNginxStop); err != nil {
		return closure.RuntimeSnapshot{}, err
	}
	manifest, err := nginx.Audit(host.Paths, host.Owner)
	if err != nil {
		return closure.RuntimeSnapshot{}, err
	}
	snapshot, err := host.observer(manifest).Observe(ctx)
	if err != nil {
		return snapshot, err
	}
	return snapshot, closure.VerifyStopped(snapshot)
}
func (host Host) Reload(ctx context.Context) error {
	if err := host.run(ctx, child.ProfileNginxTest); err != nil {
		return err
	}
	return host.run(ctx, child.ProfileNginxReloadSignal)
}
func (host Host) run(ctx context.Context, profile child.ProfileID) error {
	result, err := host.Launcher.Run(ctx, profile, nil)
	if err != nil || result.ExitCode != 0 || result.OutputCutOff {
		return fmt.Errorf("fixed Nginx activation profile %q failed: %w", profile, err)
	}
	return nil
}

func probeTemporary(ctx context.Context, candidate publication.Candidate, target domain.AppTarget, snapshot closure.RuntimeSnapshot) (string, error) {
	site := candidate.Entry.Temporary
	authority := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(site.Port)))
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+authority+target.ReadinessPath, nil)
	if err != nil {
		return "", err
	}
	request.Host = site.HostAuthority
	request.Header.Set("Authorization", "LanPanel-publication-probe-secret")
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	response.Body.Close()
	if response.Header.Get("X-LanPanel-Plaintext-Warning") != "public_http_anyone_no_credentials" || !strings.Contains(response.Header.Get("Warning"), "Public plaintext HTTP") {
		return "", fmt.Errorf("temporary plaintext warning missing")
	}
	allowed := false
	for _, status := range target.AllowedHTTPStatuses {
		allowed = allowed || response.StatusCode == int(status)
	}
	if !allowed {
		return "", fmt.Errorf("temporary runtime positive probe returned %d", response.StatusCode)
	}
	wrong, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+authority+"/__lanpanel_wrong_host", nil)
	if err != nil {
		return "", err
	}
	wrong.Host = "wrong.invalid"
	rejected, err := client.Do(wrong)
	if err != nil {
		return "", err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(rejected.Body, 4096))
	rejected.Body.Close()
	if rejected.StatusCode != http.StatusMisdirectedRequest || rejected.Header.Get("X-LanPanel-Rejection") != "temporary_default" {
		return "", fmt.Errorf("temporary wrong Host was not fixed rejection")
	}
	for _, raw := range []string{"GET / HTTP/1.1\r\nConnection: close\r\n\r\n", "GET / HTTP/1.0\r\nHost: " + site.HostAuthority + "\r\nConnection: close\r\n\r\n"} {
		connection, err := (&net.Dialer{}).DialContext(ctx, "tcp4", authority)
		if err != nil {
			return "", err
		}
		if _, err = io.WriteString(connection, raw); err != nil {
			connection.Close()
			return "", err
		}
		parsed, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodGet})
		connection.Close()
		if err != nil {
			return "", err
		}
		if parsed.StatusCode < 400 || parsed.StatusCode >= 600 {
			return "", fmt.Errorf("temporary malformed authority or protocol was accepted")
		}
	}
	identity := fmt.Sprintf("%s\x00%s\x00%d\x00%d\x00%s", candidate.BundleDigest, snapshot.Generation, response.StatusCode, rejected.StatusCode, site.HostAuthority)
	sum := sha256.Sum256([]byte(identity))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

var _ = strings.TrimSpace
