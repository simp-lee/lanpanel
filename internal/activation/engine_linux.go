//go:build linux

// Package activation owns the bounded local Nginx activation critical section.
package activation

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"lanpanel/internal/certificates"
	"lanpanel/internal/child"
	"lanpanel/internal/closure"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/nginx"
	"lanpanel/internal/publication"
	"net"
	"net/http"
	"os"
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

type pointerActivator func(context.Context, certificates.Pointer) (certificates.PointerResult, error)
type pointerRestorer func(context.Context, certificates.Pointer, string) error

func activateCandidatePointer(ctx context.Context, pointer certificates.Pointer, expected string, activate pointerActivator, restore pointerRestorer) (certificates.PointerResult, error) {
	result, err := activate(ctx, pointer)
	if err == nil && result.CandidateTarget == expected {
		return result, nil
	}
	if result.CandidateTarget == "" {
		return result, err
	}
	restoreErr := restore(context.WithoutCancel(ctx), pointer, result.CandidateTarget)
	if err == nil {
		err = fmt.Errorf("certificate pointer candidate identity changed")
	}
	return result, &Failure{Cause: errors.Join(err, restoreErr), PriorRestored: restoreErr == nil}
}

func NewFixedHost() (Host, error) {
	launcher, err := child.NewLauncher(child.FixedLanPanelExecutable, child.Identities{})
	return Host{Launcher: launcher, Paths: nginx.FixedPaths(), Owner: filetxn.Owner{UID: 0, GID: 0}}, err
}

func (host Host) Activate(ctx context.Context, candidate publication.Candidate, target domain.AppTarget) (result Result, resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if host.Launcher == nil || (candidate.Entry.Kind != nginx.EntryTemporary && candidate.Entry.Kind != nginx.EntryApp) {
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
	var pointerResult certificates.PointerResult
	if candidate.CertificatePointer != nil {
		pointerResult, err = activateCandidatePointer(ctx, *candidate.CertificatePointer, candidate.CertificateCandidatePath, certificates.ActivatePointer, certificates.RestorePointer)
		if err != nil {
			return Result{}, err
		}
	}
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
		if candidate.CertificatePointer != nil {
			restoreErr = errors.Join(restoreErr, certificates.RestorePointer(recoveryCtx, *candidate.CertificatePointer, pointerResult.CandidateTarget))
		}
		if restoreErr == nil {
			restoreErr = host.Reload(recoveryCtx)
		}
		if restoreErr == nil {
			priorObserver := host.observer(priorDisk.Manifest)
			snapshot, observeErr := closure.WaitPriorWorkers(recoveryCtx, priorObserver, candidateWorkers, nginx.DefaultWorkerTimeout)
			restoreErr = errors.Join(observeErr, verifyPriorSnapshot(snapshot, priorDisk.Manifest))
			if restoreErr == nil && candidate.PriorBundle != nil {
				var priorEntry *nginx.Entry
				for index := range priorDisk.Manifest.Entries {
					entry := &priorDisk.Manifest.Entries[index]
					if entry.ResourceID == candidate.ResourceID {
						priorEntry = entry
					}
				}
				if priorEntry == nil {
					restoreErr = fmt.Errorf("prior publication entry missing")
				} else {
					priorCandidate := publication.Candidate{ResourceID: candidate.ResourceID, Generation: candidate.PriorBundle.Generation, Bundle: *candidate.PriorBundle, BundleDigest: candidate.PriorBundleDigest, Entry: *priorEntry}
					if priorCandidate.Bundle.Kind == domain.PublicationDomainHTTPS {
						_, restoreErr = probeDomain(recoveryCtx, priorCandidate, target, snapshot)
					} else {
						_, restoreErr = probeTemporary(recoveryCtx, priorCandidate, target, snapshot)
					}
				}
			}
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
	var runtimeDigest string
	if candidate.Entry.Kind == nginx.EntryTemporary {
		runtimeDigest, err = probeTemporary(ctx, candidate, target, snapshot)
	} else {
		runtimeDigest, err = probeDomain(ctx, candidate, target, snapshot)
	}
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
func (host Host) ObserveRuntime(ctx context.Context, manifest nginx.Manifest) (closure.RuntimeSnapshot, error) {
	if host.Launcher == nil || nginx.ValidateManifest(manifest) != nil {
		return closure.RuntimeSnapshot{}, fmt.Errorf("Nginx runtime observation authority invalid")
	}
	return host.observer(manifest).Observe(ctx)
}
func (host Host) WaitForPriorWorkers(ctx context.Context, manifest nginx.Manifest, prior []closure.ProcessIdentity) (closure.RuntimeSnapshot, error) {
	if host.Launcher == nil || nginx.ValidateManifest(manifest) != nil {
		return closure.RuntimeSnapshot{}, fmt.Errorf("Nginx reload observation authority invalid")
	}
	snapshot, err := closure.WaitPriorWorkers(ctx, host.observer(manifest), prior, nginx.DefaultWorkerTimeout)
	if err != nil {
		return snapshot, err
	}
	return snapshot, verifyPriorSnapshot(snapshot, manifest)
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
func (host Host) ObserveCurrent(ctx context.Context) (closure.RuntimeSnapshot, error) {
	manifest, err := nginx.Audit(host.Paths, host.Owner)
	if err != nil {
		return closure.RuntimeSnapshot{}, err
	}
	return host.observer(manifest).Observe(ctx)
}
func (host Host) VerifyDomain(ctx context.Context, candidate publication.Candidate, target domain.AppTarget) (string, error) {
	manifest, err := nginx.Audit(host.Paths, host.Owner)
	if err != nil {
		return "", err
	}
	matched := false
	for _, entry := range manifest.Entries {
		if entry.ResourceID == candidate.ResourceID && entry.Kind == nginx.EntryApp && entry.Digest == candidate.Entry.Digest {
			matched = true
		}
	}
	if !matched {
		return "", fmt.Errorf("domain runtime manifest candidate missing")
	}
	snapshot, err := host.observer(manifest).Observe(ctx)
	if err != nil || snapshot.Master == nil {
		return "", fmt.Errorf("domain runtime observation failed: %w", err)
	}
	return probeDomain(ctx, candidate, target, snapshot)
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
func (host Host) ContractResource(ctx context.Context, resourceID string) (Result, error) {
	priorManifest, err := nginx.Audit(host.Paths, host.Owner)
	if err != nil {
		return Result{}, err
	}
	prior, err := host.observer(priorManifest).Observe(ctx)
	if err != nil {
		return Result{}, err
	}
	running := prior.Master != nil
	if !running && (len(prior.Workers) != 0 || len(prior.Listeners) != 0) {
		return Result{}, fmt.Errorf("stopped Nginx runtime inconsistent")
	}
	manifest, paths, err := nginx.Contract(ctx, host.Paths, host.Owner, []string{resourceID})
	if err != nil {
		return Result{}, err
	}
	if running {
		if err := host.Reload(ctx); err != nil {
			return Result{}, err
		}
		runtime, err := closure.WaitPriorWorkers(ctx, host.observer(manifest), prior.Workers, nginx.DefaultWorkerTimeout)
		if err != nil || runtime.Master == nil {
			return Result{}, fmt.Errorf("publication contraction prior workers remain")
		}
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return Result{}, err
	}
	sum := sha256.Sum256(append([]byte(resourceID+"\x00"), raw...))
	return Result{Manifest: manifest, ModifiedPaths: paths, RuntimeDigest: "sha256:" + hex.EncodeToString(sum[:])}, nil
}

func (host Host) run(ctx context.Context, profile child.ProfileID) error {
	result, err := host.Launcher.Run(ctx, profile, nil)
	if err != nil || result.ExitCode != 0 || result.OutputCutOff {
		return fmt.Errorf("fixed Nginx activation profile %q failed: %w", profile, err)
	}
	return nil
}

func probeDomain(ctx context.Context, candidate publication.Candidate, target domain.AppTarget, snapshot closure.RuntimeSnapshot) (string, error) {
	site := candidate.Entry.Domain
	if site == nil || candidate.Bundle.DomainHTTPS == nil {
		return "", fmt.Errorf("domain runtime candidate missing")
	}
	if err := probeRejectedLegacyTLS(ctx, site.Hosts[0]); err != nil {
		return "", err
	}
	observations := []string{"legacy-tls:rejected"}
	for _, hostName := range site.Hosts {
		status, observed, err := probeDomainRequest(ctx, hostName, hostName, target.ReadinessPath)
		if err != nil {
			return "", err
		}
		if observed != candidate.Bundle.DomainHTTPS.Certificate.Fingerprint {
			return "", fmt.Errorf("domain served certificate changed")
		}
		allowed := slices.Contains(target.AllowedHTTPStatuses, uint16(status)) || site.AuthMode == "basic" && (status == http.StatusUnauthorized || status == http.StatusForbidden) || site.AuthMode == "application_managed" && (status == http.StatusUnauthorized || status == http.StatusForbidden)
		if !allowed {
			return "", fmt.Errorf("domain runtime status %d rejected", status)
		}
		redirect, location, rejection, redirectErr := probeDomainHTTP(ctx, hostName, target.ReadinessPath)
		if redirectErr != nil || redirect != http.StatusPermanentRedirect || location != "https://"+hostName+target.ReadinessPath || rejection != "" {
			return "", fmt.Errorf("domain HTTP redirect changed")
		}
		websocketStatus := 0
		if target.WebSocket.Enabled {
			websocketStatus, err = probeDomainWebSocket(ctx, hostName, target.WebSocket.Path, site.AuthMode, candidate.Bundle.DomainHTTPS.Certificate.Fingerprint)
			if err != nil {
				return "", err
			}
		}
		observations = append(observations, fmt.Sprintf("%s:%d:%s:http=%d:ws=%d", hostName, status, observed, redirect, websocketStatus))
	}
	auditOffset, err := rejectionAuditOffset(site.RejectionAuditPath)
	if err != nil {
		return "", err
	}
	wrongHTTP, _, httpRejection, httpErr := probeDomainHTTP(ctx, "unmatched.invalid", target.ReadinessPath)
	if httpErr != nil || wrongHTTP != http.StatusMisdirectedRequest || httpRejection != "default" {
		return "", fmt.Errorf("domain HTTP wrong Host was not rejected")
	}
	observations = append(observations, fmt.Sprintf("wrong-http:%d", wrongHTTP))
	wrongStatus, _, err := probeDomainRequest(ctx, site.Hosts[0], "unmatched.invalid", target.ReadinessPath)
	if err != nil {
		return "", err
	}
	if wrongStatus != http.StatusMisdirectedRequest {
		return "", fmt.Errorf("domain wrong Host was not rejected")
	}
	observations = append(observations, fmt.Sprintf("wrong-host:%d", wrongStatus))
	unmatchedStatus, unmatchedFingerprint, err := probeDomainRequest(ctx, "unmatched.invalid", "unmatched.invalid", target.ReadinessPath)
	if err != nil {
		return "", err
	}
	defaultFingerprint, fingerprintErr := fixedRejectionFingerprint(nginx.FixedPaths().CertificatePath)
	if fingerprintErr != nil || unmatchedStatus != http.StatusMisdirectedRequest || unmatchedFingerprint != defaultFingerprint {
		return "", fmt.Errorf("domain unmatched SNI did not reach fixed rejection")
	}
	observations = append(observations, fmt.Sprintf("unmatched:%d:%s", unmatchedStatus, unmatchedFingerprint))
	if err := verifyRejectionAudit(ctx, site.RejectionAuditPath, auditOffset, site.Hosts[0], "unmatched.invalid"); err != nil {
		return "", err
	}
	data := fmt.Sprintf("%s\x00%s\x00%s", candidate.BundleDigest, snapshot.Generation, strings.Join(observations, ","))
	sum := sha256.Sum256([]byte(data))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
func probeRejectedLegacyTLS(ctx context.Context, serverName string) error {
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", "127.0.0.1:443")
	if err != nil {
		return err
	}
	defer raw.Close()
	connection := tls.Client(raw, &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11})
	if err := connection.HandshakeContext(ctx); err == nil {
		return fmt.Errorf("legacy TLS version accepted")
	}
	return nil
}
func fixedRejectionFingerprint(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, remainder := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(remainder) != 0 {
		return "", fmt.Errorf("fixed rejection certificate malformed")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(certificate.Raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
func rejectionAuditOffset(path string) (int64, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0o777 != 0o600 || stat.Nlink != 1 {
		return 0, fmt.Errorf("rejection audit identity invalid")
	}
	return stat.Size, nil
}
func verifyRejectionAudit(ctx context.Context, path string, offset int64, validSNI, wrong string) error {
	expectedHost := " " + validSNI + " " + wrong + " 421 "
	expectedSNI := " " + wrong + " " + wrong + " 421 "
	deadline := time.Now().Add(time.Second)
	for {
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		buffer := make([]byte, 64<<10)
		count, _ := unix.Pread(fd, buffer, offset)
		unix.Close(fd)
		text := string(buffer[:count])
		if strings.Contains(text, expectedHost) && strings.Contains(text, expectedSNI) {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("domain rejection audit evidence missing")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}
func probeDomainWebSocket(ctx context.Context, hostName, path, authMode, certificateFingerprint string) (int, error) {
	dialer := &net.Dialer{}
	raw, err := dialer.DialContext(ctx, "tcp", "127.0.0.1:443")
	if err != nil {
		return 0, err
	}
	defer raw.Close()
	connection := tls.Client(raw, &tls.Config{ServerName: hostName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	deadline := time.Now().Add(5 * time.Second)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return 0, err
	}
	if err := connection.HandshakeContext(ctx); err != nil {
		return 0, err
	}
	state := connection.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return 0, fmt.Errorf("domain WebSocket certificate missing")
	}
	sum := sha256.Sum256(state.PeerCertificates[0].Raw)
	if "sha256:"+hex.EncodeToString(sum[:]) != certificateFingerprint {
		return 0, fmt.Errorf("domain WebSocket certificate changed")
	}
	rawKey := make([]byte, 16)
	if _, err := rand.Read(rawKey); err != nil {
		return 0, err
	}
	key := base64.StdEncoding.EncodeToString(rawKey)
	clear(rawKey)
	requestText := "GET " + path + " HTTP/1.1\r\nHost: " + hostName + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + key + "\r\n\r\n"
	if _, err := io.WriteString(connection, requestText); err != nil {
		return 0, err
	}
	response, err := http.ReadResponse(bufio.NewReader(io.LimitReader(connection, 16<<10)), &http.Request{Method: http.MethodGet})
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if authMode == "public" || authMode == "application_managed" && response.StatusCode == http.StatusSwitchingProtocols {
		expected := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		accept := base64.StdEncoding.EncodeToString(expected[:])
		if response.StatusCode != http.StatusSwitchingProtocols || !headerContainsToken(response.Header.Values("Connection"), "upgrade") || !headerContainsToken(response.Header.Values("Upgrade"), "websocket") || response.Header.Get("Sec-WebSocket-Accept") != accept {
			return response.StatusCode, fmt.Errorf("domain WebSocket upgrade rejected")
		}
		return response.StatusCode, nil
	}
	if response.StatusCode != http.StatusUnauthorized && response.StatusCode != http.StatusForbidden {
		return response.StatusCode, fmt.Errorf("protected domain WebSocket boundary changed")
	}
	return response.StatusCode, nil
}
func headerContainsToken(values []string, want string) bool {
	for _, value := range values {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), want) {
				return true
			}
		}
	}
	return false
}
func probeDomainHTTP(ctx context.Context, hostName, path string) (int, string, string, error) {
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1"+path, nil)
	if err != nil {
		return 0, "", "", err
	}
	request.Host = hostName
	response, err := client.Do(request)
	if err != nil {
		return 0, "", "", err
	}
	response.Body.Close()
	return response.StatusCode, response.Header.Get("Location"), response.Header.Get("X-LanPanel-Rejection"), nil
}
func probeDomainRequest(ctx context.Context, serverName, hostName, path string) (int, string, error) {
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://127.0.0.1"+path, nil)
	if err != nil {
		return 0, "", err
	}
	request.Host = hostName
	response, err := client.Do(request)
	if err != nil {
		return 0, "", err
	}
	defer response.Body.Close()
	if response.TLS == nil || len(response.TLS.PeerCertificates) == 0 {
		return 0, "", fmt.Errorf("domain runtime TLS evidence missing")
	}
	fingerprint := sha256.Sum256(response.TLS.PeerCertificates[0].Raw)
	return response.StatusCode, "sha256:" + hex.EncodeToString(fingerprint[:]), nil
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
