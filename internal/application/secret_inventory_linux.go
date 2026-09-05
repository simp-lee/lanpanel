//go:build linux

package application

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"lanpanel/internal/acmeaccount"
	"lanpanel/internal/certificates"
	"lanpanel/internal/domain"
	"lanpanel/internal/nginx"
	"lanpanel/internal/secrets"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type secretSource struct {
	path string
	kind string
}

var dnsCredentialFileKeys = map[string]struct{}{
	"CF_DNS_API_TOKEN_FILE":           {},
	"DO_AUTH_TOKEN_FILE":              {},
	"AWS_SHARED_CREDENTIALS_FILE":     {},
	"GCE_SERVICE_ACCOUNT_FILE":        {},
	"TENCENTCLOUD_SECRET_ID_FILE":     {},
	"TENCENTCLOUD_SECRET_KEY_FILE":    {},
	"TENCENTCLOUD_SESSION_TOKEN_FILE": {},
}

// KnownSecretDigests builds the protected-secret inventory used at managed
// process admission. Only fingerprints are retained; no secret bytes enter the
// process authority or any job/audit record.
func KnownSecretDigests() (map[string]struct{}, error) {
	service, err := OpenFixed()
	if err != nil {
		return nil, err
	}
	defer func() { _ = service.Close() }()
	document, err := service.Normal().Read()
	if err != nil {
		return nil, err
	}
	raw, present := document.Entries["installations/current"]
	if !present {
		return nil, fmt.Errorf("installation authority is missing")
	}
	installation, err := domain.DecodeInstallation(raw)
	if err != nil {
		return nil, err
	}
	fingerprints := make([]string, 0, len(installation.Credentials)+4)
	accountKey, err := readProtectedSource(acmeaccount.ManagedKeyPath, "account")
	if err != nil {
		return nil, err
	}
	accountFingerprint, err := acmeaccount.Fingerprint(accountKey)
	clear(accountKey)
	if err != nil {
		return nil, err
	}
	fingerprints = append(fingerprints, accountFingerprint)
	sources := make([]secretSource, 0, len(installation.Credentials)+12)
	sources = append(sources, secretSource{path: nginx.FixedPaths().PrivateKeyPath, kind: "private_key"})
	for _, credential := range installation.Credentials {
		if credential.Fingerprint != "" {
			fingerprints = append(fingerprints, credential.Fingerprint)
		}
		if credential.Kind == "external_htpasswd" && credential.ExternalPath != "" {
			sources = append(sources, secretSource{path: credential.ExternalPath, kind: "htpasswd"})
		}
		if credential.Kind == "managed_basic" && credential.ManagedPath != "" {
			sources = append(sources, secretSource{path: credential.ManagedPath, kind: "htpasswd"})
		}
	}
	collectCertificate := func(certificate *domain.CertificateBundleIdentity) {
		if certificate == nil || certificate.Authority == nil {
			return
		}
		if certificate.Authority.AccountKeyFingerprint != "" {
			fingerprints = append(fingerprints, certificate.Authority.AccountKeyFingerprint)
		}
		if certificate.Authority.ProfileFingerprint != "" {
			fingerprints = append(fingerprints, certificate.Authority.ProfileFingerprint)
		}
		if certificate.Authority.ProfilePath != "" {
			sources = append(sources, secretSource{path: certificate.Authority.ProfilePath, kind: "profile"})
		}
		if certificate.Authority.CertificateID != "" && certificate.Generation > 0 {
			if bundlePath, err := certificates.BundlePath(certificate.Authority.CertificateID, certificate.Generation); err == nil {
				sources = append(sources, secretSource{path: filepath.Join(bundlePath, "private-key.pem"), kind: "private_key"})
			}
		}
		for _, credential := range certificate.Authority.CredentialFiles {
			if credential.Fingerprint != "" {
				fingerprints = append(fingerprints, credential.Fingerprint)
			}
			if credential.Path != "" {
				sources = append(sources, secretSource{path: credential.Path, kind: "credential"})
			}
		}
	}
	collectRequest := func(request *domain.CertificateRequest) {
		if request != nil && request.ProviderProfilePath != "" {
			sources = append(sources, secretSource{path: request.ProviderProfilePath, kind: "profile"})
		}
	}
	if installation.Headscale != nil {
		collectCertificate(installation.Headscale.Certificate)
	}
	for _, app := range installation.Resources {
		if app.ManagedProcess != nil && app.ManagedProcess.Service.EnvironmentFile != "" {
			sources = append(sources, secretSource{path: app.ManagedProcess.Service.EnvironmentFile, kind: "environment"})
		}
		if app.Publication.DomainHTTPS != nil {
			collectRequest(app.Publication.DomainHTTPS.Certificate)
		}
		if bundle := app.PublicationRecord.LastAppliedBundle; bundle != nil && bundle.DomainHTTPS != nil {
			collectCertificate(&bundle.DomainHTTPS.Certificate)
		}
		if intent := app.PublicationRecord.ActivationIntent; intent != nil {
			if intent.Candidate.DomainHTTPS != nil {
				collectCertificate(&intent.Candidate.DomainHTTPS.Certificate)
			}
			if intent.Prior != nil && intent.Prior.DomainHTTPS != nil {
				collectCertificate(&intent.Prior.DomainHTTPS.Certificate)
			}
		}
		if intent := app.PublicationRecord.ContractionIntent; intent != nil {
			if intent.Candidate != nil && intent.Candidate.DomainHTTPS != nil {
				collectCertificate(&intent.Candidate.DomainHTTPS.Certificate)
			}
			if intent.Prior != nil && intent.Prior.DomainHTTPS != nil {
				collectCertificate(&intent.Prior.DomainHTTPS.Certificate)
			}
		}
	}
	seenSources := map[string]struct{}{}
	for index := 0; index < len(sources); index++ {
		source := sources[index]
		if _, seen := seenSources[source.path]; seen {
			continue
		}
		seenSources[source.path] = struct{}{}
		values, discovered, err := protectedSourceDigests(source.path, source.kind)
		if err != nil {
			return nil, err
		}
		fingerprints = append(fingerprints, values...)
		for _, path := range discovered {
			sources = append(sources, secretSource{path: path, kind: "credential"})
		}
	}
	return secrets.KnownHostSecretDigests(fingerprints...)
}

// KnownSecretDigestsForResource extends the persisted inventory with protected
// sources referenced by a candidate resource before that candidate is committed.
func KnownSecretDigestsForResource(candidate domain.AppResource) (map[string]struct{}, error) {
	inventory, err := KnownSecretDigests()
	if err != nil {
		return nil, err
	}
	sources := []secretSource{}
	if candidate.ManagedProcess != nil && candidate.ManagedProcess.Service.EnvironmentFile != "" {
		sources = append(sources, secretSource{path: candidate.ManagedProcess.Service.EnvironmentFile, kind: "environment"})
	}
	if candidate.Publication.DomainHTTPS != nil && candidate.Publication.DomainHTTPS.Certificate != nil && candidate.Publication.DomainHTTPS.Certificate.ProviderProfilePath != "" {
		sources = append(sources, secretSource{path: candidate.Publication.DomainHTTPS.Certificate.ProviderProfilePath, kind: "profile"})
	}
	seen := map[string]struct{}{}
	for index := 0; index < len(sources); index++ {
		source := sources[index]
		if _, present := seen[source.path]; present {
			continue
		}
		seen[source.path] = struct{}{}
		values, discovered, err := protectedSourceDigests(source.path, source.kind)
		if err != nil {
			return nil, err
		}
		for _, value := range values {
			inventory[value] = struct{}{}
		}
		for _, path := range discovered {
			sources = append(sources, secretSource{path: path, kind: "credential"})
		}
	}
	return inventory, nil
}

func openProtectedSource(path string) (int, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return -1, fmt.Errorf("protected secret source path is invalid")
	}
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for index, component := range components {
		last := index == len(components)-1
		flags := unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if last {
			flags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		}
		next, openErr := unix.Openat(fd, component, flags, 0)
		_ = unix.Close(fd)
		if openErr != nil {
			return -1, openErr
		}
		fd = next
		var stat unix.Stat_t
		if unix.Fstat(fd, &stat) != nil {
			_ = unix.Close(fd)
			return -1, fmt.Errorf("inspect protected secret source")
		}
		if !last && (stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 || stat.Mode&0o022 != 0) {
			_ = unix.Close(fd)
			return -1, fmt.Errorf("protected secret parent is unsafe")
		}
	}
	return fd, nil
}

func readProtectedSource(path, kind string) ([]byte, error) {
	fd, err := openProtectedSource(path)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > 64<<10 {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("protected secret source is unsafe")
	}
	if kind == "htpasswd" {
		mode := stat.Mode & 0o777
		group, groupErr := user.LookupGroup("www-data")
		if groupErr != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("protected htpasswd source is unsafe")
		}
		nginxGID, parseErr := strconv.ParseUint(group.Gid, 10, 32)
		if parseErr != nil || uint32(nginxGID) != stat.Gid || mode != 0o640 && mode != 0o440 {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("protected htpasswd source is unsafe")
		}
	} else if stat.Mode&0o077 != 0 {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("protected secret source is unsafe")
	}
	file := os.NewFile(uintptr(fd), "protected-secret")
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("protected secret descriptor is invalid")
	}
	data, err := io.ReadAll(io.LimitReader(file, 64<<10+1))
	var after unix.Stat_t
	afterErr := unix.Fstat(fd, &after)
	closeErr := file.Close()
	if err != nil || closeErr != nil || afterErr != nil || int64(len(data)) != stat.Size || after.Dev != stat.Dev || after.Ino != stat.Ino || after.Size != stat.Size || after.Mtim != stat.Mtim || after.Ctim != stat.Ctim {
		clear(data)
		return nil, fmt.Errorf("protected secret source changed")
	}
	return data, nil
}

func parseEnvironmentValues(data []byte) ([]string, error) {
	values := []string{}
	seen := map[string]struct{}{}
	for _, raw := range strings.Split(string(data), "\n") {
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		if strings.ContainsAny(raw, "\x00\r") {
			return nil, fmt.Errorf("environment file syntax is invalid")
		}
		name, _, found := strings.Cut(raw, "=")
		if name == "" || strings.ContainsAny(name, "= \t") || name[0] >= '0' && name[0] <= '9' {
			return nil, fmt.Errorf("environment file syntax is invalid")
		}
		for _, character := range name {
			valid := character == '_' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
			if !valid {
				return nil, fmt.Errorf("environment file syntax is invalid")
			}
		}
		if !found || name == "LANPANEL_HTTP_SOCKET" || strings.HasPrefix(name, "LISTEN_") {
			return nil, fmt.Errorf("environment file syntax is invalid")
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, fmt.Errorf("environment file syntax is invalid")
		}
		seen[name] = struct{}{}
		values = append(values, raw)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("environment file is empty")
	}
	return values, nil
}

func protectedSourceDigests(path, kind string) ([]string, []string, error) {
	data, err := readProtectedSource(path, kind)
	if err != nil {
		return nil, nil, err
	}

	defer clear(data)
	seen := map[string]struct{}{}
	discovered := []string{}
	add := func(value string) {
		if value != "" {
			sum := sha256.Sum256([]byte(value))
			seen["sha256:"+hex.EncodeToString(sum[:])] = struct{}{}
		}
	}
	text := string(data)
	if kind == "environment" {
		values, err := parseEnvironmentValues(data)
		if err != nil {
			return nil, nil, err
		}
		for _, line := range values {
			if _, value, ok := strings.Cut(line, "="); ok {
				add(value)
			}
		}
	} else if kind == "profile" {
		for _, line := range strings.Split(text, "\n") {
			key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
			if !ok {
				continue
			}
			if _, credentialFile := dnsCredentialFileKeys[key]; !credentialFile {
				continue
			}
			value = strings.TrimSpace(value)
			if filepath.IsAbs(value) && filepath.Clean(value) == value {
				discovered = append(discovered, value)
			}
		}
	} else {
		add(text)
		add(strings.TrimSpace(text))
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
			if line == "" {
				continue
			}
			if kind == "htpasswd" {
				add(line)
			}
			if _, value, ok := strings.Cut(line, "="); ok {
				add(strings.TrimSpace(value))
			}
		}
		var object map[string]json.RawMessage
		if json.Unmarshal(data, &object) == nil {
			for _, key := range []string{"private_key", "client_secret", "secret", "token", "password"} {
				var value string
				if json.Unmarshal(object[key], &value) == nil {
					add(value)
				}
			}
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	return result, discovered, nil
}
