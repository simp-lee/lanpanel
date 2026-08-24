package acme

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"lanpanel/internal/acmeaccount"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

type ChallengeMethod string

const (
	ChallengeHTTP01 ChallengeMethod = "http-01"
	ChallengeDNS01  ChallengeMethod = "dns-01"
)

func ParseChallengeMethod(value string) (ChallengeMethod, error) {
	switch ChallengeMethod(value) {
	case ChallengeHTTP01, ChallengeDNS01:
		return ChallengeMethod(value), nil
	default:
		return "", fmt.Errorf("unsupported ACME challenge method %q", value)
	}
}

type Binding struct {
	DirectoryURL          string           `json:"directory_url"`
	AccountKeyPath        string           `json:"account_key_path"`
	AccountKeyFingerprint string           `json:"account_key_fingerprint"`
	Method                ChallengeMethod  `json:"method"`
	Provider              DNSProvider      `json:"provider,omitempty"`
	ProfilePath           string           `json:"profile_path,omitempty"`
	ProfileFingerprint    string           `json:"profile_fingerprint,omitempty"`
	CredentialFiles       []CredentialFile `json:"credential_files"`
	Zone                  string           `json:"zone,omitempty"`
	Principal             string           `json:"principal,omitempty"`
	AccountEmail          string           `json:"account_email"`
	TermsAccepted         bool             `json:"terms_accepted"`
}
type CredentialFile struct {
	Key         string `json:"key"`
	Path        string `json:"path"`
	Fingerprint string `json:"fingerprint"`
}

type ProviderSchema struct {
	EnvironmentKeys []string
	RequiredValues  []string
	OptionalKeys    []string
	DirectValues    []string
}

var providerSchemas = map[DNSProvider]ProviderSchema{
	DNSProviderCloudflare:   {EnvironmentKeys: []string{"CF_DNS_API_TOKEN_FILE"}},
	DNSProviderRoute53:      {EnvironmentKeys: []string{"AWS_SHARED_CREDENTIALS_FILE"}, RequiredValues: []string{"AWS_REGION", "AWS_HOSTED_ZONE_ID", "AWS_PROFILE"}, DirectValues: []string{"AWS_REGION", "AWS_HOSTED_ZONE_ID", "AWS_PROFILE"}},
	DNSProviderDigitalOcean: {EnvironmentKeys: []string{"DO_AUTH_TOKEN_FILE"}},
	DNSProviderGCloud:       {EnvironmentKeys: []string{"GCE_SERVICE_ACCOUNT_FILE"}, RequiredValues: []string{"GCE_PROJECT"}, DirectValues: []string{"GCE_PROJECT"}},
	DNSProviderTencentCloud: {EnvironmentKeys: []string{"TENCENTCLOUD_SECRET_ID_FILE", "TENCENTCLOUD_SECRET_KEY_FILE"}, OptionalKeys: []string{"TENCENTCLOUD_SESSION_TOKEN_FILE", "TENCENTCLOUD_REGION"}, DirectValues: []string{"TENCENTCLOUD_REGION"}},
}
var envKeyPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

func ProviderSchemaFor(provider DNSProvider) (ProviderSchema, error) {
	schema, ok := providerSchemas[provider]
	if !ok {
		return ProviderSchema{}, fmt.Errorf("unsupported DNS provider")
	}
	schema.EnvironmentKeys = append([]string(nil), schema.EnvironmentKeys...)
	schema.OptionalKeys = append([]string(nil), schema.OptionalKeys...)
	schema.RequiredValues = append([]string(nil), schema.RequiredValues...)
	schema.DirectValues = append([]string(nil), schema.DirectValues...)
	return schema, nil
}

func LoadDNSBinding(directoryURL, accountKeyPath, accountEmail string, termsAccepted bool, provider DNSProvider, profilePath, zone string) (Binding, error) {
	directory, err := canonicalDirectory(directoryURL)
	if err != nil {
		return Binding{}, err
	}
	accountFingerprint, err := fingerprintProtected(accountKeyPath)
	if err != nil {
		return Binding{}, fmt.Errorf("ACME account key: %w", err)
	}
	schema, err := ProviderSchemaFor(provider)
	if err != nil {
		return Binding{}, err
	}
	profileFingerprint, err := fingerprintProtected(profilePath)
	if err != nil {
		return Binding{}, fmt.Errorf("DNS profile: %w", err)
	}
	values, err := parseProfile(profilePath)
	if err != nil {
		return Binding{}, err
	}
	required := map[string]bool{}
	optional := map[string]bool{}
	direct := map[string]bool{}
	for _, key := range schema.EnvironmentKeys {
		required[key] = true
	}
	for _, key := range schema.OptionalKeys {
		optional[key] = true
	}
	for _, key := range schema.RequiredValues {
		required[key] = true
	}
	for _, key := range schema.DirectValues {
		direct[key] = true
	}
	credentials := []CredentialFile{}
	principals := []string{}
	for key, value := range values {
		if !required[key] && !optional[key] {
			return Binding{}, fmt.Errorf("DNS profile contains unknown key %q", key)
		}
		if direct[key] {
			if !validPrincipalValue(value) {
				return Binding{}, fmt.Errorf("DNS non-secret identity invalid")
			}
			principals = append(principals, key+"="+value+";")
			delete(required, key)
			continue
		}
		fingerprint, err := fingerprintProtected(value)
		if err != nil {
			return Binding{}, fmt.Errorf("DNS credential %q: %w", key, err)
		}
		credentials = append(credentials, CredentialFile{Key: key, Path: value, Fingerprint: fingerprint})
		delete(required, key)
	}
	if len(required) != 0 {
		return Binding{}, fmt.Errorf("DNS profile omits required keys")
	}
	if provider == DNSProviderRoute53 {
		if err := validateRoute53Credentials(values["AWS_SHARED_CREDENTIALS_FILE"], values["AWS_PROFILE"]); err != nil {
			return Binding{}, err
		}
	}
	if provider == DNSProviderGCloud {
		if err := validateGCloudCredentials(values["GCE_SERVICE_ACCOUNT_FILE"], values["GCE_PROJECT"]); err != nil {
			return Binding{}, err
		}
	}
	slices.SortFunc(credentials, func(a, b CredentialFile) int { return strings.Compare(a.Key, b.Key) })
	slices.Sort(principals)
	principal := strings.Join(principals, "")
	if !validDNSZone(zone) {
		return Binding{}, fmt.Errorf("DNS authoritative zone invalid")
	}
	if !validAccountEmail(accountEmail) || !termsAccepted {
		return Binding{}, fmt.Errorf("ACME account email or Terms approval invalid")
	}
	return Binding{DirectoryURL: directory, AccountKeyPath: accountKeyPath, AccountKeyFingerprint: accountFingerprint, AccountEmail: accountEmail, TermsAccepted: true, Method: ChallengeDNS01, Provider: provider, ProfilePath: profilePath, ProfileFingerprint: profileFingerprint, CredentialFiles: credentials, Zone: zone, Principal: principal}, nil
}

func LoadHTTPBinding(directoryURL, accountKeyPath, accountEmail string, termsAccepted bool) (Binding, error) {
	directory, err := canonicalDirectory(directoryURL)
	if err != nil {
		return Binding{}, err
	}
	fingerprint, err := fingerprintProtected(accountKeyPath)
	if err != nil {
		return Binding{}, err
	}
	if !validAccountEmail(accountEmail) || !termsAccepted {
		return Binding{}, fmt.Errorf("ACME account email or Terms approval invalid")
	}
	return Binding{DirectoryURL: directory, AccountKeyPath: accountKeyPath, AccountKeyFingerprint: fingerprint, AccountEmail: accountEmail, TermsAccepted: true, Method: ChallengeHTTP01, CredentialFiles: []CredentialFile{}}, nil
}

func ValidateBinding(binding Binding) error {
	if _, err := canonicalDirectory(binding.DirectoryURL); err != nil {
		return err
	}
	if !digest(binding.AccountKeyFingerprint) || !cleanAbsolute(binding.AccountKeyPath) || !validAccountEmail(binding.AccountEmail) || !binding.TermsAccepted {
		return fmt.Errorf("ACME account binding invalid")
	}
	switch binding.Method {
	case ChallengeHTTP01:
		if binding.Provider != "" || binding.ProfilePath != "" || binding.ProfileFingerprint != "" || len(binding.CredentialFiles) != 0 || binding.Zone != "" || binding.Principal != "" {
			return fmt.Errorf("HTTP-01 binding contains DNS authority")
		}
	case ChallengeDNS01:
		if _, err := ParseDNSProvider(string(binding.Provider)); err != nil || !cleanAbsolute(binding.ProfilePath) || !digest(binding.ProfileFingerprint) || !validDNSZone(binding.Zone) {
			return fmt.Errorf("DNS-01 binding invalid")
		}
		schema, _ := ProviderSchemaFor(binding.Provider)
		allowedFiles := map[string]bool{}
		requiredFiles := map[string]bool{}
		direct := map[string]bool{}
		requiredDirect := map[string]bool{}
		for _, key := range schema.EnvironmentKeys {
			allowedFiles[key] = true
			requiredFiles[key] = true
		}
		for _, key := range schema.OptionalKeys {
			allowedFiles[key] = true
		}
		for _, key := range schema.DirectValues {
			direct[key] = true
			delete(allowedFiles, key)
		}
		for _, key := range schema.RequiredValues {
			requiredDirect[key] = true
		}
		for index, value := range binding.CredentialFiles {
			if !allowedFiles[value.Key] || !envKeyPattern.MatchString(value.Key) || !cleanAbsolute(value.Path) || !digest(value.Fingerprint) || index > 0 && binding.CredentialFiles[index-1].Key >= value.Key {
				return fmt.Errorf("DNS credential binding noncanonical")
			}
			delete(requiredFiles, value.Key)
		}
		if len(requiredFiles) != 0 {
			return fmt.Errorf("DNS credential binding incomplete")
		}
		seenDirect := map[string]bool{}
		principalEntries := []string{}
		if binding.Principal != "" {
			if !strings.HasSuffix(binding.Principal, ";") {
				return fmt.Errorf("DNS principal binding noncanonical")
			}
			for _, entry := range strings.Split(strings.TrimSuffix(binding.Principal, ";"), ";") {
				key, value, present := strings.Cut(entry, "=")
				canonical := entry + ";"
				if entry == "" || !present || !direct[key] || seenDirect[key] || !validPrincipalValue(value) || len(principalEntries) > 0 && principalEntries[len(principalEntries)-1] >= canonical {
					return fmt.Errorf("DNS principal binding noncanonical")
				}
				seenDirect[key] = true
				delete(requiredDirect, key)
				principalEntries = append(principalEntries, canonical)
			}
		}
		if len(requiredDirect) != 0 || strings.Join(principalEntries, "") != binding.Principal {
			return fmt.Errorf("DNS principal binding incomplete")
		}
	default:
		return fmt.Errorf("ACME challenge method invalid")
	}
	return nil
}

func BindingDigest(binding Binding) (string, error) {
	if err := ValidateBinding(binding); err != nil {
		return "", err
	}
	data := strings.Builder{}
	fmt.Fprintf(&data, "%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s", binding.DirectoryURL, binding.AccountKeyPath, binding.AccountKeyFingerprint+"\x00"+binding.AccountEmail+"\x00terms-approved", binding.Method, binding.Provider, binding.ProfilePath, binding.ProfileFingerprint, binding.Zone+"\x00"+binding.Principal)
	for _, file := range binding.CredentialFiles {
		fmt.Fprintf(&data, "\x00%s\x00%s\x00%s", file.Key, file.Path, file.Fingerprint)
	}
	sum := sha256.Sum256([]byte(data.String()))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func DNS01ZoneCoversDomains(zone string, domains []string) bool {
	if !validDNSZone(zone) || len(domains) == 0 {
		return false
	}
	for _, domain := range domains {
		owner := "_acme-challenge." + domain
		if owner != zone && !strings.HasSuffix(owner, "."+zone) {
			return false
		}
	}
	return true
}

func validPrincipalValue(value string) bool {
	return value != "" && !strings.ContainsAny(value, "\x00\r\n= ;")
}

func validDNSZone(value string) bool {
	if value == "" || value != strings.ToLower(value) || strings.HasSuffix(value, ".") || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func validAccountEmail(value string) bool { return acmeaccount.ValidContact(value) }

func canonicalDirectory(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" || parsed.String() != value {
		return "", fmt.Errorf("ACME directory URL must be canonical HTTPS")
	}
	return value, nil
}

func parseProfile(path string) (map[string]string, error) {
	if !cleanAbsolute(path) {
		return nil, fmt.Errorf("DNS profile path invalid")
	}
	file, err := openProtected(path)
	if err != nil {
		return nil, err
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 32<<10)
	values := map[string]string{}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || !envKeyPattern.MatchString(key) || value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n") || values[key] != "" {
			return nil, fmt.Errorf("DNS profile is noncanonical")
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

func validateRoute53Credentials(path, profile string) error {
	file, err := openProtected(path)
	if err != nil {
		return fmt.Errorf("Route53 credentials: %w", err)
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	scanner := bufio.NewScanner(io.LimitReader(file, 64<<10+1))
	scanner.Buffer(make([]byte, 1024), 64<<10)
	section := ""
	values := map[string]string{}
	seenSection := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			if name != profile || seenSection {
				return fmt.Errorf("Route53 credentials contain unbound profile")
			}
			section = name
			seenSection = true
			continue
		}
		if section != profile {
			return fmt.Errorf("Route53 credentials entry is outside selected profile")
		}
		key, value, found := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !found || value == "" || values[key] != "" || strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("Route53 credentials entry invalid")
		}
		switch key {
		case "aws_access_key_id", "aws_secret_access_key", "aws_session_token":
		default:
			return fmt.Errorf("Route53 credentials contain fallback directive")
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if !seenSection || values["aws_access_key_id"] == "" || values["aws_secret_access_key"] == "" {
		return fmt.Errorf("Route53 static credentials incomplete")
	}
	return nil
}

func validateGCloudCredentials(path, project string) error {
	file, err := openProtected(path)
	if err != nil {
		return fmt.Errorf("GCloud credentials: %w", err)
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	data, err := io.ReadAll(io.LimitReader(file, 64<<10+1))
	if err != nil || len(data) == 0 || len(data) > 64<<10 {
		return fmt.Errorf("GCloud credentials invalid")
	}
	var values map[string]json.RawMessage
	if err := json.Unmarshal(data, &values); err != nil {
		return fmt.Errorf("GCloud credentials invalid")
	}
	allowed := map[string]bool{"type": true, "project_id": true, "private_key_id": true, "private_key": true, "client_email": true, "client_id": true, "auth_uri": true, "token_uri": true, "auth_provider_x509_cert_url": true, "client_x509_cert_url": true, "universe_domain": true}
	for key := range values {
		if !allowed[key] {
			return fmt.Errorf("GCloud credentials contain unbound field")
		}
	}
	stringValue := func(key string) string {
		var value string
		if json.Unmarshal(values[key], &value) != nil {
			return ""
		}
		return value
	}
	if stringValue("type") != "service_account" || stringValue("project_id") != project || stringValue("private_key_id") == "" || stringValue("private_key") == "" || stringValue("client_email") == "" || stringValue("token_uri") != "https://oauth2.googleapis.com/token" {
		return fmt.Errorf("GCloud static service account incomplete")
	}
	return nil
}

func fingerprintProtected(path string) (string, error) {
	file, err := openProtected(path)
	if err != nil {
		return "", err
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	sum := sha256.New()
	buffer := make([]byte, 4096)
	total := 0
	for {
		n, readErr := file.Read(buffer)
		total += n
		if total > 64<<10 {
			return "", fmt.Errorf("protected source oversized")
		}
		if n > 0 {
			sum.Write(buffer[:n])
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return "", readErr
		}
	}
	if total == 0 {
		return "", fmt.Errorf("protected source empty")
	}
	return "sha256:" + hex.EncodeToString(sum.Sum(nil)), nil
}

func openProtected(path string) (*os.File, error) {
	if !cleanAbsolute(path) {
		return nil, fmt.Errorf("protected path invalid")
	}
	if err := safeParents(path); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("protected descriptor invalid")
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0o777 != 0o600 || stat.Nlink != 1 {
		_ = file.Close()
		return nil, fmt.Errorf("protected source metadata unsafe")
	}
	return file, nil
}

func safeParents(path string) error {
	for current := filepath.Dir(path); ; current = filepath.Dir(current) {
		var stat unix.Stat_t
		if unix.Lstat(current, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 || stat.Mode&0o022 != 0 {
			return fmt.Errorf("protected parent unsafe")
		}
		if current == "/" {
			return nil
		}
	}
}

func cleanAbsolute(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func digest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
