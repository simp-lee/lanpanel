// Package nginx owns LanPanel's closed Nginx configuration graph.
package nginx

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	ManifestSchema       = "lanpanel.nginx.graph.v1"
	DefaultWorkerTimeout = 10 * time.Second
	MaximumGraphEntries  = 1024
	MaximumGraphFileSize = 4 << 20
	MainFileName         = "nginx.conf"
	SanitizerFileName    = "header-sanitizer.conf"
	ManifestFileName     = "graph.json"
	AppsDirectory        = "apps-enabled"
	ChallengesDirectory  = "challenges-enabled"
	ControlDirectory     = "control-enabled"
	TemporaryDirectory   = "temporary-enabled"
	AuditMarker          = "# lanpanel rejection audit\n"
)

var (
	resourcePattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	acmeTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{20,256}$`)
)

type Paths struct {
	ConfigRoot      string
	StateRoot       string
	AuditPath       string
	CertificatePath string
	PrivateKeyPath  string
	PIDPath         string
}

func FixedPaths() Paths {
	return Paths{
		ConfigRoot:      "/etc/lanpanel/nginx",
		StateRoot:       "/var/lib/lanpanel/nginx",
		AuditPath:       "/var/log/lanpanel/nginx-rejections.log",
		CertificatePath: "/var/lib/lanpanel/installation/default-rejection.crt",
		PrivateKeyPath:  "/var/lib/lanpanel/installation/default-rejection.key",
		PIDPath:         "/run/lanpanel/nginx.pid",
	}
}

func (paths Paths) MainPath() string      { return filepath.Join(paths.ConfigRoot, MainFileName) }
func (paths Paths) SanitizerPath() string { return filepath.Join(paths.ConfigRoot, SanitizerFileName) }
func (paths Paths) ManifestPath() string  { return filepath.Join(paths.ConfigRoot, ManifestFileName) }
func (paths Paths) StagingPath() string   { return filepath.Join(paths.ConfigRoot, ".lanpanel-filetxn") }

type EntryKind string

const (
	EntryApp       EntryKind = "app"
	EntryChallenge EntryKind = "challenge"
	EntryControl   EntryKind = "control"
	EntryTemporary EntryKind = "temporary"
)

type Entry struct {
	Kind       EntryKind      `json:"kind"`
	ResourceID string         `json:"resource_id,omitempty"`
	Relative   string         `json:"relative"`
	Digest     string         `json:"digest"`
	Domains    []string       `json:"domains,omitempty"`
	Listeners  []string       `json:"listeners,omitempty"`
	Generation uint64         `json:"generation"`
	Temporary  *TemporarySite `json:"temporary,omitempty"`
	Challenge  *ChallengeSite `json:"challenge,omitempty"`
	Domain     *DomainSite    `json:"domain,omitempty"`
}
type DomainSite struct {
	Hosts              []string      `json:"hosts"`
	CertificatePointer string        `json:"certificate_pointer"`
	RejectionAuditPath string        `json:"rejection_audit_path"`
	AuthMode           string        `json:"auth_mode"`
	HTPasswdPath       string        `json:"htpasswd_path,omitempty"`
	CIDRs              []string      `json:"cidrs,omitempty"`
	UpstreamNetwork    string        `json:"upstream_network"`
	UpstreamAddress    string        `json:"upstream_address"`
	UpstreamSource     string        `json:"upstream_source,omitempty"`
	WebSocket          bool          `json:"websocket"`
	Tailnet            bool          `json:"tailnet,omitempty"`
	Static             []StaticRoute `json:"static,omitempty"`
	GoAccess           *GoAccessSite `json:"goaccess,omitempty"`
}
type GoAccessSite struct {
	CanonicalHost  string   `json:"canonical_host"`
	CredentialPath string   `json:"credential_path"`
	CIDRs          []string `json:"cidrs,omitempty"`
	DashboardPath  string   `json:"dashboard_path"`
	WebSocketPath  string   `json:"websocket_path"`
	Endpoint       string   `json:"endpoint"`
	ReportPath     string   `json:"report_path"`
	AccessLog      string   `json:"access_log"`
	Identity       string   `json:"identity"`
}
type StaticRoute struct {
	URLPath      string `json:"url_path"`
	RelativePath string `json:"relative_path"`
	SourcePath   string `json:"source_path"`
	Directory    bool   `json:"directory"`
	Anonymous    bool   `json:"anonymous,omitempty"`
	Identity     string `json:"identity"`
}
type ChallengeSite struct {
	Generation             uint64 `json:"generation"`
	Host                   string `json:"host"`
	Token                  string `json:"token"`
	TokenPath              string `json:"token_path"`
	KeyAuthorizationDigest string `json:"key_authorization_digest"`
	Webroot                string `json:"webroot"`
}

type TemporarySite struct {
	PublicIPv4      string `json:"public_ipv4"`
	Port            uint16 `json:"port"`
	HostAuthority   string `json:"host_authority"`
	UpstreamNetwork string `json:"upstream_network"`
	UpstreamAddress string `json:"upstream_address"`
	UpstreamSource  string `json:"upstream_source,omitempty"`
	ReadinessPath   string `json:"readiness_path"`
	Tailnet         bool   `json:"tailnet,omitempty"`
}

type Manifest struct {
	SchemaVersion          string  `json:"schema_version"`
	InstallationID         string  `json:"installation_id"`
	GenerationID           string  `json:"generation_id"`
	DefaultCertFingerprint string  `json:"default_certificate_fingerprint"`
	MainDigest             string  `json:"main_digest"`
	SanitizerDigest        string  `json:"sanitizer_digest"`
	Entries                []Entry `json:"entries"`
}

type Baseline struct {
	Files    map[string][]byte
	Manifest Manifest
}

type DefaultCertificate struct {
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	Fingerprint    string
	DNSName        string
}

func GenerateDefaultCertificate(installationID string, random io.Reader, now time.Time) (DefaultCertificate, error) {
	if !validRef(installationID) || now.IsZero() {
		return DefaultCertificate{}, fmt.Errorf("default rejection certificate authority is invalid")
	}
	if random == nil {
		random = rand.Reader
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), random)
	if err != nil {
		return DefaultCertificate{}, fmt.Errorf("generate default rejection key: %w", err)
	}
	serialBytes := make([]byte, 16)
	if _, err := io.ReadFull(random, serialBytes); err != nil {
		return DefaultCertificate{}, fmt.Errorf("generate default rejection serial: %w", err)
	}
	serialBytes[0] |= 0x80
	serial := new(big.Int).SetBytes(serialBytes)
	dnsName, _ := ExpectedDefaultDNSName(installationID)
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: dnsName, Organization: []string{"LanPanel default rejection"}},
		DNSNames:              []string{dnsName},
		NotBefore:             now.UTC().Add(-5 * time.Minute),
		NotAfter:              now.UTC().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(random, &template, &template, &key.PublicKey, key)
	if err != nil {
		return DefaultCertificate{}, fmt.Errorf("create default rejection certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return DefaultCertificate{}, err
	}
	fingerprint := sha256.Sum256(der)
	return DefaultCertificate{
		CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		PrivateKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		Fingerprint:    "sha256:" + hex.EncodeToString(fingerprint[:]),
		DNSName:        dnsName,
	}, nil
}

func ExpectedDefaultDNSName(installationID string) (string, error) {
	if !validRef(installationID) {
		return "", fmt.Errorf("installation identity is invalid")
	}
	nameSum := sha256.Sum256([]byte("lanpanel-default-rejection\x00" + installationID))
	return hex.EncodeToString(nameSum[:16]) + ".lanpanel.invalid", nil
}

func ParseDefaultCertificate(certificatePEM, privateKeyPEM []byte) (DefaultCertificate, error) {
	certificateBlock, rest := pem.Decode(certificatePEM)
	if certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return DefaultCertificate{}, fmt.Errorf("default rejection certificate PEM is invalid")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil || certificate.IsCA || certificate.SerialNumber == nil || certificate.SerialNumber.Sign() <= 0 || len(certificate.DNSNames) != 1 || !validDefaultDNSName(certificate.DNSNames[0]) || certificate.Subject.CommonName != certificate.DNSNames[0] || len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || certificate.KeyUsage != x509.KeyUsageDigitalSignature || certificate.NotAfter.Before(certificate.NotBefore) || certificate.CheckSignature(certificate.SignatureAlgorithm, certificate.RawTBSCertificate, certificate.Signature) != nil {
		return DefaultCertificate{}, fmt.Errorf("default rejection certificate identity is invalid")
	}
	keyBlock, rest := pem.Decode(privateKeyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return DefaultCertificate{}, fmt.Errorf("default rejection private key PEM is invalid")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	key, keyOK := parsed.(*ecdsa.PrivateKey)
	publicKey, publicOK := certificate.PublicKey.(*ecdsa.PublicKey)
	if err != nil || !keyOK || !publicOK || key.Curve != elliptic.P256() || !key.PublicKey.Equal(publicKey) {
		return DefaultCertificate{}, fmt.Errorf("default rejection certificate and key do not match")
	}
	fingerprint := sha256.Sum256(certificate.Raw)
	return DefaultCertificate{CertificatePEM: append([]byte(nil), certificatePEM...), PrivateKeyPEM: append([]byte(nil), privateKeyPEM...), Fingerprint: "sha256:" + hex.EncodeToString(fingerprint[:]), DNSName: certificate.DNSNames[0]}, nil
}

func RenderBaseline(paths Paths, installationID, generationID, certificateFingerprint string) (Baseline, error) {
	if err := validatePaths(paths); err != nil || !validRef(installationID) || !validRef(generationID) || !validDigest(certificateFingerprint) {
		return Baseline{}, fmt.Errorf("baseline Nginx graph authority is invalid: %w", err)
	}
	main := []byte(renderMain(paths))
	sanitizer := []byte(renderSanitizer())
	manifest := Manifest{
		SchemaVersion: ManifestSchema, InstallationID: installationID, GenerationID: generationID,
		DefaultCertFingerprint: certificateFingerprint, MainDigest: digest(main), SanitizerDigest: digest(sanitizer), Entries: []Entry{},
	}
	manifestBytes, err := EncodeManifest(manifest)
	if err != nil {
		return Baseline{}, err
	}
	return Baseline{Files: map[string][]byte{paths.MainPath(): main, paths.SanitizerPath(): sanitizer, paths.ManifestPath(): manifestBytes, paths.AuditPath: []byte(AuditMarker)}, Manifest: manifest}, nil
}

func EncodeManifest(manifest Manifest) ([]byte, error) {
	manifest.Entries = canonicalEntries(manifest.Entries)
	if err := ValidateManifest(manifest); err != nil {
		return nil, err
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func DecodeManifest(data []byte) (Manifest, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Manifest{}, fmt.Errorf("nginx graph manifest has trailing data")
	}
	canonical, err := EncodeManifest(manifest)
	if err != nil || !bytes.Equal(canonical, data) {
		return Manifest{}, fmt.Errorf("nginx graph manifest is noncanonical")
	}
	return manifest, nil
}

func ValidateManifest(manifest Manifest) error {
	if manifest.SchemaVersion != ManifestSchema || !validRef(manifest.InstallationID) || !validRef(manifest.GenerationID) || !validDigest(manifest.DefaultCertFingerprint) || !validDigest(manifest.MainDigest) || !validDigest(manifest.SanitizerDigest) || len(manifest.Entries) > MaximumGraphEntries {
		return fmt.Errorf("nginx graph manifest identity is invalid")
	}
	if !entriesEqual(manifest.Entries, canonicalEntries(manifest.Entries)) {
		return fmt.Errorf("nginx graph entries are noncanonical")
	}
	seenPath := map[string]bool{}
	seenDomain := map[string]string{}
	seenListener := map[string]string{}
	for _, entry := range manifest.Entries {
		if !validEntry(entry) || seenPath[entry.Relative] {
			return fmt.Errorf("nginx graph entry is invalid or duplicated")
		}
		seenPath[entry.Relative] = true
		for _, domain := range entry.Domains {
			if owner := seenDomain[domain]; owner != "" && owner != entry.ResourceID {
				return fmt.Errorf("nginx domain %q belongs to multiple resources", domain)
			}
			seenDomain[domain] = entry.ResourceID
		}
		for _, listener := range entry.Listeners {
			if sharedHTTPSListener(listener) {
				continue
			}
			if owner := seenListener[listener]; owner != "" && owner != entry.ResourceID {
				return fmt.Errorf("nginx listener %q belongs to multiple resources", listener)
			}
			seenListener[listener] = entry.ResourceID
		}
	}
	return nil
}

func Audit(paths Paths, owner filetxn.Owner) (Manifest, error) {
	if err := validateGraphBoundary(paths, owner); err != nil {
		return Manifest{}, err
	}
	manifestBytes, err := readRegular(paths.ManifestPath(), owner, 0o600, MaximumGraphFileSize)
	if err != nil {
		return Manifest{}, err
	}
	manifest, err := DecodeManifest(manifestBytes)
	if err != nil {
		return Manifest{}, err
	}
	if err := auditManifestGraph(paths, owner, manifest, nil); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// auditManifestGraph verifies an exact manifest graph. During a durable
// contraction only, allowedMissing may name journal-bound entries whose exact
// files have already been removed while the prior manifest is still current.
func auditManifestGraph(paths Paths, owner filetxn.Owner, manifest Manifest, allowedMissing map[string]bool) error {
	if err := validateGraphBoundary(paths, owner); err != nil {
		return err
	}
	if err := ValidateManifest(manifest); err != nil {
		return err
	}
	main, err := readRegular(paths.MainPath(), owner, 0o600, MaximumGraphFileSize)
	if err != nil || digest(main) != manifest.MainDigest || string(main) != renderMain(paths) {
		return fmt.Errorf("nginx main config differs from the closed graph")
	}
	sanitizer, err := readRegular(paths.SanitizerPath(), owner, 0o600, MaximumGraphFileSize)
	if err != nil || digest(sanitizer) != manifest.SanitizerDigest || string(sanitizer) != renderSanitizer() {
		return fmt.Errorf("nginx sanitizer differs from the closed graph")
	}
	certificatePEM, err := readRegular(paths.CertificatePath, owner, 0o644, MaximumGraphFileSize)
	if err != nil {
		return err
	}
	privateKeyPEM, err := readRegular(paths.PrivateKeyPath, owner, 0o600, MaximumGraphFileSize)
	if err != nil {
		return err
	}
	certificate, err := ParseDefaultCertificate(certificatePEM, privateKeyPEM)
	expectedDNS, dnsErr := ExpectedDefaultDNSName(manifest.InstallationID)
	if err != nil || dnsErr != nil || certificate.Fingerprint != manifest.DefaultCertFingerprint || certificate.DNSName != expectedDNS {
		return fmt.Errorf("nginx default rejection certificate fingerprint differs")
	}
	if err := validateAuditSink(paths.AuditPath, owner); err != nil {
		return err
	}
	rootEntries, err := os.ReadDir(paths.ConfigRoot)
	if err != nil {
		return err
	}
	allowedRoot := map[string]bool{MainFileName: true, SanitizerFileName: true, ManifestFileName: true, filepath.Base(paths.StagingPath()): true, AppsDirectory: true, ChallengesDirectory: true, ControlDirectory: true, TemporaryDirectory: true}
	for _, item := range rootEntries {
		if !allowedRoot[item.Name()] {
			return fmt.Errorf("foreign Nginx root graph entry %q", item.Name())
		}
	}
	want := map[string]Entry{}
	for _, entry := range manifest.Entries {
		want[entry.Relative] = entry
		data, readErr := readRegular(filepath.Join(paths.ConfigRoot, filepath.FromSlash(entry.Relative)), owner, 0o600, MaximumGraphFileSize)
		if readErr != nil && errors.Is(readErr, os.ErrNotExist) && allowedMissing[entry.Relative] {
			continue
		}
		if readErr != nil || digest(data) != entry.Digest || validateEntryConfig(entry, data) != nil {
			return fmt.Errorf("nginx graph entry %q differs from its manifest", entry.Relative)
		}
	}
	for _, directory := range []string{AppsDirectory, ChallengesDirectory, ControlDirectory, TemporaryDirectory} {
		entries, readErr := os.ReadDir(filepath.Join(paths.ConfigRoot, directory))
		if readErr != nil {
			return readErr
		}
		for _, item := range entries {
			relative := filepath.ToSlash(filepath.Join(directory, item.Name()))
			if item.IsDir() || !want[relative].valid() {
				return fmt.Errorf("foreign Nginx include graph entry %q", relative)
			}
		}
	}
	staging, err := os.ReadDir(paths.StagingPath())
	if err != nil || len(staging) != 0 {
		return fmt.Errorf("nginx graph staging is not empty")
	}
	return nil
}

func validateGraphBoundary(paths Paths, owner filetxn.Owner) error {
	if err := validatePaths(paths); err != nil {
		return err
	}
	if paths == FixedPaths() {
		for _, root := range []string{paths.ConfigRoot, paths.StateRoot, paths.CertificatePath, paths.PrivateKeyPath, paths.AuditPath, paths.PIDPath} {
			if err := validateParentChain(root); err != nil {
				return err
			}
		}
	}
	for _, directory := range []string{paths.ConfigRoot, paths.StagingPath(), filepath.Join(paths.ConfigRoot, AppsDirectory), filepath.Join(paths.ConfigRoot, ChallengesDirectory), filepath.Join(paths.ConfigRoot, ControlDirectory), filepath.Join(paths.ConfigRoot, TemporaryDirectory), paths.StateRoot} {
		if err := validateDirectory(directory, owner); err != nil {
			return err
		}
	}
	return nil
}

// Contract removes only manifest-bound App/challenge/temporary entries. It
// never restores an enable after the caller has persisted contraction authority.
func ProspectiveManifest(manifest Manifest, entry Entry) (Manifest, error) {
	prospective, _, _, err := prospectiveManifestEntry(manifest, entry)
	return prospective, err
}

func ProspectiveRemoval(manifest Manifest, expected Entry) (Manifest, error) {
	prospective, _, err := prospectiveManifestRemoval(manifest, expected)
	return prospective, err
}

func prospectiveManifestEntry(manifest Manifest, entry Entry) (Manifest, bool, []byte, error) {
	if err := ValidateManifest(manifest); err != nil {
		return Manifest{}, false, nil, err
	}
	manifest.Entries = append([]Entry(nil), manifest.Entries...)
	replaceIndex := -1
	for index, current := range manifest.Entries {
		if current.Relative == entry.Relative || current.ResourceID == entry.ResourceID && current.Kind == entry.Kind {
			if current.Relative != entry.Relative || current.ResourceID != entry.ResourceID || current.Kind != entry.Kind {
				return Manifest{}, false, nil, fmt.Errorf("nginx active entry identity conflicts")
			}
			replaceIndex = index
		}
	}
	data, err := RenderEntry(entry)
	if err != nil {
		return Manifest{}, false, nil, err
	}
	entry.Digest = digest(data)
	if replaceIndex >= 0 {
		manifest.Entries = append(manifest.Entries[:replaceIndex], manifest.Entries[replaceIndex+1:]...)
	}
	manifest.Entries = canonicalEntries(append(manifest.Entries, entry))
	if err := ValidateManifest(manifest); err != nil {
		return Manifest{}, false, nil, err
	}
	return manifest, replaceIndex >= 0, data, nil
}

func InstallEntry(ctx context.Context, paths Paths, owner filetxn.Owner, entry Entry) (Manifest, []string, error) {
	if err := requireNoPendingContraction(paths, owner); err != nil {
		return Manifest{}, nil, err
	}
	manifest, err := Audit(paths, owner)
	if err != nil {
		return Manifest{}, nil, err
	}
	manifest, replacing, data, err := prospectiveManifestEntry(manifest, entry)
	if err != nil {
		return Manifest{}, nil, err
	}
	txn, err := filetxn.Open(filetxn.Config{RootPath: paths.ConfigRoot, Root: filetxn.Metadata{Owner: owner, Mode: 0o700}, StagingPath: paths.StagingPath(), Staging: filetxn.Metadata{Owner: owner, Mode: 0o700}, StagingParents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o700}}, filetxn.Options{})
	if err != nil {
		return Manifest{}, nil, err
	}
	defer func(ignore func() error) { _ = ignore() }(txn.Close)
	metadata := filetxn.Metadata{Owner: owner, Mode: 0o600}
	entryPath := filepath.Join(paths.ConfigRoot, filepath.FromSlash(entry.Relative))
	var existing *filetxn.Metadata
	mode := filetxn.CreateOnly
	if replacing {
		existing = &metadata
		mode = filetxn.ReplaceOnly
	}
	result, err := txn.Put(ctx, filetxn.Request{Path: entryPath, Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o700}, Existing: existing, New: metadata, MaxBytes: MaximumGraphFileSize}, data, mode)
	if err != nil || result.State != filetxn.StateDurable {
		return Manifest{}, nil, fmt.Errorf("install active Nginx entry: %w", err)
	}
	manifestData, err := EncodeManifest(manifest)
	if err != nil {
		return Manifest{}, []string{entryPath}, err
	}
	result, err = txn.Put(ctx, filetxn.Request{Path: paths.ManifestPath(), Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o700}, Existing: &metadata, New: metadata, MaxBytes: MaximumGraphFileSize}, manifestData, filetxn.ReplaceOnly)
	if err != nil || result.State != filetxn.StateDurable {
		return Manifest{}, []string{entryPath}, fmt.Errorf("commit active Nginx manifest: %w", err)
	}
	audited, err := Audit(paths, owner)
	return audited, []string{entryPath, paths.ManifestPath()}, err
}

func prospectiveManifestRemoval(manifest Manifest, expected Entry) (Manifest, bool, error) {
	if err := ValidateManifest(manifest); err != nil {
		return Manifest{}, false, err
	}
	manifest.Entries = append([]Entry(nil), manifest.Entries...)
	index := -1
	for currentIndex, current := range manifest.Entries {
		if current.Relative == expected.Relative || current.ResourceID == expected.ResourceID && current.Kind == expected.Kind {
			if current.Relative != expected.Relative || current.ResourceID != expected.ResourceID || current.Kind != expected.Kind || current.Generation != expected.Generation || current.Digest != expected.Digest {
				return Manifest{}, false, fmt.Errorf("nginx exact entry identity changed")
			}
			index = currentIndex
		}
	}
	if index < 0 {
		return manifest, false, nil
	}
	manifest.Entries = append(manifest.Entries[:index], manifest.Entries[index+1:]...)
	if err := ValidateManifest(manifest); err != nil {
		return Manifest{}, false, err
	}
	return manifest, true, nil
}

func RemoveEntry(ctx context.Context, paths Paths, owner filetxn.Owner, expected Entry) (Manifest, []string, error) {
	if err := requireNoPendingContraction(paths, owner); err != nil {
		return Manifest{}, nil, err
	}
	manifest, err := Audit(paths, owner)
	if err != nil {
		return Manifest{}, nil, err
	}
	manifest, present, err := prospectiveManifestRemoval(manifest, expected)
	if err != nil {
		return Manifest{}, nil, err
	}
	if !present {
		return manifest, []string{}, nil
	}
	txn, err := filetxn.Open(filetxn.Config{RootPath: paths.ConfigRoot, Root: filetxn.Metadata{Owner: owner, Mode: 0o700}, StagingPath: paths.StagingPath(), Staging: filetxn.Metadata{Owner: owner, Mode: 0o700}, StagingParents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o700}}, filetxn.Options{})
	if err != nil {
		return Manifest{}, nil, err
	}
	defer func(ignore func() error) { _ = ignore() }(txn.Close)
	metadata := filetxn.Metadata{Owner: owner, Mode: 0o600}
	entryPath := filepath.Join(paths.ConfigRoot, filepath.FromSlash(expected.Relative))
	result, err := txn.Remove(ctx, filetxn.Request{Path: entryPath, Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o700}, Existing: &metadata, New: metadata, MaxBytes: MaximumGraphFileSize})
	if err != nil || result.State != filetxn.StateDurable {
		return Manifest{}, nil, fmt.Errorf("remove exact Nginx entry: %w", err)
	}
	data, err := EncodeManifest(manifest)
	if err != nil {
		return Manifest{}, []string{entryPath}, err
	}
	result, err = txn.Put(ctx, filetxn.Request{Path: paths.ManifestPath(), Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o700}, Existing: &metadata, New: metadata, MaxBytes: MaximumGraphFileSize}, data, filetxn.ReplaceOnly)
	if err != nil || result.State != filetxn.StateDurable {
		return Manifest{}, []string{entryPath}, fmt.Errorf("commit exact Nginx entry removal: %w", err)
	}
	audited, err := Audit(paths, owner)
	return audited, []string{entryPath, paths.ManifestPath()}, err
}

func Contract(ctx context.Context, paths Paths, owner filetxn.Owner, resourceIDs []string) (Manifest, []string, error) {
	return contract(ctx, paths, owner, resourceIDs, contractionOptions{})
}

func renderMain(paths Paths) string {
	return "user www-data;\n" +
		"worker_processes auto;\n" +
		"pid " + paths.PIDPath + ";\n" +
		"error_log stderr notice;\n" +
		"worker_shutdown_timeout 10s;\n" +
		"events { worker_connections 1024; }\n" +
		"http {\n" +
		"  server_tokens off;\n" +
		"  access_log off;\n" +
		"  include " + paths.SanitizerPath() + ";\n" +
		"  log_format lanpanel_rejection '$msec $remote_addr $server_port $ssl_server_name $host $status $http_x_lanpanel_closure_id';\n  map $status $lanpanel_rejection_loggable { default 0; 421 1; }\n" +
		"  server {\n" +
		"    listen 80 default_server;\n" +
		"    listen [::]:80 default_server;\n" +
		"    server_name _;\n" +
		"    access_log " + paths.AuditPath + " lanpanel_rejection;\n" +
		"    add_header X-LanPanel-Rejection default always;\n" +
		"    return 421;\n" +
		"  }\n" +
		"  server {\n" +
		"    listen 443 ssl default_server;\n" +
		"    listen [::]:443 ssl default_server;\n" +
		"    server_name _;\n" +
		"    ssl_certificate " + paths.CertificatePath + ";\n" +
		"    ssl_certificate_key " + paths.PrivateKeyPath + ";\n" +
		"    ssl_protocols TLSv1.2 TLSv1.3;\n" +
		"    access_log " + paths.AuditPath + " lanpanel_rejection;\n" +
		"    add_header X-LanPanel-Rejection default always;\n" +
		"    return 421;\n" +
		"  }\n" +
		"  include " + filepath.Join(paths.ConfigRoot, ControlDirectory, "*.conf") + ";\n" +
		"  include " + filepath.Join(paths.ConfigRoot, ChallengesDirectory, "*.conf") + ";\n" +
		"  include " + filepath.Join(paths.ConfigRoot, AppsDirectory, "*.conf") + ";\n" +
		"  include " + filepath.Join(paths.ConfigRoot, TemporaryDirectory, "*.conf") + ";\n" +
		"}\n"
}

func renderSanitizer() string {
	headers := []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "X-Real-IP", "X-Client-IP", "X-Cluster-Client-IP", "X-Original-Forwarded-For", "CF-Connecting-IP", "True-Client-IP", "EO-Connecting-IP", "EO-Client-IP", "X-LanPanel-Closure-ID"}
	var output strings.Builder
	output.WriteString("# release-owned fixed identity-header sanitizer\n")
	for _, header := range headers {
		fmt.Fprintf(&output, "proxy_set_header %s \"\";\n", header)
	}
	output.WriteString("proxy_set_header X-Real-IP $remote_addr;\n")
	output.WriteString("proxy_set_header X-Forwarded-For $remote_addr;\n")
	output.WriteString("proxy_set_header X-Forwarded-Host $host;\n")
	output.WriteString("proxy_set_header X-Forwarded-Proto $scheme;\n")
	return output.String()
}

func HeaderSanitizer() string { return renderSanitizer() }

func DomainSNIGuard(domains []string) (string, error) {
	if len(domains) == 0 || len(domains) > 256 {
		return "", fmt.Errorf("domain SNI guard requires an exact bounded domain set")
	}
	copyDomains := append([]string(nil), domains...)
	sort.Strings(copyDomains)
	for index, domain := range copyDomains {
		if !validDomain(domain) || index > 0 && copyDomains[index-1] == domain {
			return "", fmt.Errorf("domain SNI guard contains invalid or duplicate domain")
		}
	}
	quoted := make([]string, len(copyDomains))
	for index, domain := range copyDomains {
		quoted[index] = regexp.QuoteMeta(domain)
	}
	return "if ($ssl_server_name !~ ^(?:" + strings.Join(quoted, "|") + ")$) { return 421; }\n", nil
}

func (entry Entry) valid() bool { return validEntry(entry) }
func validEntry(entry Entry) bool {
	if entry.Generation == 0 || !validDigest(entry.Digest) || filepath.IsAbs(entry.Relative) || filepath.Clean(entry.Relative) != entry.Relative || strings.Contains(entry.Relative, "\\") || filepath.Ext(entry.Relative) != ".conf" {
		return false
	}
	prefix := strings.Split(entry.Relative, string(filepath.Separator))[0]
	switch entry.Kind {
	case EntryApp:
		if prefix != AppsDirectory || !resourcePattern.MatchString(entry.ResourceID) || len(entry.Domains) == 0 || (entry.Domain != nil && !validDomainSite(*entry.Domain, entry.Domains)) {
			return false
		}
	case EntryChallenge:
		if prefix != ChallengesDirectory || !resourcePattern.MatchString(entry.ResourceID) || len(entry.Domains) == 0 || entry.Challenge == nil || !slices.Equal(entry.Listeners, []string{"tcp:0.0.0.0:80", "tcp:[::]:80"}) || !validChallengeSite(*entry.Challenge, entry.Domains) {
			return false
		}
	case EntryControl:
		if prefix != ControlDirectory || entry.ResourceID != "" || len(entry.Domains) != 1 || !slices.Equal(entry.Listeners, []string{"tcp:0.0.0.0:443", "tcp:0.0.0.0:80", "tcp:[::]:443", "tcp:[::]:80"}) || entry.Domain == nil || !validDomainSite(*entry.Domain, entry.Domains) || entry.Domain.AuthMode != "application_managed" || entry.Domain.UpstreamNetwork != "unix" || !entry.Domain.WebSocket || len(entry.Domain.Static) != 0 || entry.Domain.GoAccess != nil || entry.Challenge != nil && !validChallengeSite(*entry.Challenge, entry.Domains) {
			return false
		}
	case EntryTemporary:
		if prefix != TemporaryDirectory || !resourcePattern.MatchString(entry.ResourceID) || len(entry.Domains) != 0 || len(entry.Listeners) != 1 || entry.Temporary == nil || !validTemporarySite(*entry.Temporary, entry.Listeners[0]) {
			return false
		}
	default:
		return false
	}
	for index, domain := range entry.Domains {
		if !validDomain(domain) || index > 0 && entry.Domains[index-1] >= domain {
			return false
		}
	}
	for index, listener := range entry.Listeners {
		if !validRef(listener) || index > 0 && entry.Listeners[index-1] >= listener {
			return false
		}
	}
	return true
}

func sharedHTTPSListener(value string) bool {
	return value == "tcp:0.0.0.0:80" || value == "tcp:[::]:80" || value == "tcp:0.0.0.0:443" || value == "tcp:[::]:443"
}

func entriesEqual(left, right []Entry) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !reflect.DeepEqual(left[index], right[index]) {
			return false
		}
	}
	return true
}

func canonicalEntries(entries []Entry) []Entry {
	result := append([]Entry(nil), entries...)
	for index := range result {
		result[index].Domains = append([]string(nil), result[index].Domains...)
		result[index].Listeners = append([]string(nil), result[index].Listeners...)
		sort.Strings(result[index].Domains)
		sort.Strings(result[index].Listeners)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Relative < result[right].Relative })
	if result == nil {
		return []Entry{}
	}
	return result
}

func validatePaths(paths Paths) error {
	for name, path := range map[string]string{"config": paths.ConfigRoot, "state": paths.StateRoot, "audit": paths.AuditPath, "certificate": paths.CertificatePath, "private_key": paths.PrivateKeyPath, "pid": paths.PIDPath} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
			return fmt.Errorf("nginx %s path is invalid", name)
		}
	}
	return nil
}

func validateParentChain(path string) error {
	current := filepath.Dir(path)
	for {
		var stat unix.Stat_t
		if err := unix.Lstat(current, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 || stat.Mode&0o002 != 0 || stat.Mode&0o020 != 0 && current != "/var/log" {
			return fmt.Errorf("nginx graph parent %q is unsafe", current)
		}
		if current == "/" {
			return nil
		}
		current = filepath.Dir(current)
	}
}

// RenderClosedEntry is the only S11 entry renderer. It deliberately emits an
// inert include while binding every declared identity. Later typed publication
// and control renderers replace this closed representation; Audit never accepts
// free-form Nginx directives as an entry implementation.
func validChallengeSite(site ChallengeSite, domains []string) bool {
	return site.Generation != 0 && len(domains) == 1 && domains[0] == site.Host && validDomain(site.Host) && acmeTokenPattern.MatchString(site.Token) && site.TokenPath == "/.well-known/acme-challenge/"+site.Token && validDigest(site.KeyAuthorizationDigest) && strings.HasPrefix(site.Webroot, "/var/lib/lanpanel/certificates/webroot/") && filepath.Clean(site.Webroot) == site.Webroot
}

func renderChallengeLocations(site ChallengeSite) string {
	return fmt.Sprintf("  # lanpanel HTTP-01 generation %d; key authorization %s\n  location = %s {\n    default_type application/octet-stream;\n    disable_symlinks on;\n    alias %s;\n    limit_except GET HEAD { deny all; }\n  }\n  location ^~ /.well-known/acme-challenge/ { return 404; }\n", site.Generation, site.KeyAuthorizationDigest, site.TokenPath, quoteNginxArgument(site.Webroot+site.TokenPath))
}

func renderChallenge(entry Entry) ([]byte, error) {
	site := entry.Challenge
	text := fmt.Sprintf("server {\n  listen 0.0.0.0:80;\n  listen [::]:80;\n  server_name %s;\n  if ($http_host !~* ^(?:%s)$) { return 421; }\n%s  location / { return 421; }\n}\n", site.Host, regexp.QuoteMeta(site.Host), renderChallengeLocations(*site))
	return []byte(text), nil
}

func validTemporarySite(site TemporarySite, listener string) bool {
	if domain.ValidateTemporaryPublicIPv4(site.PublicIPv4) != nil || site.Port < 1024 || site.Port == 80 || site.Port == 443 || site.HostAuthority != fmt.Sprintf("%s:%d", site.PublicIPv4, site.Port) || listener != fmt.Sprintf("tcp:0.0.0.0:%d", site.Port) || site.ReadinessPath == "" || !strings.HasPrefix(site.ReadinessPath, "/") {
		return false
	}
	switch site.UpstreamNetwork {
	case "unix":
		return !site.Tailnet && site.UpstreamSource == "" && !strings.ContainsAny(site.UpstreamAddress, "\x00\r\n;{}#$\\\"'") && filepath.IsAbs(site.UpstreamAddress) && filepath.Clean(site.UpstreamAddress) == site.UpstreamAddress
	case "tcp":
		host, port, err := net.SplitHostPort(site.UpstreamAddress)
		parsed, parseErr := netip.ParseAddr(host)
		return err == nil && parseErr == nil && port != "" && (site.Tailnet && parsed.IsGlobalUnicast() && !parsed.IsLoopback() && validTailnetSource(site.UpstreamSource, parsed.BitLen()) || !site.Tailnet && parsed.IsLoopback() && site.UpstreamSource == "")
	default:
		return false
	}
}

func validTailnetSource(value string, bits int) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.IsGlobalUnicast() && !address.IsLoopback() && address.BitLen() == bits
}

func validDomainSite(site DomainSite, domains []string) bool {
	if !slices.Equal(site.Hosts, domains) || !strings.HasPrefix(site.CertificatePointer, "/var/lib/lanpanel/certificates/active/") || filepath.Clean(site.CertificatePointer) != site.CertificatePointer || strings.ContainsAny(site.CertificatePointer, "\x00\r\n") || (site.AuthMode != "public" && site.AuthMode != "application_managed" && site.AuthMode != "basic") || (site.AuthMode == "basic") != (site.HTPasswdPath != "") || (site.HTPasswdPath != "" && (!filepath.IsAbs(site.HTPasswdPath) || filepath.Clean(site.HTPasswdPath) != site.HTPasswdPath || strings.ContainsAny(site.HTPasswdPath, "\x00\r\n"))) || (site.RejectionAuditPath != "/var/log/lanpanel/nginx-rejections.log") || (site.AuthMode != "basic" && len(site.CIDRs) != 0) || (site.UpstreamNetwork != "unix" && site.UpstreamNetwork != "tcp") || site.UpstreamAddress == "" {
		return false
	}
	if strings.ContainsAny(site.UpstreamAddress, " \t\r\n;{}#$\\\"") {
		return false
	}
	if site.UpstreamNetwork == "unix" && (site.Tailnet || site.UpstreamSource != "" || strings.ContainsAny(site.UpstreamAddress, "\x00\r\n;{}#$\\\"'") || !filepath.IsAbs(site.UpstreamAddress) || filepath.Clean(site.UpstreamAddress) != site.UpstreamAddress) {
		return false
	}
	if site.UpstreamNetwork == "tcp" {
		host, port, err := net.SplitHostPort(site.UpstreamAddress)
		address, addressErr := netip.ParseAddr(host)
		value, valueErr := strconv.ParseUint(port, 10, 16)
		if err != nil || addressErr != nil || valueErr != nil || value == 0 || site.Tailnet && (!address.IsGlobalUnicast() || address.IsLoopback() || !validTailnetSource(site.UpstreamSource, address.BitLen())) || !site.Tailnet && (!address.IsLoopback() || site.UpstreamSource != "") {
			return false
		}
	}
	priorCIDR := ""
	for _, value := range site.CIDRs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.String() != value || priorCIDR != "" && priorCIDR >= value {
			return false
		}
		priorCIDR = value
	}
	if site.GoAccess != nil && (!validGoAccessSite(*site.GoAccess) || !slices.Contains(site.Hosts, site.GoAccess.CanonicalHost)) {
		return false
	}
	prior := ""
	for _, route := range site.Static {
		if route.URLPath == "" || !strings.HasPrefix(route.URLPath, "/") || strings.ContainsAny(route.URLPath, " \t\r\n;{}#$\\\"'") || route.RelativePath == "" || filepath.IsAbs(route.RelativePath) || filepath.Clean(route.RelativePath) != route.RelativePath || strings.HasPrefix(route.RelativePath, "..") || route.SourcePath == "" || !filepath.IsAbs(route.SourcePath) || filepath.Clean(route.SourcePath) != route.SourcePath || strings.ContainsAny(route.SourcePath, "\x00\r\n") || route.Directory != (route.URLPath != "/" && strings.HasSuffix(route.URLPath, "/")) || !validDigest(route.Identity) || prior != "" && prior >= route.URLPath {
			return false
		}
		if goaccess := site.GoAccess; goaccess != nil && (strings.HasPrefix(route.URLPath, goaccess.DashboardPath) || strings.HasPrefix(goaccess.DashboardPath, route.URLPath) || route.URLPath == goaccess.WebSocketPath || route.Directory && strings.HasPrefix(goaccess.WebSocketPath, route.URLPath)) {
			return false
		}
		prior = route.URLPath
	}
	return true
}

func validGoAccessSite(value GoAccessSite) bool {
	if strings.ContainsAny(value.CredentialPath+value.Endpoint+value.ReportPath+value.AccessLog, "\x00\r\n") || !filepath.IsAbs(value.CredentialPath) || filepath.Clean(value.CredentialPath) != value.CredentialPath || !validDomain(value.CanonicalHost) || !strings.HasPrefix(value.Endpoint, "/run/lanpanel-goaccess/") || filepath.Clean(value.Endpoint) != value.Endpoint || !strings.HasPrefix(value.ReportPath, "/var/lib/lanpanel/goaccess/") || filepath.Clean(value.ReportPath) != value.ReportPath || !strings.HasPrefix(value.AccessLog, "/var/log/lanpanel/goaccess/") || filepath.Clean(value.AccessLog) != value.AccessLog || !strings.HasPrefix(value.DashboardPath, "/") || !strings.HasSuffix(value.DashboardPath, "/") || filepath.Clean(value.DashboardPath) != strings.TrimSuffix(value.DashboardPath, "/") || !strings.HasPrefix(value.WebSocketPath, "/") || strings.HasSuffix(value.WebSocketPath, "/") || filepath.Clean(value.WebSocketPath) != value.WebSocketPath || strings.HasPrefix(value.WebSocketPath, value.DashboardPath) || !validDigest(value.Identity) {
		return false
	}
	prior := ""
	for _, cidr := range value.CIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil || prefix.String() != cidr || prefix.Bits() == 0 || !prefix.Addr().IsGlobalUnicast() || prefix.Addr().IsPrivate() || prior != "" && prior >= cidr {
			return false
		}
		prior = cidr
	}
	return true
}

func renderLocationAccess(output *strings.Builder, path string, cidrs []string) {
	output.WriteString("    auth_basic \"Restricted\";\n    auth_basic_user_file " + quoteNginxArgument(path) + ";\n")
	for _, cidr := range cidrs {
		output.WriteString("    allow " + cidr + ";\n")
	}
	if len(cidrs) > 0 {
		output.WriteString("    deny all;\n")
	}
}

func quoteNginxArgument(value string) string {
	replacer := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "$", "\\$")
	return "\"" + replacer.Replace(value) + "\""
}

func renderDomain(entry Entry) ([]byte, error) {
	site := entry.Domain
	hosts := strings.Join(site.Hosts, " ")
	hostPattern := make([]string, len(site.Hosts))
	for index, host := range site.Hosts {
		hostPattern[index] = regexp.QuoteMeta(host)
	}
	certificate := quoteNginxArgument(site.CertificatePointer + "/certificate.pem")
	key := quoteNginxArgument(site.CertificatePointer + "/private-key.pem")
	var output strings.Builder
	fmt.Fprintf(&output, "server {\n  listen 80;\n  listen [::]:80;\n  server_name %s;\n  access_log %s lanpanel_rejection if=$lanpanel_rejection_loggable;\n  if ($http_host !~* ^(?:%s)$) { return 421; }\n  return 308 https://$http_host$request_uri;\n}\n", hosts, quoteNginxArgument(site.RejectionAuditPath), strings.Join(hostPattern, "|"))
	fmt.Fprintf(&output, "server {\n  listen 443 ssl http2;\n  listen [::]:443 ssl http2;\n  server_name %s;\n  ssl_certificate %s;\n  ssl_certificate_key %s;\n  ssl_protocols TLSv1.2 TLSv1.3;\n  access_log %s lanpanel_rejection if=$lanpanel_rejection_loggable;\n  if ($http_host !~* ^(?:%s)$) { return 421; }\n  if ($ssl_server_name !~* ^(?:%s)$) { return 421; }\n", hosts, certificate, key, quoteNginxArgument(site.RejectionAuditPath), strings.Join(hostPattern, "|"), strings.Join(hostPattern, "|"))
	if value := site.GoAccess; value != nil {
		output.WriteString("  access_log " + quoteNginxArgument(value.AccessLog) + " combined;\n")
		output.WriteString("  location = " + value.WebSocketPath + " {\n")
		renderLocationAccess(&output, value.CredentialPath, value.CIDRs)
		output.WriteString("    proxy_http_version 1.1;\n    proxy_pass_request_headers off;\n    proxy_set_header Host $http_host;\n    proxy_set_header Upgrade $http_upgrade;\n    proxy_set_header Connection \"upgrade\";\n    proxy_set_header Sec-WebSocket-Key $http_sec_websocket_key;\n    proxy_set_header Sec-WebSocket-Version $http_sec_websocket_version;\n    proxy_set_header Authorization \"\";\n    proxy_set_header Proxy-Authorization \"\";\n    proxy_set_header Cookie \"\";\n    proxy_set_header Forwarded \"\";\n    proxy_set_header X-Forwarded-For \"\";\n    proxy_set_header X-Forwarded-Host \"\";\n    proxy_set_header X-Forwarded-Proto \"\";\n    proxy_set_header X-Real-IP \"\";\n    proxy_set_header X-Forwarded-Port \"\";\n    proxy_set_header X-Client-IP \"\";\n    proxy_set_header X-Cluster-Client-IP \"\";\n    proxy_set_header X-Original-Forwarded-For \"\";\n    proxy_set_header CF-Connecting-IP \"\";\n    proxy_set_header True-Client-IP \"\";\n    proxy_set_header EO-Connecting-IP \"\";\n    proxy_set_header EO-Client-IP \"\";\n    proxy_set_header X-LanPanel-Closure-ID \"\";\n    proxy_set_header X-Forwarded-User \"\";\n    proxy_set_header X-Authenticated-User \"\";\n    proxy_set_header Remote-User \"\";\n    proxy_set_header X-Forwarded-For $remote_addr;\n    proxy_set_header X-Forwarded-Host $http_host;\n    proxy_set_header X-Forwarded-Proto https;\n    proxy_set_header X-Real-IP $remote_addr;\n    proxy_pass http://unix:" + value.Endpoint + ":;\n  }\n")
		output.WriteString("  location = " + value.DashboardPath + " {\n    if ($host != " + quoteNginxArgument(value.CanonicalHost) + ") { return 308 https://" + value.CanonicalHost + "$request_uri; }\n")
		renderLocationAccess(&output, value.CredentialPath, value.CIDRs)
		output.WriteString("    default_type text/html;\n    disable_symlinks on;\n    alias " + quoteNginxArgument(value.ReportPath) + ";\n    limit_except GET HEAD { deny all; }\n  }\n  location ^~ " + value.DashboardPath + " { return 404; }\n")
	}
	for _, route := range site.Static {
		modifier := " ="
		source := route.SourcePath
		if route.Directory {
			modifier = " ^~"
			source += "/"
		}
		fmt.Fprintf(&output, "  location%s %s {\n", modifier, route.URLPath)
		if site.AuthMode == "basic" && !route.Anonymous {
			renderLocationAccess(&output, site.HTPasswdPath, site.CIDRs)
		}
		fmt.Fprintf(&output, "    disable_symlinks on;\n    alias %s;\n    try_files $request_filename =404;\n    limit_except GET HEAD { deny all; }\n  }\n", quoteNginxArgument(source))
	}
	authorization := "\"\""
	if site.AuthMode == "application_managed" {
		authorization = "$http_authorization"
	}
	upstream := "http://unix:" + site.UpstreamAddress + ":"
	if site.UpstreamNetwork == "tcp" {
		upstream = "http://" + site.UpstreamAddress
	}
	output.WriteString("  location / {\n")
	if site.AuthMode == "basic" {
		renderLocationAccess(&output, site.HTPasswdPath, site.CIDRs)
	}
	output.WriteString("    proxy_http_version 1.1;\n    proxy_set_header Host $http_host;\n    proxy_set_header Authorization " + authorization + ";\n    proxy_set_header Proxy-Authorization \"\";\n    proxy_set_header Forwarded \"\";\n    proxy_set_header X-Forwarded-For \"\";\n    proxy_set_header X-Forwarded-Host \"\";\n    proxy_set_header X-Forwarded-Proto \"\";\n    proxy_set_header X-Forwarded-Port \"\";\n    proxy_set_header X-Real-IP \"\";\n    proxy_set_header X-Client-IP \"\";\n    proxy_set_header X-Cluster-Client-IP \"\";\n    proxy_set_header X-Original-Forwarded-For \"\";\n    proxy_set_header CF-Connecting-IP \"\";\n    proxy_set_header True-Client-IP \"\";\n    proxy_set_header EO-Connecting-IP \"\";\n    proxy_set_header EO-Client-IP \"\";\n    proxy_set_header X-LanPanel-Closure-ID \"\";\n    proxy_set_header X-Forwarded-User \"\";\n    proxy_set_header X-Authenticated-User \"\";\n    proxy_set_header Remote-User \"\";\n    proxy_set_header X-Forwarded-For $remote_addr;\n    proxy_set_header X-Forwarded-Host $http_host;\n    proxy_set_header X-Forwarded-Proto https;\n    proxy_set_header X-Real-IP $remote_addr;\n")
	if site.WebSocket {
		output.WriteString("    proxy_set_header Upgrade $http_upgrade;\n    proxy_set_header Connection \"upgrade\";\n")
	} else {
		output.WriteString("    proxy_set_header Upgrade \"\";\n    proxy_set_header Connection \"\";\n")
	}
	if site.Tailnet {
		output.WriteString("    proxy_bind " + site.UpstreamSource + ";\n")
	}
	output.WriteString("    proxy_pass " + upstream + ";\n  }\n}\n")
	return []byte(output.String()), nil
}

func DigestEntry(entry Entry) (string, error) {
	copy := entry
	copy.Digest = "sha256:" + strings.Repeat("0", 64)
	data, err := RenderEntry(copy)
	if err != nil {
		return "", err
	}
	return digest(data), nil
}

func RenderEntry(entry Entry) ([]byte, error) {
	if !validEntry(entry) {
		return nil, fmt.Errorf("nginx graph entry authority is invalid")
	}
	if entry.Kind == EntryChallenge {
		return renderChallenge(entry)
	}
	if entry.Kind == EntryControl && entry.Domain != nil {
		data, err := renderDomain(entry)
		if err != nil {
			return nil, err
		}
		authorization := []byte("    proxy_set_header Authorization $http_authorization;\n")
		if bytes.Count(data, authorization) != 1 {
			return nil, fmt.Errorf("headscale control sanitizer rendering changed")
		}
		explicit := append(append([]byte(nil), authorization...), []byte("    proxy_set_header Cookie \"\";\n")...)
		data = bytes.Replace(data, authorization, explicit, 1)
		if entry.Challenge != nil {
			needle := []byte("  return 308 https://$http_host$request_uri;\n")
			if bytes.Count(data, needle) != 1 {
				return nil, fmt.Errorf("headscale challenge insertion changed")
			}
			route := []byte(renderChallengeLocations(*entry.Challenge))
			data = bytes.Replace(data, needle, append(route, needle...), 1)
		}
		return data, nil
	}
	if entry.Kind == EntryApp && entry.Domain != nil {
		return renderDomain(entry)
	}
	if entry.Kind != EntryTemporary {
		return RenderClosedEntry(entry)
	}
	site := entry.Temporary
	upstream := "http://" + site.UpstreamAddress
	if site.UpstreamNetwork == "unix" {
		upstream = "http://unix:" + site.UpstreamAddress + ":"
	}
	proxyBind := ""
	if site.Tailnet {
		proxyBind = "    proxy_bind " + site.UpstreamSource + ";\n"
	}
	text := fmt.Sprintf("server {\n  listen 0.0.0.0:%d default_server;\n  server_name _;\n  add_header X-LanPanel-Rejection temporary_default always;\n  return 421;\n}\nserver {\n  listen 0.0.0.0:%d;\n  server_name %s;\n  if ($http_host != %s) { return 421; }\n  if ($server_protocol != HTTP/1.1) { return 505; }\n  location / {\n    proxy_http_version 1.1;\n    proxy_set_header Host $http_host;\n    proxy_set_header Authorization \"\";\n    proxy_set_header Proxy-Authorization \"\";\n    proxy_set_header Cookie \"\";\n    proxy_set_header X-Forwarded-User \"\";\n    proxy_set_header X-Authenticated-User \"\";\n    proxy_set_header Remote-User \"\";\n    proxy_set_header Forwarded \"\";\n    proxy_set_header X-Forwarded-For \"\";\n    proxy_set_header X-Forwarded-Host \"\";\n    proxy_set_header X-Forwarded-Proto \"\";\n    proxy_set_header X-Forwarded-Port \"\";\n    proxy_set_header X-Real-IP \"\";\n    proxy_set_header X-Client-IP \"\";\n    proxy_set_header X-Cluster-Client-IP \"\";\n    proxy_set_header X-Original-Forwarded-For \"\";\n    proxy_set_header CF-Connecting-IP \"\";\n    proxy_set_header True-Client-IP \"\";\n    proxy_set_header EO-Connecting-IP \"\";\n    proxy_set_header EO-Client-IP \"\";\n    proxy_set_header X-Real-IP $remote_addr;\n    proxy_set_header X-Forwarded-For $remote_addr;\n    proxy_set_header X-Forwarded-Host $http_host;\n    proxy_set_header X-Forwarded-Proto http;\n    proxy_set_header Upgrade \"\";\n    proxy_set_header Connection \"\";\n    add_header Warning '299 lanpanel \"Public plaintext HTTP; never transmit credentials or sensitive data\"' always;\n    add_header X-LanPanel-Plaintext-Warning public_http_anyone_no_credentials always;\n%s    proxy_pass %s;\n  }\n}\n", site.Port, site.Port, site.PublicIPv4, site.HostAuthority, proxyBind, upstream)
	return []byte(text), nil
}

func RenderClosedEntry(entry Entry) ([]byte, error) {
	if !validEntry(entry) {
		return nil, fmt.Errorf("nginx graph entry authority is invalid")
	}
	binding := struct {
		Kind       EntryKind `json:"kind"`
		ResourceID string    `json:"resource_id,omitempty"`
		Relative   string    `json:"relative"`
		Domains    []string  `json:"domains,omitempty"`
		Listeners  []string  `json:"listeners,omitempty"`
		Generation uint64    `json:"generation"`
	}{entry.Kind, entry.ResourceID, entry.Relative, entry.Domains, entry.Listeners, entry.Generation}
	if entry.Temporary != nil || entry.Challenge != nil || entry.Domain != nil {
		return nil, fmt.Errorf("active entry cannot use closed renderer")
	}
	data, err := json.Marshal(binding)
	if err != nil {
		return nil, err
	}
	return []byte("# lanpanel closed graph entry v1\n# " + string(data) + "\n"), nil
}

func validateEntryConfig(entry Entry, data []byte) error {
	expected, err := RenderEntry(entry)
	if err != nil || !bytes.Equal(data, expected) {
		return fmt.Errorf("nginx graph entry is not its exact closed rendering")
	}
	return nil
}

func validateDirectory(path string, owner filetxn.Owner) error {
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o7777 != 0o700 || stat.Uid != owner.UID || stat.Gid != owner.GID {
		return fmt.Errorf("nginx graph directory %q is unsafe", path)
	}
	return nil
}

func readRegular(path string, owner filetxn.Owner, mode fs.FileMode, maximum int64) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("wrap Nginx graph descriptor")
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&0o7777 != uint32(mode.Perm()) || before.Uid != owner.UID || before.Gid != owner.GID || before.Nlink != 1 || before.Size <= 0 || before.Size > maximum {
		return nil, fmt.Errorf("nginx graph file %q has unsafe metadata", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) != before.Size || unix.Fstat(fd, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim {
		return nil, fmt.Errorf("nginx graph file %q changed while read", path)
	}
	return data, nil
}

func validateAuditSink(path string, owner filetxn.Owner) error {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_APPEND|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != 0o600 || stat.Uid != owner.UID || stat.Gid != owner.GID || stat.Nlink != 1 {
		return fmt.Errorf("nginx rejection audit sink is unsafe")
	}
	return nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil
}

func validRef(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= 256 && !strings.ContainsAny(value, "\x00\r\n")
}

func validDefaultDNSName(value string) bool {
	if !strings.HasSuffix(value, ".lanpanel.invalid") || strings.Count(value, ".") != 2 {
		return false
	}
	prefix := strings.TrimSuffix(value, ".lanpanel.invalid")
	if len(prefix) != 32 || strings.ToLower(prefix) != prefix {
		return false
	}
	_, err := hex.DecodeString(prefix)
	return err == nil
}

func validDomain(value string) bool {
	if value == "" || value != strings.ToLower(value) || len(value) > 253 || strings.ContainsAny(value, "*:/ ") {
		return false
	}
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "" || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, character := range part {
			if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
				return false
			}
		}
	}
	return true
}
