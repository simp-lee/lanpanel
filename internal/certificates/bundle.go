package certificates

import (
	"bytes"
	"context"
	"crypto"
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
	"lanpanel/internal/filetxn"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	SchemaVersion         = "lanpanel.certificate.bundle.v2"
	minimumIssuedLifetime = time.Hour
)

type Identity struct {
	SchemaVersion     string    `json:"schema_version"`
	ID                string    `json:"id"`
	Generation        uint64    `json:"generation"`
	Domains           []string  `json:"domains"`
	SANIdentity       string    `json:"san_identity"`
	Fingerprint       string    `json:"fingerprint"`
	ChainIdentity     string    `json:"chain_identity"`
	IssuerIdentity    string    `json:"issuer_identity"`
	BindingIdentity   string    `json:"binding_identity"`
	LastTrustedWall   time.Time `json:"last_trusted_wall"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	CertificatePath   string    `json:"certificate_path"`
	PrivateKeyPath    string    `json:"private_key_path"`
	DirectoryIdentity string    `json:"directory_identity"`
}

type BundleIdentity struct {
	Fingerprint       string `json:"fingerprint"`
	SANIdentity       string `json:"san_identity"`
	ChainIdentity     string `json:"chain_identity"`
	IssuerIdentity    string `json:"issuer_identity"`
	BindingIdentity   string `json:"binding_identity"`
	DirectoryIdentity string `json:"directory_identity"`
}

func BundleIdentityFor(identity Identity) BundleIdentity {
	return BundleIdentity{Fingerprint: identity.Fingerprint, SANIdentity: identity.SANIdentity, ChainIdentity: identity.ChainIdentity, IssuerIdentity: identity.IssuerIdentity, BindingIdentity: identity.BindingIdentity, DirectoryIdentity: identity.DirectoryIdentity}
}

func ValidateBundleIdentity(identity BundleIdentity) error {
	if !digest(identity.Fingerprint) || !digest(identity.SANIdentity) || !digest(identity.ChainIdentity) || !digest(identity.IssuerIdentity) || !digest(identity.BindingIdentity) || !digest(identity.DirectoryIdentity) {
		return fmt.Errorf("certificate bundle activation identity incomplete")
	}
	return nil
}

type BootstrapMaterial struct {
	certificatePEM, privateKeyPEM []byte
	domains                       []string
	fingerprint                   string
	notAfter                      time.Time
}
type IssuedMaterial struct {
	certificatePEM, privateKeyPEM              []byte
	domains                                    []string
	fingerprint, chainIdentity, issuerIdentity string
	notBefore, notAfter                        time.Time
}

func (material BootstrapMaterial) CertificatePEM() []byte {
	return append([]byte(nil), material.certificatePEM...)
}

func (material BootstrapMaterial) PrivateKeyPEM() []byte {
	return append([]byte(nil), material.privateKeyPEM...)
}
func (material BootstrapMaterial) Fingerprint() string { return material.fingerprint }
func (material BootstrapMaterial) NotAfter() time.Time { return material.notAfter }
func (material IssuedMaterial) CertificatePEM() []byte {
	return append([]byte(nil), material.certificatePEM...)
}

func (material IssuedMaterial) PrivateKeyPEM() []byte {
	return append([]byte(nil), material.privateKeyPEM...)
}
func (material IssuedMaterial) NotAfter() time.Time { return material.notAfter }
func (material IssuedMaterial) Fingerprint() string { return material.fingerprint }

func GenerateBootstrap(domains []string, now time.Time, random io.Reader) (BootstrapMaterial, error) {
	domains, err := validateDomains(domains)
	if err != nil || now.IsZero() {
		return BootstrapMaterial{}, fmt.Errorf("bootstrap certificate identity invalid")
	}
	if random == nil {
		random = rand.Reader
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), random)
	if err != nil {
		return BootstrapMaterial{}, err
	}
	serialBytes := make([]byte, 16)
	if _, err := io.ReadFull(random, serialBytes); err != nil {
		return BootstrapMaterial{}, err
	}
	serialBytes[0] |= 0x80
	template := x509.Certificate{SerialNumber: new(big.Int).SetBytes(serialBytes), Subject: pkix.Name{CommonName: domains[0], Organization: []string{"LanPanel challenge bootstrap"}}, DNSNames: domains, NotBefore: now.UTC().Add(-time.Minute), NotAfter: now.UTC().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(random, &template, &template, &key.PublicKey, key)
	if err != nil {
		return BootstrapMaterial{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return BootstrapMaterial{}, err
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certificate, _ := x509.ParseCertificate(der)
	return BootstrapMaterial{certificatePEM: certificatePEM, privateKeyPEM: privateKeyPEM, domains: domains, fingerprint: sum(certificate.Raw), notAfter: certificate.NotAfter.UTC()}, nil
}

func JoinLegoChain(leafPEM, issuerPEM []byte) ([]byte, error) {
	leaf, err := parseCertificateChain(leafPEM)
	if err != nil || len(leaf) != 1 {
		return nil, fmt.Errorf("lego leaf output invalid")
	}
	issuer, err := parseCertificateChain(issuerPEM)
	if err != nil || len(issuer) == 0 {
		return nil, fmt.Errorf("lego issuer output invalid")
	}
	seen := map[string]bool{sum(leaf[0].Raw): true}
	for _, certificate := range issuer {
		fingerprint := sum(certificate.Raw)
		if seen[fingerprint] {
			return nil, fmt.Errorf("lego certificate chain duplicates identity")
		}
		seen[fingerprint] = true
	}
	result := append([]byte(nil), leafPEM...)
	if len(result) > 0 && result[len(result)-1] != '\n' {
		result = append(result, '\n')
	}
	result = append(result, issuerPEM...)
	return result, nil
}

func ValidateIssued(certificateChainPEM, privateKeyPEM []byte, domains []string, now time.Time, directoryURL string) (IssuedMaterial, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		return IssuedMaterial{}, fmt.Errorf("system certificate roots unavailable")
	}
	return ValidateIssuedWithRoots(certificateChainPEM, privateKeyPEM, domains, now, directoryURL, roots)
}

func ValidateIssuedWithRoots(certificateChainPEM, privateKeyPEM []byte, domains []string, now time.Time, directoryURL string, roots *x509.CertPool) (IssuedMaterial, error) {
	domains, err := validateDomains(domains)
	if err != nil || now.IsZero() {
		return IssuedMaterial{}, fmt.Errorf("issued certificate identity invalid")
	}
	directory, err := url.Parse(directoryURL)
	if err != nil || directory.Scheme != "https" || directory.Host == "" {
		return IssuedMaterial{}, fmt.Errorf("issued certificate directory authority invalid")
	}
	inspected, err := inspectBundleMaterial(certificateChainPEM, privateKeyPEM)
	if err != nil {
		return IssuedMaterial{}, fmt.Errorf("issued certificate material invalid: %w", err)
	}
	certificates := inspected.certificates
	leaf := certificates[0]
	if leaf.IsCA || leaf.SerialNumber == nil || leaf.SerialNumber.BitLen() < 64 || !slices.Equal(inspected.domains, domains) || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || now.Before(leaf.NotBefore) || !leaf.NotAfter.After(now.Add(minimumIssuedLifetime)) {
		return IssuedMaterial{}, fmt.Errorf("issued leaf identity invalid")
	}
	if len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.URIs) != 0 {
		return IssuedMaterial{}, fmt.Errorf("issued certificate contains non-DNS SAN")
	}
	if roots == nil {
		return IssuedMaterial{}, fmt.Errorf("issued certificate trust roots unavailable")
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		if !certificate.IsCA {
			return IssuedMaterial{}, fmt.Errorf("issued certificate chain contains non-CA issuer")
		}
		intermediates.AddCert(certificate)
	}
	verified, err := leaf.Verify(x509.VerifyOptions{DNSName: domains[0], Intermediates: intermediates, Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	if err != nil || len(verified) == 0 || len(verified[0]) < 2 {
		return IssuedMaterial{}, fmt.Errorf("issued certificate chain is not trusted")
	}
	canonicalKey, err := x509.MarshalPKCS8PrivateKey(inspected.privateKey)
	if err != nil {
		return IssuedMaterial{}, fmt.Errorf("canonicalize issued private key: %w", err)
	}
	canonicalKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: canonicalKey})
	return IssuedMaterial{certificatePEM: append([]byte(nil), certificateChainPEM...), privateKeyPEM: canonicalKeyPEM, domains: domains, fingerprint: sum(leaf.Raw), chainIdentity: sum(certificateChainPEM), issuerIdentity: inspected.issuerIdentity, notBefore: leaf.NotBefore.UTC(), notAfter: leaf.NotAfter.UTC()}, nil
}

func StageIssued(ctx context.Context, parent, id string, generation uint64, bindingIdentity string, material IssuedMaterial, owner filetxn.Owner, now time.Time, authorize ...func(Identity) error) (Identity, error) {
	if id == "" || generation == 0 || !digest(bindingIdentity) || !cleanAbsolute(parent) || now.IsZero() || len(authorize) > 1 {
		return Identity{}, fmt.Errorf("certificate staging authority invalid")
	}
	name := fmt.Sprintf("%s-%020d", id, generation)
	base := filepath.Join(parent, name)
	identity := Identity{SchemaVersion: SchemaVersion, ID: id, Generation: generation, Domains: material.domains, SANIdentity: sum([]byte(strings.Join(material.domains, "\x00"))), Fingerprint: material.fingerprint, ChainIdentity: material.chainIdentity, IssuerIdentity: material.issuerIdentity, BindingIdentity: bindingIdentity, LastTrustedWall: now.UTC(), NotBefore: material.notBefore, NotAfter: material.notAfter, CertificatePath: filepath.Join(base, "certificate.pem"), PrivateKeyPath: filepath.Join(base, "private-key.pem")}
	identity.DirectoryIdentity = identityDigest(identity)
	if len(authorize) == 1 {
		if authorize[0] == nil {
			return Identity{}, fmt.Errorf("certificate staging identity authorizer missing")
		}
		if err := authorize[0](identity); err != nil {
			return Identity{}, err
		}
	}
	raw, _ := json.Marshal(identity)
	request := filetxn.DirectoryRequest{ParentPath: parent, Parent: filetxn.Metadata{Owner: filetxn.Owner{UID: 0, GID: 0}, Mode: 0o700}, TargetName: name, Directory: filetxn.Metadata{Owner: owner, Mode: 0o700}, Members: []filetxn.DirectoryMember{{Name: "certificate.pem", Data: material.certificatePEM, Owner: owner, Mode: 0o600, Maximum: 1 << 20}, {Name: "identity.json", Data: raw, Owner: owner, Mode: 0o600, Maximum: 64 << 10}, {Name: "private-key.pem", Data: material.privateKeyPEM, Owner: owner, Mode: 0o600, Maximum: 1 << 20}}}
	if _, err := filetxn.CommitNewDirectory(ctx, request); err != nil {
		return Identity{}, err
	}
	return identity, nil
}

func ObserveIdentity(parent, id string, generation uint64, owner filetxn.Owner) (Identity, error) {
	if !cleanAbsolute(parent) || id == "" || generation == 0 {
		return Identity{}, fmt.Errorf("certificate bundle observation authority invalid")
	}
	name := fmt.Sprintf("%s-%020d", id, generation)
	base := filepath.Join(parent, name)
	members, err := readCertificateBundle(parent, name, owner)
	if err != nil {
		return Identity{}, err
	}
	identityRaw := members["identity.json"]
	certificateRaw := members["certificate.pem"]
	privateRaw := members["private-key.pem"]
	var identity Identity
	decoder := json.NewDecoder(bytes.NewReader(identityRaw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&identity) != nil || decoder.Decode(&struct{}{}) != io.EOF || ValidateIdentity(identity) != nil || identity.ID != id || identity.Generation != generation {
		return Identity{}, fmt.Errorf("certificate identity observation invalid")
	}
	if err := verifyBundleMaterial(base, identity, certificateRaw, privateRaw); err != nil {
		return Identity{}, err
	}
	request := filetxn.DirectoryRequest{ParentPath: parent, Parent: filetxn.Metadata{Owner: filetxn.Owner{UID: 0, GID: 0}, Mode: 0o700}, TargetName: name, Directory: filetxn.Metadata{Owner: owner, Mode: 0o700}, Members: []filetxn.DirectoryMember{{Name: "certificate.pem", Data: certificateRaw, Owner: owner, Mode: 0o600, Maximum: 1 << 20}, {Name: "identity.json", Data: identityRaw, Owner: owner, Mode: 0o600, Maximum: 64 << 10}, {Name: "private-key.pem", Data: privateRaw, Owner: owner, Mode: 0o600, Maximum: 1 << 20}}}
	if _, err := filetxn.VerifyDirectory(request); err != nil {
		return Identity{}, err
	}
	return identity, nil
}

func readCertificateBundle(parent, name string, owner filetxn.Owner) (map[string][]byte, error) {
	current, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(current) }()
	for _, component := range strings.Split(strings.TrimPrefix(parent, "/"), "/") {
		next, openErr := unix.Openat(current, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			return nil, openErr
		}
		_ = unix.Close(current)
		current = next
	}
	var parentStat unix.Stat_t
	if err := unix.Fstat(current, &parentStat); err != nil || parentStat.Mode&unix.S_IFMT != unix.S_IFDIR || parentStat.Mode&0o7777 != 0o700 || parentStat.Uid != 0 || parentStat.Gid != 0 {
		return nil, fmt.Errorf("certificate bundle parent metadata is unsafe: %w", err)
	}
	directory, err := unix.Openat(current, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(directory) }()
	var beforeDirectory unix.Stat_t
	if err := unix.Fstat(directory, &beforeDirectory); err != nil || beforeDirectory.Mode&unix.S_IFMT != unix.S_IFDIR || beforeDirectory.Mode&0o7777 != 0o700 || beforeDirectory.Uid != owner.UID || beforeDirectory.Gid != owner.GID {
		return nil, fmt.Errorf("certificate bundle directory metadata is unsafe: %w", err)
	}
	entries, err := os.ReadDir(fmt.Sprintf("/proc/self/fd/%d", directory))
	if err != nil {
		return nil, err
	}
	expected := map[string]int64{"certificate.pem": 1 << 20, "identity.json": 64 << 10, "private-key.pem": 1 << 20}
	if len(entries) != len(expected) {
		return nil, fmt.Errorf("certificate bundle inventory is incomplete or contains foreign members")
	}
	for _, entry := range entries {
		if _, present := expected[entry.Name()]; !present {
			return nil, fmt.Errorf("certificate bundle contains foreign member %q", entry.Name())
		}
	}
	result := make(map[string][]byte, len(expected))
	for _, name := range []string{"certificate.pem", "identity.json", "private-key.pem"} {
		maximum := expected[name]
		fd, openErr := unix.Openat(directory, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			return nil, openErr
		}
		var before, after unix.Stat_t
		if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&0o7777 != 0o600 || before.Uid != owner.UID || before.Gid != owner.GID || before.Nlink != 1 || before.Size <= 0 || before.Size > maximum {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("certificate bundle member %q metadata is unsafe", name)
		}
		file := os.NewFile(uintptr(fd), name)
		if file == nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("wrap certificate bundle member %q", name)
		}
		data, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
		statErr := unix.Fstat(fd, &after)
		closeErr := file.Close()
		if readErr != nil || statErr != nil || closeErr != nil || int64(len(data)) != before.Size || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
			return nil, fmt.Errorf("certificate bundle member %q changed while reading: %w", name, errors.Join(readErr, statErr, closeErr))
		}
		result[name] = data
	}
	var afterDirectory unix.Stat_t
	if err := unix.Fstat(directory, &afterDirectory); err != nil || beforeDirectory.Dev != afterDirectory.Dev || beforeDirectory.Ino != afterDirectory.Ino || beforeDirectory.Mtim != afterDirectory.Mtim || beforeDirectory.Ctim != afterDirectory.Ctim {
		return nil, fmt.Errorf("certificate bundle directory changed while reading: %w", err)
	}
	return result, nil
}

func ValidateIdentity(identity Identity) error {
	if identity.SchemaVersion != SchemaVersion || identity.ID == "" || identity.Generation == 0 || len(identity.Domains) == 0 || !digest(identity.SANIdentity) || !digest(identity.Fingerprint) || !digest(identity.ChainIdentity) || !digest(identity.IssuerIdentity) || !digest(identity.BindingIdentity) || !cleanAbsolute(identity.CertificatePath) || !cleanAbsolute(identity.PrivateKeyPath) || identity.LastTrustedWall.IsZero() || identity.NotBefore.IsZero() || !identity.NotAfter.After(identity.NotBefore) || !digest(identity.DirectoryIdentity) || identity.DirectoryIdentity != identityDigest(identity) {
		return fmt.Errorf("certificate bundle identity incomplete")
	}
	return nil
}

func identityDigest(identity Identity) string {
	copy := identity
	copy.DirectoryIdentity = ""
	raw, _ := json.Marshal(copy)
	return sum(raw)
}

type inspectedBundleMaterial struct {
	certificates   []*x509.Certificate
	privateKey     crypto.Signer
	domains        []string
	fingerprint    string
	chainIdentity  string
	issuerIdentity string
	notBefore      time.Time
	notAfter       time.Time
}

func verifyBundleMaterial(base string, identity Identity, certificatePEM, privateKeyPEM []byte) error {
	if !cleanAbsolute(base) || identity.CertificatePath != filepath.Join(base, "certificate.pem") || identity.PrivateKeyPath != filepath.Join(base, "private-key.pem") {
		return fmt.Errorf("certificate bundle material paths differ from identity")
	}
	material, err := inspectBundleMaterial(certificatePEM, privateKeyPEM)
	if err != nil {
		return fmt.Errorf("certificate bundle material invalid: %w", err)
	}
	if !slices.Equal(material.domains, identity.Domains) || identity.SANIdentity != sum([]byte(strings.Join(material.domains, "\x00"))) || identity.Fingerprint != material.fingerprint || identity.ChainIdentity != material.chainIdentity || identity.IssuerIdentity != material.issuerIdentity || !identity.NotBefore.Equal(material.notBefore) || !identity.NotAfter.Equal(material.notAfter) {
		return fmt.Errorf("certificate bundle material differs from identity")
	}
	return nil
}

func inspectBundleMaterial(certificatePEM, privateKeyPEM []byte) (inspectedBundleMaterial, error) {
	certificates, err := parseCertificateChain(certificatePEM)
	if err != nil || len(certificates) < 2 {
		return inspectedBundleMaterial{}, fmt.Errorf("certificate chain invalid")
	}
	seen := make(map[string]bool, len(certificates))
	for index, certificate := range certificates {
		fingerprint := sum(certificate.Raw)
		if seen[fingerprint] {
			return inspectedBundleMaterial{}, fmt.Errorf("certificate chain duplicates identity")
		}
		seen[fingerprint] = true
		if index+1 < len(certificates) {
			issuer := certificates[index+1]
			if !issuer.IsCA || certificate.CheckSignatureFrom(issuer) != nil {
				return inspectedBundleMaterial{}, fmt.Errorf("certificate chain order or signature invalid")
			}
		}
	}
	leaf := certificates[0]
	domains, err := validateDomains(leaf.DNSNames)
	if err != nil || len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.URIs) != 0 {
		return inspectedBundleMaterial{}, fmt.Errorf("certificate SAN material invalid")
	}
	privateKey, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return inspectedBundleMaterial{}, err
	}
	if !publicKeysEqual(leaf.PublicKey, privateKey.Public()) {
		return inspectedBundleMaterial{}, fmt.Errorf("certificate private key mismatch")
	}
	issuerFingerprints := make([]string, 0, len(certificates)-1)
	for _, certificate := range certificates[1:] {
		issuerFingerprints = append(issuerFingerprints, sum(certificate.Raw))
	}
	return inspectedBundleMaterial{
		certificates:   certificates,
		privateKey:     privateKey,
		domains:        domains,
		fingerprint:    sum(leaf.Raw),
		chainIdentity:  sum(certificatePEM),
		issuerIdentity: sum([]byte(strings.Join(issuerFingerprints, "\x00"))),
		notBefore:      leaf.NotBefore.UTC(),
		notAfter:       leaf.NotAfter.UTC(),
	}, nil
}

func parseCertificateChain(value []byte) ([]*x509.Certificate, error) {
	remaining := value
	result := []*x509.Certificate{}
	for len(bytes.TrimSpace(remaining)) != 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("certificate PEM invalid")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		result = append(result, certificate)
		remaining = rest
	}
	return result, nil
}

func parsePrivateKey(value []byte) (crypto.Signer, error) {
	block, rest := pem.Decode(value)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("private key PEM invalid")
	}
	var parsed any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("private key PEM type invalid")
	}
	signer, ok := parsed.(crypto.Signer)
	if err != nil || !ok {
		return nil, fmt.Errorf("private key invalid")
	}
	return signer, nil
}

func publicKeysEqual(left, right crypto.PublicKey) bool {
	a, errA := x509.MarshalPKIXPublicKey(left)
	b, errB := x509.MarshalPKIXPublicKey(right)
	return errA == nil && errB == nil && bytes.Equal(a, b)
}

func validateDomains(values []string) ([]string, error) {
	result := canonicalDomains(values)
	if len(result) == 0 || len(result) != len(values) {
		return nil, fmt.Errorf("certificate domains invalid")
	}
	for _, value := range result {
		if value == "" || len(value) > 253 || strings.ContainsAny(value, "/\\\x00\r\n ") {
			return nil, fmt.Errorf("certificate domain invalid")
		}
	}
	return result, nil
}

func canonicalDomains(values []string) []string {
	result := append([]string(nil), values...)
	for i := range result {
		result[i] = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(result[i]), "."))
	}
	slices.Sort(result)
	return slices.Compact(result)
}

func sum(data []byte) string {
	value := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(value[:])
}

func digest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil
}

func cleanAbsolute(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && value != "/"
}
