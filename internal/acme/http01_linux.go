//go:build linux

package acme

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
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/acmeaccount"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	xacme "golang.org/x/crypto/acme"
	"golang.org/x/sys/unix"
)

// HTTP01Presentation is the exact CA-selected presentation handed to the
// durable challenge coordinator. KeyAuthorization is written only to the
// operation-owned webroot; durable state stores its digest.
type HTTP01Presentation struct {
	Host                   string
	Token                  string
	TokenPath              string
	KeyAuthorization       string
	KeyAuthorizationDigest string
}

// HTTP01Presenter synchronously acknowledges presentation only after the exact
// route is durable and active, and cleanup only after that route is gone.
type HTTP01Presenter interface {
	PresentHTTP01(context.Context, HTTP01Presentation) error
	CleanUpHTTP01(context.Context, HTTP01Presentation) error
}

func RunHTTP01(ctx context.Context, request IssueRequest, presenter HTTP01Presenter) (IssueResult, error) {
	return runHTTP01(ctx, request, presenter, writeHTTP01Issued, nil, loadHTTP01AccountKey)
}

func runHTTP01(ctx context.Context, request IssueRequest, presenter HTTP01Presenter, writeIssued func(IssueRequest, *ecdsa.PrivateKey, [][]byte) error, httpClient *http.Client, loadAccountKey func(Binding) (*ecdsa.PrivateKey, error)) (IssueResult, error) {
	if presenter == nil || writeIssued == nil || loadAccountKey == nil || request.Binding.Method != ChallengeHTTP01 || request.CertificateID == "" || len(request.Domains) == 0 || request.UID == 0 || request.GID == 0 {
		return IssueResult{}, fmt.Errorf("HTTP-01 issue authority incomplete")
	}
	if err := ValidateBinding(request.Binding); err != nil {
		return IssueResult{}, err
	}
	domains := append([]string(nil), request.Domains...)
	slices.Sort(domains)
	if !slices.Equal(domains, request.Domains) {
		return IssueResult{}, fmt.Errorf("HTTP-01 SAN inventory is noncanonical")
	}
	accountKey, err := loadAccountKey(request.Binding)
	if err != nil {
		return IssueResult{}, err
	}
	client := &xacme.Client{Key: accountKey, DirectoryURL: request.Binding.DirectoryURL, UserAgent: "LanPanel HTTP-01", HTTPClient: httpClient}
	account, err := client.GetReg(ctx, "")
	if errors.Is(err, xacme.ErrNoAccount) {
		account, err = client.Register(ctx, &xacme.Account{Contact: []string{"mailto:" + request.Binding.AccountEmail}}, xacme.AcceptTOS)
		if errors.Is(err, xacme.ErrAccountAlreadyExists) {
			account, err = client.GetReg(ctx, "")
		}
	}
	if err != nil || account == nil || account.Status != "" && account.Status != xacme.StatusValid {
		return IssueResult{}, fmt.Errorf("HTTP-01 account authority unavailable: %w", err)
	}
	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs(domains...))
	if err != nil {
		return IssueResult{}, err
	}
	if !exactHTTP01OrderIdentifiers(order.Identifiers, domains) {
		return IssueResult{}, fmt.Errorf("ACME order identifiers changed")
	}
	if order.Status != xacme.StatusPending && order.Status != xacme.StatusReady {
		return IssueResult{}, fmt.Errorf("HTTP-01 order entered unexpected status %q", order.Status)
	}
	allowed := make(map[string]bool, len(domains))
	for _, domain := range domains {
		allowed[domain] = true
	}
	seen := map[string]bool{}
	for _, authorizationURL := range order.AuthzURLs {
		authorization, err := client.GetAuthorization(ctx, authorizationURL)
		if err != nil {
			return IssueResult{}, err
		}
		host := authorization.Identifier.Value
		if authorization.Identifier.Type != "dns" || authorization.Wildcard || !allowed[host] || seen[host] {
			return IssueResult{}, fmt.Errorf("HTTP-01 authorization Host is outside the exact SAN inventory")
		}
		seen[host] = true
		if authorization.Status == xacme.StatusValid {
			continue
		}
		if authorization.Status != xacme.StatusPending {
			return IssueResult{}, fmt.Errorf("HTTP-01 authorization entered unexpected status %q", authorization.Status)
		}
		var selected *xacme.Challenge
		for _, candidate := range authorization.Challenges {
			if candidate.Type == "http-01" {
				if selected != nil {
					return IssueResult{}, fmt.Errorf("HTTP-01 authorization offered duplicate challenge types")
				}
				selected = candidate
			}
		}
		if selected == nil {
			return IssueResult{}, fmt.Errorf("HTTP-01 authorization omitted its challenge")
		}
		keyAuthorization, err := client.HTTP01ChallengeResponse(selected.Token)
		if err != nil {
			return IssueResult{}, err
		}
		presentation := NewHTTP01Presentation(host, selected.Token, keyAuthorization)
		if err := ValidateHTTP01Presentation(presentation); err != nil {
			return IssueResult{}, err
		}
		if err := presenter.PresentHTTP01(ctx, presentation); err != nil {
			return IssueResult{}, err
		}
		_, acceptErr := client.Accept(ctx, selected)
		if acceptErr == nil {
			_, acceptErr = client.WaitAuthorization(ctx, authorization.URI)
		}
		cleanupCtx, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		cleanupErr := presenter.CleanUpHTTP01(cleanupCtx, presentation)
		cancelCleanup()
		if err := errors.Join(acceptErr, cleanupErr); err != nil {
			return IssueResult{}, err
		}
	}
	if len(seen) != len(domains) {
		return IssueResult{}, fmt.Errorf("ACME authorization inventory changed")
	}
	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil || order.Status != xacme.StatusReady && order.Status != xacme.StatusValid {
		return IssueResult{}, fmt.Errorf("HTTP-01 order did not become ready: %w", err)
	}
	certificateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return IssueResult{}, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: domains[0]}, DNSNames: domains}, certificateKey)
	if err != nil {
		return IssueResult{}, err
	}
	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return IssueResult{}, err
	}
	if len(chain) < 2 {
		return IssueResult{}, fmt.Errorf("HTTP-01 CA returned an incomplete certificate chain")
	}
	if err := writeIssued(request, certificateKey, chain); err != nil {
		return IssueResult{}, err
	}
	var identity bytes.Buffer
	for _, certificate := range chain {
		identity.Write(certificate)
	}
	stdout := sha256.Sum256(identity.Bytes())
	stderr := sha256.Sum256([]byte("lanpanel-http-01-complete"))
	return IssueResult{StdoutDigest: "sha256:" + hex.EncodeToString(stdout[:]), StderrDigest: "sha256:" + hex.EncodeToString(stderr[:])}, nil
}

func exactHTTP01OrderIdentifiers(identifiers []xacme.AuthzID, domains []string) bool {
	if len(identifiers) != len(domains) || len(domains) == 0 {
		return false
	}
	values := make([]string, len(identifiers))
	for index, identifier := range identifiers {
		if identifier.Type != "dns" || identifier.Value == "" {
			return false
		}
		values[index] = identifier.Value
	}
	slices.Sort(values)
	return slices.Equal(values, domains)
}

func NewHTTP01Presentation(host, token, keyAuthorization string) HTTP01Presentation {
	digest := sha256.Sum256([]byte(keyAuthorization))
	return HTTP01Presentation{Host: host, Token: token, TokenPath: "/.well-known/acme-challenge/" + token, KeyAuthorization: keyAuthorization, KeyAuthorizationDigest: "sha256:" + hex.EncodeToString(digest[:])}
}

func ValidateHTTP01Presentation(value HTTP01Presentation) error {
	if !validHTTP01Token(value.Token) || value.TokenPath != "/.well-known/acme-challenge/"+value.Token || value.Host == "" || strings.ToLower(value.Host) != value.Host || strings.ContainsAny(value.Host, "\x00\r\n /:") || value.KeyAuthorization == "" || len(value.KeyAuthorization) > 4096 {
		return fmt.Errorf("HTTP-01 presentation is invalid")
	}
	digest := sha256.Sum256([]byte(value.KeyAuthorization))
	if value.KeyAuthorizationDigest != "sha256:"+hex.EncodeToString(digest[:]) {
		return fmt.Errorf("HTTP-01 key authorization digest changed")
	}
	return nil
}

func WriteHTTP01Token(certificateID string, uid, gid uint32, presentation HTTP01Presentation) error {
	if !certificateIDPattern(certificateID) || uid == 0 || gid == 0 || ValidateHTTP01Presentation(presentation) != nil {
		return fmt.Errorf("HTTP-01 token write authority invalid")
	}
	return writeHTTP01TokenAt(filepath.Join("/var/lib/lanpanel/certificates/webroot", certificateID), uid, gid, presentation)
}

func writeHTTP01TokenAt(root string, uid, gid uint32, presentation HTTP01Presentation) error {
	rootFD, err := openDirectoryPathNoFollow(root)
	if err != nil {
		return fmt.Errorf("HTTP-01 webroot identity invalid: %w", err)
	}
	if err := validateHTTP01WebrootFD(rootFD, uid, gid); err != nil {
		_ = unix.Close(rootFD)
		return err
	}
	wellKnownFD, err := ensureHTTP01DirectoryAt(rootFD, ".well-known", uid, gid, 0o711)
	if err != nil {
		_ = unix.Close(rootFD)
		return err
	}
	challengeFD, err := ensureHTTP01DirectoryAt(wellKnownFD, "acme-challenge", uid, gid, 0o711)
	if err != nil {
		_ = unix.Close(wellKnownFD)
		_ = unix.Close(rootFD)
		return err
	}
	defer func() {
		_ = unix.Close(challengeFD)
		_ = unix.Close(wellKnownFD)
		_ = unix.Close(rootFD)
	}()
	fd, err := unix.Openat(challengeFD, presentation.Token, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), presentation.Token)
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("HTTP-01 token descriptor unavailable")
	}
	writeErr := writeFull(file, []byte(presentation.KeyAuthorization))
	ownerErr := file.Chown(int(uid), int(gid))
	modeErr := file.Chmod(0o644)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, ownerErr, modeErr, syncErr, closeErr); err != nil {
		_ = unix.Unlinkat(challengeFD, presentation.Token, 0)
		return err
	}
	return unix.Fsync(challengeFD)
}

func VerifyHTTP01Token(certificateID string, uid, gid uint32, presentation HTTP01Presentation) error {
	if !certificateIDPattern(certificateID) || uid == 0 || gid == 0 || ValidateHTTP01Presentation(presentation) != nil {
		return fmt.Errorf("HTTP-01 token verification authority invalid")
	}
	return verifyHTTP01TokenAt(filepath.Join("/var/lib/lanpanel/certificates/webroot", certificateID), uid, gid, presentation)
}

// VerifyHTTP01TokenDigest proves a recovered exact token file against durable
// authority without requiring the plaintext key authorization to be persisted.
func VerifyHTTP01TokenDigest(certificateID string, uid, gid uint32, token, keyAuthorizationDigest string) error {
	if !certificateIDPattern(certificateID) || uid == 0 || gid == 0 || !validHTTP01Token(token) || !validHTTP01Digest(keyAuthorizationDigest) {
		return fmt.Errorf("HTTP-01 recovered token authority invalid")
	}
	root := filepath.Join("/var/lib/lanpanel/certificates/webroot", certificateID)
	return verifyHTTP01TokenDigestAt(root, uid, gid, token, keyAuthorizationDigest)
}

func verifyHTTP01TokenAt(root string, uid, gid uint32, presentation HTTP01Presentation) error {
	return verifyHTTP01TokenDigestAt(root, uid, gid, presentation.Token, presentation.KeyAuthorizationDigest)
}

func verifyHTTP01TokenDigestAt(root string, uid, gid uint32, token, keyAuthorizationDigest string) error {
	rootFD, wellKnownFD, challengeFD, err := openHTTP01ChallengeDirectories(root, uid, gid)
	if err != nil {
		return err
	}
	defer func() {
		_ = unix.Close(challengeFD)
		_ = unix.Close(wellKnownFD)
		_ = unix.Close(rootFD)
	}()
	return verifyHTTP01TokenFD(challengeFD, uid, gid, token, keyAuthorizationDigest)
}

func verifyHTTP01TokenFD(challengeFD int, uid, gid uint32, token, keyAuthorizationDigest string) error {
	fd, err := unix.Openat(challengeFD, token, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), token)
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("HTTP-01 token descriptor unavailable")
	}
	defer func() { _ = file.Close() }()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uid || stat.Gid != gid || stat.Mode&0o7777 != 0o644 || stat.Size <= 0 || stat.Size > 4096 {
		return fmt.Errorf("HTTP-01 token file identity is invalid")
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	digest := sha256.Sum256(data)
	if err != nil || len(data) > 4096 || keyAuthorizationDigest != "sha256:"+hex.EncodeToString(digest[:]) {
		return fmt.Errorf("HTTP-01 token file content changed")
	}
	var after unix.Stat_t
	if unix.Fstat(fd, &after) != nil || stat.Dev != after.Dev || stat.Ino != after.Ino || stat.Size != after.Size || stat.Mtim != after.Mtim {
		return fmt.Errorf("HTTP-01 token file changed during verification")
	}
	return nil
}

func RemoveHTTP01Token(certificateID string, uid, gid uint32, presentation HTTP01Presentation) error {
	if !certificateIDPattern(certificateID) || uid == 0 || gid == 0 || ValidateHTTP01Presentation(presentation) != nil {
		return fmt.Errorf("HTTP-01 token cleanup authority invalid")
	}
	return removeHTTP01TokenAt(filepath.Join("/var/lib/lanpanel/certificates/webroot", certificateID), uid, gid, presentation)
}

func removeHTTP01TokenAt(root string, uid, gid uint32, presentation HTTP01Presentation) (resultErr error) {
	rootFD, err := openDirectoryPathNoFollow(root)
	if err != nil {
		return fmt.Errorf("HTTP-01 webroot identity invalid: %w", err)
	}
	defer func() { _ = unix.Close(rootFD) }()
	if err := validateHTTP01WebrootFD(rootFD, uid, gid); err != nil {
		return err
	}
	rootSeal, err := sealDirectory(rootFD)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, restoreDirectorySeal(rootFD, rootSeal)) }()

	wellKnownFD, err := openDirectoryAtNoFollow(rootFD, ".well-known")
	if err != nil {
		return fmt.Errorf("HTTP-01 challenge directory unsafe: %w", err)
	}
	defer func() { _ = unix.Close(wellKnownFD) }()
	if err := validateHTTP01ChallengeDirectoryFD(wellKnownFD, uid, gid); err != nil {
		return err
	}
	wellKnownSeal, err := sealDirectory(wellKnownFD)
	if err != nil {
		return err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, restoreDirectorySeal(wellKnownFD, wellKnownSeal))
		}
	}()

	challengeFD, err := openDirectoryAtNoFollow(wellKnownFD, "acme-challenge")
	if err != nil {
		return fmt.Errorf("HTTP-01 challenge directory unsafe: %w", err)
	}
	defer func() { _ = unix.Close(challengeFD) }()
	if err := validateHTTP01ChallengeDirectoryFD(challengeFD, uid, gid); err != nil {
		return err
	}
	challengeSeal, err := sealDirectory(challengeFD)
	if err != nil {
		return err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, restoreDirectorySeal(challengeFD, challengeSeal))
		}
	}()
	if err := verifyHTTP01TokenFD(challengeFD, uid, gid, presentation.Token, presentation.KeyAuthorizationDigest); err != nil {
		return err
	}
	if err := unix.Unlinkat(challengeFD, presentation.Token, 0); err != nil {
		return err
	}
	if err := unix.Fsync(challengeFD); err != nil {
		return err
	}
	entries, err := readDirectoryFD(challengeFD)
	if err != nil || len(entries) != 0 {
		return errors.Join(err, fmt.Errorf("HTTP-01 token directory is not empty after exact cleanup"))
	}
	if err := unix.Unlinkat(wellKnownFD, "acme-challenge", unix.AT_REMOVEDIR); err != nil {
		return err
	}
	entries, err = readDirectoryFD(wellKnownFD)
	if err != nil || len(entries) != 0 {
		return errors.Join(err, fmt.Errorf("HTTP-01 challenge parent is not empty after exact cleanup"))
	}
	if err := unix.Unlinkat(rootFD, ".well-known", unix.AT_REMOVEDIR); err != nil {
		return err
	}
	if err := restoreDirectorySeal(rootFD, rootSeal); err != nil {
		return err
	}
	return unix.Fsync(rootFD)
}

func loadHTTP01AccountKey(binding Binding) (*ecdsa.PrivateKey, error) {
	input, err := openProtected(binding.AccountKeyPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = input.Close() }()
	data, err := io.ReadAll(io.LimitReader(input, acmeaccount.MaximumKeyBytes+1))
	if err != nil || len(data) > acmeaccount.MaximumKeyBytes {
		return nil, fmt.Errorf("HTTP-01 account key read failed: %w", err)
	}
	fingerprint, err := acmeaccount.Fingerprint(data)
	if err != nil || fingerprint != binding.AccountKeyFingerprint {
		return nil, fmt.Errorf("HTTP-01 account key identity changed")
	}
	block, _ := pem.Decode(data)
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func writeHTTP01Issued(request IssueRequest, key *ecdsa.PrivateKey, chain [][]byte) error {
	base := filepath.Join(request.Chroot, "work", "certificates")
	if request.Chroot != "/var/lib/lanpanel/certificates/chroot/"+request.CertificateID || filepath.Clean(base) != base {
		return fmt.Errorf("HTTP-01 certificate output authority invalid")
	}
	return writeHTTP01IssuedAt(request, key, chain, request.Chroot)
}

func writeHTTP01IssuedAt(request IssueRequest, key *ecdsa.PrivateKey, chain [][]byte, outputRoot string) error {
	base := filepath.Join(outputRoot, "work", "certificates")
	if filepath.Clean(base) != base || outputRoot == "" {
		return fmt.Errorf("HTTP-01 certificate output authority invalid")
	}
	if err := ensureStageDirectory(base, request.UID, request.GID); err != nil {
		return err
	}
	var leaf, issuer bytes.Buffer
	if err := pem.Encode(&leaf, &pem.Block{Type: "CERTIFICATE", Bytes: chain[0]}); err != nil {
		return err
	}
	for _, certificate := range chain[1:] {
		if err := pem.Encode(&issuer, &pem.Block{Type: "CERTIFICATE", Bytes: certificate}); err != nil {
			return err
		}
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	name := request.Domains[0]
	for _, output := range []struct {
		suffix string
		data   []byte
		mode   os.FileMode
	}{{".crt", leaf.Bytes(), 0o644}, {".issuer.crt", issuer.Bytes(), 0o644}, {".key", privateKey, 0o600}} {
		if err := writeOwnedStageFile(filepath.Join(base, name+output.suffix), output.data, output.mode, request.UID, request.GID); err != nil {
			return err
		}
	}
	return syncDirectory(base)
}

func writeOwnedStageFile(path string, data []byte, mode os.FileMode, uid, gid uint32) error {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode))
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("HTTP-01 output descriptor unavailable")
	}
	writeErr := writeFull(file, data)
	ownerErr := file.Chown(int(uid), int(gid))
	modeErr := file.Chmod(mode)
	syncErr := file.Sync()
	closeErr := file.Close()
	return errors.Join(writeErr, ownerErr, modeErr, syncErr, closeErr)
}

func ensureHTTP01DirectoryAt(parentFD int, name string, uid, gid uint32, mode uint32) (int, error) {
	if err := unix.Mkdirat(parentFD, name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return -1, err
	}
	fd, err := openDirectoryAtNoFollow(parentFD, name)
	if err != nil {
		return -1, err
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o022 != 0 {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("ACME stage directory unsafe")
	}
	if err := unix.Fchown(fd, int(uid), int(gid)); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	if err := unix.Fchmod(fd, mode); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func openHTTP01ChallengeDirectories(root string, uid, gid uint32) (rootFD, wellKnownFD, challengeFD int, err error) {
	rootFD, err = openDirectoryPathNoFollow(root)
	if err != nil {
		return -1, -1, -1, fmt.Errorf("HTTP-01 webroot identity invalid: %w", err)
	}
	if err = validateHTTP01WebrootFD(rootFD, uid, gid); err != nil {
		_ = unix.Close(rootFD)
		return -1, -1, -1, err
	}
	wellKnownFD, err = openDirectoryAtNoFollow(rootFD, ".well-known")
	if err != nil {
		_ = unix.Close(rootFD)
		return -1, -1, -1, fmt.Errorf("HTTP-01 challenge directory unsafe: %w", err)
	}
	if err = validateHTTP01ChallengeDirectoryFD(wellKnownFD, uid, gid); err != nil {
		_ = unix.Close(wellKnownFD)
		_ = unix.Close(rootFD)
		return -1, -1, -1, err
	}
	challengeFD, err = openDirectoryAtNoFollow(wellKnownFD, "acme-challenge")
	if err != nil {
		_ = unix.Close(wellKnownFD)
		_ = unix.Close(rootFD)
		return -1, -1, -1, fmt.Errorf("HTTP-01 challenge directory unsafe: %w", err)
	}
	if err = validateHTTP01ChallengeDirectoryFD(challengeFD, uid, gid); err != nil {
		_ = unix.Close(challengeFD)
		_ = unix.Close(wellKnownFD)
		_ = unix.Close(rootFD)
		return -1, -1, -1, err
	}
	return rootFD, wellKnownFD, challengeFD, nil
}

func validateACMEWebrootFD(fd int, uid, gid uint32) error {
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("ACME webroot identity invalid")
	}
	if stat.Uid != uid || stat.Gid != gid {
		return fmt.Errorf("ACME webroot owner changed")
	}
	return nil
}

func validateHTTP01WebrootFD(fd int, uid, gid uint32) error {
	if err := validateACMEWebrootFD(fd, uid, gid); err != nil {
		return fmt.Errorf("HTTP-01 webroot identity invalid: %w", err)
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&0o777 != 0o711 {
		return fmt.Errorf("HTTP-01 webroot identity invalid")
	}
	return nil
}

func validateHTTP01ChallengeDirectoryFD(fd int, uid, gid uint32) error {
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o022 != 0 {
		return fmt.Errorf("ACME challenge directory unsafe")
	}
	if stat.Uid != uid || stat.Gid != gid {
		return fmt.Errorf("ACME challenge directory owner changed")
	}
	return nil
}

func validHTTP01Digest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func validHTTP01Token(value string) bool {
	if len(value) < 20 || len(value) > 256 {
		return false
	}
	for _, character := range value {
		letter := character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z'
		digit := character >= '0' && character <= '9'
		if !letter && !digit && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
