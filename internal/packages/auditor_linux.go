//go:build linux

package packages

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	cgroupfs "lanpanel/internal/cgroup"
	"lanpanel/internal/child"
	"lanpanel/internal/filetxn"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
	"golang.org/x/sys/unix"
)

type LinuxAuditor struct {
	launcher        ChildLauncher
	aptRoot         string
	aptListsRoot    string
	dpkgRoot        string
	transactionRoot string
	cgroupRoot      string
	procRoot        string
	policyPath      string
	binaryPath      string
	maskRoot        string
	strict          bool
}

func NewLinuxAuditor(launcher ChildLauncher) (*LinuxAuditor, error) {
	if launcher == nil {
		return nil, fmt.Errorf("package auditor requires the typed child launcher")
	}
	procRoot := filepath.Join("/proc", strconv.Itoa(os.Getpid()), "net")
	topology, err := cgroupfs.Discover()
	if err != nil {
		return nil, fmt.Errorf("package auditor requires a unified cgroup v2 hierarchy: %w", err)
	}
	if topology.Root != "/" {
		return nil, fmt.Errorf("package auditor requires a cgroup v2 hierarchy rooted at /")
	}
	cgroupRoot := filepath.Join(topology.Mountpoint, "system.slice")
	paths := []string{"/etc/apt", "/etc/dpkg", "/usr/share/keyrings", "/var/lib/apt/lists", "/var/lib/dpkg", cgroupRoot, procRoot, "/usr/sbin", filepath.Dir(child.FixedLanPanelExecutable), FixedSystemdMaskDirectory}
	for _, path := range paths {
		if err := validateAuditorParent(path); err != nil {
			return nil, err
		}
	}
	return &LinuxAuditor{launcher: launcher, aptRoot: "/etc/apt", aptListsRoot: "/var/lib/apt/lists", dpkgRoot: "/var/lib/dpkg", transactionRoot: FixedPackageTransactionRoot, cgroupRoot: cgroupRoot, procRoot: procRoot, policyPath: "/usr/sbin/policy-rc.d", binaryPath: child.FixedLanPanelExecutable, maskRoot: FixedSystemdMaskDirectory, strict: true}, nil
}

func newTestLinuxAuditor(launcher ChildLauncher, root string) *LinuxAuditor {
	return &LinuxAuditor{launcher: launcher, aptRoot: filepath.Join(root, "etc/apt"), aptListsRoot: filepath.Join(root, "var/lib/apt/lists"), dpkgRoot: filepath.Join(root, "var/lib/dpkg"), transactionRoot: filepath.Join(root, "var/lib/lanpanel/packages/transactions"), cgroupRoot: filepath.Join(root, "cgroup"), procRoot: filepath.Join(root, "proc"), policyPath: filepath.Join(root, "usr/sbin/policy-rc.d"), binaryPath: filepath.Join(root, "usr/lib/lanpanel/lanpanel"), maskRoot: filepath.Join(root, "etc/systemd/system")}
}

func (auditor *LinuxAuditor) LockRepositoryMetadata(ctx context.Context, wait time.Duration) (func(), error) {
	if auditor == nil || auditor.aptListsRoot == "" || wait <= 0 {
		return nil, fmt.Errorf("APT repository metadata lock authority is invalid")
	}
	directory, err := openSafeDirectory(auditor.aptListsRoot, auditor.strict)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Openat(directory, "lock", unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	_ = unix.Close(directory)
	if err != nil {
		return nil, fmt.Errorf("open APT repository metadata lock: %w", err)
	}
	owner, group := uint32(0), uint32(0)
	if !auditor.strict {
		owner, group = uint32(os.Geteuid()), uint32(os.Getegid())
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != owner || stat.Gid != group || stat.Mode&0o022 != 0 {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("APT repository metadata lock identity is unsafe")
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	for {
		lock := unix.Flock_t{Type: unix.F_WRLCK, Whence: int16(io.SeekStart)}
		err := unix.FcntlFlock(uintptr(fd), unix.F_SETLK, &lock)
		if err == nil {
			return func() {
				unlock := unix.Flock_t{Type: unix.F_UNLCK, Whence: int16(io.SeekStart)}
				_ = unix.FcntlFlock(uintptr(fd), unix.F_SETLK, &unlock)
				_ = unix.Close(fd)
			}, nil
		}
		if !errors.Is(err, unix.EACCES) && !errors.Is(err, unix.EAGAIN) {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("lock APT repository metadata: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = unix.Close(fd)
			return nil, ctx.Err()
		case <-deadline.C:
			_ = unix.Close(fd)
			return nil, fmt.Errorf("APT repository metadata lock wait elapsed")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (auditor *LinuxAuditor) AuditPackages(ctx context.Context, plan Plan) (Audit, error) {
	if auditor == nil || auditor.launcher == nil {
		return Audit{}, fmt.Errorf("package auditor is unavailable")
	}
	configuration, repositories, err := auditor.readConfiguration(ctx, plan)
	if err != nil {
		return Audit{}, err
	}
	dpkg, installed, systemPackages, err := auditor.readDPKG(ctx, plan.Packages)
	if err != nil {
		return Audit{}, err
	}
	runtime, err := auditor.runtimeSnapshot(plan, installed, systemPackages)
	if err != nil {
		return Audit{}, err
	}
	policy, err := auditor.noAutostartPolicy(plan.NoAutostartPolicyDigest)
	if err != nil {
		return Audit{}, err
	}
	if plan.Mode == DistroRepository {
		present, err := auditor.distroCacheNeedsVerification(plan)
		if err != nil {
			return Audit{}, err
		}
		if present {
			if err := auditor.verifyDistroPackageArtifacts(plan, repositories); err != nil {
				return Audit{}, fmt.Errorf("distro package artifact authority is invalid: %w", err)
			}
		}
	}
	return Audit{Configuration: configuration, Repositories: repositories, DPKG: dpkg, Before: runtime, NoAutostart: policy}, nil
}

// PreflightReadiness reuses the exact no-follow APT/dpkg inventory and parser
// used by package execution without starting a child or changing host state.
func (auditor *LinuxAuditor) PreflightReadiness(ctx context.Context, repositories []Repository) (string, error) {
	if auditor == nil || auditor.launcher == nil {
		return "", fmt.Errorf("package auditor is unavailable")
	}
	configuration, observedRepositories, err := auditor.readConfiguration(ctx, Plan{})
	if err != nil {
		return "", err
	}
	if err := ValidateAPTConfigurationBasic(configuration, observedRepositories); err != nil {
		return "", err
	}
	dpkg, _, packages, err := auditor.readDPKG(ctx, nil)
	if err != nil {
		return "", err
	}
	if err := ValidateDPKGReady(dpkg); err != nil {
		return "", err
	}
	identity, err := digestValue(struct {
		Configuration []ObservedConfig
		Repositories  []ObservedRepository
		Packages      []InstalledPackage
	}{configuration, observedRepositories, packages})
	if err != nil {
		return "", err
	}
	return identity, nil
}

func (auditor *LinuxAuditor) ObservePackages(ctx context.Context, plan Plan) (Postcondition, error) {
	repositories, err := auditor.observeAPTAuthority(ctx, plan)
	if err != nil {
		return Postcondition{}, err
	}
	_, installed, systemPackages, err := auditor.readDPKG(ctx, plan.Packages)
	if err != nil {
		return Postcondition{}, err
	}
	if !reflectPackages(installed, plan.Packages) {
		return Postcondition{}, fmt.Errorf("installed package closure differs from the exact Plan")
	}
	if err := auditor.verifyDistroPackageArtifacts(plan, repositories); err != nil {
		return Postcondition{}, err
	}
	runtime, err := auditor.runtimeSnapshot(plan, installed, systemPackages)
	if err != nil {
		return Postcondition{}, err
	}
	postcondition := Postcondition{Repositories: repositories, Installed: installed, SystemPackages: runtime.SystemPackages, Units: runtime.Units, Listeners: runtime.Listeners}
	finalRepositories, err := auditor.observeAPTAuthority(ctx, plan)
	if err != nil {
		return Postcondition{}, err
	}
	postcondition.Repositories = finalRepositories
	return postcondition, nil
}

func (auditor *LinuxAuditor) observeAPTAuthority(ctx context.Context, plan Plan) ([]ObservedRepository, error) {
	configuration, repositories, err := auditor.readConfiguration(ctx, plan)
	if err != nil {
		return nil, err
	}
	if err := ValidateAPTConfiguration(configuration, repositories, plan.Repositories); err != nil {
		return nil, fmt.Errorf("post-transaction APT authority changed: %w", err)
	}
	return repositories, nil
}

func (auditor *LinuxAuditor) VerifyPackageMasks(ctx context.Context, identities []MaskIdentity, present bool) error {
	if !validMaskIdentities(identities) {
		return fmt.Errorf("package mask verification authority is invalid")
	}
	result, err := auditor.launcher.RunInvocation(ctx, child.ProfileSystemctl, child.Invocation{}, nil)
	if err != nil || result.ExitCode != 0 || result.OutputCutOff {
		return fmt.Errorf("systemd daemon-reload did not reach a bounded terminal result")
	}
	for _, identity := range identities {
		path := filepath.Join(auditor.maskRoot, identity.Unit)
		var stat unix.Stat_t
		err := unix.Lstat(path, &stat)
		if present {
			if err != nil || stat.Mode&unix.S_IFMT != unix.S_IFLNK || uint64(stat.Dev) != identity.Device || stat.Ino != identity.Inode || stat.Ctim.Sec != identity.CTimeSec || stat.Ctim.Nsec != identity.CTimeNsec {
				return fmt.Errorf("PID 1 mask identity changed before verification")
			}
			target, err := os.Readlink(path)
			if err != nil || target != "/dev/null" {
				return fmt.Errorf("PID 1 package mask target is invalid")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("transaction-created package mask remains after cleanup")
		}
		active, err := cgroupHasProcesses(filepath.Join(auditor.cgroupRoot, identity.Unit, "cgroup.procs"))
		if err != nil || active {
			return fmt.Errorf("masked package unit is active")
		}
	}
	return nil
}

type repositoryMetadataFile struct {
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	Digest string `json:"digest"`
}

type repositoryPackageEntry struct {
	RepositoryID string
	Component    string
	IndexArch    string
	Name         string
	Version      string
	Architecture string
	Filename     string
	Size         int64
	Digest       string
}

type repositoryReleaseFile struct {
	Bytes  int64
	Digest string
}

const (
	maximumRepositoryMetadataFileBytes = 128 << 20
	maximumRepositoryPackageEntries    = 1 << 20
)

// observeRepositoryMetadata derives repository authority from the signed APT
// metadata actually present in the local lists directory. The Plan is never
// used as a source for either digest: it is only compared later by
// ValidateAPTConfiguration.
func (auditor *LinuxAuditor) observeRepositoryMetadata(ctx context.Context, repositories []ObservedRepository, keyrings map[string][]byte, expectedPackages []Package) error {
	if len(repositories) == 0 {
		return nil
	}
	if auditor == nil || auditor.aptListsRoot == "" {
		return fmt.Errorf("APT repository metadata observer is unavailable")
	}
	listsFD, err := openSafeDirectory(auditor.aptListsRoot, auditor.strict)
	if err != nil {
		return fmt.Errorf("open APT repository metadata directory: %w", err)
	}
	defer func() { _ = unix.Close(listsFD) }()
	entries, err := os.ReadDir(fmt.Sprintf("/proc/self/fd/%d", listsFD))
	if err != nil {
		return fmt.Errorf("enumerate APT repository metadata: %w", err)
	}
	for index := range repositories {
		if err := ctx.Err(); err != nil {
			return err
		}
		prefix, err := aptListRepositoryPrefix(repositories[index].URI, repositories[index].Suite)
		if err != nil {
			return err
		}
		metadata := []repositoryMetadataFile{}
		var release []byte
		for _, entry := range entries {
			if entry.Name() == "lock" || entry.Name() == "partial" || entry.Name() == "auxfiles" && entry.IsDir() {
				continue
			}
			if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
				continue
			}
			path := filepath.Join(auditor.aptListsRoot, entry.Name())
			data, _, err := auditor.readFileAndStat(path, maximumRepositoryMetadataFileBytes)
			if err != nil {
				return fmt.Errorf("read exact APT repository metadata %q: %w", entry.Name(), err)
			}
			metadata = append(metadata, repositoryMetadataFile{Name: entry.Name(), Bytes: int64(len(data)), Digest: digestBytes(data)})
			if entry.Name() == prefix+"InRelease" {
				release = data
			}
		}
		if len(metadata) == 0 || len(release) == 0 {
			return fmt.Errorf("APT repository %q lacks exact signed InRelease metadata", repositories[index].ID)
		}
		plaintext, err := verifyInRelease(release, keyrings[repositories[index].KeyringPath])
		if err != nil {
			return fmt.Errorf("APT repository %q InRelease signature is invalid: %w", repositories[index].ID, err)
		}
		releaseFiles, err := releaseSHA256Files(plaintext)
		if err != nil {
			return fmt.Errorf("read exact APT repository metadata checksums for %q: %w", repositories[index].ID, err)
		}
		if !releaseFieldContainsToken(plaintext, "Architectures", "amd64") {
			return fmt.Errorf("APT repository %q InRelease does not authorize amd64", repositories[index].ID)
		}
		if !releaseSuiteMatches(plaintext, repositories[index].Suite) || !releaseComponentsAuthorize(plaintext, repositories[index].Components) {
			return fmt.Errorf("APT repository %q signed suite or components do not authorize the configured source", repositories[index].ID)
		}
		allArchitectureRequired := releaseFieldContainsToken(plaintext, "Architectures", "all") && !releaseFieldContainsToken(plaintext, "No-Support-for-Architecture-all", "Packages")
		requireIndexes := expectedPackages == nil
		if !requireIndexes {
			for _, pkg := range expectedPackages {
				if pkg.RepositoryID == "" || pkg.RepositoryID == repositories[index].ID {
					requireIndexes = true
					break
				}
			}
		}
		entries := []repositoryPackageEntry{}
		entryByIdentity := map[string]repositoryPackageEntry{}
		for _, component := range repositories[index].Components {
			for _, architecture := range []string{"amd64", "all"} {
				packagePrefix := prefix + aptListPart(component) + "_binary-" + architecture + "_Packages"
				found := false
				canonicalSet := false
				var canonicalPackages []byte
				canonicalName := ""
				for _, packageFile := range metadata {
					if !aptPackageIndexName(packageFile.Name, packagePrefix) {
						continue
					}
					found = true
					suffix := strings.TrimPrefix(packageFile.Name, packagePrefix)
					releasePath := component + "/binary-" + architecture + "/Packages"
					packagesBytes, err := auditor.validateRepositoryPackageIndex(packageFile, suffix, releasePath, releaseFiles)
					if err != nil {
						return fmt.Errorf("APT repository %q package index is not bound by its InRelease metadata: %w", repositories[index].ID, err)
					}
					if !canonicalSet {
						canonicalPackages, canonicalName, canonicalSet = packagesBytes, packageFile.Name, true
					} else if !bytes.Equal(canonicalPackages, packagesBytes) {
						return fmt.Errorf("APT repository %q has conflicting compressed representations for package index %q", repositories[index].ID, packagePrefix)
					}
				}
				if found && expectedPackages != nil {
					parsed, err := parseRepositoryPackageIndex(canonicalPackages, repositories[index].ID, component, architecture)
					if err != nil {
						return fmt.Errorf("APT repository %q package index %q is malformed: %w", repositories[index].ID, canonicalName, err)
					}
					if len(entries)+len(parsed) > maximumRepositoryPackageEntries {
						return fmt.Errorf("APT repository %q contains too many package stanzas", repositories[index].ID)
					}
					if err := appendRepositoryPackageEntries(&entries, entryByIdentity, parsed); err != nil {
						return fmt.Errorf("APT repository %q has conflicting package stanzas: %w", repositories[index].ID, err)
					}
				}
				if !found && requireIndexes && (architecture == "amd64" || allArchitectureRequired) {
					return fmt.Errorf("APT repository %q lacks the exact %s package index for component %q", repositories[index].ID, architecture, component)
				}
			}
		}
		if expectedPackages != nil {
			if err := validateExpectedRepositoryPackages(expectedPackages, repositories[index].ID, repositories, entries); err != nil {
				return fmt.Errorf("APT repository %q package ownership is invalid: %w", repositories[index].ID, err)
			}
		}
		bindings := entries
		if expectedPackages != nil {
			bindings = expectedRepositoryPackageEntries(expectedPackages, repositories[index].ID, repositories, entries)
		}
		repositories[index].PackageBindings = make([]RepositoryPackageBinding, 0, len(bindings))
		for _, entry := range bindings {
			repositories[index].PackageBindings = append(repositories[index].PackageBindings, RepositoryPackageBinding{Name: entry.Name, Version: entry.Version, Architecture: entry.Architecture, Filename: entry.Filename, Size: entry.Size, Digest: entry.Digest})
		}
		metadataDigest := digestBytes(release)
		cutoffDigest, err := repositoryCutoffDigest(plaintext)
		if err != nil {
			return fmt.Errorf("read exact APT repository cutoff for %q: %w", repositories[index].ID, err)
		}
		repositories[index].MetadataDigest = metadataDigest
		repositories[index].CutoffDigest = cutoffDigest
	}
	return nil
}

func verifyInRelease(data, keyring []byte) ([]byte, error) {
	if len(keyring) == 0 {
		return nil, fmt.Errorf("repository keyring is missing")
	}
	if !bytes.HasPrefix(data, []byte("-----BEGIN PGP SIGNED MESSAGE-----")) {
		return nil, fmt.Errorf("InRelease is not an exact clear-signed message")
	}
	block, rest := clearsign.Decode(data)
	if block == nil || block.ArmoredSignature == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("InRelease is not one exact clear-signed message")
	}
	entities, err := openpgp.ReadKeyRing(bytes.NewReader(keyring))
	if err != nil {
		entities, err = openpgp.ReadArmoredKeyRing(bytes.NewReader(keyring))
	}
	if err != nil || len(entities) == 0 {
		return nil, fmt.Errorf("repository keyring cannot verify OpenPGP metadata")
	}
	if _, err := openpgp.CheckDetachedSignature(entities, bytes.NewReader(block.Bytes), block.ArmoredSignature.Body, nil); err != nil {
		return nil, fmt.Errorf("InRelease was not signed by the exact repository keyring")
	}
	return append([]byte(nil), block.Plaintext...), nil
}

func aptListRepositoryPrefix(uri, suite string) (string, error) {
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Host == "" || parsed.Path == "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" || parsed.String() != uri {
		return "", fmt.Errorf("APT repository URI cannot identify local metadata")
	}
	host := parsed.Host
	// APT's URI parser stores an IPv6 host without brackets; URItoFileName
	// clears the access scheme before serialization, so brackets are not added.
	if strings.HasPrefix(host, "[") {
		closing := strings.IndexByte(host, ']')
		if closing < 0 {
			return "", fmt.Errorf("APT repository IPv6 host is malformed")
		}
		host = host[1:closing] + host[closing+1:]
	}
	path := strings.TrimSuffix(parsed.EscapedPath(), "/")
	return aptListPart(host+path) + "_dists_" + aptListPart(suite) + "_", nil
}

func aptPackageIndexName(name, prefix string) bool {
	for _, suffix := range []string{"", ".gz", ".xz", ".bz2", ".lz4", ".zst", ".lzma"} {
		if name == prefix+suffix {
			return true
		}
	}
	return false
}

func (auditor *LinuxAuditor) validateRepositoryPackageIndex(file repositoryMetadataFile, suffix, releasePath string, releaseFiles map[string]repositoryReleaseFile) ([]byte, error) {
	data, _, err := auditor.readFileAndStat(filepath.Join(auditor.aptListsRoot, file.Name), maximumRepositoryMetadataFileBytes)
	if err != nil || int64(len(data)) != file.Bytes || digestBytes(data) != file.Digest {
		return nil, fmt.Errorf("package index changed before verification")
	}
	if suffix != ".lz4" {
		releaseFile, found := releaseFiles[releasePath+suffix]
		if !found {
			return nil, fmt.Errorf("stored package index representation is absent from InRelease")
		}
		if file.Bytes != releaseFile.Bytes || file.Digest != releaseFile.Digest {
			return nil, fmt.Errorf("stored package index differs from its signed compressed identity")
		}
		data, err = decompressRepositoryPackageIndex(data, suffix)
		if err != nil {
			return nil, err
		}
		if releaseFile, found := releaseFiles[releasePath]; found && (int64(len(data)) != releaseFile.Bytes || digestBytes(data) != releaseFile.Digest) {
			return nil, fmt.Errorf("package index content differs from its signed uncompressed identity")
		}
		return data, nil
	}
	if compressed, found := releaseFiles[releasePath+suffix]; found && (file.Bytes != compressed.Bytes || file.Digest != compressed.Digest) {
		return nil, fmt.Errorf("stored LZ4 package index differs from its signed compressed identity")
	}
	releaseFile, found := releaseFiles[releasePath]
	if !found || releaseFile.Bytes < 0 || releaseFile.Bytes > maximumRepositoryMetadataFileBytes {
		return nil, fmt.Errorf("LZ4 package index lacks a bounded signed uncompressed identity")
	}
	data, err = decompressRepositoryPackageIndex(data, suffix)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != releaseFile.Bytes || digestBytes(data) != releaseFile.Digest {
		return nil, fmt.Errorf("LZ4 package index content differs from its signed uncompressed identity")
	}
	return data, nil
}

func decompressRepositoryPackageIndex(data []byte, suffix string) ([]byte, error) {
	var reader io.Reader
	var closeReader func() error
	switch suffix {
	case "":
		reader = bytes.NewReader(data)
	case ".gz":
		gzipReader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("decompress gzip package index: %w", err)
		}
		reader, closeReader = gzipReader, gzipReader.Close
	case ".bz2":
		reader = bzip2.NewReader(bytes.NewReader(data))
	case ".xz":
		xzReader, err := xz.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("decompress XZ package index: %w", err)
		}
		reader = xzReader
	case ".lzma":
		lzmaReader, err := lzma.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("decompress LZMA package index: %w", err)
		}
		reader = lzmaReader
	case ".lz4":
		reader = lz4.NewReader(bytes.NewReader(data))
	case ".zst":
		zstdReader, err := zstd.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("decompress Zstandard package index: %w", err)
		}
		defer zstdReader.Close()
		reader = zstdReader
	default:
		return nil, fmt.Errorf("unsupported package index compression %q", suffix)
	}
	if closeReader != nil {
		defer func() { _ = closeReader() }()
	}
	output, err := io.ReadAll(io.LimitReader(reader, maximumRepositoryMetadataFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read decompressed package index: %w", err)
	}
	if len(output) > maximumRepositoryMetadataFileBytes {
		return nil, fmt.Errorf("decompressed package index exceeds its bound")
	}
	return output, nil
}

func parseRepositoryPackageIndex(data []byte, repositoryID, component, indexArchitecture string) ([]repositoryPackageEntry, error) {
	if component == "" || indexArchitecture != "amd64" && indexArchitecture != "all" {
		return nil, fmt.Errorf("package index authority is incomplete")
	}
	entries := []repositoryPackageEntry{}
	identities := map[string]struct{}{}
	fields := map[string]string{}
	current := ""
	flush := func() error {
		if len(fields) == 0 {
			return nil
		}
		for _, required := range []string{"Package", "Version", "Architecture", "Filename", "Size", "SHA256"} {
			if strings.TrimSpace(fields[required]) == "" {
				return fmt.Errorf("package stanza is missing %s", required)
			}
		}
		name, version, architecture := strings.TrimSpace(fields["Package"]), strings.TrimSpace(fields["Version"]), strings.TrimSpace(fields["Architecture"])
		filename, digest := strings.TrimSpace(fields["Filename"]), strings.TrimSpace(fields["SHA256"])
		if !packageNamePattern.MatchString(name) || !versionPattern.MatchString(version) || moving(version) || architecture != "amd64" && architecture != "all" || indexArchitecture == "all" && architecture != "all" || !validRepositoryFilename(filename) || !digestPattern.MatchString(digest) {
			return fmt.Errorf("package stanza identity is invalid")
		}
		size, err := strconv.ParseInt(strings.TrimSpace(fields["Size"]), 10, 64)
		if err != nil || size <= 0 || size > 4<<30 {
			return fmt.Errorf("package stanza size is invalid")
		}
		key := repositoryPackageKey(name, version, architecture)
		if _, duplicate := identities[key]; duplicate {
			return fmt.Errorf("package stanza is duplicated")
		}
		if len(entries) >= maximumRepositoryPackageEntries {
			return fmt.Errorf("package index contains too many package stanzas")
		}
		identities[key] = struct{}{}
		entries = append(entries, repositoryPackageEntry{RepositoryID: repositoryID, Component: component, IndexArch: indexArchitecture, Name: name, Version: version, Architecture: architecture, Filename: filename, Size: size, Digest: digest})
		fields = map[string]string{}
		current = ""
		return nil
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 32<<10), 2<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasSuffix(line, "\r") {
			return nil, fmt.Errorf("package index contains CRLF data")
		}
		if line == "" {
			if err := flush(); err != nil {
				return nil, err
			}
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if current == "" {
				return nil, fmt.Errorf("package continuation has no field")
			}
			fields[current] += "\n" + strings.TrimSpace(line)
			continue
		}
		key, value, found := strings.Cut(line, ":")
		if !found || key == "" || strings.TrimSpace(key) != key {
			return nil, fmt.Errorf("package stanza field is malformed")
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, fmt.Errorf("package stanza duplicates %s", key)
		}
		fields[key], current = strings.TrimSpace(value), key
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan package index: %w", err)
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return entries, nil
}

func repositoryPackageKey(name, version, architecture string) string {
	return name + "\x00" + version + "\x00" + architecture
}

func appendRepositoryPackageEntries(destination *[]repositoryPackageEntry, identities map[string]repositoryPackageEntry, candidates []repositoryPackageEntry) error {
	for _, candidate := range candidates {
		key := repositoryPackageKey(candidate.Name, candidate.Version, candidate.Architecture)
		if existing, found := identities[key]; found {
			if existing.Filename != candidate.Filename || existing.Size != candidate.Size || existing.Digest != candidate.Digest {
				return fmt.Errorf("package %s=%s/%s has conflicting filename, size, or digest", candidate.Name, candidate.Version, candidate.Architecture)
			}
			continue
		}
		identities[key] = candidate
		*destination = append(*destination, candidate)
	}
	return nil
}

func expectedRepositoryID(pkg Package, repositories []ObservedRepository) string {
	if pkg.RepositoryID != "" {
		return pkg.RepositoryID
	}
	if len(repositories) == 1 {
		return repositories[0].ID
	}
	return ""
}

func matchesRepositoryPackage(pkg Package, entry repositoryPackageEntry) bool {
	return entry.Name == pkg.Name && entry.Version == pkg.Version && entry.Architecture == pkg.Architecture && entry.Size == pkg.ArtifactBytes && entry.Digest == pkg.ArtifactDigest && (pkg.RepositoryFilename == "" || entry.Filename == pkg.RepositoryFilename)
}

func expectedRepositoryPackageEntries(expected []Package, currentRepositoryID string, repositories []ObservedRepository, entries []repositoryPackageEntry) []repositoryPackageEntry {
	byIdentity := make(map[string]repositoryPackageEntry, len(entries))
	for _, entry := range entries {
		byIdentity[repositoryPackageKey(entry.Name, entry.Version, entry.Architecture)] = entry
	}
	result := make([]repositoryPackageEntry, 0, len(expected))
	for _, pkg := range expected {
		if expectedRepositoryID(pkg, repositories) != currentRepositoryID {
			continue
		}
		if entry, found := byIdentity[repositoryPackageKey(pkg.Name, pkg.Version, pkg.Architecture)]; found && matchesRepositoryPackage(pkg, entry) {
			result = append(result, entry)
		}
	}
	return result
}

func validateExpectedRepositoryPackages(expected []Package, currentRepositoryID string, repositories []ObservedRepository, entries []repositoryPackageEntry) error {
	byIdentity := make(map[string]repositoryPackageEntry, len(entries))
	for _, entry := range entries {
		byIdentity[repositoryPackageKey(entry.Name, entry.Version, entry.Architecture)] = entry
	}
	for _, pkg := range expected {
		if expectedRepositoryID(pkg, repositories) != currentRepositoryID {
			continue
		}
		entry, found := byIdentity[repositoryPackageKey(pkg.Name, pkg.Version, pkg.Architecture)]
		if !found || !matchesRepositoryPackage(pkg, entry) {
			matches := 0
			if found {
				matches = 1
			}
			return fmt.Errorf("package %s=%s/%s has %d matching signed entries", pkg.Name, pkg.Version, pkg.Architecture, matches)
		}
	}
	return nil
}

func releaseFieldTokens(release []byte, field string) ([]string, bool) {
	var values []string
	found := false
	for line := range strings.SplitSeq(string(release), "\n") {
		key, value, hasValue := strings.Cut(line, ":")
		if key != field || !hasValue || found {
			if key == field && found {
				return nil, false
			}
			continue
		}
		values, found = strings.Fields(value), true
	}
	return values, found
}

func releaseFieldEqualsTokens(release []byte, field string, expected []string) bool {
	actual, found := releaseFieldTokens(release, field)
	return found && slices.Equal(actual, expected)
}

func releaseSuiteMatches(release []byte, configured string) bool {
	for _, field := range []string{"Suite", "Codename"} {
		values, found := releaseFieldTokens(release, field)
		if found && slices.Contains(values, configured) {
			return true
		}
	}
	return false
}

func releaseComponentsAuthorize(release []byte, configured []string) bool {
	values, found := releaseFieldTokens(release, "Components")
	if !found || len(configured) == 0 {
		return false
	}
	for _, component := range configured {
		if !slices.Contains(values, component) {
			return false
		}
	}
	return true
}

func releaseFieldContainsToken(release []byte, field, expected string) bool {
	values, found := releaseFieldTokens(release, field)
	return found && slices.Contains(values, expected)
}

func releaseSHA256Files(release []byte) (map[string]repositoryReleaseFile, error) {
	files := map[string]repositoryReleaseFile{}
	inSHA256 := false
	for line := range strings.SplitSeq(string(release), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "SHA256:" {
			inSHA256 = true
			continue
		}
		if !inSHA256 || trimmed == "" {
			continue
		}
		if trimmed == "SHA512:" || trimmed == "MD5Sum:" || strings.HasPrefix(trimmed, "-----BEGIN PGP ") {
			break
		}
		fields := strings.Fields(trimmed)
		if len(fields) != 3 || !digestPattern.MatchString(fields[0]) {
			return nil, fmt.Errorf("signed Release SHA256 entry is malformed")
		}
		bytes, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || bytes < 0 || fields[2] == "" || strings.ContainsAny(fields[2], "\u0000\r\n") {
			return nil, fmt.Errorf("signed Release SHA256 entry has invalid size or path")
		}
		if _, exists := files[fields[2]]; exists {
			return nil, fmt.Errorf("signed Release SHA256 entry is duplicated")
		}
		files[fields[2]] = repositoryReleaseFile{Bytes: bytes, Digest: fields[0]}
	}
	if !inSHA256 {
		return nil, fmt.Errorf("signed Release metadata omits its SHA256 index")
	}
	return files, nil
}

func aptListPart(value string) string {
	const quoteCharacters = `\|{}[]<>"^~_=!@#$%^&*`
	var result strings.Builder
	for index := 0; index < len(value); index++ {
		character := value[index]
		switch {
		case character == '/':
			result.WriteByte('_')
		case character < 0x21 || character >= 0x7f || strings.ContainsRune(quoteCharacters, rune(character)):
			_, _ = fmt.Fprintf(&result, "%%%02x", character)
		default:
			result.WriteByte(character)
		}
	}
	return result.String()
}

func repositoryCutoffDigest(release []byte) (string, error) {
	dateText, found := "", false
	for line := range strings.SplitSeq(string(release), "\n") {
		key, value, hasValue := strings.Cut(line, ":")
		if !hasValue || key != "Date" {
			continue
		}
		if found || strings.TrimSpace(value) == "" {
			return "", fmt.Errorf("signed Release metadata has an invalid Date field")
		}
		dateText, found = strings.TrimSpace(value), true
	}
	if !found {
		return "", fmt.Errorf("signed Release metadata omits its Date cutoff")
	}
	var date time.Time
	var err error
	for _, layout := range []string{time.RFC1123Z, time.RFC1123, time.RFC822Z, time.RFC822} {
		date, err = time.Parse(layout, dateText)
		if err == nil {
			break
		}
	}
	if err != nil {
		return "", fmt.Errorf("signed Release Date is not an RFC timestamp")
	}
	canonical, err := json.Marshal(struct {
		Date string `json:"date"`
	}{Date: date.UTC().Format(time.RFC3339)})
	if err != nil {
		return "", err
	}
	return digestBytes(canonical), nil
}

func digestBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func (auditor *LinuxAuditor) readConfiguration(ctx context.Context, plan Plan) ([]ObservedConfig, []ObservedRepository, error) {
	files := []ObservedConfig{}
	for _, entry := range []struct {
		path string
		kind ConfigKind
		dir  bool
	}{
		{filepath.Join(auditor.aptRoot, "apt.conf"), APTConfig, false},
		{filepath.Join(auditor.aptRoot, "apt.conf.d"), APTConfig, true},
		{filepath.Join(auditor.aptRoot, "auth.conf"), APTConfig, false},
		{filepath.Join(auditor.aptRoot, "auth.conf.d"), APTConfig, true},
		{filepath.Join(auditor.aptRoot, "keyrings"), APTKeyring, true},
		{filepath.Join(filepath.Dir(filepath.Dir(auditor.aptRoot)), "usr/share/keyrings"), APTKeyring, true},
		{filepath.Join(auditor.aptRoot, "preferences"), APTConfig, false},
		{filepath.Join(auditor.aptRoot, "preferences.d"), APTConfig, true},
		{filepath.Join(auditor.aptRoot, "sources.list"), APTSource, false},
		{filepath.Join(auditor.aptRoot, "sources.list.d"), APTSource, true},
		{filepath.Join(auditor.aptRoot, "trusted.gpg"), APTKeyring, false},
		{filepath.Join(auditor.aptRoot, "trusted.gpg.d"), APTKeyring, true},
		{filepath.Join(filepath.Dir(auditor.aptRoot), "dpkg/dpkg.cfg"), DPKGConfig, false},
		{filepath.Join(filepath.Dir(auditor.aptRoot), "dpkg/dpkg.cfg.d"), DPKGConfig, true},
	} {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		observed, err := auditor.readConfigEntry(entry.path, entry.kind, entry.dir)
		if err != nil {
			return nil, nil, err
		}
		files = append(files, observed...)
	}
	slices.SortFunc(files, func(left, right ObservedConfig) int { return strings.Compare(left.Path, right.Path) })
	basic := len(plan.Repositories) == 0
	repositories, err := parseObservedRepositories(files, plan.Repositories)
	if err != nil && !basic {
		// Existing host sources need not match the release transaction plan.
		// They are still parsed and signature-checked before the transaction
		// installs its exact source set.
		repositories, err = parseObservedRepositories(files, nil)
		basic = true
	}
	if err != nil {
		return nil, nil, err
	}
	if auditor.strict && len(repositories) == 0 {
		return nil, nil, fmt.Errorf("APT has no configured repository")
	}
	keyrings := map[string][]byte{}
	for _, file := range files {
		if file.Kind == APTKeyring {
			keyrings[file.Path] = file.Bytes
		}
	}
	if basic {
		if err := auditor.bindObservedRepositoryKeyrings(repositories, keyrings); err != nil {
			return nil, nil, err
		}
	}
	// Public distro plans intentionally use the host's configured APT sources,
	// but still require the currently installed Release/InRelease metadata to
	// verify against its configured keyring before apt is allowed to mutate.
	for index := range repositories {
		repositories[index].KeyringDigest = digestBytes(keyrings[repositories[index].KeyringPath])
	}
	if basic && plan.Mode == DistroRepository && len(plan.Repositories) != 0 {
		planRepositories := make([]ObservedRepository, 0, len(plan.Repositories))
		for _, expected := range plan.Repositories {
			keyring, found := keyrings[expected.KeyringPath]
			if !found || len(keyring) == 0 {
				return nil, nil, fmt.Errorf("package Plan repository %q keyring is not present on the host", expected.ID)
			}
			planRepositories = append(planRepositories, ObservedRepository{ID: expected.ID, URI: expected.URI, Suite: expected.Suite, Components: append([]string(nil), expected.Components...), KeyringPath: expected.KeyringPath, KeyringDigest: digestBytes(keyring), Enabled: true})
		}
		if err := auditor.observeRepositoryMetadata(ctx, planRepositories, keyrings, plan.Packages); err != nil {
			return nil, nil, fmt.Errorf("package Plan repository package authority is invalid: %w", err)
		}
		if err := validateRepositoryObservations(planRepositories, plan.Repositories); err != nil {
			return nil, nil, fmt.Errorf("package Plan repository metadata differs from the signed authority: %w", err)
		}
	}
	var expectedPackages []Package
	if !basic {
		expectedPackages = plan.Packages
	}
	if err := auditor.observeRepositoryMetadata(ctx, repositories, keyrings, expectedPackages); err != nil {
		return nil, nil, err
	}
	return files, repositories, nil
}

func (auditor *LinuxAuditor) readConfigEntry(path string, kind ConfigKind, directory bool) ([]ObservedConfig, error) {
	if directory {
		fd, err := openSafeDirectory(path, auditor.strict)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		defer func() { _ = unix.Close(fd) }()
		entries, err := os.ReadDir(fmt.Sprintf("/proc/self/fd/%d", fd))
		if err != nil {
			return nil, err
		}
		result := []ObservedConfig{}
		for _, entry := range entries {
			if entry.IsDir() {
				return nil, fmt.Errorf("APT/dpkg configuration directory contains a nested directory")
			}
			observed, err := readObservedAt(fd, filepath.Join(path, entry.Name()), entry.Name(), kind, auditor.strict)
			if err != nil {
				return nil, err
			}
			result = append(result, observed)
		}
		return result, nil
	}
	parentFD, err := openSafeDirectory(filepath.Dir(path), auditor.strict)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(parentFD) }()
	observed, err := readObservedAt(parentFD, path, filepath.Base(path), kind, auditor.strict)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return []ObservedConfig{observed}, nil
}

func readObservedAt(parentFD int, path, name string, kind ConfigKind, strict bool) (ObservedConfig, error) {
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ObservedConfig{}, err
	}
	defer func() { _ = unix.Close(fd) }()
	var stat unix.Stat_t
	owner, group := uint32(0), uint32(0)
	if !strict {
		owner, group = uint32(os.Geteuid()), uint32(os.Getegid())
	}
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != owner || stat.Gid != group || stat.Mode&0o022 != 0 || stat.Size < 0 || stat.Size > 1<<20 {
		return ObservedConfig{}, fmt.Errorf("APT/dpkg file type, owner, group, link, mode, or size is unsafe")
	}
	data, err := readExactFD(fd, stat.Size+1)
	if err != nil || int64(len(data)) != stat.Size {
		return ObservedConfig{}, fmt.Errorf("read exact APT/dpkg configuration")
	}
	return ObservedConfig{Path: canonicalAuditPath(path, kind, strict), Kind: kind, UID: 0, GID: 0, Mode: stat.Mode & 0o777, Regular: true, ParentsSafe: true, Bytes: data}, nil
}

func canonicalAuditPath(path string, kind ConfigKind, strict bool) string {
	if strict {
		return path
	}
	base := filepath.Base(path)
	switch kind {
	case APTConfig:
		if strings.Contains(path, "/apt.conf.d/") {
			return "/etc/apt/apt.conf.d/" + base
		}
		return "/etc/apt/apt.conf"
	case APTSource:
		if strings.HasSuffix(path, "/sources.list") {
			return "/etc/apt/sources.list"
		}
		return "/etc/apt/sources.list.d/" + base
	case APTKeyring:
		switch {
		case strings.Contains(path, "/usr/share/keyrings/"):
			return "/usr/share/keyrings/" + base
		case strings.Contains(path, "/trusted.gpg.d/"):
			return "/etc/apt/trusted.gpg.d/" + base
		case strings.HasSuffix(path, "/trusted.gpg"):
			return "/etc/apt/trusted.gpg"
		default:
			return "/etc/apt/keyrings/" + base
		}
	case DPKGConfig:
		if strings.Contains(path, "/dpkg.cfg.d/") {
			return "/etc/dpkg/dpkg.cfg.d/" + base
		}
		return "/etc/dpkg/dpkg.cfg"
	default:
		return path
	}
}

func (auditor *LinuxAuditor) bindObservedRepositoryKeyrings(repositories []ObservedRepository, keyrings map[string][]byte) error {
	for index := range repositories {
		repository := &repositories[index]
		if repository.KeyringPath == "" {
			prefix, err := aptListRepositoryPrefix(repository.URI, repository.Suite)
			if err != nil {
				return err
			}
			release, _, err := auditor.readFileAndStat(filepath.Join(auditor.aptListsRoot, prefix+"InRelease"), maximumRepositoryMetadataFileBytes)
			if err != nil {
				return fmt.Errorf("read signed InRelease for repository %q: %w", repository.URI, err)
			}
			paths := make([]string, 0, len(keyrings))
			for path := range keyrings {
				if strings.HasPrefix(path, "/usr/share/keyrings/") || strings.HasPrefix(path, "/etc/apt/trusted.gpg") {
					paths = append(paths, path)
				}
			}
			slices.Sort(paths)
			for _, path := range paths {
				if _, err := verifyInRelease(release, keyrings[path]); err == nil {
					repository.KeyringPath = path
					break
				}
			}
			if repository.KeyringPath == "" {
				return fmt.Errorf("repository %q has no trusted keyring for its signed InRelease", repository.URI)
			}
		}
		repository.ID = "host-" + digestBytes([]byte(repository.URI + "\x00" + repository.Suite))[:32]
		repository.Enabled = true
	}
	slices.SortFunc(repositories, func(left, right ObservedRepository) int { return strings.Compare(left.ID, right.ID) })
	return nil
}

func parseObservedRepositories(files []ObservedConfig, expected []Repository) ([]ObservedRepository, error) {
	parsed := []ObservedRepository{}
	for _, file := range files {
		if file.Kind != APTSource {
			continue
		}
		values, err := parseSourceFile(file.Path, file.Bytes)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, values...)
	}
	result := make([]ObservedRepository, 0, len(parsed))
	for _, observed := range parsed {
		if len(expected) == 0 {
			result = append(result, observed)
			continue
		}
		matched := false
		for _, want := range expected {
			keyringMatches := observed.KeyringPath == want.KeyringPath
			if observed.KeyringPath == "" && strings.HasPrefix(want.KeyringPath, "/usr/share/keyrings/") {
				keyringMatches = true
			}
			if observed.URI == want.URI && observed.Suite == want.Suite && slices.Equal(observed.Components, want.Components) && keyringMatches {
				if matched {
					return nil, fmt.Errorf("active APT source matches multiple repository authorities")
				}
				if observed.KeyringPath == "" {
					observed.KeyringPath = want.KeyringPath
				}
				observed.ID, observed.Enabled = want.ID, true
				result = append(result, observed)
				matched = true
			}
		}
		if !matched {
			return nil, fmt.Errorf("active APT source is not authorized by the package Plan")
		}
	}
	slices.SortFunc(result, func(left, right ObservedRepository) int { return strings.Compare(left.ID, right.ID) })
	return result, nil
}

func parseSourceFile(path string, data []byte) ([]ObservedRepository, error) {
	if strings.HasSuffix(path, ".sources") {
		return parseDeb822Sources(data)
	}
	result := []ObservedRepository{}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != "deb" && fields[0] != "deb-src" {
			return nil, fmt.Errorf("APT source line is unsupported or malformed")
		}
		binarySource := fields[0] == "deb"
		if !strings.HasPrefix(fields[1], "[") {
			if binarySource {
				result = append(result, ObservedRepository{URI: fields[1], Suite: fields[2], Components: append([]string(nil), fields[3:]...), Enabled: true})
			}
			continue
		}
		closing := slices.IndexFunc(fields, func(value string) bool { return strings.HasSuffix(value, "]") })
		if closing < 1 || closing+3 >= len(fields) {
			return nil, fmt.Errorf("APT source options are incomplete")
		}
		options := strings.Join(fields[1:closing+1], " ")
		if len(options) < 2 || options[0] != '[' || options[len(options)-1] != ']' || strings.Count(options, "[") != 1 || strings.Count(options, "]") != 1 {
			return nil, fmt.Errorf("APT source option brackets are malformed")
		}
		options = options[1 : len(options)-1]
		signedBy := ""
		for _, option := range strings.Fields(options) {
			key, value, found := strings.Cut(option, "=")
			if !found || key != "arch" && key != "signed-by" || key == "arch" && value != "amd64" {
				return nil, fmt.Errorf("APT source option is unauthorized")
			}
			if key == "signed-by" {
				signedBy = value
			}
		}
		if signedBy == "" {
			return nil, fmt.Errorf("APT source omits exact signed-by authority")
		}
		if binarySource {
			result = append(result, ObservedRepository{URI: fields[closing+1], Suite: fields[closing+2], Components: append([]string(nil), fields[closing+3:]...), KeyringPath: signedBy, Enabled: true})
		}
	}
	return result, nil
}

func parseDeb822Sources(data []byte) ([]ObservedRepository, error) {
	result := []ObservedRepository{}
	paragraph := []string{}
	flush := func() error {
		if len(paragraph) == 0 {
			return nil
		}
		fields := map[string]string{}
		for _, line := range paragraph {
			key, value, found := strings.Cut(line, ":")
			if !found || strings.TrimSpace(key) != key || key == "" {
				return fmt.Errorf("deb822 APT source is malformed or duplicated")
			}
			if _, duplicate := fields[key]; duplicate {
				return fmt.Errorf("deb822 APT source is malformed or duplicated")
			}
			fields[key] = strings.TrimSpace(value)
		}
		for key := range fields {
			if key != "Types" && key != "URIs" && key != "Suites" && key != "Components" && key != "Signed-By" && key != "Architectures" && key != "Enabled" {
				return fmt.Errorf("deb822 APT source contains an unsupported field")
			}
		}
		uris, suites, components, signedBy := strings.Fields(fields["URIs"]), strings.Fields(fields["Suites"]), strings.Fields(fields["Components"]), strings.Fields(fields["Signed-By"])
		if fields["Types"] != "deb" || len(uris) != 1 || len(suites) == 0 || len(suites) > 16 || len(signedBy) != 1 || len(components) == 0 || fields["Architectures"] != "" && fields["Architectures"] != "amd64" || fields["Enabled"] != "" && fields["Enabled"] != "yes" {
			return fmt.Errorf("deb822 APT source authority is unsupported")
		}
		for _, suite := range suites {
			result = append(result, ObservedRepository{URI: uris[0], Suite: suite, Components: append([]string(nil), components...), KeyringPath: signedBy[0], Enabled: true})
		}
		paragraph = nil
		return nil
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSuffix(raw, "\r")
		if strings.TrimSpace(line) == "" {
			if err := flush(); err != nil {
				return nil, err
			}
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			return nil, fmt.Errorf("deb822 APT source continuation is unsupported")
		}
		paragraph = append(paragraph, line)
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return result, nil
}

func (auditor *LinuxAuditor) readDPKG(ctx context.Context, closure []Package) (DPKGState, []Package, []InstalledPackage, error) {
	path := filepath.Join(auditor.dpkgRoot, "status")
	data, err := auditor.readSafeFile(path, 32<<20)
	if err != nil {
		return DPKGState{}, nil, nil, err
	}
	state := DPKGState{}
	installedByName := map[string]Package{}
	systemPackages := []InstalledPackage{}
	for stanzaIndex, paragraph := range strings.Split(string(data), "\n\n") {
		if strings.TrimSpace(paragraph) == "" {
			continue
		}
		fields := map[string]string{}
		scanner := bufio.NewScanner(strings.NewReader(paragraph))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
				continue
			}
			key, value, found := strings.Cut(line, ":")
			if !found || key == "" {
				return DPKGState{}, nil, nil, fmt.Errorf("dpkg status stanza %d is malformed", stanzaIndex+1)
			}
			if _, duplicate := fields[key]; duplicate {
				return DPKGState{}, nil, nil, fmt.Errorf("dpkg status stanza %d duplicates %s", stanzaIndex+1, key)
			}
			fields[key] = strings.TrimSpace(value)
		}
		if err := scanner.Err(); err != nil {
			return DPKGState{}, nil, nil, fmt.Errorf("scan dpkg status stanza %d: %w", stanzaIndex+1, err)
		}
		for _, required := range []string{"Package", "Status", "Version", "Architecture"} {
			if fields[required] == "" {
				return DPKGState{}, nil, nil, fmt.Errorf("dpkg status stanza %d is missing %s", stanzaIndex+1, required)
			}
		}
		name := fields["Package"]
		_, errorState, packageState, err := parseDPKGStatusFields(fields["Status"])
		if err != nil {
			return DPKGState{}, nil, nil, fmt.Errorf("dpkg status stanza %d: %w", stanzaIndex+1, err)
		}
		if errorState != "ok" {
			state.Broken = append(state.Broken, name)
			continue
		}
		switch packageState {
		case "installed":
			systemPackages = append(systemPackages, InstalledPackage{Name: name, Version: fields["Version"], Architecture: fields["Architecture"]})
			if wanted, ok := packageByName(closure, name); ok {
				wanted.Version = fields["Version"]
				wanted.Architecture = fields["Architecture"]
				installedByName[name] = wanted
			}
		case "unpacked":
			state.Unpacked = append(state.Unpacked, name)
		case "half-configured":
			state.HalfConfigured = append(state.HalfConfigured, name)
		case "triggers-awaited", "triggers-pending":
			state.TriggersPending = append(state.TriggersPending, name)
		case "half-installed":
			state.Broken = append(state.Broken, name)
		case "not-installed", "config-files":
		}
	}
	for _, values := range [][]string{state.HalfConfigured, state.Unpacked, state.TriggersPending, state.Broken} {
		slices.Sort(values)
	}
	installed := []Package{}
	for _, pkg := range closure {
		if current, ok := installedByName[pkg.Name]; ok {
			installed = append(installed, current)
		}
	}
	if err := ctx.Err(); err != nil {
		return DPKGState{}, nil, nil, err
	}
	slices.SortFunc(systemPackages, func(left, right InstalledPackage) int { return strings.Compare(left.Name, right.Name) })
	if err := validateInstalledPackages(systemPackages); err != nil {
		return DPKGState{}, nil, nil, err
	}
	return state, installed, systemPackages, nil
}

func parseDPKGStatusFields(value string) (string, string, string, error) {
	fields := strings.Fields(value)
	if len(fields) != 3 {
		return "", "", "", fmt.Errorf("dpkg Status must contain exactly selection, error, and state fields")
	}
	selection, errorState, packageState := fields[0], fields[1], fields[2]
	switch selection {
	case "unknown", "install", "hold", "deinstall", "purge":
	default:
		return "", "", "", fmt.Errorf("dpkg Status selection field is invalid")
	}
	if errorState != "ok" && errorState != "reinstreq" {
		return "", "", "", fmt.Errorf("dpkg Status error field is invalid")
	}
	switch packageState {
	case "not-installed", "config-files", "half-installed", "unpacked", "half-configured", "triggers-awaited", "triggers-pending", "installed":
	default:
		return "", "", "", fmt.Errorf("dpkg Status state field is invalid")
	}
	return selection, errorState, packageState, nil
}

func (auditor *LinuxAuditor) distroCacheNeedsVerification(plan Plan) (bool, error) {
	if auditor == nil || auditor.transactionRoot == "" {
		return false, fmt.Errorf("distro package cache authority is unavailable")
	}
	cachePath := filepath.Join(auditor.transactionRoot, plan.TransactionID, "archives")
	fd, err := openSafeDirectory(cachePath, auditor.strict)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = unix.Close(fd) }()
	entries, err := os.ReadDir(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if entry.Name() != "lock" && entry.Name() != "partial" {
			return true, nil
		}
	}
	return false, nil
}

func (auditor *LinuxAuditor) verifyDistroPackageArtifacts(plan Plan, repositories []ObservedRepository) error {
	if plan.Mode != DistroRepository || len(plan.Repositories) == 0 {
		return nil
	}
	if auditor == nil || auditor.transactionRoot == "" {
		return fmt.Errorf("distro package artifact authority is unavailable")
	}
	cachePath := filepath.Join(auditor.transactionRoot, plan.TransactionID, "archives")
	cacheFD, err := openSafeDirectory(cachePath, auditor.strict)
	if err != nil {
		return fmt.Errorf("open exact distro package cache: %w", err)
	}
	defer func() { _ = unix.Close(cacheFD) }()
	entries, err := os.ReadDir(fmt.Sprintf("/proc/self/fd/%d", cacheFD))
	if err != nil {
		return fmt.Errorf("read exact distro package cache: %w", err)
	}
	matched := map[string]bool{}
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == "lock" || entry.Name() == "partial" {
			continue
		}
		if filepath.Ext(entry.Name()) != ".deb" {
			return fmt.Errorf("distro package cache contains an unexpected member")
		}
		digest, bytes, err := auditor.hashFile(filepath.Join(cachePath, entry.Name()), 4<<30)
		if err != nil {
			return fmt.Errorf("read exact installed distro package artifact: %w", err)
		}
		pkg, ok := packageByDigest(plan.Packages, digest, bytes)
		if !ok || matched[pkg.ArtifactDigest] {
			return fmt.Errorf("installed distro package artifact is not in the frozen closure")
		}
		binding, err := repositoryPackageBinding(pkg, repositories)
		if err != nil {
			return err
		}
		if filepath.Base(binding.Filename) != entry.Name() {
			return fmt.Errorf("installed distro package artifact filename differs from the signed Packages index")
		}
		matched[pkg.ArtifactDigest] = true
	}
	if len(matched) != len(plan.Packages) {
		return fmt.Errorf("distro package cache omits a frozen package artifact")
	}
	return nil
}

func (auditor *LinuxAuditor) hashFile(path string, maximum int64) (string, int64, error) {
	parent, err := openSafeDirectory(filepath.Dir(path), auditor.strict)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = unix.Close(parent) }()
	fd, err := unix.Openat(parent, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", 0, err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return "", 0, fmt.Errorf("package artifact descriptor is invalid")
	}
	defer func() { _ = file.Close() }()
	var before unix.Stat_t
	owner, group := uint32(0), uint32(0)
	if !auditor.strict {
		owner, group = uint32(os.Geteuid()), uint32(os.Getegid())
	}
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Uid != owner || before.Gid != group || before.Mode&0o022 != 0 || before.Size <= 0 || before.Size > maximum {
		return "", 0, fmt.Errorf("package artifact file identity is unsafe")
	}
	hasher := sha256.New()
	read, err := io.CopyBuffer(hasher, io.LimitReader(file, maximum+1), make([]byte, 32<<10))
	var after unix.Stat_t
	if err != nil || read != before.Size || unix.Fstat(fd, &after) != nil || after.Dev != before.Dev || after.Ino != before.Ino || after.Size != before.Size || after.Mtim != before.Mtim {
		return "", 0, fmt.Errorf("package artifact changed while reading")
	}
	return hex.EncodeToString(hasher.Sum(nil)), read, nil
}

func (auditor *LinuxAuditor) runtimeSnapshot(plan Plan, installed []Package, systemPackages []InstalledPackage) (RuntimeSnapshot, error) {
	entries, err := os.ReadDir(auditor.cgroupRoot)
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	unitNames := affectedUnits(plan.Packages)
	for _, entry := range entries {
		if entry.IsDir() && unitPattern.MatchString(entry.Name()) {
			unitNames = append(unitNames, entry.Name())
		}
	}
	slices.Sort(unitNames)
	unitNames = slices.Compact(unitNames)
	units := make([]UnitState, 0, len(unitNames))
	for _, name := range unitNames {
		active, err := cgroupHasProcesses(filepath.Join(auditor.cgroupRoot, name, "cgroup.procs"))
		if err != nil {
			return RuntimeSnapshot{}, err
		}
		masked := false
		if target, err := os.Readlink(filepath.Join(auditor.maskRoot, name)); err == nil {
			masked = target == "/dev/null"
		} else if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, unix.EINVAL) {
			return RuntimeSnapshot{}, fmt.Errorf("observe systemd unit mask: %w", err)
		}
		units = append(units, UnitState{Name: name, Active: active, Masked: masked})
	}
	bound, err := readBoundListeners(auditor.procRoot)
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	keys := make([]string, 0, len(bound))
	for key := range bound {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	listeners := make([]Listener, 0, len(keys))
	for _, key := range keys {
		protocol, portText, _ := strings.Cut(key, "/")
		port, _ := strconv.Atoi(portText)
		listeners = append(listeners, Listener{Protocol: protocol, Port: uint16(port), Owner: "host"})
	}
	return RuntimeSnapshot{Installed: clonePackagesForJournal(installed), SystemPackages: append([]InstalledPackage(nil), systemPackages...), Units: units, Listeners: listeners}, nil
}

func (auditor *LinuxAuditor) noAutostartPolicy(expectedDigest string) (NoAutostartPolicy, error) {
	policy, policyStat, err := auditor.readFileAndStat(auditor.policyPath, filetxn.MaximumContentBytes)
	if err != nil {
		return NoAutostartPolicy{}, err
	}
	binary, _, err := auditor.readFileAndStat(auditor.binaryPath, filetxn.MaximumContentBytes)
	if err != nil {
		return NoAutostartPolicy{}, err
	}
	policyDigest := sha256.Sum256(policy)
	binaryDigest := sha256.Sum256(binary)
	digest := hex.EncodeToString(policyDigest[:])
	if digest != expectedDigest {
		return NoAutostartPolicy{}, fmt.Errorf("package no-autostart policy digest differs from Plan")
	}
	return NoAutostartPolicy{Path: "/usr/sbin/policy-rc.d", Digest: digest, UID: policyStat.Uid, GID: policyStat.Gid, Mode: policyStat.Mode & 0o777, Regular: policyStat.Mode&unix.S_IFMT == unix.S_IFREG, ParentsSafe: true, SameLanPanelBinary: bytes.Equal(policyDigest[:], binaryDigest[:])}, nil
}

func (auditor *LinuxAuditor) readSafeFile(path string, maximum int64) ([]byte, error) {
	data, _, err := auditor.readFileAndStat(path, maximum)
	return data, err
}

func (auditor *LinuxAuditor) readFileAndStat(path string, maximum int64) ([]byte, unix.Stat_t, error) {
	parent, err := openSafeDirectory(filepath.Dir(path), auditor.strict)
	if err != nil {
		return nil, unix.Stat_t{}, err
	}
	defer func() { _ = unix.Close(parent) }()
	fd, err := unix.Openat(parent, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, unix.Stat_t{}, err
	}
	defer func() { _ = unix.Close(fd) }()
	var before, after unix.Stat_t
	owner, group := uint32(0), uint32(0)
	if !auditor.strict {
		owner, group = uint32(os.Geteuid()), uint32(os.Getegid())
	}
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Uid != owner || before.Gid != group || before.Mode&0o022 != 0 || before.Size < 0 || before.Size > maximum {
		return nil, unix.Stat_t{}, fmt.Errorf("package audit file identity is unsafe")
	}
	data, err := readExactFD(fd, before.Size+1)
	if err != nil || int64(len(data)) != before.Size || unix.Fstat(fd, &after) != nil || after.Dev != before.Dev || after.Ino != before.Ino || after.Size != before.Size || after.Mtim != before.Mtim {
		return nil, unix.Stat_t{}, fmt.Errorf("package audit file changed while reading")
	}
	return data, after, nil
}

func openSafeDirectory(path string, strict bool) (int, error) {
	if !strict {
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return -1, err
		}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) || stat.Mode&0o022 != 0 {
			_ = unix.Close(fd)
			return -1, fmt.Errorf("test package audit directory is unsafe")
		}
		return fd, nil
	}
	current, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	relative := strings.TrimPrefix(path, "/")
	if relative == "" {
		return current, nil
	}
	owner, group := uint32(0), uint32(0)
	if !strict {
		owner, group = uint32(os.Geteuid()), uint32(os.Getegid())
	}
	for _, component := range strings.Split(relative, "/") {
		next, openErr := unix.Openat(current, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(current)
		if openErr != nil {
			return -1, openErr
		}
		current = next
		var stat unix.Stat_t
		if err := unix.Fstat(current, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || strict && (stat.Uid != 0 || stat.Gid != 0) || !strict && (stat.Uid != owner || stat.Gid != group) || stat.Mode&0o022 != 0 {
			_ = unix.Close(current)
			return -1, fmt.Errorf("package audit parent is linked, non-directory, incorrectly owned, or writable")
		}
	}
	return current, nil
}

func validateAuditorParent(path string) error {
	fd, err := openSafeDirectory(path, true)
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

func packageByName(packages []Package, name string) (Package, bool) {
	for _, pkg := range packages {
		if pkg.Name == name {
			return pkg, true
		}
	}
	return Package{}, false
}
