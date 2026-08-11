package release

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"path"
	"slices"
	"strings"
	"unicode/utf8"
)

const MaximumChecksumFileBytes = 4 << 20

type ChecksumEntry struct {
	Path   string
	Digest string
}

type ChecksumSet struct {
	entries []ChecksumEntry
	byPath  map[string]string
}

func (set ChecksumSet) Entries() []ChecksumEntry {
	return append([]ChecksumEntry(nil), set.entries...)
}

func (set ChecksumSet) DigestFor(assetPath string) (string, bool) {
	digest, ok := set.byPath[assetPath]
	return digest, ok
}

// ParseChecksums accepts only "<64-hex><two spaces><relative-path>\n" rows in
// exact UTF-8 byte order and requires an exact expected asset inventory.
func ParseChecksums(data []byte, expectedPaths []string) (ChecksumSet, error) {
	if len(data) == 0 || len(data) > MaximumChecksumFileBytes || data[len(data)-1] != '\n' || !utf8.Valid(data) {
		return ChecksumSet{}, fmt.Errorf("checksum file encoding or size is invalid")
	}
	expected := map[string]struct{}{}
	for _, assetPath := range expectedPaths {
		if !ValidRelativePath(assetPath) {
			return ChecksumSet{}, fmt.Errorf("expected checksum asset path %q is invalid", assetPath)
		}
		if _, duplicate := expected[assetPath]; duplicate {
			return ChecksumSet{}, fmt.Errorf("expected checksum asset path %q is duplicated", assetPath)
		}
		expected[assetPath] = struct{}{}
	}
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	if len(lines) == 0 || len(lines) != len(expected) {
		return ChecksumSet{}, fmt.Errorf("checksum file does not contain the exact asset count")
	}
	set := ChecksumSet{entries: make([]ChecksumEntry, 0, len(lines)), byPath: map[string]string{}}
	previous := ""
	for index, line := range lines {
		if len(line) < 67 || line[64:66] != "  " {
			return ChecksumSet{}, fmt.Errorf("checksum row %d has an invalid shape", index+1)
		}
		digest, assetPath := line[:64], line[66:]
		if !ValidDigest(digest) || !ValidRelativePath(assetPath) {
			return ChecksumSet{}, fmt.Errorf("checksum row %d has an invalid digest or path", index+1)
		}
		if index != 0 && strings.Compare(previous, assetPath) >= 0 {
			return ChecksumSet{}, fmt.Errorf("checksum paths are duplicated or not in UTF-8 byte order")
		}
		if _, listed := expected[assetPath]; !listed {
			return ChecksumSet{}, fmt.Errorf("checksum file lists unexpected asset %q", assetPath)
		}
		if _, duplicate := set.byPath[assetPath]; duplicate {
			return ChecksumSet{}, fmt.Errorf("checksum file duplicates asset %q", assetPath)
		}
		set.entries = append(set.entries, ChecksumEntry{Path: assetPath, Digest: digest})
		set.byPath[assetPath] = digest
		previous = assetPath
	}
	for assetPath := range expected {
		if _, present := set.byPath[assetPath]; !present {
			return ChecksumSet{}, fmt.Errorf("checksum file omits asset %q", assetPath)
		}
	}
	return set, nil
}

func EncodeChecksums(entries []ChecksumEntry) ([]byte, error) {
	copyEntries := append([]ChecksumEntry(nil), entries...)
	slices.SortFunc(copyEntries, func(left, right ChecksumEntry) int { return strings.Compare(left.Path, right.Path) })
	var output strings.Builder
	seen := map[string]struct{}{}
	for _, entry := range copyEntries {
		if !ValidDigest(entry.Digest) || !ValidRelativePath(entry.Path) {
			return nil, fmt.Errorf("checksum entry is invalid")
		}
		if _, duplicate := seen[entry.Path]; duplicate {
			return nil, fmt.Errorf("checksum entry path is duplicated")
		}
		seen[entry.Path] = struct{}{}
		fmt.Fprintf(&output, "%s  %s\n", entry.Digest, entry.Path)
	}
	if output.Len() == 0 || output.Len() > MaximumChecksumFileBytes {
		return nil, fmt.Errorf("checksum file is empty or unbounded")
	}
	return []byte(output.String()), nil
}

func VerifyAssetBytes(set ChecksumSet, assets map[string][]byte) error {
	if len(assets) != len(set.entries) {
		return fmt.Errorf("asset bytes do not match the checksum inventory")
	}
	for _, entry := range set.entries {
		data, present := assets[entry.Path]
		if !present || DigestBytes(data) != entry.Digest {
			return fmt.Errorf("asset %q does not match its checksum", entry.Path)
		}
	}
	return nil
}

func ValidRelativePath(value string) bool {
	if value == "" || !utf8.ValidString(value) || strings.HasPrefix(value, "/") || strings.Contains(value, "\\") || path.Clean(value) != value {
		return false
	}
	for _, character := range []byte(value) {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	return true
}

const (
	TreeEntryRegular = "regular"
	TreeEntrySymlink = "symlink"
	TreeModeRegular  = uint32(0o100644)
	TreeModeExec     = uint32(0o100755)
	TreeModeSymlink  = uint32(0o120000)
)

type TreeEntry struct {
	Path    string
	Type    string
	Mode    uint32
	Content []byte
}

type TrackedInventory struct {
	paths  []string
	digest string
}

func NewTrackedInventory(paths []string) (TrackedInventory, error) {
	copyPaths := append([]string(nil), paths...)
	slices.Sort(copyPaths)
	if len(copyPaths) == 0 {
		return TrackedInventory{}, fmt.Errorf("tracked source inventory is empty")
	}
	hasher := sha256.New()
	writeLengthPrefixed(hasher, []byte("lanpanel.tracked-inventory.v1"))
	previous := ""
	for _, trackedPath := range copyPaths {
		if !ValidRelativePath(trackedPath) || previous != "" && trackedPath == previous {
			return TrackedInventory{}, fmt.Errorf("tracked source inventory path is invalid or duplicated")
		}
		writeLengthPrefixed(hasher, []byte(trackedPath))
		previous = trackedPath
	}
	return TrackedInventory{paths: copyPaths, digest: fmt.Sprintf("%x", hasher.Sum(nil))}, nil
}

func (inventory TrackedInventory) Digest() string  { return inventory.digest }
func (inventory TrackedInventory) Paths() []string { return append([]string(nil), inventory.paths...) }

// SourceTreeDigest hashes the complete tracked inventory as a path-sorted,
// unambiguous stream of type, mode, UTF-8 path, and content/target bytes.
func SourceTreeDigest(inventory TrackedInventory, entries []TreeEntry) (string, error) {
	copyEntries := make([]TreeEntry, len(entries))
	for index, entry := range entries {
		copyEntries[index] = TreeEntry{Path: entry.Path, Type: entry.Type, Mode: entry.Mode, Content: append([]byte(nil), entry.Content...)}
	}
	slices.SortFunc(copyEntries, func(left, right TreeEntry) int { return strings.Compare(left.Path, right.Path) })
	if !ValidDigest(inventory.digest) || len(inventory.paths) == 0 || len(copyEntries) != len(inventory.paths) {
		return "", fmt.Errorf("source-tree entries do not match a complete tracked inventory")
	}
	hasher := sha256.New()
	writeLengthPrefixed(hasher, []byte("lanpanel.source-tree.v1"))
	var count [8]byte
	binary.BigEndian.PutUint64(count[:], uint64(len(copyEntries)))
	writeLengthPrefixed(hasher, count[:])
	previous := ""
	for index, entry := range copyEntries {
		if !ValidRelativePath(entry.Path) || index != 0 && entry.Path == previous || entry.Path != inventory.paths[index] {
			return "", fmt.Errorf("source-tree path is invalid, untracked, omitted, or duplicated")
		}
		switch entry.Type {
		case TreeEntryRegular:
			if entry.Mode != TreeModeRegular && entry.Mode != TreeModeExec {
				return "", fmt.Errorf("regular source-tree mode is invalid")
			}
		case TreeEntrySymlink:
			if entry.Mode != TreeModeSymlink || len(entry.Content) == 0 || len(entry.Content) > 16<<10 || strings.IndexByte(string(entry.Content), 0) >= 0 {
				return "", fmt.Errorf("symlink source-tree entry is invalid")
			}
		default:
			return "", fmt.Errorf("source-tree entry type is unknown")
		}
		var mode [4]byte
		binary.BigEndian.PutUint32(mode[:], entry.Mode)
		writeLengthPrefixed(hasher, []byte(entry.Type))
		writeLengthPrefixed(hasher, mode[:])
		writeLengthPrefixed(hasher, []byte(entry.Path))
		writeLengthPrefixed(hasher, entry.Content)
		previous = entry.Path
	}
	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}

func writeLengthPrefixed(writer hash.Hash, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write(value)
}
