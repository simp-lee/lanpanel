package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1" // #nosec G505 -- Git index object identity is SHA-1; release authority remains SHA-256.
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"
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
		if !present {
			return fmt.Errorf("asset %q is missing from the installer asset set", entry.Path)
		}
		observed := DigestBytes(data)
		if observed != entry.Digest {
			return fmt.Errorf("asset %q does not match its checksum: expected=%s observed=%s", entry.Path, entry.Digest, observed)
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

// CleanTrackedSourceTree reads the stage-0 Git index directly and requires
// every indexed blob to match the worktree. Release gates separately require
// the index to equal HEAD so no process execution enters this verifier.
func CleanTrackedSourceTree(root string) (TrackedInventory, []TreeEntry, string, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return TrackedInventory{}, nil, "", err
	}
	indexPath, err := gitIndexPath(absolute)
	if err != nil {
		return TrackedInventory{}, nil, "", err
	}
	index, err := os.ReadFile(indexPath)
	if err != nil {
		return TrackedInventory{}, nil, "", err
	}
	if len(index) < 32 || len(index) > 64<<20 || string(index[:4]) != "DIRC" || binary.BigEndian.Uint32(index[4:8]) < 2 || binary.BigEndian.Uint32(index[4:8]) > 3 {
		return TrackedInventory{}, nil, "", fmt.Errorf("git index format is unsupported")
	}
	payload, checksum := index[:len(index)-sha1.Size], index[len(index)-sha1.Size:]
	actual := sha1.Sum(payload)
	if !bytes.Equal(actual[:], checksum) {
		return TrackedInventory{}, nil, "", fmt.Errorf("git index checksum changed")
	}
	count := int(binary.BigEndian.Uint32(index[8:12]))
	offset := 12
	paths := make([]string, 0, count)
	entries := make([]TreeEntry, 0, count)
	for item := 0; item < count; item++ {
		start := offset
		if offset+62 > len(payload) {
			return TrackedInventory{}, nil, "", fmt.Errorf("git index entry is truncated")
		}
		mode := binary.BigEndian.Uint32(index[offset+24 : offset+28])
		objectID := index[offset+40 : offset+60]
		flags := binary.BigEndian.Uint16(index[offset+60 : offset+62])
		if flags&0x3000 != 0 || flags&0x4000 != 0 {
			return TrackedInventory{}, nil, "", fmt.Errorf("git index contains a non-stage-zero or extended entry")
		}
		pathStart := offset + 62
		pathEnd := bytes.IndexByte(index[pathStart:len(payload)], 0)
		if pathEnd < 0 {
			return TrackedInventory{}, nil, "", fmt.Errorf("git index path is unterminated")
		}
		pathEnd += pathStart
		trackedPath := string(index[pathStart:pathEnd])
		if !ValidRelativePath(trackedPath) {
			return TrackedInventory{}, nil, "", fmt.Errorf("git index path is invalid")
		}
		length := pathEnd - start + 1
		offset = start + (length+7)&^7
		if offset > len(payload) {
			return TrackedInventory{}, nil, "", fmt.Errorf("git index padding is invalid")
		}
		fullPath := filepath.Join(absolute, filepath.FromSlash(trackedPath))
		entry := TreeEntry{Path: trackedPath}
		switch mode {
		case 0o100644, 0o100755:
			info, statErr := os.Lstat(fullPath)
			if statErr != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
				return TrackedInventory{}, nil, "", fmt.Errorf("tracked source file %q changed type or size", trackedPath)
			}
			content, readErr := os.ReadFile(fullPath)
			if readErr != nil {
				return TrackedInventory{}, nil, "", readErr
			}
			entry.Type, entry.Mode, entry.Content = TreeEntryRegular, TreeModeRegular, content
			if mode == 0o100755 {
				entry.Mode = TreeModeExec
			}
		case 0o120000:
			target, readErr := os.Readlink(fullPath)
			if readErr != nil {
				return TrackedInventory{}, nil, "", fmt.Errorf("read tracked source symlink %q: %w", trackedPath, readErr)
			}
			entry.Type, entry.Mode, entry.Content = TreeEntrySymlink, TreeModeSymlink, []byte(target)
		default:
			return TrackedInventory{}, nil, "", fmt.Errorf("git index mode is unsupported")
		}
		blob := sha1.New()
		_, _ = fmt.Fprintf(blob, "blob %d%c", len(entry.Content), byte(0))
		_, _ = blob.Write(entry.Content)
		if !bytes.Equal(blob.Sum(nil), objectID) {
			return TrackedInventory{}, nil, "", fmt.Errorf("tracked source entry %q differs from Git index", trackedPath)
		}
		paths = append(paths, trackedPath)
		entries = append(entries, entry)
	}
	for offset < len(payload) {
		if offset+8 > len(payload) {
			return TrackedInventory{}, nil, "", fmt.Errorf("git index extension is truncated")
		}
		extensionKind := string(payload[offset : offset+4])
		size := int(binary.BigEndian.Uint32(payload[offset+4 : offset+8]))
		offset += 8
		if size < 0 || offset+size > len(payload) {
			return TrackedInventory{}, nil, "", fmt.Errorf("git index extension size is invalid")
		}
		if extensionKind != "TREE" {
			return TrackedInventory{}, nil, "", fmt.Errorf("git index extension %q is unsupported for release inventory", extensionKind)
		}
		offset += size
	}
	inventory, err := NewTrackedInventory(paths)
	if err != nil {
		return TrackedInventory{}, nil, "", err
	}
	digest, err := SourceTreeDigest(inventory, entries)
	if err != nil {
		return TrackedInventory{}, nil, "", err
	}
	return inventory, entries, digest, nil
}

func gitIndexPath(root string) (string, error) {
	dotGit := filepath.Join(root, ".git")
	info, err := os.Lstat(dotGit)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return filepath.Join(dotGit, "index"), nil
	}
	if !info.Mode().IsRegular() || info.Size() > 4096 {
		return "", fmt.Errorf("git metadata reference is invalid")
	}
	raw, err := os.ReadFile(dotGit)
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(line, "gitdir: ") {
		return "", fmt.Errorf("git metadata reference is invalid")
	}
	directory := strings.TrimPrefix(line, "gitdir: ")
	if !filepath.IsAbs(directory) {
		directory = filepath.Join(root, directory)
	}
	directory = filepath.Clean(directory)
	return filepath.Join(directory, "index"), nil
}

// GenerateSourceArchive builds the one canonical USTAR+gzip source archive
// directly from the already verified stage-0 index/worktree inventory.
func GenerateSourceArchive(root, releaseTag string) ([]byte, string, error) {
	if !releaseTagPattern.MatchString(releaseTag) {
		return nil, "", fmt.Errorf("source archive release tag is invalid")
	}
	inventory, entries, digest, err := CleanTrackedSourceTree(root)
	if err != nil {
		return nil, "", err
	}
	if len(entries) != len(inventory.Paths()) {
		return nil, "", fmt.Errorf("source archive inventory changed")
	}
	rootName := "lanpanel-" + releaseTag
	type archiveEntry struct {
		name  string
		entry *TreeEntry
	}
	values := []archiveEntry{{name: rootName + "/"}}
	directories := map[string]bool{}
	for index := range entries {
		entry := entries[index]
		for parent := path.Dir(entry.Path); parent != "."; parent = path.Dir(parent) {
			directories[parent] = true
		}
		copyEntry := entry
		values = append(values, archiveEntry{name: rootName + "/" + entry.Path, entry: &copyEntry})
	}
	for directory := range directories {
		values = append(values, archiveEntry{name: rootName + "/" + directory + "/"})
	}
	slices.SortFunc(values, func(left, right archiveEntry) int { return strings.Compare(left.name, right.name) })
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	compressed.ModTime = time.Time{}
	compressed.OS = 255
	archive := tar.NewWriter(compressed)
	for _, value := range values {
		header := &tar.Header{Name: value.name, Uid: 0, Gid: 0, ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatUSTAR}
		if value.entry == nil {
			header.Typeflag = tar.TypeDir
			header.Mode = 0o755
		} else if value.entry.Type == TreeEntrySymlink {
			header.Typeflag = tar.TypeSymlink
			header.Mode = 0o777
			header.Linkname = string(value.entry.Content)
		} else {
			header.Typeflag = tar.TypeReg
			header.Mode = 0o644
			if value.entry.Mode == TreeModeExec {
				header.Mode = 0o755
			}
			header.Size = int64(len(value.entry.Content))
		}
		if err := archive.WriteHeader(header); err != nil {
			return nil, "", err
		}
		if value.entry != nil && value.entry.Type == TreeEntryRegular {
			if _, err := archive.Write(value.entry.Content); err != nil {
				return nil, "", err
			}
		}
	}
	if err := archive.Close(); err != nil {
		return nil, "", err
	}
	if err := compressed.Close(); err != nil {
		return nil, "", err
	}
	data := output.Bytes()
	verified, err := sourceArchiveTreeDigest(data, rootName)
	if err != nil || verified != digest {
		return nil, "", fmt.Errorf("generated source archive failed exact self-verification: %w", err)
	}
	return append([]byte(nil), data...), digest, nil
}

func ReadSourceArchiveFile(data []byte, releaseTag, relative string, maximum int64) ([]byte, error) {
	if !releaseTagPattern.MatchString(releaseTag) || !ValidRelativePath(relative) || maximum <= 0 {
		return nil, fmt.Errorf("source archive file authority is invalid")
	}
	root := "lanpanel-" + releaseTag
	if _, err := sourceArchiveTreeDigest(data, root); err != nil {
		return nil, err
	}
	compressed, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer func() { _ = compressed.Close() }()
	reader := tar.NewReader(compressed)
	expected := root + "/" + relative
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if header.Name != expected {
			continue
		}
		if header.Typeflag != tar.TypeReg || header.Size <= 0 || header.Size > maximum {
			return nil, fmt.Errorf("source archive file type or size is invalid")
		}
		content, err := io.ReadAll(io.LimitReader(reader, maximum+1))
		if err != nil || int64(len(content)) != header.Size {
			return nil, fmt.Errorf("source archive file changed: %w", err)
		}
		return content, nil
	}
	return nil, fmt.Errorf("source archive file %q is missing", relative)
}

func VerifySourceArchiveAgainstCleanTree(root string, archive []byte) (string, error) {
	_, _, trackedDigest, err := CleanTrackedSourceTree(root)
	if err != nil {
		return "", err
	}
	archiveDigest, err := SourceArchiveTreeDigest(archive)
	if err != nil {
		return "", err
	}
	if archiveDigest != trackedDigest {
		return "", fmt.Errorf("source archive does not match the clean tracked source tree")
	}
	return trackedDigest, nil
}

func SourceArchiveTreeDigest(data []byte) (string, error) { return sourceArchiveTreeDigest(data, "") }
func sourceArchiveTreeDigest(data []byte, expectedRoot string) (string, error) {
	if len(data) == 0 || len(data) > 512<<20 {
		return "", fmt.Errorf("source archive is empty or unbounded")
	}
	compressed := bytes.NewReader(data)
	gzipReader, err := gzip.NewReader(compressed)
	if err != nil {
		return "", err
	}
	gzipReader.Multistream(false)
	if !gzipReader.ModTime.IsZero() || gzipReader.Name != "" || gzipReader.Comment != "" || len(gzipReader.Extra) != 0 || gzipReader.OS != 255 {
		return "", fmt.Errorf("source archive gzip metadata is noncanonical")
	}
	defer func(ignore func() error) { _ = ignore() }(gzipReader.Close)
	reader := tar.NewReader(gzipReader)
	entries := []TreeEntry{}
	paths := []string{}
	prefix := ""
	previousHeader := ""
	seenHeaders := map[string]bool{}
	directories := map[string]bool{}
	total := int64(0)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if header.Format != tar.FormatUSTAR || header.Uid != 0 || header.Gid != 0 || header.Uname != "" || header.Gname != "" || !header.ModTime.Equal(time.Unix(0, 0).UTC()) || !header.AccessTime.IsZero() || !header.ChangeTime.IsZero() || len(header.PAXRecords) != 0 {
			return "", fmt.Errorf("source archive tar metadata is noncanonical")
		}
		rawName := header.Name
		name := path.Clean(strings.TrimSuffix(rawName, "/"))
		canonicalRaw := name
		if header.Typeflag == tar.TypeDir {
			canonicalRaw += "/"
		}
		if rawName != canonicalRaw || name == "." || strings.HasPrefix(name, "../") || path.IsAbs(name) || strings.Contains(name, "\\") || seenHeaders[rawName] || previousHeader != "" && previousHeader >= rawName {
			return "", fmt.Errorf("source archive path, order, or uniqueness is noncanonical")
		}
		seenHeaders[rawName] = true
		previousHeader = rawName
		parts := strings.Split(name, "/")
		if prefix == "" {
			prefix = parts[0]
		} else if parts[0] != prefix {
			return "", fmt.Errorf("source archive lacks one canonical root")
		}
		if len(parts) == 1 {
			if header.Typeflag != tar.TypeDir || len(entries) != 0 || len(paths) != 0 || header.Mode != 0o755 {
				return "", fmt.Errorf("source archive root is not one canonical directory")
			}
			continue
		}
		relative := strings.Join(parts[1:], "/")
		if header.Typeflag == tar.TypeDir {
			if header.Mode != 0o755 {
				return "", fmt.Errorf("source archive directory mode is noncanonical")
			}
			directories[relative] = true
			continue
		}
		entry := TreeEntry{Path: relative}
		switch header.Typeflag {
		case tar.TypeReg:
			if header.Mode != 0o644 && header.Mode != 0o755 {
				return "", fmt.Errorf("source archive regular mode is noncanonical")
			}
			if header.Size < 0 || header.Size > 64<<20 {
				return "", fmt.Errorf("source archive member is unbounded")
			}
			content, err := io.ReadAll(io.LimitReader(reader, header.Size+1))
			if err != nil || int64(len(content)) != header.Size {
				return "", fmt.Errorf("source archive member changed")
			}
			total += header.Size
			if total > 512<<20 {
				return "", fmt.Errorf("source archive expands beyond bound")
			}
			entry.Type = TreeEntryRegular
			entry.Mode = TreeModeRegular
			if header.Mode&0o111 != 0 {
				entry.Mode = TreeModeExec
			}
			entry.Content = content
		case tar.TypeSymlink:
			if header.Mode != 0o777 || header.Linkname == "" || strings.ContainsRune(header.Linkname, '\x00') {
				return "", fmt.Errorf("source archive symlink is noncanonical")
			}
			entry.Type = TreeEntrySymlink
			entry.Mode = TreeModeSymlink
			entry.Content = []byte(header.Linkname)
		default:
			return "", fmt.Errorf("source archive member type is unsupported")
		}
		paths = append(paths, relative)
		entries = append(entries, entry)
	}
	if prefix == "" {
		return "", fmt.Errorf("source archive root is missing")
	}
	if expectedRoot != "" && prefix != expectedRoot {
		return "", fmt.Errorf("source archive root does not match release tag")
	}
	expectedDirectories := map[string]bool{}
	for _, filePath := range paths {
		for parent := path.Dir(filePath); parent != "."; parent = path.Dir(parent) {
			expectedDirectories[parent] = true
		}
	}
	if !reflect.DeepEqual(directories, expectedDirectories) {
		return "", fmt.Errorf("source archive directory inventory differs from tracked tree")
	}
	trailing, tailErr := io.ReadAll(io.LimitReader(gzipReader, 1))
	if tailErr != nil || len(trailing) != 0 || gzipReader.Close() != nil || compressed.Len() != 0 {
		return "", fmt.Errorf("source archive contains trailing payload")
	}
	inventory, err := NewTrackedInventory(paths)
	if err != nil {
		return "", err
	}
	return SourceTreeDigest(inventory, entries)
}

func writeLengthPrefixed(writer hash.Hash, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write(value)
}
