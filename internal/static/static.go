package staticcontent

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	maximumEntries = 10_000
	maximumBytes   = int64(256 << 20)
)

type RootIdentity struct {
	ID          string `json:"id"`
	Path        string `json:"path"`
	Fingerprint string `json:"fingerprint"`
	Device      uint64 `json:"device"`
}
type Mapping struct {
	URLPath      string `json:"url_path"`
	RelativePath string `json:"relative_path"`
	Directory    bool   `json:"directory"`
	Anonymous    bool   `json:"anonymous,omitempty"`
}
type MappingIdentity struct {
	Mapping     Mapping `json:"mapping"`
	SourcePath  string  `json:"source_path"`
	Fingerprint string  `json:"fingerprint"`
}

var idPattern = regexp.MustCompile(`^static_[0-9a-f]{32}$`)

func Register(id, path string, forbidden []string) (RootIdentity, error) {
	if !idPattern.MatchString(id) || !cleanAbsolute(path) {
		return RootIdentity{}, fmt.Errorf("static root identity invalid")
	}
	for _, value := range forbidden {
		if cleanAbsolute(value) && (path == value || strings.HasPrefix(path, value+string(filepath.Separator)) || strings.HasPrefix(value, path+string(filepath.Separator))) {
			return RootIdentity{}, fmt.Errorf("static root overlaps protected inventory")
		}
	}
	if err := validateRoot(path); err != nil {
		return RootIdentity{}, err
	}
	if err := rejectMounts(path); err != nil {
		return RootIdentity{}, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return RootIdentity{}, err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return RootIdentity{}, err
	}
	sum := sha256.Sum256([]byte(path + "\x00" + fmt.Sprint(stat.Dev) + "\x00" + fmt.Sprint(stat.Ino)))
	return RootIdentity{ID: id, Path: path, Fingerprint: "sha256:" + hex.EncodeToString(sum[:]), Device: uint64(stat.Dev)}, nil
}

func ValidateMappings(root RootIdentity, mappings []Mapping) ([]MappingIdentity, error) {
	if !idPattern.MatchString(root.ID) || !cleanAbsolute(root.Path) || len(mappings) > 128 {
		return nil, fmt.Errorf("static mapping authority invalid")
	}
	observed, err := Register(root.ID, root.Path, nil)
	if err != nil {
		return nil, err
	}
	if observed.Fingerprint != root.Fingerprint || observed.Device != root.Device {
		return nil, fmt.Errorf("static root identity changed")
	}
	rootFD, err := unix.Open(root.Path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(rootFD)
	var rootStat unix.Stat_t
	if unix.Fstat(rootFD, &rootStat) != nil {
		return nil, fmt.Errorf("static root descriptor invalid")
	}
	rootSum := sha256.Sum256([]byte(root.Path + "\x00" + fmt.Sprint(rootStat.Dev) + "\x00" + fmt.Sprint(rootStat.Ino)))
	if "sha256:"+hex.EncodeToString(rootSum[:]) != root.Fingerprint || uint64(rootStat.Dev) != root.Device {
		return nil, fmt.Errorf("static root descriptor identity changed")
	}
	result := make([]MappingIdentity, len(mappings))
	prior := ""
	count, total := 0, int64(0)
	for index, mapping := range mappings {
		if !validURLPath(mapping.URLPath, mapping.Directory) || !cleanRelative(mapping.RelativePath) || prior != "" && prior >= mapping.URLPath {
			return nil, fmt.Errorf("static mapping noncanonical")
		}
		prior = mapping.URLPath
		fd, stat, err := openRelative(rootFD, mapping.RelativePath, mapping.Directory, root.Device)
		if err != nil {
			return nil, err
		}
		h := sha256.New()
		err = inventoryFD(fd, mapping.RelativePath, root.Device, h, &count, &total)
		unix.Close(fd)
		if err != nil {
			return nil, err
		}
		typeBits := uint32(stat.Mode) & unix.S_IFMT
		if mapping.Directory != (typeBits == unix.S_IFDIR) {
			return nil, fmt.Errorf("static mapping source type invalid")
		}
		result[index] = MappingIdentity{Mapping: mapping, SourcePath: filepath.Join(root.Path, filepath.FromSlash(mapping.RelativePath)), Fingerprint: "sha256:" + hex.EncodeToString(h.Sum(nil))}
	}
	return result, nil
}

func openRelative(rootFD int, relative string, directory bool, device uint64) (int, unix.Stat_t, error) {
	parts := strings.Split(filepath.ToSlash(relative), "/")
	current, err := unix.Dup(rootFD)
	if err != nil {
		return -1, unix.Stat_t{}, err
	}
	for index, part := range parts {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if index < len(parts)-1 || directory {
			flags |= unix.O_DIRECTORY
		}
		next, openErr := unix.Openat(current, part, flags, 0)
		unix.Close(current)
		if openErr != nil {
			return -1, unix.Stat_t{}, fmt.Errorf("static mapping openat failed: %w", openErr)
		}
		if index < len(parts)-1 || directory {
			var component unix.Stat_t
			if unix.Fstat(next, &component) != nil || component.Mode&unix.S_IFMT != unix.S_IFDIR || uint64(component.Dev) != device || component.Uid != 0 || component.Mode&0o022 != 0 || component.Mode&0o005 != 0o005 {
				unix.Close(next)
				return -1, unix.Stat_t{}, fmt.Errorf("static mapping parent ownership or mode unsafe")
			}
		}
		current = next
	}
	var stat unix.Stat_t
	if err := unix.Fstat(current, &stat); err != nil {
		unix.Close(current)
		return -1, unix.Stat_t{}, err
	}
	return current, stat, nil
}

func inventoryFD(fd int, name string, device uint64, h hash.Hash, count *int, total *int64) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if uint64(stat.Dev) != device {
		return fmt.Errorf("static mapping crossed mount")
	}
	kind := uint32(stat.Mode) & unix.S_IFMT
	switch kind {
	case unix.S_IFREG:
		if stat.Uid != 0 || stat.Nlink != 1 || stat.Mode&0o004 == 0 || stat.Mode&0o022 != 0 {
			return fmt.Errorf("static file ownership or link unsafe")
		}
		*total += stat.Size
		if *total > maximumBytes {
			return fmt.Errorf("static mapping bytes oversized")
		}
		fmt.Fprintf(h, "f\x00%s\x00%d\x00%d\x00%d\x00%d\x00", name, stat.Ino, stat.Size, stat.Mtim.Sec, stat.Mtim.Nsec)
		duplicate, err := unix.Dup(fd)
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(duplicate), "static-file")
		if _, seekErr := file.Seek(0, 0); seekErr != nil {
			file.Close()
			return seekErr
		}
		written, copyErr := io.Copy(h, file)
		var after unix.Stat_t
		statErr := unix.Fstat(fd, &after)
		file.Close()
		if copyErr != nil {
			return copyErr
		}
		if statErr != nil || written != stat.Size || after.Dev != stat.Dev || after.Ino != stat.Ino || after.Size != stat.Size || after.Mtim != stat.Mtim {
			return fmt.Errorf("static file changed while reading")
		}
		h.Write([]byte{'\n'})
	case unix.S_IFDIR:
		if stat.Uid != 0 || stat.Mode&0o005 != 0o005 || stat.Mode&0o022 != 0 {
			return fmt.Errorf("static directory mode unsafe")
		}
		fmt.Fprintf(h, "d\x00%s\x00%d\x00%d\x00%d\n", name, stat.Ino, stat.Mtim.Sec, stat.Mtim.Nsec)
		duplicate, err := unix.Dup(fd)
		if err != nil {
			return err
		}
		directory := os.NewFile(uintptr(duplicate), "static-directory")
		entries, err := directory.ReadDir(-1)
		directory.Close()
		if err != nil {
			return err
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			*count++
			if *count > maximumEntries {
				return fmt.Errorf("static mapping inventory oversized")
			}
			child, err := unix.Openat(fd, entry.Name(), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
			if err != nil {
				return fmt.Errorf("static descendant openat failed: %w", err)
			}
			childName := name + "/" + entry.Name()
			err = inventoryFD(child, childName, device, h, count, total)
			unix.Close(child)
			if err != nil {
				return err
			}
		}
		var after unix.Stat_t
		if unix.Fstat(fd, &after) != nil || after.Dev != stat.Dev || after.Ino != stat.Ino || after.Mtim != stat.Mtim {
			return fmt.Errorf("static directory changed while reading")
		}
	default:
		return fmt.Errorf("static mapping special file rejected")
	}
	return nil
}

func rejectMounts(root string) error {
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}
		mount := decodeMountPath(fields[4])
		if mount == root || strings.HasPrefix(mount, root+string(filepath.Separator)) {
			return fmt.Errorf("static root contains mount point")
		}
	}
	return scanner.Err()
}
func decodeMountPath(value string) string {
	for encoded, decoded := range map[string]string{"\\040": " ", "\\011": "\t", "\\012": "\n", "\\134": "\\"} {
		value = strings.ReplaceAll(value, encoded, decoded)
	}
	return value
}
func validateRoot(path string) error {
	current := path
	for {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("static root parent unsafe")
		}
		stat, ok := info.Sys().(*unix.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o005 != 0o005 {
			return fmt.Errorf("static root parent ownership or mode unsafe")
		}
		if current == "/" {
			return nil
		}
		current = filepath.Dir(current)
	}
}
func validURLPath(value string, directory bool) bool {
	if value == "" || value[0] != '/' || strings.ContainsAny(value, "?#\\%\x00\r\n \t;{}$\"'") || filepath.Clean(value) != strings.TrimSuffix(value, "/") {
		return false
	}
	if directory != (value != "/" && strings.HasSuffix(value, "/")) {
		return false
	}
	parts := strings.Split(strings.Trim(value, "/"), "/")
	return value == "/" || !slices.Contains(parts, "") && !slices.Contains(parts, ".") && !slices.Contains(parts, "..")
}
func noControls(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}
func cleanRelative(value string) bool {
	return value != "" && !filepath.IsAbs(value) && filepath.Clean(value) == value && !strings.HasPrefix(value, "..") && !strings.Contains(value, "\\") && noControls(value)
}
func cleanAbsolute(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && value != "/" && noControls(value)
}
