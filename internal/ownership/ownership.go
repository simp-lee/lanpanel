//go:build linux

package ownership

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/locks"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const SchemaVersion = "lanpanel.ownership.v1"

const maxRecordBytes = 1 << 20

var resourceIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

type State string

const (
	Owned             State = "owned"
	OwnershipOrphaned State = "ownership_orphan"
)

type PathKind string

const (
	PathSite      PathKind = "site"
	PathListener  PathKind = "listener"
	PathChallenge PathKind = "challenge"
	PathService   PathKind = "service"
)

type OwnedPath struct {
	Kind           PathKind `json:"kind"`
	Path           string   `json:"path"`
	IdentityDigest string   `json:"identity_digest"`
}

type OwnedListener struct {
	Protocol       string `json:"protocol"`
	Address        string `json:"address"`
	Port           uint16 `json:"port"`
	IdentityDigest string `json:"identity_digest"`
}

type Record struct {
	SchemaVersion string          `json:"schema_version"`
	Revision      uint64          `json:"revision"`
	ResourceID    string          `json:"resource_id"`
	State         State           `json:"state"`
	Paths         []OwnedPath     `json:"paths"`
	Listeners     []OwnedListener `json:"listeners"`
	Checksum      string          `json:"checksum"`
}

type Policy struct {
	ManagedRoots []string
}

func FixedPolicy() Policy {
	return Policy{ManagedRoots: []string{"/etc/lanpanel", "/etc/lanpanel-public", "/var/lib/lanpanel", "/var/log/lanpanel", "/etc/systemd/system", "/etc/sysusers.d", "/run/lanpanel", "/run/lanpanel-goaccess"}}
}

type WriterRole string

const (
	ActivationWriter                WriterRole = "activation_writer"
	GoAccessRetirementWriter        WriterRole = "goaccess_retirement_writer"
	GoAccessCandidateRollbackWriter WriterRole = "goaccess_candidate_rollback_writer"
	ContractionWriter               WriterRole = "contraction_writer"
	DeleteWriter                    WriterRole = "delete_writer"
)

type Config struct {
	RootPath      string
	StagingPath   string
	RecordsPath   string
	Owner         filetxn.Owner
	Policy        Policy
	LockAuthority locks.Authority
}

type Store struct {
	config      Config
	txn         *filetxn.Store
	recordsFD   int
	recordsStat unix.Stat_t
}

type Issue struct {
	Name  string
	Error string
}

type Inventory struct {
	Records         []Record
	FallbackRecords []Record
	Issues          []Issue
	Complete        bool
}

func Open(config Config) (*Store, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	directories := filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{config.Owner}, AllowedMode: 0o700}
	recordsFD, recordsStat, err := openRecordsDirectory(config)
	if err != nil {
		return nil, err
	}
	txn, err := filetxn.Open(filetxn.Config{
		RootPath:       config.RootPath,
		Root:           filetxn.Metadata{Owner: config.Owner, Mode: 0o700},
		StagingPath:    config.StagingPath,
		Staging:        filetxn.Metadata{Owner: config.Owner, Mode: 0o700},
		StagingParents: directories,
	}, filetxn.Options{})
	if err != nil {
		_ = unix.Close(recordsFD)
		return nil, err
	}
	return &Store{config: cloneConfig(config), txn: txn, recordsFD: recordsFD, recordsStat: recordsStat}, nil
}

func (store *Store) Close() error { return errors.Join(store.txn.Close(), unix.Close(store.recordsFD)) }

func (store *Store) Write(ctx context.Context, lease *locks.Lease, role WriterRole, expectedRevision uint64, record Record) (filetxn.Result, error) {
	if lease == nil || lease.Authority() != store.config.LockAuthority || lease.Kind() != locks.Exposure || lease.Validate() != nil {
		return filetxn.Result{}, fmt.Errorf("ownership write requires the shared exposure lock")
	}
	if role != ActivationWriter && role != GoAccessRetirementWriter && role != GoAccessCandidateRollbackWriter && role != ContractionWriter {
		return filetxn.Result{}, fmt.Errorf("ownership writer role %q is not authorized", role)
	}
	if record.State != Owned {
		return filetxn.Result{}, fmt.Errorf("ownership_orphan is a derived read-only classification")
	}
	record.SchemaVersion = SchemaVersion
	record.Checksum = ""
	if record.Revision != expectedRevision+1 {
		return filetxn.Result{}, fmt.Errorf("ownership revision must advance from %d to %d", expectedRevision, expectedRevision+1)
	}
	inventory, err := store.Inventory()
	if err != nil {
		return filetxn.Result{}, err
	}
	if !inventory.Complete {
		return filetxn.Result{}, errors.New("ownership inventory is incomplete")
	}
	for _, other := range inventory.Records {
		if other.ResourceID != record.ResourceID {
			if kind, value, collided := recordCollision(other, record); collided {
				return filetxn.Result{}, fmt.Errorf("ownership %s collision with %q at %q", kind, other.ResourceID, value)
			}
		}
	}
	var disposition filetxn.Disposition
	if expectedRevision == 0 {
		if role == ContractionWriter {
			return filetxn.Result{}, fmt.Errorf("publication contraction cannot create ownership")
		}
		disposition = filetxn.CreateOnly
	} else {
		current, err := store.Read(record.ResourceID)
		if err != nil {
			return filetxn.Result{}, err
		}
		if current.Revision != expectedRevision {
			return filetxn.Result{}, fmt.Errorf("ownership revision changed: current=%d expected=%d", current.Revision, expectedRevision)
		}
		if role == ActivationWriter && !preservesInventory(current, record) {
			return filetxn.Result{}, fmt.Errorf("activation ownership update must preserve the complete prior inventory")
		}
		if role == GoAccessRetirementWriter && !exactGoAccessRetirement(current, record) {
			return filetxn.Result{}, fmt.Errorf("GoAccess retirement ownership delta is not exact")
		}
		if role == GoAccessCandidateRollbackWriter && !exactGoAccessCandidateRollback(current, record) {
			return filetxn.Result{}, fmt.Errorf("GoAccess candidate rollback ownership delta is not exact")
		}
		if role == ContractionWriter && !exactPublicationContraction(current, record) {
			return filetxn.Result{}, fmt.Errorf("publication contraction ownership delta is not exact")
		}
		disposition = filetxn.ReplaceOnly
	}
	if err := Validate(record, store.config.Policy); err != nil {
		return filetxn.Result{}, err
	}
	checksum, err := recordChecksum(record)
	if err != nil {
		return filetxn.Result{}, err
	}
	record.Checksum = checksum
	data, err := json.Marshal(record)
	if err != nil {
		return filetxn.Result{}, err
	}
	data = append(data, '\n')
	metadata := filetxn.Metadata{Owner: store.config.Owner, Mode: 0o600}
	return store.txn.Put(ctx, filetxn.Request{
		Path:     filepath.Join(store.config.RecordsPath, record.ResourceID+".json"),
		Parents:  filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{store.config.Owner}, AllowedMode: 0o700},
		Existing: &metadata, New: metadata, MaxBytes: maxRecordBytes,
	}, data, disposition)
}

func (store *Store) Delete(ctx context.Context, lease *locks.Lease, expected Record) error {
	if store == nil || lease == nil || lease.Authority() != store.config.LockAuthority || !lease.Holds(locks.Exposure) || expected.State != Owned || Validate(expected, store.config.Policy) != nil {
		return fmt.Errorf("ownership delete authority invalid")
	}
	current, err := store.Read(expected.ResourceID)
	if err != nil || !reflect.DeepEqual(current, expected) {
		return fmt.Errorf("ownership delete record changed: %w", err)
	}
	metadata := filetxn.Metadata{Owner: store.config.Owner, Mode: 0o600}
	_, err = store.txn.Remove(ctx, filetxn.Request{Path: filepath.Join(store.config.RecordsPath, expected.ResourceID+".json"), Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{store.config.Owner}, AllowedMode: 0o700}, Existing: &metadata, New: metadata, MaxBytes: maxRecordBytes})
	return err
}

func (store *Store) Read(resourceID string) (Record, error) {
	if !resourceIDPattern.MatchString(resourceID) {
		return Record{}, fmt.Errorf("invalid resource ID")
	}
	return store.readFile(resourceID + ".json")
}

// InventoryAuthority returns the complete checksum authority used by the
// independent safety tree. Any invalid record makes the inventory incomplete;
// callers must contract rather than infer or narrow it.
func (store *Store) InventoryAuthority() (map[string]string, bool, error) {
	inventory, err := store.Inventory()
	if err != nil {
		return nil, false, err
	}
	result := make(map[string]string, len(inventory.Records))
	for _, record := range inventory.Records {
		result[record.ResourceID] = record.Checksum
	}
	return result, inventory.Complete, nil
}

func (store *Store) Inventory() (Inventory, error) {
	if err := store.validateDirectories(); err != nil {
		return Inventory{}, err
	}
	dup, err := unix.Dup(store.recordsFD)
	if err != nil {
		return Inventory{}, err
	}
	if _, err := unix.Seek(dup, 0, 0); err != nil {
		_ = unix.Close(dup)
		return Inventory{}, err
	}
	directory := os.NewFile(uintptr(dup), store.config.RecordsPath)
	if directory == nil {
		_ = unix.Close(dup)
		return Inventory{}, fmt.Errorf("wrap ownership records directory")
	}
	entries, err := directory.ReadDir(-1)
	_ = directory.Close()
	if err != nil {
		return Inventory{}, err
	}
	inventory := Inventory{Complete: true}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".json") || !resourceIDPattern.MatchString(strings.TrimSuffix(name, ".json")) {
			inventory.Complete = false
			inventory.Issues = append(inventory.Issues, Issue{Name: name, Error: "unexpected ownership tree entry"})
			continue
		}
		record, readErr := store.readFile(name)
		if readErr != nil {
			inventory.Complete = false
			inventory.Issues = append(inventory.Issues, Issue{Name: name, Error: readErr.Error()})
			continue
		}
		inventory.Records = append(inventory.Records, record)
	}
	inventory.FallbackRecords = append([]Record(nil), inventory.Records...)
	invalid := map[string]bool{}
	for left := 0; left < len(inventory.Records); left++ {
		for right := left + 1; right < len(inventory.Records); right++ {
			if kind, value, collided := recordCollision(inventory.Records[left], inventory.Records[right]); collided {
				invalid[inventory.Records[left].ResourceID] = true
				invalid[inventory.Records[right].ResourceID] = true
				inventory.Complete = false
				inventory.Issues = append(inventory.Issues, Issue{Name: value, Error: fmt.Sprintf("%s collision between %q and %q", kind, inventory.Records[left].ResourceID, inventory.Records[right].ResourceID)})
			}
		}
	}
	if len(invalid) != 0 {
		kept := inventory.Records[:0]
		for _, record := range inventory.Records {
			if !invalid[record.ResourceID] {
				kept = append(kept, record)
			}
		}
		inventory.Records = kept
	}
	sort.Slice(inventory.Records, func(i, j int) bool { return inventory.Records[i].ResourceID < inventory.Records[j].ResourceID })
	sort.Slice(inventory.Issues, func(i, j int) bool { return inventory.Issues[i].Name < inventory.Issues[j].Name })
	return inventory, nil
}

func Classify(record Record, configPresent bool) Record {
	copy := record
	if !configPresent {
		copy.State = OwnershipOrphaned
	}
	copy.Checksum = ""
	return copy
}

func Validate(record Record, policy Policy) error {
	if record.SchemaVersion != SchemaVersion {
		return fmt.Errorf("ownership schema version %q is unsupported", record.SchemaVersion)
	}
	if record.Revision == 0 || !resourceIDPattern.MatchString(record.ResourceID) {
		return fmt.Errorf("ownership revision and resource ID are required")
	}
	if record.State != Owned {
		return fmt.Errorf("persisted ownership state %q is unsupported", record.State)
	}
	if len(record.Paths) == 0 && len(record.Listeners) == 0 {
		return fmt.Errorf("ownership record must identify at least one path or listener")
	}
	roots, err := validatePolicy(policy)
	if err != nil {
		return err
	}
	seen := map[string]struct{}{}
	for index, owned := range record.Paths {
		switch owned.Kind {
		case PathSite, PathListener, PathChallenge, PathService:
		default:
			return fmt.Errorf("paths[%d] kind %q is unsupported", index, owned.Kind)
		}
		if err := validateManagedPath(owned.Path, roots); err != nil {
			return fmt.Errorf("paths[%d]: %w", index, err)
		}
		if owned.IdentityDigest != PathIdentity(record.ResourceID, owned.Kind, owned.Path) {
			return fmt.Errorf("paths[%d] identity digest does not match the canonical owned path", index)
		}
		key := "path:" + owned.Path
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("duplicate ownership identity %s", owned.Path)
		}
		seen[key] = struct{}{}
	}
	for index, listener := range record.Listeners {
		if listener.Protocol != "tcp" && listener.Protocol != "udp" {
			return fmt.Errorf("listeners[%d] protocol is unsupported", index)
		}
		address, err := netip.ParseAddr(listener.Address)
		if err != nil || address.String() != listener.Address || listener.Port == 0 || listener.IdentityDigest != ListenerIdentity(record.ResourceID, listener.Protocol, listener.Address, listener.Port) {
			return fmt.Errorf("listeners[%d] identity is invalid or non-canonical", index)
		}
		key := fmt.Sprintf("listener:%s:%s:%d", listener.Protocol, listener.Address, listener.Port)
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("duplicate ownership identity %s", key)
		}
		seen[key] = struct{}{}
	}
	if record.Checksum != "" {
		actual := record.Checksum
		copy := record
		copy.Checksum = ""
		expected, err := recordChecksum(copy)
		if err != nil {
			return err
		}
		if actual != expected {
			return fmt.Errorf("ownership record checksum mismatch")
		}
	}
	return nil
}

func (store *Store) readFile(name string) (Record, error) {
	if err := store.validateDirectories(); err != nil {
		return Record{}, err
	}
	fd, err := unix.Openat2(store.recordsFD, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return Record{}, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return Record{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != 0o600 || stat.Uid != store.config.Owner.UID || stat.Gid != store.config.Owner.GID || stat.Nlink != 1 || stat.Size > maxRecordBytes {
		_ = unix.Close(fd)
		return Record{}, fmt.Errorf("ownership record %s has unsafe type, owner, mode, links, or size", name)
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return Record{}, fmt.Errorf("wrap ownership record descriptor")
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	decoder := json.NewDecoder(io.LimitReader(file, maxRecordBytes+1))
	decoder.DisallowUnknownFields()
	var record Record
	if err := decoder.Decode(&record); err != nil {
		return Record{}, fmt.Errorf("decode ownership record %s: %w", name, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Record{}, fmt.Errorf("ownership record %s contains trailing data", name)
	}
	if record.ResourceID+".json" != name {
		return Record{}, fmt.Errorf("ownership filename does not match resource ID")
	}
	if err := Validate(record, store.config.Policy); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (store *Store) validateDirectories() error {
	var opened unix.Stat_t
	if err := unix.Fstat(store.recordsFD, &opened); err != nil {
		return err
	}
	if err := validateRecordsStat(opened, store.config.Owner); err != nil || !sameDirectory(opened, store.recordsStat) {
		return fmt.Errorf("open ownership records directory changed: %w", err)
	}
	var fresh unix.Stat_t
	if err := unix.Lstat(store.config.RecordsPath, &fresh); err != nil {
		return err
	}
	if err := validateRecordsStat(fresh, store.config.Owner); err != nil || !sameDirectory(fresh, store.recordsStat) {
		return fmt.Errorf("configured ownership records directory changed: %w", err)
	}
	return nil
}

func validateConfig(config Config) error {
	if config.Owner.UID != uint32(os.Geteuid()) || config.Owner.GID != uint32(os.Getegid()) {
		return fmt.Errorf("ownership tree must be helper-owned")
	}
	if !config.LockAuthority.Valid() {
		return fmt.Errorf("ownership store requires the installation lock authority")
	}
	for label, path := range map[string]string{"root": config.RootPath, "staging": config.StagingPath, "records": config.RecordsPath} {
		if path == "" || path != strings.TrimSpace(path) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("ownership %s path must be clean and absolute", label)
		}
		if label != "root" && filepath.Dir(path) != config.RootPath {
			return fmt.Errorf("ownership %s path must be a direct root child", label)
		}
	}
	_, err := validatePolicy(config.Policy)
	return err
}

func validatePolicy(policy Policy) ([]string, error) {
	if len(policy.ManagedRoots) == 0 {
		return nil, fmt.Errorf("at least one managed ownership root is required")
	}
	roots := append([]string(nil), policy.ManagedRoots...)
	sort.Strings(roots)
	for index, root := range roots {
		if root == "" || root != strings.TrimSpace(root) || !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
			return nil, fmt.Errorf("managed root %q must be a non-root clean absolute path", root)
		}
		if index > 0 && (root == roots[index-1] || strings.HasPrefix(root, roots[index-1]+string(filepath.Separator))) {
			return nil, fmt.Errorf("managed roots overlap")
		}
	}
	return roots, nil
}

func validateManagedPath(path string, roots []string) error {
	if path == "" || path != strings.TrimSpace(path) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("managed path must be clean and absolute")
	}
	for _, root := range roots {
		relative, err := filepath.Rel(root, path)
		if err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return nil
		}
	}
	return fmt.Errorf("managed path is outside fixed ownership roots")
}

func PathIdentity(resourceID string, kind PathKind, path string) string {
	return identityDigest("path\x00" + resourceID + "\x00" + string(kind) + "\x00" + path)
}

func ListenerIdentity(resourceID, protocol, address string, port uint16) string {
	return identityDigest(fmt.Sprintf("listener\x00%s\x00%s\x00%s\x00%d", resourceID, protocol, address, port))
}

func identityDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func recordCollision(left, right Record) (string, string, bool) {
	paths := map[string]struct{}{}
	for _, item := range left.Paths {
		paths[item.Path] = struct{}{}
	}
	for _, item := range right.Paths {
		for path := range paths {
			if path == item.Path || strings.HasPrefix(path, item.Path+string(filepath.Separator)) || strings.HasPrefix(item.Path, path+string(filepath.Separator)) {
				return "path", item.Path, true
			}
		}
	}
	for _, leftListener := range left.Listeners {
		leftAddress, _ := netip.ParseAddr(leftListener.Address)
		for _, rightListener := range right.Listeners {
			rightAddress, _ := netip.ParseAddr(rightListener.Address)
			if leftListener.Protocol == rightListener.Protocol && leftListener.Port == rightListener.Port && (leftAddress == rightAddress || leftAddress.IsUnspecified() || rightAddress.IsUnspecified()) {
				return "listener", fmt.Sprintf("%s|%s|%d", rightListener.Protocol, rightListener.Address, rightListener.Port), true
			}
		}
	}
	return "", "", false
}

func preservesInventory(current, next Record) bool {
	paths := map[string]struct{}{}
	for _, owned := range next.Paths {
		paths[string(owned.Kind)+"\x00"+owned.Path+"\x00"+owned.IdentityDigest] = struct{}{}
	}
	for _, owned := range current.Paths {
		if _, ok := paths[string(owned.Kind)+"\x00"+owned.Path+"\x00"+owned.IdentityDigest]; !ok {
			return false
		}
	}
	listeners := map[string]struct{}{}
	for _, owned := range next.Listeners {
		listeners[fmt.Sprintf("%s\x00%s\x00%d\x00%s", owned.Protocol, owned.Address, owned.Port, owned.IdentityDigest)] = struct{}{}
	}
	for _, owned := range current.Listeners {
		if _, ok := listeners[fmt.Sprintf("%s\x00%s\x00%d\x00%s", owned.Protocol, owned.Address, owned.Port, owned.IdentityDigest)]; !ok {
			return false
		}
	}
	return true
}

func exactPublicationContraction(current, next Record) bool {
	if current.ResourceID != next.ResourceID || current.State != next.State || len(next.Listeners) != 0 {
		return false
	}
	retained := map[string]OwnedPath{}
	servicePath := false
	for _, path := range current.Paths {
		if path.Kind == PathSite || path.Kind == PathListener {
			continue
		}
		servicePath = servicePath || path.Kind == PathService
		retained[string(path.Kind)+"\x00"+path.Path+"\x00"+path.IdentityDigest] = path
	}
	for _, path := range next.Paths {
		if path.Kind == PathSite || path.Kind == PathListener {
			return false
		}
		key := string(path.Kind) + "\x00" + path.Path + "\x00" + path.IdentityDigest
		if _, ok := retained[key]; !ok {
			return false
		}
		delete(retained, key)
	}
	return len(retained) == 0 && servicePath
}

func exactGoAccessRetirement(current, next Record) bool {
	if current.ResourceID != next.ResourceID || current.State != next.State || len(current.Listeners) != len(next.Listeners) {
		return false
	}
	currentPaths := map[string]OwnedPath{}
	for _, path := range current.Paths {
		currentPaths[string(path.Kind)+"\x00"+path.Path+"\x00"+path.IdentityDigest] = path
	}
	nextPaths := map[string]bool{}
	for _, path := range next.Paths {
		key := string(path.Kind) + "\x00" + path.Path + "\x00" + path.IdentityDigest
		if _, present := currentPaths[key]; !present {
			return false
		}
		nextPaths[key] = true
	}
	removed := map[string]bool{}
	for key, path := range currentPaths {
		if !nextPaths[key] {
			removed[path.Path] = true
		}
	}
	listenerKey := func(value OwnedListener) string {
		return fmt.Sprintf("%s\x00%s\x00%d\x00%s", value.Protocol, value.Address, value.Port, value.IdentityDigest)
	}
	listeners := map[string]bool{}
	for _, value := range current.Listeners {
		listeners[listenerKey(value)] = true
	}
	for _, value := range next.Listeners {
		if !listeners[listenerKey(value)] {
			return false
		}
	}
	endpointPrefix := "/run/lanpanel-goaccess/" + current.ResourceID + "-"
	generation := uint64(0)
	for path := range removed {
		if strings.HasPrefix(path, endpointPrefix) && strings.HasSuffix(path, ".sock") {
			value, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(path, endpointPrefix), ".sock"), 10, 64)
			if err != nil || value == 0 || generation != 0 {
				return false
			}
			generation = value
		}
	}
	if generation == 0 {
		return false
	}
	unitID := current.ResourceID + "-" + strconv.FormatUint(generation, 10)
	expected := map[string]bool{"/etc/systemd/system/lanpanel-goaccess-" + unitID + ".service": true, "/etc/systemd/system/multi-user.target.wants/lanpanel-goaccess-" + unitID + ".service": true, "/etc/systemd/system/lanpanel-goaccess-relay-" + unitID + ".service": true, "/etc/systemd/system/multi-user.target.wants/lanpanel-goaccess-relay-" + unitID + ".service": true, "/etc/systemd/system/lanpanel-goaccess-" + unitID + ".socket": true, "/etc/systemd/system/sockets.target.wants/lanpanel-goaccess-" + unitID + ".socket": true, "/etc/systemd/system/lanpanel-goaccess-retention-" + unitID + ".service": true, "/etc/systemd/system/lanpanel-goaccess-retention-" + unitID + ".timer": true, "/etc/systemd/system/timers.target.wants/lanpanel-goaccess-retention-" + unitID + ".timer": true, "/run/lanpanel-goaccess/" + unitID + ".sock": true}
	statePrefix := "/var/lib/lanpanel/goaccess/" + current.ResourceID + "/generations/"
	stateRoot := ""
	for path := range removed {
		if !strings.HasPrefix(path, statePrefix) {
			continue
		}
		stateGeneration, err := strconv.ParseUint(strings.TrimPrefix(path, statePrefix), 10, 64)
		if err != nil || stateGeneration == 0 || stateGeneration > generation || stateRoot != "" {
			return false
		}
		stateRoot = path
	}
	if stateRoot != "" {
		expected[stateRoot] = true
	}
	if len(removed) != len(expected) {
		return false
	}
	for path := range expected {
		if !removed[path] {
			return false
		}
	}
	return true
}

func exactGoAccessCandidateRollback(current, next Record) bool {
	shared := map[string]bool{"/etc/sysusers.d/lanpanel-goaccess-" + current.ResourceID + ".conf": true, "/var/log/lanpanel/goaccess/" + current.ResourceID: true, "/var/log/lanpanel/goaccess/" + current.ResourceID + "/.retention.lock": true}
	middle := current
	middle.Paths = make([]OwnedPath, 0, len(current.Paths))
	seen := map[string]bool{}
	for _, path := range current.Paths {
		if shared[path.Path] {
			seen[path.Path] = true
			continue
		}
		middle.Paths = append(middle.Paths, path)
	}
	if len(seen) != len(shared) {
		return false
	}
	for _, path := range next.Paths {
		if shared[path.Path] {
			return false
		}
	}
	return exactGoAccessRetirement(middle, next)
}

func openRecordsDirectory(config Config) (int, unix.Stat_t, error) {
	fd, err := unix.Open(config.RecordsPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, unix.Stat_t{}, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, err
	}
	if err := validateRecordsStat(stat, config.Owner); err != nil {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, err
	}
	return fd, stat, nil
}

func validateRecordsStat(stat unix.Stat_t, owner filetxn.Owner) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o7777 != 0o700 || stat.Uid != owner.UID || stat.Gid != owner.GID {
		return fmt.Errorf("ownership records directory must be helper-owned mode 0700")
	}
	return nil
}

func sameDirectory(actual, expected unix.Stat_t) bool {
	return actual.Dev == expected.Dev && actual.Ino == expected.Ino && actual.Mode == expected.Mode && actual.Uid == expected.Uid && actual.Gid == expected.Gid
}

func recordChecksum(record Record) (string, error) {
	data, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func cloneConfig(config Config) Config {
	copy := config
	copy.Policy.ManagedRoots = append([]string(nil), config.Policy.ManagedRoots...)
	return copy
}
