//go:build linux

// Package persist provides the single versioned, checksummed normal-state
// transaction used by jobs, Plans, and operation intents.
package persist

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/locks"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	SchemaVersion    = "lanpanel.normal.v1"
	maxDocumentBytes = 8 << 20
)

var (
	canonicalNamespaceOwners = map[string]string{
		"installations":      "persist.installations.v1",
		"plans":              "plans.v1",
		"jobs":               "jobs.v1",
		"intents":            "operations.intents.v1",
		"expiry_generations": "operations.expiry.generations.v1",
		"children":           "operations.children.v1",
		"journals":           "operations.journals.v1",
	}
	ErrMissing          = errors.New("normal state is missing")
	ErrRevision         = errors.New("normal state revision mismatch")
	ErrRecoveryRequired = errors.New("normal state transaction requires reconciliation")
	entryPattern        = regexp.MustCompile(`^[a-z][a-z0-9_]*(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,127})$`)
)

type Config struct {
	RootPath      string
	StagingPath   string
	StatePath     string
	Owner         filetxn.Owner
	Fault         filetxn.FaultFunc
	LockAuthority locks.Authority
}

type UnavailableProof struct {
	store     *Store
	authority locks.Authority
	device    uint64
	inode     uint64
	epoch     uint64
}

func (store *Store) ValidateUnavailable(proof UnavailableProof) bool {
	if store == nil {
		return false
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if proof.store != store || proof.authority != store.config.LockAuthority || proof.device != uint64(store.rootStat.Dev) || proof.inode != store.rootStat.Ino || !store.schemaSealed || proof.epoch == 0 || proof.epoch != store.proofEpoch {
		return false
	}
	if !store.uncertain && !store.writeUnavailable {
		if _, err := store.readLocked(); err == nil {
			return false
		}
	}
	if store.writeUnavailable && !store.uncertain {
		store.writeUnavailable = false
	}
	store.proofEpoch++
	return true
}

func (store *Store) SealSchema() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	for namespace, owner := range canonicalNamespaceOwners {
		if store.validators[namespace] == nil || store.namespaceOwners[namespace] != owner {
			return fmt.Errorf("normal store schema registry omits canonical owner for %q", namespace)
		}
	}
	transitionOwners := map[string]bool{}
	for _, owner := range store.documentTransitionValidatorOwners {
		transitionOwners[owner] = true
	}
	if len(store.validators) != len(canonicalNamespaceOwners) || len(store.documentValidators) != 1 || len(store.documentTransitionValidators) != 2 || store.documentValidatorOwners[0] != "operations.links.v1" || !transitionOwners["operations.resource_transitions.v1"] || !transitionOwners["plans.retention.v1"] {
		return fmt.Errorf("normal store schema registry is not canonical")
	}
	store.schemaSealed = true
	return nil
}

func (store *Store) ProveUnavailable() (UnavailableProof, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.schemaSealed {
		return UnavailableProof{}, fmt.Errorf("normal store schema is not sealed")
	}
	if !store.uncertain && !store.writeUnavailable {
		if _, err := store.readLocked(); err == nil {
			return UnavailableProof{}, fmt.Errorf("normal store is available and no durable admission write has failed")
		}
	}
	store.proofEpoch++
	return UnavailableProof{store: store, authority: store.config.LockAuthority, device: uint64(store.rootStat.Dev), inode: store.rootStat.Ino, epoch: store.proofEpoch}, nil
}

type Document struct {
	SchemaVersion string                     `json:"schema_version"`
	Revision      uint64                     `json:"revision"`
	Entries       map[string]json.RawMessage `json:"entries"`
	Checksum      string                     `json:"checksum"`
}

type Transaction struct{ before, entries map[string]json.RawMessage }

func (transaction *Transaction) Get(key string) (json.RawMessage, bool) {
	value, ok := transaction.entries[key]
	return append(json.RawMessage(nil), value...), ok
}

func (transaction *Transaction) Create(key string, value json.RawMessage) error {
	if _, exists := transaction.entries[key]; exists {
		return fmt.Errorf("normal entry %q already exists", key)
	}
	transaction.entries[key] = append(json.RawMessage(nil), value...)
	return nil
}

func (transaction *Transaction) Replace(key string, value json.RawMessage) error {
	if _, exists := transaction.entries[key]; !exists {
		return fmt.Errorf("normal entry %q is missing", key)
	}
	transaction.entries[key] = append(json.RawMessage(nil), value...)
	return nil
}

func (transaction *Transaction) Delete(key string) error {
	if _, exists := transaction.entries[key]; !exists {
		return fmt.Errorf("normal entry %q is missing", key)
	}
	delete(transaction.entries, key)
	return nil
}

func (transaction *Transaction) Keys(namespace string) []string {
	prefix := namespace + "/"
	result := []string{}
	for key := range transaction.entries {
		if strings.HasPrefix(key, prefix) {
			result = append(result, key)
		}
	}
	sort.Strings(result)
	return result
}

type (
	NamespaceValidator          func(key string, value json.RawMessage) error
	TransitionValidator         func(key string, before, after json.RawMessage) error
	DocumentValidator           func(Document) error
	DocumentTransitionValidator func(before, after Document) error
)

type Store struct {
	mu                                sync.Mutex
	config                            Config
	txn                               *filetxn.Store
	rootFD                            int
	rootStat                          unix.Stat_t
	validators                        map[string]NamespaceValidator
	transitions                       map[string]TransitionValidator
	namespaceOwners                   map[string]string
	documentValidators                []DocumentValidator
	documentValidatorOwners           []string
	documentTransitionValidators      []DocumentTransitionValidator
	documentTransitionValidatorOwners []string
	uncertain                         bool
	writeUnavailable                  bool
	schemaSealed                      bool
	proofEpoch                        uint64
}

func Open(config Config) (*Store, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	rootFD, rootStat, err := openRoot(config)
	if err != nil {
		return nil, err
	}
	txn, err := filetxn.Open(filetxn.Config{RootPath: config.RootPath, Root: filetxn.Metadata{Owner: config.Owner, Mode: 0o700}, StagingPath: config.StagingPath, Staging: filetxn.Metadata{Owner: config.Owner, Mode: 0o700}, StagingParents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{config.Owner}, AllowedMode: 0o700}}, filetxn.Options{Fault: config.Fault})
	if err != nil {
		_ = unix.Close(rootFD)
		return nil, err
	}
	return &Store{config: config, txn: txn, rootFD: rootFD, rootStat: rootStat, validators: map[string]NamespaceValidator{"installations": validateInstallationEntry}, transitions: map[string]TransitionValidator{"installations": validateInstallationTransition}, namespaceOwners: map[string]string{"installations": canonicalNamespaceOwners["installations"]}}, nil
}

func (store *Store) RegisterNamespace(namespace string, validator NamespaceValidator, transition TransitionValidator) error {
	return store.registerNamespace(namespace, "", validator, transition)
}

func (store *Store) RegisterCanonicalNamespace(namespace, owner string, validator NamespaceValidator, transition TransitionValidator) error {
	if canonicalNamespaceOwners[namespace] != owner {
		return fmt.Errorf("normal namespace %q canonical owner is invalid", namespace)
	}
	return store.registerNamespace(namespace, owner, validator, transition)
}

func (store *Store) registerNamespace(namespace, owner string, validator NamespaceValidator, transition TransitionValidator) error {
	if namespace == "" || strings.Contains(namespace, "/") || validator == nil {
		return fmt.Errorf("normal namespace registration is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.schemaSealed {
		return fmt.Errorf("normal schema registry is sealed")
	}
	if _, exists := store.validators[namespace]; exists {
		return fmt.Errorf("normal namespace %q is already registered", namespace)
	}
	store.validators[namespace] = validator
	store.namespaceOwners[namespace] = owner
	if transition != nil {
		store.transitions[namespace] = transition
	}
	return nil
}

func (store *Store) NamespaceRegistered(namespace string) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.validators[namespace] != nil
}

func (store *Store) RegisterDocumentValidator(validator DocumentValidator) error {
	return store.registerDocumentValidator("", validator)
}

func (store *Store) RegisterCanonicalDocumentValidator(owner string, validator DocumentValidator) error {
	if owner != "operations.links.v1" {
		return fmt.Errorf("normal document validator canonical owner is invalid")
	}
	return store.registerDocumentValidator(owner, validator)
}

func (store *Store) registerDocumentValidator(owner string, validator DocumentValidator) error {
	if validator == nil {
		return fmt.Errorf("normal document validator is nil")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.schemaSealed {
		return fmt.Errorf("normal schema registry is sealed")
	}
	store.documentValidators = append(store.documentValidators, validator)
	store.documentValidatorOwners = append(store.documentValidatorOwners, owner)
	return nil
}

func (store *Store) DocumentTransitionOwnerRegistered(owner string) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, existing := range store.documentTransitionValidatorOwners {
		if existing == owner {
			return true
		}
	}
	return false
}

func (store *Store) RegisterDocumentTransitionValidator(validator DocumentTransitionValidator) error {
	return store.registerDocumentTransitionValidator("", validator)
}

func (store *Store) RegisterCanonicalDocumentTransitionValidator(owner string, validator DocumentTransitionValidator) error {
	if owner != "operations.resource_transitions.v1" && owner != "plans.retention.v1" {
		return fmt.Errorf("normal document transition validator canonical owner is invalid")
	}
	return store.registerDocumentTransitionValidator(owner, validator)
}

func (store *Store) registerDocumentTransitionValidator(owner string, validator DocumentTransitionValidator) error {
	if validator == nil {
		return fmt.Errorf("normal document transition validator is nil")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.schemaSealed {
		return fmt.Errorf("normal schema registry is sealed")
	}
	for _, existing := range store.documentTransitionValidatorOwners {
		if owner != "" && existing == owner {
			return fmt.Errorf("normal document transition owner %q is already registered", owner)
		}
	}
	store.documentTransitionValidators = append(store.documentTransitionValidators, validator)
	store.documentTransitionValidatorOwners = append(store.documentTransitionValidatorOwners, owner)
	return nil
}

func (store *Store) SchemaSealed() bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.schemaSealed
}

func (store *Store) LockAuthority() locks.Authority {
	if store == nil {
		return locks.Authority{}
	}
	return store.config.LockAuthority
}
func (store *Store) Close() error { return errors.Join(store.txn.Close(), unix.Close(store.rootFD)) }

func (store *Store) Initialize(ctx context.Context, lease *locks.Lease) (filetxn.Result, error) {
	if !store.authorized(lease) {
		return filetxn.Result{}, fmt.Errorf("normal state initialization requires an independent write lock")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.uncertain {
		return filetxn.Result{}, ErrRecoveryRequired
	}
	document := Document{SchemaVersion: SchemaVersion, Revision: 1, Entries: map[string]json.RawMessage{}}
	return store.persist(ctx, document, filetxn.CreateOnly, false)
}

func (store *Store) Read() (Document, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.readLocked()
}

func (store *Store) Reconcile() (Document, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	document, err := store.readLocked()
	if err != nil {
		return Document{}, err
	}
	if err := unix.Fsync(store.rootFD); err != nil {
		return Document{}, err
	}
	store.uncertain = false
	store.writeUnavailable = false
	return document, nil
}

// Update commits all entry mutations as one compare-and-swap transaction.
// The callback must be deterministic and must not retain the supplied map.
func (store *Store) Update(ctx context.Context, lease *locks.Lease, expectedRevision uint64, mutate func(*Transaction) error) (Document, filetxn.Result, error) {
	if !store.authorized(lease) {
		return Document{}, filetxn.Result{}, fmt.Errorf("normal state update requires an independent write lock")
	}
	if mutate == nil {
		return Document{}, filetxn.Result{}, fmt.Errorf("normal state mutator is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.uncertain {
		return Document{}, filetxn.Result{}, ErrRecoveryRequired
	}
	current, err := store.readLocked()
	if err != nil {
		return Document{}, filetxn.Result{}, err
	}
	if current.Revision != expectedRevision {
		return Document{}, filetxn.Result{}, fmt.Errorf("%w: current=%d expected=%d", ErrRevision, current.Revision, expectedRevision)
	}
	entries := cloneEntries(current.Entries)
	transaction := &Transaction{before: cloneEntries(current.Entries), entries: entries}
	if err := mutate(transaction); err != nil {
		return Document{}, filetxn.Result{}, err
	}
	if err := store.validateTypedEntries(entries); err != nil {
		return Document{}, filetxn.Result{}, err
	}
	if err := store.validateEntryTransitions(transaction.before, entries); err != nil {
		return Document{}, filetxn.Result{}, err
	}
	next := Document{SchemaVersion: SchemaVersion, Revision: current.Revision + 1, Entries: entries}
	for _, validator := range store.documentTransitionValidators {
		if err := validator(current, next); err != nil {
			return Document{}, filetxn.Result{}, err
		}
	}
	result, err := store.persist(ctx, next, filetxn.ReplaceOnly, isDurableAdmissionDelta(current.Entries, entries))
	if err != nil {
		return Document{}, result, err
	}
	checksum, _ := documentChecksum(next)
	next.Checksum = checksum
	return next, result, nil
}

func DecodeEntry[T any](document Document, key string) (T, bool, error) {
	var zero T
	raw, present := document.Entries[key]
	if !present {
		return zero, false, nil
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var value T
	if err := decoder.Decode(&value); err != nil {
		return zero, true, fmt.Errorf("decode normal entry %q: %w", key, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return zero, true, fmt.Errorf("normal entry %q has trailing data", key)
	}
	return value, true, nil
}

func EncodeEntry(value any) (json.RawMessage, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > maxDocumentBytes {
		return nil, fmt.Errorf("normal entry is empty or too large")
	}
	return json.RawMessage(data), nil
}

func EntryKeys(document Document, namespace string) []string {
	prefix := namespace + "/"
	keys := make([]string, 0)
	for key := range document.Entries {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func (store *Store) readLocked() (Document, error) {
	if err := store.revalidateRoot(); err != nil {
		return Document{}, err
	}
	fd, err := unix.Openat2(store.rootFD, filepath.Base(store.config.StatePath), &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV})
	if errors.Is(err, unix.ENOENT) {
		return Document{}, ErrMissing
	}
	if err != nil {
		return Document{}, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return Document{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != 0o600 || stat.Uid != store.config.Owner.UID || stat.Gid != store.config.Owner.GID || stat.Nlink != 1 || stat.Size > maxDocumentBytes {
		_ = unix.Close(fd)
		return Document{}, fmt.Errorf("normal state file has unsafe metadata or size")
	}
	file := os.NewFile(uintptr(fd), "normal-state")
	if file == nil {
		return Document{}, fmt.Errorf("wrap normal state descriptor")
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	decoder := json.NewDecoder(io.LimitReader(file, maxDocumentBytes+1))
	decoder.DisallowUnknownFields()
	var document Document
	if err := decoder.Decode(&document); err != nil {
		return Document{}, fmt.Errorf("decode normal state: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Document{}, fmt.Errorf("normal state contains trailing data")
	}
	if err := validateDocument(document); err != nil {
		return Document{}, err
	}
	actual := document.Checksum
	document.Checksum = ""
	expected, err := documentChecksum(document)
	if err != nil {
		return Document{}, err
	}
	if actual != expected {
		return Document{}, fmt.Errorf("normal state checksum mismatch")
	}
	document.Checksum = actual
	if err := store.validateTypedEntries(document.Entries); err != nil {
		return Document{}, err
	}
	return document, nil
}

func (store *Store) persist(ctx context.Context, document Document, disposition filetxn.Disposition, failedAdmissionProofEligible bool) (filetxn.Result, error) {
	if err := store.revalidateRoot(); err != nil {
		return filetxn.Result{}, err
	}
	document.SchemaVersion = SchemaVersion
	document.Checksum = ""
	if err := validateDocument(document); err != nil {
		return filetxn.Result{}, err
	}
	if err := store.validateTypedEntries(document.Entries); err != nil {
		return filetxn.Result{}, err
	}
	checksum, err := documentChecksum(document)
	if err != nil {
		return filetxn.Result{}, err
	}
	document.Checksum = checksum
	data, err := json.Marshal(document)
	if err != nil {
		return filetxn.Result{}, err
	}
	data = append(data, '\n')
	metadata := filetxn.Metadata{Owner: store.config.Owner, Mode: 0o600}
	result, err := store.txn.Put(ctx, filetxn.Request{Path: store.config.StatePath, Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{store.config.Owner}, AllowedMode: 0o700}, Existing: &metadata, New: metadata, MaxBytes: maxDocumentBytes}, data, disposition)
	if err == nil {
		store.writeUnavailable = false
		return result, nil
	}
	if disposition == filetxn.ReplaceOnly && failedAdmissionProofEligible && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		// Only an actual failed write of one new reserved job+intent pair opens
		// the one-use no-normal-store contraction exception.
		store.writeUnavailable = true
		store.proofEpoch++
	}
	if result.State == filetxn.StateDurable {
		loaded, readErr := store.readLocked()
		if readErr == nil && loaded.Revision == document.Revision && loaded.Checksum == document.Checksum {
			store.writeUnavailable = false
			return result, nil
		}
		store.uncertain = true
		return result, fmt.Errorf("%w: durable result mismatch: %v", ErrRecoveryRequired, readErr)
	}
	if result.State == filetxn.StateNamespaceChanged || result.State == filetxn.StateIndeterminate {
		store.uncertain = true
		return result, fmt.Errorf("%w: %v", ErrRecoveryRequired, err)
	}
	return result, err
}

func isDurableAdmissionDelta(before, after map[string]json.RawMessage) bool {
	for key, raw := range after {
		jobID, ok := strings.CutPrefix(key, "intents/")
		if !ok || jobID == "" {
			continue
		}
		if _, existed := before[key]; existed {
			continue
		}
		if _, jobExisted := before["jobs/"+jobID]; jobExisted {
			continue
		}
		if _, jobCreated := after["jobs/"+jobID]; !jobCreated {
			continue
		}
		var intent struct {
			JobID string `json:"job_id"`
			Phase string `json:"phase"`
		}
		if err := json.Unmarshal(raw, &intent); err == nil && intent.JobID == jobID && intent.Phase == "reserved" {
			return true
		}
	}
	return false
}

func validateDocument(document Document) error {
	if document.SchemaVersion != SchemaVersion || document.Revision == 0 || document.Entries == nil {
		return fmt.Errorf("normal state schema, revision, and entries are required")
	}
	return validateEntries(document.Entries)
}

func (store *Store) validateTypedEntries(entries map[string]json.RawMessage) error {
	if err := validateEntries(entries); err != nil {
		return err
	}
	for key, value := range entries {
		namespace, _, ok := strings.Cut(key, "/")
		if !ok {
			return fmt.Errorf("normal entry %q has no namespace", key)
		}
		validator, registered := store.validators[namespace]
		if !registered {
			return fmt.Errorf("normal entry namespace %q is not registered", namespace)
		}
		if err := validator(key, value); err != nil {
			return err
		}
	}
	document := Document{SchemaVersion: SchemaVersion, Revision: 1, Entries: cloneEntries(entries)}
	for _, validator := range store.documentValidators {
		if err := validator(document); err != nil {
			return err
		}
	}
	return nil
}

func (store *Store) validateEntryTransitions(before, after map[string]json.RawMessage) error {
	for key, newValue := range after {
		if _, exists := before[key]; exists {
			continue
		}
		namespace, _, _ := strings.Cut(key, "/")
		if validator := store.transitions[namespace]; validator != nil {
			if err := validator(key, nil, newValue); err != nil {
				return err
			}
		}
	}
	for key, oldValue := range before {
		newValue, exists := after[key]
		if !exists {
			namespace, _, _ := strings.Cut(key, "/")
			validator := store.transitions[namespace]
			if validator == nil {
				return fmt.Errorf("normal entry %q is immutable and cannot be deleted", key)
			}
			if err := validator(key, oldValue, nil); err != nil {
				return err
			}
			continue
		}
		if string(oldValue) == string(newValue) {
			continue
		}
		namespace, _, _ := strings.Cut(key, "/")
		validator := store.transitions[namespace]
		if validator == nil {
			return fmt.Errorf("normal entry %q is immutable", key)
		}
		if err := validator(key, oldValue, newValue); err != nil {
			return err
		}
		if namespace == "installations" && !slices.Contains(store.documentTransitionValidatorOwners, "operations.resource_transitions.v1") {
			if err := rejectUnownedInstallationStateChange(oldValue, newValue); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateInstallationEntry(key string, value json.RawMessage) error {
	if key != "installations/current" {
		return fmt.Errorf("installation entry key is invalid")
	}
	_, err := decodeInstallation(value)
	return err
}

func validateInstallationTransition(_ string, before, after json.RawMessage) error {
	if len(before) == 0 {
		installation, err := decodeInstallation(after)
		if err != nil {
			return err
		}
		for _, resource := range installation.Resources {
			if resource.Lifecycle != domain.LifecycleActive || resource.PublicationRecord.State != domain.PublicationUnpublished || resource.PublicationRecord.UnpublishedGeneration == 0 || resource.PublicationRecord.LastAppliedDigest != nil || resource.PublicationRecord.LastAppliedBundle != nil || resource.PublicationRecord.ActivationIntent != nil || resource.PublicationRecord.RuntimeObservation != nil || resource.PublicationRecord.LastOperation != "" || resource.PublicationRecord.LastOperationResult != "" || resource.PublicationRecord.LastJobID != "" || resource.ManagedProcess != nil && (resource.ManagedProcess.Requested != domain.ProcessRequestedStopped || resource.ManagedProcess.RuntimeObservation != nil) {
				return fmt.Errorf("initial resource must start active, unpublished, unapplied, and stopped with a generation")
			}
		}
		return nil
	}
	oldValue, err := decodeInstallation(before)
	if err != nil {
		return err
	}
	newValue, err := decodeInstallation(after)
	if err != nil {
		return err
	}
	if oldValue.InstallationID != newValue.InstallationID {
		return fmt.Errorf("installation identity is immutable")
	}
	oldResources := map[string]domain.AppResource{}
	for _, resource := range oldValue.Resources {
		oldResources[resource.ID] = resource
	}
	for _, resource := range newValue.Resources {
		if _, exists := oldResources[resource.ID]; exists {
			// Operation-owned lifecycle/publication/process transitions are
			// authorized by the canonical document-transition validator, which
			// can inspect the matching immutable job and intent atomically.
			delete(oldResources, resource.ID)
		} else if resource.Lifecycle != domain.LifecycleActive || resource.PublicationRecord.State != domain.PublicationUnpublished || resource.PublicationRecord.UnpublishedGeneration == 0 || resource.PublicationRecord.LastAppliedDigest != nil || resource.PublicationRecord.LastAppliedBundle != nil || resource.PublicationRecord.ActivationIntent != nil || resource.PublicationRecord.RuntimeObservation != nil || resource.PublicationRecord.LastOperation != "" || resource.PublicationRecord.LastOperationResult != "" || resource.PublicationRecord.LastJobID != "" || resource.ManagedProcess != nil && (resource.ManagedProcess.Requested != domain.ProcessRequestedStopped || resource.ManagedProcess.RuntimeObservation != nil) {
			return fmt.Errorf("new resource must start active, unpublished, unapplied, and stopped with a generation")
		}
	}
	for id, resource := range oldResources {
		if resource.Lifecycle != domain.LifecycleDeleting {
			return fmt.Errorf("resource %q cannot disappear before its deleting tombstone", id)
		}
		// The canonical operation document validator verifies the matching
		// running delete intent/job; this namespace check cannot inspect them.
	}
	return nil
}

func rejectUnownedInstallationStateChange(before, after json.RawMessage) error {
	oldValue, err := decodeInstallation(before)
	if err != nil {
		return err
	}
	newValue, err := decodeInstallation(after)
	if err != nil {
		return err
	}
	oldResources := map[string]domain.AppResource{}
	for _, resource := range oldValue.Resources {
		oldResources[resource.ID] = resource
	}
	for _, resource := range newValue.Resources {
		old, exists := oldResources[resource.ID]
		if exists && (old.Lifecycle != resource.Lifecycle || !reflect.DeepEqual(old.PublicationRecord, resource.PublicationRecord) || !reflect.DeepEqual(old.ManagedProcess, resource.ManagedProcess)) {
			return fmt.Errorf("resource %q lifecycle, applied publication, and process state require an operation intent", resource.ID)
		}
		delete(oldResources, resource.ID)
	}
	if len(oldResources) != 0 {
		return fmt.Errorf("resource removal requires the canonical operation authority")
	}
	return nil
}

func decodeInstallation(value json.RawMessage) (domain.Installation, error) {
	decoder := json.NewDecoder(strings.NewReader(string(value)))
	decoder.DisallowUnknownFields()
	var installation domain.Installation
	if err := decoder.Decode(&installation); err != nil {
		return domain.Installation{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return domain.Installation{}, fmt.Errorf("installation entry has trailing data")
	}
	if err := domain.ValidateInstallation(installation); err != nil {
		return domain.Installation{}, err
	}
	return installation, nil
}

func validateEntries(entries map[string]json.RawMessage) error {
	for key, raw := range entries {
		if !entryPattern.MatchString(key) {
			return fmt.Errorf("normal state entry key %q is invalid", key)
		}
		if len(raw) == 0 || len(raw) > maxDocumentBytes || !json.Valid(raw) {
			return fmt.Errorf("normal state entry %q is invalid", key)
		}
	}
	return nil
}

func documentChecksum(document Document) (string, error) {
	document.Checksum = ""
	data, err := json.Marshal(document)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func cloneEntries(entries map[string]json.RawMessage) map[string]json.RawMessage {
	result := make(map[string]json.RawMessage, len(entries))
	for key, value := range entries {
		result[key] = append(json.RawMessage(nil), value...)
	}
	return result
}

func (store *Store) authorized(lease *locks.Lease) bool {
	return lease != nil && lease.Authority() == store.config.LockAuthority && (lease.Holds(locks.MutationAdmission) || lease.Holds(locks.Exposure))
}

func validateConfig(config Config) error {
	if config.Owner.UID != uint32(os.Geteuid()) || config.Owner.GID != uint32(os.Getegid()) || !config.LockAuthority.Valid() {
		return fmt.Errorf("normal state must be helper-owned")
	}
	for label, path := range map[string]string{"root": config.RootPath, "staging": config.StagingPath, "state": config.StatePath} {
		if path == "" || path != strings.TrimSpace(path) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("normal %s path must be clean and absolute", label)
		}
		if label != "root" && filepath.Dir(path) != config.RootPath {
			return fmt.Errorf("normal %s path must be a direct root child", label)
		}
	}
	return nil
}

func openRoot(config Config) (int, unix.Stat_t, error) {
	fd, err := unix.Open(config.RootPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, unix.Stat_t{}, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, err
	}
	if err := validateRootStat(stat, config.Owner); err != nil {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, err
	}
	return fd, stat, nil
}

func (store *Store) revalidateRoot() error {
	var opened unix.Stat_t
	if err := unix.Fstat(store.rootFD, &opened); err != nil {
		return err
	}
	if err := validateRootStat(opened, store.config.Owner); err != nil || !sameRoot(opened, store.rootStat) {
		return fmt.Errorf("open normal root changed: %w", err)
	}
	var fresh unix.Stat_t
	if err := unix.Lstat(store.config.RootPath, &fresh); err != nil {
		return err
	}
	if err := validateRootStat(fresh, store.config.Owner); err != nil || !sameRoot(fresh, store.rootStat) {
		return fmt.Errorf("configured normal root changed: %w", err)
	}
	return nil
}

func validateRootStat(stat unix.Stat_t, owner filetxn.Owner) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o7777 != 0o700 || stat.Uid != owner.UID || stat.Gid != owner.GID {
		return fmt.Errorf("normal root must be helper-owned mode 0700")
	}
	return nil
}

func sameRoot(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode == right.Mode && left.Uid == right.Uid && left.Gid == right.Gid
}
