package nginx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/filetxn"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	contractionJournalSchema      = "lanpanel.nginx.contraction.v1"
	MaximumContractionJournalSize = 2 * MaximumGraphFileSize
)

type contractionPhase string

const (
	contractionEntriesPending    contractionPhase = "entries_pending"
	contractionManifestPending   contractionPhase = "manifest_pending"
	contractionManifestCommitted contractionPhase = "manifest_committed"
)

type contractionJournal struct {
	SchemaVersion string           `json:"schema_version"`
	Phase         contractionPhase `json:"phase"`
	ResourceIDs   []string         `json:"resource_ids"`
	Candidate     Manifest         `json:"candidate_manifest"`
	Entries       []Entry          `json:"entries"`
}

type contractionOptions struct {
	BeforeDelete         func(int, Entry) error
	BeforeManifestCommit func() error
	AfterManifestCommit  func() error
	GraphFault           filetxn.FaultFunc
	JournalFault         filetxn.FaultFunc
}

type contractionProgress struct {
	candidateCommitted bool
	missing            map[string]bool
}

type ContractionReceipt struct {
	ResourceIDs   []string
	ModifiedPaths []string
	Manifest      Manifest
}

func contractionJournalPath(paths Paths) string {
	return filepath.Join(paths.StateRoot, "contraction.json")
}

func contractionStagingPath(paths Paths) string {
	return filepath.Join(paths.StateRoot, ".lanpanel-contraction-filetxn")
}

// PendingContraction returns the exact candidate graph of an interrupted
// multi-entry contraction. It validates the journal and partial graph without
// requiring the prior manifest's already-removed entries to remain present.
func PendingContraction(paths Paths, owner filetxn.Owner) (Manifest, bool, error) {
	journal, present, err := readContractionJournal(paths, owner)
	if err != nil || !present {
		return Manifest{}, present, err
	}
	if _, err := inspectContractionProgress(paths, owner, journal); err != nil {
		return Manifest{}, true, err
	}
	return journal.Candidate, true, nil
}

func ContractionScope(paths Paths, owner filetxn.Owner) ([]string, bool, error) {
	journal, present, completed, err := readContractionJournalWithCompleted(paths, owner, nil)
	if err != nil {
		return nil, false, err
	}
	if !present && completed != nil {
		journal, present = *completed, true
	}
	if !present {
		return nil, false, nil
	}
	return append([]string(nil), journal.ResourceIDs...), true, nil
}

func TerminalContractionReceipt(paths Paths, owner filetxn.Owner) (ContractionReceipt, bool, error) {
	journal, present, completed, err := readContractionJournalWithCompleted(paths, owner, nil)
	if err != nil {
		return ContractionReceipt{}, false, err
	}
	if !present && completed != nil {
		journal, present = *completed, true
	}
	if !present || journal.Phase != contractionManifestCommitted {
		return ContractionReceipt{}, false, nil
	}
	progress, err := inspectContractionProgress(paths, owner, journal)
	if err != nil || !progress.candidateCommitted {
		return ContractionReceipt{}, false, errors.Join(err, fmt.Errorf("nginx contraction terminal receipt is incomplete"))
	}
	modified := make([]string, 0, len(journal.Entries)+1)
	for _, entry := range journal.Entries {
		modified = append(modified, filepath.Join(paths.ConfigRoot, filepath.FromSlash(entry.Relative)))
	}
	modified = append(modified, paths.ManifestPath())
	slices.Sort(modified)
	return ContractionReceipt{ResourceIDs: append([]string(nil), journal.ResourceIDs...), ModifiedPaths: modified, Manifest: journal.Candidate}, true, nil
}

func requireNoPendingContraction(paths Paths, owner filetxn.Owner) error {
	_, present, completed, err := readContractionJournalWithCompleted(paths, owner, nil)
	if err != nil {
		return err
	}
	if present || completed != nil {
		return fmt.Errorf("pending nginx contraction blocks graph mutation")
	}
	return nil
}

// RecoverContraction finishes only an already-journaled contraction. It never
// infers a new deletion set from a damaged manifest.
func RecoverContraction(ctx context.Context, paths Paths, owner filetxn.Owner) (Manifest, []string, bool, error) {
	journal, present, err := readContractionJournal(paths, owner)
	if err != nil || !present {
		return Manifest{}, nil, present, err
	}
	manifest, modified, err := advanceContraction(ctx, paths, owner, journal, contractionOptions{})
	return manifest, modified, true, err
}

func contract(ctx context.Context, paths Paths, owner filetxn.Owner, resourceIDs []string, options contractionOptions) (Manifest, []string, error) {
	selected, canonicalIDs, err := validateContractionResourceIDs(resourceIDs)
	if err != nil {
		return Manifest{}, nil, err
	}
	modified := []string{}
	pendingJournal, present, completed, readErr := readContractionJournalWithCompleted(paths, owner, nil)
	if readErr != nil {
		return Manifest{}, nil, readErr
	}
	if completed != nil {
		return Manifest{}, nil, fmt.Errorf("unacknowledged nginx contraction receipt blocks contraction")
	}
	if present {
		if !slices.Equal(pendingJournal.ResourceIDs, canonicalIDs) {
			return Manifest{}, nil, fmt.Errorf("pending nginx contraction scope differs from request")
		}
		recoveredManifest, recovered, recoverErr := advanceContraction(ctx, paths, owner, pendingJournal, contractionOptions{})
		modified = appendUniquePaths(modified, recovered...)
		return recoveredManifest, modified, recoverErr
	}
	manifest, err := Audit(paths, owner)
	if err != nil {
		return Manifest{}, modified, err
	}
	if len(selected) == 0 {
		return manifest, modified, nil
	}
	candidate := manifest
	candidate.Entries = make([]Entry, 0, len(manifest.Entries))
	removed := make([]Entry, 0, len(manifest.Entries))
	for _, entry := range manifest.Entries {
		if selected[entry.ResourceID] && entry.Kind != EntryControl {
			removed = append(removed, entry)
			continue
		}
		candidate.Entries = append(candidate.Entries, entry)
	}
	if len(removed) == 0 {
		return manifest, modified, nil
	}
	journal := contractionJournal{SchemaVersion: contractionJournalSchema, Phase: contractionEntriesPending, ResourceIDs: canonicalIDs, Candidate: candidate, Entries: removed}
	if err := validateContractionJournal(journal); err != nil {
		return Manifest{}, modified, err
	}
	if err := createContractionJournal(ctx, paths, owner, journal, options.JournalFault); err != nil {
		return Manifest{}, modified, fmt.Errorf("persist Nginx contraction intent: %w", err)
	}
	contracted, changed, err := advanceContraction(ctx, paths, owner, journal, options)
	modified = appendUniquePaths(modified, changed...)
	return contracted, modified, err
}

func validateContractionResourceIDs(resourceIDs []string) (map[string]bool, []string, error) {
	selected := make(map[string]bool, len(resourceIDs))
	canonical := append([]string(nil), resourceIDs...)
	for _, id := range canonical {
		if !resourcePattern.MatchString(id) || selected[id] {
			return nil, nil, fmt.Errorf("nginx contraction resource inventory is invalid")
		}
		selected[id] = true
	}
	sort.Strings(canonical)
	return selected, canonical, nil
}

func validateContractionJournal(journal contractionJournal) error {
	if journal.SchemaVersion != contractionJournalSchema || len(journal.ResourceIDs) == 0 || len(journal.Entries) == 0 || !slices.IsSorted(journal.ResourceIDs) {
		return fmt.Errorf("nginx contraction journal authority is invalid")
	}
	scope := make(map[string]bool, len(journal.ResourceIDs))
	for index, id := range journal.ResourceIDs {
		if !resourcePattern.MatchString(id) || scope[id] || index > 0 && journal.ResourceIDs[index-1] == id {
			return fmt.Errorf("nginx contraction journal resource inventory is invalid")
		}
		scope[id] = true
	}
	if journal.Phase != contractionEntriesPending && journal.Phase != contractionManifestPending && journal.Phase != contractionManifestCommitted || ValidateManifest(journal.Candidate) != nil || !entriesEqual(journal.Entries, canonicalEntries(journal.Entries)) {
		return fmt.Errorf("nginx contraction journal phase or candidate is invalid")
	}
	for _, entry := range journal.Entries {
		if entry.Kind == EntryControl || !scope[entry.ResourceID] {
			return fmt.Errorf("nginx contraction journal entry leaves exact scope")
		}
	}
	prior := contractionPriorManifest(journal)
	if ValidateManifest(prior) != nil {
		return fmt.Errorf("nginx contraction journal prior graph is invalid")
	}
	removed := make(map[string]bool, len(journal.Entries))
	for _, entry := range journal.Entries {
		removed[entry.Relative] = true
	}
	for _, entry := range prior.Entries {
		shouldRemove := scope[entry.ResourceID] && entry.Kind != EntryControl
		if shouldRemove != removed[entry.Relative] {
			return fmt.Errorf("nginx contraction journal deletion set is incomplete")
		}
	}
	return nil
}

func contractionPriorManifest(journal contractionJournal) Manifest {
	prior := journal.Candidate
	prior.Entries = canonicalEntries(append(append([]Entry(nil), journal.Candidate.Entries...), journal.Entries...))
	return prior
}

func inspectContractionProgress(paths Paths, owner filetxn.Owner, journal contractionJournal) (contractionProgress, error) {
	if err := validateContractionJournal(journal); err != nil {
		return contractionProgress{}, err
	}
	manifestBytes, err := readRegular(paths.ManifestPath(), owner, 0o600, MaximumGraphFileSize)
	if err != nil {
		return contractionProgress{}, err
	}
	current, err := DecodeManifest(manifestBytes)
	if err != nil {
		return contractionProgress{}, err
	}
	if err := reconcileContractionGraphStaging(paths, owner, journal, current); err != nil {
		return contractionProgress{}, err
	}
	prior := contractionPriorManifest(journal)
	progress := contractionProgress{missing: map[string]bool{}}
	switch {
	case sameManifest(current, journal.Candidate):
		if journal.Phase == contractionEntriesPending {
			return contractionProgress{}, fmt.Errorf("nginx contraction manifest advanced before its journal phase")
		}
		if err := auditManifestGraph(paths, owner, journal.Candidate, nil); err != nil {
			return contractionProgress{}, err
		}
		progress.candidateCommitted = true
		for _, entry := range journal.Entries {
			progress.missing[entry.Relative] = true
		}
		return progress, nil
	case sameManifest(current, prior):
		allowedMissing := make(map[string]bool, len(journal.Entries))
		for _, entry := range journal.Entries {
			allowedMissing[entry.Relative] = true
		}
		if err := auditManifestGraph(paths, owner, prior, allowedMissing); err != nil {
			return contractionProgress{}, err
		}
		for _, entry := range journal.Entries {
			_, readErr := readRegular(filepath.Join(paths.ConfigRoot, filepath.FromSlash(entry.Relative)), owner, 0o600, MaximumGraphFileSize)
			if errors.Is(readErr, os.ErrNotExist) {
				progress.missing[entry.Relative] = true
			} else if readErr != nil {
				return contractionProgress{}, readErr
			}
		}
		if journal.Phase == contractionManifestPending && len(progress.missing) != len(journal.Entries) || journal.Phase == contractionManifestCommitted {
			return contractionProgress{}, fmt.Errorf("nginx contraction journal phase is ahead of durable graph progress")
		}
		return progress, nil
	default:
		return contractionProgress{}, fmt.Errorf("nginx contraction manifest is neither the exact prior nor candidate graph")
	}
}

func advanceContraction(ctx context.Context, paths Paths, owner filetxn.Owner, journal contractionJournal, options contractionOptions) (Manifest, []string, error) {
	progress, err := inspectContractionProgress(paths, owner, journal)
	if err != nil {
		return Manifest{}, nil, err
	}
	modified := make([]string, 0, len(journal.Entries))
	for _, entry := range journal.Entries {
		if progress.missing[entry.Relative] {
			modified = appendUniquePaths(modified, filepath.Join(paths.ConfigRoot, filepath.FromSlash(entry.Relative)))
		}
	}
	metadata := filetxn.Metadata{Owner: owner, Mode: 0o600}
	if !progress.candidateCommitted {
		txn, openErr := openGraphTransaction(paths, owner, options.GraphFault)
		if openErr != nil {
			return Manifest{}, modified, openErr
		}
		defer func(ignore func() error) { _ = ignore() }(txn.Close)
		for index, entry := range journal.Entries {
			progress, err = inspectContractionProgress(paths, owner, journal)
			if err != nil {
				return Manifest{}, modified, err
			}
			if progress.missing[entry.Relative] {
				continue
			}
			if options.BeforeDelete != nil {
				if err := options.BeforeDelete(index, entry); err != nil {
					return Manifest{}, modified, err
				}
			}
			path := filepath.Join(paths.ConfigRoot, filepath.FromSlash(entry.Relative))
			result, removeErr := txn.Remove(ctx, filetxn.Request{Path: path, Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o700}, Existing: &metadata, New: metadata, MaxBytes: MaximumGraphFileSize})
			if removeErr != nil || result.State != filetxn.StateDurable {
				return Manifest{}, modified, fmt.Errorf("remove journaled Nginx graph entry %q without rollback: %w", entry.Relative, removeErr)
			}
			modified = appendUniquePaths(modified, path)
		}
		progress, err = inspectContractionProgress(paths, owner, journal)
		if err != nil || len(progress.missing) != len(journal.Entries) {
			return Manifest{}, modified, errors.Join(err, fmt.Errorf("journaled Nginx contraction entries are not durably absent"))
		}
		if journal.Phase == contractionEntriesPending {
			next := journal
			next.Phase = contractionManifestPending
			if err := replaceContractionJournal(ctx, paths, owner, journal, next, options.JournalFault); err != nil {
				return Manifest{}, modified, err
			}
			journal = next
		}
		if options.BeforeManifestCommit != nil {
			if err := options.BeforeManifestCommit(); err != nil {
				return Manifest{}, modified, err
			}
		}
		data, err := EncodeManifest(journal.Candidate)
		if err != nil {
			return Manifest{}, modified, err
		}
		result, putErr := txn.Put(ctx, filetxn.Request{Path: paths.ManifestPath(), Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o700}, Existing: &metadata, New: metadata, MaxBytes: MaximumGraphFileSize}, data, filetxn.ReplaceOnly)
		if putErr != nil || result.State != filetxn.StateDurable {
			return Manifest{}, modified, fmt.Errorf("commit journaled Nginx contraction manifest: %w", putErr)
		}
		if options.AfterManifestCommit != nil {
			if err := options.AfterManifestCommit(); err != nil {
				return Manifest{}, modified, err
			}
		}
	}
	if journal.Phase != contractionManifestCommitted {
		next := journal
		next.Phase = contractionManifestCommitted
		if err := replaceContractionJournal(ctx, paths, owner, journal, next, options.JournalFault); err != nil {
			return Manifest{}, modified, err
		}
		journal = next
	}
	contracted, err := Audit(paths, owner)
	if err != nil || !sameManifest(contracted, journal.Candidate) {
		return Manifest{}, modified, errors.Join(err, fmt.Errorf("final journaled Nginx contraction audit differs"))
	}
	modified = appendUniquePaths(modified, paths.ManifestPath())
	return contracted, modified, nil
}

// AcknowledgeContraction removes only an exact terminal receipt after its
// caller has durably committed the returned modified-path evidence.
func AcknowledgeContraction(ctx context.Context, paths Paths, owner filetxn.Owner, resourceIDs []string) error {
	return acknowledgeContraction(ctx, paths, owner, resourceIDs, nil)
}

func acknowledgeContraction(ctx context.Context, paths Paths, owner filetxn.Owner, resourceIDs []string, fault filetxn.FaultFunc) error {
	selected, canonicalIDs, err := validateContractionResourceIDs(resourceIDs)
	if err != nil || len(selected) == 0 {
		return errors.Join(err, fmt.Errorf("nginx contraction acknowledgement scope is invalid"))
	}
	journal, present, completed, err := readContractionJournalWithCompleted(paths, owner, canonicalIDs)
	if err != nil {
		return err
	}
	if !present {
		if completed != nil && !slices.Equal(completed.ResourceIDs, canonicalIDs) {
			return fmt.Errorf("completed nginx contraction acknowledgement scope changed")
		}
		return nil
	}
	if journal.Phase != contractionManifestCommitted || !slices.Equal(journal.ResourceIDs, canonicalIDs) {
		return fmt.Errorf("nginx contraction terminal receipt differs from acknowledgement")
	}
	progress, err := inspectContractionProgress(paths, owner, journal)
	if err != nil || !progress.candidateCommitted {
		return errors.Join(err, fmt.Errorf("nginx contraction is not terminal for acknowledgement"))
	}
	return removeContractionJournal(ctx, paths, owner, journal, fault)
}

func reconcileContractionGraphStaging(paths Paths, owner filetxn.Owner, journal contractionJournal, current Manifest) error {
	if err := validateGraphBoundary(paths, owner); err != nil {
		return err
	}
	prior := contractionPriorManifest(journal)
	if !sameManifest(current, prior) && !sameManifest(current, journal.Candidate) {
		return fmt.Errorf("nginx contraction staging lacks an exact current manifest")
	}
	items, err := os.ReadDir(paths.StagingPath())
	if err != nil || len(items) == 0 {
		return err
	}
	priorManifest, err := EncodeManifest(prior)
	if err != nil {
		return err
	}
	candidateManifest, err := EncodeManifest(journal.Candidate)
	if err != nil {
		return err
	}
	entryData := make(map[string][][]byte, len(journal.Entries))
	for _, entry := range journal.Entries {
		data, renderErr := RenderEntry(entry)
		if renderErr != nil {
			return renderErr
		}
		base := filepath.Base(entry.Relative)
		entryData[base] = append(entryData[base], data)
	}
	for _, item := range items {
		if item.IsDir() {
			return fmt.Errorf("foreign Nginx graph staging entry %q", item.Name())
		}
		data, readErr := readContractionStagingArtifact(filepath.Join(paths.StagingPath(), item.Name()), owner, MaximumGraphFileSize)
		if readErr != nil {
			return readErr
		}
		matched := false
		for base, expectedValues := range entryData {
			if !contractionStagingName(item.Name(), base, ".lanpanel-remove.") {
				continue
			}
			for _, expected := range expectedValues {
				if bytes.Equal(data, expected) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched && contractionStagingName(item.Name(), ManifestFileName, ".lanpanel-txn.") {
			// Before rename this is an inert, possibly partial candidate; after
			// exchange it is the exact prior manifest. The name, metadata,
			// journal, and still-exact active manifest bind safe cleanup.
			matched = len(data) == 0 || bytes.Equal(data, priorManifest) || bytes.Equal(data, candidateManifest) || sameManifest(current, prior)
		}
		if !matched {
			return fmt.Errorf("unplanned Nginx graph staging entry %q", item.Name())
		}
	}
	// A process may have died after the atomic namespace operation but before
	// filetxn synchronized both directories. Synchronize every bounded graph
	// directory before removing only the exact journal-bound tombstones above.
	for _, directory := range []string{paths.ConfigRoot, paths.StagingPath(), filepath.Join(paths.ConfigRoot, AppsDirectory), filepath.Join(paths.ConfigRoot, ChallengesDirectory), filepath.Join(paths.ConfigRoot, ControlDirectory), filepath.Join(paths.ConfigRoot, TemporaryDirectory)} {
		fd, openErr := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			return openErr
		}
		syncErr := unix.Fsync(fd)
		closeErr := unix.Close(fd)
		if syncErr != nil || closeErr != nil {
			return errors.Join(syncErr, closeErr)
		}
	}
	stagingFD, err := unix.Open(paths.StagingPath(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(stagingFD) }()
	for _, item := range items {
		if err := unix.Unlinkat(stagingFD, item.Name(), 0); err != nil {
			return err
		}
	}
	return unix.Fsync(stagingFD)
}

func readContractionStagingArtifact(path string, owner filetxn.Owner, maximum int64) ([]byte, error) {
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != 0o600 || stat.Uid != owner.UID || stat.Gid != owner.GID || stat.Nlink != 1 || stat.Size < 0 || stat.Size > maximum {
		return nil, fmt.Errorf("nginx contraction staging metadata is unsafe")
	}
	if stat.Size == 0 {
		return []byte{}, nil
	}
	return readRegular(path, owner, 0o600, maximum)
}

func contractionStagingName(name, base, prefix string) bool {
	sum := sha256.Sum256([]byte(base))
	start := prefix + hex.EncodeToString(sum[:8]) + "."
	if !strings.HasPrefix(name, start) || len(name) != len(start)+24 {
		return false
	}
	_, err := hex.DecodeString(name[len(start):])
	return err == nil
}

func sameManifest(left, right Manifest) bool {
	leftBytes, leftErr := EncodeManifest(left)
	rightBytes, rightErr := EncodeManifest(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func encodeContractionJournal(journal contractionJournal) ([]byte, error) {
	if err := validateContractionJournal(journal); err != nil {
		return nil, err
	}
	data, err := json.Marshal(journal)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func decodeContractionJournal(data []byte) (contractionJournal, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var journal contractionJournal
	if err := decoder.Decode(&journal); err != nil {
		return contractionJournal{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return contractionJournal{}, fmt.Errorf("nginx contraction journal has trailing data")
	}
	canonical, err := encodeContractionJournal(journal)
	if err != nil || !bytes.Equal(canonical, data) {
		return contractionJournal{}, fmt.Errorf("nginx contraction journal is noncanonical")
	}
	return journal, nil
}

func validateContractionStateRoot(paths Paths, owner filetxn.Owner) error {
	if err := validatePaths(paths); err != nil {
		return err
	}
	if paths == FixedPaths() {
		if err := validateParentChain(paths.StateRoot); err != nil {
			return err
		}
	}
	return validateDirectory(paths.StateRoot, owner)
}

func readContractionJournal(paths Paths, owner filetxn.Owner) (contractionJournal, bool, error) {
	journal, present, _, err := readContractionJournalWithCompleted(paths, owner, nil)
	return journal, present, err
}

func readContractionJournalWithCompleted(paths Paths, owner filetxn.Owner, completedScope []string) (contractionJournal, bool, *contractionJournal, error) {
	if err := validateContractionStateRoot(paths, owner); err != nil {
		return contractionJournal{}, false, nil, err
	}
	completed, err := reconcileContractionJournalStaging(paths, owner, completedScope)
	if err != nil {
		return contractionJournal{}, false, nil, err
	}
	data, err := readRegular(contractionJournalPath(paths), owner, 0o600, MaximumContractionJournalSize)
	if errors.Is(err, os.ErrNotExist) {
		return contractionJournal{}, false, completed, nil
	}
	if err != nil {
		return contractionJournal{}, false, nil, err
	}
	journal, err := decodeContractionJournal(data)
	return journal, true, completed, err
}

func reconcileContractionJournalStaging(paths Paths, owner filetxn.Owner, completedScope []string) (*contractionJournal, error) {
	staging := contractionStagingPath(paths)
	var stagingStat unix.Stat_t
	if err := unix.Lstat(staging, &stagingStat); errors.Is(err, unix.ENOENT) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if stagingStat.Mode&unix.S_IFMT != unix.S_IFDIR || stagingStat.Uid != owner.UID || stagingStat.Gid != owner.GID || stagingStat.Mode&0o7777 != 0o700 {
		return nil, fmt.Errorf("nginx contraction journal staging metadata is unsafe")
	}
	items, err := os.ReadDir(staging)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		if _, activeErr := readRegular(contractionJournalPath(paths), owner, 0o600, MaximumContractionJournalSize); activeErr == nil {
			return nil, syncContractionDirectory(paths.StateRoot)
		} else if errors.Is(activeErr, os.ErrNotExist) {
			return nil, nil
		} else {
			return nil, activeErr
		}
	}
	activeData, activeErr := readRegular(contractionJournalPath(paths), owner, 0o600, MaximumContractionJournalSize)
	activePresent := activeErr == nil
	if activeErr != nil && !errors.Is(activeErr, os.ErrNotExist) {
		return nil, activeErr
	}
	var active contractionJournal
	if activePresent {
		active, err = decodeContractionJournal(activeData)
		if err != nil {
			return nil, err
		}
	}
	var removed *contractionJournal
	for _, item := range items {
		if item.IsDir() {
			return nil, fmt.Errorf("foreign nginx contraction journal staging entry %q", item.Name())
		}
		data, readErr := readContractionStagingArtifact(filepath.Join(staging, item.Name()), owner, MaximumContractionJournalSize)
		if readErr != nil {
			return nil, readErr
		}
		switch {
		case contractionStagingName(item.Name(), filepath.Base(contractionJournalPath(paths)), ".lanpanel-txn."):
			if len(data) != 0 {
				if staged, decodeErr := decodeContractionJournal(data); decodeErr == nil && activePresent && !sameContractionJournalAuthority(active, staged) {
					return nil, fmt.Errorf("nginx contraction journal staging authority changed")
				}
			}
		case contractionStagingName(item.Name(), filepath.Base(contractionJournalPath(paths)), ".lanpanel-remove."):
			if activePresent {
				return nil, fmt.Errorf("nginx contraction journal removal staging conflicts with an active journal")
			}
			staged, decodeErr := decodeContractionJournal(data)
			if decodeErr != nil || staged.Phase != contractionManifestCommitted {
				return nil, errors.Join(decodeErr, fmt.Errorf("nginx contraction journal removal staging is invalid"))
			}
			if removed != nil && !reflect.DeepEqual(*removed, staged) {
				return nil, fmt.Errorf("nginx contraction journal removal staging is ambiguous")
			}
			copy := staged
			removed = &copy
		default:
			return nil, fmt.Errorf("foreign nginx contraction journal staging entry %q", item.Name())
		}
	}
	if removed != nil {
		if err := auditManifestGraph(paths, owner, removed.Candidate, nil); err != nil {
			return nil, fmt.Errorf("removed nginx contraction journal lacks its exact candidate graph: %w", err)
		}
		if completedScope != nil && !slices.Equal(removed.ResourceIDs, completedScope) {
			return nil, fmt.Errorf("removed nginx contraction journal scope differs from acknowledgement")
		}
	}
	for _, directory := range []string{paths.StateRoot, staging} {
		if err := syncContractionDirectory(directory); err != nil {
			return nil, err
		}
	}
	if removed != nil && completedScope == nil {
		copy := *removed
		return &copy, nil
	}
	stagingFD, err := unix.Open(staging, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(stagingFD) }()
	for _, item := range items {
		if err := unix.Unlinkat(stagingFD, item.Name(), 0); err != nil {
			return nil, err
		}
	}
	if err := unix.Fsync(stagingFD); err != nil {
		return nil, err
	}
	if removed == nil {
		return nil, nil
	}
	copy := *removed
	return &copy, nil
}

func syncContractionDirectory(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	syncErr := unix.Fsync(fd)
	closeErr := unix.Close(fd)
	return errors.Join(syncErr, closeErr)
}

func sameContractionJournalAuthority(left, right contractionJournal) bool {
	left.Phase = ""
	right.Phase = ""
	return reflect.DeepEqual(left, right)
}

func ensureContractionStaging(paths Paths, owner filetxn.Owner) error {
	if err := validateContractionStateRoot(paths, owner); err != nil {
		return err
	}
	staging := contractionStagingPath(paths)
	if filepath.Dir(staging) != paths.StateRoot {
		return fmt.Errorf("nginx contraction staging leaves state root")
	}
	parent, err := unix.Open(paths.StateRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	name := filepath.Base(staging)
	if err := unix.Mkdirat(parent, name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(parent, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != owner.UID || stat.Gid != owner.GID || stat.Mode&0o7777 != 0o700 {
		return fmt.Errorf("nginx contraction staging metadata is unsafe")
	}
	return unix.Fsync(parent)
}

func openContractionStore(paths Paths, owner filetxn.Owner, fault filetxn.FaultFunc) (*filetxn.Store, error) {
	if err := ensureContractionStaging(paths, owner); err != nil {
		return nil, err
	}
	return filetxn.Open(filetxn.Config{RootPath: paths.StateRoot, Root: filetxn.Metadata{Owner: owner, Mode: 0o700}, StagingPath: contractionStagingPath(paths), Staging: filetxn.Metadata{Owner: owner, Mode: 0o700}, StagingParents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o700}}, filetxn.Options{Fault: fault})
}

func openGraphTransaction(paths Paths, owner filetxn.Owner, fault filetxn.FaultFunc) (*filetxn.Store, error) {
	return filetxn.Open(filetxn.Config{RootPath: paths.ConfigRoot, Root: filetxn.Metadata{Owner: owner, Mode: 0o700}, StagingPath: paths.StagingPath(), Staging: filetxn.Metadata{Owner: owner, Mode: 0o700}, StagingParents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o700}}, filetxn.Options{Fault: fault})
}

func createContractionJournal(ctx context.Context, paths Paths, owner filetxn.Owner, journal contractionJournal, fault filetxn.FaultFunc) error {
	data, err := encodeContractionJournal(journal)
	if err != nil {
		return err
	}
	store, err := openContractionStore(paths, owner, fault)
	if err != nil {
		return err
	}
	result, putErr := store.Put(ctx, filetxn.Request{Path: contractionJournalPath(paths), Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o700}, New: filetxn.Metadata{Owner: owner, Mode: 0o600}, MaxBytes: MaximumContractionJournalSize}, data, filetxn.CreateOnly)
	closeErr := store.Close()
	if putErr != nil || result.State != filetxn.StateDurable || closeErr != nil {
		return errors.Join(putErr, closeErr, fmt.Errorf("nginx contraction journal creation was not durable"))
	}
	return nil
}

func replaceContractionJournal(ctx context.Context, paths Paths, owner filetxn.Owner, prior, next contractionJournal, fault filetxn.FaultFunc) error {
	current, present, err := readContractionJournal(paths, owner)
	if err != nil || !present || !reflect.DeepEqual(current, prior) {
		return errors.Join(err, fmt.Errorf("nginx contraction journal changed before phase advance"))
	}
	data, err := encodeContractionJournal(next)
	if err != nil {
		return err
	}
	store, err := openContractionStore(paths, owner, fault)
	if err != nil {
		return err
	}
	metadata := filetxn.Metadata{Owner: owner, Mode: 0o600}
	result, putErr := store.Put(ctx, filetxn.Request{Path: contractionJournalPath(paths), Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o700}, Existing: &metadata, New: metadata, MaxBytes: MaximumContractionJournalSize}, data, filetxn.ReplaceOnly)
	closeErr := store.Close()
	if putErr != nil || result.State != filetxn.StateDurable || closeErr != nil {
		return errors.Join(putErr, closeErr, fmt.Errorf("nginx contraction journal phase was not durable"))
	}
	return nil
}

func removeContractionJournal(ctx context.Context, paths Paths, owner filetxn.Owner, expected contractionJournal, fault filetxn.FaultFunc) error {
	current, present, err := readContractionJournal(paths, owner)
	if err != nil || !present || !reflect.DeepEqual(current, expected) {
		return errors.Join(err, fmt.Errorf("nginx contraction journal changed before completion"))
	}
	store, err := openContractionStore(paths, owner, fault)
	if err != nil {
		return err
	}
	metadata := filetxn.Metadata{Owner: owner, Mode: 0o600}
	result, removeErr := store.Remove(ctx, filetxn.Request{Path: contractionJournalPath(paths), Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o700}, Existing: &metadata, New: metadata, MaxBytes: MaximumContractionJournalSize})
	closeErr := store.Close()
	if removeErr != nil || result.State != filetxn.StateDurable || closeErr != nil {
		return errors.Join(removeErr, closeErr, fmt.Errorf("nginx contraction journal completion was not durable"))
	}
	return nil
}

func appendUniquePaths(paths []string, values ...string) []string {
	seen := make(map[string]bool, len(paths)+len(values))
	for _, path := range paths {
		seen[path] = true
	}
	for _, value := range values {
		if !seen[value] {
			paths = append(paths, value)
			seen[value] = true
		}
	}
	return paths
}
