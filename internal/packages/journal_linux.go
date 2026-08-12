//go:build linux

package packages

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"

	"lanpanel/internal/filetxn"
)

const maximumJournalBytes = 64 << 10

type FileJournalStore struct {
	mu       sync.Mutex
	files    *filetxn.Store
	root     string
	owner    filetxn.Owner
	metadata filetxn.Metadata
	parents  filetxn.DirectoryPolicy
}

func NewFileJournalStore(files *filetxn.Store, root string, owner filetxn.Owner) (*FileJournalStore, error) {
	if files == nil || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, fmt.Errorf("package journal store authority is invalid")
	}
	metadata := filetxn.Metadata{Owner: owner, Mode: 0o600}
	parents := filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o700}
	return &FileJournalStore{files: files, root: root, owner: owner, metadata: metadata, parents: parents}, nil
}

func (store *FileJournalStore) Create(ctx context.Context, journal Journal) error {
	if err := ValidateJournal(journal); err != nil || journal.Phase != JournalPrepared {
		return fmt.Errorf("new package journal is not a valid prepared intent")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	data, err := encodeJournal(journal)
	if err != nil {
		return err
	}
	_, err = store.files.Put(ctx, store.request(journal.TransactionID, nil), data, filetxn.CreateOnly)
	return err
}

func (store *FileJournalStore) Advance(ctx context.Context, before, after Journal) error {
	if err := ValidateJournalTransition(before, after); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	currentBytes, err := store.files.Read(ctx, store.request(before.TransactionID, &store.metadata))
	if err != nil {
		return err
	}
	current, err := decodeJournal(currentBytes)
	if err != nil || !reflect.DeepEqual(current, before) {
		return fmt.Errorf("durable package journal changed before phase advance")
	}
	data, err := encodeJournal(after)
	if err != nil {
		return err
	}
	_, err = store.files.Put(ctx, store.request(after.TransactionID, &store.metadata), data, filetxn.ReplaceOnly)
	return err
}

func (store *FileJournalStore) Pending(ctx context.Context) ([]Journal, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	entries, err := os.ReadDir(store.root)
	if err != nil {
		return nil, fmt.Errorf("enumerate package journals: %w", err)
	}
	if len(entries) > 256 {
		return nil, fmt.Errorf("package journal inventory is unbounded")
	}
	result := []Journal{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			return nil, fmt.Errorf("package journal directory contains an unexpected member")
		}
		transactionID := strings.TrimSuffix(entry.Name(), ".json")
		if !transactionPattern.MatchString(transactionID) {
			return nil, fmt.Errorf("package journal filename is invalid")
		}
		data, err := store.files.Read(ctx, store.request(transactionID, &store.metadata))
		if err != nil {
			return nil, err
		}
		journal, err := decodeJournal(data)
		if err != nil || journal.TransactionID != transactionID {
			return nil, fmt.Errorf("package journal inventory identity mismatch")
		}
		if journal.Phase != JournalCleaned {
			result = append(result, journal)
		}
	}
	slices.SortFunc(result, func(left, right Journal) int { return strings.Compare(left.TransactionID, right.TransactionID) })
	return result, nil
}

func (store *FileJournalStore) Read(ctx context.Context, transactionID string) (Journal, error) {
	if !transactionPattern.MatchString(transactionID) {
		return Journal{}, fmt.Errorf("package transaction ID is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	data, err := store.files.Read(ctx, store.request(transactionID, &store.metadata))
	if err != nil {
		return Journal{}, err
	}
	return decodeJournal(data)
}

func (store *FileJournalStore) request(transactionID string, existing *filetxn.Metadata) filetxn.Request {
	return filetxn.Request{Path: filepath.Join(store.root, transactionID+".json"), Parents: store.parents, Existing: existing, New: store.metadata, MaxBytes: maximumJournalBytes}
}

func encodeJournal(journal Journal) ([]byte, error) {
	data, err := json.Marshal(journal)
	if err != nil || len(data) > maximumJournalBytes {
		return nil, fmt.Errorf("encode bounded package journal")
	}
	return data, nil
}

func decodeJournal(data []byte) (Journal, error) {
	var journal Journal
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&journal); err != nil {
		return Journal{}, fmt.Errorf("decode package journal: %w", err)
	}
	canonical, err := json.Marshal(journal)
	if err != nil || !bytes.Equal(canonical, data) || ValidateJournal(journal) != nil {
		return Journal{}, fmt.Errorf("package journal is noncanonical or invalid")
	}
	return journal, nil
}
