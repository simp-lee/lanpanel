//go:build linux

package headscale

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/release"
	"lanpanel/internal/sources"
	"os"
	"path/filepath"
	"reflect"
	"slices"

	"golang.org/x/sys/unix"
)

const initializationJournalSchema = "lanpanel.headscale.initialization-journal.v1"

type InitializationJournal struct {
	SchemaVersion  string                 `json:"schema_version"`
	Candidate      domain.HeadscaleDomain `json:"candidate"`
	JobID          string                 `json:"job_id"`
	Source         sources.Source         `json:"source"`
	ProxyURL       string                 `json:"proxy_url,omitempty"`
	FreshValidated bool                   `json:"fresh_validated"`
	ArchiveDigest  string                 `json:"archive_digest"`
	Snapshot       json.RawMessage        `json:"snapshot"`
	SnapshotDigest string                 `json:"snapshot_digest"`
}

func BuildInitializationJournal(candidate domain.HeadscaleDomain, installed release.InstallIdentity, snapshot []byte, jobID string, source sources.Source, proxyURL string) (InitializationJournal, []byte, error) {
	artifact, err := ArtifactIdentity(installed)
	if err != nil || candidate.Artifact != artifact {
		return InitializationJournal{}, nil, fmt.Errorf("headscale candidate release authority mismatched")
	}
	if err := VerifySnapshot(candidate, snapshot); err != nil {
		return InitializationJournal{}, nil, err
	}
	var proxy *sources.Proxy
	if proxyURL != "" {
		proxy = &sources.Proxy{URL: proxyURL}
	}
	if !attemptPattern.MatchString(jobID) || validateJournalSource(installed, source) != nil || sources.ValidateProxy(proxy) != nil {
		return InitializationJournal{}, nil, fmt.Errorf("headscale acquisition journal authority is invalid")
	}
	digest := sha256.Sum256(snapshot)
	value := InitializationJournal{SchemaVersion: initializationJournalSchema, Candidate: candidate, JobID: jobID, Source: source, ProxyURL: proxyURL, FreshValidated: false, ArchiveDigest: installed.Headscale.Archive.Digest, Snapshot: append(json.RawMessage(nil), snapshot...), SnapshotDigest: "sha256:" + hex.EncodeToString(digest[:])}
	data, err := json.Marshal(value)
	return value, data, err
}

func LoadInitializationJournal(paths Paths, installed release.InstallIdentity) (*InitializationJournal, []byte, error) {
	data, err := readJournalFile(paths.Journal)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var value InitializationJournal
	if json.Unmarshal(data, &value) != nil {
		return nil, nil, fmt.Errorf("headscale initialization journal is invalid")
	}
	canonical, err := json.Marshal(value)
	if err != nil || !slices.Equal(canonical, data) || value.SchemaVersion != initializationJournalSchema || !attemptPattern.MatchString(value.JobID) || validateJournalSource(installed, value.Source) != nil || sources.ValidateProxy(journalProxy(value.ProxyURL)) != nil || value.ArchiveDigest != installed.Headscale.Archive.Digest {
		return nil, nil, fmt.Errorf("headscale initialization journal authority mismatched")
	}
	artifact, err := ArtifactIdentity(installed)
	if err != nil || value.Candidate.Artifact != artifact || VerifySnapshot(value.Candidate, value.Snapshot) != nil {
		return nil, nil, fmt.Errorf("headscale initialization journal candidate mismatched")
	}
	snapshot := []byte(value.Snapshot)
	digest := sha256.Sum256(snapshot)
	if value.SnapshotDigest != "sha256:"+hex.EncodeToString(digest[:]) {
		return nil, nil, fmt.Errorf("headscale initialization journal snapshot mismatched")
	}
	return &value, snapshot, nil
}

func CommitInitializationJournal(ctx context.Context, paths Paths, installed release.InstallIdentity, candidate domain.HeadscaleDomain, snapshot []byte, jobID string, source sources.Source, proxyURL string) error {
	_, data, err := BuildInitializationJournal(candidate, installed, snapshot, jobID, source, proxyURL)
	if err != nil {
		return err
	}
	if current, err := readJournalFile(paths.Journal); err == nil {
		var currentValue, expectedValue InitializationJournal
		if json.Unmarshal(current, &currentValue) == nil && json.Unmarshal(data, &expectedValue) == nil {
			currentValue.FreshValidated = false
			expectedValue.FreshValidated = false
			currentCanonical, _ := json.Marshal(currentValue)
			expectedCanonical, _ := json.Marshal(expectedValue)
			if slices.Equal(currentCanonical, expectedCanonical) {
				return nil
			}
		}
		return fmt.Errorf("a different Headscale initialization is pending")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	owner := filetxn.Owner{UID: 0, GID: 0}
	store, err := filetxn.Open(filetxn.Config{RootPath: paths.Root, Root: filetxn.Metadata{Owner: owner, Mode: 0o755}, StagingPath: paths.JournalStaging, Staging: filetxn.Metadata{Owner: owner, Mode: 0o700}, StagingParents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o755}}, filetxn.Options{})
	if err != nil {
		return err
	}
	_, putErr := store.Put(ctx, filetxn.Request{Path: paths.Journal, Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o755}, New: filetxn.Metadata{Owner: owner, Mode: 0o600}, MaxBytes: int64(len(data))}, data, filetxn.CreateOnly)
	return errors.Join(putErr, store.Close())
}

func MarkInitializationFreshValidated(ctx context.Context, paths Paths, installed release.InstallIdentity, candidate domain.HeadscaleDomain, snapshot []byte, jobID string, source sources.Source, proxyURL string) error {
	current, _, err := LoadInitializationJournal(paths, installed)
	if err != nil || current == nil || current.JobID != jobID || current.Candidate.ID != candidate.ID || !reflect.DeepEqual(current.Source, source) || current.ProxyURL != proxyURL {
		return fmt.Errorf("headscale initialization freshness authority changed")
	}
	if current.FreshValidated {
		return nil
	}
	_, encoded, err := BuildInitializationJournal(candidate, installed, snapshot, jobID, source, proxyURL)
	if err != nil {
		return err
	}
	var next InitializationJournal
	if json.Unmarshal(encoded, &next) != nil {
		return fmt.Errorf("headscale initialization freshness encoding failed")
	}
	next.FreshValidated = true
	data, err := json.Marshal(next)
	if err != nil {
		return err
	}
	owner := filetxn.Owner{UID: 0, GID: 0}
	store, err := filetxn.Open(filetxn.Config{RootPath: paths.Root, Root: filetxn.Metadata{Owner: owner, Mode: 0o755}, StagingPath: paths.JournalStaging, Staging: filetxn.Metadata{Owner: owner, Mode: 0o700}, StagingParents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o755}}, filetxn.Options{})
	if err != nil {
		return err
	}
	_, putErr := store.Put(ctx, filetxn.Request{Path: paths.Journal, Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o755}, Existing: &filetxn.Metadata{Owner: owner, Mode: 0o600}, New: filetxn.Metadata{Owner: owner, Mode: 0o600}, MaxBytes: int64(len(data))}, data, filetxn.ReplaceOnly)
	return errors.Join(putErr, store.Close())
}

func RemoveInitializationJournal(paths Paths, installed release.InstallIdentity, candidate domain.HeadscaleDomain, snapshot []byte, jobID string, source sources.Source, proxyURL string) error {
	_, expected, err := BuildInitializationJournal(candidate, installed, snapshot, jobID, source, proxyURL)
	if err != nil {
		return err
	}
	current, err := readJournalFile(paths.Journal)
	var currentValue, expectedValue InitializationJournal
	if err != nil || json.Unmarshal(current, &currentValue) != nil || json.Unmarshal(expected, &expectedValue) != nil {
		return fmt.Errorf("headscale initialization journal changed")
	}
	currentValue.FreshValidated = false
	expectedValue.FreshValidated = false
	currentCanonical, _ := json.Marshal(currentValue)
	expectedCanonical, _ := json.Marshal(expectedValue)
	if !slices.Equal(currentCanonical, expectedCanonical) {
		return fmt.Errorf("headscale initialization journal changed")
	}
	parent, err := unix.Open(filepath.Dir(paths.Journal), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	if err := unix.Unlinkat(parent, filepath.Base(paths.Journal), 0); err != nil {
		return err
	}
	return unix.Fsync(parent)
}

func validateJournalSource(installed release.InstallIdentity, source sources.Source) error {
	choice := SourceChoice{Kind: source.Kind, MirrorURL: source.URL, OfflinePath: source.OfflinePath}
	if source.Kind == sources.OfficialCanonical {
		choice.MirrorURL = ""
	}
	expected, err := BuildSource(installed, choice)
	if err != nil || !reflect.DeepEqual(expected, source) {
		return fmt.Errorf("headscale source differs from release authority")
	}
	return nil
}

func journalProxy(value string) *sources.Proxy {
	if value == "" {
		return nil
	}
	return &sources.Proxy{URL: value}
}

func readJournalFile(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("headscale initialization journal descriptor unavailable")
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0o7777 != 0o600 || stat.Size <= 0 || stat.Size > 1<<20 {
		return nil, fmt.Errorf("headscale initialization journal metadata is unsafe")
	}
	data := make([]byte, stat.Size)
	if _, err := file.ReadAt(data, 0); err != nil {
		return nil, err
	}
	var after unix.Stat_t
	if unix.Fstat(fd, &after) != nil || stat.Dev != after.Dev || stat.Ino != after.Ino || stat.Size != after.Size || stat.Mtim != after.Mtim {
		return nil, fmt.Errorf("headscale initialization journal changed during read")
	}
	return data, nil
}
