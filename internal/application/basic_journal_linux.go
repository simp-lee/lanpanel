//go:build linux

package application

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/htpasswdref"
	"os"
	"path/filepath"
	"regexp"

	"golang.org/x/sys/unix"
)

const basicJournalSchema = "lanpanel.managed-basic.v1"

type BasicJournal struct {
	SchemaVersion        string `json:"schema_version"`
	JobID                string `json:"job_id"`
	Operation            string `json:"operation"`
	CredentialID         string `json:"credential_id"`
	ResourceID           string `json:"resource_id"`
	Username             string `json:"username"`
	Path                 string `json:"path"`
	PriorFingerprint     string `json:"prior_fingerprint,omitempty"`
	CandidateFingerprint string `json:"candidate_fingerprint,omitempty"`
}

func basicJournalPath(id string) string { return fixedRoot + "/safety/managed-basic/" + id + ".json" }
func writeBasicJournal(ctx context.Context, value BasicJournal) error {
	if err := writeBasicJournalValidation(value); err != nil {
		return err
	}
	if _, err := os.Lstat(basicJournalPath(value.CredentialID)); err == nil {
		return fmt.Errorf("managed Basic journal already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writeBoundedJournal(ctx, basicJournalPath(value.CredentialID), raw)
}

func readBasicJournal(path string) (BasicJournal, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return BasicJournal{}, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return BasicJournal{}, fmt.Errorf("managed Basic journal descriptor invalid")
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o600 || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > 4096 {
		return BasicJournal{}, fmt.Errorf("managed Basic journal identity unsafe")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || int64(len(raw)) != stat.Size {
		return BasicJournal{}, fmt.Errorf("managed Basic journal read changed")
	}
	var value BasicJournal
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return BasicJournal{}, fmt.Errorf("managed Basic journal malformed")
	}
	canonical, _ := json.Marshal(value)
	if !bytes.Equal(canonical, raw) {
		return BasicJournal{}, fmt.Errorf("managed Basic journal noncanonical")
	}
	if err := writeBasicJournalValidation(value); err != nil {
		return BasicJournal{}, err
	}
	return value, nil
}

var (
	basicDigestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	basicCredentialPattern = regexp.MustCompile(`^cred_[0-9a-f]{32}$`)
	basicResourcePattern   = regexp.MustCompile(`^res_[0-9a-f]{32}$`)
)

func writeBasicJournalValidation(value BasicJournal) error {
	if value.SchemaVersion != basicJournalSchema || value.JobID == "" || !basicCredentialPattern.MatchString(value.CredentialID) || !basicResourcePattern.MatchString(value.ResourceID) || !htpasswdref.ValidUsername(value.Username) || value.Path != "/etc/lanpanel-public/basic/"+value.CredentialID+".htpasswd" || (value.Operation != "create" && value.Operation != "rotate" && value.Operation != "delete") || (value.Operation == "delete") != (value.CandidateFingerprint == "") || ((value.Operation == "create") != (value.PriorFingerprint == "") || value.PriorFingerprint != "" && !basicDigestPattern.MatchString(value.PriorFingerprint)) || (value.CandidateFingerprint != "" && !basicDigestPattern.MatchString(value.CandidateFingerprint)) {
		return fmt.Errorf("managed Basic journal invalid")
	}
	return nil
}

func removeBasicJournal(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return fmt.Errorf("managed Basic journal removal unsafe")
	}
	stat, ok := info.Sys().(*unix.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 {
		return fmt.Errorf("managed Basic journal owner changed")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(directory.Close)
	return directory.Sync()
}
