// Package jobs defines durable, redacted operation records with a closed result vocabulary.
package jobs

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/persist"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	SchemaVersion         = "lanpanel.job.v1"
	MaximumModifiedPaths  = 64
	MaximumPostconditions = 32
)

var (
	ErrMissing        = errors.New("job is missing")
	idPattern         = regexp.MustCompile(`^job_[0-9a-f]{64}$`)
	refPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
	errorCodePattern  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	allowedErrorCodes = map[string]struct{}{
		"activation_contracted":       {},
		"binding_refresh_failed":      {},
		"confirmation_invalid":        {},
		"confirmation_rejected":       {},
		"exact_reconciliation_closed": {},
		"normal_revision_changed":     {},
		"plan_consumption_rejected":   {},
		"planless_start_rejected":     {},
		"safety_authority_changed":    {},
		"safety_recheck_unavailable":  {},
		"safety_refresh_failed":       {},
	}
)

type Status string

const (
	StatusReserved Status = "reserved"
	StatusRunning  Status = "running"
	StatusTerminal Status = "terminal"
)

type Result string

const (
	ResultSucceeded   Result = "succeeded"
	ResultFailed      Result = "failed"
	ResultPartial     Result = "partial"
	ResultInterrupted Result = "interrupted"
	ResultUnknown     Result = "unknown"
)

type PostconditionStatus string

const (
	PostconditionVerified   PostconditionStatus = "verified"
	PostconditionKnown      PostconditionStatus = "known_residual"
	PostconditionUnobserved PostconditionStatus = "unobserved"
)

type Postcondition struct {
	Kind     string              `json:"kind"`
	Status   PostconditionStatus `json:"status"`
	Identity string              `json:"identity"`
}
type Record struct {
	SchemaVersion  string          `json:"schema_version"`
	ID             string          `json:"id"`
	Operation      string          `json:"operation"`
	Target         string          `json:"target"`
	ActorIdentity  string          `json:"actor_identity"`
	StartedAt      time.Time       `json:"started_at"`
	EndedAt        *time.Time      `json:"ended_at,omitempty"`
	Status         Status          `json:"status"`
	Result         Result          `json:"result,omitempty"`
	ModifiedPaths  []string        `json:"modified_paths"`
	Postconditions []Postcondition `json:"postconditions"`
	ErrorCode      string          `json:"error_code,omitempty"`
}
type Spec struct{ Operation, Target, ActorIdentity string }
type Completion struct {
	Result         Result
	ModifiedPaths  []string
	Postconditions []Postcondition
	ErrorCode      string
}
type Options struct {
	Now    func() time.Time
	Random io.Reader
}
type Store struct {
	normal *persist.Store
	now    func() time.Time
	random io.Reader
}

func NewStore(normal *persist.Store, options Options) (*Store, error) {
	if normal == nil {
		return nil, fmt.Errorf("job store requires normal persistence")
	}
	now := options.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	random := options.Random
	if random == nil {
		random = rand.Reader
	}
	if err := Register(normal); err != nil {
		return nil, err
	}
	return &Store{normal: normal, now: now, random: random}, nil
}

func (store *Store) Read(id string) (Record, error) {
	document, err := store.normal.Read()
	if err != nil {
		return Record{}, err
	}
	return LoadEntries(document.Entries, id)
}

func Register(normal *persist.Store) error {
	if normal.NamespaceRegistered("jobs") {
		return nil
	}
	return normal.RegisterCanonicalNamespace("jobs", "jobs.v1", validateEntry, validateJobTransition)
}
func validateEntry(key string, raw json.RawMessage) error {
	record, err := decode(raw)
	if err != nil {
		return err
	}
	if key != "jobs/"+record.ID {
		return fmt.Errorf("job key does not match ID")
	}
	return nil
}
func validateJobTransition(_ string, before, after json.RawMessage) error {
	if len(before) == 0 {
		record, err := decode(after)
		if err != nil {
			return err
		}
		if record.Status != StatusReserved {
			return fmt.Errorf("new job must start reserved")
		}
		return nil
	}
	oldRecord, err := decode(before)
	if err != nil {
		return err
	}
	if len(after) == 0 {
		if oldRecord.Status != StatusTerminal {
			return fmt.Errorf("only a terminal job may be pruned")
		}
		return nil
	}
	newRecord, err := decode(after)
	if err != nil {
		return err
	}
	oldStatus := oldRecord.Status
	newStatus := newRecord.Status
	oldRecord.Status = ""
	oldRecord.EndedAt = nil
	oldRecord.Result = ""
	oldRecord.ModifiedPaths = nil
	oldRecord.Postconditions = nil
	oldRecord.ErrorCode = ""
	newRecord.Status = ""
	newRecord.EndedAt = nil
	newRecord.Result = ""
	newRecord.ModifiedPaths = nil
	newRecord.Postconditions = nil
	newRecord.ErrorCode = ""
	if !reflect.DeepEqual(oldRecord, newRecord) {
		return fmt.Errorf("job identity was rewritten")
	}
	if oldStatus == StatusTerminal {
		return fmt.Errorf("terminal job is immutable")
	}
	if oldStatus == StatusReserved && newStatus != StatusRunning && newStatus != StatusTerminal {
		return fmt.Errorf("reserved job transition is invalid")
	}
	if oldStatus == StatusRunning && newStatus != StatusTerminal {
		return fmt.Errorf("running job transition is invalid")
	}
	return nil
}

func Put(transaction *persist.Transaction, record Record) error {
	if _, exists := transaction.Get(key(record.ID)); exists {
		return fmt.Errorf("job ID collision")
	}
	if err := Validate(record); err != nil {
		return err
	}
	raw, err := persist.EncodeEntry(record)
	if err != nil {
		return err
	}
	return transaction.Create(key(record.ID), raw)
}
func Replace(transaction *persist.Transaction, record Record) error {
	if _, exists := transaction.Get(key(record.ID)); !exists {
		return ErrMissing
	}
	if err := Validate(record); err != nil {
		return err
	}
	raw, err := persist.EncodeEntry(record)
	if err != nil {
		return err
	}
	return transaction.Replace(key(record.ID), raw)
}
func LoadEntries(entries map[string]json.RawMessage, id string) (Record, error) {
	if !idPattern.MatchString(id) {
		return Record{}, fmt.Errorf("invalid job ID")
	}
	raw, exists := entries[key(id)]
	if !exists {
		return Record{}, ErrMissing
	}
	return decode(raw)
}

func Load(transaction *persist.Transaction, id string) (Record, error) {
	if !idPattern.MatchString(id) {
		return Record{}, fmt.Errorf("invalid job ID")
	}
	raw, exists := transaction.Get(key(id))
	if !exists {
		return Record{}, ErrMissing
	}
	return decode(raw)
}

func NewReserved(spec Spec, now time.Time, random io.Reader) (Record, error) {
	id, err := newID(random)
	if err != nil {
		return Record{}, err
	}
	record := Record{SchemaVersion: SchemaVersion, ID: id, Operation: spec.Operation, Target: spec.Target, ActorIdentity: spec.ActorIdentity, StartedAt: now.UTC(), Status: StatusReserved, ModifiedPaths: []string{}, Postconditions: []Postcondition{}}
	if err := Validate(record); err != nil {
		return Record{}, err
	}
	return record, nil
}

func Start(record Record) (Record, error) {
	if record.Status != StatusReserved {
		return Record{}, fmt.Errorf("only a reserved job can start")
	}
	record.Status = StatusRunning
	if err := Validate(record); err != nil {
		return Record{}, err
	}
	return record, nil
}

func Finish(record Record, completion Completion, now time.Time) (Record, error) {
	if record.Status == StatusTerminal {
		return Record{}, fmt.Errorf("terminal job is immutable")
	}
	record.Status = StatusTerminal
	record.Result = completion.Result
	stamp := now.UTC()
	record.EndedAt = &stamp
	record.ModifiedPaths = canonicalPaths(completion.ModifiedPaths)
	record.Postconditions = canonicalPostconditions(completion.Postconditions)
	record.ErrorCode = completion.ErrorCode
	if err := Validate(record); err != nil {
		return Record{}, err
	}
	return record, nil
}

func Validate(record Record) error {
	if record.SchemaVersion != SchemaVersion || !idPattern.MatchString(record.ID) || !validRef(record.Operation) || !validRef(record.Target) || !validRef(record.ActorIdentity) || record.StartedAt.IsZero() {
		return fmt.Errorf("job identity is invalid")
	}
	if len(record.ModifiedPaths) > MaximumModifiedPaths || len(record.Postconditions) > MaximumPostconditions {
		return fmt.Errorf("job evidence exceeds the bounded retention shape")
	}
	if !pathsEqual(record.ModifiedPaths, canonicalPaths(record.ModifiedPaths)) || !postconditionsEqual(record.Postconditions, canonicalPostconditions(record.Postconditions)) {
		return fmt.Errorf("job evidence is not canonical")
	}
	for _, path := range record.ModifiedPaths {
		if len(path) > 512 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("job modified path is not bounded, clean, and absolute")
		}
	}
	for _, condition := range record.Postconditions {
		if !validRef(condition.Kind) || !validRef(condition.Identity) || (condition.Status != PostconditionVerified && condition.Status != PostconditionKnown && condition.Status != PostconditionUnobserved) {
			return fmt.Errorf("job postcondition is invalid")
		}
	}
	switch record.Status {
	case StatusReserved, StatusRunning:
		if record.EndedAt != nil || record.Result != "" || len(record.ModifiedPaths) != 0 || len(record.Postconditions) != 0 || record.ErrorCode != "" {
			return fmt.Errorf("nonterminal job contains terminal evidence")
		}
	case StatusTerminal:
		if record.EndedAt == nil || record.EndedAt.Before(record.StartedAt) || !validResult(record.Result) || len(record.Postconditions) == 0 {
			return fmt.Errorf("terminal job evidence is incomplete")
		}
		if record.Result == ResultSucceeded && record.ErrorCode != "" {
			return fmt.Errorf("succeeded job cannot contain an error")
		}
		_, allowedErrorCode := allowedErrorCodes[record.ErrorCode]
		if record.Result != ResultSucceeded && (!errorCodePattern.MatchString(record.ErrorCode) || !allowedErrorCode) {
			return fmt.Errorf("non-success job requires a closed redacted error code")
		}
		if (record.Result == ResultSucceeded || record.Result == ResultFailed) && !allPostconditions(record.Postconditions, PostconditionVerified) {
			return fmt.Errorf("succeeded or restored-failure job requires verified postconditions")
		}
		if record.Result == ResultPartial && (hasPostcondition(record.Postconditions, PostconditionUnobserved) || !hasPostcondition(record.Postconditions, PostconditionKnown)) {
			return fmt.Errorf("partial job requires a known residual side effect")
		}
		if record.Result == ResultUnknown && !hasPostcondition(record.Postconditions, PostconditionUnobserved) {
			return fmt.Errorf("unknown job requires an unobserved critical postcondition")
		}
	default:
		return fmt.Errorf("job status is unsupported")
	}
	return nil
}

func Nonterminal(entries map[string]json.RawMessage) ([]Record, error) {
	result := []Record{}
	keys := make([]string, 0)
	for key := range entries {
		if strings.HasPrefix(key, "jobs/") {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		record, err := decode(entries[key])
		if err != nil {
			return nil, err
		}
		if record.Status != StatusTerminal {
			result = append(result, record)
		}
	}
	return result, nil
}

func newID(reader io.Reader) (string, error) {
	bytes := make([]byte, 32)
	if _, err := io.ReadFull(reader, bytes); err != nil {
		return "", fmt.Errorf("generate job ID: %w", err)
	}
	return "job_" + hex.EncodeToString(bytes), nil
}
func key(id string) string       { return "jobs/" + id }
func validRef(value string) bool { return refPattern.MatchString(value) }
func allPostconditions(values []Postcondition, status PostconditionStatus) bool {
	for _, value := range values {
		if value.Status != status {
			return false
		}
	}
	return len(values) != 0
}
func hasPostcondition(values []Postcondition, status PostconditionStatus) bool {
	for _, value := range values {
		if value.Status == status {
			return true
		}
	}
	return false
}
func validResult(result Result) bool {
	return result == ResultSucceeded || result == ResultFailed || result == ResultPartial || result == ResultInterrupted || result == ResultUnknown
}
func canonicalPaths(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return compact(result)
}
func compact(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	out := values[:1]
	for _, v := range values[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}
func canonicalPostconditions(values []Postcondition) []Postcondition {
	result := append([]Postcondition(nil), values...)
	sort.Slice(result, func(i, j int) bool {
		if result[i].Kind == result[j].Kind {
			return result[i].Identity < result[j].Identity
		}
		return result[i].Kind < result[j].Kind
	})
	return result
}
func pathsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func postconditionsEqual(a, b []Postcondition) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func decode(raw json.RawMessage) (Record, error) {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var value Record
	if err := decoder.Decode(&value); err != nil {
		return Record{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Record{}, fmt.Errorf("job has trailing data")
	}
	if err := Validate(value); err != nil {
		return Record{}, err
	}
	return value, nil
}
