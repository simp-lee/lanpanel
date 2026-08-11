// Package plans defines immutable, bounded, one-time normal operation Plans.
package plans

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/locks"
	"lanpanel/internal/persist"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
)

const SchemaVersion = "lanpanel.plan.v1"
const MaximumLifetime = 10 * time.Minute
const MaximumEvidenceAge = 10 * time.Minute

var (
	ErrMissing  = errors.New("Plan is missing")
	ErrConsumed = errors.New("Plan was already consumed")
	ErrExpired  = errors.New("Plan expired")
	idPattern   = regexp.MustCompile(`^plan_[0-9a-f]{64}$`)
	refPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
)

type TargetKind string

const (
	TargetInstallation TargetKind = "installation"
	TargetResource     TargetKind = "resource"
	TargetHeadscale    TargetKind = "headscale"
)

type Target struct {
	Kind TargetKind `json:"kind"`
	ID   string     `json:"id,omitempty"`
}
type DigestBinding struct {
	Applicable bool   `json:"applicable"`
	Digest     string `json:"digest,omitempty"`
}
type Evidence struct {
	Kind       string    `json:"kind"`
	Identity   string    `json:"identity"`
	Generation uint64    `json:"generation"`
	Digest     string    `json:"digest"`
	ObservedAt time.Time `json:"observed_at"`
}
type Spec struct {
	Operation       string
	Target          Target
	ActorIdentity   string
	Config          DigestBinding
	Applied         DigestBinding
	Evidence        []Evidence
	ExposureSummary string
	Prerequisites   string
	Lifetime        time.Duration
}
type Plan struct {
	SchemaVersion   string        `json:"schema_version"`
	ID              string        `json:"id"`
	Operation       string        `json:"operation"`
	Target          Target        `json:"target"`
	ActorIdentity   string        `json:"actor_identity"`
	Config          DigestBinding `json:"config"`
	Applied         DigestBinding `json:"applied"`
	Evidence        []Evidence    `json:"evidence"`
	ExposureSummary string        `json:"exposure_summary"`
	Prerequisites   string        `json:"prerequisites"`
	CreatedAt       time.Time     `json:"created_at"`
	ExpiresAt       time.Time     `json:"expires_at"`
	NonceDigest     string        `json:"nonce_digest"`
	ReservedAt      *time.Time    `json:"reserved_at,omitempty"`
	ReservedByJob   string        `json:"reserved_by_job,omitempty"`
	ConsumedAt      *time.Time    `json:"consumed_at,omitempty"`
	ConsumedByJob   string        `json:"consumed_by_job,omitempty"`
	RejectedAt      *time.Time    `json:"rejected_at,omitempty"`
	RejectedByJob   string        `json:"rejected_by_job,omitempty"`
}
type Binding struct {
	Operation     string
	Target        Target
	ActorIdentity string
	Config        DigestBinding
	Applied       DigestBinding
	Evidence      []Evidence
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
		return nil, fmt.Errorf("Plan store requires normal persistence")
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

func (store *Store) Create(ctx context.Context, lease *locks.Lease, expectedRevision uint64, spec Spec) (Plan, error) {
	now := store.now().UTC()
	lifetime := spec.Lifetime
	if lifetime == 0 {
		lifetime = MaximumLifetime
	}
	id, nonce, err := randomIdentities(store.random)
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{SchemaVersion: SchemaVersion, ID: id, Operation: spec.Operation, Target: spec.Target, ActorIdentity: spec.ActorIdentity, Config: spec.Config, Applied: spec.Applied, Evidence: canonicalEvidence(spec.Evidence), ExposureSummary: spec.ExposureSummary, Prerequisites: spec.Prerequisites, CreatedAt: now, ExpiresAt: now.Add(lifetime), NonceDigest: nonce}
	if err := Validate(plan, now); err != nil {
		return Plan{}, err
	}
	_, _, err = store.normal.Update(ctx, lease, expectedRevision, func(transaction *persist.Transaction) error { return Put(transaction, plan) })
	if err != nil {
		return Plan{}, err
	}
	return plan, nil
}

func (store *Store) Read(id string) (Plan, error) {
	document, err := store.normal.Read()
	if err != nil {
		return Plan{}, err
	}
	return LoadEntries(document.Entries, id)
}

func Register(normal *persist.Store) error {
	if normal.NamespaceRegistered("plans") {
		return nil
	}
	return normal.RegisterNamespace("plans", validateEntry, validatePlanTransition)
}
func validateEntry(key string, raw json.RawMessage) error {
	plan, err := decode(raw)
	if err != nil {
		return err
	}
	if key != "plans/"+plan.ID {
		return fmt.Errorf("Plan key does not match ID")
	}
	return Validate(plan, plan.CreatedAt)
}
func validatePlanTransition(_ string, before, after json.RawMessage) error {
	if len(before) == 0 {
		plan, err := decode(after)
		if err != nil {
			return err
		}
		if plan.ConsumedAt != nil || plan.ReservedAt != nil || plan.RejectedAt != nil {
			return fmt.Errorf("new Plan cannot start consumed")
		}
		return nil
	}
	oldPlan, err := decode(before)
	if err != nil {
		return err
	}
	newPlan, err := decode(after)
	if err != nil {
		return err
	}
	oldReservedAt, oldReservedJob := oldPlan.ReservedAt, oldPlan.ReservedByJob
	newReservedAt, newReservedJob := newPlan.ReservedAt, newPlan.ReservedByJob
	oldConsumedAt, oldJob := oldPlan.ConsumedAt, oldPlan.ConsumedByJob
	newConsumedAt, newJob := newPlan.ConsumedAt, newPlan.ConsumedByJob
	oldRejectedAt, oldRejectedJob := oldPlan.RejectedAt, oldPlan.RejectedByJob
	newRejectedAt, newRejectedJob := newPlan.RejectedAt, newPlan.RejectedByJob
	oldPlan.ReservedAt = nil
	oldPlan.ReservedByJob = ""
	newPlan.ReservedAt = nil
	newPlan.ReservedByJob = ""
	oldPlan.ConsumedAt = nil
	oldPlan.ConsumedByJob = ""
	newPlan.ConsumedAt = nil
	newPlan.ConsumedByJob = ""
	oldPlan.RejectedAt = nil
	oldPlan.RejectedByJob = ""
	newPlan.RejectedAt = nil
	newPlan.RejectedByJob = ""
	if !reflect.DeepEqual(oldPlan, newPlan) {
		return fmt.Errorf("immutable Plan binding was rewritten")
	}
	if oldConsumedAt != nil || oldJob != "" || oldRejectedAt != nil || oldRejectedJob != "" {
		return fmt.Errorf("consumed Plan is immutable")
	}
	if oldReservedAt == nil {
		if newReservedAt == nil || newReservedJob == "" || newConsumedAt != nil || newRejectedAt != nil {
			return fmt.Errorf("Plan must first transition to one reservation")
		}
		return nil
	}
	if newReservedAt == nil || newReservedJob != oldReservedJob || !newReservedAt.Equal(*oldReservedAt) {
		return fmt.Errorf("Plan reservation was rewritten")
	}
	consumed := newConsumedAt != nil && newJob == oldReservedJob && newRejectedAt == nil
	rejected := newRejectedAt != nil && newRejectedJob == oldReservedJob && newConsumedAt == nil
	if !consumed && !rejected {
		return fmt.Errorf("reserved Plan can terminate only for its job")
	}
	return nil
}

func Put(transaction *persist.Transaction, plan Plan) error {
	if _, exists := transaction.Get(key(plan.ID)); exists {
		return fmt.Errorf("Plan ID collision")
	}
	raw, err := persist.EncodeEntry(plan)
	if err != nil {
		return err
	}
	return transaction.Create(key(plan.ID), raw)
}

func LoadEntries(entries map[string]json.RawMessage, id string) (Plan, error) {
	if !idPattern.MatchString(id) {
		return Plan{}, fmt.Errorf("invalid Plan ID")
	}
	raw, exists := entries[key(id)]
	if !exists {
		return Plan{}, ErrMissing
	}
	return decode(raw)
}

// Consume mutates the caller's normal-state transaction. It must be committed
// together with the matching phase intent and durable job reservation.
func Load(transaction *persist.Transaction, id string) (Plan, error) {
	if !idPattern.MatchString(id) {
		return Plan{}, fmt.Errorf("invalid Plan ID")
	}
	raw, exists := transaction.Get(key(id))
	if !exists {
		return Plan{}, ErrMissing
	}
	return decode(raw)
}
func Reserve(transaction *persist.Transaction, id, jobID, operation, target, actor string, now time.Time) (Plan, error) {
	plan, err := Load(transaction, id)
	if err != nil {
		return Plan{}, err
	}
	if err := Validate(plan, now); err != nil {
		return Plan{}, err
	}
	if plan.ReservedAt != nil || plan.ConsumedAt != nil || plan.RejectedAt != nil {
		return Plan{}, ErrConsumed
	}
	if plan.Operation != operation || planTarget(plan.Target) != target || plan.ActorIdentity != actor {
		return Plan{}, fmt.Errorf("Plan does not match reservation request")
	}
	stamp := now.UTC()
	plan.ReservedAt = &stamp
	plan.ReservedByJob = jobID
	raw, err := persist.EncodeEntry(plan)
	if err != nil {
		return Plan{}, err
	}
	if err := transaction.Replace(key(id), raw); err != nil {
		return Plan{}, err
	}
	return plan, nil
}
func Reject(transaction *persist.Transaction, id, jobID string, now time.Time) (Plan, error) {
	plan, err := Load(transaction, id)
	if err != nil {
		return Plan{}, err
	}
	if plan.ReservedAt == nil || plan.ReservedByJob != jobID || plan.ConsumedAt != nil || plan.RejectedAt != nil {
		return Plan{}, fmt.Errorf("Plan is not rejectable by this job")
	}
	stamp := now.UTC()
	plan.RejectedAt = &stamp
	plan.RejectedByJob = jobID
	raw, err := persist.EncodeEntry(plan)
	if err != nil {
		return Plan{}, err
	}
	if err := transaction.Replace(key(id), raw); err != nil {
		return Plan{}, err
	}
	return plan, nil
}
func Consume(transaction *persist.Transaction, id, jobID string, binding Binding, now time.Time) (Plan, error) {
	plan, err := Load(transaction, id)
	if err != nil {
		return Plan{}, err
	}
	if plan.ConsumedAt != nil || plan.RejectedAt != nil {
		return Plan{}, ErrConsumed
	}
	if plan.ReservedAt == nil || plan.ReservedByJob != jobID {
		return Plan{}, fmt.Errorf("Plan is not reserved by this job")
	}
	if err := Match(plan, binding, now); err != nil {
		return Plan{}, err
	}
	stamp := now.UTC()
	plan.ConsumedAt = &stamp
	plan.ConsumedByJob = jobID
	raw, err := persist.EncodeEntry(plan)
	if err != nil {
		return Plan{}, err
	}
	if err := transaction.Replace(key(id), raw); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

func Match(plan Plan, binding Binding, now time.Time) error {
	if err := Validate(plan, now); err != nil {
		return err
	}
	if plan.ConsumedAt != nil || plan.RejectedAt != nil {
		return ErrConsumed
	}
	binding.Evidence = canonicalEvidence(binding.Evidence)
	if plan.Operation != binding.Operation || plan.Target != binding.Target || plan.ActorIdentity != binding.ActorIdentity || plan.Config != binding.Config || plan.Applied != binding.Applied || !evidenceIdentityEqual(plan.Evidence, binding.Evidence) {
		return fmt.Errorf("Plan binding changed")
	}
	for _, evidence := range binding.Evidence {
		if evidence.ObservedAt.After(now) || evidence.ObservedAt.Before(plan.CreatedAt) || now.Sub(evidence.ObservedAt) > MaximumEvidenceAge {
			return fmt.Errorf("Plan prerequisite evidence is stale")
		}
	}
	return nil
}

func Validate(plan Plan, now time.Time) error {
	if plan.SchemaVersion != SchemaVersion || !idPattern.MatchString(plan.ID) || !validRef(plan.Operation) || !validTarget(plan.Target) || !validRef(plan.ActorIdentity) || !digestBindingValid(plan.Config) || !digestBindingValid(plan.Applied) || !digest(plan.NonceDigest) || plan.CreatedAt.IsZero() || plan.ExpiresAt.IsZero() || !plan.ExpiresAt.After(plan.CreatedAt) || plan.ExpiresAt.Sub(plan.CreatedAt) > MaximumLifetime || !validRef(plan.ExposureSummary) || !validRef(plan.Prerequisites) {
		return fmt.Errorf("Plan identity or lifetime is invalid")
	}
	if now.Before(plan.CreatedAt) {
		return fmt.Errorf("trusted time regressed before Plan creation")
	}
	if plan.ConsumedAt == nil && !now.Before(plan.ExpiresAt) {
		return ErrExpired
	}
	if (plan.RejectedAt == nil) != (plan.RejectedByJob == "") {
		return fmt.Errorf("Plan rejection identity is incomplete")
	}
	if plan.RejectedAt != nil && (plan.RejectedAt.Before(plan.CreatedAt) || !validRef(plan.RejectedByJob) || plan.RejectedByJob != plan.ReservedByJob) {
		return fmt.Errorf("Plan rejection identity is invalid")
	}
	if (plan.ReservedAt == nil) != (plan.ReservedByJob == "") {
		return fmt.Errorf("Plan reservation identity is incomplete")
	}
	if plan.ReservedAt != nil && (plan.ReservedAt.Before(plan.CreatedAt) || !plan.ReservedAt.Before(plan.ExpiresAt) || !validRef(plan.ReservedByJob)) {
		return fmt.Errorf("Plan reservation time is invalid")
	}
	if plan.ConsumedAt != nil && (!plan.ConsumedAt.Before(plan.ExpiresAt) || !validRef(plan.ConsumedByJob) || plan.ReservedByJob != plan.ConsumedByJob) {
		return fmt.Errorf("Plan consumption identity is invalid")
	}
	canonical := canonicalEvidence(plan.Evidence)
	if !evidenceEqual(plan.Evidence, canonical) {
		return fmt.Errorf("Plan evidence is not canonical")
	}
	for index, evidence := range plan.Evidence {
		if index > 0 && evidence.Kind == plan.Evidence[index-1].Kind && evidence.Identity == plan.Evidence[index-1].Identity {
			return fmt.Errorf("Plan evidence identity is duplicated")
		}
		if !validEvidence(evidence) || evidence.ObservedAt.After(plan.CreatedAt) || plan.CreatedAt.Sub(evidence.ObservedAt) > MaximumEvidenceAge {
			return fmt.Errorf("Plan evidence is invalid or stale at creation")
		}
	}
	return nil
}

func randomIdentities(reader io.Reader) (string, string, error) {
	bytes := make([]byte, 64)
	if _, err := io.ReadFull(reader, bytes); err != nil {
		return "", "", fmt.Errorf("generate Plan entropy: %w", err)
	}
	return "plan_" + hex.EncodeToString(bytes[:32]), digestBytes(bytes[32:]), nil
}
func digestBytes(value []byte) string {
	sum := sha256Sum(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func sha256Sum(value []byte) [32]byte { return sha256.Sum256(value) }

func planTarget(target Target) string {
	if target.ID == "" {
		return string(target.Kind)
	}
	return string(target.Kind) + "/" + target.ID
}
func key(id string) string { return "plans/" + id }
func validTarget(target Target) bool {
	return target.Kind == TargetInstallation && target.ID == "" || (target.Kind == TargetResource || target.Kind == TargetHeadscale) && validRef(target.ID)
}
func digestBindingValid(value DigestBinding) bool {
	return value.Applicable && digest(value.Digest) || !value.Applicable && value.Digest == ""
}
func validEvidence(value Evidence) bool {
	return validRef(value.Kind) && validRef(value.Identity) && value.Generation != 0 && digest(value.Digest) && !value.ObservedAt.IsZero()
}
func canonicalEvidence(values []Evidence) []Evidence {
	result := append([]Evidence(nil), values...)
	sort.Slice(result, func(i, j int) bool {
		if result[i].Kind == result[j].Kind {
			return result[i].Identity < result[j].Identity
		}
		return result[i].Kind < result[j].Kind
	})
	return result
}
func SameBindingIdentity(left, right Binding) bool {
	left.Evidence = canonicalEvidence(left.Evidence)
	right.Evidence = canonicalEvidence(right.Evidence)
	return left.Operation == right.Operation && left.Target == right.Target && left.ActorIdentity == right.ActorIdentity && left.Config == right.Config && left.Applied == right.Applied && evidenceIdentityEqual(left.Evidence, right.Evidence)
}
func evidenceIdentityEqual(left, right []Evidence) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		a, b := left[index], right[index]
		if a.Kind != b.Kind || a.Identity != b.Identity || a.Generation != b.Generation || a.Digest != b.Digest {
			return false
		}
	}
	return true
}
func evidenceEqual(left, right []Evidence) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
func digest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil
}
func validRef(value string) bool { return refPattern.MatchString(value) }
func decode(raw json.RawMessage) (Plan, error) {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var plan Plan
	if err := decoder.Decode(&plan); err != nil {
		return Plan{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Plan{}, fmt.Errorf("Plan has trailing data")
	}
	return plan, nil
}
