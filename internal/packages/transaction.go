package packages

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"lanpanel/internal/child"
	"lanpanel/internal/preflight"
	"reflect"
	"slices"
	"strings"
	"time"
)

const PackageJournalSchemaVersion = "lanpanel.package.journal.v4"

type JournalPhase string

const (
	JournalPrepared        JournalPhase = "prepared"
	JournalArtifactsStaged JournalPhase = "artifacts_staged"
	JournalFilesPrepared   JournalPhase = "files_prepared"
	JournalMasking         JournalPhase = "masking"
	JournalMasksApplied    JournalPhase = "masks_applied"
	JournalChildSubmitted  JournalPhase = "child_submitted"
	JournalChildTerminal   JournalPhase = "child_terminal"
	JournalVerified        JournalPhase = "verified"
	JournalCommitted       JournalPhase = "committed"
	JournalCleaned         JournalPhase = "cleaned"
)

type Journal struct {
	SchemaVersion       string          `json:"schema_version"`
	TransactionID       string          `json:"transaction_id"`
	NormalJournalID     string          `json:"normal_journal_id"`
	ChildID             string          `json:"child_id"`
	JobID               string          `json:"job_id"`
	PlanDigest          string          `json:"plan_digest"`
	AuthorityDigest     string          `json:"authority_digest"`
	PackageProfile      child.ProfileID `json:"package_profile"`
	Prior               RuntimeSnapshot `json:"prior"`
	Phase               JournalPhase    `json:"phase"`
	Masks               []MaskIdentity  `json:"masks"`
	MaskIntent          string          `json:"mask_intent,omitempty"`
	MasksComplete       bool            `json:"masks_complete"`
	ChildResultDigest   string          `json:"child_result_digest,omitempty"`
	ChildSucceeded      bool            `json:"child_succeeded,omitempty"`
	PostconditionDigest string          `json:"postcondition_digest,omitempty"`
	ErrorCode           string          `json:"error_code,omitempty"`
}

type NormalAuthority struct {
	JobID            string
	IntentGeneration uint64
	PackageJournalID string
	ChildID          string
	PackageProfile   child.ProfileID
	PlanDigest       string
	AuthorityDigest  string
	Deadline         time.Time
}

type JournalStore interface {
	Create(context.Context, Journal) error
	Advance(context.Context, Journal, Journal) error
}

type NoAutostartPolicy struct {
	Path               string
	Digest             string
	UID                uint32
	GID                uint32
	Mode               uint32
	Regular            bool
	Linked             bool
	ParentsSafe        bool
	SameLanPanelBinary bool
}

type Audit struct {
	Configuration []ObservedConfig
	Repositories  []ObservedRepository
	DPKG          DPKGState
	Before        RuntimeSnapshot
	NoAutostart   NoAutostartPolicy
}

type MaskIdentity struct {
	Unit        string `json:"unit"`
	Preexisting bool   `json:"preexisting"`
	Device      uint64 `json:"device"`
	Inode       uint64 `json:"inode"`
	CTimeSec    int64  `json:"ctime_sec"`
	CTimeNsec   int64  `json:"ctime_nsec"`
}

type MaskResult struct {
	Masks []MaskIdentity
}

type Executor interface {
	LockRepositories(context.Context, Plan) (func(), error)
	Audit(context.Context, Plan) (Audit, error)
	Stage(context.Context, Plan) error
	VerifyStaged(context.Context, Plan) error
	Prepare(context.Context, Plan, []byte, []byte) error
	Resolve(context.Context, Plan) ([]Package, error)
	Mask(context.Context, []string, string, func(string) error, func(MaskIdentity) error) (MaskResult, error)
	VerifyMasks(context.Context, []MaskIdentity) error
	Run(context.Context, child.ProfileID, child.Invocation) (child.Result, error)
	Observe(context.Context, Plan) (Postcondition, error)
	Unmask(context.Context, []MaskIdentity) error
}

type Monitor interface {
	Start(context.Context, []string, []string) (context.Context, func() error, error)
}

type Engine struct {
	Journals        JournalStore
	Executor        Executor
	Monitor         Monitor
	MonitorRequired bool
	Now             func() time.Time
}

func (engine Engine) Execute(ctx context.Context, plan Plan, preflightResult preflight.Result) (Journal, error) {
	if engine.Journals == nil || engine.Executor == nil || engine.MonitorRequired && engine.Monitor == nil {
		return Journal{}, fmt.Errorf("package transaction dependencies are incomplete")
	}
	if err := ValidatePlan(plan); err != nil {
		return Journal{}, err
	}
	now := time.Now().UTC
	if engine.Now != nil {
		now = engine.Now
	}
	observedNow := now().UTC()
	if err := preflight.RequireExpansionResult(preflightResult, []preflight.ExpansionScope{preflight.ExpansionBootstrap, preflight.ExpansionHeadscale}, "installation", plan.IntentGeneration, observedNow); err != nil {
		return Journal{}, fmt.Errorf("package transaction expansion preflight: %w", err)
	}
	deadline := observedNow.Add(plan.TotalTimeout)
	if plan.Deadline.Before(deadline) {
		deadline = plan.Deadline
	}
	if !deadline.After(observedNow) {
		return Journal{}, fmt.Errorf("package transaction deadline elapsed")
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	unlockRepositories, err := engine.Executor.LockRepositories(ctx, plan)
	if err != nil || unlockRepositories == nil {
		return Journal{}, errors.Join(err, fmt.Errorf("lock exact package repository metadata"))
	}
	defer unlockRepositories()

	audit, err := engine.Executor.Audit(ctx, plan)
	if err != nil {
		return Journal{}, fmt.Errorf("package transaction preflight audit: %w", err)
	}
	if err := ValidateAPTConfigurationBasic(audit.Configuration, audit.Repositories); err != nil {
		return Journal{}, err
	}
	if err := ValidateDPKGReady(audit.DPKG); err != nil {
		return Journal{}, err
	}
	if err := validateNoAutostartPolicy(plan, audit.NoAutostart); err != nil {
		return Journal{}, err
	}
	if err := validateBefore(plan, audit.Before); err != nil {
		return Journal{}, err
	}
	planDigest, authorityDigest, err := transactionDigests(plan)
	if err != nil {
		return Journal{}, err
	}
	profile := child.ProfileAPTOfflineTransaction
	staged := true
	if plan.Mode == DistroRepository && len(plan.Repositories) == 0 {
		profile = child.ProfileAPTTransaction
		staged = false
	}
	normalJournalID := "package-" + plan.TransactionID
	childID := "package-child-" + plan.TransactionID
	journal := Journal{SchemaVersion: PackageJournalSchemaVersion, TransactionID: plan.TransactionID, NormalJournalID: normalJournalID, ChildID: childID, JobID: plan.JobID, PlanDigest: planDigest, AuthorityDigest: authorityDigest, PackageProfile: profile, Prior: cloneRuntimeSnapshot(audit.Before), Phase: JournalPrepared, Masks: []MaskIdentity{}}
	if err := ValidateJournal(journal); err != nil {
		return Journal{}, err
	}
	if err := engine.Journals.Create(ctx, journal); err != nil {
		return Journal{}, fmt.Errorf("persist package transaction intent: %w", err)
	}
	aptConfig, aptSources, err := RenderAPTConfiguration(plan)
	if err != nil {
		return journal, err
	}
	if err := engine.Executor.Prepare(ctx, plan, aptConfig, aptSources); err != nil {
		return journal, fmt.Errorf("prepare exact package transaction files: %w", err)
	}
	next := journal
	next.Phase = JournalFilesPrepared
	if err := engine.Journals.Advance(ctx, journal, next); err != nil {
		return journal, fmt.Errorf("persist prepared package transaction files: %w", err)
	}
	journal = next
	if err := engine.Executor.Stage(ctx, plan); err != nil {
		return journal, fmt.Errorf("stage exact package artifacts: %w", err)
	}
	next = journal
	next.Phase = JournalArtifactsStaged
	if err := engine.Journals.Advance(ctx, journal, next); err != nil {
		return journal, fmt.Errorf("persist staged package artifact authority: %w", err)
	}
	journal = next
	resolved, err := engine.Executor.Resolve(ctx, plan)
	if err != nil {
		return journal, fmt.Errorf("simulate exact package closure: %w", err)
	}
	if !reflectPackages(resolved, plan.Packages) {
		return journal, fmt.Errorf("resolved package closure differs from the frozen Plan")
	}

	units := affectedUnits(plan.Packages)
	next = journal
	next.Phase = JournalMasking
	if err := engine.Journals.Advance(ctx, journal, next); err != nil {
		return journal, fmt.Errorf("persist package masking phase: %w", err)
	}
	journal = next
	masks, err := engine.Executor.Mask(ctx, units, journal.MaskIntent, func(unit string) error {
		if err := validateMaskIntent(units, journal.Prior, journal.Masks, journal.MaskIntent, unit); err != nil {
			return err
		}
		advanced := journal
		advanced.MaskIntent = unit
		if err := engine.Journals.Advance(ctx, journal, advanced); err != nil {
			return err
		}
		journal = advanced
		return nil
	}, func(identity MaskIdentity) error {
		if err := validateMaskAppend(units, journal.Prior, journal.Masks, journal.MaskIntent, identity); err != nil {
			return err
		}
		advanced := journal
		advanced.Masks = append(append([]MaskIdentity(nil), journal.Masks...), identity)
		advanced.MaskIntent = ""
		if err := engine.Journals.Advance(ctx, journal, advanced); err != nil {
			return err
		}
		journal = advanced
		return nil
	})
	if err != nil {
		return journal, fmt.Errorf("apply package no-autostart masks: %w", err)
	}
	if !slices.Equal(masks.Masks, journal.Masks) {
		return journal, fmt.Errorf("package mask result differs from the exact persisted identities")
	}
	if err := validateMasks(units, audit.Before, masks); err != nil {
		return journal, err
	}
	next = journal
	next.Phase = JournalMasksApplied
	next.MasksComplete = true
	if err := engine.Journals.Advance(ctx, journal, next); err != nil {
		return journal, fmt.Errorf("persist package mask authority: %w", err)
	}
	journal = next

	finalAudit, err := engine.Executor.Audit(ctx, plan)
	if err != nil {
		return journal, fmt.Errorf("final pre-child package audit: %w", err)
	}
	if err := ValidateAPTConfiguration(finalAudit.Configuration, finalAudit.Repositories, plan.Repositories); err != nil {
		return journal, fmt.Errorf("final pre-child APT authority audit: %w", err)
	}
	if err := ValidateDPKGReady(finalAudit.DPKG); err != nil {
		return journal, fmt.Errorf("final pre-child dpkg audit: %w", err)
	}
	if err := validateNoAutostartPolicy(plan, finalAudit.NoAutostart); err != nil {
		return journal, fmt.Errorf("final pre-child no-autostart authority audit: %w", err)
	}
	if err := validateResumeRuntime(JournalMasksApplied, audit.Before, finalAudit.Before, journal.Masks, ""); err != nil {
		return journal, fmt.Errorf("final pre-child runtime audit: %w", err)
	}
	if err := engine.Executor.VerifyMasks(ctx, journal.Masks); err != nil {
		return journal, fmt.Errorf("final pre-child package mask audit: %w", err)
	}
	if err := engine.Executor.VerifyStaged(ctx, plan); err != nil {
		return journal, fmt.Errorf("final pre-child staged package artifact audit: %w", err)
	}

	monitoredCtx := ctx
	stopMonitor := func() error { return nil }
	if engine.Monitor != nil {
		monitoredCtx, stopMonitor, err = engine.Monitor.Start(ctx, units, possibleListeners(plan.Packages))
		if err != nil {
			return journal, fmt.Errorf("start package unit/listener monitor: %w", err)
		}
	}
	monitorStopped := false
	defer func() {
		if !monitorStopped {
			_ = stopMonitor()
		}
	}()

	next = journal
	next.Phase = JournalChildSubmitted
	if err := engine.Journals.Advance(ctx, journal, next); err != nil {
		return journal, fmt.Errorf("persist package child submission: %w", err)
	}
	journal = next
	invocation := packageInvocation(plan, staged)
	result, runErr := engine.Executor.Run(monitoredCtx, profile, invocation)
	monitorErr := stopMonitor()
	monitorStopped = true
	if engine.MonitorRequired && engine.Monitor == nil {
		monitorErr = fmt.Errorf("qualified package monitor is unavailable")
	}
	next = journal
	next.Phase = JournalChildTerminal
	next.ChildResultDigest = childResultDigest(result)
	next.ChildSucceeded = runErr == nil && result.ExitCode == 0 && !result.OutputCutOff && monitorErr == nil
	if !next.ChildSucceeded {
		next.ErrorCode = packageFailureCode(runErr, monitorErr, result)
	}
	if err := engine.Journals.Advance(context.WithoutCancel(ctx), journal, next); err != nil {
		return journal, errors.Join(runErr, monitorErr, fmt.Errorf("persist terminal package child result: %w", err))
	}
	journal = next
	if !journal.ChildSucceeded {
		return journal, errors.Join(runErr, monitorErr, fmt.Errorf("package child failed under retained no-start masks"))
	}

	observed, err := engine.Executor.Observe(ctx, plan)
	if err != nil {
		return journal, fmt.Errorf("observe package postcondition: %w", err)
	}
	retained := maskNames(masks.Masks)
	observed.RetainedMasks = retained
	if err := ValidatePostcondition(plan, audit.Before, observed, createdMaskNames(masks.Masks)); err != nil {
		return journal, err
	}
	postDigest, err := digestValue(observed)
	if err != nil {
		return journal, err
	}
	next = journal
	next.Phase = JournalVerified
	next.PostconditionDigest = postDigest
	next.ErrorCode = ""
	if err := engine.Journals.Advance(ctx, journal, next); err != nil {
		return journal, fmt.Errorf("persist verified package postcondition: %w", err)
	}
	journal = next

	next = journal
	next.Phase = JournalCommitted
	if err := engine.Journals.Advance(ctx, journal, next); err != nil {
		return journal, fmt.Errorf("persist committed package transaction before mask cleanup: %w", err)
	}
	journal = next
	if err := engine.Executor.VerifyMasks(ctx, preexistingMasks(masks.Masks)); err != nil {
		return journal, fmt.Errorf("verify preexisting package masks before cleanup: %w", err)
	}
	if err := engine.Executor.Unmask(ctx, createdMasks(masks.Masks)); err != nil {
		return journal, fmt.Errorf("remove only exact transaction-created package masks: %w", err)
	}
	next = journal
	next.Phase = JournalCleaned
	if err := engine.Journals.Advance(ctx, journal, next); err != nil {
		return journal, fmt.Errorf("persist cleaned package transaction: %w", err)
	}
	return next, nil
}

// Resume continues only the exact persisted package transaction. It performs
// no rollback, plan substitution, package re-resolution outside the frozen
// closure, or unit-mask adoption.
func (engine Engine) Resume(ctx context.Context, plan Plan, preflightResult preflight.Result, journal Journal) (Journal, error) {
	if engine.Journals == nil || engine.Executor == nil || engine.MonitorRequired && engine.Monitor == nil {
		return Journal{}, fmt.Errorf("package transaction dependencies are incomplete")
	}
	if err := ValidatePlan(plan); err != nil {
		return Journal{}, err
	}
	if err := ValidateJournal(journal); err != nil {
		return Journal{}, err
	}
	planDigest, authorityDigest, err := transactionDigests(plan)
	if err != nil || journal.TransactionID != plan.TransactionID || journal.JobID != plan.JobID || journal.PlanDigest != planDigest || journal.AuthorityDigest != authorityDigest {
		return Journal{}, fmt.Errorf("package resume authority differs from the exact journal")
	}
	units := affectedUnits(plan.Packages)
	if journal.Phase == JournalMasking {
		if err := validateMaskProgress(units, journal.Prior, journal.Masks, journal.MaskIntent); err != nil {
			return journal, err
		}
	}
	if journal.MasksComplete {
		if err := validateMasks(units, journal.Prior, MaskResult{Masks: journal.Masks}); err != nil {
			return journal, err
		}
	}
	if journal.Phase == JournalCleaned {
		return journal, nil
	}
	if journal.Phase == JournalCommitted {
		if err := engine.Executor.VerifyMasks(ctx, preexistingMasks(journal.Masks)); err != nil {
			return journal, err
		}
		if err := engine.Executor.Unmask(ctx, createdMasks(journal.Masks)); err != nil {
			return journal, err
		}
		next := journal
		next.Phase = JournalCleaned
		if err := engine.Journals.Advance(context.WithoutCancel(ctx), journal, next); err != nil {
			return journal, err
		}
		return next, nil
	}
	now := time.Now().UTC
	if engine.Now != nil {
		now = engine.Now
	}
	observedNow := now().UTC()
	terminalRecovery := journal.Phase == JournalChildSubmitted || journal.Phase == JournalChildTerminal && journal.ChildSucceeded || journal.Phase == JournalVerified
	cancel := func() {}
	if !terminalRecovery {
		if err := preflight.RequireExpansionResult(preflightResult, []preflight.ExpansionScope{preflight.ExpansionBootstrap, preflight.ExpansionHeadscale}, "installation", plan.IntentGeneration, observedNow); err != nil {
			return journal, fmt.Errorf("package resume expansion preflight: %w", err)
		}
		deadline := observedNow.Add(plan.TotalTimeout)
		if plan.Deadline.Before(deadline) {
			deadline = plan.Deadline
		}
		if !deadline.After(observedNow) {
			return journal, fmt.Errorf("package resume deadline elapsed")
		}
		ctx, cancel = context.WithDeadline(ctx, deadline)
	}
	defer cancel()
	unlockRepositories := func() {}
	switch journal.Phase {
	case JournalPrepared, JournalFilesPrepared, JournalArtifactsStaged, JournalMasking, JournalMasksApplied:
		unlockRepositories, err = engine.Executor.LockRepositories(ctx, plan)
	case JournalChildTerminal:
		if journal.ChildSucceeded {
			unlockRepositories, err = engine.Executor.LockRepositories(ctx, plan)
		}
	}
	if err != nil || unlockRepositories == nil {
		return journal, errors.Join(err, fmt.Errorf("lock exact package repository metadata for resume"))
	}
	defer unlockRepositories()
	advance := func(next Journal) error {
		if err := engine.Journals.Advance(context.WithoutCancel(ctx), journal, next); err != nil {
			return err
		}
		journal = next
		return nil
	}
	for {
		switch journal.Phase {
		case JournalPrepared, JournalFilesPrepared, JournalArtifactsStaged, JournalMasking:
			audit, auditErr := engine.Executor.Audit(ctx, plan)
			if auditErr != nil || ValidateAPTConfiguration(audit.Configuration, audit.Repositories, plan.Repositories) != nil || ValidateDPKGReady(audit.DPKG) != nil {
				return journal, errors.Join(auditErr, fmt.Errorf("package resume pre-child audit failed"))
			}
			if err := validateNoAutostartPolicy(plan, audit.NoAutostart); err != nil {
				return journal, fmt.Errorf("package resume no-autostart authority changed: %w", err)
			}
			if err := validateResumeRuntime(journal.Phase, journal.Prior, audit.Before, journal.Masks, journal.MaskIntent); err != nil {
				return journal, err
			}
			switch journal.Phase {
			case JournalPrepared:
				aptConfig, aptSources, renderErr := RenderAPTConfiguration(plan)
				if renderErr != nil {
					return journal, renderErr
				}
				if err := engine.Executor.Prepare(ctx, plan, aptConfig, aptSources); err != nil {
					return journal, err
				}
				next := journal
				next.Phase = JournalFilesPrepared
				if err := advance(next); err != nil {
					return journal, err
				}
			case JournalFilesPrepared:
				if err := engine.Executor.Stage(ctx, plan); err != nil {
					return journal, err
				}
				next := journal
				next.Phase = JournalArtifactsStaged
				if err := advance(next); err != nil {
					return journal, err
				}
			case JournalArtifactsStaged:
				resolved, err := engine.Executor.Resolve(ctx, plan)
				if err != nil || !reflectPackages(resolved, plan.Packages) {
					return journal, errors.Join(err, fmt.Errorf("package resume closure differs from the frozen Plan"))
				}
				next := journal
				next.Phase = JournalMasking
				if err := advance(next); err != nil {
					return journal, err
				}
			case JournalMasking:
				if len(journal.Masks) != 0 {
					if err := engine.Executor.VerifyMasks(ctx, journal.Masks); err != nil {
						return journal, err
					}
				}
				remaining := units[len(journal.Masks):]
				if len(remaining) != 0 {
					persisted := len(journal.Masks)
					created, err := engine.Executor.Mask(ctx, remaining, journal.MaskIntent, func(unit string) error {
						if err := validateMaskIntent(units, journal.Prior, journal.Masks, journal.MaskIntent, unit); err != nil {
							return err
						}
						next := journal
						next.MaskIntent = unit
						return advance(next)
					}, func(identity MaskIdentity) error {
						if err := validateMaskAppend(units, journal.Prior, journal.Masks, journal.MaskIntent, identity); err != nil {
							return err
						}
						next := journal
						next.Masks = append(append([]MaskIdentity(nil), journal.Masks...), identity)
						next.MaskIntent = ""
						return advance(next)
					})
					if err != nil {
						return journal, err
					}
					if !slices.Equal(created.Masks, journal.Masks[persisted:]) {
						return journal, fmt.Errorf("package mask result differs from the exact persisted identities")
					}
				}
				result := MaskResult{Masks: journal.Masks}
				if err := validateMasks(units, journal.Prior, result); err != nil {
					return journal, err
				}
				next := journal
				next.Phase = JournalMasksApplied
				next.MasksComplete = true
				if err := advance(next); err != nil {
					return journal, err
				}
			}
		case JournalMasksApplied:
			audit, auditErr := engine.Executor.Audit(ctx, plan)
			if auditErr != nil || ValidateAPTConfiguration(audit.Configuration, audit.Repositories, plan.Repositories) != nil || ValidateDPKGReady(audit.DPKG) != nil {
				return journal, errors.Join(auditErr, fmt.Errorf("package resume pre-child audit failed"))
			}
			if err := validateNoAutostartPolicy(plan, audit.NoAutostart); err != nil {
				return journal, fmt.Errorf("package resume no-autostart authority changed: %w", err)
			}
			if err := validateResumeRuntime(journal.Phase, journal.Prior, audit.Before, journal.Masks, journal.MaskIntent); err != nil {
				return journal, err
			}
			if err := engine.Executor.VerifyMasks(ctx, journal.Masks); err != nil {
				return journal, err
			}
			if err := engine.Executor.VerifyStaged(ctx, plan); err != nil {
				return journal, fmt.Errorf("pre-child staged package artifact audit: %w", err)
			}
			monitoredCtx := ctx
			stopMonitor := func() error { return nil }
			if engine.Monitor != nil {
				monitoredCtx, stopMonitor, err = engine.Monitor.Start(ctx, units, possibleListeners(plan.Packages))
				if err != nil {
					return journal, err
				}
			}
			next := journal
			next.Phase = JournalChildSubmitted
			if err := advance(next); err != nil {
				_ = stopMonitor()
				return journal, err
			}
			staged := plan.Mode != DistroRepository || len(plan.Repositories) != 0
			result, runErr := engine.Executor.Run(monitoredCtx, journal.PackageProfile, packageInvocation(plan, staged))
			monitorErr := stopMonitor()
			next = journal
			next.Phase = JournalChildTerminal
			next.ChildResultDigest = childResultDigest(result)
			next.ChildSucceeded = runErr == nil && result.ExitCode == 0 && !result.OutputCutOff && monitorErr == nil
			if !next.ChildSucceeded {
				next.ErrorCode = packageFailureCode(runErr, monitorErr, result)
			}
			if err := advance(next); err != nil {
				return journal, errors.Join(runErr, monitorErr, err)
			}
			if !journal.ChildSucceeded {
				return journal, errors.Join(runErr, monitorErr, fmt.Errorf("exact package child failed under retained masks"))
			}
		case JournalChildSubmitted:
			if err := engine.Executor.VerifyMasks(ctx, journal.Masks); err != nil {
				return journal, err
			}
			return journal, fmt.Errorf("submitted package child terminal result is unknown and remains fenced")
		case JournalChildTerminal:
			if !journal.ChildSucceeded {
				return journal, fmt.Errorf("failed package child remains fenced and is not retryable as success")
			}
			observed, err := engine.Executor.Observe(ctx, plan)
			if err != nil {
				return journal, err
			}
			observed.RetainedMasks = maskNames(journal.Masks)
			if err := ValidatePostcondition(plan, journal.Prior, observed, createdMaskNames(journal.Masks)); err != nil {
				return journal, err
			}
			postDigest, err := digestValue(observed)
			if err != nil {
				return journal, err
			}
			next := journal
			next.Phase = JournalVerified
			next.PostconditionDigest = postDigest
			next.ErrorCode = ""
			if err := advance(next); err != nil {
				return journal, err
			}
		case JournalVerified:
			next := journal
			next.Phase = JournalCommitted
			if err := advance(next); err != nil {
				return journal, err
			}
		case JournalCommitted:
			if err := engine.Executor.VerifyMasks(ctx, preexistingMasks(journal.Masks)); err != nil {
				return journal, err
			}
			if err := engine.Executor.Unmask(ctx, createdMasks(journal.Masks)); err != nil {
				return journal, err
			}
			next := journal
			next.Phase = JournalCleaned
			if err := advance(next); err != nil {
				return journal, err
			}
		case JournalCleaned:
			return journal, nil
		default:
			return journal, fmt.Errorf("package resume phase is unsupported")
		}
	}
}

func ValidateJournal(journal Journal) error {
	if journal.SchemaVersion != PackageJournalSchemaVersion || !transactionPattern.MatchString(journal.TransactionID) || journal.NormalJournalID != "package-"+journal.TransactionID || journal.ChildID != "package-child-"+journal.TransactionID || !jobPattern.MatchString(journal.JobID) || !digestPattern.MatchString(journal.PlanDigest) || !digestPattern.MatchString(journal.AuthorityDigest) || journal.PackageProfile != child.ProfileAPTTransaction && journal.PackageProfile != child.ProfileAPTOfflineTransaction || validateRuntime(journal.Prior) != nil || len(journal.Prior.Units) > 4096 || len(journal.Prior.Listeners) > 4096 || !validMaskIdentities(journal.Masks) || !validJournalMaskIntent(journal) {
		return fmt.Errorf("package journal identity, prior state, or mask authority is invalid")
	}
	switch journal.Phase {
	case JournalPrepared, JournalArtifactsStaged, JournalFilesPrepared:
		if len(journal.Masks) != 0 || journal.MaskIntent != "" || journal.MasksComplete || journal.ChildResultDigest != "" || journal.ChildSucceeded || journal.PostconditionDigest != "" || journal.ErrorCode != "" {
			return fmt.Errorf("prepared package journal contains later-phase evidence")
		}
	case JournalMasking:
		if journal.MasksComplete || journal.ChildResultDigest != "" || journal.ChildSucceeded || journal.PostconditionDigest != "" || journal.ErrorCode != "" {
			return fmt.Errorf("package masking journal contains later-phase evidence")
		}
	case JournalMasksApplied, JournalChildSubmitted:
		if journal.MaskIntent != "" || !journal.MasksComplete || journal.ChildResultDigest != "" || journal.ChildSucceeded || journal.PostconditionDigest != "" || journal.ErrorCode != "" {
			return fmt.Errorf("pre-child package journal contains terminal evidence")
		}
	case JournalChildTerminal:
		if journal.MaskIntent != "" || !journal.MasksComplete || !digestPattern.MatchString(journal.ChildResultDigest) || journal.PostconditionDigest != "" || journal.ChildSucceeded == (journal.ErrorCode != "") {
			return fmt.Errorf("terminal package child evidence is incomplete")
		}
	case JournalVerified, JournalCommitted, JournalCleaned:
		if journal.MaskIntent != "" || !journal.MasksComplete || !journal.ChildSucceeded || journal.ErrorCode != "" || !digestPattern.MatchString(journal.ChildResultDigest) || !digestPattern.MatchString(journal.PostconditionDigest) {
			return fmt.Errorf("verified package journal evidence is incomplete")
		}
	default:
		return fmt.Errorf("package journal phase is unknown")
	}
	return nil
}

func validJournalMaskIntent(journal Journal) bool {
	if journal.MaskIntent == "" {
		return true
	}
	if journal.Phase != JournalMasking || !unitPattern.MatchString(journal.MaskIntent) || len(journal.Masks) != 0 && journal.Masks[len(journal.Masks)-1].Unit >= journal.MaskIntent {
		return false
	}
	index := slices.IndexFunc(journal.Prior.Units, func(unit UnitState) bool { return unit.Name == journal.MaskIntent })
	return index >= 0 && !journal.Prior.Units[index].Masked
}

func ValidateJournalTransition(before, after Journal) error {
	if err := ValidateJournal(before); err != nil {
		return err
	}
	if err := ValidateJournal(after); err != nil {
		return err
	}
	sameMasks := slices.Equal(before.Masks, after.Masks)
	intentBegin := before.Phase == JournalMasking && after.Phase == JournalMasking && sameMasks && before.MaskIntent == "" && after.MaskIntent != ""
	maskAppend := before.Phase == JournalMasking && after.Phase == JournalMasking && len(after.Masks) == len(before.Masks)+1 && slices.Equal(after.Masks[:len(before.Masks)], before.Masks)
	if maskAppend {
		appended := after.Masks[len(before.Masks)]
		maskAppend = after.MaskIntent == "" && (appended.Preexisting && before.MaskIntent == "" || !appended.Preexisting && before.MaskIntent == appended.Unit)
	}
	if before.SchemaVersion != after.SchemaVersion || before.TransactionID != after.TransactionID || before.NormalJournalID != after.NormalJournalID || before.ChildID != after.ChildID || before.JobID != after.JobID || before.PlanDigest != after.PlanDigest || before.AuthorityDigest != after.AuthorityDigest || before.PackageProfile != after.PackageProfile || !reflect.DeepEqual(before.Prior, after.Prior) || !intentBegin && !maskAppend && (!sameMasks || before.MaskIntent != after.MaskIntent) || before.MasksComplete && !after.MasksComplete {
		return fmt.Errorf("package journal immutable authority was rewritten")
	}
	allowed := map[JournalPhase]JournalPhase{
		JournalPrepared:        JournalFilesPrepared,
		JournalFilesPrepared:   JournalArtifactsStaged,
		JournalArtifactsStaged: JournalMasking,
		JournalMasking:         JournalMasksApplied,
		JournalMasksApplied:    JournalChildSubmitted,
		JournalChildSubmitted:  JournalChildTerminal,
		JournalChildTerminal:   JournalVerified,
		JournalVerified:        JournalCommitted,
		JournalCommitted:       JournalCleaned,
	}
	if intentBegin || maskAppend {
		return nil
	}
	if allowed[before.Phase] != after.Phase {
		return fmt.Errorf("package journal phase transition is invalid")
	}
	return nil
}

func packageInvocation(plan Plan, staged bool) child.Invocation {
	packages := make([]child.PackageArgument, 0, len(plan.Packages))
	for _, pkg := range plan.Packages {
		packages = append(packages, child.PackageArgument{Name: pkg.Name, Version: pkg.Version, VersionMinimum: pkg.VersionMinimum, VersionMaximum: pkg.VersionMaximum, Digest: pkg.ArtifactDigest, Bytes: pkg.ArtifactBytes, MaximumInstalledFileBytes: pkg.MaximumInstalledFileBytes})
	}
	return child.Invocation{Package: &child.PackageInvocation{TransactionID: plan.TransactionID, LockWaitSeconds: uint32(plan.LockWait / time.Second), Staged: staged, Packages: packages}}
}

func validateNoAutostartPolicy(plan Plan, policy NoAutostartPolicy) error {
	if policy.Path != "/usr/sbin/policy-rc.d" || policy.Digest != plan.NoAutostartPolicyDigest || policy.UID != 0 || policy.GID != 0 || policy.Mode != 0o755 || !policy.Regular || policy.Linked || !policy.ParentsSafe || !policy.SameLanPanelBinary {
		return fmt.Errorf("package no-autostart policy identity is missing or unsafe")
	}
	return nil
}

func validateBefore(plan Plan, before RuntimeSnapshot) error {
	if err := validateRuntime(before); err != nil {
		return err
	}
	if hasPackage(plan.Packages, "nginx") {
		installed := hasPackage(before.Installed, "nginx")
		if plan.FirstNginxInstall && installed {
			return fmt.Errorf("nginx is already installed outside LanPanel; remove the foreign Nginx installation or use the existing LanPanel-owned transaction; no package mutation was performed")
		}
		if !plan.FirstNginxInstall && !installed {
			return fmt.Errorf("LanPanel-owned Nginx is missing from the audited installed state")
		}
	}
	units := affectedUnits(plan.Packages)
	state := map[string]UnitState{}
	for _, unit := range before.Units {
		state[unit.Name] = unit
	}
	for _, unit := range units {
		observed, exists := state[unit]
		if !exists || observed.Active {
			return fmt.Errorf("affected package unit is missing from inventory or already active")
		}
	}
	return nil
}

func validateMasks(expected []string, before RuntimeSnapshot, result MaskResult) error {
	if !validMaskIdentities(result.Masks) || !slices.Equal(maskNames(result.Masks), expected) {
		return fmt.Errorf("package mask result does not cover exact affected units")
	}
	prior := map[string]UnitState{}
	for _, unit := range before.Units {
		prior[unit.Name] = unit
	}
	for _, mask := range result.Masks {
		unit, exists := prior[mask.Unit]
		if !exists || mask.Preexisting != unit.Masked {
			return fmt.Errorf("package mask ownership differs from the audited prior state")
		}
	}
	return nil
}

func validateMaskPrefix(expected []string, before RuntimeSnapshot, masks []MaskIdentity) error {
	if len(masks) > len(expected) || !validMaskIdentities(masks) || !slices.Equal(maskNames(masks), expected[:len(masks)]) {
		return fmt.Errorf("package resume mask journal is not an exact unit prefix")
	}
	prior := map[string]UnitState{}
	for _, unit := range before.Units {
		prior[unit.Name] = unit
	}
	for _, mask := range masks {
		unit, exists := prior[mask.Unit]
		if !exists || mask.Preexisting != unit.Masked {
			return fmt.Errorf("package mask ownership differs from the audited prior state")
		}
	}
	return nil
}

func validateMaskProgress(expected []string, before RuntimeSnapshot, masks []MaskIdentity, intent string) error {
	if err := validateMaskPrefix(expected, before, masks); err != nil {
		return err
	}
	if intent == "" {
		return nil
	}
	if len(masks) >= len(expected) || intent != expected[len(masks)] {
		return fmt.Errorf("package mask intent is not the exact next unit")
	}
	index := slices.IndexFunc(before.Units, func(unit UnitState) bool { return unit.Name == intent })
	if index < 0 || before.Units[index].Masked {
		return fmt.Errorf("package mask intent cannot adopt a preexisting mask")
	}
	return nil
}

func validateMaskIntent(expected []string, before RuntimeSnapshot, masks []MaskIdentity, current, requested string) error {
	if current != "" || requested == "" {
		return fmt.Errorf("package mask intent callback is ambiguous")
	}
	return validateMaskProgress(expected, before, masks, requested)
}

func validateMaskAppend(expected []string, before RuntimeSnapshot, masks []MaskIdentity, intent string, identity MaskIdentity) error {
	if len(masks) >= len(expected) || identity.Unit != expected[len(masks)] {
		return fmt.Errorf("package mask callback is not the exact next unit")
	}
	if identity.Preexisting && intent != "" || !identity.Preexisting && intent != identity.Unit {
		return fmt.Errorf("package mask identity does not complete its exact durable intent")
	}
	appended := append(append([]MaskIdentity(nil), masks...), identity)
	if err := validateMaskPrefix(expected, before, appended); err != nil {
		return fmt.Errorf("package mask callback is not an exact identity prefix: %w", err)
	}
	return nil
}

func validateResumeRuntime(phase JournalPhase, prior, current RuntimeSnapshot, masks []MaskIdentity, intent string) error {
	expected := prior
	expected.Units = append([]UnitState(nil), prior.Units...)
	if phase == JournalMasking || phase == JournalMasksApplied {
		for _, mask := range masks {
			index := slices.IndexFunc(expected.Units, func(unit UnitState) bool { return unit.Name == mask.Unit })
			if index < 0 {
				return fmt.Errorf("package resume mask unit is absent from the prior runtime")
			}
			expected.Units[index].Masked = true
		}
	}
	if runtimeSnapshotsEqual(current, expected) {
		return nil
	}
	if phase == JournalMasking && intent != "" {
		index := slices.IndexFunc(expected.Units, func(unit UnitState) bool { return unit.Name == intent })
		if index >= 0 && !expected.Units[index].Masked {
			expected.Units[index].Masked = true
			if runtimeSnapshotsEqual(current, expected) {
				return nil
			}
		}
	}
	return fmt.Errorf("package resume runtime changed outside the exact %s phase allowance", phase)
}

func runtimeSnapshotsEqual(left, right RuntimeSnapshot) bool {
	return reflectPackages(left.Installed, right.Installed) &&
		slices.Equal(left.SystemPackages, right.SystemPackages) &&
		slices.Equal(left.Units, right.Units) &&
		slices.Equal(left.Listeners, right.Listeners)
}

func PlanDigest(plan Plan) (string, error) {
	if err := ValidatePlan(plan); err != nil {
		return "", err
	}
	return digestValue(plan)
}

func JournalDigest(journal Journal) (string, error) {
	if err := ValidateJournal(journal); err != nil {
		return "", err
	}
	return digestValue(journal)
}

func transactionDigests(plan Plan) (string, string, error) {
	planDigest, err := digestValue(plan)
	if err != nil {
		return "", "", err
	}
	authorityDigest, err := digestValue(plan.Authority)
	return planDigest, authorityDigest, err
}

func digestValue(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func childResultDigest(result child.Result) string {
	digest, _ := digestValue(result)
	return digest
}

func packageFailureCode(runErr, monitorErr error, result child.Result) string {
	switch {
	case monitorErr != nil:
		return "unit_or_listener_bypass"
	case errors.Is(runErr, context.DeadlineExceeded) || errors.Is(runErr, context.Canceled):
		return "package_child_interrupted"
	case result.OutputCutOff:
		return "package_output_unbounded"
	default:
		return "package_child_failed"
	}
}

func reflectPackages(left, right []Package) bool {
	return slices.EqualFunc(left, right, func(a, b Package) bool {
		return a.Name == b.Name && PackageVersionMatches(b, a.Version) && a.Architecture == b.Architecture && a.RepositoryID == b.RepositoryID && a.RepositoryFilename == b.RepositoryFilename && a.ArtifactDigest == b.ArtifactDigest && a.ArtifactBytes == b.ArtifactBytes && a.MaximumInstalledFileBytes == b.MaximumInstalledFileBytes && a.StagedIdentity == b.StagedIdentity && reflect.DeepEqual(a.Source, b.Source) && slices.Equal(a.AffectedUnits, b.AffectedUnits) && slices.Equal(a.PossibleListeners, b.PossibleListeners)
	})
}

func possibleListeners(packages []Package) []string {
	listeners := []string{}
	for _, pkg := range packages {
		listeners = append(listeners, pkg.PossibleListeners...)
	}
	slices.Sort(listeners)
	return slices.Compact(listeners)
}

func sortedUniqueUnits(values []string) bool {
	return validateSortedUnits(values) == nil
}

func validMaskIdentities(values []MaskIdentity) bool {
	previous := ""
	for _, value := range values {
		if !unitPattern.MatchString(value.Unit) || value.Device == 0 || value.Inode == 0 || value.CTimeSec == 0 || previous != "" && strings.Compare(previous, value.Unit) >= 0 {
			return false
		}
		previous = value.Unit
	}
	return true
}

func maskNames(values []MaskIdentity) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.Unit)
	}
	return result
}

func preexistingMasks(values []MaskIdentity) []MaskIdentity {
	result := []MaskIdentity{}
	for _, value := range values {
		if value.Preexisting {
			result = append(result, value)
		}
	}
	return result
}

func createdMasks(values []MaskIdentity) []MaskIdentity {
	result := []MaskIdentity{}
	for _, value := range values {
		if !value.Preexisting {
			result = append(result, value)
		}
	}
	return result
}

func createdMaskNames(values []MaskIdentity) []string { return maskNames(createdMasks(values)) }

func cloneRuntimeSnapshot(value RuntimeSnapshot) RuntimeSnapshot {
	value.Installed = clonePackagesForJournal(value.Installed)
	value.SystemPackages = append([]InstalledPackage(nil), value.SystemPackages...)
	value.Units = append([]UnitState(nil), value.Units...)
	value.Listeners = append([]Listener(nil), value.Listeners...)
	return value
}

func clonePackagesForJournal(values []Package) []Package {
	result := append([]Package(nil), values...)
	for index := range result {
		result[index].AffectedUnits = append([]string(nil), result[index].AffectedUnits...)
		result[index].PossibleListeners = append([]string(nil), result[index].PossibleListeners...)
		result[index].Source.OfficialAuthorities = slices.Clone(result[index].Source.OfficialAuthorities)
	}
	return result
}
