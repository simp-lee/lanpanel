package qualification

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"lanpanel/internal/release"
	"slices"
	"time"
)

type PriorObservation struct {
	Scope           []byte
	PriorState      []byte
	PlannedMutation []byte
	Selector        []byte
}

type MutationObservation struct {
	Identity string
	Evidence []byte
}

type Executor interface {
	Observe(context.Context, string) (PriorObservation, error)
	Execute(context.Context, string) (MutationObservation, error)
	Recover(context.Context, string) (MutationObservation, error)
	Cleanup(context.Context, string, MutationObservation, string) (release.CleanupResult, error)
}

type ReportStore interface {
	Read() (release.LiveCleanupReport, bool, error)
	Write(release.LiveCleanupReport) error
}

type Attestor interface {
	Attest(context.Context, release.LiveCleanupReport) ([]byte, error)
}

type AttestationStore interface {
	Write([]byte) error
}

type Runner struct {
	RunID                 string
	Plan                  release.LiveSideEffectPlan
	PlanDigest            string
	InstallManifestDigest string
	ProtectedInputDigest  string
	Executor              Executor
	Reports               ReportStore
	Attestor              Attestor
	Attestations          AttestationStore
	Now                   func() time.Time
	NewAttemptID          func() (string, error)
	ExecutionTimeout      time.Duration
	CleanupTimeout        time.Duration
}

// Run observes the exact prior state immediately before each fixed mutation.
// A resumed nonterminal run is cleanup-only: it never replays remote work and
// can never be promoted to a successful qualification.
func (runner Runner) Run(ctx context.Context) (release.LiveCleanupReport, error) {
	if runner.Executor == nil || runner.Reports == nil || runner.Attestor == nil || runner.Attestations == nil || runner.RunID != runner.Plan.RunID || !release.ValidDigest(runner.PlanDigest) || !release.ValidDigest(runner.InstallManifestDigest) || !release.ValidDigest(runner.ProtectedInputDigest) || runner.Now == nil || runner.ExecutionTimeout <= 0 || runner.ExecutionTimeout > 30*time.Minute || runner.CleanupTimeout <= 0 || runner.CleanupTimeout > 10*time.Minute {
		return release.LiveCleanupReport{}, fmt.Errorf("live qualification runner authority is incomplete")
	}
	if runner.NewAttemptID == nil {
		runner.NewAttemptID = newAttemptID
	}
	planBytes, marshalErr := release.MarshalCanonical(runner.Plan)
	if marshalErr != nil || release.DigestBytes(planBytes) != runner.PlanDigest {
		return release.LiveCleanupReport{}, fmt.Errorf("live qualification runner Plan digest changed")
	}
	decodedPlan, decodeErr := release.DecodeLiveSideEffectPlan(planBytes)
	if decodeErr != nil {
		return release.LiveCleanupReport{}, decodeErr
	}
	runner.Plan = decodedPlan
	if err := validateOrderedJourneyPlan(runner.Plan); err != nil {
		return release.LiveCleanupReport{}, err
	}
	planByID := make(map[string]release.PlannedMutation, len(runner.Plan.Mutations))
	for _, mutation := range runner.Plan.Mutations {
		planByID[mutation.ID] = mutation
	}

	report, present, err := runner.Reports.Read()
	if err != nil {
		return release.LiveCleanupReport{}, err
	}
	if present {
		if !sameReportAuthority(report, runner) || report.JourneySucceeded {
			return release.LiveCleanupReport{}, fmt.Errorf("persisted live journey authority differs or is already terminal")
		}
		report.ExecutionFailed = true
		if err := runner.writeReport(&report, false, ""); err != nil {
			return report, err
		}
		cleaned, cleanupErr := runner.cleanup(ctx, report, planByID)
		return cleaned, errors.Join(cleanupErr, fmt.Errorf("persisted nonterminal live journey is cleanup-only and cannot succeed"))
	}

	report = release.LiveCleanupReport{
		SchemaVersion:                      release.LiveCleanupReportSchemaVersion,
		RunID:                              runner.RunID,
		SideEffectPlanDigest:               runner.PlanDigest,
		QualificationInstallManifestDigest: runner.InstallManifestDigest,
		ProtectedInputDigest:               runner.ProtectedInputDigest,
		Steps:                              []release.JourneyStepResult{},
		Items:                              []release.CleanupItem{},
	}
	var runErr error
	for _, step := range orderedJourney {
		planned := planByID[step]
		observeCtx, observeCancel := context.WithTimeout(ctx, runner.ExecutionTimeout)
		observed, observeErr := runner.Executor.Observe(observeCtx, step)
		observeCancel()
		if observeErr != nil {
			report.ExecutionFailed = len(report.Steps) != 0
			runErr = errors.Join(runErr, fmt.Errorf("observe live qualification prior state for %q: %w", step, observeErr))
			break
		}
		if release.DigestBytes(observed.Scope) != planned.ScopeDigest || release.DigestBytes(observed.PriorState) != planned.PriorStateDigest || release.DigestBytes(observed.PlannedMutation) != planned.PlannedMutationDigest || release.DigestBytes(observed.Selector) != planned.SelectorDigest {
			report.ExecutionFailed = len(report.Steps) != 0
			runErr = errors.Join(runErr, fmt.Errorf("live qualification prior observation changed for %q", step))
			break
		}
		attemptID, attemptErr := runner.NewAttemptID()
		if attemptErr != nil || attemptID == "" {
			runErr = errors.Join(runErr, attemptErr, fmt.Errorf("create live qualification attempt identity"))
			break
		}
		setStep(&report, release.JourneyStepResult{MutationID: step, AttemptID: attemptID, Outcome: release.StepSubmitted})
		setItem(&report, release.CleanupItem{MutationID: step, ObservedIdentity: "pending/" + attemptID, Result: release.CleanupSubmitted})
		if err := runner.writeReport(&report, false, ""); err != nil {
			runErr = errors.Join(runErr, err)
			break
		}

		executeCtx, executeCancel := context.WithTimeout(ctx, runner.ExecutionTimeout)
		observation, executeErr := runner.Executor.Execute(executeCtx, step)
		executeCancel()
		terminalStep := release.JourneyStepResult{MutationID: step, AttemptID: attemptID}
		switch {
		case observation.Identity != "" && len(observation.Evidence) != 0 && executeErr == nil:
			terminalStep.Outcome = release.StepPassed
			terminalStep.EvidenceDigest = release.DigestBytes(observation.Evidence)
			setItem(&report, release.CleanupItem{MutationID: step, ObservedIdentity: observation.Identity, Result: release.CleanupExecuted})
		case observation.Identity != "" && executeErr != nil:
			terminalStep.Outcome = release.StepFailed
			if len(observation.Evidence) != 0 {
				terminalStep.EvidenceDigest = release.DigestBytes(observation.Evidence)
			}
			terminalStep.ErrorDigest = errorDigest(executeErr)
			setItem(&report, release.CleanupItem{MutationID: step, ObservedIdentity: observation.Identity, Result: release.CleanupExecuted})
			report.ExecutionFailed = true
		default:
			terminalStep.Outcome = release.StepUnknown
			if len(observation.Evidence) != 0 {
				terminalStep.EvidenceDigest = release.DigestBytes(observation.Evidence)
			}
			terminalStep.ErrorDigest = errorDigest(errors.Join(executeErr, fmt.Errorf("live mutation did not return a durable cleanup identity and evidence")))
			report.ExecutionFailed = true
		}
		setStep(&report, terminalStep)
		if err := runner.writeReport(&report, false, ""); err != nil {
			runErr = errors.Join(runErr, err)
			break
		}
		if terminalStep.Outcome != release.StepPassed {
			runErr = errors.Join(runErr, executeErr, fmt.Errorf("live mutation %q did not pass", step))
			break
		}
	}

	if len(report.Steps) == 0 {
		return report, runErr
	}
	cleaned, cleanupErr := runner.cleanup(ctx, report, planByID)
	runErr = errors.Join(runErr, cleanupErr)
	if runErr != nil {
		return cleaned, runErr
	}
	if !readyForAttestation(cleaned, runner.Plan) {
		return cleaned, fmt.Errorf("live qualification execution or cleanup is incomplete")
	}
	return runner.finalizeAttestation(ctx, cleaned)
}

func (runner Runner) cleanup(ctx context.Context, report release.LiveCleanupReport, planByID map[string]release.PlannedMutation) (release.LiveCleanupReport, error) {
	items := make(map[string]release.CleanupItem, len(report.Items))
	for _, item := range report.Items {
		items[item.MutationID] = item
	}
	var cleanupErr error
	for index := len(orderedJourney) - 1; index >= 0; index-- {
		step := orderedJourney[index]
		item, present := items[step]
		if !present || item.Result == release.CleanupCleaned || item.Result == release.CleanupRetained {
			continue
		}
		observation := MutationObservation{Identity: item.ObservedIdentity}
		if item.Result == release.CleanupSubmitted {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), runner.CleanupTimeout)
			recovered, recoverErr := runner.Executor.Recover(cleanupCtx, step)
			cancel()
			if recoverErr != nil || recovered.Identity == "" {
				cleanupErr = errors.Join(cleanupErr, recoverErr, fmt.Errorf("submitted live mutation %q cannot be recovered", step))
				continue
			}
			observation = recovered
			item = release.CleanupItem{MutationID: step, ObservedIdentity: recovered.Identity, Result: release.CleanupExecuted}
			setItem(&report, item)
			report.ExecutionFailed = true
			if err := runner.writeReport(&report, false, ""); err != nil {
				cleanupErr = errors.Join(cleanupErr, err)
				continue
			}
		}
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), runner.CleanupTimeout)
		result, err := runner.Executor.Cleanup(cleanupCtx, step, observation, planByID[step].CleanupPolicy)
		cancel()
		if err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
			continue
		}
		if result != release.CleanupCleaned && result != release.CleanupRetained || planByID[step].CleanupPolicy == "delete_exact" && result != release.CleanupCleaned {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("live qualification cleanup policy was not satisfied for %q", step))
			continue
		}
		setItem(&report, release.CleanupItem{MutationID: step, ObservedIdentity: observation.Identity, Result: result})
		if err := runner.writeReport(&report, false, ""); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	if !allCleanupTerminal(report, runner.Plan) {
		cleanupErr = errors.Join(cleanupErr, fmt.Errorf("live qualification cleanup report is incomplete"))
	}
	return report, cleanupErr
}

func (runner Runner) finalizeAttestation(ctx context.Context, report release.LiveCleanupReport) (release.LiveCleanupReport, error) {
	if !readyForAttestation(report, runner.Plan) {
		return report, fmt.Errorf("live qualification is not eligible for attestation")
	}
	attestation, err := runner.Attestor.Attest(ctx, report)
	if err != nil || len(attestation) == 0 {
		return report, errors.Join(err, fmt.Errorf("trusted live executor attestation failed"))
	}
	if _, err := release.DecodeLiveExecutorAttestation(attestation); err != nil {
		return report, err
	}
	if err := runner.Attestations.Write(attestation); err != nil {
		return report, err
	}
	if err := runner.writeReport(&report, true, release.DigestBytes(attestation)); err != nil {
		return report, err
	}
	return report, nil
}

func (runner Runner) writeReport(report *release.LiveCleanupReport, succeeded bool, attestationDigest string) error {
	report.SchemaVersion = release.LiveCleanupReportSchemaVersion
	report.JourneySucceeded = succeeded
	report.ExecutorAttestationDigest = attestationDigest
	report.UpdatedAt = runner.Now().UTC().Truncate(time.Second)
	slices.SortFunc(report.Steps, func(left, right release.JourneyStepResult) int { return compare(left.MutationID, right.MutationID) })
	slices.SortFunc(report.Items, func(left, right release.CleanupItem) int { return compare(left.MutationID, right.MutationID) })
	return runner.Reports.Write(*report)
}

func sameReportAuthority(report release.LiveCleanupReport, runner Runner) bool {
	return report.RunID == runner.RunID && report.SideEffectPlanDigest == runner.PlanDigest && report.QualificationInstallManifestDigest == runner.InstallManifestDigest && report.ProtectedInputDigest == runner.ProtectedInputDigest
}

func readyForAttestation(report release.LiveCleanupReport, plan release.LiveSideEffectPlan) bool {
	if report.ExecutionFailed || report.JourneySucceeded || len(report.Steps) != len(plan.Mutations) || !allCleanupTerminal(report, plan) {
		return false
	}
	for _, step := range report.Steps {
		if step.Outcome != release.StepPassed || !release.ValidDigest(step.EvidenceDigest) {
			return false
		}
	}
	return true
}

func allCleanupTerminal(report release.LiveCleanupReport, plan release.LiveSideEffectPlan) bool {
	if len(report.Items) != len(plan.Mutations) {
		return false
	}
	byID := make(map[string]release.CleanupItem, len(report.Items))
	for _, item := range report.Items {
		byID[item.MutationID] = item
	}
	for _, mutation := range plan.Mutations {
		item, present := byID[mutation.ID]
		if !present || item.Result != release.CleanupCleaned && item.Result != release.CleanupRetained || mutation.CleanupPolicy == "delete_exact" && item.Result != release.CleanupCleaned {
			return false
		}
	}
	return true
}

func setStep(report *release.LiveCleanupReport, value release.JourneyStepResult) {
	for index := range report.Steps {
		if report.Steps[index].MutationID == value.MutationID {
			report.Steps[index] = value
			return
		}
	}
	report.Steps = append(report.Steps, value)
}

func setItem(report *release.LiveCleanupReport, value release.CleanupItem) {
	for index := range report.Items {
		if report.Items[index].MutationID == value.MutationID {
			report.Items[index] = value
			return
		}
	}
	report.Items = append(report.Items, value)
}

func errorDigest(err error) string {
	if err == nil {
		err = fmt.Errorf("unknown live qualification error")
	}
	return release.DigestBytes([]byte(err.Error()))
}

func newAttemptID() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "attempt_" + hex.EncodeToString(value[:]), nil
}

func validateOrderedJourneyPlan(plan release.LiveSideEffectPlan) error {
	if len(plan.Mutations) != len(orderedJourney) {
		return fmt.Errorf("live qualification plan does not contain the exact ordered journey")
	}
	retained := map[string]bool{
		"clean_install":               true,
		"headscale_initialize_http01": true,
		"headscale_entities":          true,
		"connector_assisted_login":    true,
		"final_cleanup_inventory":     true,
	}
	present := map[string]bool{}
	for _, mutation := range plan.Mutations {
		expectedPolicy := "delete_exact"
		if retained[mutation.ID] {
			expectedPolicy = "retain_authorized"
		}
		if mutation.CleanupPolicy != expectedPolicy {
			return fmt.Errorf("live qualification cleanup policy for %q is not fixed", mutation.ID)
		}
		present[mutation.ID] = true
	}
	for _, step := range orderedJourney {
		if !present[step] {
			return fmt.Errorf("live qualification plan omits fixed step %q", step)
		}
	}
	return nil
}

func compare(left, right string) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}
