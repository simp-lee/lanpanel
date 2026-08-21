package qualification

import (
	"context"
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

type Runner struct {
	RunID                 string
	Plan                  release.LiveSideEffectPlan
	PlanDigest            string
	InstallManifestDigest string
	ProtectedInputDigest  string
	Executor              Executor
	Reports               ReportStore
	Now                   func() time.Time
}

// Run observes and validates every prior state before invoking the first live
// mutation. Execution order is fixed in source; cleanup is exact and reversed.
func (runner Runner) Run(ctx context.Context) (release.LiveCleanupReport, error) {
	if runner.Executor == nil || runner.Reports == nil || runner.RunID != runner.Plan.RunID || !release.ValidDigest(runner.PlanDigest) || !release.ValidDigest(runner.InstallManifestDigest) || !release.ValidDigest(runner.ProtectedInputDigest) || runner.Now == nil {
		return release.LiveCleanupReport{}, fmt.Errorf("live qualification runner authority is incomplete")
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
	if len(planByID) != len(orderedJourney) {
		return release.LiveCleanupReport{}, fmt.Errorf("live qualification plan does not contain the exact ordered journey")
	}
	for _, step := range orderedJourney {
		if _, present := planByID[step]; !present {
			return release.LiveCleanupReport{}, fmt.Errorf("live qualification plan omits fixed step %q", step)
		}
	}
	type executedMutation struct {
		step        string
		observation MutationObservation
	}
	executed := []executedMutation{}
	items := []release.CleanupItem{}
	latest, present, readErr := runner.Reports.Read()
	if readErr != nil {
		return release.LiveCleanupReport{}, readErr
	}
	resuming := present
	if present {
		if latest.RunID != runner.RunID || latest.SideEffectPlanDigest != runner.PlanDigest || latest.QualificationInstallManifestDigest != runner.InstallManifestDigest || latest.ProtectedInputDigest != runner.ProtectedInputDigest || latest.JourneySucceeded {
			return release.LiveCleanupReport{}, fmt.Errorf("persisted live journey authority differs")
		}
		items = append(items, latest.Items...)
	} else {
		for _, step := range orderedJourney {
			observed, err := runner.Executor.Observe(ctx, step)
			if err != nil {
				return release.LiveCleanupReport{}, err
			}
			planned := planByID[step]
			if release.DigestBytes(observed.Scope) != planned.ScopeDigest || release.DigestBytes(observed.PriorState) != planned.PriorStateDigest || release.DigestBytes(observed.PlannedMutation) != planned.PlannedMutationDigest || release.DigestBytes(observed.Selector) != planned.SelectorDigest {
				return release.LiveCleanupReport{}, fmt.Errorf("live qualification prior observation changed for %q", step)
			}
		}
	}
	setItem := func(item release.CleanupItem) {
		for index := range items {
			if items[index].MutationID == item.MutationID {
				items[index] = item
				return
			}
		}
		items = append(items, item)
	}
	writeReport := func(succeeded bool) error {
		copyItems := append([]release.CleanupItem(nil), items...)
		slices.SortFunc(copyItems, func(left, right release.CleanupItem) int { return compare(left.MutationID, right.MutationID) })
		latest = release.LiveCleanupReport{SchemaVersion: release.LiveCleanupReportSchemaVersion, RunID: runner.RunID, SideEffectPlanDigest: runner.PlanDigest, QualificationInstallManifestDigest: runner.InstallManifestDigest, ProtectedInputDigest: runner.ProtectedInputDigest, JourneySucceeded: succeeded, UpdatedAt: runner.Now().UTC().Truncate(time.Second), Items: copyItems}
		return runner.Reports.Write(latest)
	}
	var runErr error
	if resuming {
		byStep := map[string]release.CleanupItem{}
		for _, item := range items {
			byStep[item.MutationID] = item
		}
		for _, step := range orderedJourney {
			item, present := byStep[step]
			if !present {
				continue
			}
			switch item.Result {
			case release.CleanupSubmitted:
				observation, err := runner.Executor.Recover(context.WithoutCancel(ctx), item.MutationID)
				if err != nil || observation.Identity == "" {
					runErr = errors.Join(runErr, err, fmt.Errorf("submitted live mutation %q cannot be recovered", item.MutationID))
					continue
				}
				setItem(release.CleanupItem{MutationID: item.MutationID, ObservedIdentity: observation.Identity, Result: release.CleanupExecuted})
				executed = append(executed, executedMutation{item.MutationID, observation})
				if err := writeReport(false); err != nil {
					runErr = errors.Join(runErr, err)
				}
			case release.CleanupExecuted:
				executed = append(executed, executedMutation{item.MutationID, MutationObservation{Identity: item.ObservedIdentity}})
			}
		}
	} else {
		for _, step := range orderedJourney {
			setItem(release.CleanupItem{MutationID: step, ObservedIdentity: "pending/" + step, Result: release.CleanupSubmitted})
			if err := writeReport(false); err != nil {
				runErr = errors.Join(runErr, err)
				break
			}
			observation, err := runner.Executor.Execute(ctx, step)
			if observation.Identity != "" {
				setItem(release.CleanupItem{MutationID: step, ObservedIdentity: observation.Identity, Result: release.CleanupExecuted})
				executed = append(executed, executedMutation{step, observation})
				if persistErr := writeReport(false); persistErr != nil {
					runErr = errors.Join(runErr, persistErr)
					break
				}
				if err != nil {
					runErr = errors.Join(runErr, err)
					break
				}
				continue
			}
			if err != nil || observation.Identity == "" {
				runErr = errors.Join(runErr, err, fmt.Errorf("live mutation %q did not return a durable cleanup identity", step))
				break
			}
		}
	}
	for index := len(executed) - 1; index >= 0; index-- {
		value := executed[index]
		planned := planByID[value.step]
		result, err := runner.Executor.Cleanup(context.WithoutCancel(ctx), value.step, value.observation, planned.CleanupPolicy)
		if err != nil {
			runErr = errors.Join(runErr, err)
			continue
		}
		if result != release.CleanupCleaned && result != release.CleanupRetained || planned.CleanupPolicy == "delete_exact" && result != release.CleanupCleaned {
			runErr = errors.Join(runErr, fmt.Errorf("live qualification cleanup policy was not satisfied for %q", value.step))
			continue
		}
		setItem(release.CleanupItem{MutationID: value.step, ObservedIdentity: value.observation.Identity, Result: result})
		if err := writeReport(false); err != nil {
			runErr = errors.Join(runErr, err)
		}
	}
	terminal := len(items) == len(orderedJourney)
	for _, item := range items {
		terminal = terminal && (item.Result == release.CleanupCleaned || item.Result == release.CleanupRetained)
	}
	if runErr == nil && terminal {
		if err := writeReport(true); err != nil {
			runErr = errors.Join(runErr, err)
		}
	}
	if terminal {
		return latest, runErr
	}
	return latest, errors.Join(runErr, fmt.Errorf("live qualification cleanup report is incomplete"))
}

func validateOrderedJourneyPlan(plan release.LiveSideEffectPlan) error {
	if len(plan.Mutations) != len(orderedJourney) {
		return fmt.Errorf("live qualification plan does not contain the exact ordered journey")
	}
	present := map[string]bool{}
	for _, mutation := range plan.Mutations {
		expectedPolicy := "delete_exact"
		if mutation.ID == "clean_install" {
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
