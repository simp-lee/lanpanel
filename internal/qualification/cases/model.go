// Package cases defines the ordinary GA clause-to-case inventory and the
// exact-scope focused-test runner contract. It is traceability, not a second
// normative requirements authority or a release verdict store.
package cases

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

type Kind string

const (
	KindFixture Kind = "fixture"
	KindLive    Kind = "live"
)

type VerificationMode string

const (
	VerificationTestAssertion   VerificationMode = "test_assertion"
	VerificationReviewAssertion VerificationMode = "review_assertion"
)

type DeferRule string

const (
	DeferNever             DeferRule = "never"
	DeferRequirementsNamed DeferRule = "requirements_named"
)

type PreflightStatus string

type GateStatus string

type LiveStatus string

const (
	PreflightEligible      PreflightStatus = "eligible"
	PreflightIneligible    PreflightStatus = "ineligible"
	PreflightIndeterminate PreflightStatus = "indeterminate"
	PreflightNotApplicable PreflightStatus = "not_applicable"

	GatePassed   GateStatus = "passed"
	GateDeferred GateStatus = "deferred"
	GateBlocked  GateStatus = "blocked"

	LiveQualified     LiveStatus = "live_qualified"
	LiveUnqualified   LiveStatus = "live_unqualified"
	LiveNotApplicable LiveStatus = "not_applicable"
)

type StatusTriple struct {
	Preflight PreflightStatus `json:"preflight_status"`
	Gate      GateStatus      `json:"gate_status"`
	Live      LiveStatus      `json:"live_status"`
}

type Row struct {
	SourceAnchor     string           `json:"source_anchor"`
	ClauseID         string           `json:"clause_id"`
	Behavior         string           `json:"behavior"`
	ImplementingStep string           `json:"implementing_step"`
	CaseID           string           `json:"case_id"`
	Package          string           `json:"package"`
	Test             string           `json:"test"`
	Profile          string           `json:"profile"`
	Prerequisite     string           `json:"prerequisite"`
	Kind             Kind             `json:"kind"`
	VerificationMode VerificationMode `json:"verification_mode"`
	DeferRule        DeferRule        `json:"defer_rule"`
	SuccessStatus    StatusTriple     `json:"success_status"`
}

var (
	clausePattern = regexp.MustCompile(`^R[1-9][0-9]*\.[1-9][0-9]*\.[a-z0-9_]+(?:\.[a-z0-9_]+)*$`)
	stepPattern   = regexp.MustCompile(`^S[1-9][0-9]*$`)
	casePattern   = regexp.MustCompile(`^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)*$`)
	testPattern   = regexp.MustCompile(`^Test[A-Za-z0-9_]+(?:/[a-z][a-z0-9_]*)+$`)
)

func Validate(rows []Row) error {
	if len(rows) == 0 {
		return fmt.Errorf("case inventory is empty")
	}
	clauseIDs := map[string]struct{}{}
	caseIDs := map[string]struct{}{}
	bindings := map[string]struct{}{}
	for index, row := range rows {
		if !strings.HasPrefix(row.SourceAnchor, ".pi-work/requirements.md#R") || strings.ContainsAny(row.SourceAnchor, "\r\n") {
			return fmt.Errorf("row[%d] source_anchor must identify one Requirements clause", index)
		}
		if !clausePattern.MatchString(row.ClauseID) {
			return fmt.Errorf("row[%d] clause_id %q is not an atomic selector", index, row.ClauseID)
		}
		clauseParts := strings.Split(row.ClauseID, ".")
		expectedAnchor := ".pi-work/requirements.md#" + strings.Join(clauseParts[:2], ".")
		if row.SourceAnchor != expectedAnchor {
			return fmt.Errorf("row[%d] source_anchor %q does not match clause_id %q", index, row.SourceAnchor, row.ClauseID)
		}
		if _, duplicate := clauseIDs[row.ClauseID]; duplicate {
			return fmt.Errorf("row[%d] clause_id %q is duplicated", index, row.ClauseID)
		}
		clauseIDs[row.ClauseID] = struct{}{}
		if strings.TrimSpace(row.Behavior) == "" || row.Behavior != strings.TrimSpace(row.Behavior) || strings.ContainsAny(row.Behavior, "\r\n") {
			return fmt.Errorf("row[%d] behavior must describe exactly one trimmed behavior", index)
		}
		if !stepPattern.MatchString(row.ImplementingStep) {
			return fmt.Errorf("row[%d] implementing_step %q is not exact", index, row.ImplementingStep)
		}
		if !casePattern.MatchString(row.CaseID) {
			return fmt.Errorf("row[%d] case_id %q is invalid", index, row.CaseID)
		}
		if _, duplicate := caseIDs[row.CaseID]; duplicate {
			return fmt.Errorf("row[%d] case_id %q is duplicated", index, row.CaseID)
		}
		caseIDs[row.CaseID] = struct{}{}
		if err := validatePackage(row.Package); err != nil {
			return fmt.Errorf("row[%d]: %w", index, err)
		}
		if !testPattern.MatchString(row.Test) {
			return fmt.Errorf("row[%d] test %q must select one exact leaf subtest", index, row.Test)
		}
		binding := row.Package + "\x00" + row.Test
		if _, duplicate := bindings[binding]; duplicate {
			return fmt.Errorf("row[%d] test binding %s %s is duplicated", index, row.Package, row.Test)
		}
		bindings[binding] = struct{}{}
		if strings.TrimSpace(row.Profile) == "" || row.Profile != strings.TrimSpace(row.Profile) || strings.ContainsAny(row.Profile, "*\r\n") {
			return fmt.Errorf("row[%d] profile must be exact", index)
		}
		if strings.TrimSpace(row.Prerequisite) == "" || row.Prerequisite != strings.TrimSpace(row.Prerequisite) {
			return fmt.Errorf("row[%d] prerequisite is required", index)
		}
		switch row.Kind {
		case KindFixture, KindLive:
		default:
			return fmt.Errorf("row[%d] kind %q is not supported", index, row.Kind)
		}
		switch row.VerificationMode {
		case VerificationTestAssertion, VerificationReviewAssertion:
		default:
			return fmt.Errorf("row[%d] verification_mode %q is not supported", index, row.VerificationMode)
		}
		switch row.DeferRule {
		case DeferNever, DeferRequirementsNamed:
		default:
			return fmt.Errorf("row[%d] defer_rule %q is not supported", index, row.DeferRule)
		}
		if err := validateSuccessStatus(row); err != nil {
			return fmt.Errorf("row[%d]: %w", index, err)
		}
	}
	return nil
}

func RowsForScope(rows []Row, scope string) ([]Row, error) {
	if !stepPattern.MatchString(scope) {
		return nil, fmt.Errorf("SCOPE %q must be one exact implementing step", scope)
	}
	if err := Validate(rows); err != nil {
		return nil, err
	}
	selected := make([]Row, 0)
	for _, row := range rows {
		if row.ImplementingStep == scope {
			selected = append(selected, row)
		}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("SCOPE %q has no atomic case rows", scope)
	}
	sort.Slice(selected, func(left, right int) bool { return selected[left].ClauseID < selected[right].ClauseID })
	return selected, nil
}

func validatePackage(value string) error {
	allowedPrefix := strings.HasPrefix(value, "./internal/") || strings.HasPrefix(value, "./cmd/")
	if !allowedPrefix || value != strings.TrimSpace(value) || strings.Contains(value, "...") || strings.ContainsAny(value, "*?, \t\r\n") {
		return fmt.Errorf("package %q must be one explicit ./internal or ./cmd path", value)
	}
	return nil
}

func validateSuccessStatus(row Row) error {
	status := row.SuccessStatus
	switch status.Preflight {
	case PreflightEligible, PreflightIneligible, PreflightIndeterminate, PreflightNotApplicable:
	default:
		return fmt.Errorf("preflight_status %q is not supported", status.Preflight)
	}
	switch status.Gate {
	case GatePassed, GateDeferred, GateBlocked:
	default:
		return fmt.Errorf("gate_status %q is not supported", status.Gate)
	}
	switch status.Live {
	case LiveQualified, LiveUnqualified, LiveNotApplicable:
	default:
		return fmt.Errorf("live_status %q is not supported", status.Live)
	}
	fixtureSuccess := StatusTriple{Preflight: PreflightNotApplicable, Gate: GatePassed, Live: LiveNotApplicable}
	if row.Kind == KindFixture {
		if status != fixtureSuccess {
			return fmt.Errorf("fixture success status must be not_applicable/passed/not_applicable")
		}
		return nil
	}
	if row.Kind != KindLive {
		return fmt.Errorf("kind %q has no status mapping", row.Kind)
	}
	allowed := false
	switch status {
	case StatusTriple{Preflight: PreflightEligible, Gate: GatePassed, Live: LiveQualified},
		StatusTriple{Preflight: PreflightEligible, Gate: GateBlocked, Live: LiveUnqualified},
		StatusTriple{Preflight: PreflightIneligible, Gate: GateBlocked, Live: LiveUnqualified},
		StatusTriple{Preflight: PreflightIndeterminate, Gate: GateBlocked, Live: LiveUnqualified}:
		allowed = true
	case StatusTriple{Preflight: PreflightIneligible, Gate: GateDeferred, Live: LiveUnqualified},
		StatusTriple{Preflight: PreflightEligible, Gate: GateDeferred, Live: LiveUnqualified}:
		allowed = row.DeferRule == DeferRequirementsNamed
	}
	if !allowed {
		return fmt.Errorf("live status triple %s/%s/%s is not allowed for defer_rule %q", status.Preflight, status.Gate, status.Live, row.DeferRule)
	}
	return nil
}
