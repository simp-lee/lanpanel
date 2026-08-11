package cases

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestLedgerContract(t *testing.T) {
	t.Run("atomic_rows_validate", func(t *testing.T) {
		rows := Ledger()
		if err := Validate(rows); err != nil {
			t.Fatalf("Validate(Ledger()) error = %v", err)
		}
		duplicate := append([]Row(nil), rows...)
		duplicate[1].ClauseID = duplicate[0].ClauseID
		if err := Validate(duplicate); err == nil || !strings.Contains(err.Error(), "clause_id") {
			t.Fatalf("Validate(duplicate clause) error = %v", err)
		}
		duplicate = append([]Row(nil), rows...)
		duplicate[1].CaseID = duplicate[0].CaseID
		if err := Validate(duplicate); err == nil || !strings.Contains(err.Error(), "case_id") {
			t.Fatalf("Validate(duplicate case) error = %v", err)
		}
		wrongAnchor := append([]Row(nil), rows...)
		wrongAnchor[0].SourceAnchor = ".pi-work/requirements.md#R9.9"
		if err := Validate(wrongAnchor); err == nil || !strings.Contains(err.Error(), "does not match clause_id") {
			t.Fatalf("Validate(wrong source anchor) error = %v", err)
		}
		invalidStatus := append([]Row(nil), rows...)
		invalidStatus[0].SuccessStatus = StatusTriple{Preflight: PreflightEligible, Gate: GatePassed, Live: LiveQualified}
		if err := Validate(invalidStatus); err == nil || !strings.Contains(err.Error(), "fixture success") {
			t.Fatalf("Validate(fixture live status) error = %v", err)
		}
		live := rows[0]
		live.Kind = KindLive
		live.SuccessStatus = StatusTriple{Preflight: PreflightNotApplicable, Gate: GatePassed, Live: LiveNotApplicable}
		if err := Validate([]Row{live}); err == nil || !strings.Contains(err.Error(), "live status triple") {
			t.Fatalf("Validate(live not-applicable status) error = %v", err)
		}
		live.SuccessStatus = StatusTriple{Preflight: PreflightEligible, Gate: GatePassed, Live: LiveQualified}
		if err := Validate([]Row{live}); err != nil {
			t.Fatalf("Validate(eligible live success) error = %v", err)
		}
		cmdRow := rows[0]
		cmdRow.Package = "./cmd/lanpanel"
		if err := Validate([]Row{cmdRow}); err != nil {
			t.Fatalf("Validate(explicit cmd package) error = %v", err)
		}
	})

	t.Run("parent_only_selectors_are_rejected", func(t *testing.T) {
		rows := Ledger()
		parentClause := append([]Row(nil), rows...)
		parentClause[0].ClauseID = "R1.2"
		if err := Validate(parentClause); err == nil || !strings.Contains(err.Error(), "atomic selector") {
			t.Fatalf("Validate(parent clause) error = %v", err)
		}
		parentTest := append([]Row(nil), rows...)
		parentTest[0].Test = "TestInstallationSchema"
		if err := Validate(parentTest); err == nil || !strings.Contains(err.Error(), "leaf subtest") {
			t.Fatalf("Validate(parent test) error = %v", err)
		}
		for _, scope := range []string{"S", "S1*", "S1/S2", "R1"} {
			if _, err := RowsForScope(rows, scope); err == nil {
				t.Fatalf("RowsForScope(%q) error = nil", scope)
			}
		}
	})
}

func TestRunnerContract(t *testing.T) {
	t.Run("missing_package_is_rejected", func(t *testing.T) {
		row := runnerRow("R10.10.runner_package", "runner.package", "TestRunnerFixture/package")
		err := Run(context.Background(), RunConfig{
			Scope:    "S1",
			Rows:     []Row{row},
			Packages: []string{"./internal/domain"},
			Execute: func(context.Context, string, ...string) ([]byte, error) {
				t.Fatal("executor called before package ownership validation")
				return nil, nil
			},
		}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "absent from PKGS") {
			t.Fatalf("Run(missing package) error = %v", err)
		}
	})

	t.Run("exact_leaf_execution_is_required_and_recorded", func(t *testing.T) {
		rows := []Row{
			runnerRow("R10.10.runner_first", "runner.first", "TestRunnerFixture/first"),
			runnerRow("R10.10.runner_second", "runner.second", "TestRunnerFixture/group/second"),
		}
		rows[1].VerificationMode = VerificationReviewAssertion
		execute := fakeExecutor([]goEvent{
			{Action: "pass", Package: "lanpanel/internal/qualification/cases", Test: "TestRunnerFixture/first"},
			{Action: "pass", Package: "lanpanel/internal/qualification/cases", Test: "TestRunnerFixture/group/second"},
		})
		var output bytes.Buffer
		if err := Run(context.Background(), RunConfig{
			Scope:    "S1",
			Rows:     rows,
			Packages: []string{"./internal/qualification/cases"},
			Execute:  execute,
		}, &output); err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		for _, expected := range []string{`"case_id":"runner.first"`, `"case_id":"runner.second"`, `"verification_mode":"test_assertion"`, `"verification_mode":"review_assertion"`, `"result":"passed"`} {
			if !strings.Contains(output.String(), expected) {
				t.Fatalf("Run() output = %s, want %s", output.String(), expected)
			}
		}

		missing := fakeExecutor([]goEvent{{Action: "pass", Package: "lanpanel/internal/qualification/cases", Test: "TestRunnerFixture/first"}})
		if err := Run(context.Background(), RunConfig{Scope: "S1", Rows: rows, Packages: []string{"./internal/qualification/cases"}, Execute: missing}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "expected one passing terminal event") {
			t.Fatalf("Run(missing leaf) error = %v", err)
		}

		duplicate := fakeExecutor([]goEvent{
			{Action: "pass", Package: "lanpanel/internal/qualification/cases", Test: "TestRunnerFixture/first"},
			{Action: "pass", Package: "lanpanel/internal/qualification/cases", Test: "TestRunnerFixture/first"},
			{Action: "pass", Package: "lanpanel/internal/qualification/cases", Test: "TestRunnerFixture/group/second"},
		})
		if err := Run(context.Background(), RunConfig{Scope: "S1", Rows: rows, Packages: []string{"./internal/qualification/cases"}, Execute: duplicate}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "expected one passing terminal event") {
			t.Fatalf("Run(duplicate leaf) error = %v", err)
		}

		parentRow := runnerRow("R10.10.runner_parent", "runner.parent", "TestRunnerFixture/group")
		parent := fakeExecutor([]goEvent{
			{Action: "pass", Package: "lanpanel/internal/qualification/cases", Test: "TestRunnerFixture/group/child"},
			{Action: "pass", Package: "lanpanel/internal/qualification/cases", Test: "TestRunnerFixture/group"},
		})
		if err := Run(context.Background(), RunConfig{Scope: "S1", Rows: []Row{parentRow}, Packages: []string{"./internal/qualification/cases"}, Execute: parent}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "is a parent of descendant") {
			t.Fatalf("Run(parent leaf) error = %v", err)
		}
	})
}

func runnerRow(clauseID, caseID, test string) Row {
	row := fixtureRow(clauseID, "R10.10", "Runner contract behavior", caseID, "./internal/qualification/cases", test)
	return row
}

func fakeExecutor(events []goEvent) ExecuteFunc {
	return func(_ context.Context, _ string, arguments ...string) ([]byte, error) {
		if len(arguments) == 0 {
			return nil, errors.New("missing command arguments")
		}
		switch arguments[0] {
		case "list":
			return []byte("lanpanel/internal/qualification/cases\n"), nil
		case "test":
			var output bytes.Buffer
			for _, event := range events {
				fmt.Fprintf(&output, `{"Action":%q,"Package":%q,"Test":%q}`+"\n", event.Action, event.Package, event.Test)
			}
			return output.Bytes(), nil
		default:
			return nil, fmt.Errorf("unexpected command %q", arguments[0])
		}
	}
}
