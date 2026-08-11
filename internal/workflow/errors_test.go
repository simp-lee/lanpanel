package workflow

import (
	"errors"
	"testing"
)

func TestFailureSnapshotFormatsUserReadableFields(t *testing.T) {
	t.Parallel()

	failure := Failure{
		Step:      "install packages",
		Operation: "headscale package installation did not complete",
		Impact:    "deploy cannot continue until host packages are installed",
		Remediation: []string{
			"Check package mirror reachability or switch to a verified offline package.",
			"Confirm the configured package checksum matches the artifact you expect to install.",
		},
		RetryCommand: "Management UI",
		Cause:        errors.New("apt-get install headscale exited with status 100\nraw shell spew that should stay hidden"),
	}

	snapshot := failure.Snapshot()
	if snapshot.SummaryText() != "install packages failed: headscale package installation did not complete" {
		t.Fatalf("SummaryText = %q, want failure summary", snapshot.SummaryText())
	}
	fields := snapshot.ResultFields()
	if len(fields) != 4 {
		t.Fatalf("len(fields) = %d, want 4", len(fields))
	}
	if fields[2].Label != "impact" || fields[2].Value != "deploy cannot continue until host packages are installed" {
		t.Fatalf("impact field = %#v, want user-readable impact", fields[2])
	}
	if fields[3].Value != "apt-get install headscale exited with status 100" {
		t.Fatalf("details = %q, want sanitized single-line cause", fields[3].Value)
	}
	nextSteps := snapshot.NextSteps()
	if len(nextSteps) != 3 {
		t.Fatalf("len(nextSteps) = %d, want 3", len(nextSteps))
	}
	if nextSteps[2] != "Retry after remediation: Management UI" {
		t.Fatalf("retry step = %q, want retry command", nextSteps[2])
	}
	if failure.Error() != snapshot.SummaryText() {
		t.Fatalf("Error() = %q, want %q", failure.Error(), snapshot.SummaryText())
	}
}

func TestFailureSnapshotCarriesSerializableUserContext(t *testing.T) {
	t.Parallel()

	failure := Failure{
		Step:      "install runtime assets",
		Operation: "writing /etc/nginx/sites-available/headscale.conf",
		Impact:    "the reverse proxy configuration is incomplete",
		Remediation: []string{
			"Check the destination directory permissions.",
		},
		RetryCommand: "Management UI",
		Cause:        errors.New("write failed\nraw shell spew"),
	}

	snapshot := failure.Snapshot()
	if snapshot.Summary != "install runtime assets failed: writing /etc/nginx/sites-available/headscale.conf" {
		t.Fatalf("Summary = %q, want failure summary", snapshot.Summary)
	}
	if snapshot.Details != "write failed" {
		t.Fatalf("Details = %q, want sanitized single-line cause", snapshot.Details)
	}
	if len(snapshot.Remediation) != 1 || snapshot.Remediation[0] != "Check the destination directory permissions." {
		t.Fatalf("Remediation = %v, want serialized remediation", snapshot.Remediation)
	}
	if snapshot.RetryCommand != "Management UI" {
		t.Fatalf("RetryCommand = %q, want serialized retry command", snapshot.RetryCommand)
	}
}

func TestShellCommandRoutesManagementActionsToUI(t *testing.T) {
	t.Parallel()

	got := ShellCommand("lanpanel", "obsolete")
	want := "Management UI"
	if got != want {
		t.Fatalf("ShellCommand() = %q, want %q", got, want)
	}
}
