package workflow

import (
	"lanpanel/internal/domain"
	"slices"
	"strings"
	"unicode"
)

type Failure struct {
	Step         string
	Operation    string
	Impact       string
	Remediation  []string
	RetryCommand string
	Cause        error
}

type FailureSnapshot struct {
	Summary      string   `json:"summary,omitempty"`
	Step         string   `json:"step,omitempty"`
	Operation    string   `json:"operation,omitempty"`
	Impact       string   `json:"impact,omitempty"`
	Details      string   `json:"details,omitempty"`
	Remediation  []string `json:"remediation,omitempty"`
	RetryCommand string   `json:"retry_command,omitempty"`
}

func (failure Failure) Error() string {
	return failure.Summary()
}

func (failure Failure) Summary() string {
	step := strings.TrimSpace(failure.Step)
	operation := strings.TrimSpace(failure.Operation)

	switch {
	case step != "" && operation != "":
		return step + " failed: " + operation
	case operation != "":
		return operation
	case step != "":
		return step + " failed"
	default:
		return "workflow failed"
	}
}

func (failure Failure) Snapshot() FailureSnapshot {
	return FailureSnapshot{
		Summary:      failure.Summary(),
		Step:         strings.TrimSpace(failure.Step),
		Operation:    strings.TrimSpace(failure.Operation),
		Impact:       strings.TrimSpace(failure.Impact),
		Details:      summarizeCause(failure.Cause),
		Remediation:  append([]string(nil), failure.Remediation...),
		RetryCommand: strings.TrimSpace(failure.RetryCommand),
	}
}

func (snapshot FailureSnapshot) HasContent() bool {
	return strings.TrimSpace(snapshot.Summary) != "" ||
		strings.TrimSpace(snapshot.Step) != "" ||
		strings.TrimSpace(snapshot.Operation) != "" ||
		strings.TrimSpace(snapshot.Impact) != "" ||
		strings.TrimSpace(snapshot.Details) != "" ||
		len(snapshot.Remediation) > 0 ||
		strings.TrimSpace(snapshot.RetryCommand) != ""
}

func (snapshot FailureSnapshot) ResultFields() []domain.ResultField {
	fields := make([]domain.ResultField, 0, 4)
	if step := strings.TrimSpace(snapshot.Step); step != "" {
		fields = append(fields, domain.ResultField{Label: "step", Value: step})
	}
	if operation := strings.TrimSpace(snapshot.Operation); operation != "" {
		fields = append(fields, domain.ResultField{Label: "what failed", Value: operation})
	}
	if impact := strings.TrimSpace(snapshot.Impact); impact != "" {
		fields = append(fields, domain.ResultField{Label: "impact", Value: impact})
	}
	if details := strings.TrimSpace(snapshot.Details); details != "" {
		fields = append(fields, domain.ResultField{Label: "details", Value: details})
	}
	return fields
}

func (snapshot FailureSnapshot) NextSteps() []string {
	nextSteps := append([]string(nil), snapshot.Remediation...)
	if retry := strings.TrimSpace(snapshot.RetryCommand); retry != "" {
		nextSteps = append(nextSteps, "Retry after remediation: "+retry)
	}
	return nextSteps
}

func (snapshot FailureSnapshot) SummaryText() string {
	return snapshot.summary()
}

func (snapshot FailureSnapshot) summary() string {
	if summary := strings.TrimSpace(snapshot.Summary); summary != "" {
		return summary
	}

	step := strings.TrimSpace(snapshot.Step)
	operation := strings.TrimSpace(snapshot.Operation)
	switch {
	case step != "" && operation != "":
		return step + " failed: " + operation
	case operation != "":
		return operation
	case step != "":
		return step + " failed"
	default:
		return "workflow failed"
	}
}

func summarizeCause(err error) string {
	if err == nil {
		return ""
	}
	message := strings.TrimSpace(err.Error())
	if message == "" {
		return ""
	}
	line, _, _ := strings.Cut(message, "\n")
	return strings.TrimSpace(line)
}

func ShellCommand(args ...string) string {
	if slices.Contains(args, "lanpanel") {
		return "Management UI"
	}
	parts := make([]string, 0, len(args))
	for _, arg := range args {
		parts = append(parts, shellQuote(arg))
	}
	return strings.Join(parts, " ")
}

func shellQuote(arg string) string {
	if arg == "" {
		return "''"
	}
	if shellSafe(arg) {
		return arg
	}
	return "'" + strings.ReplaceAll(arg, "'", "'\\''") + "'"
}

func shellSafe(arg string) bool {
	for _, r := range arg {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r):
		case strings.ContainsRune("_@%+=:,./-", r):
		default:
			return false
		}
	}
	return true
}
