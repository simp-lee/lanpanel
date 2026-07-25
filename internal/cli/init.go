package cli

import (
	"fmt"
	"io"
	"lanpanel/internal/domain"
	"lanpanel/internal/output"
	"lanpanel/internal/workflow"
	"strings"
)

func newInitCommand() command {
	return command{
		summary: "Generate a guided config or write the example template.",
		usage:   writeInitHelp,
		run:     runInit,
	}
}

func runInit(ctx context, args []string) error {
	flagSet := newFlagSet("init")
	options := sharedOptions{configPath: DefaultConfigPath, formatValue: string(output.FormatHuman)}
	advanced := false
	example := false
	options.bind(flagSet, "Path to create the lanpanel config file.")
	flagSet.BoolVar(&advanced, "advanced", false, "Prompt for advanced settings too.")
	flagSet.BoolVar(&example, "example", false, "Write the example template without guided prompts.")

	shown, err := parseFlags(flagSet, args, writeInitHelp, ctx.stdout)
	if err != nil {
		return fmt.Errorf("parse init flags: %w", err)
	}
	if shown {
		return nil
	}
	if err := rejectPositionalArgs("init", flagSet); err != nil {
		return err
	}

	if advanced && example {
		return fmt.Errorf("--advanced and --example cannot be used together")
	}

	format, err := output.ParseFormat(options.formatValue)
	if err != nil {
		return err
	}
	formatter := output.NewFormatter(ctx.stdout, format)

	promptWriter := ctx.stderr
	if promptWriter == nil {
		promptWriter = ctx.stdout
	}
	prompter := output.NewPrompter(ctx.stdin, promptWriter)

	if example {
		result, err := workflow.RunMainInit(workflow.Context{Version: ctx.version}, options.configPath)
		return writeMainInitOperationResult(formatter, options.configPath, result, err)
	}

	if advanced && !prompter.Enabled() {
		return fmt.Errorf("guided init requires interactive input; rerun in a terminal or use --example")
	}

	if prompter.Enabled() {
		result, err := workflow.RunInit(prompter, workflow.InitOptions{Advanced: advanced})
		if err != nil {
			return fmt.Errorf("run guided init: %w", err)
		}
		if err := workflow.EnsureNewConfigTarget(options.configPath, "config file"); err != nil {
			return writeInitFailureResponse(formatter, options.configPath, initFailureOutputStatus(err), initFailureSummary(err), err)
		}
		if err := result.Config.WriteFile(options.configPath); err != nil {
			return writeInitFailureResponse(formatter, options.configPath, "failed", "failed to write guided config", err)
		}
		return writeInitResponse(formatter, initResultResponse(result, options.configPath), options.configPath)
	}

	result, err := workflow.RunMainInit(workflow.Context{Version: ctx.version}, options.configPath)
	return writeMainInitOperationResult(formatter, options.configPath, result, err)
}

func writeMainInitOperationResult(formatter output.Formatter, configPath string, result workflow.OperationResult, err error) error {
	status := "written"
	nextSteps := workflow.ExampleInitResult().NextSteps(configPath)
	if result.Status == domain.JobStatusFailed {
		status = initFailureOutputStatus(err)
		nextSteps = []string{"Choose a different --config path or remove the existing failed target and rerun init."}
	}
	if result.Kind != "" {
		if writeErr := writeOperationResult(formatter, "init", status, result, nextSteps); writeErr != nil {
			return writeErr
		}
	}
	return err
}

func initFailureOutputStatus(cause error) string {
	if cause != nil && strings.Contains(cause.Error(), "already exists") {
		return "already-exists"
	}
	return "failed"
}

func initFailureSummary(cause error) string {
	if cause != nil && strings.Contains(cause.Error(), "already exists") {
		return "config file already exists"
	}
	if cause != nil && strings.HasPrefix(cause.Error(), "stat ") {
		return "failed to inspect config file"
	}
	return "failed to write config file"
}

func initResultResponse(result workflow.InitResult, configPath string) output.Response {
	return output.Response{
		Command:   "init",
		Status:    "written",
		Summary:   result.Summary(),
		Fields:    result.Fields(configPath),
		NextSteps: result.NextSteps(configPath),
	}
}

func writeInitResponse(formatter output.Formatter, response output.Response, configPath string) error {
	result := commandOperationResult(response.Command, response.Status, domain.JobStatusSucceeded, domain.DiagnosticStatusPass, response.Summary, response.Fields, "")
	result.Kind = domain.JobKindConfigSave
	result.ModifiedPaths = []string{configPath}
	return writeOperationResult(formatter, response.Command, response.Status, result, response.NextSteps)
}

func writeInitFailureResponse(formatter output.Formatter, configPath string, outputStatus string, summary string, cause error) error {
	result := workflow.OperationResult{
		Kind:    domain.JobKindConfigSave,
		Status:  domain.JobStatusFailed,
		Summary: summary,
		Fields: []output.Field{
			{Label: "config path", Value: configPath},
			{Label: "details", Value: cause.Error()},
		},
		Diagnostics:  []domain.DiagnosticItem{commandDiagnosticItem(domain.JobKindConfigSave, "init", outputStatus, domain.DiagnosticStatusFail, summary)},
		RetryCommand: workflow.ShellCommand("lanpanel", "init", "--config", configPath),
	}
	if err := writeOperationResult(formatter, "init", outputStatus, result, []string{"Choose a different --config path or remove the existing failed target and rerun init."}); err != nil {
		return err
	}
	return cause
}

func writeInitHelp(stdout io.Writer) error {
	return writeHelpLines(stdout,
		"Generate a guided config or write the example template.",
		"",
		"Usage:",
		"  lanpanel init [--config path] [--format human|json] [--advanced] [--example]",
		"",
		"Flags:",
		"  --config string   Path to create the lanpanel config file.",
		"  --format string   Output format: human | json",
		"  --advanced        Prompt for advanced settings too.",
		"  --example         Write the example template without guided prompts.",
	)
}
