package cli

import (
	"fmt"
	"io"
	"lanpanel/internal/output"
	"lanpanel/internal/workflow"
)

func newStatusCommand() command {
	return command{
		summary: "Show config readiness and persisted deploy context.",
		usage:   writeStatusHelp,
		run:     runStatus,
	}
}

func runStatus(ctx context, args []string) error {
	flagSet := newFlagSet("status")
	options := sharedOptions{configPath: DefaultConfigPath, formatValue: string(output.FormatHuman)}
	options.bind(flagSet, "Path to the lanpanel config file.")

	shown, err := parseFlags(flagSet, args, writeStatusHelp, ctx.stdout)
	if err != nil {
		return fmt.Errorf("parse status flags: %w", err)
	}
	if shown {
		return nil
	}
	if err := rejectPositionalArgs("status", flagSet); err != nil {
		return err
	}

	formatter, err := options.formatter(ctx.stdout)
	if err != nil {
		return err
	}
	result, resultErr := workflow.RunMainStatus(workflow.Context{
		Version:      ctx.version,
		Actor:        cliActor(),
		HostWorkflow: newCLIHostWorkflow(ctx),
	}, options.configPath)
	if result.Kind != "" {
		if err := writeOperationResult(formatter, "status", workflowOutputStatus("status", result), result, nil); err != nil {
			return err
		}
	}
	return resultErr
}

func writeStatusHelp(stdout io.Writer) error {
	return writeHelpLines(stdout,
		"Show config readiness and persisted deploy context.",
		"",
		"Usage:",
		"  lanpanel status [--config path] [--format human|json]",
		"",
		"Flags:",
		"  --config string   Path to the lanpanel config file.",
		"  --format string   Output format: human | json",
	)
}
