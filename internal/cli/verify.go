package cli

import (
	"fmt"
	"io"
	"lanpanel/internal/output"
	"lanpanel/internal/workflow"
	"strings"
)

func newVerifyCommand() command {
	return command{
		summary: "Validate config, runtime assets, and onboarding readiness.",
		usage:   writeVerifyHelp,
		run:     runVerify,
	}
}

func runVerify(ctx context, args []string) error {
	flagSet := newFlagSet("verify")
	options := sharedOptions{configPath: DefaultConfigPath, formatValue: string(output.FormatHuman)}
	options.bind(flagSet, "Path to the lanpanel config file.")

	shown, err := parseFlags(flagSet, args, writeVerifyHelp, ctx.stdout)
	if err != nil {
		return fmt.Errorf("parse verify flags: %w", err)
	}
	if shown {
		return nil
	}
	if err := rejectPositionalArgs("verify", flagSet); err != nil {
		return err
	}

	formatter, err := options.formatter(ctx.stdout)
	if err != nil {
		return err
	}

	result, err := workflow.RunMainVerify(workflow.Context{Version: ctx.version}, options.configPath)
	if err != nil {
		return err
	}
	return writeOperationResult(formatter, "verify", mainVerifyOutputStatus(result), result, mainVerifyNextSteps(options.configPath, result))
}

func writeVerifyHelp(stdout io.Writer) error {
	return writeHelpLines(stdout,
		"Validate config, runtime assets, and onboarding readiness.",
		"",
		"Usage:",
		"  lanpanel verify [--config path] [--format human|json]",
		"",
		"Flags:",
		"  --config string   Path to the lanpanel config file.",
		"  --format string   Output format: human | json",
	)
}

func mainVerifyOutputStatus(result workflow.OperationResult) string {
	if result.Status == "succeeded" {
		return "passed"
	}
	for _, diagnostic := range result.Diagnostics {
		if diagnostic.ID != "main-config" {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(result.Summary), "no config file found") {
			return "missing-config"
		}
		return "invalid-config"
	}
	return "failed"
}

func mainVerifyNextSteps(configPath string, result workflow.OperationResult) []string {
	switch mainVerifyOutputStatus(result) {
	case "missing-config":
		return []string{fmt.Sprintf("Run 'lanpanel init --config %s' to generate a starter config.", configPath)}
	case "invalid-config":
		return []string{fmt.Sprintf("Fix the config at %s and rerun 'lanpanel verify --config %s'.", configPath, configPath)}
	case "failed":
		for _, diagnostic := range result.Diagnostics {
			if diagnostic.ID == "main-runtime-stage" {
				return []string{fmt.Sprintf("Fix config/template inputs and rerun 'lanpanel verify --config %s'.", configPath)}
			}
		}
	}
	return []string{
		fmt.Sprintf("Use 'lanpanel deploy --config %s' to apply or refresh server runtime state.", configPath),
		"After deploy, join at least two clients from different networks and observe direct or DERP fallback paths.",
	}
}
