// Package cli provides the lanpanel command surface.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"lanpanel/internal/config"
	"lanpanel/internal/output"
	"os"
	"sort"
)

const DefaultConfigPath = "lanpanel.yaml"

type context struct {
	stdin   io.Reader
	stdout  io.Writer
	stderr  io.Writer
	version string
}

type command struct {
	summary string
	usage   func(io.Writer) error
	run     func(context, []string) error
}

type sharedOptions struct {
	configPath  string
	formatValue string
}

func (options *sharedOptions) bind(flagSet *flag.FlagSet, configUsage string) {
	flagSet.StringVar(&options.configPath, "config", DefaultConfigPath, configUsage)
	flagSet.StringVar(&options.formatValue, "format", string(output.FormatHuman), "Output format: human | json")
}

func (options sharedOptions) formatter(stdout io.Writer) (output.Formatter, error) {
	format, err := output.ParseFormat(options.formatValue)
	if err != nil {
		return output.Formatter{}, err
	}

	return output.NewFormatter(stdout, format), nil
}

func (ctx context) formatter(format output.Format) output.Formatter {
	return output.NewFormatter(ctx.stdout, format)
}

var commands = map[string]command{
	"app":    newAppCommand(),
	"deploy": newDeployCommand(),
	"init":   newInitCommand(),
	"status": newStatusCommand(),
	"ui":     newUICommand(),
	"verify": newVerifyCommand(),
}

func Execute(args []string, stdout io.Writer, stderr io.Writer, version string) error {
	ctx := context{stdin: os.Stdin, stdout: stdout, stderr: stderr, version: version}

	if len(args) == 0 {
		return writeRootHelp(stdout)
	}

	switch args[0] {
	case "help", "-h", "--help":
		return runHelp(ctx, args[1:])
	case "version", "--version":
		_, err := fmt.Fprintf(stdout, "lanpanel %s\n", version)
		return err
	}

	selected, ok := commands[args[0]]
	if !ok {
		if err := writeRootHelp(stderr); err != nil {
			return err
		}
		return fmt.Errorf("unknown command %q", args[0])
	}

	return selected.run(ctx, args[1:])
}

func runHelp(ctx context, args []string) error {
	if len(args) == 0 {
		return writeRootHelp(ctx.stdout)
	}

	selected, ok := commands[args[0]]
	if !ok {
		if err := writeRootHelp(ctx.stderr); err != nil {
			return err
		}
		return fmt.Errorf("unknown command %q", args[0])
	}

	return selected.usage(ctx.stdout)
}

func newFlagSet(name string) *flag.FlagSet {
	flagSet := flag.NewFlagSet(name, flag.ContinueOnError)
	flagSet.SetOutput(io.Discard)
	return flagSet
}

func parseFlags(flagSet *flag.FlagSet, args []string, usage func(io.Writer) error, stdout io.Writer) (bool, error) {
	err := flagSet.Parse(args)
	if err == nil {
		return false, nil
	}
	if errors.Is(err, flag.ErrHelp) {
		return true, usage(stdout)
	}
	return false, err
}

func rejectPositionalArgs(name string, flagSet *flag.FlagSet) error {
	if flagSet.NArg() == 0 {
		return nil
	}
	return fmt.Errorf("%s does not accept positional arguments", name)
}

func loadConfig(path string) (config.Config, error) {
	return config.LoadFile(path)
}

func configFields(path string, cfg config.Config) []output.Field {
	return []output.Field{
		{Label: "config path", Value: path},
		{Label: "server url", Value: cfg.Default.ServerURL},
		{Label: "base domain", Value: cfg.Default.BaseDomain},
		{Label: "acme challenge", Value: cfg.Default.ACMEChallenge},
	}
}

func writeHelpLines(stdout io.Writer, lines ...string) error {
	for _, line := range lines {
		if _, err := fmt.Fprintln(stdout, line); err != nil {
			return err
		}
	}
	return nil
}

func writeRootHelp(stdout io.Writer) error {
	names := make([]string, 0, len(commands))
	for name := range commands {
		names = append(names, name)
	}
	sort.Strings(names)

	if err := writeHelpLines(stdout,
		"lanpanel manages init, deploy, verify, status, and app workflows.",
		"",
		"Usage:",
		"  lanpanel <command> [flags]",
		"",
		"Happy path:",
		"  lanpanel init",
		"  lanpanel deploy",
		"  lanpanel verify",
		"  lanpanel ui",
		"",
		"Commands:",
	); err != nil {
		return err
	}
	for _, name := range names {
		if _, err := fmt.Fprintf(stdout, "  %-8s %s\n", name, commands[name].summary); err != nil {
			return err
		}
	}
	return writeHelpLines(stdout, "  version  Print the current build version.")
}
