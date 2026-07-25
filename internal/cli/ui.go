package cli

import (
	"fmt"
	"io"
	"lanpanel/internal/hostworkflow"
	"lanpanel/internal/maindeploy"
	"lanpanel/internal/ui"
	"lanpanel/internal/workflow"
	"time"
)

type managementUIServer interface {
	StartupURL() string
	SSHExample() string
	TokenTTL() time.Duration
	ListenAndServe() error
}

var newUIServerFn = func(options ui.Options) (managementUIServer, error) {
	return ui.NewServer(options)
}

func newUICommand() command {
	return command{
		summary: "Start the loopback-only Management UI for SSH tunnel access.",
		usage:   writeUIHelp,
		run:     runUI,
	}
}

func runUI(ctx context, args []string) error {
	flagSet := newFlagSet("ui")
	addr := ui.DefaultAddr
	stateDir := ui.DefaultStateDir
	configPath := DefaultConfigPath
	appConfigPath := DefaultAppConfigPath
	tokenTTL := ui.DefaultTokenTTL
	flagSet.StringVar(&addr, "listen", addr, "Loopback listen address.")
	flagSet.StringVar(&stateDir, "state-dir", stateDir, "Path to the local UI state directory.")
	flagSet.StringVar(&configPath, "config", configPath, "Path to the lanpanel config file.")
	flagSet.StringVar(&appConfigPath, "app-config", appConfigPath, "Path to the lanpanel app config file.")
	flagSet.DurationVar(&tokenTTL, "token-ttl", tokenTTL, "Startup token lifetime.")
	shown, err := parseFlags(flagSet, args, writeUIHelp, ctx.stdout)
	if err != nil {
		return fmt.Errorf("parse ui flags: %w", err)
	}
	if shown {
		return nil
	}
	if err := rejectPositionalArgs("ui", flagSet); err != nil {
		return err
	}
	if tokenTTL <= 0 || tokenTTL > 30*time.Minute {
		return fmt.Errorf("ui token-ttl must be greater than 0 and at most 30m")
	}
	if stateDir == "" {
		return fmt.Errorf("ui state-dir is required")
	}
	server, err := newUIServerFn(ui.Options{
		Addr:              addr,
		Version:           ctx.version,
		StateDir:          stateDir,
		ConfigPath:        configPath,
		AppConfigPath:     appConfigPath,
		TokenTTL:          tokenTTL,
		HostWorkflow:      newUIHostWorkflow(ctx),
		PreAuthKeyCreator: newHeadscaleOnboarderFn(newHostExecutorFn(nil)),
	})
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(ctx.stdout, "LanPanel UI listening on http://%s\n", addr); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(ctx.stdout, "Open once: %s\n", server.StartupURL()); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(ctx.stdout, "SSH tunnel: %s\n", server.SSHExample()); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(ctx.stdout, "Startup token TTL: %s\n", server.TokenTTL()); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(ctx.stdout, "Security: loopback-only management UI; use SSH local forwarding; do not expose this port; startup token is one-time and expires."); err != nil {
		return err
	}
	return server.ListenAndServe()
}

func newUIHostWorkflow(ctx context) workflow.HostWorkflow {
	return newCLIHostWorkflow(ctx)
}

func newCLIHostWorkflow(ctx context) workflow.HostWorkflow {
	return hostworkflow.Service{
		Version: ctx.version,
		MainStatusOptions: hostworkflow.StatusOptions{
			CheckpointPath:     checkpointPathForConfigFn,
			CheckpointStore:    checkpointStoreForConfigFn,
			StageRuntimeFiles:  stageRuntimeFilesFn,
			LoadMainConfigFile: loadConfig,
		},
		MainDeployOptions:        maindeploy.Options{Dependencies: mainDeployDependencies()},
		AppHostDependencies:      apphostDependencies(),
		RealIPDiagnosticsOptions: cliRealIPDiagnosticsOptions(),
		Ops: hostworkflow.Operations{
			DetectPermissions:          detectPermissionStateFn,
			LoadRealIPAppConfigProfile: loadRealIPAppConfigProfile,
		},
	}
}

func writeUIHelp(stdout io.Writer) error {
	return writeHelpLines(stdout,
		"Start the loopback-only LanPanel Management UI.",
		"",
		"Usage:",
		"  lanpanel ui [flags]",
		"",
		"Flags:",
		"  -listen string",
		"      Loopback listen address. Default 127.0.0.1:18080.",
		"  -state-dir string",
		"      Path to local UI state directory. Default "+ui.DefaultStateDir+".",
		"  -config string",
		"      Path to lanpanel.yaml.",
		"  -app-config string",
		"      Path to lanpanel-app.yaml.",
		"  -token-ttl duration",
		"      Startup token lifetime, max 30m.",
	)
}
