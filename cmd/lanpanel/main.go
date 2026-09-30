package main

import (
	"fmt"
	"io"
	"lanpanel/internal/bootstrap"
	"lanpanel/internal/child"
	"lanpanel/internal/control"
	"lanpanel/internal/goaccess"
	"lanpanel/internal/helper"
	"lanpanel/internal/nginxguard"
	"lanpanel/internal/packages"
	"lanpanel/internal/preflight"
	managedprocess "lanpanel/internal/process"
	"lanpanel/internal/relay"
	"lanpanel/internal/renewal"
	"lanpanel/internal/roles"
	"os"
	"path/filepath"
)

var version = "dev"

func main() {
	if filepath.Base(os.Args[0]) == "policy-rc.d" {
		os.Exit(packages.NoAutostartExitCode(os.Args[1:]))
	}
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) > 0 && args[0] == "install" {
		return bootstrap.RunInstallerRole(args, stdout)
	}
	if len(args) > 0 && args[0] == "uninstall" {
		return bootstrap.RunPublicUninstall(args[1:], os.Stdin, stdout)
	}
	registry, err := roles.NewRegistry([]roles.Registration{
		{Name: roles.ChildExecutor, Handler: func(args []string, _, _ io.Writer) error { return child.ExecuteBootstrap(args) }},
		{Name: roles.Helper, Handler: func(args []string, _, _ io.Writer) error {
			if err := bootstrap.RequireCommitted(bootstrap.FixedPaths()); err != nil {
				return err
			}
			return helper.RunRole(args)
		}},
		{Name: roles.Installer, Handler: func(args []string, stdout, _ io.Writer) error { return bootstrap.RunInstallerRole(args, stdout) }},
		{Name: roles.UI, Handler: bootstrap.RunUIRole},
		{Name: roles.Timer, Handler: func(args []string, _, _ io.Writer) error {
			if err := bootstrap.RequireCommitted(bootstrap.FixedPaths()); err != nil {
				return err
			}
			return renewal.RunTimer(args)
		}},
		{Name: roles.StartupRecovery, Handler: func(args []string, _, _ io.Writer) error {
			if err := bootstrap.RequireCommitted(bootstrap.FixedPaths()); err != nil {
				return err
			}
			return helper.RunStartupRecovery(args)
		}},
		{Name: roles.StartupGuard, Handler: func(args []string, _, _ io.Writer) error { return nginxguard.RunStartupGuard(args) }},
		{Name: roles.ReloadGuard, Handler: func(args []string, _, _ io.Writer) error { return nginxguard.RunReloadGuard(args) }},
		{Name: roles.RuntimeGuard, Handler: func(args []string, _, _ io.Writer) error { return bootstrap.RunRuntimeGuard(args) }},
		{Name: roles.ManagedExecutor, Handler: func(args []string, _, _ io.Writer) error { return managedprocess.Execute(args) }},
		{Name: roles.DelegationProbe, Handler: func(args []string, _, _ io.Writer) error {
			if len(args) != 0 {
				return fmt.Errorf("delegation probe does not accept arguments")
			}
			return preflight.RunDelegationProbeChild()
		}},
		{Name: roles.HeadscalePrivateProbe, Handler: func(args []string, _, _ io.Writer) error { return control.RunPrivateProbe(args) }},
		{Name: roles.HeadscaleControlRelay, Handler: func(args []string, _, _ io.Writer) error { return control.RunControlRelay(args) }},
		{Name: roles.HeadscaleSTUNRelay, Handler: func(args []string, _, _ io.Writer) error { return control.RunSTUNRelay(args) }},
		{Name: roles.Relay, Handler: func(args []string, _, _ io.Writer) error { return relay.Run(args) }},
		{Name: roles.GoAccessRelay, Handler: func(args []string, _, _ io.Writer) error { return goaccess.RunRelay(args) }},
		{Name: roles.GoAccessRetention, Handler: func(args []string, _, _ io.Writer) error { return goaccess.RunRetention(args) }},
		{Name: roles.GoAccessAccountGuard, Handler: func(args []string, _, _ io.Writer) error {
			if err := bootstrap.RequireCommitted(bootstrap.FixedPaths()); err != nil {
				return err
			}
			return goaccess.RunAccountGuard(args)
		}},
	})
	if err != nil {
		return err
	}
	return registry.Dispatch(args, stdout, stderr, version)
}
