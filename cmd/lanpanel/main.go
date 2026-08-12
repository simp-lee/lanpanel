package main

import (
	"fmt"
	"io"
	"lanpanel/internal/bootstrap"
	"lanpanel/internal/child"
	"lanpanel/internal/helper"
	"lanpanel/internal/packages"
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
	requireCommitted := func(args []string, _ io.Writer, _ io.Writer) error {
		if len(args) != 0 {
			return fmt.Errorf("installed role rejects arguments")
		}
		return bootstrap.RequireCommitted(bootstrap.FixedPaths())
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
		{Name: roles.Timer, Handler: requireCommitted},
		{Name: roles.StartupGuard, Handler: requireCommitted},
		{Name: roles.ReloadGuard, Handler: requireCommitted},
		{Name: roles.RuntimeGuard, Handler: func(args []string, _, _ io.Writer) error { return bootstrap.RunRuntimeGuard(args) }},
	})
	if err != nil {
		return err
	}
	return registry.Dispatch(args, stdout, stderr, version)
}
