package main

import (
	"fmt"
	"io"
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
	registry, err := roles.NewRegistry([]roles.Registration{
		{Name: roles.ChildExecutor, Handler: func(args []string, _, _ io.Writer) error { return child.ExecuteBootstrap(args) }},
		{Name: roles.Helper, Handler: func(args []string, _, _ io.Writer) error { return helper.RunRole(args) }},
	})
	if err != nil {
		return err
	}
	return registry.Dispatch(args, stdout, stderr, version)
}
