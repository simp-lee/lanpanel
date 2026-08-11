package main

import (
	"fmt"
	"io"
	"lanpanel/internal/roles"
	"os"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	registry, err := roles.NewRegistry(nil)
	if err != nil {
		return err
	}
	return registry.Dispatch(args, stdout, stderr, version)
}
