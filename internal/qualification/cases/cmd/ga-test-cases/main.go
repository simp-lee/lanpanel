package main

import (
	"context"
	"flag"
	"fmt"
	"lanpanel/internal/qualification/cases"
	"os"
)

func main() {
	scope := flag.String("scope", "", "exact implementing step, for example S1")
	goBinary := flag.String("go", "go", "Go command")
	flag.Parse()
	if err := cases.Run(context.Background(), cases.RunConfig{
		Scope:    *scope,
		Packages: flag.Args(),
		GoBinary: *goBinary,
	}, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "ga-test-cases: %v\n", err)
		os.Exit(1)
	}
}
