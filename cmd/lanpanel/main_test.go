package main

import (
	"bytes"
	"strings"
	"testing"
)

func runBinary(args ...string) (string, string, error) {
	var stdout, stderr bytes.Buffer
	err := run(args, &stdout, &stderr)
	return stdout.String(), stderr.String(), err
}

func TestBinaryHelpHasNoManagementInterface(t *testing.T) {
	t.Run("help_omits_management_commands", func(t *testing.T) {
		for _, args := range [][]string{nil, {"help"}, {"-h"}, {"--help"}} {
			stdout, stderr, err := runBinary(args...)
			if err != nil || stderr != "" {
				t.Fatalf("run(%v)=(%q,%q,%v)", args, stdout, stderr, err)
			}
			for _, forbidden := range []string{"deploy", "status", "verify", "init", "app", "--config", "--format", "json", "yaml", "generic", "alias", "migration"} {
				if strings.Contains(strings.ToLower(stdout), forbidden) {
					t.Fatalf("help exposes %q: %s", forbidden, stdout)
				}
			}
		}
	})
}

func TestBinaryVersionAndClosedDispatch(t *testing.T) {
	t.Run("version", func(t *testing.T) {
		for _, argument := range []string{"version", "--version"} {
			stdout, stderr, err := runBinary(argument)
			if err != nil || stderr != "" || stdout != "lanpanel dev\n" {
				t.Fatalf("version=(%q,%q,%v)", stdout, stderr, err)
			}
		}
	})
	t.Run("obsolete_inputs_rejected", func(t *testing.T) {
		for _, args := range [][]string{{"deploy"}, {"status"}, {"ui"}, {"--role", "helper"}, {"legacy-deploy"}, {"config.yaml"}} {
			stdout, _, err := runBinary(args...)
			if err == nil || stdout != "" {
				t.Fatalf("obsolete or unavailable entry %v was accepted", args)
			}
		}
	})
}
