package main

import (
	"path/filepath"
	"testing"
)

func TestBuildBaselineAcceptsRepositoryDependencyLock(t *testing.T) {
	baseline, err := buildBaseline(filepath.Join("..", "..", "release-inputs", "dependency-inputs.v2.json"))
	if err != nil {
		t.Fatalf("repository dependency lock cannot build a profile baseline: %v", err)
	}
	if len(baseline.Selections) != 4 {
		t.Fatalf("baseline has %d selections, want 4", len(baseline.Selections))
	}
}
