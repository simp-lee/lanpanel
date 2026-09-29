package main

import (
	"path/filepath"
	"testing"
)

func TestRepositoryDependencyLockIsCanonical(t *testing.T) {
	value, err := readCanonical(filepath.Join("..", "..", "release-inputs", "dependency-inputs.v2.json"), &dependencyInputs{})
	if err != nil {
		t.Fatalf("repository dependency lock is not canonical: %v", err)
	}
	inputs, ok := value.(dependencyInputs)
	if !ok {
		t.Fatalf("readCanonical returned %T, want dependencyInputs", value)
	}
	if err := validateDependencies(inputs); err != nil {
		t.Fatalf("repository dependency lock is invalid: %v", err)
	}
}
