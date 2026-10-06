//go:build linux

package application

import (
	"lanpanel/internal/operations"
	"testing"
)

func TestOperationRegistryIncludesManagementHTTPSConfiguration(t *testing.T) {
	registry, err := operationRegistry()
	if err != nil {
		t.Fatal(err)
	}
	registration, ok := registry.Registration(operations.ManagementHTTPSConfigure)
	if !ok {
		t.Fatal("management HTTPS configuration operation is not registered")
	}
	if registration.Owner != "application.management-https" {
		t.Fatalf("unexpected owner %q", registration.Owner)
	}
	if registration.Results == nil {
		t.Fatal("management HTTPS configuration has no result branches")
	}
}
