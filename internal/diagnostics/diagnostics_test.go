package diagnostics

import "testing"

func TestBuildReportsPackageIdentityDrift(t *testing.T) {
	issues := Build(Observation{Nginx: "package_identity_drift"})
	if len(issues) != 1 || issues[0].Code != "package_identity_drift" {
		t.Fatalf("issues=%#v", issues)
	}
	if issues[0].Guidance == "" {
		t.Fatal("package identity drift guidance is missing")
	}
}
