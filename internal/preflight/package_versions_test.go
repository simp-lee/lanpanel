package preflight

import (
	"testing"
	"time"
)

func TestExpansionPreflightDoesNotBindSystemdOrNginxPackageVersions(t *testing.T) {
	request := expansionRequest(ExpansionDomainHTTPS)
	request.Profile.SystemdVersion = "not-a-version"
	request.Profile.NginxVersion = "not-a-version"
	request.Profile.PackageSnapshotDigest = "not-a-digest"
	observed := passingExpansionObservations(request, time.Unix(1_700_000_000, 0).UTC())
	observed.Packages.SystemdVersion = "different"
	observed.Packages.NginxVersion = "different"
	observed.Packages.PackageSnapshotDigest = "different"
	result, err := EvaluateExpansion(request, observed)
	if err != nil || !result.Allowed {
		t.Fatalf("obsolete package identity fields blocked preflight: err=%v result=%#v", err, result)
	}
}
