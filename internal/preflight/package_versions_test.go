package preflight

import (
	"testing"
	"time"
)

func TestExpansionPreflightExactPackageVersions(t *testing.T) {
	for _, scope := range []ExpansionScope{ExpansionDomainHTTPS, ExpansionBootstrap} {
		for _, change := range []string{"matching", "systemd_revision", "nginx_revision", "systemd_invalid", "nginx_invalid"} {
			t.Run(string(scope)+"/"+change, func(t *testing.T) {
				request := expansionRequest(scope)
				request.Profile.SystemdVersion = "1:257.8-1~deb13u1"
				request.Profile.NginxVersion = "1.26.3-3+deb13u1"
				if scope == ExpansionBootstrap {
					request.Target = "installation"
					request.Domains = nil
					request.BootstrapListeners = []ListenerRequirement{{Protocol: "tcp", Address: "127.23.45.67", Port: 52345, Purpose: "management"}}
				}
				observed := passingExpansionObservations(request, time.Unix(1_700_000_000, 0).UTC())
				if scope == ExpansionBootstrap {
					observed.Packages.NginxVersion = ""
				}
				switch change {
				case "systemd_revision":
					observed.Packages.SystemdVersion = "1:257.8-1~deb13u2"
				case "nginx_revision":
					observed.Packages.NginxVersion = "1.26.3-3+deb13u2"
				case "systemd_invalid":
					request.Profile.SystemdVersion = ""
				case "nginx_invalid":
					request.Profile.NginxVersion = "nginx/1.26.3"
				}
				result, err := EvaluateExpansion(request, observed)
				if change == "systemd_invalid" || change == "nginx_invalid" {
					if err == nil {
						t.Fatal("malformed expected package identity accepted")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if change == "matching" {
					if !result.Allowed {
						t.Fatalf("matching full package versions blocked: %#v", result)
					}
					return
				}
				if scope == ExpansionBootstrap {
					if !result.Allowed {
						t.Fatalf("bootstrap package capability check blocked: %#v", result)
					}
					return
				}
				finding, ok := findingByCode(result.Findings, "package_state")
				if result.Allowed || !ok || finding.Disposition != FindingBlocked {
					t.Fatalf("package revision drift was not blocked after installation: %#v", result)
				}
			})
		}
	}
}
