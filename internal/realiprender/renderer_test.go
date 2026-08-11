package realiprender

import (
	"lanpanel/internal/realip"
	"strings"
	"testing"
	"time"
)

func TestStageRuntimeRendersProfileArtifacts(t *testing.T) {
	t.Parallel()

	profile := realip.ProfileConfig{
		Name:            "edgeone-prod",
		Provider:        "edgeone",
		ZoneID:          "zone-2abcDEF123",
		EnvFile:         "/etc/lanpanel/realip/edgeone-prod.env",
		RefreshInterval: "3600000000000ns",
		Domains:         []string{"app.example.com"},
	}
	state := realip.State{
		ProfileName:     "edgeone-prod",
		Provider:        "edgeone",
		ZoneID:          "zone-2abcDEF123",
		OriginACLStatus: "online",
		OriginACLFamily: "global",
		CurrentVersion:  "v1",
		TrustedCIDRs:    []string{"8.8.8.0/24", "9.9.9.9/32"},
		CurrentCIDRs:    []string{"8.8.8.0/24", "9.9.9.9/32"},
		UpdatedAt:       time.Unix(1700000000, 0).UTC(),
	}
	reference := realip.Reference{AppName: "example-app", Profile: "edgeone-prod", Domains: []string{"app.example.com"}}
	staged, err := StageRuntime(profile, state, reference, "/etc/lanpanel/lanpanel-app.yaml")
	if err != nil {
		t.Fatalf("StageRuntime() error = %v", err)
	}
	content := map[string]string{}
	for _, file := range staged {
		content[file.SourcePath] = string(file.Content)
		if !strings.Contains(string(file.Content), "Lanpanel-managed: realip.profile=edgeone-prod provider=edgeone") &&
			!strings.Contains(file.SourcePath, "generated/realip/") {
			t.Fatalf("%s missing managed marker\n%s", file.SourcePath, file.Content)
		}
	}
	if got, want := renderedRealIPPayloadLines(content["templates/realip/nginx-realip.conf.tmpl"]), []string{
		"set_real_ip_from 8.8.8.0/24;",
		"set_real_ip_from 9.9.9.9/32;",
	}; !stringSlicesEqual(got, want) {
		t.Fatalf("nginx realip include payload lines = %#v, want %#v\n%s", got, want, content["templates/realip/nginx-realip.conf.tmpl"])
	}
	if got, want := renderedRealIPPayloadLines(content["templates/realip/trusted-cidrs.conf.tmpl"]), []string{
		"8.8.8.0/24 1;",
		"9.9.9.9/32 1;",
	}; !stringSlicesEqual(got, want) {
		t.Fatalf("trusted CIDR include payload lines = %#v, want %#v\n%s", got, want, content["templates/realip/trusted-cidrs.conf.tmpl"])
	}
	if !strings.Contains(content["templates/realip/refresh.timer.tmpl"], "OnUnitActiveSec=3600s") || strings.Contains(content["templates/realip/refresh.timer.tmpl"], "3600000000000ns") {
		t.Fatalf("refresh timer missing interval\n%s", content["templates/realip/refresh.timer.tmpl"])
	}
	if !strings.Contains(content["templates/realip/refresh.service.tmpl"], "ExecStart=/usr/local/bin/lanpanel timer") {
		t.Fatalf("refresh service missing closed timer role\n%s", content["templates/realip/refresh.service.tmpl"])
	}
	if strings.Contains(content["templates/realip/refresh.service.tmpl"], "--") {
		t.Fatalf("refresh service must not embed manual confirmation\n%s", content["templates/realip/refresh.service.tmpl"])
	}
	if !strings.Contains(content["templates/realip/refresh.service.tmpl"], "TimeoutStartSec=2min") {
		t.Fatalf("refresh service missing bounded timeout\n%s", content["templates/realip/refresh.service.tmpl"])
	}
	if !strings.Contains(content["generated/realip/state.json"], `"trusted_cidrs": [`) {
		t.Fatalf("state json missing trusted CIDRs\n%s", content["generated/realip/state.json"])
	}
	if !strings.Contains(content["generated/realip/state.json"], `"origin_acl_status": "online"`) {
		t.Fatalf("state json missing origin ACL status\n%s", content["generated/realip/state.json"])
	}
	if !strings.Contains(content["generated/realip/profile.json"], `"env_file": "/etc/lanpanel/realip/edgeone-prod.env"`) {
		t.Fatalf("profile json missing env_file\n%s", content["generated/realip/profile.json"])
	}
	if !strings.Contains(content["generated/realip/reference.json"], `"app_name": "example-app"`) {
		t.Fatalf("reference json missing app name\n%s", content["generated/realip/reference.json"])
	}
}

func TestNewTemplateDataRejectsUnsafeAppConfigPath(t *testing.T) {
	t.Parallel()

	profile := realip.ProfileConfig{Name: "edgeone-prod", Provider: "edgeone", RefreshInterval: "1h"}
	state := realip.State{ProfileName: "edgeone-prod", Provider: "edgeone"}
	if _, err := NewTemplateData(profile, state, realip.Reference{}, "lanpanel-app.yaml"); err == nil || !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("NewTemplateData(relative) error = %v, want absolute path refusal", err)
	}
	for _, path := range []string{
		"/etc/lanpanel/app;evil.yaml",
		"/etc/lanpanel/app$evil.yaml",
		"/etc/lanpanel/app{evil}.yaml",
		"/etc/lanpanel/app%h.yaml",
		"/etc/lanpanel/app name.yaml",
	} {
		path := path
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			if _, err := NewTemplateData(profile, state, realip.Reference{}, path); err == nil || !strings.Contains(err.Error(), "single systemd ExecStart token") {
				t.Fatalf("NewTemplateData(%q) error = %v, want token refusal", path, err)
			}
		})
	}
}

func renderedRealIPPayloadLines(content string) []string {
	lines := []string{}
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

func stringSlicesEqual(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
