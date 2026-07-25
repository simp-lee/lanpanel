package ui

import (
	"lanpanel/internal/appconfig"
	"lanpanel/internal/components/headscale"
	legocomponent "lanpanel/internal/components/lego"
	"lanpanel/internal/config"
	"strings"
	"testing"
)

func TestAppConfigFormDoesNotDefaultMissingAccessModeToPublic(t *testing.T) {
	t.Parallel()

	cfg := appconfig.ExampleConfig()
	cfg.Access.AccessMode = ""

	body := appConfigFormHTML("/tmp/lanpanel-app.yaml", cfg, nil, nil)
	if !strings.Contains(body, `<option value="" selected>Select Access mode</option>`) {
		t.Fatalf("appConfigFormHTML() missing selected empty access mode option: %s", body)
	}
	if strings.Contains(body, `<option value="public" selected>public</option>`) {
		t.Fatalf("appConfigFormHTML() selected public for missing access mode: %s", body)
	}
	if strings.Contains(body, `value="private_client"`) {
		t.Fatalf("appConfigFormHTML() exposed private_client write option: %s", body)
	}
}

func TestAppConfigFormShowsPrivateClientAsReadOnly(t *testing.T) {
	t.Parallel()

	cfg := appconfig.ExampleConfig()
	cfg.Access.AccessMode = appconfig.AccessModePrivateClient

	body := appConfigFormHTML("/tmp/lanpanel-app.yaml", cfg, nil, nil)
	if !strings.Contains(body, `<input id="field-current_access_mode" value="private_client" readonly disabled>`) {
		t.Fatalf("appConfigFormHTML() missing read-only private_client display: %s", body)
	}
	if strings.Contains(body, `<option value="private_client"`) {
		t.Fatalf("appConfigFormHTML() exposed private_client write option: %s", body)
	}
}

func TestAppConfigFormShowsRequiredExposureConfirmationControls(t *testing.T) {
	t.Parallel()

	body := appConfigFormHTML("/tmp/lanpanel-app.yaml", appconfig.ExampleConfig(), []string{"origin-protection-manual"}, nil)
	if count := strings.Count(body, `name="confirmation" value="origin-protection-manual"`); count != 1 {
		t.Fatalf("origin-protection-manual count = %d, want deploy control only:\n%s", count, body)
	}
	for _, token := range []string{"public-app-risk", "direct-origin-risk"} {
		if strings.Contains(body, `name="confirmation" value="`+token+`"`) {
			t.Fatalf("confirmation %q rendered without being required:\n%s", token, body)
		}
	}
}

func TestDependencyUploadFormsExposeControlledOperations(t *testing.T) {
	t.Parallel()

	mainBody := mainConfigFormHTML("/tmp/lanpanel.yaml", config.ExampleConfig())
	for _, want := range []string{
		`value="main_lego_archive_upload"`,
		`value="main_headscale_deb_upload"`,
		`name="dependency_upload_file"`,
		legocomponent.OfficialArchiveAssetName(legocomponent.Version, config.ArchAMD64),
		headscale.OfficialPackageAssetName(headscale.Version, config.ArchAMD64),
	} {
		if !strings.Contains(mainBody, want) {
			t.Fatalf("mainConfigFormHTML() missing %q:\n%s", want, mainBody)
		}
	}

	appBody := appConfigFormHTML("/tmp/lanpanel-app.yaml", appconfig.ExampleConfig(), nil, nil)
	for _, want := range []string{
		`value="app_lego_archive_upload"`,
		`name="dependency_upload_file"`,
		legocomponent.OfficialArchiveAssetName(legocomponent.Version, config.ArchAMD64),
	} {
		if !strings.Contains(appBody, want) {
			t.Fatalf("appConfigFormHTML() missing %q:\n%s", want, appBody)
		}
	}
	if strings.Contains(appBody, `value="main_headscale_deb_upload"`) {
		t.Fatalf("appConfigFormHTML() exposed main Headscale upload operation:\n%s", appBody)
	}
}

func TestAppConfigFormDoesNotExposeGoAccessCredentialJobs(t *testing.T) {
	t.Parallel()

	body := appConfigFormHTML("/tmp/lanpanel-app.yaml", appconfig.ExampleConfig(), nil, nil)
	for _, disallowed := range []string{
		`goaccess_auth_create`,
		`goaccess_auth_rotate`,
		`GoAccess Dashboard Credentials`,
		`Create and Enable`,
	} {
		if strings.Contains(body, disallowed) {
			t.Fatalf("appConfigFormHTML() exposed unsupported GoAccess credential job %q:\n%s", disallowed, body)
		}
	}
	if !strings.Contains(body, `name="goaccess_auth_file"`) {
		t.Fatalf("appConfigFormHTML() missing external GoAccess auth file field:\n%s", body)
	}
}
