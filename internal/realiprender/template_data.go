package realiprender

import (
	"fmt"
	"lanpanel/internal/realip"
	"lanpanel/internal/realipassets"
	"path/filepath"
	"strings"
	"unicode"
)

type TemplateData struct {
	ProfileName     string
	Provider        string
	RefreshInterval string
	TrustedCIDRs    []string
	LanpanelBinary  string
	AppConfigPath   string
	StateJSON       string
	ProfileJSON     string
	ReferenceJSON   string
}

func NewTemplateData(profile realip.ProfileConfig, state realip.State, reference realip.Reference, appConfigPath string) (TemplateData, error) {
	appConfigPath = strings.TrimSpace(appConfigPath)
	if appConfigPath == "" {
		return TemplateData{}, fmt.Errorf("realip refresh app config path is required")
	}
	if !filepath.IsAbs(appConfigPath) {
		return TemplateData{}, fmt.Errorf("realip refresh app config path must be absolute")
	}
	if !isSystemdExecToken(appConfigPath) {
		return TemplateData{}, fmt.Errorf("realip refresh app config path must be a single systemd ExecStart token")
	}
	marker := "Lanpanel-managed: realip.profile=" + strings.TrimSpace(profile.Name) + " provider=" + strings.TrimSpace(profile.Provider)
	stateJSON, err := marshalManagedJSON(struct {
		SchemaVersion   string `json:"schema_version"`
		LanpanelManaged string `json:"lanpanel_managed"`
		realip.State
	}{SchemaVersion: realip.StateSchemaVersion, LanpanelManaged: marker, State: state})
	if err != nil {
		return TemplateData{}, err
	}
	profileJSON, err := marshalManagedJSON(struct {
		SchemaVersion   string `json:"schema_version"`
		LanpanelManaged string `json:"lanpanel_managed"`
		realip.ProfileConfig
	}{SchemaVersion: realip.ProfileSchemaVersion, LanpanelManaged: marker, ProfileConfig: profile})
	if err != nil {
		return TemplateData{}, err
	}
	referenceJSON := ""
	if strings.TrimSpace(reference.AppName) != "" {
		referenceBytes, err := marshalManagedJSON(struct {
			SchemaVersion   string `json:"schema_version"`
			LanpanelManaged string `json:"lanpanel_managed"`
			realip.Reference
		}{SchemaVersion: realip.ReferenceSchemaVersion, LanpanelManaged: marker, Reference: reference})
		if err != nil {
			return TemplateData{}, err
		}
		referenceJSON = string(referenceBytes)
	}
	refreshInterval := strings.TrimSpace(profile.RefreshInterval)
	if refreshInterval == "" {
		refreshInterval = "72h"
	}
	systemdRefreshInterval, err := realip.SystemdRefreshInterval(refreshInterval)
	if err != nil {
		return TemplateData{}, err
	}
	return TemplateData{
		ProfileName:     strings.TrimSpace(profile.Name),
		Provider:        strings.TrimSpace(profile.Provider),
		RefreshInterval: systemdRefreshInterval,
		TrustedCIDRs:    append([]string(nil), state.TrustedCIDRs...),
		LanpanelBinary:  realipassets.DefaultRefreshBinaryPath,
		AppConfigPath:   appConfigPath,
		StateJSON:       string(stateJSON),
		ProfileJSON:     string(profileJSON),
		ReferenceJSON:   referenceJSON,
	}, nil
}

func isSystemdExecToken(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) || unicode.IsSpace(r) || strings.ContainsRune("%;\"'\\${}", r) {
			return false
		}
	}
	return true
}
