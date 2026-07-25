package realip

import "time"

const (
	ProfileSchemaVersion   = "lanpanel.realip.profile.v1"
	StateSchemaVersion     = "lanpanel.realip.state.v1"
	ReferenceSchemaVersion = "lanpanel.realip.reference.v1"
)

type ProfileConfig struct {
	Name            string   `json:"name"`
	Provider        string   `json:"provider"`
	ZoneID          string   `json:"zone_id"`
	EnvFile         string   `json:"env_file"`
	RefreshInterval string   `json:"refresh_interval"`
	Domains         []string `json:"domains"`
}

type Reference struct {
	AppName string   `json:"app_name"`
	Profile string   `json:"profile"`
	Domains []string `json:"domains"`
}

type State struct {
	ProfileName       string    `json:"profile_name"`
	Provider          string    `json:"provider"`
	ZoneID            string    `json:"zone_id"`
	OriginACLStatus   string    `json:"origin_acl_status"`
	OriginACLFamily   string    `json:"origin_acl_family"`
	CurrentVersion    string    `json:"current_version"`
	CurrentActiveTime string    `json:"current_active_time"`
	NextVersion       string    `json:"next_version,omitempty"`
	NextActiveTime    string    `json:"next_active_time,omitempty"`
	PlannedActiveTime string    `json:"planned_active_time,omitempty"`
	L7Hosts           []string  `json:"l7_hosts"`
	CurrentCIDRs      []string  `json:"current_cidrs"`
	NextCIDRs         []string  `json:"next_cidrs,omitempty"`
	TrustedCIDRs      []string  `json:"trusted_cidrs"`
	UpdatedAt         time.Time `json:"updated_at"`
}
