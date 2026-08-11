package assets

import (
	"fmt"
	"io/fs"
	"slices"
)

type Role string

const (
	RoleReference     Role = "reference"
	RoleDocumentation Role = "documentation"
	RoleRuntime       Role = "runtime"
)

type ContentMode string

const (
	ContentModeCopy   ContentMode = "copy"
	ContentModeRender ContentMode = "render"
)

type Activation string

const (
	ActivationReloadNginx      Activation = "reload-nginx"
	ActivationRestartHeadscale Activation = "restart-headscale"
)

type Asset struct {
	SourcePath  string
	Role        Role
	ContentMode ContentMode
	HostPath    string
	Mode        fs.FileMode
	Activations []Activation
}

var catalog = []Asset{
	{SourcePath: "templates/app/goaccess-logrotate.tmpl", Role: RoleRuntime, ContentMode: ContentModeRender},
	{SourcePath: "templates/app/goaccess.conf.tmpl", Role: RoleRuntime, ContentMode: ContentModeRender},
	{SourcePath: "templates/app/goaccess.service.tmpl", Role: RoleRuntime, ContentMode: ContentModeRender},
	{SourcePath: "templates/app/install-cert-and-reload-nginx.sh.tmpl", Role: RoleRuntime, ContentMode: ContentModeRender},
	{SourcePath: "templates/app/lego-renew.service.tmpl", Role: RoleRuntime, ContentMode: ContentModeRender},
	{SourcePath: "templates/app/lego-renew.timer.tmpl", Role: RoleRuntime, ContentMode: ContentModeRender},
	{SourcePath: "templates/app/nginx.conf.tmpl", Role: RoleRuntime, ContentMode: ContentModeRender},
	{SourcePath: "templates/app/service.tmpl", Role: RoleRuntime, ContentMode: ContentModeRender},
	{SourcePath: "templates/realip/nginx-realip.conf.tmpl", Role: RoleRuntime, ContentMode: ContentModeRender},
	{SourcePath: "templates/realip/refresh.service.tmpl", Role: RoleRuntime, ContentMode: ContentModeRender},
	{SourcePath: "templates/realip/refresh.timer.tmpl", Role: RoleRuntime, ContentMode: ContentModeRender},
	{SourcePath: "templates/realip/trusted-cidrs.conf.tmpl", Role: RoleRuntime, ContentMode: ContentModeRender},
	{
		SourcePath:  "templates/etc/headscale/config.yaml.tmpl",
		Role:        RoleRuntime,
		ContentMode: ContentModeRender,
		HostPath:    "/etc/headscale/config.yaml",
		Mode:        0o644,
		Activations: []Activation{ActivationRestartHeadscale},
	},
	{
		SourcePath:  "templates/etc/headscale/policy.hujson",
		Role:        RoleRuntime,
		ContentMode: ContentModeCopy,
		HostPath:    "/etc/headscale/policy.hujson",
		Mode:        0o644,
		Activations: []Activation{ActivationRestartHeadscale},
	},
	{
		SourcePath:  "templates/usr/local/lib/lanpanel/hooks/install-lego-cert-and-reload-nginx.sh",
		Role:        RoleRuntime,
		ContentMode: ContentModeCopy,
		HostPath:    "/usr/local/lib/lanpanel/hooks/install-lego-cert-and-reload-nginx.sh",
		Mode:        0o755,
	},
	{
		SourcePath:  "templates/etc/systemd/system/lanpanel-lego-renew.service.tmpl",
		Role:        RoleRuntime,
		ContentMode: ContentModeRender,
		HostPath:    "/etc/systemd/system/lanpanel-lego-renew.service",
		Mode:        0o644,
	},
	{
		SourcePath:  "templates/etc/systemd/system/lanpanel-lego-renew.timer",
		Role:        RoleRuntime,
		ContentMode: ContentModeCopy,
		HostPath:    "/etc/systemd/system/lanpanel-lego-renew.timer",
		Mode:        0o644,
	},
	{
		SourcePath:  "templates/etc/nginx/sites-available/headscale.conf.tmpl",
		Role:        RoleRuntime,
		ContentMode: ContentModeRender,
		HostPath:    "/etc/nginx/sites-available/headscale.conf",
		Mode:        0o644,
		Activations: []Activation{ActivationReloadNginx},
	},
}

func Catalog() []Asset {
	return cloneCatalog(catalog)
}

func RuntimeCatalog() []Asset {
	items := make([]Asset, 0, len(catalog))
	for _, asset := range catalog {
		if asset.HostPath == "" {
			continue
		}
		items = append(items, cloneAsset(asset))
	}
	return items
}

func Lookup(sourcePath string) (Asset, bool) {
	for _, asset := range catalog {
		if asset.SourcePath == sourcePath {
			return cloneAsset(asset), true
		}
	}
	return Asset{}, false
}

func MustLookup(sourcePath string) Asset {
	asset, ok := Lookup(sourcePath)
	if !ok {
		panic(fmt.Sprintf("assets: unknown source path %q", sourcePath))
	}
	return asset
}

func cloneCatalog(items []Asset) []Asset {
	cloned := make([]Asset, 0, len(items))
	for _, asset := range items {
		cloned = append(cloned, cloneAsset(asset))
	}
	slices.SortFunc(cloned, func(left Asset, right Asset) int {
		switch {
		case left.SourcePath < right.SourcePath:
			return -1
		case left.SourcePath > right.SourcePath:
			return 1
		default:
			return 0
		}
	})
	return cloned
}

func cloneAsset(asset Asset) Asset {
	asset.Activations = slices.Clone(asset.Activations)
	return asset
}
