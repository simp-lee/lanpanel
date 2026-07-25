package nginx

import (
	"context"
	"lanpanel/internal/host"
	"strings"
)

type Activator struct {
	executor host.Executor
}

func NewActivator(executor host.Executor) Activator {
	return Activator{executor: executor}
}

func EnsureSiteEnabledCommand() host.Command {
	return host.Command{Name: "ln", Args: []string{"-sfn", "--", SiteAvailablePath, SiteEnabledPath}}
}

func DisableDefaultSiteCommand() host.Command {
	return disableDefaultSiteCommand(DefaultSiteEnabledPath, DefaultSiteAvailablePath)
}

func TestConfigCommand() host.Command {
	return host.Command{Name: "nginx", Args: []string{"-t"}}
}

func ReloadCommand() host.Command {
	return host.Command{Name: "systemctl", Args: []string{"reload", "nginx.service"}}
}

func (activator Activator) EnableTestAndReload(ctx context.Context) ([]host.Result, error) {
	result, err := activator.executor.Run(ctx, activateSiteCommand(SiteEnabledPath, SiteAvailablePath, DefaultSiteEnabledPath, DefaultSiteAvailablePath))
	results := []host.Result{result}
	return results, err
}

func activateSiteCommand(siteEnabledPath string, siteAvailablePath string, defaultEnabledPath string, defaultAvailablePath string) host.Command {
	script := `set -u
site_enabled=$1
site_available=$2
default_enabled=$3
default_available=$4

snapshot_link() {
    path=$1
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        printf 'absent'
        return 0
    fi
    if [ ! -L "$path" ]; then
        echo "$path exists but is not a symlink; refusing to activate lanpanel Nginx site" >&2
        return 64
    fi
    target=$(readlink -- "$path")
    status=$?
    if [ "$status" -ne 0 ]; then
        return "$status"
    fi
    if [ -z "$target" ]; then
        echo "$path symlink target is empty; refusing to activate lanpanel Nginx site" >&2
        return 64
    fi
    case "$target" in
        *'
'*)
            echo "$path symlink target contains a newline; refusing to activate lanpanel Nginx site" >&2
            return 64
            ;;
    esac
    printf 'symlink:%s' "$target"
}

restore_link() {
    snapshot=$1
    path=$2
    case "$snapshot" in
        absent)
            rm -f -- "$path"
            return $?
            ;;
        symlink:*)
            target=${snapshot#symlink:}
            if [ -z "$target" ]; then
                echo "saved Nginx symlink target for $path is empty" >&2
                return 64
            fi
            ln -sfn -- "$target" "$path"
            return $?
            ;;
        *)
            echo "invalid Nginx symlink snapshot for $path: $snapshot" >&2
            return 64
            ;;
    esac
}

restore_after_failure() {
    original_status=$1
    reload_restored=$2
    restore_link "$site_snapshot" "$site_enabled"
    status=$?
    if [ "$status" -ne 0 ]; then
        echo "rollback lanpanel Nginx site symlink failed" >&2
        exit "$status"
    fi
    restore_link "$default_snapshot" "$default_enabled"
    status=$?
    if [ "$status" -ne 0 ]; then
        echo "rollback default Nginx site symlink failed" >&2
        exit "$status"
    fi
    nginx -t
    status=$?
    if [ "$status" -ne 0 ]; then
        echo "restored previous Nginx site symlinks but nginx -t still failed" >&2
        exit "$status"
    fi
    if [ "$reload_restored" = "yes" ]; then
        systemctl reload nginx.service
        status=$?
        if [ "$status" -ne 0 ]; then
            echo "restored previous Nginx site symlinks but nginx reload failed" >&2
            exit "$status"
        fi
    fi
    exit "$original_status"
}

disable_default_site() {
    enabled=$1
    default_target=$2
    if [ ! -e "$enabled" ] && [ ! -L "$enabled" ]; then
        return 0
    fi
    if [ ! -L "$enabled" ]; then
        echo "$enabled exists but is not a symlink; remove or migrate it before enabling lanpanel's default_server site" >&2
        return 64
    fi
    target=$(readlink -- "$enabled")
    status=$?
    if [ "$status" -ne 0 ]; then
        return "$status"
    fi
    case "$target" in
        "$default_target"|../sites-available/default)
            rm -f -- "$enabled"
            return $?
            ;;
        *)
            resolved=$(readlink -f -- "$enabled" 2>/dev/null || true)
            resolved_default=$(readlink -f -- "$default_target" 2>/dev/null || true)
            if [ -n "$resolved" ] && [ -n "$resolved_default" ] && [ "$resolved" = "$resolved_default" ]; then
                rm -f -- "$enabled"
                return $?
            fi
            echo "$enabled points to $target; remove or migrate it before enabling lanpanel's default_server site" >&2
            return 64
            ;;
    esac
}

default_snapshot=$(snapshot_link "$default_enabled")
status=$?
if [ "$status" -ne 0 ]; then
    exit "$status"
fi
site_snapshot=$(snapshot_link "$site_enabled")
status=$?
if [ "$status" -ne 0 ]; then
    exit "$status"
fi

disable_default_site "$default_enabled" "$default_available"
status=$?
if [ "$status" -ne 0 ]; then
    exit "$status"
fi

ln -sfn -- "$site_available" "$site_enabled"
status=$?
if [ "$status" -ne 0 ]; then
    restore_after_failure "$status" no
fi

nginx -t
status=$?
if [ "$status" -ne 0 ]; then
    restore_after_failure "$status" no
fi

systemctl reload nginx.service
status=$?
if [ "$status" -ne 0 ]; then
    restore_after_failure "$status" yes
fi`
	return host.Command{
		Name: "sh",
		Args: []string{
			"-c",
			script,
			"lanpanel-activate-nginx-site",
			strings.TrimSpace(siteEnabledPath),
			strings.TrimSpace(siteAvailablePath),
			strings.TrimSpace(defaultEnabledPath),
			strings.TrimSpace(defaultAvailablePath),
		},
		DisplayName: "activate-nginx-site",
		DisplayArgs: []string{strings.TrimSpace(siteEnabledPath), strings.TrimSpace(defaultEnabledPath)},
	}
}

func disableDefaultSiteCommand(enabledPath string, availablePath string) host.Command {
	script := `set -eu
enabled=$1
default_target=$2
if [ ! -e "$enabled" ] && [ ! -L "$enabled" ]; then
    exit 0
fi
if [ ! -L "$enabled" ]; then
    echo "$enabled exists but is not a symlink; remove or migrate it before enabling lanpanel's default_server site" >&2
    exit 64
fi
target=$(readlink -- "$enabled")
case "$target" in
    "$default_target"|../sites-available/default)
        rm -f -- "$enabled"
        ;;
    *)
        resolved=$(readlink -f -- "$enabled" 2>/dev/null || true)
        resolved_default=$(readlink -f -- "$default_target" 2>/dev/null || true)
        if [ -n "$resolved" ] && [ -n "$resolved_default" ] && [ "$resolved" = "$resolved_default" ]; then
            rm -f -- "$enabled"
        else
            echo "$enabled points to $target; remove or migrate it before enabling lanpanel's default_server site" >&2
            exit 64
        fi
        ;;
esac`
	return host.Command{
		Name:        "sh",
		Args:        []string{"-c", script, "lanpanel-disable-nginx-default-site", strings.TrimSpace(enabledPath), strings.TrimSpace(availablePath)},
		DisplayName: "disable-nginx-default-site",
		DisplayArgs: []string{strings.TrimSpace(enabledPath)},
	}
}
