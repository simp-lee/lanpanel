package appsvc

import (
	"lanpanel/internal/host"
	"strings"
)

func EnsureSystemUserCommands(names Names) []host.Command {
	return []host.Command{ensureSystemUserCommand(names.SystemUser, names.VarLibDir, "lanpanel-app-user", "ensure-app-user")}
}

func ensureSystemUserCommand(name string, home string, arg0 string, displayName string) host.Command {
	script := `set -eu
name=$1
home=$2
shell=/usr/sbin/nologin

group_line="$(getent group "$name" || true)"
passwd_line="$(getent passwd "$name" || true)"

if [ -n "$group_line" ] && [ -z "$passwd_line" ]; then
    echo "app group $name already exists without matching app user; refusing to reuse" >&2
    exit 1
fi
if [ -z "$group_line" ] && [ -n "$passwd_line" ]; then
    echo "app user $name already exists without matching app group; refusing to reuse" >&2
    exit 1
fi

if [ -n "$group_line" ] && [ -n "$passwd_line" ]; then
    group_gid="$(printf '%s\n' "$group_line" | awk -F: '{print $3}')"
    user_uid="$(printf '%s\n' "$passwd_line" | awk -F: '{print $3}')"
    user_gid="$(printf '%s\n' "$passwd_line" | awk -F: '{print $4}')"
    user_home="$(printf '%s\n' "$passwd_line" | awk -F: '{print $6}')"
    user_shell="$(printf '%s\n' "$passwd_line" | awk -F: '{print $7}')"

    if [ "$user_gid" != "$group_gid" ]; then
        echo "app user $name primary group does not match app group; refusing to reuse" >&2
        exit 1
    fi
    if [ "$user_home" != "$home" ]; then
        echo "app user $name home is $user_home, expected $home; refusing to reuse" >&2
        exit 1
    fi
    if [ "$user_shell" != "$shell" ]; then
        echo "app user $name shell is $user_shell, expected $shell; refusing to reuse" >&2
        exit 1
    fi
    if [ "$user_uid" -eq 0 ] || [ "$user_uid" -ge 1000 ] || [ "$group_gid" -eq 0 ] || [ "$group_gid" -ge 1000 ]; then
        echo "app user/group $name is not a non-root system identity; refusing to reuse" >&2
        exit 1
    fi
    exit 0
fi

groupadd --system "$name"
useradd --system --gid "$name" --home-dir "$home" --shell "$shell" "$name"`
	return host.Command{
		Name:        "sh",
		Args:        []string{"-c", script, arg0, strings.TrimSpace(name), strings.TrimSpace(home)},
		DisplayName: displayName,
		DisplayArgs: []string{strings.TrimSpace(name)},
	}
}

func GuardSystemUserCommand(names Names) host.Command {
	return guardSystemUserCommand(names.SystemUser, names.VarLibDir, "lanpanel-app-user-guard", "guard-app-user")
}

func guardSystemUserCommand(name string, home string, arg0 string, displayName string) host.Command {
	script := `set -eu
name=$1
home=$2
shell=/usr/sbin/nologin

group_line="$(getent group "$name" || true)"
passwd_line="$(getent passwd "$name" || true)"

if [ -n "$group_line" ] && [ -z "$passwd_line" ]; then
    echo "app group $name already exists without matching app user; refusing to reuse" >&2
    exit 1
fi
if [ -z "$group_line" ] && [ -n "$passwd_line" ]; then
    echo "app user $name already exists without matching app group; refusing to reuse" >&2
    exit 1
fi
if [ -z "$group_line" ] && [ -z "$passwd_line" ]; then
    exit 0
fi

group_gid="$(printf '%s\n' "$group_line" | awk -F: '{print $3}')"
user_uid="$(printf '%s\n' "$passwd_line" | awk -F: '{print $3}')"
user_gid="$(printf '%s\n' "$passwd_line" | awk -F: '{print $4}')"
user_home="$(printf '%s\n' "$passwd_line" | awk -F: '{print $6}')"
user_shell="$(printf '%s\n' "$passwd_line" | awk -F: '{print $7}')"

if [ "$user_gid" != "$group_gid" ]; then
    echo "app user $name primary group does not match app group; refusing to reuse" >&2
    exit 1
fi
if [ "$user_home" != "$home" ]; then
    echo "app user $name home is $user_home, expected $home; refusing to reuse" >&2
    exit 1
fi
if [ "$user_shell" != "$shell" ]; then
    echo "app user $name shell is $user_shell, expected $shell; refusing to reuse" >&2
    exit 1
fi
if [ "$user_uid" -eq 0 ] || [ "$user_uid" -ge 1000 ] || [ "$group_gid" -eq 0 ] || [ "$group_gid" -ge 1000 ]; then
    echo "app user/group $name is not a non-root system identity; refusing to reuse" >&2
    exit 1
fi`
	return host.Command{
		Name:        "sh",
		Args:        []string{"-c", script, arg0, strings.TrimSpace(name), strings.TrimSpace(home)},
		DisplayName: displayName,
		DisplayArgs: []string{strings.TrimSpace(name)},
	}
}

func GuardRootDirectoriesCommand(names Names) host.Command {
	return guardRootDirectoriesCommand(names, "", "")
}

func GuardRootDirectoriesWithGoAccessAuthBootstrapCommand(names Names, authFile string) host.Command {
	return guardRootDirectoriesCommand(names, "", strings.TrimSpace(authFile))
}

func GuardRootDirectoriesWithAuthBootstrapsCommand(names Names, browserAuthFile string, goAccessAuthFile string) host.Command {
	return guardRootDirectoriesCommand(names, strings.TrimSpace(browserAuthFile), strings.TrimSpace(goAccessAuthFile))
}

func guardRootDirectoriesCommand(names Names, browserAuthFile string, goAccessAuthFile string) host.Command {
	script := `set -eu
app_name=$1
var_lib_dir=$2
var_lib_marker=$3
etc_dir=$4
etc_marker=$5
hook_dir=$6
hook_marker=$7
browser_auth_file=$8
goaccess_auth_file=$9
expected_marker="Lanpanel-managed: app.name=$app_name"
suggested_browser_auth_file="$etc_dir/browser.htpasswd"
suggested_goaccess_auth_file="$etc_dir/goaccess.htpasswd"

fail() {
    echo "$1" >&2
    exit 1
}

refuse_writable() {
    target=$1
    label=$2
    writable=$(find "$target" -maxdepth 0 \( -perm -020 -o -perm -002 \) -print -quit) || fail "failed to inspect $label $target permissions"
    if [ -n "$writable" ]; then
        fail "$label $target must not be writable by group or others"
    fi
}

require_root_owned() {
    target=$1
    label=$2
    owner=$(stat -c %u "$target")
    if [ "$owner" != "0" ]; then
        fail "$label $target must be owned by root"
    fi
}

write_marker() {
    dir=$1
    marker=$2
    tmp=$(mktemp "$dir/.lanpanel-managed.XXXXXX")
    trap 'rm -f "$tmp"' EXIT INT TERM
    printf '%s\n' "$expected_marker" > "$tmp"
    chmod 0644 "$tmp"
    mv "$tmp" "$marker"
    trap - EXIT INT TERM
}

validate_bootstrap_file() {
    dir=$1
    file=$2
    expected=$3
    label=$4

    if [ "$file" != "$expected" ]; then
        fail "$label $file must be $expected"
    fi
    if [ "$(dirname "$file")" != "$dir" ]; then
        fail "$label $file is not directly under $dir"
    fi
    if [ -L "$file" ]; then
        fail "$label $file must not be a symlink"
    fi
    if [ ! -f "$file" ]; then
        fail "$label $file must be a regular file"
    fi
    require_root_owned "$file" "$label"
    refuse_writable "$file" "$label"
}

validate_bootstrap_files() {
    dir=$1
    browser_name=""
    goaccess_name=""
    if [ -n "$browser_auth_file" ] && [ "$(dirname "$browser_auth_file")" = "$dir" ]; then
        validate_bootstrap_file "$dir" "$browser_auth_file" "$suggested_browser_auth_file" "browser auth bootstrap file"
        browser_name=$(basename "$browser_auth_file")
    fi
    if [ -n "$goaccess_auth_file" ] && [ "$(dirname "$goaccess_auth_file")" = "$dir" ]; then
        validate_bootstrap_file "$dir" "$goaccess_auth_file" "$suggested_goaccess_auth_file" "GoAccess auth bootstrap file"
        goaccess_name=$(basename "$goaccess_auth_file")
    fi
    if [ -z "$browser_name" ] && [ -z "$goaccess_name" ]; then
        fail "$dir exists without $expected_marker and no expected auth bootstrap file is directly under it"
    fi
    extra=$(find "$dir" -mindepth 1 -maxdepth 1 ! -name "$browser_name" ! -name "$goaccess_name" ! -name ".lanpanel-managed" -print -quit) || fail "failed to inspect auth bootstrap directory $dir"
    if [ -n "$extra" ]; then
        fail "$dir exists without $expected_marker and contains files other than expected auth bootstrap files"
    fi
}

check_existing_root() {
    dir=$1
    marker=$2

    if [ -L "$dir" ]; then
        fail "$dir is a symlink; refusing to use it as a Lanpanel app root"
    fi
    if [ -e "$dir" ] && [ ! -d "$dir" ]; then
        fail "$dir exists and is not a directory; refusing to use it as a Lanpanel app root"
    fi
    if [ ! -d "$dir" ]; then
        return
    fi
    require_root_owned "$dir" "app root directory"
    refuse_writable "$dir" "app root directory"
    if [ -L "$marker" ]; then
        fail "$marker is a symlink; refusing to trust app root ownership"
    fi
    if [ ! -e "$marker" ]; then
        if { [ -n "$browser_auth_file" ] && [ "$dir" = "$(dirname "$browser_auth_file")" ]; } || { [ -n "$goaccess_auth_file" ] && [ "$dir" = "$(dirname "$goaccess_auth_file")" ]; }; then
            validate_bootstrap_files "$dir"
            write_marker "$dir" "$marker"
            return
        fi
        fail "$dir exists without $marker; refusing to write into a non-Lanpanel app root"
    fi
    if [ ! -f "$marker" ]; then
        fail "$marker is not a regular file; refusing to trust app root ownership"
    fi
    require_root_owned "$marker" "app root marker"
    refuse_writable "$marker" "app root marker"
    actual_marker=$(cat "$marker")
    if [ "$actual_marker" != "$expected_marker" ]; then
        fail "$dir is managed by a different Lanpanel app; refusing to write into it"
    fi
}

create_missing_root() {
    dir=$1
    marker=$2

    if [ -d "$dir" ]; then
        return
    fi
    install -d -m 0755 "$dir"
    write_marker "$dir" "$marker"
}

check_existing_root "$var_lib_dir" "$var_lib_marker"
check_existing_root "$etc_dir" "$etc_marker"
check_existing_root "$hook_dir" "$hook_marker"

create_missing_root "$var_lib_dir" "$var_lib_marker"
create_missing_root "$etc_dir" "$etc_marker"
create_missing_root "$hook_dir" "$hook_marker"`
	args := []string{
		"-c", script, "lanpanel-app-root-dirs", names.AppName,
		names.VarLibDir, names.VarLibMarkerPath,
		names.EtcDir, names.EtcMarkerPath,
		names.HookDir, names.HookDirMarkerPath,
		strings.TrimSpace(browserAuthFile),
		strings.TrimSpace(goAccessAuthFile),
	}
	return host.Command{
		Name:        "sh",
		Args:        args,
		DisplayName: "guard-app-root-directories",
		DisplayArgs: []string{names.VarLibDir, names.EtcDir, names.HookDir},
	}
}

func EnsureDirectoryCommands(names Names) []host.Command {
	return []host.Command{
		{Name: "install", Args: []string{"-d", "-m", "0755", "--", names.WebrootPath, names.LegoDataPath}},
		{Name: "install", Args: []string{"-d", "-m", "0755", "--", names.TLSDir}},
	}
}

func GuardServiceAccessCommand(names Names, binaryPath string, workingDirectory string) host.Command {
	script := `set -eu
user=$1
binary=$2
working_dir=$3

if ! command -v runuser >/dev/null 2>&1; then
    echo "runuser is required to verify app service user access" >&2
    exit 1
fi
if ! runuser -u "$user" -- test -x "$binary"; then
    echo "app service user $user cannot execute service binary $binary" >&2
    exit 1
fi
if [ -n "$working_dir" ]; then
    if ! runuser -u "$user" -- test -d "$working_dir"; then
        echo "app service user $user cannot access working_directory $working_dir as a directory" >&2
        exit 1
    fi
    if ! runuser -u "$user" -- test -x "$working_dir"; then
        echo "app service user $user cannot enter working_directory $working_dir" >&2
        exit 1
    fi
fi`
	return host.Command{
		Name:        "sh",
		Args:        []string{"-c", script, "lanpanel-app-service-access", names.SystemUser, strings.TrimSpace(binaryPath), strings.TrimSpace(workingDirectory)},
		DisplayName: "guard-app-service-access",
		DisplayArgs: []string{names.SystemUser, strings.TrimSpace(binaryPath)},
	}
}

func RemoveManagedServiceUnitCommand(names Names) host.Command {
	unitPath := "/etc/systemd/system/" + names.ServiceUnit
	script := `set -eu
unit=$1
unit_path=$2
app_name=$3
marker="Lanpanel-managed: app.name=$app_name"

if [ ! -e "$unit_path" ]; then
    exit 0
fi
if ! grep -Fqx "# $marker" "$unit_path" && ! grep -Fqx "$marker" "$unit_path"; then
    echo "$unit_path exists but is not a Lanpanel-managed service for app $app_name; refusing to remove it" >&2
    exit 1
fi

systemctl disable --now "$unit"
rm -f -- "$unit_path"
printf '%s\n' "$unit_path"`
	return host.Command{
		Name:        "sh",
		Args:        []string{"-c", script, "lanpanel-app-remove-stale-service", names.ServiceUnit, unitPath, names.AppName},
		DisplayName: "remove-stale-app-service",
		DisplayArgs: []string{unitPath},
	}
}
