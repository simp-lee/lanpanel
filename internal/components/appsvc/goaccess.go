package appsvc

import (
	"fmt"
	"lanpanel/internal/host"
	"strings"
)

func GuardGoAccessSystemUserCommand(names Names) host.Command {
	return guardSystemUserCommand(names.GoAccessSystemUser, names.GoAccessReportDir, "lanpanel-app-goaccess-user-guard", "guard-goaccess-user")
}

func EnsureGoAccessSystemUserCommands(names Names) []host.Command {
	return []host.Command{ensureSystemUserCommand(names.GoAccessSystemUser, names.GoAccessReportDir, "lanpanel-app-goaccess-user", "ensure-goaccess-user")}
}

func GuardGoAccessLogDirectoryCommand(names Names) host.Command {
	script := `set -eu
app_name=$1
dir=$2
marker=$3
expected_marker="Lanpanel-managed: app.name=$app_name"

fail() {
    echo "$1" >&2
    exit 1
}

guard_safe_parent() {
    parent=$1
    if [ -L "$parent" ]; then
        fail "$parent is a symlink; refusing to use it as a Lanpanel app log parent"
    fi
    if [ -e "$parent" ] && [ ! -d "$parent" ]; then
        fail "$parent exists and is not a directory; refusing to use it as a Lanpanel app log parent"
    fi
    if [ ! -e "$parent" ]; then
        return
    fi
    if [ "$(stat -c %u "$parent")" != "0" ]; then
        fail "GoAccess log parent $parent must be owned by root"
    fi
    writable=$(find "$parent" -maxdepth 0 \( -perm -020 -o -perm -002 \) -print -quit) || fail "failed to inspect GoAccess log parent $parent permissions"
    if [ -n "$writable" ]; then
        fail "GoAccess log parent $parent must not be writable by group or others"
    fi
    searchable=$(find "$parent" -maxdepth 0 ! -perm -001 -print -quit) || fail "failed to inspect GoAccess log parent $parent search permissions"
    if [ -n "$searchable" ]; then
        fail "GoAccess log parent $parent must be searchable by others"
    fi
}

lanpanel_log_root=$(dirname "$(dirname "$dir")")
apps_log_root=$(dirname "$dir")
guard_safe_parent "$lanpanel_log_root"
guard_safe_parent "$apps_log_root"

if [ -L "$dir" ]; then
    fail "$dir is a symlink; refusing to use it as a Lanpanel app log root"
fi
if [ -e "$dir" ] && [ ! -d "$dir" ]; then
    fail "$dir exists and is not a directory; refusing to use it as a Lanpanel app log root"
fi
if [ ! -d "$dir" ]; then
    exit 0
fi
if [ "$(stat -c %u "$dir")" != "0" ]; then
    fail "GoAccess log directory $dir must be owned by root"
fi
writable=$(find "$dir" -maxdepth 0 \( -perm -020 -o -perm -002 \) -print -quit) || fail "failed to inspect GoAccess log directory $dir permissions"
if [ -n "$writable" ]; then
    fail "GoAccess log directory $dir must not be writable by group or others"
fi
if [ -L "$marker" ]; then
    fail "$marker is a symlink; refusing to trust GoAccess log ownership"
fi
if [ ! -e "$marker" ]; then
    fail "$dir exists without $marker; refusing to write into a non-Lanpanel log root"
fi
if [ ! -f "$marker" ]; then
    fail "$marker is not a regular file; refusing to trust GoAccess log ownership"
fi
if [ "$(stat -c %u "$marker")" != "0" ]; then
    fail "GoAccess log marker $marker must be owned by root"
fi
writable=$(find "$marker" -maxdepth 0 \( -perm -020 -o -perm -002 \) -print -quit) || fail "failed to inspect GoAccess log marker $marker permissions"
if [ -n "$writable" ]; then
    fail "GoAccess log marker $marker must not be writable by group or others"
fi
actual_marker=$(cat "$marker")
if [ "$actual_marker" != "$expected_marker" ]; then
    fail "$dir is managed by a different Lanpanel app; refusing to write into it"
fi`
	return host.Command{
		Name:        "sh",
		Args:        []string{"-c", script, "lanpanel-app-goaccess-log-guard", names.AppName, names.GoAccessLogDir, names.GoAccessLogDirMarkerPath},
		DisplayName: "guard-goaccess-log-directory",
		DisplayArgs: []string{names.GoAccessLogDir},
	}
}

func EnsureGoAccessDirectoryCommands(names Names, managedLog bool) []host.Command {
	commands := []host.Command{
		ensureGoAccessReportDirectoryCommand(names),
		ensureGoAccessDBDirectoryCommand(names),
		ensureGoAccessReportFileCommand(names),
	}
	if managedLog {
		script := `set -eu
app_name=$1
log_dir=$2
marker=$3
log_file=$4
goaccess_group=$5
expected_marker="Lanpanel-managed: app.name=$app_name"

fail() {
    echo "$1" >&2
    exit 1
}

ensure_safe_parent() {
    parent=$1
    if [ -L "$parent" ]; then
        fail "$parent is a symlink; refusing to use it as a Lanpanel app log parent"
    fi
    if [ -e "$parent" ] && [ ! -d "$parent" ]; then
        fail "$parent exists and is not a directory; refusing to use it as a Lanpanel app log parent"
    fi
    if [ ! -e "$parent" ]; then
        install -d -m 0755 -o root -g root "$parent"
    fi
    if [ "$(stat -c %u "$parent")" != "0" ]; then
        fail "GoAccess log parent $parent must be owned by root"
    fi
    writable=$(find "$parent" -maxdepth 0 \( -perm -020 -o -perm -002 \) -print -quit) || fail "failed to inspect GoAccess log parent $parent permissions"
    if [ -n "$writable" ]; then
        fail "GoAccess log parent $parent must not be writable by group or others"
    fi
    searchable=$(find "$parent" -maxdepth 0 ! -perm -001 -print -quit) || fail "failed to inspect GoAccess log parent $parent search permissions"
    if [ -n "$searchable" ]; then
        fail "GoAccess log parent $parent must be searchable by others"
    fi
}

lanpanel_log_root=$(dirname "$(dirname "$log_dir")")
apps_log_root=$(dirname "$log_dir")
ensure_safe_parent "$lanpanel_log_root"
ensure_safe_parent "$apps_log_root"

created_dir=0
if [ -L "$log_dir" ]; then
    fail "$log_dir is a symlink; refusing to use it as a Lanpanel app log root"
fi
if [ -e "$log_dir" ] && [ ! -d "$log_dir" ]; then
    fail "$log_dir exists and is not a directory; refusing to use it as a Lanpanel app log root"
fi
if [ ! -e "$log_dir" ]; then
    install -d -m 0751 -o root -g root "$log_dir"
    created_dir=1
fi
if [ "$(stat -c %u "$log_dir")" != "0" ]; then
    fail "GoAccess log directory $log_dir must be owned by root"
fi
writable=$(find "$log_dir" -maxdepth 0 \( -perm -020 -o -perm -002 \) -print -quit) || fail "failed to inspect GoAccess log directory $log_dir permissions"
if [ -n "$writable" ]; then
    fail "GoAccess log directory $log_dir must not be writable by group or others"
fi
if [ -L "$marker" ]; then
    fail "$marker is a symlink; refusing to trust GoAccess log ownership"
fi
if [ ! -e "$marker" ] && [ "$created_dir" -ne 1 ]; then
    fail "$log_dir exists without $marker; refusing to write into a non-Lanpanel log root"
fi
if [ -e "$marker" ] && [ ! -f "$marker" ]; then
    fail "$marker is not a regular file; refusing to trust GoAccess log ownership"
fi
if [ -f "$marker" ]; then
    if [ "$(stat -c %u "$marker")" != "0" ]; then
        fail "GoAccess log marker $marker must be owned by root"
    fi
    writable=$(find "$marker" -maxdepth 0 \( -perm -020 -o -perm -002 \) -print -quit) || fail "failed to inspect GoAccess log marker $marker permissions"
    if [ -n "$writable" ]; then
        fail "GoAccess log marker $marker must not be writable by group or others"
    fi
    actual_marker=$(cat "$marker")
    if [ "$actual_marker" != "$expected_marker" ]; then
        fail "$log_dir is managed by a different Lanpanel app; refusing to write into it"
    fi
fi
if [ ! -e "$marker" ]; then
    tmp=$(mktemp "$log_dir/.lanpanel-managed.XXXXXX")
    trap 'rm -f "$tmp"' EXIT INT TERM
    printf '%s\n' "$expected_marker" > "$tmp"
    chmod 0644 "$tmp"
    chown root:root "$tmp"
    mv "$tmp" "$marker"
    trap - EXIT INT TERM
fi
if [ -L "$log_file" ]; then
    fail "GoAccess canonical access log must not be a symlink: $log_file"
fi
if [ -e "$log_file" ] && [ ! -f "$log_file" ]; then
    fail "GoAccess canonical access log must be a regular file: $log_file"
fi
if [ ! -e "$log_file" ]; then
    install -m 0640 -o www-data -g "$goaccess_group" /dev/null "$log_file"
fi
chown root:root "$log_dir"
chmod 0751 "$log_dir"
chown www-data:"$goaccess_group" "$log_file"
chmod 0640 "$log_file"`
		commands = append(commands, host.Command{
			Name:        "sh",
			Args:        []string{"-c", script, "lanpanel-app-goaccess-log-dir", names.AppName, names.GoAccessLogDir, names.GoAccessLogDirMarkerPath, names.GoAccessCanonicalAccessLogPath, names.GoAccessSystemGroup},
			DisplayName: "ensure-goaccess-log-directory",
			DisplayArgs: []string{names.GoAccessLogDir},
		})
	}
	return commands
}

func ensureGoAccessReportDirectoryCommand(names Names) host.Command {
	script := `set -eu
report_dir=$1

fail() {
    echo "$1" >&2
    exit 1
}

if [ -L "$report_dir" ]; then
    fail "GoAccess report directory must not be a symlink: $report_dir"
fi
if [ -e "$report_dir" ] && [ ! -d "$report_dir" ]; then
    fail "GoAccess report directory must be a directory: $report_dir"
fi
if [ ! -e "$report_dir" ]; then
    install -d -m 0755 -o root -g root "$report_dir"
fi
chown root:root "$report_dir"
chmod 0755 "$report_dir"`
	return host.Command{
		Name:        "sh",
		Args:        []string{"-c", script, "lanpanel-app-goaccess-report-dir", names.GoAccessReportDir},
		DisplayName: "ensure-goaccess-report-directory",
		DisplayArgs: []string{names.GoAccessReportDir},
	}
}

func ensureGoAccessDBDirectoryCommand(names Names) host.Command {
	script := `set -eu
db_dir=$1
goaccess_user=$2
goaccess_group=$3

fail() {
    echo "$1" >&2
    exit 1
}

if [ -L "$db_dir" ]; then
    fail "GoAccess db directory must not be a symlink: $db_dir"
fi
if [ -e "$db_dir" ] && [ ! -d "$db_dir" ]; then
    fail "GoAccess db directory must be a directory: $db_dir"
fi
if [ ! -e "$db_dir" ]; then
    install -d -m 0750 -o "$goaccess_user" -g "$goaccess_group" "$db_dir"
fi
chown "$goaccess_user:$goaccess_group" "$db_dir"
chmod 0750 "$db_dir"`
	return host.Command{
		Name:        "sh",
		Args:        []string{"-c", script, "lanpanel-app-goaccess-db-dir", names.GoAccessDBPath, names.GoAccessSystemUser, names.GoAccessSystemGroup},
		DisplayName: "ensure-goaccess-db-directory",
		DisplayArgs: []string{names.GoAccessDBPath},
	}
}

func ensureGoAccessReportFileCommand(names Names) host.Command {
	script := `set -eu
report_file=$1
goaccess_user=$2
nginx_group=$3

fail() {
    echo "$1" >&2
    exit 1
}

if [ -L "$report_file" ]; then
    fail "GoAccess report file must not be a symlink: $report_file"
fi
if [ -e "$report_file" ] && [ ! -f "$report_file" ]; then
    fail "GoAccess report file must be a regular file: $report_file"
fi
if [ ! -e "$report_file" ]; then
    install -m 0640 -o "$goaccess_user" -g "$nginx_group" /dev/null "$report_file"
fi
chown "$goaccess_user:$nginx_group" "$report_file"
chmod 0640 "$report_file"`
	return host.Command{
		Name:        "sh",
		Args:        []string{"-c", script, "lanpanel-app-goaccess-report-file", names.GoAccessReportPath, names.GoAccessSystemUser, "www-data"},
		DisplayName: "ensure-goaccess-report-file",
		DisplayArgs: []string{names.GoAccessReportPath},
	}
}

func GuardGoAccessAuthFileCommand(names Names, authFile string) host.Command {
	script := authFileMetadataGuardScript("nginx.goaccess.auth_basic_user_file") + `
	nginx_user=${2:-www-data}

if ! command -v runuser >/dev/null 2>&1; then
    fail "runuser is required to verify nginx.goaccess.auth_basic_user_file readability"
fi
if ! getent passwd "$nginx_user" >/dev/null 2>&1; then
    fail "nginx runtime user $nginx_user does not exist"
fi
if ! runuser -u "$nginx_user" -- test -r "$auth_file"; then
    fail "nginx runtime user $nginx_user cannot read nginx.goaccess.auth_basic_user_file"
fi`
	return host.Command{
		Name:        "sh",
		Args:        []string{"-c", script, "lanpanel-app-goaccess-auth-file", strings.TrimSpace(authFile), "www-data"},
		DisplayName: "guard-goaccess-auth-file",
		DisplayArgs: []string{strings.TrimSpace(authFile)},
	}
}

func GuardGoAccessAuthFileMetadataCommand(names Names, authFile string) host.Command {
	return host.Command{
		Name:        "sh",
		Args:        []string{"-c", authFileMetadataGuardScript("nginx.goaccess.auth_basic_user_file"), "lanpanel-app-goaccess-auth-file-metadata", strings.TrimSpace(authFile)},
		DisplayName: "guard-goaccess-auth-file-metadata",
		DisplayArgs: []string{strings.TrimSpace(authFile)},
	}
}

func GuardBrowserAuthFileCommand(names Names, authFile string) host.Command {
	script := authFileMetadataGuardScript("access.browser_auth htpasswd file") + `
nginx_user=${2:-www-data}

if ! command -v runuser >/dev/null 2>&1; then
    fail "runuser is required to verify access.browser_auth htpasswd file readability"
fi
if ! getent passwd "$nginx_user" >/dev/null 2>&1; then
    fail "nginx runtime user $nginx_user does not exist"
fi
if ! runuser -u "$nginx_user" -- test -r "$auth_file"; then
    fail "nginx runtime user $nginx_user cannot read access.browser_auth htpasswd file"
fi`
	return host.Command{
		Name:        "sh",
		Args:        []string{"-c", script, "lanpanel-app-browser-auth-file", strings.TrimSpace(authFile), "www-data"},
		DisplayName: "guard-browser-auth-file",
		DisplayArgs: []string{strings.TrimSpace(authFile)},
	}
}

func GuardManagedBrowserAuthFileCommand(names Names, authFile string) host.Command {
	script := authFileMetadataGuardScript("access.browser_auth managed htpasswd file") + `
if ! awk '
    NR == 1 && $0 == "# LanPanel-managed browser-auth" { marker = 1; next }
    /^[[:space:]]*($|#)/ { next }
    {
        count++
        if ($0 !~ /^[^:[:space:]][^:[:space:]]*:\$2[aby]\$(1[2-9]|[2-9][0-9])\$[.\/A-Za-z0-9]{53}$/) {
            bad = 1
        }
    }
    END { exit marker && count == 1 && !bad ? 0 : 1 }
' "$auth_file"; then
    fail "access.browser_auth managed htpasswd file must keep the LanPanel marker and exactly one bcrypt credential with cost at least 12"
fi`
	return host.Command{
		Name:        "sh",
		Args:        []string{"-c", script, "lanpanel-app-managed-browser-auth-file", strings.TrimSpace(authFile)},
		DisplayName: "guard-managed-browser-auth-file",
		DisplayArgs: []string{strings.TrimSpace(authFile)},
	}
}

func authFileMetadataGuardScript(label string) string {
	return fmt.Sprintf(`set -eu
auth_file=$1

fail() {
    echo "$1" >&2
    exit 1
}

if [ -L "$auth_file" ]; then
    fail "%[1]s must not be a symlink"
fi
if [ ! -f "$auth_file" ]; then
    fail "%[1]s must be a regular file"
fi
if [ ! -s "$auth_file" ]; then
    fail "%[1]s must not be empty"
fi
if ! awk '
    /^[[:space:]]*($|#)/ { next }
    /^[^:[:space:]][^:[:space:]]*:[^[:space:]][^[:space:]]*$/ { found = 1 }
    END { exit found ? 0 : 1 }
' "$auth_file"; then
    fail "%[1]s must contain at least one user:hash credential line"
fi
if [ "$(stat -c %%u "$auth_file")" != "0" ]; then
    fail "%[1]s must be owned by root"
fi
unsafe_mode=$(find "$auth_file" -maxdepth 0 \( -perm -020 -o -perm -004 -o -perm -002 -o -perm -001 \) -print -quit) || fail "failed to inspect %[1]s permissions"
if [ -n "$unsafe_mode" ]; then
    fail "%[1]s must not be group-writable or accessible by others"
fi
dir=$(dirname "$auth_file")
while :; do
    if [ -L "$dir" ]; then
        fail "%[1]s parent directory $dir must not be a symlink"
    fi
    if [ ! -d "$dir" ]; then
        fail "%[1]s parent path $dir must be a directory"
    fi
    if [ "$(stat -c %%u "$dir")" != "0" ]; then
        fail "%[1]s parent directory $dir must be owned by root"
    fi
    writable=$(find "$dir" -maxdepth 0 \( -perm -020 -o -perm -002 \) -print -quit) || fail "failed to inspect %[1]s parent directory $dir permissions"
    if [ -n "$writable" ]; then
        fail "%[1]s parent directory $dir must not be writable by group or others"
    fi
    parent=$(dirname "$dir")
    if [ "$parent" = "$dir" ]; then
        break
    fi
    dir=$parent
done`, label)
}

func GuardGoAccessCanonicalLogReadableCommand(names Names) host.Command {
	script := `set -eu
user=$1
log_file=$2

fail() {
    echo "$1" >&2
    exit 1
}

if [ -L "$log_file" ]; then
    fail "GoAccess canonical access log must not be a symlink"
fi
if [ ! -f "$log_file" ]; then
    fail "GoAccess canonical access log must be a regular file: $log_file"
fi
owner_uid=$(stat -c %u "$log_file")
if [ "$owner_uid" != "0" ] && [ "$owner_uid" != "33" ]; then
    fail "GoAccess canonical access log must be owned by root or www-data: $log_file"
fi
dir=$(dirname "$log_file")
while :; do
    if [ -L "$dir" ]; then
        fail "GoAccess canonical access log parent directory $dir must not be a symlink"
    fi
    if [ ! -d "$dir" ]; then
        fail "GoAccess canonical access log parent path $dir must be a directory"
    fi
    if [ "$(stat -c %u "$dir")" != "0" ]; then
        fail "GoAccess canonical access log parent directory $dir must be owned by root"
    fi
    writable=$(find "$dir" -maxdepth 0 \( -perm -020 -o -perm -002 \) -print -quit) || fail "failed to inspect GoAccess canonical access log parent directory $dir permissions"
    if [ -n "$writable" ]; then
        fail "GoAccess canonical access log parent directory $dir must not be writable by group or others"
    fi
    parent=$(dirname "$dir")
    if [ "$parent" = "$dir" ]; then
        break
    fi
    dir=$parent
done
writable=$(find "$log_file" -maxdepth 0 \( -perm -020 -o -perm -002 \) -print -quit) || fail "failed to inspect GoAccess canonical access log permissions"
if [ -n "$writable" ]; then
    fail "GoAccess canonical access log must not be writable by group or others"
fi
if ! command -v runuser >/dev/null 2>&1; then
    fail "runuser is required to verify GoAccess log readability"
fi
if ! runuser -u "$user" -- test -r "$log_file"; then
    fail "GoAccess user $user cannot read canonical access log $log_file"
fi`
	return host.Command{
		Name:        "sh",
		Args:        []string{"-c", script, "lanpanel-app-goaccess-log-readable", names.GoAccessSystemUser, names.GoAccessCanonicalAccessLogPath},
		DisplayName: "guard-goaccess-log-readable",
		DisplayArgs: []string{names.GoAccessCanonicalAccessLogPath},
	}
}

func GuardManagedGoAccessCanonicalLogReadableCommand(names Names) host.Command {
	script := `set -eu
user=$1
log_file=$2

fail() {
    echo "$1" >&2
    exit 1
}

if [ -L "$log_file" ]; then
    fail "GoAccess canonical access log must not be a symlink"
fi
if [ ! -f "$log_file" ]; then
    fail "GoAccess canonical access log must be a regular file: $log_file"
fi
writable=$(find "$log_file" -maxdepth 0 \( -perm -020 -o -perm -002 \) -print -quit) || fail "failed to inspect GoAccess canonical access log permissions"
if [ -n "$writable" ]; then
    fail "GoAccess canonical access log must not be writable by group or others"
fi
if ! command -v runuser >/dev/null 2>&1; then
    fail "runuser is required to verify GoAccess log readability"
fi
if ! runuser -u "$user" -- test -r "$log_file"; then
    fail "GoAccess user $user cannot read canonical access log $log_file"
fi`
	return host.Command{
		Name:        "sh",
		Args:        []string{"-c", script, "lanpanel-app-goaccess-managed-log-readable", names.GoAccessSystemUser, names.GoAccessCanonicalAccessLogPath},
		DisplayName: "guard-goaccess-managed-log-readable",
		DisplayArgs: []string{names.GoAccessCanonicalAccessLogPath},
	}
}

func GuardGoAccessRuntimeAccessCommand(names Names) host.Command {
	script := `set -eu
goaccess_user=$1
goaccess_group=$2
nginx_user=$3
config_file=$4
report_dir=$5
db_path=$6
report_file=$7

fail() {
    echo "$1" >&2
    exit 1
}

guard_root_owned_safe_parents() {
    path=$1
    label=$2
    dir=$(dirname "$path")
    while :; do
        if [ -L "$dir" ]; then
            fail "$label parent directory $dir must not be a symlink"
        fi
        if [ ! -d "$dir" ]; then
            fail "$label parent path $dir must be a directory"
        fi
        if [ "$(stat -c %u "$dir")" != "0" ]; then
            fail "$label parent directory $dir must be owned by root"
        fi
        writable=$(find "$dir" -maxdepth 0 \( -perm -020 -o -perm -002 \) -print -quit) || fail "failed to inspect $label parent directory $dir permissions"
        if [ -n "$writable" ]; then
            fail "$label parent directory $dir must not be writable by group or others"
        fi
        parent=$(dirname "$dir")
        if [ "$parent" = "$dir" ]; then
            break
        fi
        dir=$parent
    done
}

if ! command -v runuser >/dev/null 2>&1; then
    fail "runuser is required to verify GoAccess runtime permissions"
fi
if ! getent passwd "$goaccess_user" >/dev/null 2>&1; then
    fail "GoAccess runtime user $goaccess_user does not exist"
fi
if ! getent passwd "$nginx_user" >/dev/null 2>&1; then
    fail "Nginx runtime user $nginx_user does not exist"
fi
if [ -L "$config_file" ]; then
    fail "GoAccess config file must not be a symlink: $config_file"
fi
if [ ! -f "$config_file" ]; then
    fail "GoAccess config file must be a regular file: $config_file"
fi
if [ "$(stat -c %u "$config_file")" != "0" ]; then
    fail "GoAccess config file must be owned by root: $config_file"
fi
config_mode=$(stat -c %a "$config_file")
if [ "$config_mode" != "644" ]; then
    fail "GoAccess config file must have mode 0644: $config_file"
fi
guard_root_owned_safe_parents "$config_file" "GoAccess config file"
if ! runuser -u "$goaccess_user" -- test -r "$config_file"; then
    fail "GoAccess runtime user $goaccess_user cannot read config file $config_file"
fi
if [ -L "$report_dir" ]; then
    fail "GoAccess report directory must not be a symlink: $report_dir"
fi
if [ ! -d "$report_dir" ]; then
    fail "GoAccess report directory must be a directory: $report_dir"
fi
report_dir_owner=$(stat -c %U:%G "$report_dir")
if [ "$report_dir_owner" != "root:root" ]; then
    fail "GoAccess report directory must be owned by root:root: $report_dir"
fi
report_dir_mode=$(stat -c %a "$report_dir")
if [ "$report_dir_mode" != "755" ]; then
    fail "GoAccess report directory must have mode 0755: $report_dir"
fi
if runuser -u "$goaccess_user" -- test -w "$report_dir"; then
    fail "GoAccess runtime user $goaccess_user must not be able to write report directory $report_dir"
fi
if ! runuser -u "$nginx_user" -- test -r "$report_dir"; then
    fail "Nginx runtime user $nginx_user cannot read GoAccess report directory $report_dir"
fi
if ! runuser -u "$nginx_user" -- test -x "$report_dir"; then
    fail "Nginx runtime user $nginx_user cannot search GoAccess report directory $report_dir"
fi
if [ -L "$db_path" ]; then
    fail "GoAccess db path must not be a symlink: $db_path"
fi
if [ ! -d "$db_path" ]; then
    fail "GoAccess db path must be a directory: $db_path"
fi
db_owner=$(stat -c %U:%G "$db_path")
if [ "$db_owner" != "$goaccess_user:$goaccess_group" ]; then
    fail "GoAccess db path must be owned by $goaccess_user:$goaccess_group: $db_path"
fi
db_mode=$(stat -c %a "$db_path")
if [ "$db_mode" != "750" ]; then
    fail "GoAccess db path must have mode 0750: $db_path"
fi
if ! runuser -u "$goaccess_user" -- test -w "$db_path"; then
    fail "GoAccess runtime user $goaccess_user cannot write db path $db_path"
fi
if [ -L "$report_file" ]; then
    fail "GoAccess report file must not be a symlink: $report_file"
fi
if [ ! -f "$report_file" ]; then
    fail "GoAccess report file must be a regular file: $report_file"
fi
report_file_owner=$(stat -c %U:%G "$report_file")
if [ "$report_file_owner" != "$goaccess_user:$nginx_user" ]; then
    fail "GoAccess report file must be owned by $goaccess_user:$nginx_user: $report_file"
fi
report_file_mode=$(stat -c %a "$report_file")
if [ "$report_file_mode" != "640" ]; then
    fail "GoAccess report file must have mode 0640: $report_file"
fi
if ! runuser -u "$goaccess_user" -- test -w "$report_file"; then
    fail "GoAccess runtime user $goaccess_user cannot write report file $report_file"
fi
if ! runuser -u "$nginx_user" -- test -r "$report_file"; then
    fail "Nginx runtime user $nginx_user cannot read GoAccess report file $report_file"
fi`
	return host.Command{
		Name: "sh",
		Args: []string{
			"-c", script, "lanpanel-app-goaccess-runtime-access",
			names.GoAccessSystemUser, names.GoAccessSystemGroup, "www-data", names.GoAccessConfigPath,
			names.GoAccessReportDir, names.GoAccessDBPath, names.GoAccessReportPath,
		},
		DisplayName: "guard-goaccess-runtime-access",
		DisplayArgs: []string{names.GoAccessConfigPath, names.GoAccessReportDir, names.GoAccessDBPath, names.GoAccessReportPath},
	}
}

func RemoveManagedGoAccessLogrotateCommand(names Names) host.Command {
	script := managedGoAccessLogrotateRemovalGuardScript() + `
rm -f -- "$logrotate_path"
printf '%s\n' "$logrotate_path"`
	return host.Command{
		Name:        "sh",
		Args:        []string{"-c", script, "lanpanel-app-remove-goaccess-logrotate", names.GoAccessLogrotatePath, names.AppName},
		DisplayName: "remove-stale-goaccess-logrotate",
		DisplayArgs: []string{names.GoAccessLogrotatePath},
	}
}

func GuardManagedGoAccessLogrotateRemovalCommand(names Names) host.Command {
	return host.Command{
		Name:        "sh",
		Args:        []string{"-c", managedGoAccessLogrotateRemovalGuardScript(), "lanpanel-app-guard-goaccess-logrotate-removal", names.GoAccessLogrotatePath, names.AppName},
		DisplayName: "guard-stale-goaccess-logrotate",
		DisplayArgs: []string{names.GoAccessLogrotatePath},
	}
}

func managedGoAccessLogrotateRemovalGuardScript() string {
	return `set -eu
logrotate_path=$1
app_name=$2
marker="Lanpanel-managed: app.name=$app_name"

fail() {
    echo "$1" >&2
    exit 1
}

managed_marker_matches() {
    path=$1
    found=0
    while IFS= read -r line || [ -n "$line" ]; do
        normalized=${line#"#"}
        normalized=$(printf '%s' "$normalized" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
        case "$normalized" in
            Lanpanel-managed:*)
                if [ "$normalized" != "$marker" ]; then
                    return 1
                fi
                found=1
                ;;
        esac
    done < "$path"
    [ "$found" -eq 1 ]
}

if [ -L "$logrotate_path" ]; then
    fail "$logrotate_path is a symlink; refusing to remove it as Lanpanel-managed GoAccess logrotate"
fi
if [ ! -e "$logrotate_path" ]; then
    exit 0
fi
if [ ! -f "$logrotate_path" ]; then
    fail "$logrotate_path is not a regular file; refusing to remove it as Lanpanel-managed GoAccess logrotate"
fi
if ! managed_marker_matches "$logrotate_path"; then
    fail "$logrotate_path exists but is not a Lanpanel-managed GoAccess logrotate file for app $app_name; refusing to remove it"
fi`
}

func RemoveManagedGoAccessRuntimeCommand(names Names) host.Command {
	unitPath := "/etc/systemd/system/" + names.GoAccessServiceUnit
	return removeManagedGoAccessRuntimeCommand(names, unitPath)
}

func GuardManagedGoAccessRuntimeRemovalCommand(names Names) host.Command {
	unitPath := "/etc/systemd/system/" + names.GoAccessServiceUnit
	return guardManagedGoAccessRuntimeRemovalCommand(names, unitPath)
}

func guardManagedGoAccessRuntimeRemovalCommand(names Names, unitPath string) host.Command {
	return host.Command{
		Name:        "sh",
		Args:        []string{"-c", managedGoAccessRuntimeRemovalGuardScript(), "lanpanel-app-guard-goaccess-runtime-removal", names.GoAccessServiceUnit, unitPath, names.GoAccessConfigPath, names.GoAccessLogrotatePath, names.AppName},
		DisplayName: "guard-stale-goaccess-runtime",
		DisplayArgs: []string{unitPath, names.GoAccessConfigPath, names.GoAccessLogrotatePath},
	}
}

func removeManagedGoAccessRuntimeCommand(names Names, unitPath string) host.Command {
	script := managedGoAccessRuntimeRemovalGuardScript() + `
if is_managed_file "$unit_path"; then
    systemctl disable --now "$unit"
    rm -f -- "$unit_path"
    printf '%s\n' "$unit_path"
fi
if is_managed_file "$config_path"; then
    rm -f -- "$config_path"
    printf '%s\n' "$config_path"
fi
if is_managed_file "$logrotate_path"; then
    rm -f -- "$logrotate_path"
    printf '%s\n' "$logrotate_path"
fi`
	return host.Command{
		Name:        "sh",
		Args:        []string{"-c", script, "lanpanel-app-remove-goaccess-runtime", names.GoAccessServiceUnit, unitPath, names.GoAccessConfigPath, names.GoAccessLogrotatePath, names.AppName},
		DisplayName: "remove-stale-goaccess-runtime",
		DisplayArgs: []string{unitPath, names.GoAccessConfigPath, names.GoAccessLogrotatePath},
	}
}

func managedGoAccessRuntimeRemovalGuardScript() string {
	return `set -eu
unit=$1
unit_path=$2
config_path=$3
logrotate_path=$4
app_name=$5
marker="Lanpanel-managed: app.name=$app_name"

managed_marker_matches() {
    path=$1
    found=0
    while IFS= read -r line || [ -n "$line" ]; do
        normalized=${line#"#"}
        normalized=$(printf '%s' "$normalized" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
        case "$normalized" in
            Lanpanel-managed:*)
                if [ "$normalized" != "$marker" ]; then
                    return 1
                fi
                found=1
                ;;
        esac
    done < "$path"
    [ "$found" -eq 1 ]
}

is_managed_file() {
    path=$1
    if [ -L "$path" ]; then
        return 1
    fi
    if [ ! -e "$path" ]; then
        return 1
    fi
    if [ ! -f "$path" ]; then
        return 1
    fi
    managed_marker_matches "$path"
}

guard_removable_candidate() {
    path=$1
    label=$2
    if [ -L "$path" ]; then
        echo "$path is a symlink; refusing to remove it as Lanpanel-managed GoAccess $label" >&2
        exit 1
    fi
    if [ ! -e "$path" ]; then
        return
    fi
    if [ ! -f "$path" ]; then
        echo "$path is not a regular file; refusing to remove it as Lanpanel-managed GoAccess $label" >&2
        exit 1
    fi
    if ! is_managed_file "$path"; then
        echo "$path exists but is not a Lanpanel-managed GoAccess $label for app $app_name; refusing to remove it" >&2
        exit 1
    fi
}

guard_removable_candidate "$unit_path" "service unit"
guard_removable_candidate "$config_path" "config"
guard_removable_candidate "$logrotate_path" "logrotate"`
}
