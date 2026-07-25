package appsvc

import (
	"errors"
	"fmt"
	"lanpanel/internal/appconfig"
	"lanpanel/internal/host"
	"strconv"
	"strings"
)

const NginxBinaryPath = "/usr/sbin/nginx"

func EnableSiteCommand(names Names) host.Command {
	return host.Command{Name: "ln", Args: []string{"-sfn", names.NginxAvailablePath, names.NginxEnabledPath}}
}

func GuardEnabledSiteCommand(names Names) host.Command {
	script := `set -eu
enabled=$1
expected=$2
if [ ! -e "$enabled" ] && [ ! -L "$enabled" ]; then
    exit 0
fi
if [ -L "$enabled" ]; then
    target=$(readlink "$enabled")
    if [ "$target" = "$expected" ]; then
        exit 0
    fi
    printf '%s\n' "$enabled exists as a symlink to $target, not $expected; refusing to replace it" >&2
    exit 1
fi
printf '%s\n' "$enabled exists and is not a Lanpanel-managed app symlink; refusing to replace it" >&2
exit 1`
	return host.Command{
		Name:        "sh",
		Args:        []string{"-c", script, "lanpanel-app-nginx-enabled-guard", names.NginxEnabledPath, names.NginxAvailablePath},
		DisplayName: "guard-nginx-enabled-site",
		DisplayArgs: []string{names.NginxEnabledPath},
	}
}

func GuardServerNameConflictsCommand(names Names, domains []string) host.Command {
	return guardServerNameConflictsCommand(names.NginxEnabledPath, names.NginxAvailablePath, domains)
}

func GuardRealIPConflictsCommand(names Names, realIPNames RealIPProfileNames) host.Command {
	script := `set -eu
nginx_binary=$1
current_enabled=$2
current_available=$3
managed_realip_dir=$4
app_name=$5
managed_realip_root=$(dirname "$managed_realip_dir")
dump=$(mktemp)
trap 'rm -f "$dump"' EXIT INT TERM

if ! "$nginx_binary" -T > "$dump" 2>&1; then
    cat "$dump" >&2
    exit 1
fi

awk -v current_enabled="$current_enabled" -v current_available="$current_available" -v managed_realip_root="$managed_realip_root" -v app_marker="Lanpanel-managed: app.name=$app_name" '
    function count_char(text, char,    count, i) {
        count = 0
        for (i = 1; i <= length(text); i++) {
            if (substr(text, i, 1) == char) count++
        }
        return count
    }
    function starts_server_block(text,    normalized) {
        normalized = text
        gsub(/[ \t\r\n]+/, " ", normalized)
        return normalized ~ /^[ \t]*server[ \t]*\{/
    }
    function is_server_token(text,    normalized) {
        normalized = text
        gsub(/^[ \t]+|[ \t]+$/, "", normalized)
        return normalized == "server"
    }
    function starts_pending_server_block(text,    normalized) {
        normalized = text
        gsub(/^[ \t]+|[ \t]+$/, "", normalized)
        return pending_server && normalized ~ /^\{/
    }
	    /^# configuration file / {
	        current_file = $0
	        sub(/^# configuration file /, "", current_file)
	        sub(/:$/, "", current_file)
	        current_file_managed_realip = managed_realip_files[current_file]
	        current_file_managed_app = managed_app_files[current_file]
	        pending_server = 0
	        next
	    }
    index(current_file, managed_realip_root "/") == 1 && index($0, "Lanpanel-managed: realip.profile=") > 0 {
        current_file_managed_realip = 1
        managed_realip_files[current_file] = 1
        next
    }
    index($0, app_marker) > 0 {
        current_file_managed_app = 1
        managed_app_files[current_file] = 1
        next
    }
    {
        line = $0
        sub(/[ \t]*#.*/, "", line)
        if (server_depth == 0 && is_server_token(line)) {
            pending_server = 1
        } else if (server_depth == 0 && (starts_server_block(line) || starts_pending_server_block(line))) {
            server_depth = depth + count_char(line, "{")
            pending_server = 0
        } else if (line !~ /^[ \t]*$/) {
            pending_server = 0
        }
        if (line !~ /(^|[ \t;{])(real_ip_header|set_real_ip_from|real_ip_recursive)([ \t;}]|$)/) {
            depth += count_char(line, "{") - count_char(line, "}")
            if (server_depth > 0 && depth < server_depth) {
                server_depth = 0
            }
            next
        }
        if (index(current_file, managed_realip_root "/") == 1 && current_file_managed_realip) {
            depth += count_char(line, "{") - count_char(line, "}")
            if (server_depth > 0 && depth < server_depth) {
                server_depth = 0
            }
            next
        }
        if (current_file == current_enabled || current_file == current_available) {
            normalized = line
            gsub(/^[ \t]+|[ \t]+$/, "", normalized)
            gsub(/[ \t]+/, " ", normalized)
            if (current_file_managed_app && normalized == "real_ip_header EO-Connecting-IP;") {
                depth += count_char(line, "{") - count_char(line, "}")
                if (server_depth > 0 && depth < server_depth) {
                    server_depth = 0
                }
                next
            }
        }
        if (server_depth > 0 && current_file != current_enabled && current_file != current_available) {
            depth += count_char(line, "{") - count_char(line, "}")
            if (server_depth > 0 && depth < server_depth) {
                server_depth = 0
            }
            next
        }
        printf "%s contains non-Lanpanel realip directive: %s\n", current_file, line > "/dev/stderr"
        found = 1
        depth += count_char(line, "{") - count_char(line, "}")
        if (server_depth > 0 && depth < server_depth) {
            server_depth = 0
        }
    }
    END { exit found ? 1 : 0 }
' "$dump"

scan_file() {
    file=$1
    [ -e "$file" ] || return 0
    if [ -L "$file" ]; then
        echo "$file is a symlink; refusing to inspect realip directives" >&2
        exit 1
    fi
    if [ ! -f "$file" ]; then
        echo "$file exists but is not a regular file; refusing to inspect realip directives" >&2
        exit 1
    fi
    case "$file" in
        "$managed_realip_root"/*)
            if grep -Fq "Lanpanel-managed: realip.profile=" "$file"; then
                return 0
            fi
            ;;
    esac

    managed_app=false
    if grep -Fq "Lanpanel-managed: app.name=$app_name" "$file"; then
        managed_app=true
    fi
    awk -v current_file="$file" -v managed_app="$managed_app" '
        {
            line = $0
            sub(/[ \t]*#.*/, "", line)
            if (line !~ /(^|[ \t;{])(real_ip_header|set_real_ip_from|real_ip_recursive)([ \t;}]|$)/) {
                next
            }
            normalized = line
            gsub(/^[ \t]+|[ \t]+$/, "", normalized)
            gsub(/[ \t]+/, " ", normalized)
            if (managed_app == "true" && normalized == "real_ip_header EO-Connecting-IP;") {
                next
            }
            printf "%s contains non-Lanpanel realip directive: %s\n", current_file, line > "/dev/stderr"
            found = 1
        }
        END { exit found ? 1 : 0 }
    ' "$file"

    include_paths=$(awk '
        {
            line = $0
            sub(/[ \t]*#.*/, "", line)
            count = split(line, directives, ";")
            trailing = directives[count]
            gsub(/^[ \t{}]+|[ \t{}]+$/, "", trailing)
            if (trailing ~ /(^|[{} \t])include([ \t]|$)/) {
                printf "%s contains multi-line include directive; refusing realip conflict scan\n", FILENAME > "/dev/stderr"
                found = 1
                next
            }
            for (i = 1; i < count; i++) {
                directive = directives[i]
                gsub(/^[ \t{}]+|[ \t{}]+$/, "", directive)
                if (directive ~ /^include[ \t]+/) {
                    sub(/^include[ \t]+/, "", directive)
                } else if (directive ~ /[{][ \t]*include[ \t]+/) {
                    sub(/^.*[{][ \t]*include[ \t]+/, "", directive)
                } else {
                    next
                }
                if (directive != "") {
                    gsub(/^[ \t]+|[ \t]+$/, "", directive)
                    print directive
                }
            }
        }
        END { exit found ? 1 : 0 }
    ' "$file")
    printf '%s\n' "$include_paths" | while IFS= read -r include_path; do
        [ -n "$include_path" ] || continue
        case "$include_path" in
            *'$'*|*'{'*|*'}'*)
                echo "$file contains dynamic include $include_path; refusing realip conflict scan" >&2
                exit 1
                ;;
            /*)
                ;;
            *)
                echo "$file contains non-absolute include $include_path; refusing realip conflict scan" >&2
                exit 1
                ;;
        esac
        for included in $include_path; do
            if [ ! -e "$included" ]; then
                echo "$file include $include_path did not match a file; refusing realip conflict scan" >&2
                exit 1
            fi
            scan_file "$included"
        done
    done
}

scan_file "$current_available"`
	return host.Command{
		Name:        "sh",
		Args:        []string{"-c", script, "lanpanel-app-realip-conflict-guard", NginxBinaryPath, strings.TrimSpace(names.NginxEnabledPath), strings.TrimSpace(names.NginxAvailablePath), strings.TrimSpace(realIPNames.NginxDir), strings.TrimSpace(names.AppName)},
		DisplayName: "guard-nginx-realip-conflicts",
		DisplayArgs: []string{realIPNames.ProfileName},
	}
}

func GuardGoAccessWebSocketPortAssignmentCommand(names Names) host.Command {
	script := `set -eu
nginx_binary=$1
current_enabled=$2
current_available=$3
target=$4
target_host=$5
target_port=$6
dump=$(mktemp)
trap 'rm -f "$dump"' EXIT INT TERM

if ! "$nginx_binary" -T > "$dump" 2>&1; then
    cat "$dump" >&2
    exit 1
fi

awk -v current_enabled="$current_enabled" -v current_available="$current_available" -v target="$target" -v target_host="$target_host" -v target_port="$target_port" '
    function init_targets() {
        proxy_targets["http://" target] = "http://" target
        upstream_server_targets[target] = "http://" target
        if ((target_host == "127.0.0.1" || target_host == "::1") && target_port != "") {
            proxy_targets["http://localhost:" target_port] = "http://localhost:" target_port
            upstream_server_targets["localhost:" target_port] = "http://localhost:" target_port
        }
    }
    function count_char(text, char,    count, i) {
        count = 0
        for (i = 1; i <= length(text); i++) {
            if (substr(text, i, 1) == char) count++
        }
        return count
    }
    function normalize_directive(text,    normalized) {
        normalized = text
        gsub(/[{};]/, " ", normalized)
        gsub(/[ \t\r\n]+/, " ", normalized)
        return " " normalized " "
    }
    function check_upstream_server(text,    normalized, tail, count, parts) {
        if (!in_upstream || upstream_name == "") {
            return
        }
        normalized = normalize_directive(text)
        while (match(normalized, /(^| )server /)) {
            tail = substr(normalized, RSTART + RLENGTH)
            count = split(tail, parts, /[ \t]+/)
            if (count > 0 && parts[1] in upstream_server_targets) {
                target_upstreams[upstream_name] = upstream_server_targets[parts[1]]
            }
            normalized = tail
        }
    }
    function reset_upstream_state() {
        in_upstream = 0
        pending_upstream_name = ""
        upstream_name = ""
        upstream_file = ""
        upstream_depth = 0
    }
    function start_upstream(name) {
        pending_upstream_name = ""
        upstream_name = name
        upstream_file = current_file
        upstream_depth = 0
        in_upstream = 1
    }
    function process_upstream_line(text,    header) {
        if (!in_upstream && pending_upstream_name != "") {
            if (text ~ /^[ \t]*$/) {
                return
            }
            if (match(text, /^[ \t]*\{/)) {
                start_upstream(pending_upstream_name)
            } else {
                pending_upstream_name = ""
            }
        }
        if (!in_upstream && match(text, /^[ \t]*upstream[ \t]+[A-Za-z0-9_.-]+[ \t]*(\{|$)/)) {
            header = substr(text, RSTART, RLENGTH)
            sub(/^[ \t]*upstream[ \t]+/, "", header)
            sub(/[ \t]*\{$/, "", header)
            sub(/[ \t]+$/, "", header)
            if (index(text, "{") > 0) {
                start_upstream(header)
            } else {
                pending_upstream_name = header
                return
            }
        }
        if (!in_upstream) {
            return
        }
        check_upstream_server(text)
        upstream_depth += count_char(text, "{") - count_char(text, "}")
        if (upstream_depth <= 0) {
            in_upstream = 0
            upstream_name = ""
            upstream_file = ""
        }
    }
    function check_proxy_target(normalized, proxy_target, label,    prefix, nextChar) {
        prefix = " proxy_pass " proxy_target
        if (index(normalized, prefix) == 0) {
            return
        }
        nextChar = substr(normalized, index(normalized, prefix) + length(prefix), 1)
        if (nextChar == "" || nextChar == " " || nextChar == "/" || nextChar == "$" || nextChar == "?") {
            printf "%s already proxies to %s; set nginx.goaccess.websocket_listen to a different loopback host:port\n", current_file, label > "/dev/stderr"
            found = 1
        }
    }
    function check_directive(text,    normalized, proxy_target, upstream) {
        if (current_file == "" || current_file == current_enabled || current_file == current_available) {
            return
        }
        normalized = normalize_directive(text)
        for (proxy_target in proxy_targets) {
            check_proxy_target(normalized, proxy_target, proxy_targets[proxy_target])
        }
        for (upstream in target_upstreams) {
            check_proxy_target(normalized, "http://" upstream, "upstream " upstream " for " target_upstreams[upstream])
        }
    }
    function process_line(text,    pos, part) {
        while (text != "") {
            pos = index(text, ";")
            if (pos == 0) {
                directive = directive " " text
                return
            }
            part = substr(text, 1, pos)
            directive = directive " " part
            check_directive(directive)
            directive = ""
            text = substr(text, pos + 1)
        }
    }
    BEGIN {
        init_targets()
        current_file = ""
        directive = ""
    }
    FNR == 1 {
        current_file = ""
        directive = ""
        reset_upstream_state()
    }
    NR == FNR {
        if ($0 ~ /^# configuration file /) {
            reset_upstream_state()
            current_file = $0
            sub(/^# configuration file /, "", current_file)
            sub(/:$/, "", current_file)
            next
        }
        line = $0
        sub(/[ \t]*#.*/, "", line)
        process_upstream_line(line)
        next
    }
    /^# configuration file / {
        directive = ""
        current_file = $0
        sub(/^# configuration file /, "", current_file)
        sub(/:$/, "", current_file)
        next
    }
    {
        line = $0
        sub(/[ \t]*#.*/, "", line)
        process_line(line)
    }
    END { exit found ? 1 : 0 }
' "$dump" "$dump"`
	return host.Command{
		Name:        "sh",
		Args:        []string{"-c", script, "lanpanel-app-goaccess-websocket-port-assignment", NginxBinaryPath, strings.TrimSpace(names.NginxEnabledPath), strings.TrimSpace(names.NginxAvailablePath), strings.TrimSpace(names.GoAccessWebSocketListen), strings.TrimSpace(names.GoAccessWebSocketHost), strconv.Itoa(names.GoAccessWebSocketPort)},
		DisplayName: "guard-goaccess-websocket-port-assignment",
		DisplayArgs: []string{names.GoAccessWebSocketListen},
	}
}

func guardServerNameConflictsCommand(currentEnabledPath string, currentAvailablePath string, domains []string) host.Command {
	script := `set -eu
nginx_binary=$1
current_enabled=$2
current_available=$3
domains=$4
dump=$(mktemp)
trap 'rm -f "$dump"' EXIT INT TERM

if ! "$nginx_binary" -T > "$dump" 2>&1; then
    cat "$dump" >&2
    exit 1
fi

awk -v current_enabled="$current_enabled" -v current_available="$current_available" -v domains="$domains" '
    function check_directive(text,    normalized, tail, count, parts, i) {
        normalized = text
        gsub(/[{};]/, " ", normalized)
        gsub(/[ \t\r\n]+/, " ", normalized)
        if (match(normalized, /(^| )server_name /)) {
            tail = substr(normalized, RSTART + RLENGTH)
            count = split(tail, parts, /[ \t]+/)
            for (i = 1; i <= count; i++) {
                if (parts[i] in wanted) {
                    printf "%s already appears in Nginx config %s; refusing duplicate app domain\n", parts[i], current_file > "/dev/stderr"
                    found = 1
                }
            }
        }
    }
    function process_line(text,    pos, part) {
        while (text != "") {
            pos = index(text, ";")
            if (pos == 0) {
                directive = directive " " text
                return
            }
            part = substr(text, 1, pos)
            directive = directive " " part
            check_directive(directive)
            directive = ""
            text = substr(text, pos + 1)
        }
    }
    BEGIN {
        split(domains, list, " ")
        for (i in list) {
            if (list[i] != "") wanted[list[i]] = 1
        }
        current_file = ""
        directive = ""
    }
    /^# configuration file / {
        directive = ""
        current_file = $0
        sub(/^# configuration file /, "", current_file)
        sub(/:$/, "", current_file)
        next
    }
    current_file == current_enabled || current_file == current_available {
        next
    }
    {
        line = $0
        sub(/[ \t]*#.*/, "", line)
        process_line(line)
    }
    END { exit found ? 1 : 0 }
' "$dump"`
	args := []string{"-c", script, "lanpanel-app-nginx-server-name-guard", NginxBinaryPath, strings.TrimSpace(currentEnabledPath), strings.TrimSpace(currentAvailablePath), strings.Join(domains, " ")}
	return host.Command{
		Name:        "sh",
		Args:        args,
		DisplayName: "guard-nginx-server-names",
		DisplayArgs: domains,
	}
}

func GuardDefaultServerCommand(names Names) host.Command {
	return guardDefaultServerCommand(names.NginxEnabledPath, names.NginxAvailablePath)
}

func guardDefaultServerCommand(currentEnabledPath string, currentAvailablePath string) host.Command {
	script := `set -eu
nginx_binary=$1
current_enabled=$2
current_available=$3
dump=$(mktemp)
trap 'rm -f "$dump"' EXIT INT TERM

if ! "$nginx_binary" -T > "$dump" 2>&1; then
    cat "$dump" >&2
    exit 1
fi

awk -v current_enabled="$current_enabled" -v current_available="$current_available" '
    function reset_section() {
        in_server = 0
        depth = 0
        block_text = ""
    }
    function check_section(    normalized, has_default, has_empty_name, has_444, has_421, has_lanpanel_tls) {
        if (current_file == "" || current_file == current_enabled || current_file == current_available) {
            return
        }
        normalized = block_text
        gsub(/[{};]/, " ", normalized)
        gsub(/[ \t\r\n]+/, " ", normalized)
        normalized = " " normalized " "
        has_default = index(normalized, " default_server ") > 0
        has_empty_name = normalized ~ / server_name "" /
        has_444 = normalized ~ / return 444 /
        has_421 = normalized ~ / return 421 /
        has_lanpanel_tls = index(block_text, "/etc/lanpanel/tls/") > 0
        if (has_default && !(has_empty_name && (has_444 || (has_421 && has_lanpanel_tls)))) {
            printf "%s declares default_server and is not a Lanpanel catch-all; remove or migrate it before deploying app sites\n", current_file > "/dev/stderr"
            failed = 1
        }
    }
    function count_char(text, char,    i, count) {
        count = 0
        for (i = 1; i <= length(text); i++) {
            if (substr(text, i, 1) == char) count++
        }
        return count
    }
    BEGIN {
        current_file = ""
        reset_section()
    }
    /^# configuration file / {
        if (in_server) check_section()
        current_file = $0
        sub(/^# configuration file /, "", current_file)
        sub(/:$/, "", current_file)
        reset_section()
        next
    }
    current_file == current_enabled || current_file == current_available {
        next
    }
    {
        line = $0
        sub(/[ \t]*#.*/, "", line)
        if (!in_server && line ~ /^[ \t]*server[ \t]*\{/) {
            reset_section()
            in_server = 1
        }
        if (in_server) {
            block_text = block_text "\n" line
            depth += count_char(line, "{") - count_char(line, "}")
            if (depth <= 0) {
                check_section()
                reset_section()
            }
        }
    }
    END {
        if (in_server) check_section()
        exit failed ? 1 : 0
    }
' "$dump"`
	return host.Command{
		Name:        "sh",
		Args:        []string{"-c", script, "lanpanel-app-nginx-default-server-guard", NginxBinaryPath, strings.TrimSpace(currentEnabledPath), strings.TrimSpace(currentAvailablePath)},
		DisplayName: "guard-nginx-default-server",
		DisplayArgs: []string{strings.TrimSpace(currentEnabledPath)},
	}
}

func TestNginxCommand() host.Command {
	return host.Command{Name: NginxBinaryPath, Args: []string{"-t"}}
}

func ReloadNginxCommand() host.Command {
	return host.Command{Name: "systemctl", Args: []string{"reload", "nginx.service"}}
}

func ValidateRenderedNginx(cfg appconfig.Config, names Names, content []byte) error {
	text := string(content)
	var errs []string
	httpBlock := nginxServerBlockContaining(text, "listen 80;")
	httpsBlock := nginxServerBlockContaining(text, "listen 443 ssl;")

	mustContain(&errs, text, "server_name "+strings.Join(cfg.App.Domains, " ")+";", "server_name domain list")
	mustContain(&errs, text, "server "+upstreamAddress(cfg)+";", "fixed upstream address")
	mustContain(&errs, text, "map $http_host $"+names.VarPrefix+"_host_header_valid", "Host allowlist map")
	mustContain(&errs, text, "map $http_host $"+names.VarPrefix+"_validated_host", "validated Host map")
	mustContain(&errs, text, "map $ssl_server_name $"+names.VarPrefix+"_sni_valid", "SNI allowlist map")
	mustContain(&errs, text, "root "+names.WebrootPath+";", "HTTP-01 webroot")
	mustContain(&errs, text, "ssl_certificate "+names.FullchainPath+";", "fullchain certificate path")
	mustContain(&errs, text, "ssl_certificate_key "+names.PrivateKeyPath+";", "private key path")
	if cfg.Nginx.HTTP2Enabled() {
		mustContain(&errs, text, "http2 on;", "HTTP/2 server directive")
	} else if strings.Contains(text, "http2 on;") {
		errs = append(errs, "HTTP/2 server directive must be absent when nginx.http2 is false")
	}
	mustContain(&errs, text, "client_max_body_size "+cfg.Nginx.EffectiveClientMaxBodySize()+";", "client_max_body_size")
	mustContain(&errs, text, "proxy_http_version 1.1;", "HTTP/1.1 reverse proxy")
	mustContain(&errs, text, "proxy_set_header Upgrade $http_upgrade;", "WebSocket Upgrade header")
	mustContain(&errs, text, "proxy_set_header Connection $"+names.VarPrefix+"_connection_upgrade;", "WebSocket Connection header")
	mustContain(&errs, text, "proxy_set_header Host $"+names.VarPrefix+"_validated_host;", "validated request Host forwarding")
	mustContain(&errs, text, "proxy_set_header X-Forwarded-Host $"+names.VarPrefix+"_validated_host;", "validated X-Forwarded-Host forwarding")
	mustContain(&errs, text, "location /.well-known/acme-challenge/", "ACME challenge location")
	if strings.Contains(text, "default_server") {
		errs = append(errs, "app Nginx site must not declare default_server")
	}
	hostMap := nginxMapBlock(text, "map $http_host $"+names.VarPrefix+"_host_header_valid")
	validatedHostMap := nginxMapBlock(text, "map $http_host $"+names.VarPrefix+"_validated_host")
	sniMap := nginxMapBlock(text, "map $ssl_server_name $"+names.VarPrefix+"_sni_valid")
	for _, domain := range cfg.App.Domains {
		mustContain(&errs, hostMap, `"`+domain+`" 1;`, "Host allowlist for "+domain)
		mustContain(&errs, hostMap, `"`+domain+`:80" 1;`, "HTTP Host allowlist with port for "+domain)
		mustContain(&errs, hostMap, `"`+domain+`:443" 1;`, "Host allowlist with port for "+domain)
		mustContain(&errs, validatedHostMap, `"`+domain+`" "`+domain+`";`, "validated Host map for "+domain)
		mustContain(&errs, validatedHostMap, `"`+domain+`:80" "`+domain+`";`, "validated Host map with HTTP port for "+domain)
		mustContain(&errs, validatedHostMap, `"`+domain+`:443" "`+domain+`";`, "validated Host map with HTTPS port for "+domain)
		mustContain(&errs, sniMap, `"`+domain+`" 1;`, "SNI allowlist for "+domain)
	}
	validateHTTPServerBlock(&errs, httpBlock, cfg, names)
	validateHTTPSServerBlock(&errs, httpsBlock, cfg, names)
	validateRealIPNginx(&errs, text, httpBlock, httpsBlock, cfg, names)
	validateGoAccessNginx(&errs, text, httpBlock, httpsBlock, cfg, names)
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func validateHTTPServerBlock(errs *[]string, block string, cfg appconfig.Config, names Names) {
	if block == "" {
		*errs = append(*errs, "HTTP server block missing")
		return
	}
	mustContain(errs, block, "server_name "+strings.Join(cfg.App.Domains, " ")+";", "HTTP server_name domain list")
	mustContain(errs, block, "location /.well-known/acme-challenge/", "HTTP ACME challenge location")
	mustAppearBefore(errs, block,
		"if ($"+names.VarPrefix+"_host_header_valid = 0) {\n        return 421;\n    }",
		"location /.well-known/acme-challenge/",
		"HTTP Host allowlist before ACME challenge")
}

func validateHTTPSServerBlock(errs *[]string, block string, cfg appconfig.Config, names Names) {
	if block == "" {
		*errs = append(*errs, "HTTPS server block missing")
		return
	}
	mustContain(errs, block, "server_name "+strings.Join(cfg.App.Domains, " ")+";", "HTTPS server_name domain list")
	mustContain(errs, block, "ssl_certificate "+names.FullchainPath+";", "HTTPS fullchain certificate path")
	mustContain(errs, block, "ssl_certificate_key "+names.PrivateKeyPath+";", "HTTPS private key path")
	if cfg.Nginx.GoAccess.Enabled {
		if cfg.Nginx.GoAccess.EffectiveLogFormat() == appconfig.NginxGoAccessLogFormatEnhanced {
			mustContain(errs, block, "access_log "+names.GoAccessCanonicalAccessLogPath+" "+names.GoAccessNginxLogFormatName+";", "HTTPS GoAccess enhanced access_log")
		} else {
			mustContain(errs, block, "access_log "+names.GoAccessCanonicalAccessLogPath+" combined;", "HTTPS GoAccess combined access_log")
		}
	} else if cfg.Nginx.AccessLog != "" {
		mustContain(errs, block, "access_log "+cfg.Nginx.AccessLog+";", "HTTPS access_log")
	}
	if cfg.Nginx.ErrorLog != "" {
		mustContain(errs, block, "error_log "+cfg.Nginx.ErrorLog+";", "HTTPS error_log")
	}
	mustAppearBefore(errs, block,
		"if ($"+names.VarPrefix+"_sni_valid = 0) {\n        return 421;\n    }",
		"if ($"+names.VarPrefix+"_host_header_valid = 0) {\n        return 421;\n    }",
		"HTTPS SNI allowlist before Host allowlist")
	mustAppearBefore(errs, block,
		"if ($"+names.VarPrefix+"_host_header_valid = 0) {\n        return 421;\n    }",
		"location / {\n        proxy_pass",
		"HTTPS Host allowlist before proxy location")
	validateStaticLocations(errs, block, cfg)
	validateAppProxyLocation(errs, block, cfg, names)
}

func validateAppProxyLocation(errs *[]string, block string, cfg appconfig.Config, names Names) {
	appProxyBlock := nginxBlockStartingWith(block, "location / {")
	if appProxyBlock == "" {
		*errs = append(*errs, "HTTPS app proxy location missing")
		return
	}
	mustContain(errs, block, "proxy_set_header Host $"+names.VarPrefix+"_validated_host;", "HTTPS validated Host forwarding")
	mustContain(errs, block, "proxy_pass http://"+names.VarPrefix+"_upstream", "HTTPS proxy_pass app upstream")
	mustHaveNginxDirectiveLine(errs, appProxyBlock, 1, "proxy_pass http://"+names.VarPrefix+"_upstream;", "HTTPS app proxy_pass")
	mustHaveNginxDirective(errs, appProxyBlock, 1, "HTTPS app HTTP/1.1 proxy", "proxy_http_version", "1.1")
	mustHaveNginxDirective(errs, appProxyBlock, 1, "HTTPS app validated Host forwarding", "proxy_set_header", "Host", "$"+names.VarPrefix+"_validated_host")
	mustHaveNginxDirective(errs, appProxyBlock, 1, "HTTPS app WebSocket Upgrade header", "proxy_set_header", "Upgrade", "$http_upgrade")
	mustHaveNginxDirective(errs, appProxyBlock, 1, "HTTPS app WebSocket Connection header", "proxy_set_header", "Connection", "$"+names.VarPrefix+"_connection_upgrade")
	mustHaveNginxDirective(errs, appProxyBlock, 1, "HTTPS app canonical X-Real-IP forwarding", "proxy_set_header", "X-Real-IP", "$remote_addr")
	if cfg.RealIPEnabled() {
		mustHaveNginxDirective(errs, appProxyBlock, 1, "HTTPS app canonical X-Forwarded-For forwarding", "proxy_set_header", "X-Forwarded-For", "$remote_addr")
		validateSensitiveForwardedHeadersCleared(errs, appProxyBlock, "HTTPS app proxy")
		if strings.Contains(appProxyBlock, "$proxy_add_x_forwarded_for") {
			*errs = append(*errs, "HTTPS app proxy must not use $proxy_add_x_forwarded_for when realip is enabled")
		}
	} else {
		mustHaveNginxDirective(errs, appProxyBlock, 1, "HTTPS app X-Forwarded-For forwarding", "proxy_set_header", "X-Forwarded-For", "$proxy_add_x_forwarded_for")
	}
	mustHaveNginxDirective(errs, appProxyBlock, 1, "HTTPS app validated X-Forwarded-Host forwarding", "proxy_set_header", "X-Forwarded-Host", "$"+names.VarPrefix+"_validated_host")
	mustHaveNginxDirective(errs, appProxyBlock, 1, "HTTPS app X-Forwarded-Proto forwarding", "proxy_set_header", "X-Forwarded-Proto", "$scheme")
	if cfg.Nginx.Proxy.ConnectTimeout != "" {
		mustHaveNginxDirective(errs, appProxyBlock, 1, "proxy connect timeout", "proxy_connect_timeout", cfg.Nginx.Proxy.ConnectTimeout)
	}
	mustHaveNginxDirective(errs, appProxyBlock, 1, "proxy read timeout", "proxy_read_timeout", cfg.Nginx.Proxy.EffectiveReadTimeout())
	mustHaveNginxDirective(errs, appProxyBlock, 1, "proxy send timeout", "proxy_send_timeout", cfg.Nginx.Proxy.EffectiveSendTimeout())
	if cfg.Nginx.Proxy.Buffering != nil {
		mustHaveNginxDirective(errs, appProxyBlock, 1, "proxy buffering", "proxy_buffering", nginxBool(*cfg.Nginx.Proxy.Buffering))
	}
	if cfg.Nginx.Proxy.RequestBuffering != nil {
		mustHaveNginxDirective(errs, appProxyBlock, 1, "proxy request buffering", "proxy_request_buffering", nginxBool(*cfg.Nginx.Proxy.RequestBuffering))
	}
	if cfg.BrowserAuthEnabled() {
		mustHaveNginxDirectiveLine(errs, appProxyBlock, 1, `proxy_set_header Authorization "";`, "HTTPS app browser Authorization header clearing")
		validateBrowserAccessControls(errs, appProxyBlock, cfg, "HTTPS app proxy")
	} else if nginxHasDirectiveLineAtDepth(appProxyBlock, 1, `proxy_set_header Authorization "";`) {
		*errs = append(*errs, "HTTPS app proxy must not clear Authorization outside browser access mode")
	}
}

func validateRealIPNginx(errs *[]string, text string, httpBlock string, httpsBlock string, cfg appconfig.Config, names Names) {
	if !cfg.RealIPEnabled() {
		for _, forbidden := range []string{"real_ip_header", "set_real_ip_from", "real_ip_recursive"} {
			if nginxHasDirectiveName(text, forbidden) {
				*errs = append(*errs, "realip directive or guard "+forbidden+" must be absent when access.origin_protection.mode is not edgeone")
			}
		}
		for _, forbidden := range []string{
			"$" + names.VarPrefix + "_eo_connecting_ip_is_ip",
			"$" + names.VarPrefix + "_eo_connecting_ip_is_public",
			"$" + names.VarPrefix + "_realip_reject_reason",
		} {
			if nginxHasVariableReference(text, forbidden) {
				*errs = append(*errs, "realip directive or guard "+strings.TrimPrefix(forbidden, "$"+names.VarPrefix+"_")+" must be absent when access.origin_protection.mode is not edgeone")
			}
		}
		return
	}
	profileName := cfg.EffectiveRealIPProfileName()
	profile, ok := cfg.RealIPProfile(profileName)
	if !ok {
		*errs = append(*errs, "realip profile data missing for rendered Nginx validation")
		return
	}
	realIPNames, err := NewRealIPProfileNames(profileName, profile.Provider, names.AppName)
	if err != nil {
		*errs = append(*errs, err.Error())
		return
	}
	sourceTrustedVar := "$" + names.VarPrefix + "_realip_source_trusted"
	originalSourceVar := "$" + names.VarPrefix + "_realip_original_source"
	headerIsIPVar := "$" + names.VarPrefix + "_eo_connecting_ip_is_ip"
	headerPublicVar := "$" + names.VarPrefix + "_eo_connecting_ip_is_public"
	rejectReasonVar := "$" + names.VarPrefix + "_realip_reject_reason"
	rejectLogVar := "$" + names.VarPrefix + "_realip_reject_log"

	mustContain(errs, text, "log_format "+names.RealIPRejectionLogFormatName+" ", "realip rejection log format")
	mustContain(errs, text, "reason=\""+rejectReasonVar+"\"", "realip rejection log reason")
	mustContain(errs, text, "source=\""+originalSourceVar+"\"", "realip rejection log source")
	mustContain(errs, text, "map $realip_remote_addr "+originalSourceVar+" {", "realip original source map")
	mustContain(errs, text, "default $realip_remote_addr;", "realip original source uses realip_remote_addr when available")
	mustContain(errs, text, `"" $remote_addr;`, "realip original source falls back to remote_addr")
	mustContain(errs, text, "geo "+originalSourceVar+" "+sourceTrustedVar+" {", "realip trusted source geo")
	mustContain(errs, text, "include "+realIPNames.TrustedCIDRPath+";", "realip trusted CIDR geo include")
	mustContain(errs, text, "map $http_eo_connecting_ip "+headerIsIPVar+" {", "realip EO-Connecting-IP syntax map")
	mustContain(errs, text, `"~^(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})$" 1;`, "realip IPv4 syntax validation")
	mustContain(errs, text, `"~*^(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}$" 1;`, "realip IPv6 syntax validation")
	mustContain(errs, text, `"~*^[0-9a-f]{1,4}:(?:(?::[0-9a-f]{1,4}){1,6})$" 1;`, "realip IPv6 compressed syntax validation")
	mustContain(errs, text, `"~*^::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}$" 1;`, "realip IPv6 leading compression syntax validation")
	mustContain(errs, text, `"::" 1;`, "realip IPv6 unspecified syntax validation")
	mustNotContain(errs, text, `"~*^[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){1,6}$" 1;`, "realip IPv6 syntax validation rejects short uncompressed addresses")
	mustNotContain(errs, text, `"~*^:(?::[0-9a-f]{1,4}){1,7}$" 1;`, "realip IPv6 syntax validation rejects single-colon prefixes")
	mustContain(errs, text, "geo $http_eo_connecting_ip "+headerPublicVar+" {", "realip EO-Connecting-IP public range geo")
	mustContain(errs, text, "0.0.0.0/1 1;", "realip IPv4 low-half header validation")
	mustContain(errs, text, "128.0.0.0/1 1;", "realip IPv4 high-half header validation")
	mustNotContain(errs, text, "0.0.0.0/0 1;", "realip IPv4 public validation avoids duplicate default network")
	mustContain(errs, text, "2000::/3 1;", "realip IPv6 global unicast header validation")
	mustNotContain(errs, text, "::/0 1;", "realip IPv6 public validation must not allow every IPv6 range")
	for _, blocked := range []string{
		"0.0.0.0/8 0;",
		"10.0.0.0/8 0;",
		"127.0.0.0/8 0;",
		"169.254.0.0/16 0;",
		"172.16.0.0/12 0;",
		"192.168.0.0/16 0;",
		"224.0.0.0/4 0;",
		"::/128 0;",
		"::1/128 0;",
		"::ffff:0:0/96 0;",
		"fc00::/7 0;",
		"fe80::/10 0;",
		"ff00::/8 0;",
	} {
		mustContain(errs, text, blocked, "realip rejects non-public EO-Connecting-IP range "+blocked)
	}
	mustContain(errs, text, `map "`+sourceTrustedVar+`:`+headerIsIPVar+`:`+headerPublicVar+`:$http_eo_connecting_ip" `+rejectReasonVar+` {`, "realip reject reason map")
	mustContain(errs, text, `~^1:[01]:[01]:.*,.* "duplicate_eo_connecting_ip";`, "realip duplicate header reject map")
	mustContain(errs, text, `~^0:[01]:[01]: "untrusted_source_ip";`, "realip untrusted source reject map")
	mustContain(errs, text, `~^1:0:[01]: "missing_or_invalid_eo_connecting_ip";`, "realip missing or syntactically invalid header reject map")
	mustContain(errs, text, `~*^1:1:[01]:::ffff: "missing_or_invalid_eo_connecting_ip";`, "realip IPv4-mapped header reject map")
	mustContain(errs, text, `~^1:1:0: "missing_or_invalid_eo_connecting_ip";`, "realip non-public header reject map")
	mustContain(errs, text, "map "+rejectReasonVar+" "+rejectLogVar+" {", "realip reject log map")
	mustContain(errs, text, "default 1;", "realip reject log enabled for rejection reasons")
	mustContain(errs, text, `"" 0;`, "realip reject log disabled for accepted requests")
	if nginxHasDirectiveName(text, "real_ip_recursive") {
		*errs = append(*errs, "realip must not render real_ip_recursive")
	}
	rejectLocation := "@" + names.VarPrefix + "_realip_reject"
	validateRealIPServerBlock(errs, "HTTP", httpBlock, realIPNames.NginxIncludePath, names.RealIPRejectionLogPath, names.RealIPRejectionLogFormatName, rejectLogVar, rejectReasonVar, rejectLocation)
	validateRealIPServerBlock(errs, "HTTPS", httpsBlock, realIPNames.NginxIncludePath, names.RealIPRejectionLogPath, names.RealIPRejectionLogFormatName, rejectLogVar, rejectReasonVar, rejectLocation)
}

func validateRealIPServerBlock(errs *[]string, label string, block string, includePath string, rejectionLogPath string, rejectionLogFormatName string, rejectLogVar string, rejectReasonVar string, rejectLocation string) {
	mustHaveNginxDirective(errs, block, 1, label+" realip include", "include", includePath)
	mustHaveNginxDirective(errs, block, 1, label+" realip header", "real_ip_header", appconfig.RealIPHeaderEdgeOne)
	mustHaveNginxDirective(errs, block, 1, label+" realip rejection error_page", "error_page", "418", "=", rejectLocation)
	mustContain(errs, block, "if ("+rejectReasonVar+" != \"\") {\n        return 418;\n    }", label+" realip fail-closed guard")
	if nginxHasDirectiveFieldsAtDepth(block, 1, "access_log", rejectionLogPath, rejectionLogFormatName, "if="+rejectLogVar) {
		*errs = append(*errs, label+" realip rejection access_log must be scoped to the internal rejection location")
	}
	rejectBlock := nginxBlockStartingWith(block, "location "+rejectLocation+" {")
	if rejectBlock == "" {
		*errs = append(*errs, label+" realip rejection location missing")
		return
	}
	mustHaveNginxDirectiveLine(errs, rejectBlock, 1, "internal;", label+" realip rejection location internal")
	mustHaveNginxDirective(errs, rejectBlock, 1, label+" realip rejection access log", "access_log", rejectionLogPath, rejectionLogFormatName, "if="+rejectLogVar)
	mustHaveNginxDirectiveLine(errs, rejectBlock, 1, "return 400 \"lanpanel realip rejected: "+rejectReasonVar+"\\n\";", label+" realip rejection return")
}

func validateSensitiveForwardedHeadersCleared(errs *[]string, block string, label string) {
	for _, header := range []string{
		"Forwarded",
		"X-Forwarded-Port",
		"X-Forwarded-Prefix",
		"X-Original-Forwarded-For",
		"X-Client-IP",
		"Client-IP",
		"True-Client-IP",
		"EO-Connecting-IP",
		"EO-Client-IP",
	} {
		mustHaveNginxDirectiveLine(errs, block, 1, `proxy_set_header `+header+` "";`, label+" clears "+header)
	}
}

func validateGoAccessNginx(errs *[]string, text string, httpBlock string, httpsBlock string, cfg appconfig.Config, names Names) {
	goaccess := cfg.Nginx.GoAccess
	dashboardPath := cfg.NginxGoAccessDashboardPath()
	websocketPath := cfg.NginxGoAccessWebSocketPath()
	if !cfg.Nginx.GoAccess.Enabled {
		for _, forbidden := range []struct {
			needle string
			label  string
		}{
			{"log_format " + names.GoAccessNginxLogFormatName, "GoAccess log_format"},
			{"location = " + dashboardPath + " {\n        access_log off;\n        return 301 https://" + cfg.PrimaryDomain() + dashboardPath + ";", "GoAccess dashboard redirect"},
			{"alias " + names.GoAccessReportPath + ";", "GoAccess dashboard report alias"},
			{"location = " + websocketPath + " {\n        access_log off;\n        return 421;", "GoAccess WebSocket block"},
			{`auth_basic "Lanpanel GoAccess";`, "GoAccess basic auth"},
			{"proxy_pass http://" + names.GoAccessWebSocketListen + ";", "GoAccess WebSocket upstream"},
		} {
			if strings.Contains(text, forbidden.needle) {
				*errs = append(*errs, forbidden.label+" must be absent when nginx.goaccess.enabled is false")
			}
		}
		return
	}
	if nginxHasDirectiveFields(text, "satisfy", "any") {
		*errs = append(*errs, "GoAccess Nginx must not render satisfy any")
	}
	if goaccess.EffectiveLogFormat() == appconfig.NginxGoAccessLogFormatEnhanced {
		mustContain(errs, text, goAccessEnhancedLogFormatDirective(names), "GoAccess enhanced log_format")
		mustContain(errs, text, goAccessCanonicalAccessLogDirective(cfg, names), "GoAccess enhanced canonical access_log")
	} else {
		mustContain(errs, text, goAccessCanonicalAccessLogDirective(cfg, names), "GoAccess combined canonical access_log")
	}
	validateGoAccessCanonicalAccessLogDirective(errs, "HTTP", httpBlock, cfg, names)
	validateGoAccessCanonicalAccessLogDirective(errs, "HTTPS", httpsBlock, cfg, names)

	dashboardHeader := "location = " + dashboardPath + " {"
	websocketHeader := "location = " + websocketPath + " {"
	httpDashboardBlock := nginxBlockStartingWith(httpBlock, dashboardHeader)
	httpWebsocketBlock := nginxBlockStartingWith(httpBlock, websocketHeader)
	dashboardBlock := nginxBlockStartingWith(httpsBlock, dashboardHeader)
	websocketBlock := nginxBlockStartingWith(httpsBlock, websocketHeader)
	if httpDashboardBlock == "" {
		*errs = append(*errs, "HTTP GoAccess dashboard location missing")
	} else {
		mustAppearBefore(errs, httpBlock, dashboardHeader, "location / {\n        return 301", "HTTP GoAccess dashboard location before redirect")
		mustHaveNginxDirectiveLine(errs, httpDashboardBlock, 1, "access_log off;", "HTTP GoAccess dashboard access_log off")
		mustHaveNginxDirectiveLine(errs, httpDashboardBlock, 1, "return 301 https://"+cfg.PrimaryDomain()+dashboardPath+";", "HTTP GoAccess dashboard primary-domain redirect")
	}
	if httpWebsocketBlock == "" {
		*errs = append(*errs, "HTTP GoAccess WebSocket location missing")
	} else {
		mustAppearBefore(errs, httpBlock, websocketHeader, "location / {\n        return 301", "HTTP GoAccess WebSocket location before redirect")
		mustHaveNginxDirectiveLine(errs, httpWebsocketBlock, 1, "access_log off;", "HTTP GoAccess WebSocket access_log off")
		mustHaveNginxDirectiveLine(errs, httpWebsocketBlock, 1, "return 421;", "HTTP GoAccess WebSocket block")
	}
	if dashboardBlock == "" {
		*errs = append(*errs, "GoAccess dashboard location missing")
	} else {
		mustAppearBefore(errs, httpsBlock, dashboardHeader, "location / {\n        proxy_pass", "GoAccess dashboard location before proxy")
		validateGoAccessPrimaryDomainRedirectGuard(errs, dashboardBlock, cfg.PrimaryDomain(), dashboardPath)
		mustHaveNginxDirectiveLine(errs, dashboardBlock, 1, "alias "+names.GoAccessReportPath+";", "GoAccess dashboard report alias")
		mustHaveNginxDirectiveLine(errs, dashboardBlock, 1, "default_type text/html;", "GoAccess dashboard default_type")
		mustHaveNginxDirectiveLine(errs, dashboardBlock, 1, "disable_symlinks on;", "GoAccess dashboard disable_symlinks")
		validateGoAccessAccessControls(errs, dashboardBlock, goaccess, "GoAccess dashboard")
		mustHaveNginxDirectiveLine(errs, dashboardBlock, 1, "access_log off;", "GoAccess dashboard access_log off")
	}
	if websocketBlock == "" {
		*errs = append(*errs, "GoAccess WebSocket location missing")
	} else {
		mustAppearBefore(errs, httpsBlock, websocketHeader, "location / {\n        proxy_pass", "GoAccess WebSocket location before proxy")
		validateGoAccessWebSocketSecondaryDomainGuard(errs, websocketBlock, cfg.PrimaryDomain())
		mustHaveNginxDirectiveLine(errs, websocketBlock, 1, "proxy_pass http://"+names.GoAccessWebSocketListen+";", "GoAccess WebSocket loopback upstream")
		if !nginxHasDirectiveFieldsAtDepth(websocketBlock, 1, "proxy_http_version", "1.1") {
			*errs = append(*errs, "GoAccess WebSocket HTTP/1.1 proxy missing")
		}
		mustHaveNginxDirectiveLine(errs, websocketBlock, 1, `proxy_set_header Authorization "";`, "GoAccess WebSocket Authorization header clearing")
		mustHaveNginxDirective(errs, websocketBlock, 1, "GoAccess WebSocket Upgrade header", "proxy_set_header", "Upgrade", "$http_upgrade")
		mustHaveNginxDirective(errs, websocketBlock, 1, "GoAccess WebSocket Connection header", "proxy_set_header", "Connection", "$"+names.VarPrefix+"_connection_upgrade")
		mustHaveNginxDirective(errs, websocketBlock, 1, "GoAccess WebSocket canonical X-Real-IP forwarding", "proxy_set_header", "X-Real-IP", "$remote_addr")
		if cfg.RealIPEnabled() {
			mustHaveNginxDirective(errs, websocketBlock, 1, "GoAccess WebSocket canonical X-Forwarded-For forwarding", "proxy_set_header", "X-Forwarded-For", "$remote_addr")
			validateSensitiveForwardedHeadersCleared(errs, websocketBlock, "GoAccess WebSocket")
			if strings.Contains(websocketBlock, "$proxy_add_x_forwarded_for") {
				*errs = append(*errs, "GoAccess WebSocket must not use $proxy_add_x_forwarded_for when realip is enabled")
			}
		} else {
			mustHaveNginxDirective(errs, websocketBlock, 1, "GoAccess WebSocket X-Forwarded-For forwarding", "proxy_set_header", "X-Forwarded-For", "$proxy_add_x_forwarded_for")
		}
		mustHaveNginxDirective(errs, websocketBlock, 1, "GoAccess WebSocket validated X-Forwarded-Host forwarding", "proxy_set_header", "X-Forwarded-Host", "$"+names.VarPrefix+"_validated_host")
		mustHaveNginxDirective(errs, websocketBlock, 1, "GoAccess WebSocket X-Forwarded-Proto forwarding", "proxy_set_header", "X-Forwarded-Proto", "$scheme")
		mustHaveNginxDirective(errs, websocketBlock, 1, "GoAccess WebSocket read timeout", "proxy_read_timeout", "3600s")
		validateGoAccessAccessControls(errs, websocketBlock, goaccess, "GoAccess WebSocket")
		mustHaveNginxDirectiveLine(errs, websocketBlock, 1, "access_log off;", "GoAccess WebSocket access_log off")
	}
}

func goAccessEnhancedLogFormatDirective(names Names) string {
	return "log_format " + names.GoAccessNginxLogFormatName + ` '$remote_addr - $remote_user [$time_iso8601] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$host" $request_time "$upstream_status" "$upstream_response_time"';`
}

func goAccessCanonicalAccessLogDirective(cfg appconfig.Config, names Names) string {
	if cfg.Nginx.GoAccess.EffectiveLogFormat() == appconfig.NginxGoAccessLogFormatEnhanced {
		return "access_log " + names.GoAccessCanonicalAccessLogPath + " " + names.GoAccessNginxLogFormatName + ";"
	}
	return "access_log " + names.GoAccessCanonicalAccessLogPath + " combined;"
}

func validateGoAccessCanonicalAccessLogDirective(errs *[]string, label string, block string, cfg appconfig.Config, names Names) {
	expected := goAccessCanonicalAccessLogDirective(cfg, names)
	directives := nginxTopLevelDirectiveLines(block, "access_log")
	canonicalCount := 0
	for _, directive := range directives {
		switch directive {
		case expected:
			canonicalCount++
		case realIPRejectionAccessLogDirective(names):
			if cfg.RealIPEnabled() {
				continue
			}
			*errs = append(*errs, "GoAccess "+label+" server must not include realip rejection access_log when realip is disabled")
		default:
			*errs = append(*errs, "GoAccess "+label+" server contains unexpected access_log directive: "+directive)
		}
	}
	if canonicalCount != 1 {
		*errs = append(*errs, "GoAccess "+label+" server access_log directives must contain exactly one canonical access_log")
	}
}

func realIPRejectionAccessLogDirective(names Names) string {
	return "access_log " + names.RealIPRejectionLogPath + " " + names.RealIPRejectionLogFormatName + " if=$" + names.VarPrefix + "_realip_reject_log;"
}

func validateGoAccessPrimaryDomainRedirectGuard(errs *[]string, block string, primaryDomain string, dashboardPath string) {
	guardBlock := nginxBlockStartingWith(nginxWithoutComments(block), `if ($host != "`+primaryDomain+`") {`)
	expectedReturn := "return 301 https://" + primaryDomain + dashboardPath + ";"
	if guardBlock == "" || !nginxHasDirectiveLineAtDepth(guardBlock, 1, expectedReturn) {
		*errs = append(*errs, "GoAccess dashboard primary-domain redirect guard missing")
	}
}

func validateGoAccessWebSocketSecondaryDomainGuard(errs *[]string, block string, primaryDomain string) {
	guardBlock := nginxBlockStartingWith(nginxWithoutComments(block), `if ($host != "`+primaryDomain+`") {`)
	if guardBlock == "" || !nginxHasDirectiveLineAtDepth(guardBlock, 1, "return 421;") {
		*errs = append(*errs, "GoAccess WebSocket secondary-domain guard missing")
	}
}

func validateGoAccessAccessControls(errs *[]string, block string, goaccess appconfig.NginxGoAccessConfig, label string) {
	mustHaveNginxDirective(errs, block, 1, label+" satisfy all", "satisfy", "all")
	mustHaveNginxDirectiveLine(errs, block, 1, `auth_basic "Lanpanel GoAccess";`, label+" basic auth")
	mustHaveNginxDirectiveLine(errs, block, 1, "auth_basic_user_file "+goaccess.AuthBasicUserFile+";", label+" auth_basic_user_file")
	if nginxHasDirectiveFieldsAtDepth(block, 1, "auth_basic", "off") {
		*errs = append(*errs, label+" must not disable basic auth")
	}
	if nginxHasDirectiveFields(block, "satisfy", "any") {
		*errs = append(*errs, label+" must require both basic auth and CIDR allowlist checks")
	}
	validateGoAccessAllowDenyDirectives(errs, block, goaccess.AuthCIDRAllowlist, label)
}

func mustHaveNginxDirective(errs *[]string, block string, depth int, label string, fields ...string) {
	if !nginxHasDirectiveFieldsAtDepth(block, depth, fields...) {
		*errs = append(*errs, label+" missing")
	}
}

func mustHaveNginxDirectiveLine(errs *[]string, block string, depth int, expected string, label string) {
	if nginxHasDirectiveLineAtDepth(block, depth, expected) {
		return
	}
	*errs = append(*errs, label+" missing")
}

func nginxHasDirectiveLineAtDepth(block string, depth int, expected string) bool {
	for _, directive := range nginxDirectives(block) {
		if directive.depth == depth && directive.text == expected {
			return true
		}
	}
	return false
}

func nginxHasDirectiveFields(block string, want ...string) bool {
	return nginxHasDirectiveFieldsAtDepth(block, -1, want...)
}

func nginxHasDirectiveFieldsAtDepth(block string, depth int, want ...string) bool {
	for _, directive := range nginxDirectives(block) {
		if depth >= 0 && directive.depth != depth {
			continue
		}
		if len(directive.fields) != len(want) {
			continue
		}
		matches := true
		for i := range want {
			if directive.fields[i] != want[i] {
				matches = false
				break
			}
		}
		if matches {
			return true
		}
	}
	return false
}

func nginxHasDirectiveName(block string, name string) bool {
	for _, directive := range nginxDirectives(block) {
		if len(directive.fields) > 0 && directive.fields[0] == name {
			return true
		}
	}
	return false
}

func nginxHasVariableReference(block string, variable string) bool {
	for _, fields := range nginxStatementFields(block) {
		for _, field := range fields {
			if strings.Contains(field, "$") && strings.Contains(field, variable) {
				return true
			}
		}
	}
	return false
}

func nginxStatementFields(block string) [][]string {
	var statements [][]string
	var builder strings.Builder
	inComment := false
	for _, r := range block {
		if inComment {
			if r == '\n' || r == '\r' {
				inComment = false
				builder.WriteRune(' ')
			}
			continue
		}
		switch r {
		case '#':
			inComment = true
		case '{', ';':
			fields := strings.Fields(builder.String())
			if len(fields) > 0 {
				statements = append(statements, fields)
			}
			builder.Reset()
		case '}':
			builder.Reset()
		default:
			builder.WriteRune(r)
		}
	}
	return statements
}

func validateGoAccessAllowDenyDirectives(errs *[]string, block string, cidrs []string, label string) {
	validateAllowDenyDirectives(errs, block, cidrs, label, "nginx.goaccess.auth_cidr_allowlist")
}

func validateAllowDenyDirectives(errs *[]string, block string, cidrs []string, label string, source string) {
	expected := make([]string, 0, len(cidrs)+1)
	for _, cidr := range cidrs {
		expected = append(expected, "allow "+cidr+";")
	}
	if len(cidrs) > 0 {
		expected = append(expected, "deny all;")
	}

	actual := nginxTopLevelDirectiveLines(block, "allow", "deny")
	if len(actual) != len(expected) {
		*errs = append(*errs, label+" CIDR allow/deny directives must exactly match "+source)
		return
	}
	for i := range expected {
		if actual[i] != expected[i] {
			*errs = append(*errs, label+" CIDR allow/deny directives must exactly match "+source)
			return
		}
	}
}

type nginxDirective struct {
	depth  int
	text   string
	fields []string
}

func nginxTopLevelDirectiveLines(block string, names ...string) []string {
	directives := make([]string, 0)
	for _, directive := range nginxDirectives(block) {
		if directive.depth != 1 || len(directive.fields) == 0 {
			continue
		}
		for _, name := range names {
			if directive.fields[0] == name {
				directives = append(directives, directive.text)
				break
			}
		}
	}
	return directives
}

func nginxDirectives(block string) []nginxDirective {
	var directives []nginxDirective
	var builder strings.Builder
	depth := 0
	inComment := false
	for _, r := range block {
		if inComment {
			if r == '\n' || r == '\r' {
				inComment = false
				builder.WriteRune(' ')
			}
			continue
		}
		switch r {
		case '#':
			inComment = true
		case '{':
			builder.Reset()
			depth++
		case '}':
			builder.Reset()
			if depth > 0 {
				depth--
			}
		case ';':
			fields := strings.Fields(builder.String())
			if len(fields) > 0 {
				directives = append(directives, nginxDirective{
					depth:  depth,
					text:   strings.Join(fields, " ") + ";",
					fields: fields,
				})
			}
			builder.Reset()
		default:
			builder.WriteRune(r)
		}
	}
	return directives
}

func nginxWithoutComments(block string) string {
	var builder strings.Builder
	inComment := false
	for _, r := range block {
		if inComment {
			if r == '\n' || r == '\r' {
				inComment = false
				builder.WriteRune(r)
			}
			continue
		}
		if r == '#' {
			inComment = true
			continue
		}
		builder.WriteRune(r)
	}
	return builder.String()
}

func validateStaticLocations(errs *[]string, httpsBlock string, cfg appconfig.Config) {
	for _, location := range cfg.Nginx.StaticLocations {
		header := staticLocationHeader(location)
		block := nginxBlockStartingWith(httpsBlock, header)
		if block == "" {
			*errs = append(*errs, "static location "+location.Path+" missing")
			continue
		}
		mustAppearBefore(errs, httpsBlock, header, "location / {\n        proxy_pass", "static location "+location.Path+" before proxy location")
		mustContain(errs, block, "alias "+location.Alias+";", "static location "+location.Path+" alias")
		if location.DefaultType != "" {
			mustContain(errs, block, "default_type "+location.DefaultType+";", "static location "+location.Path+" default_type")
		}
		if location.Expires != "" {
			mustContain(errs, block, "expires "+location.Expires+";", "static location "+location.Path+" expires")
		}
		if location.CacheControl != "" {
			mustContain(errs, block, `add_header Cache-Control "`+location.CacheControl+`";`, "static location "+location.Path+" Cache-Control")
		}
		if location.TryFiles {
			mustContain(errs, block, "try_files $uri =404;", "static location "+location.Path+" try_files")
		}
		if location.GzipStatic {
			mustContain(errs, block, "gzip_static on;", "static location "+location.Path+" gzip_static")
		}
		if location.AccessLog != nil && !*location.AccessLog {
			mustContain(errs, block, "access_log off;", "static location "+location.Path+" access_log off")
		}
		if cfg.BrowserAuthEnabled() {
			validateBrowserAccessControls(errs, block, cfg, "static location "+location.Path)
		} else if strings.Contains(block, `auth_basic "Lanpanel Browser";`) {
			*errs = append(*errs, "static location "+location.Path+" must not render browser auth outside browser access mode")
		}
	}
}

func validateBrowserAccessControls(errs *[]string, block string, cfg appconfig.Config, label string) {
	mustHaveNginxDirective(errs, block, 1, label+" browser satisfy all", "satisfy", "all")
	mustHaveNginxDirectiveLine(errs, block, 1, `auth_basic "Lanpanel Browser";`, label+" browser basic auth")
	mustHaveNginxDirectiveLine(errs, block, 1, "auth_basic_user_file "+cfg.BrowserAuthUserFile()+";", label+" browser auth_basic_user_file")
	if nginxHasDirectiveFieldsAtDepth(block, 1, "auth_basic", "off") {
		*errs = append(*errs, label+" must not disable browser basic auth")
	}
	if nginxHasDirectiveFields(block, "satisfy", "any") {
		*errs = append(*errs, label+" must require both browser basic auth and CIDR allowlist checks")
	}
	validateAllowDenyDirectives(errs, block, cfg.Access.CIDRAllowlist, label+" browser", "access.cidr_allowlist")
}

func staticLocationHeader(location appconfig.NginxStaticLocationConfig) string {
	if location.Match == "exact" {
		return "location = " + location.Path + " {"
	}
	return "location " + location.Path + " {"
}

func nginxBool(value bool) string {
	if value {
		return "on"
	}
	return "off"
}

func upstreamAddress(cfg appconfig.Config) string {
	if cfg.Mode() == appconfig.ModeUpstream {
		return cfg.App.Upstream
	}
	return cfg.App.Listen
}

func mustContain(errs *[]string, text string, want string, label string) {
	if !strings.Contains(text, want) {
		*errs = append(*errs, fmt.Sprintf("%s missing", label))
	}
}

func mustNotContain(errs *[]string, text string, forbidden string, label string) {
	if strings.Contains(text, forbidden) {
		*errs = append(*errs, fmt.Sprintf("%s present", label))
	}
}

func mustAppearBefore(errs *[]string, text string, first string, second string, label string) {
	firstIndex := strings.Index(text, first)
	if firstIndex < 0 {
		*errs = append(*errs, label+" missing first clause")
		return
	}
	secondIndex := strings.Index(text, second)
	if secondIndex < 0 {
		*errs = append(*errs, label+" missing second clause")
		return
	}
	if firstIndex > secondIndex {
		*errs = append(*errs, label+" has wrong order")
	}
}

func nginxServerBlockContaining(text string, needle string) string {
	searchFrom := 0
	for {
		start := strings.Index(text[searchFrom:], "server {")
		if start < 0 {
			return ""
		}
		start += searchFrom
		block := nginxBlockAt(text, start)
		if block == "" {
			return ""
		}
		if strings.Contains(block, needle) {
			return block
		}
		searchFrom = start + len("server {")
	}
}

func nginxBlockAt(text string, start int) string {
	open := strings.Index(text[start:], "{")
	if open < 0 {
		return ""
	}
	open += start
	depth := 0
	for index := open; index < len(text); index++ {
		switch text[index] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return text[start : index+1]
			}
		}
	}
	return ""
}

func nginxMapBlock(text string, header string) string {
	start := strings.Index(text, header)
	if start < 0 {
		return ""
	}
	open := strings.Index(text[start:], "{")
	if open < 0 {
		return ""
	}
	open += start
	close := strings.Index(text[open:], "\n}")
	if close < 0 {
		return text[open:]
	}
	return text[start : open+close+2]
}

func nginxBlockStartingWith(text string, prefix string) string {
	start := strings.Index(text, prefix)
	if start < 0 {
		return ""
	}
	return nginxBlockAt(text, start)
}
