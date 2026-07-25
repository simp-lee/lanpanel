package tls

import (
	"errors"
	"strings"
)

func ValidateReloadHook(content []byte) error {
	var errs []string
	text := string(content)
	lines := shellLines(content)
	if len(lines) == 0 || lines[0] != "#!/bin/sh" {
		errs = append(errs, "reload hook missing #!/bin/sh")
	}
	active := activeShellLines(lines)
	setIndex := lineIndex(active, "set -eu")
	testIndex := lineIndex(active, "nginx -t")
	systemctlIndex := lineContainsIndex(active, "systemctl reload nginx")
	if setIndex < 0 {
		errs = append(errs, "reload hook missing set -eu")
	}
	if testIndex < 0 {
		errs = append(errs, "reload hook missing nginx -t")
	}
	if systemctlIndex < 0 {
		errs = append(errs, "reload hook missing systemctl reload nginx")
	}
	if lineIndex(active, "nginx -s reload") >= 0 {
		errs = append(errs, "reload hook must not fallback to nginx -s reload")
	}
	for _, want := range []struct {
		text  string
		label string
	}{
		{text: `: "${LEGO_HOOK_CERT_NAME:?}"`, label: "reload hook LEGO_HOOK_CERT_NAME guard"},
		{text: `: "${LEGO_HOOK_CERT_PATH:?}"`, label: "reload hook LEGO_HOOK_CERT_PATH guard"},
		{text: `: "${LEGO_HOOK_CERT_KEY_PATH:?}"`, label: "reload hook LEGO_HOOK_CERT_KEY_PATH guard"},
		{text: `target_dir="/etc/lanpanel/tls/$LEGO_HOOK_CERT_NAME"`, label: "reload hook stable TLS target directory"},
		{text: `install -d -m 0755 "$target_dir"`, label: "reload hook stable TLS directory install"},
		{text: `install -m 0644 "$LEGO_HOOK_CERT_PATH" "$target_dir/fullchain.pem"`, label: "reload hook fullchain install"},
		{text: `install -m 0600 "$LEGO_HOOK_CERT_KEY_PATH" "$target_dir/privkey.pem"`, label: "reload hook private key install"},
	} {
		mustContainText(&errs, text, want.text, want.label)
	}
	if strings.Contains(text, "LEGO_CERT_") || strings.Contains(text, "LEGO_ACCOUNT_EMAIL") {
		errs = append(errs, "reload hook must use LEGO_HOOK_* variables, not legacy lego hook variables")
	}
	if strings.Contains(text, "certbot") || strings.Contains(text, "/etc/letsencrypt") {
		errs = append(errs, "reload hook must not reference Certbot or /etc/letsencrypt")
	}
	if setIndex >= 0 && testIndex >= 0 && setIndex > testIndex {
		errs = append(errs, "reload hook must enable set -eu before testing Nginx")
	}
	if testIndex >= 0 && systemctlIndex >= 0 && testIndex > systemctlIndex {
		errs = append(errs, "reload hook must run nginx -t before systemctl reload nginx")
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func ValidateRenewalService(content []byte) error {
	text := string(content)
	var errs []string
	mustContainText(&errs, text, "[Unit]", "renewal service [Unit] section")
	mustContainText(&errs, text, "Requires=nginx.service", "renewal service Nginx requirement")
	mustContainText(&errs, text, "After=network-online.target nginx.service", "renewal service network and Nginx ordering")
	mustContainText(&errs, text, "[Service]", "renewal service [Service] section")
	mustContainText(&errs, text, "Type=oneshot", "renewal service oneshot type")
	mustContainText(&errs, text, `lego_path="`+LegoDataPath+`"`, "renewal service migration path")
	mustContainText(&errs, text, `migrate --path "$lego_path"`, "renewal service migration gate")
	mustContainText(&errs, text, "touch \"$marker\"", "renewal service migration marker")
	mustContainText(&errs, text, LegoBinaryPath+" run --path "+LegoDataPath, "renewal service lego run command")
	mustContainText(&errs, text, " --deploy-hook "+RunHookPath, "renewal service deploy hook")
	if strings.Contains(text, " renew ") || strings.Contains(text, "--renew-hook") || strings.Contains(text, "--run-hook") {
		errs = append(errs, "renewal service must not use lego v4 renew or hook flags")
	}
	hasDNS := strings.Contains(text, " --dns ")
	hasHTTP := strings.Contains(text, " --http ")
	switch {
	case hasDNS && hasHTTP:
		errs = append(errs, "renewal service must render exactly one ACME challenge mode")
	case hasDNS:
		if strings.Contains(text, "--http.webroot") {
			errs = append(errs, "DNS-01 renewal service must not include HTTP-01 webroot flags")
		}
	case hasHTTP:
		mustContainText(&errs, text, " --http --http.webroot "+WebrootPath, "renewal service HTTP-01 webroot")
		if strings.Contains(text, "EnvironmentFile=") {
			errs = append(errs, "HTTP-01 renewal service must not include DNS-01 EnvironmentFile")
		}
	default:
		errs = append(errs, "renewal service missing ACME challenge flag")
	}
	if strings.Contains(text, "certbot") || strings.Contains(text, "/etc/letsencrypt") {
		errs = append(errs, "renewal service must not reference Certbot or /etc/letsencrypt")
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func ValidateRenewalTimer(content []byte) error {
	text := string(content)
	var errs []string
	mustContainText(&errs, text, "[Timer]", "renewal timer [Timer] section")
	mustContainText(&errs, text, "OnCalendar=", "renewal timer schedule")
	mustContainText(&errs, text, "RandomizedDelaySec=", "renewal timer randomized delay")
	mustContainText(&errs, text, "Persistent=true", "renewal timer persistence")
	mustContainText(&errs, text, "WantedBy=timers.target", "renewal timer install target")
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func mustContainText(errs *[]string, text string, want string, label string) {
	if !strings.Contains(text, want) {
		*errs = append(*errs, label+" missing")
	}
}

func shellLines(content []byte) []string {
	rawLines := strings.Split(string(content), "\n")
	lines := make([]string, 0, len(rawLines))
	for _, line := range rawLines {
		lines = append(lines, strings.TrimSpace(line))
	}
	return lines
}

func activeShellLines(lines []string) []string {
	active := []string{}
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		active = append(active, line)
	}
	return active
}

func lineIndex(lines []string, want string) int {
	for index, line := range lines {
		if line == want {
			return index
		}
	}
	return -1
}

func lineContainsIndex(lines []string, want string) int {
	for index, line := range lines {
		if strings.Contains(line, want) {
			return index
		}
	}
	return -1
}
