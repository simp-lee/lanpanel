#!/usr/bin/env bash
set -euo pipefail

binary=${LANPANEL_BINARY:-./lanpanel}
addr=${E2E_ADDR:-127.0.0.1:18080}
base_url="http://${addr}"
tmp_dir=$(mktemp -d "${HOME}/.lanpanel-prod-ui-smoke.XXXXXX")
server_pid=

sanitize_log() {
  local path=$1
  test -f "$path" || return 0
  sed -E 's#/login\?token=[A-Za-z0-9%_.~-]+#/login?token=<redacted>#g' "$path" >&2
}

fail() {
  echo "production ui smoke failed: $*" >&2
  echo "stdout:" >&2
  sanitize_log "$tmp_dir/stdout.log"
  echo "stderr:" >&2
  sanitize_log "$tmp_dir/stderr.log"
  exit 1
}

cleanup() {
  if test -n "$server_pid"; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

if test "$(id -u)" -eq 0; then
  fail "run this smoke as a non-root user so the production root gate is exercised"
fi

command -v curl >/dev/null 2>&1 || fail "curl is required"
test -x "$binary" || fail "binary is not executable: $binary"

state_dir="$tmp_dir/state"
config_path="$tmp_dir/lanpanel.yaml"
app_config_path="$tmp_dir/lanpanel-app.yaml"
cookie_jar="$tmp_dir/cookies.txt"

"$binary" ui \
  --listen "$addr" \
  --state-dir "$state_dir" \
  --config "$config_path" \
  --app-config "$app_config_path" \
  >"$tmp_dir/stdout.log" 2>"$tmp_dir/stderr.log" &
server_pid=$!

startup_url=
for _ in $(seq 1 100); do
  if ! kill -0 "$server_pid" >/dev/null 2>&1; then
    fail "lanpanel ui exited before startup URL was printed"
  fi
  startup_url=$(sed -n 's/^Open once: //p' "$tmp_dir/stdout.log" | head -n 1)
  if test -n "$startup_url"; then
    break
  fi
  sleep 0.1
done
test -n "$startup_url" || fail "timed out waiting for startup URL"
grep -q '^Security: loopback-only management UI; use SSH local forwarding; do not expose this port; startup token is one-time and expires\.$' "$tmp_dir/stdout.log" || fail "startup output missing loopback-only security note"

case "$startup_url" in
  "$base_url"/login\?token=*) ;;
  *) fail "startup URL did not point at the requested loopback listener" ;;
esac

unauth_status=$(curl -sS -o "$tmp_dir/unauth.body" -w '%{http_code}' "$base_url/jobs" || true)
test "$unauth_status" = "401" || fail "unauthenticated /jobs status $unauth_status, want 401"

login_status=
for _ in $(seq 1 100); do
  login_status=$(curl -sS -D "$tmp_dir/login.headers" -o "$tmp_dir/login.body" -w '%{http_code}' -c "$cookie_jar" "$startup_url" || true)
  if test "$login_status" = "303"; then
    break
  fi
  sleep 0.1
done
test "$login_status" = "303" || fail "startup login status $login_status, want 303"
grep -qi '^Set-Cookie: lanpanel_ui_session=' "$tmp_dir/login.headers" || fail "startup login did not set session cookie"
grep -qi 'HttpOnly' "$tmp_dir/login.headers" || fail "session cookie missing HttpOnly"
grep -qi 'SameSite=Strict' "$tmp_dir/login.headers" || fail "session cookie missing SameSite=Strict"
grep -qi '^Location: /' "$tmp_dir/login.headers" || fail "startup login redirect did not strip startup token"
if grep -q '/login?token=' "$tmp_dir/login.headers"; then
  fail "startup login response leaked token URL in headers"
fi

reuse_status=$(curl -sS -o "$tmp_dir/reuse.body" -w '%{http_code}' "$startup_url" || true)
test "$reuse_status" = "403" || fail "reused startup token status $reuse_status, want 403"

jobs_status=$(curl -sS -o "$tmp_dir/jobs.html" -w '%{http_code}' -b "$cookie_jar" "$base_url/jobs" || true)
test "$jobs_status" = "200" || fail "authenticated /jobs status $jobs_status, want 200"
grep -q 'Job Activity' "$tmp_dir/jobs.html" || fail "authenticated /jobs missing Job Activity"
if grep -q '/login?token=' "$tmp_dir/jobs.html"; then
  fail "authenticated /jobs leaked token URL"
fi

settings_status=$(curl -sS -o "$tmp_dir/settings.html" -w '%{http_code}' -b "$cookie_jar" "$base_url/settings" || true)
test "$settings_status" = "200" || fail "authenticated /settings status $settings_status, want 200"
if grep -q '/login?token=' "$tmp_dir/settings.html"; then
  fail "authenticated /settings leaked token URL"
fi
csrf=$(sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p' "$tmp_dir/settings.html" | head -n 1)
test -n "$csrf" || fail "settings page did not expose CSRF token"

csrf_status=$(curl -sS -o "$tmp_dir/no-csrf.body" -w '%{http_code}' -b "$cookie_jar" \
  -X POST "$base_url/jobs/run" \
  --data-urlencode "operation=main_status" \
  --data-urlencode "config_path=$config_path" || true)
test "$csrf_status" = "403" || fail "missing-CSRF write status $csrf_status, want 403"
grep -q 'csrf token required' "$tmp_dir/no-csrf.body" || fail "missing-CSRF write did not return CSRF message"
if find "$state_dir/jobs" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | grep -q .; then
  fail "missing-CSRF write created a job"
fi

write_status=$(curl -sS -o "$tmp_dir/write.body" -w '%{http_code}' -b "$cookie_jar" \
  -X POST "$base_url/jobs/run" \
  --data-urlencode "csrf_token=$csrf" \
  --data-urlencode "operation=main_init" \
  --data-urlencode "config_path=$config_path" || true)
test "$write_status" = "403" || fail "non-root write job status $write_status, want 403"
grep -q 'write operations require sudo lanpanel ui' "$tmp_dir/write.body" || fail "non-root write job did not return root-gate message"

echo "production ui smoke: passed"
