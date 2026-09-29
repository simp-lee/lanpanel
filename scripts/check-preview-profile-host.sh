#!/bin/sh
# Read-only qualification check for a Preview profile capture host.
set -eu

target=${1:-debian}
case "$target" in
  debian|ubuntu) family=$target ;;
  *) echo "usage: $0 [debian|ubuntu]" >&2; exit 2 ;;
esac

fail=0
check() {
  label=$1
  shift
  if "$@"; then
    printf 'ok: %s\n' "$label"
  else
    printf 'fail: %s\n' "$label" >&2
    fail=1
  fi
}

check_os() {
  [ -r /etc/os-release ] || return 1
  . /etc/os-release
  [ "$ID" = "$family" ] && [ -n "$VERSION_ID" ]
}
check_arch() { [ "$(dpkg --print-architecture 2>/dev/null)" = amd64 ] && [ "$(uname -m)" = x86_64 ]; }
check_systemd() { [ -r /proc/1/comm ] && [ "$(cat /proc/1/comm 2>/dev/null)" = systemd ]; }
check_cgroup() { [ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" = cgroup2fs ] && [ -r /sys/fs/cgroup/cgroup.controllers ]; }
check_dpkg() { command -v apt-get >/dev/null 2>&1 && command -v dpkg >/dev/null 2>&1 && [ -z "$(dpkg --audit 2>/dev/null)" ]; }
check_packages() {
  for package in systemd nginx; do
    if ! dpkg-query -W -f='${db:Status-Status} ${Version}\n' "$package" 2>/dev/null | grep -q '^installed '; then
      return 1
    fi
  done
}
check_distribution_sources() {
  files=/etc/apt/sources.list
  if [ -d /etc/apt/sources.list.d ]; then
    files="$files /etc/apt/sources.list.d/*"
  fi
  # Do not inherit vendor repositories or their keys into the profile.
  ! grep -RhsE 'apt\.postgresql\.org|pkgs\.tailscale\.com|packages\.microsoft\.com' $files 2>/dev/null | grep -q . || return 1
  # The user owns the mirror choice. Require an APT source, while leaving
  # URI, keyring, and signature policy to the native APT configuration.
  grep -RhsE '^[[:space:]]*deb([[:space:]]|\[)|^[[:space:]]*Types:[[:space:]]*deb([[:space:]]|$)' $files 2>/dev/null | grep -q .
}

check "$target family" check_os
check 'amd64' check_arch
check 'systemd available' check_systemd
check 'unified cgroup v2' check_cgroup
check 'dpkg healthy' check_dpkg
check 'profile packages installed' check_packages
check 'only selected distribution archive sources' check_distribution_sources

if [ "$fail" -ne 0 ]; then
  echo 'profile host is not qualified; no files were changed' >&2
  exit 1
fi
echo "$target amd64 family host is qualified (read-only check)"
