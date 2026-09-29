#!/bin/sh
# Read-only qualification check for a Preview profile capture host.
set -eu

target=${1:-debian-12}
case "$target" in
  debian) family=debian; version="" ;;
  ubuntu) family=ubuntu; version="" ;;
  debian-*) family=debian; version=${target#debian-} ;;
  ubuntu-*) family=ubuntu; version=${target#ubuntu-} ;;
  *) echo "usage: $0 [debian[-VERSION]|ubuntu[-VERSION]]" >&2; exit 2 ;;
esac
case "$version" in
  ""|[0-9]*.[0-9]*|[0-9]*) ;;
  *) echo "invalid target release: $version" >&2; exit 2 ;;
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
  [ "$ID" = "$family" ] && { [ -z "$version" ] || [ "$VERSION_ID" = "$version" ]; }
}
check_arch() { [ "$(dpkg --print-architecture 2>/dev/null)" = amd64 ] && [ "$(uname -m)" = x86_64 ]; }
check_systemd() { [ -r /proc/1/comm ] && [ "$(cat /proc/1/comm 2>/dev/null)" = systemd ]; }
check_cgroup() {
  [ "$(findmnt -rn -t cgroup2 -o TARGET,ROOT 2>/dev/null | awk '$1 == "/sys/fs/cgroup" && $2 == "/" { count++ } END { print count + 0 }')" = 1 ] || return 1
  [ "$(findmnt -rn -t cgroup2 -o TARGET 2>/dev/null | wc -l)" = 1 ] || return 1
  [ -s /sys/fs/cgroup/cgroup.controllers ] || return 1
  self_cgroup=$(awk -F: '$1 == 0 { print $3 }' /proc/self/cgroup)
  [ -n "$self_cgroup" ] && [ -f "/sys/fs/cgroup${self_cgroup}/cgroup.kill" ]
}
check_systemd_delegation() {
  command -v systemd >/dev/null 2>&1 || return 1
  major=$(systemd --version 2>/dev/null | awk 'NR == 1 { print $2 }')
  [ -n "$major" ] && [ "$major" -ge 218 ]
}
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

check "$target exact OS release" check_os
check 'amd64' check_arch
check 'systemd available' check_systemd
check 'complete unified cgroup v2 topology and cgroup.kill' check_cgroup
check 'systemd Delegate= capability' check_systemd_delegation
check 'dpkg healthy' check_dpkg
check 'profile packages installed' check_packages
check 'only selected distribution archive sources' check_distribution_sources

if [ "$fail" -ne 0 ]; then
  echo 'profile host is not qualified; no files were changed' >&2
  exit 1
fi
echo "$target amd64 family host is qualified (read-only check)"
