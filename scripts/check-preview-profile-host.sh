#!/bin/sh
# Read-only qualification check for a Host Capability Contract capture host.
set -eu

target=${1:-capability-host}
case "$target" in
  capability-host|apt-dpkg-systemd) ;;
  *) echo "usage: $0 [capability-host]" >&2; exit 2 ;;
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

check_os() { [ "$(uname -s)" = Linux ]; }
check_arch() { [ "$(dpkg --print-architecture 2>/dev/null)" = amd64 ] && [ "$(uname -m)" = x86_64 ]; }
check_systemd() { [ -r /proc/1/comm ] && [ "$(cat /proc/1/comm 2>/dev/null)" = systemd ] && command -v systemd-run >/dev/null 2>&1; }
check_cgroup() {
  [ -z "$(awk 'function separator(){ for (i=1; i<=NF; i++) if ($i == "-") return i } { s=separator(); if (s && $(s+1) == "cgroup") print }' /proc/self/mountinfo)" ] || return 1
  mountpoint=$(awk 'function separator(){ for (i=1; i<=NF; i++) if ($i == "-") return i } { s=separator(); if (s && $(s+1) == "cgroup2" && $4 == "/") { print $5; count++ } } END { if (count == 1) exit 0; exit 1 }' /proc/self/mountinfo) || return 1
  [ -s "$mountpoint/cgroup.controllers" ] || return 1
  self_cgroup=$(awk -F: '$1 == 0 { print $3 }' /proc/self/cgroup)
  [ -n "$self_cgroup" ] && [ -f "$mountpoint${self_cgroup}/cgroup.procs" ] && [ -f "$mountpoint${self_cgroup}/cgroup.events" ]
}
check_systemd_delegation() {
  command -v systemd >/dev/null 2>&1 || return 1
  major=$(systemd --version 2>/dev/null | awk 'NR == 1 { print $2 }')
  [ -n "$major" ] && [ "$major" -ge 218 ]
}
check_dpkg() { command -v apt-get >/dev/null 2>&1 && command -v dpkg >/dev/null 2>&1 && [ -z "$(dpkg --audit 2>/dev/null)" ]; }
check_packages() {
  candidate=$(apt-cache policy nginx 2>/dev/null | awk '/^[[:space:]]*Candidate:/ { print $2; exit }')
  [ -n "$candidate" ] && [ "$candidate" != '(none)' ]
}
check_distribution_sources() {
  command -v apt-get >/dev/null 2>&1 && command -v dpkg >/dev/null 2>&1 && command -v apt-cache >/dev/null 2>&1
}

check 'Linux host identity' check_os
check 'amd64' check_arch
check 'systemd service manager' check_systemd
check 'complete unified cgroup v2 topology and control files' check_cgroup
check 'systemd delegation prerequisite' check_systemd_delegation
check 'APT/dpkg healthy' check_dpkg
check 'Nginx APT candidate available' check_packages
check 'APT/dpkg toolchain' check_distribution_sources

if [ "$fail" -ne 0 ]; then
  echo 'capability contract host is not qualified; no files were changed' >&2
  exit 1
fi
echo "$target amd64 APT/dpkg + systemd capability host is qualified (read-only check)"
