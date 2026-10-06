#!/bin/sh
# Prepare pinned local ACME test tools in a temporary directory and run the
# real Pebble DNS-01 round trip. Set PEBBLE_BIN, CHALLTESTSRV_BIN, or LEGO_BIN
# to reuse an existing executable; unset values are prepared temporarily.
set -eu

repo=$(CDPATH=; cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/lanpanel-local-acme.XXXXXX")
cleanup() {
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

command -v go >/dev/null 2>&1 || { echo 'Go is required for the local ACME test' >&2; exit 2; }
command -v curl >/dev/null 2>&1 || { echo 'curl is required for the local ACME test' >&2; exit 2; }
command -v jq >/dev/null 2>&1 || { echo 'jq is required for the local ACME test' >&2; exit 2; }
command -v sha256sum >/dev/null 2>&1 || { echo 'sha256sum is required for the local ACME test' >&2; exit 2; }
command -v tar >/dev/null 2>&1 || { echo 'tar is required for the local ACME test' >&2; exit 2; }

pebble=${PEBBLE_BIN:-}
challtestsrv=${CHALLTESTSRV_BIN:-}
lego=${LEGO_BIN:-}
pebble_version=${PEBBLE_VERSION:-v1.0.1}

mkdir -p "$work/bin"
if [ -z "$pebble" ]; then
  GOBIN="$work/bin" go install "github.com/letsencrypt/pebble/cmd/pebble@${pebble_version}"
  pebble="$work/bin/pebble"
fi
if [ -z "$challtestsrv" ]; then
  GOBIN="$work/bin" go install "github.com/letsencrypt/pebble/cmd/pebble-challtestsrv@${pebble_version}"
  challtestsrv="$work/bin/pebble-challtestsrv"
fi
if [ -z "$lego" ]; then
  lego_version=${LEGO_VERSION:-5.4.1}
  lego_url=$(jq -er --arg version "$lego_version" '.dependencies[] | select(.name == "lego" and .version == $version) | .source.url' "$repo/release-inputs/dependency-inputs.v2.json")
  lego_digest=$(jq -er --arg version "$lego_version" '.dependencies[] | select(.name == "lego" and .version == $version) | .source.asset.sha256' "$repo/release-inputs/dependency-inputs.v2.json")
  curl --fail --location --silent --show-error --retry 3 --output "$work/lego.tar.gz" "$lego_url"
  printf '%s  %s\n' "$lego_digest" "$work/lego.tar.gz" | sha256sum -c -
  mkdir -p "$work/lego"
  tar -xzf "$work/lego.tar.gz" -C "$work/lego"
  lego="$work/lego/lego"
fi

for tool in "$pebble" "$challtestsrv" "$lego"; do
  if [ ! -x "$tool" ]; then
    echo "local ACME test executable is missing or not executable: $tool" >&2
    exit 1
  fi
done

PEBBLE_BIN="$pebble" CHALLTESTSRV_BIN="$challtestsrv" LEGO_BIN="$lego" "$repo/scripts/test-pebble-dns01.sh"
printf '%s\n' 'Local Pebble DNS-01 round trip passed; temporary tool directory removed on exit.'
