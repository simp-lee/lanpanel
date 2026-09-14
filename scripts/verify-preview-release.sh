#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 ARTIFACT_DIR" >&2
  exit 2
fi
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd -P)
cd "$root"
exec go run ./cmd/lanpanel-release --verify-dir "$1"
