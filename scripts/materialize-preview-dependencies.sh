#!/bin/sh
# Download the exact assets named by a reviewed dependency-inputs lock.
# Unlike resolve-preview-dependencies.sh, this script never queries latest.
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 LOCK_FILE OUTPUT_DIR" >&2
  exit 2
fi
lock=$1
output=$2
for tool in curl jq sha256sum tar gzip; do
  command -v "$tool" >/dev/null 2>&1 || { echo "required command is missing: $tool" >&2; exit 1; }
done
[ -f "$lock" ] || { echo "dependency lock is missing: $lock" >&2; exit 1; }
mkdir -p -- "$output"
output=$(CDPATH= cd -- "$output" && pwd -P)
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd -P)
[ -z "$(find "$output" -mindepth 1 -print -quit)" ] || { echo "output directory must be empty: $output" >&2; exit 1; }
jq -e '.schema_version == "lanpanel.dependency-inputs.v2" and (.dependencies | length == 4)' "$lock" >/dev/null

fetch() {
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time 180 -H 'User-Agent: lanpanel-release' \
    --output "$2" "$1"
}
verify() {
  printf '%s  %s\n' "$2" "$1" | sha256sum --check --status
}

for name in lego tailscale headscale goaccess; do
  source_url=$(jq -er --arg name "$name" '.dependencies[] | select(.name == $name) | .source.url' "$lock")
  archive_path=$(jq -r --arg name "$name" '.dependencies[] | select(.name == $name) | .archive.path' "$lock")
  archive_digest=$(jq -r --arg name "$name" '.dependencies[] | select(.name == $name) | .archive.sha256' "$lock")
  source_path=$(jq -er --arg name "$name" '.dependencies[] | select(.name == $name) | .source.asset.path' "$lock")
  source_digest=$(jq -er --arg name "$name" '.dependencies[] | select(.name == $name) | .source.asset.sha256' "$lock")
  executable_path=$(jq -er --arg name "$name" '.dependencies[] | select(.name == $name) | .executable.path' "$lock")
  executable_digest=$(jq -r --arg name "$name" '.dependencies[] | select(.name == $name) | .executable.sha256' "$lock")
  executable_bytes=$(jq -r --arg name "$name" '.dependencies[] | select(.name == $name) | .executable.bytes' "$lock")
  member=$(jq -er --arg name "$name" '.dependencies[] | select(.name == $name) | .member' "$lock")
  case "$name" in
    goaccess)
      fetch "$source_url" "$output/$source_path"
      verify "$output/$source_path" "$source_digest"
      "$script_dir/build-goaccess.sh" "$output/$source_path" "$output/$executable_path"
      if [ -n "$executable_digest" ] && [ "$executable_bytes" -gt 0 ]; then
        verify "$output/$executable_path" "$executable_digest"
      fi
      rm -f "$output/$source_path"
      ;;
    headscale)
      fetch "$source_url" "$output/$executable_path"
      verify "$output/$executable_path" "$executable_digest"
      chmod 755 "$output/$executable_path"
      # Keep the generated archive on the parser's GNU tar padding contract.
      tar --create --format=ustar --blocking-factor=20 --owner=0 --group=0 --numeric-owner --mode=755 \
        --mtime='UTC 1970-01-01' --directory="$output" --file="$output/headscale.tar" headscale
      gzip -n -c "$output/headscale.tar" > "$output/$archive_path"
      rm -f "$output/headscale.tar"
      verify "$output/$archive_path" "$archive_digest"
      ;;
    *)
      fetch "$source_url" "$output/$archive_path"
      verify "$output/$archive_path" "$archive_digest"
      tar --extract --to-stdout --file "$output/$archive_path" "$member" > "$output/$executable_path"
      verify "$output/$executable_path" "$executable_digest"
      chmod 755 "$output/$executable_path"
      ;;
  esac
done
cp -- "$lock" "$output/dependency-inputs.json"
printf 'Materialized locked dependency assets: %s\n' "$output/dependency-inputs.json"
