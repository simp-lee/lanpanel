#!/bin/sh
# Resolve latest stable upstream assets once. Subsequent builds use the lock.
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 OUTPUT_DIR" >&2
  exit 2
fi
output=$1
for tool in curl jq sha256sum tar gzip awk wc; do
  command -v "$tool" >/dev/null 2>&1 || { echo "required command is missing: $tool" >&2; exit 1; }
done
mkdir -p -- "$output"
output=$(CDPATH= cd -- "$output" && pwd -P)
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd -P)
if [ -n "$(find "$output" -mindepth 1 -print -quit)" ]; then
  echo "output directory must be empty: $output" >&2
  exit 1
fi
work=$(mktemp -d "${TMPDIR:-/tmp}/lanpanel-dependencies.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

fetch() {
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time 180 -H 'User-Agent: lanpanel-release' \
    --output "$2" "$1"
}
latest() {
  fetch "https://api.github.com/repos/$1/releases/latest" "$2"
  jq -e '.draft == false and .prerelease == false' "$2" >/dev/null
}
asset_url() {
  jq -er --arg name "$2" '[.assets[] | select(.name == $name) | .browser_download_url] | if length == 1 then .[0] else error("missing or duplicate upstream asset: " + $name) end' "$1"
}
verify() {
  expected=$(awk -v name="$3" '$2 == name || $2 == "*" name {print $1}' "$2")
  case "$expected" in ''|*[!0-9a-f]*) echo "invalid upstream checksum for $3" >&2; exit 1 ;; esac
  [ "${#expected}" -eq 64 ] || { echo "missing or duplicate upstream checksum for $3" >&2; exit 1; }
  printf '%s  %s\n' "$expected" "$1" | sha256sum --check --status
}
identity() {
  jq -cn --arg path "$2" --arg sha256 "$(sha256sum "$1" | awk '{print $1}')" \
    --argjson bytes "$(wc -c < "$1")" '{path:$path,sha256:$sha256,bytes:$bytes}'
}

printf 'Resolving Lego latest stable release...\n'
latest go-acme/lego "$work/lego-release.json"
lego_version=$(jq -er '.tag_name | ltrimstr("v")' "$work/lego-release.json")
lego_name="lego_v${lego_version}_linux_amd64.tar.gz"
lego_url=$(asset_url "$work/lego-release.json" "$lego_name")
fetch "$lego_url" "$work/lego.tar.gz"
fetch "$(asset_url "$work/lego-release.json" "lego_${lego_version}_checksums.txt")" "$work/lego-checksums"
verify "$work/lego.tar.gz" "$work/lego-checksums" "$lego_name"
tar --extract --to-stdout --file "$work/lego.tar.gz" lego > "$work/lego"
chmod 755 "$work/lego"

printf 'Resolving Tailscale latest stable release...\n'
latest tailscale/tailscale "$work/tailscale-release.json"
tailscale_version=$(jq -er '.tag_name | ltrimstr("v")' "$work/tailscale-release.json")
tailscale_url="https://pkgs.tailscale.com/stable/tailscale_${tailscale_version}_amd64.tgz"
fetch "$tailscale_url" "$work/tailscale.tar.gz"
fetch "$tailscale_url.sha256" "$work/tailscale-sha256"
printf '%s  tailscale.tar.gz\n' "$(tr -d '\r\n' < "$work/tailscale-sha256")" > "$work/tailscale-checksums"
verify "$work/tailscale.tar.gz" "$work/tailscale-checksums" tailscale.tar.gz
tailscale_member="tailscale_${tailscale_version}_amd64/tailscale"
tar --extract --to-stdout --file "$work/tailscale.tar.gz" "$tailscale_member" > "$work/tailscale"
chmod 755 "$work/tailscale"

printf 'Resolving Headscale latest stable release...\n'
latest juanfont/headscale "$work/headscale-release.json"
headscale_version=$(jq -er '.tag_name | ltrimstr("v")' "$work/headscale-release.json")
headscale_name="headscale_${headscale_version}_linux_amd64"
headscale_url=$(asset_url "$work/headscale-release.json" "$headscale_name")
fetch "$headscale_url" "$work/headscale"
fetch "$(asset_url "$work/headscale-release.json" checksums.txt)" "$work/headscale-checksums"
verify "$work/headscale" "$work/headscale-checksums" "$headscale_name"
chmod 755 "$work/headscale"
# Upstream distributes a raw executable; the installation contract uses a
# single-member archive. Keep its identity separate from the upstream binary.
# The archive parser accepts GNU tar's zero-filled 20-block record padding.
tar --create --format=ustar --blocking-factor=20 --owner=0 --group=0 --numeric-owner --mode=755 \
  --mtime='UTC 1970-01-01' --directory="$work" --file="$work/headscale.tar" headscale
gzip -n -c "$work/headscale.tar" > "$work/headscale.tar.gz"

# GoAccess does not publish a portable binary asset. Pin the current stable
# source release at build time, verify its official archive digest, and build
# the release-owned binary in the controlled release environment.
goaccess_version="${GOACCESS_VERSION:-1.12}"
goaccess_source_url="https://tar.goaccess.io/goaccess-${goaccess_version}.tar.gz"
goaccess_source_sha256="${GOACCESS_SOURCE_SHA256:-3aef5f6d5061decc6fc4946339b3a61b170bd256f80b4e861194b095df83ec86}"
fetch "https://goaccess.io/download" "$work/goaccess-metadata"
fetch "$goaccess_source_url" "$work/goaccess-source.tar.gz"
printf '%s  %s\n' "$goaccess_source_sha256" "$work/goaccess-source.tar.gz" | sha256sum --check --status
"$script_dir/build-goaccess.sh" "$work/goaccess-source.tar.gz" "$work/goaccess"

jq -cjn \
  --arg lv "$lego_version" --arg lu "$lego_url" --arg lm "https://api.github.com/repos/go-acme/lego/releases/latest" --arg ld "$(sha256sum "$work/lego-release.json" | awk '{print $1}')" --arg lp "$(jq -er '.published_at' "$work/lego-release.json")" \
  --arg tv "$tailscale_version" --arg tu "$tailscale_url" --arg tm "$tailscale_member" --arg tmmeta "https://api.github.com/repos/tailscale/tailscale/releases/latest" --arg td "$(sha256sum "$work/tailscale-release.json" | awk '{print $1}')" --arg tp "$(jq -er '.published_at' "$work/tailscale-release.json")" \
  --arg hv "$headscale_version" --arg hu "$headscale_url" --arg hm "https://api.github.com/repos/juanfont/headscale/releases/latest" --arg hd "$(sha256sum "$work/headscale-release.json" | awk '{print $1}')" --arg hp "$(jq -er '.published_at' "$work/headscale-release.json")" \
  --arg gv "$goaccess_version" --arg gu "$goaccess_source_url" --arg gm "https://goaccess.io/download" --arg gd "$(sha256sum "$work/goaccess-metadata" | awk '{print $1}')" --arg gp "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
  --argjson ga "$(identity "$work/goaccess-source.tar.gz" goaccess-source.tar.gz)" \
  --argjson ge '{"path":"goaccess","sha256":"","bytes":0}' \
  --argjson la "$(identity "$work/lego.tar.gz" lego.tar.gz)" \
  --argjson le "$(identity "$work/lego" lego)" \
  --argjson ta "$(identity "$work/tailscale.tar.gz" tailscale.tar.gz)" \
  --argjson te "$(identity "$work/tailscale" tailscale)" \
  --argjson ha "$(identity "$work/headscale.tar.gz" headscale.tar.gz)" \
  --argjson he "$(identity "$work/headscale" headscale)" \
  '{schema_version:"lanpanel.dependency-inputs.v2",dependencies:[
    {name:"lego",version:$lv,metadata_source:$lm,metadata_digest:$ld,published_at:$lp,source:{url:$lu,format:"tar_gzip",asset:$la},archive:$la,executable:$le,member:"lego"},
    {name:"tailscale",version:$tv,metadata_source:$tmmeta,metadata_digest:$td,published_at:$tp,source:{url:$tu,format:"tar_gzip",asset:$ta},archive:$ta,executable:$te,member:$tm},
    {name:"headscale",version:$hv,metadata_source:$hm,metadata_digest:$hd,published_at:$hp,source:{url:$hu,format:"executable",asset:$he},archive:$ha,executable:$he,member:"headscale"},
    {name:"goaccess",version:$gv,metadata_source:$gm,metadata_digest:$gd,published_at:$gp,source:{url:$gu,format:"source_tar_gzip",asset:$ga},archive:{path:"",sha256:"",bytes:0},executable:$ge,member:"goaccess"}
  ]}' > "$work/dependency-inputs.json"
for file in lego.tar.gz lego tailscale.tar.gz tailscale headscale.tar.gz headscale goaccess dependency-inputs.json; do
  mv -- "$work/$file" "$output/$file"
done
printf 'Verified dependency assets and lock: %s/dependency-inputs.json\n' "$output"
