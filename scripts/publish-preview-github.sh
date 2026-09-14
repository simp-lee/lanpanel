#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 TAG OUTPUT_DIR" >&2
  exit 2
fi
tag=$1
output=$2
repo=${GITHUB_REPOSITORY:-simp-lee/lanpanel}
case "$tag" in v[0-9]*-preview) ;; *) echo "tag must be a fixed vN...-preview release" >&2; exit 2;; esac
command -v gh >/dev/null 2>&1 || { echo "gh CLI is required for GitHub publishing" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "curl is required for post-upload verification" >&2; exit 1; }
archive_name="lanpanel-$tag-linux-amd64.tar.gz"
archive="$output/$archive_name"
bootstrap="$output/lanpanel-bootstrap.sh"
[ -f "$archive" ] && [ -f "$bootstrap" ] || { echo "release output is incomplete" >&2; exit 1; }
if gh release view "$tag" --repo "$repo" >/dev/null 2>&1; then
  echo "GitHub release already exists and will not be overwritten: $repo $tag" >&2
  exit 1
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/lanpanel-publish.XXXXXXXX")
cleanup() { rm -rf -- "$tmp"; }
trap cleanup EXIT
archive_digest=$(sha256sum "$archive" | awk '{print $1}')
base="https://github.com/$repo/releases/download/$tag"
expected_archive_url="$base/$archive_name"
bootstrap_url="$base/lanpanel-bootstrap.sh"
embedded_url=$(sed -n "s/^readonly LANPANEL_PREVIEW_URL='\(.*\)'$/\1/p" "$bootstrap")
embedded_digest=$(sed -n "s/^readonly LANPANEL_PREVIEW_SHA256='\([0-9a-f]*\)'$/\1/p" "$bootstrap")
[ "$embedded_url" = "$expected_archive_url" ] || { echo "bootstrap URL is not the GitHub release archive URL" >&2; exit 1; }
[ "$embedded_digest" = "$archive_digest" ] || { echo "bootstrap digest does not match the local archive" >&2; exit 1; }

# Keep the release draft until the uploaded asset bytes have been checked.
gh release create "$tag" --repo "$repo" --draft --title "LanPanel $tag" --notes "LanPanel Preview $tag" "$archive" "$bootstrap"
gh release download "$tag" --repo "$repo" --pattern "$archive_name" --dir "$tmp" --clobber
[ "$(sha256sum "$tmp/$archive_name" | awk '{print $1}')" = "$archive_digest" ] || { echo "GitHub asset differs from local archive" >&2; exit 1; }
gh release edit "$tag" --repo "$repo" --draft=false

fetch="$tmp/public.tar.gz"
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 180 -o "$fetch" "$expected_archive_url"
[ "$(sha256sum "$fetch" | awk '{print $1}')" = "$archive_digest" ] || { echo "public GitHub archive differs after release publication" >&2; exit 1; }
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 60 -o "$tmp/public-bootstrap.sh" "$bootstrap_url"
public_url=$(sed -n "s/^readonly LANPANEL_PREVIEW_URL='\(.*\)'$/\1/p" "$tmp/public-bootstrap.sh")
public_digest=$(sed -n "s/^readonly LANPANEL_PREVIEW_SHA256='\([0-9a-f]*\)'$/\1/p" "$tmp/public-bootstrap.sh")
[ "$public_url" = "$expected_archive_url" ] && [ "$public_digest" = "$archive_digest" ] || { echo "public bootstrap is not bound to the published archive" >&2; exit 1; }
printf 'published and verified: %s/%s\n' "$repo" "$tag"
printf 'install: curl -fL %s -o /tmp/lanpanel-bootstrap.sh && sudo /tmp/lanpanel-bootstrap.sh install\n' "$bootstrap_url"
