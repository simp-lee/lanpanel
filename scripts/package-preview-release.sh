#!/bin/sh
set -eu

usage() {
  echo "usage: $0 VERSION ARTIFACT_DIR DOWNLOAD_BASE_URL OUTPUT_DIR" >&2
  echo "example: $0 vMAJOR.MINOR.PATCH dist/release https://github.com/simp-lee/lanpanel/releases/download/vMAJOR.MINOR.PATCH dist/releases" >&2
}

if [ "$#" -ne 4 ]; then
  usage
  exit 2
fi
version=$1
artifact_dir=$2
base_url=$3
output_dir=$4

if ! printf '%s\n' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "version must be a stable semantic release tag such as vMAJOR.MINOR.PATCH" >&2
  exit 2
fi
case "$base_url" in
  https://*) ;;
  *) echo "download base URL must be HTTPS" >&2; exit 2 ;;
esac
case "$base_url" in
  *"'"*|*'"'*|*'\\'*|*' '*|*'?'*|*'#'*)
    echo "download base URL must not contain shell or URL query characters" >&2
    exit 2
    ;;
esac

if [ ! -d "$artifact_dir" ] || [ ! -r "$artifact_dir" ]; then
  echo "release artifact directory is missing or unreadable: $artifact_dir" >&2
  exit 1
fi
if [ ! -f "$artifact_dir/lanpanel" ] || [ ! -x "$artifact_dir/lanpanel" ]; then
  echo "release artifact lanpanel must be a regular executable" >&2
  exit 1
fi
if [ ! -f "$artifact_dir/release.json" ] || [ ! -f "$artifact_dir/SHA256SUMS" ]; then
  echo "release artifact is missing release.json or SHA256SUMS" >&2
  exit 1
fi

# The installer rejects symlinks and special files. Reject them before creating
# an archive so the published bundle cannot differ from the directory contract.
if find -P "$artifact_dir" \( -type l -o -type b -o -type c -o -type p -o -type s \) -print -quit | grep -q .; then
  echo "release artifact contains a symlink or special file" >&2
  exit 1
fi
"$(dirname "$0")/verify-preview-release.sh" "$artifact_dir"

mkdir -p "$output_dir"
output_dir=$(CDPATH= cd -- "$output_dir" && pwd -P)
artifact_dir=$(CDPATH= cd -- "$artifact_dir" && pwd -P)
archive_name="lanpanel-$version-linux-amd64.tar.gz"
archive="$output_dir/$archive_name"
bootstrap="$output_dir/lanpanel-bootstrap.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/lanpanel-release.XXXXXXXX")
cleanup() { rm -rf -- "$tmp"; }
trap cleanup EXIT HUP INT TERM

# GNU tar is required for deterministic ordering and metadata. The release
# archive is the outer bundle; release.json continues to authority-bind every
# member inside it.
if ! tar --version 2>/dev/null | grep -q 'GNU tar'; then
  echo "GNU tar is required for deterministic release packaging" >&2
  exit 1
fi
if ! gzip --version 2>/dev/null | grep -q 'gzip'; then
  echo "gzip is required for release packaging" >&2
  exit 1
fi
(
  cd "$artifact_dir"
  find . -mindepth 1 -print0 | LC_ALL=C sort -z |
    tar --null --no-recursion --directory="$artifact_dir" \
      --create --format=ustar --owner=0 --group=0 --numeric-owner \
      --mtime='UTC 1970-01-01' --sort=name --file="$tmp/release.tar" \
      --files-from=-
)
gzip -n -c "$tmp/release.tar" > "$archive"
chmod 644 "$archive"

archive_digest=$(sha256sum "$archive" | awk '{print $1}')
base_url=${base_url%/}
artifact_url="$base_url/$archive_name"
"$(dirname "$0")/generate-preview-bootstrap.sh" "$version" "$artifact_url" "$archive_digest" > "$tmp/lanpanel-bootstrap.sh"
chmod 755 "$tmp/lanpanel-bootstrap.sh"
mv "$tmp/lanpanel-bootstrap.sh" "$bootstrap"

printf 'release archive: %s\n' "$archive"
printf 'release archive sha256: %s\n' "$archive_digest"
printf 'bootstrap script: %s\n' "$bootstrap"
