#!/bin/sh
# Build the pinned GoAccess source archive into a release-owned amd64 binary.
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 SOURCE_ARCHIVE OUTPUT_BINARY" >&2
  exit 2
fi
source_archive=$1
output=$2
[ -f "$source_archive" ] || { echo "GoAccess source archive is missing: $source_archive" >&2; exit 1; }
for tool in tar gzip make cc strip; do
  command -v "$tool" >/dev/null 2>&1 || { echo "required GoAccess build command is missing: $tool" >&2; exit 1; }
done

work=$(mktemp -d "${TMPDIR:-/tmp}/lanpanel-goaccess-build.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

tar --extract --gzip --file "$source_archive" --directory "$work"
source_dir=$(find "$work" -mindepth 1 -maxdepth 1 -type d -name 'goaccess-*' -print -quit)
[ -n "$source_dir" ] || { echo "GoAccess source archive has no goaccess-* directory" >&2; exit 1; }

# Build with UTF-8 support. GeoIP is deliberately omitted: it is not part of
# the LanPanel analytics contract and avoiding it removes another native
# runtime dependency.
(
  cd "$source_dir"
  # Static linking removes the target host's ncurses/glibc builder baseline
  # from the runtime dependency contract. The glibc NSS warning is harmless
  # here because LanPanel runs GoAccess as its fixed non-root service user.
  LIBS="-ltinfo -ldl" LDFLAGS="-static" ./configure --enable-utf8 --disable-geoip
  make -j2
)
[ -x "$source_dir/goaccess" ] || { echo "GoAccess build did not produce an executable" >&2; exit 1; }
mkdir -p -- "$(dirname "$output")"
install -m 0755 "$source_dir/goaccess" "$output"
strip --strip-unneeded "$output"
