#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: $0 VERSION ARTIFACT_URL ARTIFACT_SHA256" >&2
  exit 2
fi
version=$1
url=$2
digest=$3
case "$version" in v[0-9]*-preview) ;; *) echo "version must be a fixed vN...-preview release" >&2; exit 2;; esac
case "$url" in https://*) ;; *) echo "artifact URL must be HTTPS" >&2; exit 2;; esac
if ! printf '%s' "$url" | LC_ALL=C grep -Eq '^https://[A-Za-z0-9._~:/%+@=-]+$'; then
  echo "artifact URL contains unsupported or unsafe characters" >&2
  exit 2
fi
case "$digest" in [0-9a-f]*) [ "${#digest}" -eq 64 ] || { echo "artifact digest must be SHA-256" >&2; exit 2; } ;; *) echo "artifact digest must be SHA-256" >&2; exit 2;; esac
cat <<EOF
#!/bin/sh
set -eu
readonly LANPANEL_PREVIEW_VERSION='$version'
readonly LANPANEL_PREVIEW_URL='$url'
readonly LANPANEL_PREVIEW_SHA256='$digest'
tmp=
cleanup() { [ -n "\${tmp:-}" ] && rm -rf -- "\$tmp"; }
trap cleanup EXIT HUP INT TERM
tmp="\$(mktemp -d "\${HOME:?}/.lanpanel-preview.XXXXXXXX")"
chmod 700 "\$tmp"
archive="\$tmp/lanpanel-preview.tar.gz"
if command -v curl >/dev/null 2>&1; then
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --output "\$archive" "\$LANPANEL_PREVIEW_URL"
elif command -v wget >/dev/null 2>&1; then
  wget --https-only --output-document="\$archive" "\$LANPANEL_PREVIEW_URL"
else
  echo 'bootstrap requires curl or wget; no alternate source is available' >&2
  exit 1
fi
printf '%s  %s\\n' "\$LANPANEL_PREVIEW_SHA256" "\$archive" | sha256sum --check --status
# Stream the already downloaded archive into a root-owned temporary directory.
# The privileged side verifies the stream before extraction, preventing a
# user-writable extracted binary from crossing the sudo boundary.
cat "\$archive" | sudo sh -c '
set -eu
tmp="\$(mktemp -d /root/.lanpanel-preview.XXXXXXXX)"
cleanup() { rm -rf -- "\$tmp"; }
trap cleanup EXIT HUP INT TERM
archive="\$tmp/archive.tar.gz"
cat > "\$archive"
printf "%s  %s\\n" "${digest}" "\$archive" | sha256sum --check --status
mkdir "\$tmp/release"
tar --extract --file "\$archive" --directory "\$tmp/release" --no-same-owner --no-same-permissions
[ -f "\$tmp/release/lanpanel" ] && [ -x "\$tmp/release/lanpanel" ]
"\$tmp/release/lanpanel" install
'
EOF
