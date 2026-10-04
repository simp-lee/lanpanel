#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: $0 VERSION ARTIFACT_URL ARTIFACT_SHA256" >&2
  exit 2
fi
version=$1
url=$2
digest=$3
if ! printf '%s\n' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "version must be a stable semantic release tag such as v0.4.0" >&2
  exit 2
fi
case "$url" in https://*) ;; *) echo "artifact URL must be HTTPS" >&2; exit 2;; esac
if ! printf '%s' "$url" | LC_ALL=C grep -Eq '^https://[A-Za-z0-9._~:/%+@=-]+$'; then
  echo "artifact URL contains unsupported or unsafe characters" >&2
  exit 2
fi
if ! printf '%s\n' "$digest" | grep -Eq '^[0-9a-f]{64}$'; then
  echo "artifact digest must be SHA-256" >&2
  exit 2
fi
cat <<EOF
#!/bin/sh
set -eu
readonly LANPANEL_RELEASE_VERSION='$version'
readonly LANPANEL_RELEASE_URL='$url'
readonly LANPANEL_RELEASE_SHA256='$digest'
tmp=
cleanup() { [ -n "\${tmp:-}" ] && rm -rf -- "\$tmp"; }
trap cleanup EXIT HUP INT TERM
tmp="\$(mktemp -d "\${HOME:?}/.lanpanel-release.XXXXXXXX")"
chmod 700 "\$tmp"
archive="\$tmp/lanpanel-release.tar.gz"
if command -v curl >/dev/null 2>&1; then
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --output "\$archive" "\$LANPANEL_RELEASE_URL"
elif command -v wget >/dev/null 2>&1; then
  wget --https-only --output-document="\$archive" "\$LANPANEL_RELEASE_URL"
else
  echo 'bootstrap requires curl or wget; no alternate source is available' >&2
  exit 1
fi
printf '%s  %s\\n' "\$LANPANEL_RELEASE_SHA256" "\$archive" | sha256sum --check --status
# Stream the already downloaded archive into a root-owned temporary directory.
# The privileged side verifies the stream before extraction, preventing a
# user-writable extracted binary from crossing the privilege boundary.
if [ "\$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 || { echo 'bootstrap requires root or sudo' >&2; exit 1; }
  sudo -v
fi
run_privileged() {
  if [ "\$(id -u)" -eq 0 ]; then
    sh -c "\$1"
  else
    sudo sh -c "\$1"
  fi
}
run_privileged < "\$archive" '
set -eu
tmp="\$(mktemp -d /var/lib/lanpanel-release.XXXXXXXX)"
cleanup() { rm -rf -- "\$tmp"; }
trap cleanup EXIT HUP INT TERM
archive="\$tmp/archive.tar.gz"
cat > "\$archive"
printf "%s  %s\\n" "${digest}" "\$archive" | sha256sum --check --status
mkdir "\$tmp/release"
chmod 700 "\$tmp/release"
tar --extract --file "\$archive" --directory "\$tmp/release" --no-same-owner --no-same-permissions
[ -f "\$tmp/release/lanpanel" ] && [ -x "\$tmp/release/lanpanel" ]
"\$tmp/release/lanpanel" install
'
printf '%s\n' 'LanPanel installation completed successfully.'
EOF
