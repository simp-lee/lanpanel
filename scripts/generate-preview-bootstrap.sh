#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL

if [ "$#" -ne 3 ]; then
  echo "usage: $0 VERSION ARTIFACT_URL ARTIFACT_SHA256" >&2
  exit 2
fi
version=$1
url=$2
digest=$3
case "$version" in
  *[![:print:]]*) echo "version must be a single printable line" >&2; exit 2 ;;
esac
case "$url" in
  *[![:print:]]*) echo "artifact URL must be a single printable line" >&2; exit 2 ;;
esac
case "$digest" in
  *[![:print:]]*) echo "artifact digest must be a single printable line" >&2; exit 2 ;;
esac
if ! printf '%s' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "version must be a stable semantic release tag such as vMAJOR.MINOR.PATCH" >&2
  exit 2
fi
case "$url" in https://*) ;; *) echo "artifact URL must be HTTPS" >&2; exit 2;; esac
if ! printf '%s' "$url" | LC_ALL=C grep -Eq '^https://[A-Za-z0-9._~:/%+@=-]+$'; then
  echo "artifact URL contains unsupported or unsafe characters" >&2
  exit 2
fi
if ! printf '%s' "$digest" | grep -Eq '^[0-9a-f]{64}$'; then
  echo "artifact digest must be SHA-256" >&2
  exit 2
fi
cat <<EOF
#!/bin/sh
set -eu
readonly LANPANEL_RELEASE_VERSION='$version'
readonly LANPANEL_RELEASE_URL='$url'
readonly LANPANEL_RELEASE_SHA256='$digest'
started_at="\$(date +%s)"
stage() {
  now="\$(date +%s)"
  elapsed=\$((now - started_at))
  printf '[LanPanel +%ss] %s\\n' "\$elapsed" "\$1"
}
tmp=
cleanup() {
  status=\$?
  trap - HUP INT TERM
  if [ "\$status" -ne 0 ]; then
    printf '[LanPanel] installation failed after %ss.\\n' "\$((\$(date +%s) - started_at))" >&2 || :
    printf '[LanPanel] diagnostic log: /var/log/lanpanel/install.log (when available); journal: /var/lib/lanpanel.bootstrap-journal; rerun the same command to resume.\\n' >&2 || :
  fi
  [ -n "\${tmp:-}" ] && rm -rf -- "\$tmp" || :
  exit "\$status"
}
trap cleanup EXIT
trap "exit 129" HUP
trap "exit 130" INT
trap "exit 143" TERM
stage 'Preparing a private download directory'
tmp="\$(mktemp -d "\${TMPDIR:-/tmp}/lanpanel-release.XXXXXXXX")"
chmod 700 "\$tmp"
archive="\$tmp/lanpanel-release.tar.gz"
stage 'Downloading the LanPanel release archive'
if command -v curl >/dev/null 2>&1; then
  if [ -t 2 ]; then
    curl --fail --show-error --location --proto '=https' --tlsv1.2 --progress-bar --output "\$archive" "\$LANPANEL_RELEASE_URL"
  else
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --output "\$archive" "\$LANPANEL_RELEASE_URL"
  fi
elif command -v wget >/dev/null 2>&1; then
  if [ -t 2 ]; then
    wget --https-only --show-progress --output-document="\$archive" "\$LANPANEL_RELEASE_URL"
  else
    wget --https-only --quiet --output-document="\$archive" "\$LANPANEL_RELEASE_URL"
  fi
else
  echo 'bootstrap requires curl or wget; no alternate source is available' >&2
  exit 1
fi
stage 'Verifying the release archive SHA-256'
printf '%s  %s\\n' "\$LANPANEL_RELEASE_SHA256" "\$archive" | sha256sum --check --status
# Stream the already downloaded archive into a root-owned temporary directory.
# The privileged side verifies the stream before extraction, preventing a
# user-writable extracted binary from crossing the privilege boundary.
stage 'Requesting root installation privileges'
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
started_at="\$(date +%s)"
stage() {
  now="\$(date +%s)"
  elapsed=\$((now - started_at))
  printf "[LanPanel +%ss] %s\\n" "\$elapsed" "\$1"
}
tmp="\$(mktemp -d /var/lib/lanpanel-release.XXXXXXXX)"
cleanup() {
  status=\$?
  trap - HUP INT TERM
  if [ "\$status" -ne 0 ]; then
    printf "[LanPanel] installer failed after %ss.\\n" "\$((\$(date +%s) - started_at))" >&2 || :
    printf "[LanPanel] diagnostic log: /var/log/lanpanel/install.log (when available); journal: /var/lib/lanpanel.bootstrap-journal; the package journal retains resumable state.\\n" >&2 || :
  fi
  rm -rf -- "\$tmp" || :
  exit "\$status"
}
trap cleanup EXIT
trap "exit 129" HUP
trap "exit 130" INT
trap "exit 143" TERM
archive="\$tmp/archive.tar.gz"
stage "Verifying the privileged archive stream"
cat > "\$archive"
printf "%s  %s\\n" "${digest}" "\$archive" | sha256sum --check --status
stage "Extracting the verified release"
mkdir "\$tmp/release"
chmod 700 "\$tmp/release"
tar --extract --file "\$archive" --directory "\$tmp/release" --no-same-owner --no-same-permissions
[ -f "\$tmp/release/lanpanel" ] && [ -x "\$tmp/release/lanpanel" ]
stage "Running the signed LanPanel installer"
"\$tmp/release/lanpanel" install
'
stage 'Installation completed successfully'
printf '%s\n' 'LanPanel installation completed successfully.'
EOF
