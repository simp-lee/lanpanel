#!/bin/sh
# Download Debian's Nginx packages into a temporary root, run the real Nginx
# HTTPS integration test, and remove every temporary file afterwards.
set -eu

work=$(mktemp -d "${TMPDIR:-/tmp}/lanpanel-nginx-test.XXXXXX")
cleanup() {
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

command -v apt-get >/dev/null 2>&1 || { echo 'apt-get is required for the temporary Nginx test' >&2; exit 2; }
command -v dpkg-deb >/dev/null 2>&1 || { echo 'dpkg-deb is required for the temporary Nginx test' >&2; exit 2; }
command -v go >/dev/null 2>&1 || { echo 'Go is required for the temporary Nginx test' >&2; exit 2; }

mkdir -p "$work/debs" "$work/root"
(
  cd "$work/debs"
  apt-get download nginx nginx-common nginx-core
)
for deb in "$work"/debs/*.deb; do
  dpkg-deb -x "$deb" "$work/root"
done

nginx="$work/root/usr/sbin/nginx"
if [ ! -x "$nginx" ]; then
  echo 'temporary Nginx package did not contain /usr/sbin/nginx' >&2
  exit 1
fi

PATH="$work/root/usr/sbin:$PATH" go test -count=1 ./internal/nginx -run '^TestManagementHTTPSRenderedGraphServesThroughRealNginx$'
printf '%s\n' 'Temporary Nginx HTTPS integration passed; temporary package root removed on exit.'
