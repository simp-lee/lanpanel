#!/bin/sh
set -eu

: "${LEGO_HOOK_CERT_NAME:?}"
: "${LEGO_HOOK_CERT_PATH:?}"
: "${LEGO_HOOK_CERT_KEY_PATH:?}"

target_dir="/etc/lanpanel/tls/$LEGO_HOOK_CERT_NAME"
install -d -m 0755 "$target_dir"
install -m 0644 "$LEGO_HOOK_CERT_PATH" "$target_dir/fullchain.pem"
install -m 0600 "$LEGO_HOOK_CERT_KEY_PATH" "$target_dir/privkey.pem"

nginx -t
systemctl reload nginx
