#!/bin/sh
# Run a real local DNS-01 ACME round trip against Pebble and challtestsrv.
# Set PEBBLE_BIN, CHALLTESTSRV_BIN, and LEGO_BIN to the three binaries.
set -eu

: "${PEBBLE_BIN:?set PEBBLE_BIN to the Pebble binary}"
: "${CHALLTESTSRV_BIN:?set CHALLTESTSRV_BIN to pebble-challtestsrv}"
: "${LEGO_BIN:?set LEGO_BIN to the lego binary}"

work=$(mktemp -d "${TMPDIR:-/tmp}/lanpanel-pebble-dns01.XXXXXX")
pebble_pid=
chall_pid=
cleanup() {
  [ -z "$pebble_pid" ] || kill "$pebble_pid" 2>/dev/null || true
  [ -z "$chall_pid" ] || kill "$chall_pid" 2>/dev/null || true
  wait "$pebble_pid" 2>/dev/null || true
  wait "$chall_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

PEBBLE_PORT=${PEBBLE_PORT:-14000}
DNS_PORT=${DNS_PORT:-18053}
MANAGEMENT_PORT=${MANAGEMENT_PORT:-18055}

mkdir -p "$work/certs" "$work/lego"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj /CN=localhost -addext subjectAltName=DNS:localhost \
  -keyout "$work/certs/key.pem" -out "$work/certs/cert.pem" >/dev/null 2>&1
cat >"$work/pebble-config.json" <<EOF
{
  "pebble": {
    "listenAddress": "127.0.0.1:${PEBBLE_PORT}",
    "certificate": "${work}/certs/cert.pem",
    "privateKey": "${work}/certs/key.pem",
    "httpPort": 5002,
    "tlsPort": 5001
  }
}
EOF
cat >"$work/update-dns.sh" <<'EOF'
#!/bin/sh
set -eu
command=$1
host=$2
value=$3
if [ "$command" = present ]; then
  payload=$(printf '{"host":"%s","value":"%s"}' "$host" "$value")
  curl -fsS -X POST -H 'Content-Type: application/json' --data "$payload" "http://127.0.0.1:${MANAGEMENT_PORT}/set-txt" >/dev/null
elif [ "$command" = cleanup ]; then
  payload=$(printf '{"host":"%s"}' "$host")
  curl -fsS -X POST -H 'Content-Type: application/json' --data "$payload" "http://127.0.0.1:${MANAGEMENT_PORT}/clear-txt" >/dev/null
else
  exit 2
fi
EOF
chmod 700 "$work/update-dns.sh"

"$CHALLTESTSRV_BIN" \
  -dns01 "127.0.0.1:${DNS_PORT}" -http01 '' -https01 '' -tlsalpn01 '' \
  -management "127.0.0.1:${MANAGEMENT_PORT}" >"$work/chall.log" 2>&1 &
chall_pid=$!
"$PEBBLE_BIN" -config "$work/pebble-config.json" \
  -dnsserver "127.0.0.1:${DNS_PORT}" >"$work/pebble.log" 2>&1 &
pebble_pid=$!

for _ in $(seq 1 50); do
  if curl -kfsS "https://127.0.0.1:${PEBBLE_PORT}/dir" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
curl -kfsS "https://127.0.0.1:${PEBBLE_PORT}/dir" >/dev/null

lego_version=$($LEGO_BIN --version 2>&1 || true)
case "$lego_version" in
  *" version 5."*|*" version v5."*)
    MANAGEMENT_PORT=$MANAGEMENT_PORT \
    EXEC_PATH="$work/update-dns.sh" \
    EXEC_PROPAGATION_TIMEOUT=5 \
    EXEC_POLLING_INTERVAL=1 \
    EXEC_SEQUENCE_INTERVAL=1 \
    "$LEGO_BIN" run --server "https://127.0.0.1:${PEBBLE_PORT}/dir" --tls-skip-verify \
      --path "$work/lego" --email test@example.com --accept-tos --dns exec \
      --dns.resolvers "127.0.0.1:${DNS_PORT}" --dns.propagation.disable-ans \
      --domains example.com --no-bundle
    ;;
  *)
    MANAGEMENT_PORT=$MANAGEMENT_PORT \
    EXEC_PATH="$work/update-dns.sh" \
    EXEC_PROPAGATION_TIMEOUT=5 \
    EXEC_POLLING_INTERVAL=1 \
    EXEC_SEQUENCE_INTERVAL=1 \
    "$LEGO_BIN" --server "https://127.0.0.1:${PEBBLE_PORT}/dir" --tls-skip-verify \
      --path "$work/lego" --email test@example.com --accept-tos --dns exec \
      --dns.resolvers "127.0.0.1:${DNS_PORT}" --dns.propagation-disable-ans \
      --domains example.com run --no-bundle
    ;;
esac

openssl x509 -in "$work/lego/certificates/example.com.crt" -noout -subject -issuer
printf '%s\n' 'Pebble DNS-01 round trip passed.'
