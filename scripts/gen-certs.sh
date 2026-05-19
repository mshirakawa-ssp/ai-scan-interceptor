#!/usr/bin/env bash
set -euo pipefail

CERTS_DIR="$(cd "$(dirname "$0")/.." && pwd)/certs"
mkdir -p "$CERTS_DIR"

if [[ -f "$CERTS_DIR/squid-ca.pem" && -f "$CERTS_DIR/squid-ca.key" ]]; then
  echo "[gen-certs] CA already exists, skipping."
  exit 0
fi

echo "[gen-certs] Generating CA certificate..."
openssl req -new -newkey rsa:4096 -days 3650 -nodes -x509 \
  -keyout "$CERTS_DIR/squid-ca.key" \
  -out    "$CERTS_DIR/squid-ca.pem" \
  -subj   "/C=JP/ST=Tokyo/O=SecurityScanPro/OU=AI-Scan/CN=AI-Scan-Interceptor CA"

chmod 600 "$CERTS_DIR/squid-ca.key"
chmod 644 "$CERTS_DIR/squid-ca.pem"

echo "[gen-certs] Done."
echo ""
echo "  Distribute certs/squid-ca.pem to monitored endpoints."
echo "  macOS : sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain certs/squid-ca.pem"
echo "  Ubuntu: sudo cp certs/squid-ca.pem /usr/local/share/ca-certificates/squid-ca.crt && sudo update-ca-certificates"
