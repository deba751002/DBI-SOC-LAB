#!/usr/bin/env bash
# =============================================================================
# DFIR-IRIS — Self-Signed Certificate Generator
# IRIS's app/worker containers expect a root CA PEM at a fixed path, and its
# nginx container expects a web-facing cert+key — neither exists until this
# runs once. These are self-signed (lab use only, matching IRIS's own
# documented default), NOT suitable for anything internet-facing.
# Run once before the first `docker compose up -d` for dfir-iris/iris-app/
# iris-worker: ./config/dfir-iris/generate-certs.sh
# =============================================================================
set -euo pipefail

CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/certificates"

if [[ -f "$CERT_DIR/web_certificates/cert.crt" ]]; then
  echo "Certificates already exist at $CERT_DIR — skipping (delete the folder to regenerate)."
  exit 0
fi

mkdir -p "$CERT_DIR/rootCA" "$CERT_DIR/ldap" "$CERT_DIR/web_certificates"

echo "Generating root CA placeholder (required by iris-app/iris-worker)..."
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
  -keyout "$CERT_DIR/rootCA/irisRootCACert.key" \
  -out "$CERT_DIR/rootCA/irisRootCACert.pem" \
  -subj "/CN=DBI SOC Lab IRIS Root CA" 2>/dev/null

echo "Generating web-facing self-signed cert (required by dfir-iris/nginx)..."
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
  -keyout "$CERT_DIR/web_certificates/cert.key" \
  -out "$CERT_DIR/web_certificates/cert.crt" \
  -subj "/CN=dfir-iris" 2>/dev/null

# openssl writes keys as 0600 (owner-only). The nginx container runs as its
# own non-root user, whose UID doesn't match whoever ran this script on the
# host, so it can't read a 0600 file it doesn't own. World-readable is fine
# for a self-signed lab-only cert.
chmod -R a+r "$CERT_DIR"
find "$CERT_DIR" -type d -exec chmod a+rx {} +

echo ""
echo "Done. Certificates written to $CERT_DIR"
echo "Browsers will show a self-signed-certificate warning when opening"
echo "https://<host>:\${IRIS_PORT:-8443} — expected for a lab deployment."
