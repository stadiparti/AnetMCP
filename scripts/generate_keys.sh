#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

mkdir -p "$ROOT_DIR/keys"

echo "[1/3] Generating RSA private key (4096 bits)"
openssl genrsa -out "$ROOT_DIR/keys/mcp-private.pem" 4096

echo "[2/3] Converting to PKCS#8 (no password)"
openssl pkcs8 -topk8 -inform PEM -outform PEM -in "$ROOT_DIR/keys/mcp-private.pem" -out "$ROOT_DIR/keys/mcp-private-pkcs8.pem" -nocrypt

echo "[3/3] Exporting public key (SPKI)"
openssl rsa -in "$ROOT_DIR/keys/mcp-private.pem" -pubout -out "$ROOT_DIR/keys/mcp-public.pem"

echo "Done. Keys in $ROOT_DIR/keys"
