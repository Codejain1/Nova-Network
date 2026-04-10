#!/usr/bin/env bash
# ── Nova Network — Secret Rotation Script ──────────────────────────────────
# Run this on each node to generate and apply new secrets.
# Usage: ./scripts/rotate_secrets.sh <env-file>
# Example: ./scripts/rotate_secrets.sh deploy/main-node/.env
set -euo pipefail

ENV_FILE="${1:-}"
if [[ -z "$ENV_FILE" || ! -f "$ENV_FILE" ]]; then
  echo "Usage: $0 <path-to-.env-file>"
  echo "Example: $0 deploy/main-node/.env"
  exit 1
fi

echo "Rotating secrets in: $ENV_FILE"
echo ""

# Generate new secrets
NEW_JWT_SECRET=$(openssl rand -hex 32)
NEW_PEER_TOKEN=$(openssl rand -hex 24)
NEW_RPC_AUTH_TOKEN=$(openssl rand -base64 32 | tr -d '=+/' | head -c 40)

# Back up current file
cp "$ENV_FILE" "${ENV_FILE}.bak.$(date +%Y%m%d%H%M%S)"

# Replace secrets in .env file
if grep -q "^JWT_SECRET=" "$ENV_FILE"; then
  sed -i.tmp "s|^JWT_SECRET=.*|JWT_SECRET=${NEW_JWT_SECRET}|" "$ENV_FILE"
fi
if grep -q "^PEER_TOKEN=" "$ENV_FILE"; then
  sed -i.tmp "s|^PEER_TOKEN=.*|PEER_TOKEN=${NEW_PEER_TOKEN}|" "$ENV_FILE"
fi
if grep -q "^RPC_AUTH_TOKEN=" "$ENV_FILE"; then
  sed -i.tmp "s|^RPC_AUTH_TOKEN=.*|RPC_AUTH_TOKEN=${NEW_RPC_AUTH_TOKEN}|" "$ENV_FILE"
fi
rm -f "${ENV_FILE}.tmp"

echo "New secrets applied:"
echo "  JWT_SECRET   = ${NEW_JWT_SECRET:0:8}...${NEW_JWT_SECRET: -8}"
echo "  PEER_TOKEN   = ${NEW_PEER_TOKEN:0:8}...${NEW_PEER_TOKEN: -8}"
if grep -q "^RPC_AUTH_TOKEN=" "$ENV_FILE"; then
  echo "  RPC_AUTH_TOKEN = ${NEW_RPC_AUTH_TOKEN:0:8}...${NEW_RPC_AUTH_TOKEN: -8}"
fi
echo ""
echo "IMPORTANT: You must use the SAME PEER_TOKEN on all nodes for snapshot sync."
echo "           Copy the PEER_TOKEN value to every node's .env file."
echo ""
echo "Restart the node to apply: docker compose -f <compose-file> --env-file $ENV_FILE up -d --build"
