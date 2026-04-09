#!/usr/bin/env sh
# Run this script from the ROOT of the repo on a validator VM
# Usage: ./deploy/validator-node/start.sh
set -eu

COMPOSE_FILE="deploy/validator-node/docker-compose.yml"
ENV_FILE="deploy/validator-node/.env"

if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: $ENV_FILE not found."
  echo "Copy .env.example to .env and fill in the required values."
  exit 1
fi

# Validate required fields
check_var() {
  VAL="$(grep "^$1=" "$ENV_FILE" | cut -d= -f2)"
  if [ -z "$VAL" ]; then
    echo "ERROR: $1 is not set in $ENV_FILE"
    exit 1
  fi
}

check_var "PUBLIC_VALIDATORS"
check_var "AUTO_MINE_MINER"
check_var "MAIN_NODE_URL"

echo "Starting Nova validator node..."
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d --build

echo ""
echo "Waiting for node to become healthy..."
for i in $(seq 1 20); do
  if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
    echo "Validator node is up."
    break
  fi
  printf "."
  sleep 3
done

echo ""
echo "── Status ────────────────────────────────────────"
curl -s http://localhost:8000/health | python3 -m json.tool 2>/dev/null || true
echo ""
echo "── Auto-mine status ──────────────────────────────"
curl -s http://localhost:8000/mine/auto/status | python3 -m json.tool 2>/dev/null || true
echo ""
echo "Logs: docker compose -f $COMPOSE_FILE logs -f"
