#!/usr/bin/env sh
# Run this script from the ROOT of the repo on the 8GB VM
# Usage: ./deploy/main-node/start.sh
set -eu

COMPOSE_FILE="deploy/main-node/docker-compose.yml"
ENV_FILE="deploy/main-node/.env"

# Sanity check — PUBLIC_VALIDATORS must be set
VALIDATORS="$(grep '^PUBLIC_VALIDATORS=' "$ENV_FILE" | cut -d= -f2)"
if [ -z "$VALIDATORS" ]; then
  echo "ERROR: PUBLIC_VALIDATORS is empty in $ENV_FILE"
  echo "Fill in the 4 validator addresses before starting."
  exit 1
fi

echo "Starting Nova main node..."
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d --build

echo ""
echo "Waiting for node to become healthy..."
for i in $(seq 1 20); do
  if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
    echo "Node is up."
    break
  fi
  printf "."
  sleep 3
done

echo ""
echo "── Status ────────────────────────────────────────"
curl -s http://localhost:8000/health | python3 -m json.tool 2>/dev/null || true
echo ""
echo "Node API : http://$(hostname -I | awk '{print $1}'):8000"
echo "EVM RPC  : http://$(hostname -I | awk '{print $1}'):8545"
echo ""
echo "Logs: docker compose -f $COMPOSE_FILE logs -f"
