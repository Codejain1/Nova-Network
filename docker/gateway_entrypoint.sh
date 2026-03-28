#!/usr/bin/env sh
set -eu

exec python cli.py evm-gateway-start \
  --host "${RPC_HOST:-0.0.0.0}" \
  --port "${RPC_PORT:-8545}" \
  --rpc-node-url "${RPC_NODE_URL:-http://node:8000}" \
  --chain-id "${CHAIN_ID:-77001}" \
  --rpc-auth-token "${RPC_AUTH_TOKEN:-}" \
  --peer-ca "${PEER_CA:-}" \
  --cors-origin "${CORS_ORIGIN:-*}"
