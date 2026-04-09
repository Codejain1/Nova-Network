#!/usr/bin/env sh
set -eu

set -- python cli.py node-start \
  --host "${NODE_HOST:-0.0.0.0}" \
  --port "${NODE_PORT:-8000}" \
  --data-dir "${DATA_DIR:-/data}" \
  --public-difficulty "${PUBLIC_DIFFICULTY:-3}" \
  --public-reward "${PUBLIC_REWARD:-25}" \
  --public-consensus "${PUBLIC_CONSENSUS:-pow}" \
  --chain-name "${CHAIN_NAME:-Nova Network}" \
  --token-name "${TOKEN_NAME:-Nova}" \
  --token-symbol "${TOKEN_SYMBOL:-NOVA}" \
  --token-decimals "${TOKEN_DECIMALS:-18}"

if [ -n "${PUBLIC_VALIDATORS:-}" ]; then
  OLDIFS=$IFS
  IFS=','
  for validator in $PUBLIC_VALIDATORS; do
    set -- "$@" --public-validator "$validator"
  done
  IFS=$OLDIFS
fi

if [ "${PUBLIC_VALIDATOR_ROTATION:-true}" = "false" ]; then
  set -- "$@" --no-public-validator-rotation
fi

if [ -n "${CHAIN_LOGO_URL:-}" ]; then
  set -- "$@" --chain-logo-url "$CHAIN_LOGO_URL"
fi

if [ -n "${TOKEN_LOGO_URL:-}" ]; then
  set -- "$@" --token-logo-url "$TOKEN_LOGO_URL"
fi

if [ "${AUTO_MINE:-false}" = "true" ]; then
  set -- "$@" --auto-mine
fi

if [ -n "${AUTO_MINE_MINER:-}" ]; then
  set -- "$@" --auto-mine-miner "$AUTO_MINE_MINER"
fi

if [ -n "${AUTO_MINE_INTERVAL:-}" ]; then
  set -- "$@" --auto-mine-interval "$AUTO_MINE_INTERVAL"
fi

if [ "${AUTO_MINE_ALLOW_EMPTY:-false}" = "true" ]; then
  set -- "$@" --auto-mine-allow-empty
fi

if [ "${PUBLIC_FAUCET_ENABLED:-false}" = "true" ]; then
  set -- "$@" --public-faucet-enabled
fi

if [ -n "${PUBLIC_FAUCET_AMOUNT:-}" ]; then
  set -- "$@" --public-faucet-amount "$PUBLIC_FAUCET_AMOUNT"
fi

if [ -n "${PUBLIC_FAUCET_COOLDOWN:-}" ]; then
  set -- "$@" --public-faucet-cooldown "$PUBLIC_FAUCET_COOLDOWN"
fi

if [ -n "${PUBLIC_FAUCET_DAILY_CAP:-}" ]; then
  set -- "$@" --public-faucet-daily-cap "$PUBLIC_FAUCET_DAILY_CAP"
fi

if [ "${MAINNET_HARDENING:-false}" = "true" ]; then
  set -- "$@" --mainnet-hardening
fi

if [ -n "${PEERS:-}" ]; then
  OLDIFS=$IFS
  IFS=','
  for peer in $PEERS; do
    set -- "$@" --peer "$peer"
  done
  IFS=$OLDIFS
fi

if [ -n "${PEER_TOKEN:-}" ]; then
  set -- "$@" --peer-token "$PEER_TOKEN"
fi

if [ "${PEER_SYNC_ENABLED:-true}" = "false" ]; then
  set -- "$@" --no-peer-sync-enabled
fi

if [ -n "${PEER_SYNC_INTERVAL:-}" ]; then
  set -- "$@" --peer-sync-interval "$PEER_SYNC_INTERVAL"
fi

if [ -n "${PEER_LAG_RESYNC_THRESHOLD:-}" ]; then
  set -- "$@" --peer-lag-resync-threshold "$PEER_LAG_RESYNC_THRESHOLD"
fi

if [ "${STRICT_PUBLIC_SIGNATURES:-true}" = "false" ]; then
  set -- "$@" --no-strict-public-signatures
fi

if [ -n "${PUBLIC_MEMPOOL_TTL:-}" ]; then
  set -- "$@" --public-mempool-ttl "$PUBLIC_MEMPOOL_TTL"
fi

if [ -n "${PUBLIC_MEMPOOL_MAX_SIZE:-}" ]; then
  set -- "$@" --public-mempool-max-size "$PUBLIC_MEMPOOL_MAX_SIZE"
fi

if [ -n "${PUBLIC_POW_WORKERS:-}" ]; then
  set -- "$@" --public-pow-workers "$PUBLIC_POW_WORKERS"
fi

if [ -n "${PUBLIC_POW_NONCE_CHUNK:-}" ]; then
  set -- "$@" --public-pow-nonce-chunk "$PUBLIC_POW_NONCE_CHUNK"
fi

if [ "${REQUIRE_HSM_SIGNERS:-false}" = "true" ]; then
  set -- "$@" --require-hsm-signers
fi

if [ -n "${JWT_SECRET:-}" ]; then
  set -- "$@" --jwt-secret "$JWT_SECRET"
fi

if [ "${JWT_REQUIRED:-false}" = "true" ]; then
  set -- "$@" --jwt-required
fi

if [ -n "${RATE_LIMIT_PER_MINUTE:-}" ]; then
  set -- "$@" --rate-limit-per-minute "$RATE_LIMIT_PER_MINUTE"
fi

if [ -n "${TLS_CERT:-}" ]; then
  set -- "$@" --tls-cert "$TLS_CERT"
fi

if [ -n "${TLS_KEY:-}" ]; then
  set -- "$@" --tls-key "$TLS_KEY"
fi

if [ -n "${TLS_CA:-}" ]; then
  set -- "$@" --tls-ca "$TLS_CA"
fi

if [ "${TLS_REQUIRE_CLIENT_CERT:-false}" = "true" ]; then
  set -- "$@" --tls-require-client-cert
fi

if [ -n "${PEER_CA:-}" ]; then
  set -- "$@" --peer-ca "$PEER_CA"
fi

exec "$@"
