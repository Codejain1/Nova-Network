#!/usr/bin/env bash
set -euo pipefail

EXPLORER_URL="${EXPLORER_URL:-https://explorer.flowpe.io}"
RPC_URL="${RPC_URL:-https://rpc.flowpe.io}"
MIN_VALIDATORS="${MIN_VALIDATORS:-2}"
TIMEOUT="${TIMEOUT:-12}"

probe() {
  curl -fsS -m "$TIMEOUT" "$1" >/dev/null
}

probe "$EXPLORER_URL/health"
probe "$RPC_URL/health"

chain_info="$(curl -fsS -m "$TIMEOUT" "$EXPLORER_URL/chain/info")"
validator_count="$(printf '%s' "$chain_info" | jq -r '.public_chain.validator_count // 0')"
if [[ "$validator_count" -lt "$MIN_VALIDATORS" ]]; then
  echo "validator_count below threshold: $validator_count < $MIN_VALIDATORS" >&2
  exit 1
fi

hardening="$(printf '%s' "$chain_info" | jq -r '.security.mainnet_hardening // false')"
if [[ "$hardening" != "true" ]]; then
  echo "mainnet_hardening is not enabled" >&2
  exit 1
fi

slo="$(curl -fsS -m "$TIMEOUT" "$EXPLORER_URL/slo")"
auto_ok="$(printf '%s' "$slo" | jq -r '.status.auto_mine_ok // false')"
if [[ "$auto_ok" != "true" ]]; then
  echo "auto_mine health check failed" >&2
  exit 1
fi

echo "health_probe: OK"
