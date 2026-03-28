#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -z "${PYTHON_BIN:-}" ]]; then
  if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
    PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
  elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
  else
    PYTHON_BIN="python"
  fi
fi

NODE_URL="http://127.0.0.1:8010"
DATA_DIR="$(mktemp -d -t jito-e2e-data-XXXXXX)"
WALLET_DIR="$(mktemp -d -t jito-e2e-wallets-XXXXXX)"
NODE_LOG="$DATA_DIR/node.log"

cleanup() {
  if [[ -n "${NODE_PID:-}" ]] && kill -0 "$NODE_PID" >/dev/null 2>&1; then
    kill "$NODE_PID" >/dev/null 2>&1 || true
    wait "$NODE_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "E2E setup:"
echo "  data_dir=$DATA_DIR"
echo "  wallet_dir=$WALLET_DIR"

"$PYTHON_BIN" cli.py wallet-create --name validator1 --out "$WALLET_DIR/validator1.json" >/dev/null
"$PYTHON_BIN" cli.py wallet-create --name validator2 --out "$WALLET_DIR/validator2.json" >/dev/null
"$PYTHON_BIN" cli.py wallet-create --name alice --out "$WALLET_DIR/alice.json" >/dev/null
"$PYTHON_BIN" cli.py wallet-create --name bob --out "$WALLET_DIR/bob.json" >/dev/null
"$PYTHON_BIN" cli.py wallet-create --name provider --out "$WALLET_DIR/provider.json" >/dev/null

VAL1="$(jq -r '.address' "$WALLET_DIR/validator1.json")"
VAL2="$(jq -r '.address' "$WALLET_DIR/validator2.json")"
ALICE="$(jq -r '.address' "$WALLET_DIR/alice.json")"
BOB="$(jq -r '.address' "$WALLET_DIR/bob.json")"
PROVIDER="$(jq -r '.address' "$WALLET_DIR/provider.json")"

"$PYTHON_BIN" cli.py node-start \
  --host 127.0.0.1 --port 8010 --data-dir "$DATA_DIR" \
  --chain-name "JITO E2E" \
  --public-consensus poa \
  --public-validator "$VAL1" \
  --public-validator-rotation \
  --public-finality-confirmations 2 \
  --public-checkpoint-interval 2 \
  --auto-mine --auto-mine-miner "$VAL1" --auto-mine-interval 1 \
  >"$NODE_LOG" 2>&1 &
NODE_PID="$!"

for _ in {1..40}; do
  if curl -sf "$NODE_URL/health" >/dev/null; then
    break
  fi
  sleep 0.25
done
curl -sf "$NODE_URL/health" >/dev/null
echo "Node started"

echo "Phase 1/2: public chain effectiveness + hardening"
"$PYTHON_BIN" cli.py --node-url "$NODE_URL" public-mine --miner "$VAL1" >/dev/null
"$PYTHON_BIN" cli.py --node-url "$NODE_URL" public-tx --wallet "$WALLET_DIR/validator1.json" --to "$ALICE" --amount 5 --fee 0.2 >/dev/null
sleep 2
"$PYTHON_BIN" cli.py --node-url "$NODE_URL" public-tx --wallet "$WALLET_DIR/alice.json" --to "$BOB" --amount 1 --fee 0.05 >/dev/null
sleep 2

"$PYTHON_BIN" cli.py --node-url "$NODE_URL" public-ai-provider-stake --wallet "$WALLET_DIR/provider.json" --amount 0.5 >/dev/null || true
"$PYTHON_BIN" cli.py --node-url "$NODE_URL" public-tx --wallet "$WALLET_DIR/validator1.json" --to "$PROVIDER" --amount 2 --fee 0.1 >/dev/null
sleep 2
"$PYTHON_BIN" cli.py --node-url "$NODE_URL" public-ai-provider-stake --wallet "$WALLET_DIR/provider.json" --amount 0.5 >/dev/null
sleep 2
"$PYTHON_BIN" cli.py --node-url "$NODE_URL" public-ai-provider-slash --wallet "$WALLET_DIR/validator1.json" --provider "$PROVIDER" --amount 0.2 --reason "e2e-check" >/dev/null
sleep 2

"$PYTHON_BIN" cli.py --node-url "$NODE_URL" public-validator-update --wallet "$WALLET_DIR/validator1.json" --action add --validator "$VAL2" >/dev/null
sleep 2
NEXT_VAL="$("$PYTHON_BIN" cli.py --node-url "$NODE_URL" public-consensus | jq -r '.next_expected_validator // empty')"
if [[ -n "$NEXT_VAL" ]]; then
  "$PYTHON_BIN" cli.py --node-url "$NODE_URL" public-mine --miner "$NEXT_VAL" >/dev/null
fi

echo "Phase 3/4: private domains + AI-native lifecycle"
"$PYTHON_BIN" cli.py --node-url "$NODE_URL" private-register --wallet "$WALLET_DIR/validator1.json" --validator --notary >/dev/null
"$PYTHON_BIN" cli.py --node-url "$NODE_URL" private-register --wallet "$WALLET_DIR/validator2.json" --validator >/dev/null
"$PYTHON_BIN" cli.py --node-url "$NODE_URL" private-register --wallet "$WALLET_DIR/alice.json" --issuer >/dev/null
"$PYTHON_BIN" cli.py --node-url "$NODE_URL" private-register --wallet "$WALLET_DIR/bob.json" >/dev/null
"$PYTHON_BIN" cli.py --node-url "$NODE_URL" private-register --wallet "$WALLET_DIR/provider.json" >/dev/null

"$PYTHON_BIN" cli.py --node-url "$NODE_URL" private-propose --wallet "$WALLET_DIR/validator1.json" --action create_domain --payload-json "{\"domain_id\":\"org-acme\",\"members\":[\"$ALICE\",\"$BOB\",\"$PROVIDER\"]}" >/tmp/jito_e2e_proposal.json
PROPOSAL_ID="$(jq -r '.id // .proposal.id' /tmp/jito_e2e_proposal.json)"
"$PYTHON_BIN" cli.py --node-url "$NODE_URL" private-approve --wallet "$WALLET_DIR/validator2.json" --proposal-id "$PROPOSAL_ID" >/dev/null

"$PYTHON_BIN" cli.py --node-url "$NODE_URL" private-issue --wallet "$WALLET_DIR/alice.json" --asset-id RWA-E2E-1 --amount 10 --owner "$BOB" --domain org-acme >/dev/null
"$PYTHON_BIN" cli.py --node-url "$NODE_URL" private-seal --wallet "$WALLET_DIR/validator1.json" >/dev/null

"$PYTHON_BIN" cli.py --node-url "$NODE_URL" private-ai-model-register --wallet "$WALLET_DIR/alice.json" --model-id model-e2e --model-hash sha256:model --version 1.0 --price-per-call 0.1 --visibility "$ALICE,$BOB,$PROVIDER" >/dev/null
"$PYTHON_BIN" cli.py --node-url "$NODE_URL" private-seal --wallet "$WALLET_DIR/validator1.json" >/dev/null

"$PYTHON_BIN" cli.py --node-url "$NODE_URL" private-ai-job-create --wallet "$WALLET_DIR/bob.json" --job-id job-e2e --model-id model-e2e --input-hash sha256:input --max-payment 0.2 --visibility "$BOB,$PROVIDER" >/dev/null
"$PYTHON_BIN" cli.py --node-url "$NODE_URL" private-seal --wallet "$WALLET_DIR/validator1.json" >/dev/null

"$PYTHON_BIN" cli.py --node-url "$NODE_URL" private-ai-job-result --wallet "$WALLET_DIR/provider.json" --job-id job-e2e --result-hash sha256:result --quality-score 0.98 >/dev/null
"$PYTHON_BIN" cli.py --node-url "$NODE_URL" private-seal --wallet "$WALLET_DIR/validator1.json" >/dev/null

"$PYTHON_BIN" cli.py --node-url "$NODE_URL" private-ai-job-settle --wallet "$WALLET_DIR/validator1.json" --job-id job-e2e --payout 0.18 --slash-provider 0 --reason "ok" >/dev/null
"$PYTHON_BIN" cli.py --node-url "$NODE_URL" private-seal --wallet "$WALLET_DIR/validator1.json" >/dev/null

echo "Endpoint verification"
curl -sf "$NODE_URL/slo" | jq '.ok == true' | grep -q true
curl -sf "$NODE_URL/public/finality" | jq '.latest_finalized_height >= 0' | grep -q true
curl -sf "$NODE_URL/public/ai/stakes" | jq '.provider_count >= 1' | grep -q true
curl -sf "$NODE_URL/private/domains?domain_id=org-acme&include_pending=true" | jq '.count == 1' | grep -q true
curl -sf "$NODE_URL/private/ai/models" | jq '.count >= 1' | grep -q true
curl -sf "$NODE_URL/private/ai/jobs" | jq '.count >= 1' | grep -q true

echo "E2E PASS"
