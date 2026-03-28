# JITO Dual Blockchain: Public Payments + Private RWA Network

This stack runs two integrated chains:

- Public chain: open P2P payments, signed tx, PoW or PoA validator mode.
- Private chain: permissioned RWA lifecycle with domains, contracts, governance, and notary finality.

## New features added

1. Interactive UI testing
- App hub at `/app` with separated flows:
  - Investor app: `/app/investor`
  - Issuer app: `/app/issuer`
  - Operator app: `/app/operator`
- Browser control panel at `/ui` (wallet creation, tx/mine, private register, governance, issue/transfer, seal/attest).
- Dedicated RWA issuer portal at `/rwa` (asset details + valuation + one-click tokenize + private trade).
- Dedicated RWA market page at `/rwa-market` (create listing + buy listing + finalized private transfer).
- Full explorer UI at `/explorer` (Dashboard, Blocks, Transactions, Address, Prices, Analytics).
- Scanner UI at `/scanner` (fast Etherscan-style summary/search/detail panel).

2. Security hardening
- JWT bearer auth (HS256) for node APIs.
- TLS and mTLS support (client cert enforcement).

3. Cloud signer adapters
- Pluggable signer providers in `dual_chain.py`:
  - `file-hsm`
  - `aws-kms` (AWS CLI)
  - `gcp-kms` (gcloud CLI)
  - `azure-kv` (az CLI)

4. Containerization
- `Dockerfile` + `docker-compose.yml` for 2-node network startup.

5. New chain features
- O(1) balance reads on public chain via in-memory balance index (no full-history scan on each lookup).
- Public auto-mining with fixed interval (`/public/auto-mine/*` + CLI commands).
- Mempool endpoint (`GET /public/mempool`) for pending tx visibility.
- Mempool TTL + max-size eviction controls (`PUBLIC_MEMPOOL_TTL`, `PUBLIC_MEMPOOL_MAX_SIZE`).
- Optional parallel PoW workers (`PUBLIC_POW_WORKERS`, `PUBLIC_POW_NONCE_CHUNK`) for higher nonce-search throughput.
- Strict public signature validation enabled by default (legacy fallback can be disabled/enabled via node flag).
- Fee-priority public mempool ordering (`payment.fee`, EVM gas fee ordering).
- PoA proposer rotation support (`expected_next_validator` + strict rotation checks).
- Public finality/checkpoint metadata (`GET /public/finality`).
- Public AI provider staking/slashing primitives (`GET /public/ai/stakes`).
- Private AI-native tx types: model register, job create, result, settle.
- Runtime branding metadata for explorer/scanner (`POST /chain/branding`).

## Agent Trust System

JITO includes a portable reputation layer for AI agents.  Agents log work on-chain,
stake is locked behind claims, challengers can dispute, and validators adjudicate.
Trust scores and tiers are fully portable — they follow the wallet across platforms.

### Quick start (Python)

```python
from jito_agent import JitoTracker, load_wallet

wallet = load_wallet("wallet.json")   # or JitoTracker.new("my-agent") to auto-create
tracker = JitoTracker(wallet, agent_id="my-agent", node_url="https://explorer.flowpe.io")

# Log any work your agent does
tracker.log("task_completed", success=True, tags=["analysis", "finance"])

# Context manager: auto-times and logs on exit; logs failure on exception
with tracker.track("analysis_done", tags=["finance"]) as ctx:
    result = run_analysis(data)
    ctx.set_output(result)

# Read back
print(tracker.get_reputation())     # trust_score, trust_tier, counters
print(tracker.passport())           # portable trust passport
print(tracker.rules())              # live governance parameters
print(tracker.get_log(log_id))      # permanent log lookup (survives block pruning)
```

### Trust tiers

| Tier | Condition |
|---|---|
| `unverified` | No logs yet |
| `self-reported` | Has activity logs, no attestations |
| `attested` | At least one positive attestation |
| `evidence-attested` | Has evidence-backed logs |
| `stake-backed` | Has stake-locked logs |
| `disputed` | Active unanswered challenge |
| `slashed` | Evidence not produced within challenge window |

### Governance

Trust parameters (challenge window, score weights, slash outcome, endorsement threshold)
are stored as live chain state and can only be changed by multi-validator governance:

**Step 1 — Propose** (any active validator):
```bash
python cli.py --node-url http://127.0.0.1:8000 agent-param-propose \
  --wallet wallets/validator1.json \
  --changes '{"challenge_window_blocks": 100}' \
  --reason "community vote #3"
```

**Step 2 — Endorse** (a second active validator):
```bash
python cli.py --node-url http://127.0.0.1:8000 agent-param-endorse \
  --wallet wallets/validator2.json \
  --proposal-id apu_<id>
```

Changes apply immediately when `yes_count >= param_update_min_endorsements` (default: 2).
Every applied change is recorded permanently in `agent_trust_params_history`.

**Governance guarantees:**
- No silent edits — every parameter change is an immutable signed tx in the block history
- Single-validator proposals cannot apply alone (default threshold = 2)
- `param_update_min_endorsements` is itself governable (bounds: 1–100)
- Cooldown between applies prevents rapid parameter flipping
- One open proposal at a time — a second proposal is rejected until the first resolves
- Activity logs and challenge records persist indefinitely (survive block pruning)

### Key agent trust API endpoints

| Endpoint | Description |
|---|---|
| `GET /public/agent/passport?address=W...` | Trust passport: score, tier, counters, badges |
| `GET /public/agent/passport?address=W...&verbose=true` | + full log/challenge detail and evidence coverage |
| `GET /public/agent/passport?agent_id=my-agent` | Lookup by agent_id string |
| `GET /public/agent/rules` | Live governance params + open proposals + change history |
| `GET /public/agent/log?log_id=...` | Permanent single-log lookup |
| `GET /public/agent/logs?address=W...` | Filtered activity log feed |
| `GET /public/agent/leaderboard` | Top agents by trust score |

### SDK clients

- **`jito_agent/`** — Full SDK with signing, key management, and trust operations.
  Use this for AI agents. Entry point: `JitoTracker`.
- **`jito_sdk.py`** — Standalone read-only client (stdlib only, zero deps).
  Use this for dashboards and monitors that only need to query chain state.

## Key files

- `auth.py`: JWT create/verify utilities.
- `dual_chain.py`: wallet/signing + public/private chain engines.
- `node.py`: node server, security, P2P sync, UI endpoints.
- `evm_gateway.py`: starter EVM JSON-RPC gateway mapped from public chain.
- `web_ui.html`: interactive browser control panel.
- `rwa_ui.html`: dedicated private RWA tokenization portal.
- `community_ui.html`: community + AI activity hub and leaderboards.
- `explorer_ui.html`: full explorer UI pages.
- `scanner_ui.html`: explorer/scanner UI.
- `cli.py`: CLI for wallets, governance, finality, node operations.
- `jito_sdk.py`: standalone read-only Python client (stdlib only) for dashboards and monitors.
- `jito_agent/`: full agent SDK with signing (`JitoTracker`, `load_wallet`, tx builders).
- `scripts/e2e_full_stack.sh`: end-to-end phase smoke test script.
- `tests/test_blockchain.py`, `tests/test_auth.py`, `tests/test_evm_gateway.py`, `tests/test_node.py`: test suite.
- `tests/test_agent_trust.py`: agent trust system and governance tests.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

```

## Test from UI (quick start)

Start node:

```bash
python cli.py node-start --host 127.0.0.1 --port 8000 --data-dir node_data
```

Set blockchain identity/token metadata:

```bash
python cli.py node-start \
  --host 127.0.0.1 --port 8000 --data-dir node_data \
  --chain-name "JITO Public Network" \
  --token-name "JITO" \
  --token-symbol JITO \
  --token-decimals 18
```

Enable validator-based public consensus (hard step):

```bash
python cli.py node-start \
  --host 127.0.0.1 --port 8000 --data-dir node_data \
  --public-consensus poa \
  --public-validator <VALIDATOR_ADDRESS_1> \
  --public-validator <VALIDATOR_ADDRESS_2>
```

Enable auto-mining and branding at startup:

```bash
python cli.py node-start \
  --host 127.0.0.1 --port 8000 --data-dir node_data \
  --public-consensus poa \
  --public-validator <VALIDATOR_ADDRESS> \
  --auto-mine --auto-mine-miner <VALIDATOR_ADDRESS> --auto-mine-interval 5 \
  --chain-logo-url "https://example.com/jito-chain.png" \
  --token-logo-url "https://example.com/jito-token.png"
```

Enable faucet mode (testnet/dev recommended, keep disabled for mainnet):

```bash
python cli.py node-start \
  --host 127.0.0.1 --port 8000 --data-dir node_data \
  --public-consensus poa \
  --public-validator <VALIDATOR_ADDRESS> \
  --auto-mine --auto-mine-miner <VALIDATOR_ADDRESS> --auto-mine-interval 5 \
  --public-faucet-enabled \
  --public-faucet-amount 10 \
  --public-faucet-cooldown 3600 \
  --public-faucet-daily-cap 5000
```

Open:
- `http://127.0.0.1:8000/ui`
- `http://127.0.0.1:8000/rwa`
- `http://127.0.0.1:8000/rwa-market`
- `http://127.0.0.1:8000/explorer`
- `http://127.0.0.1:8000/scanner`

Private testing shortcut in UI:
- In `/ui`, use **RWA Quickstart** card to run end-to-end tokenization:
  register roles -> governance domain/contract -> issue -> seal -> attest -> holdings.

Dedicated RWA issuer flow:
- In `/rwa`, fill issuer/owner/validator/notary + asset valuation/legal fields.
- Click **Tokenize Asset (0 Gas)** to run governance + issuance + finality in one step.
- Use **Private Trade** in the same page to transfer tokenized units (also 0 gas on private chain).
- In `/rwa-market`, create public listing records and execute buy operations with private-chain finality.

Scanner features:
- Latest public blocks table.
- Latest tx across public/private chains.
- Search by tx hash, address, symbol, or block index.
- Address detail (public balance + optional private asset balances).
- Transaction detail with chain location/confirmations.
- Price history from on-chain oracle updates.

Explorer (`/explorer`) pages:
- Dashboard.
- Blocks (public/private pagination).
- Transactions (filters + pagination).
- Address inspector.
- Prices and history.
- Analytics (`/scan/activity` + `/metrics`).
- Chain/token metadata loaded from `GET /chain/info`.

From the UI, you can:
- Create wallets.
- Send/mine public transactions.
- Register private participants/roles.
- Propose/approve governance actions.
- Issue/transfer assets.
- Seal + attest (finalize) private blocks.
- Register oracle wallets and push on-chain coin prices.

## On-chain price flow (CLI)

```bash
python cli.py --node-url http://127.0.0.1:8000 public-register-oracle --wallet wallets/oracle.json
python cli.py --node-url http://127.0.0.1:8000 public-price-update --wallet wallets/oracle.json --symbol JITO --price 1.23 --source manual-cli
python cli.py --node-url http://127.0.0.1:8000 public-mine --miner <ORACLE_ADDRESS>
python cli.py --node-url http://127.0.0.1:8000 public-price --symbol JITO
```

## Enable JWT auth

Start node with JWT:

```bash
python cli.py node-start \
  --host 127.0.0.1 --port 8000 --data-dir node_data \
  --jwt-secret mysecret --jwt-required
```

Generate token:

```bash
python cli.py auth-token --secret mysecret --subject alice --ttl-seconds 3600
```

Use token in CLI calls:

```bash
python cli.py --node-url http://127.0.0.1:8000 --auth-token <TOKEN> private-governance
```

Use token in UI:
- Paste token into the top `Auth` field and click `Save Token`.

## EVM JSON-RPC gateway (MetaMask path starter)

Start node (if not running):

```bash
python cli.py node-start --host 127.0.0.1 --port 8000 --data-dir node_data
```

Start gateway:

```bash
python cli.py evm-gateway-start \
  --rpc-node-url http://127.0.0.1:8000 \
  --host 127.0.0.1 --port 8545 \
  --chain-id 149
```

If your node requires JWT:

```bash
python cli.py evm-gateway-start \
  --rpc-node-url http://127.0.0.1:8000 \
  --rpc-auth-token <TOKEN> \
  --host 127.0.0.1 --port 8545 \
  --chain-id 149
```

Add network in MetaMask:
- Network Name: `JITO Local`
- RPC URL: `http://127.0.0.1:8545`
- Chain ID: `149`
- Symbol: `JITO`
- Block Explorer URL (optional): `http://127.0.0.1:8000/explorer`

Note on logos:
- Explorer/scanner logos are controlled by `chain_logo_url` and `token_logo_url` on JITO.
- MetaMask may not show custom icons for a local native gas token; imported ERC-20 tokens support custom logos better.

Important:
- This gateway remains a starter compatibility layer.
- `eth_sendRawTransaction` is now implemented for EVM value-transfer tx and bridged as `evm_payment` on the public chain.
- `eth_sendTransaction` remains disabled (gateway does not hold private keys).
- Contract calls/deployments are not implemented yet.
- You still mine/finalize blocks with native node APIs.

Raw tx bridge behavior:
- Sender is recovered from the EVM signature.
- Sender/recipient are mapped to internal ledger accounts (`EVM:0x...`).
- Nonce and balance checks are enforced on bridged `evm_payment` tx.
- Gas fees are charged in native token and added to miner reward on block production.

Testing `eth_sendRawTransaction` quickly:

1. Fund an EVM account ledger by mining to `EVM:0x...`:
```bash
python cli.py --node-url http://127.0.0.1:8000 public-mine --miner EVM:0x<sender_address_lowercase>
```
2. Send signed raw tx to gateway:
```bash
curl -X POST http://127.0.0.1:8545 \
  -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["0x<signed_raw_tx_hex>"]}'
```
3. Mine again to include pending tx:
```bash
python cli.py --node-url http://127.0.0.1:8000 public-mine --miner EVM:0x<sender_address_lowercase>
```

Supported JSON-RPC methods (starter set):
- `web3_clientVersion`, `net_version`, `eth_chainId`
- `eth_blockNumber`, `eth_getBlockByNumber`, `eth_getBlockByHash`
- `eth_getBlockTransactionCountByNumber`, `eth_getBlockTransactionCountByHash`
- `eth_getTransactionByBlockNumberAndIndex`, `eth_getTransactionByBlockHashAndIndex`
- `eth_getTransactionByHash`, `eth_getTransactionReceipt`
- `eth_getBalance`, `eth_getTransactionCount`
- `eth_gasPrice`, `eth_estimateGas`, `eth_feeHistory`
- `eth_getLogs`, `eth_getCode`, `eth_call`, `eth_accounts`
- `eth_sendRawTransaction` (value transfer bridge)

## Transaction flows

1. UI flow
- Open `/ui` for wallet creation + tx/mine.
- Open `/explorer` or `/scanner` to verify tx/blocks/balances.

2. Native CLI flow
```bash
python cli.py wallet-create --name alice --out wallets/alice.json
python cli.py wallet-create --name bob --out wallets/bob.json
python cli.py --node-url http://127.0.0.1:8000 public-mine --miner <ALICE_ADDRESS>
python cli.py --node-url http://127.0.0.1:8000 public-tx --wallet wallets/alice.json --to <BOB_ADDRESS> --amount 2.5
python cli.py --node-url http://127.0.0.1:8000 public-mine --miner <ALICE_ADDRESS>
```

4. Public consensus operations (PoA validators)
```bash
python cli.py --node-url http://127.0.0.1:8000 public-consensus
python cli.py --node-url http://127.0.0.1:8000 public-finality
python cli.py --node-url http://127.0.0.1:8000 public-slo
python cli.py --node-url http://127.0.0.1:8000 public-performance --window-blocks 60
python cli.py --node-url http://127.0.0.1:8000 public-validator-add --validator <VALIDATOR_ADDRESS>
python cli.py --node-url http://127.0.0.1:8000 public-validator-remove --validator <VALIDATOR_ADDRESS>
python cli.py --node-url http://127.0.0.1:8000 public-validator-update --wallet wallets/validator1.json --action add --validator <VALIDATOR_ADDRESS>
python cli.py --node-url http://127.0.0.1:8000 public-auto-mine-start --miner <VALIDATOR_ADDRESS> --interval-seconds 5
python cli.py --node-url http://127.0.0.1:8000 public-auto-mine-status
python cli.py --node-url http://127.0.0.1:8000 public-auto-mine-stop
python cli.py --node-url http://127.0.0.1:8000 public-ai-provider-stake --wallet wallets/provider.json --amount 10
python cli.py --node-url http://127.0.0.1:8000 public-ai-provider-slash --wallet wallets/validator1.json --provider <PROVIDER_ADDRESS> --amount 1 --reason "invalid-result"
python cli.py --node-url http://127.0.0.1:8000 public-ai-stakes
python cli.py --node-url http://127.0.0.1:8000 public-faucet-status
python cli.py --node-url http://127.0.0.1:8000 public-faucet-claim --to EVM:0x<address> --amount 10
python cli.py --node-url http://127.0.0.1:8000 chain-branding \
  --chain-logo-url "https://example.com/jito-chain.png" \
  --token-logo-url "https://example.com/jito-token.png"
```

5. AI-native private chain flow
```bash
python cli.py --node-url http://127.0.0.1:8000 private-ai-model-register \
  --wallet wallets/alice.json --model-id model-sentiment-v1 --model-hash sha256:abc \
  --version 1.0.0 --price-per-call 0.25 --visibility "<ADDR1>,<ADDR2>"

python cli.py --node-url http://127.0.0.1:8000 private-ai-job-create \
  --wallet wallets/bob.json --job-id job-1 --model-id model-sentiment-v1 \
  --input-hash sha256:input --max-payment 1.0 --visibility "<ADDR2>,<ADDR3>"

python cli.py --node-url http://127.0.0.1:8000 private-ai-job-result \
  --wallet wallets/provider.json --job-id job-1 --result-hash sha256:result --quality-score 0.98

python cli.py --node-url http://127.0.0.1:8000 private-ai-job-settle \
  --wallet wallets/validator1.json --job-id job-1 --payout 0.9 --slash-provider 0

python cli.py --node-url http://127.0.0.1:8000 private-ai-models
python cli.py --node-url http://127.0.0.1:8000 private-ai-jobs
python cli.py --node-url http://127.0.0.1:8000 private-domains --include-pending
```

6. End-to-end full phase smoke test
```bash
./scripts/e2e_full_stack.sh
```

3. EVM wallet flow (gateway)
- Fund sender ledger with mining to `EVM:0x...`.
- Broadcast signed raw tx to gateway (`eth_sendRawTransaction`).
- Mine next block to finalize.

## Enable TLS / mTLS

Start TLS node:

```bash
python cli.py node-start \
  --host 127.0.0.1 --port 8443 --data-dir node_secure \
  --tls-cert certs/server.crt \
  --tls-key certs/server.key
```

Require client certs (mTLS):

```bash
python cli.py node-start \
  --host 127.0.0.1 --port 8443 --data-dir node_secure \
  --tls-cert certs/server.crt \
  --tls-key certs/server.key \
  --tls-ca certs/ca.crt \
  --tls-require-client-cert
```

## Cloud signer adapters

Switch wallet to a cloud signer config:

```bash
python cli.py wallet-set-signer \
  --wallet wallets/alice.json \
  --signer-type aws-kms \
  --config-json '{"key_id":"arn:aws:kms:...","region":"us-east-1","signing_algorithm":"EDDSA"}' \
  --drop-private-key
```

Examples:

```bash
# AWS KMS
python cli.py wallet-set-signer --wallet wallets/alice.json --signer-type aws-kms \
  --config-json '{"key_id":"arn:aws:kms:...","region":"us-east-1","signing_algorithm":"EDDSA"}' --drop-private-key

# GCP KMS
python cli.py wallet-set-signer --wallet wallets/alice.json --signer-type gcp-kms \
  --config-json '{"project":"my-project","location":"us-central1","keyring":"ring1","key":"key1","version":"1"}' --drop-private-key

# Azure Key Vault
python cli.py wallet-set-signer --wallet wallets/alice.json --signer-type azure-kv \
  --config-json '{"key_id":"https://<vault>.vault.azure.net/keys/<key>/<version>","algorithm":"EdDSA"}' --drop-private-key

# Security audit (fail if any local signer/private key remains in wallets dir)
python cli.py wallet-security-audit --wallet-dir wallets --require-nonlocal --require-no-private-key
```

## Production hardening mode

`node-start` supports `--mainnet-hardening` and will fail startup unless all guardrails pass:
- public consensus is `poa`
- at least 2 validators are configured
- proposer rotation is enabled
- faucet is disabled

Example:

```bash
python cli.py node-start \
  --host 127.0.0.1 --port 8000 --data-dir node_data \
  --public-consensus poa \
  --public-validator <VALIDATOR_1> \
  --public-validator <VALIDATOR_2> \
  --mainnet-hardening
```

For docker live deployment set:
- `MAINNET_HARDENING=true`
- `PUBLIC_FAUCET_ENABLED=false`

## Token pricing / valuation

JITO token price is market-discovered from buy/sell liquidity, not by chain launch alone. See `docs/TOKEN_PRICING_BOOTSTRAP.md` for the practical launch model.

## Docker 2-node network

```bash
docker compose up --build
```

Node UI URLs:
- `http://localhost:8001/ui`
- `http://localhost:8002/ui`

Optional envs in compose:
- `JWT_SECRET`, `JWT_REQUIRED`, `PEER_TOKEN`
- `TLS_CERT`, `TLS_KEY`, `TLS_CA`, `TLS_REQUIRE_CLIENT_CERT`, `PEER_CA`
- `PUBLIC_FAUCET_ENABLED`, `PUBLIC_FAUCET_AMOUNT`, `PUBLIC_FAUCET_COOLDOWN`, `PUBLIC_FAUCET_DAILY_CAP`
- `MAINNET_HARDENING`
- `NODE_BIND_ADDR`, `RPC_BIND_ADDR` (set to `127.0.0.1` for private bind behind reverse proxy)

## Backup / restore

Create backup archive:

```bash
./scripts/backup_state.sh --data-dir node_data --out-dir backups --label jito-mainnet --keep 14
```

Restore backup:

```bash
./scripts/restore_state.sh --backup backups/jito-mainnet-state-<timestamp>.tar.gz --target-dir node_data --force
```

## Health probe (monitoring hook)

```bash
./scripts/health_probe.sh
```

Use this in cron/systemd and alert on non-zero exit.

## Live deployment + Chainlist

Deploy single public node + EVM gateway:

```bash
docker compose -f docker-compose.live.yml up -d --build
```

Then follow:
- `docs/CHAINLIST_GO_LIVE.md`
- `docs/chainlist/eip155-149.json`
- `docs/chainlist/defillama-rpc-submission.md`

## Run tests

```bash
./run_tests.sh
```

## API summary

- `GET /ui`
- `GET /app`
- `GET /app/investor`
- `GET /app/issuer`
- `GET /app/operator`
- `GET /rwa`
- `GET /rwa-market`
- `GET /explorer`
- `GET /scanner`
- `GET /ui/wallets`
- `POST /ui/wallets/create`
- `POST /ui/public/tx`
- `POST /ui/public/mine`
- `POST /ui/public/oracle/register`
- `POST /ui/public/price/update`
- `POST /ui/private/register`
- `POST /ui/private/propose`
- `POST /ui/private/approve`
- `POST /ui/private/issue`
- `POST /ui/private/rwa/tokenize`
- `POST /ui/private/rwa/listings/create`
- `POST /ui/private/rwa/listings/buy`
- `POST /ui/private/transfer`
- `POST /ui/private/seal`
- `POST /ui/private/attest`
- `GET /status`
- `GET /chain/info`
- `POST /chain/branding`
- `GET /public/chain`
- `GET /public/consensus`
- `GET /public/finality`
- `GET /public/mempool`
- `GET /public/performance`
- `GET /public/auto-mine`
- `GET /public/ai/stakes`
- `GET /public/faucet/status`
- `GET /public/prices`
- `GET /public/price`
- `POST /public/auto-mine/start`
- `POST /public/auto-mine/stop`
- `POST /public/faucet/claim`
- `POST /public/oracle/register`
- `POST /public/validators/add`
- `POST /public/validators/remove`
- `POST /public/price/update`
- `GET /scan/summary`
- `GET /scan/blocks`
- `GET /scan/block`
- `GET /scan/transactions`
- `GET /scan/tx`
- `GET /scan/address`
- `GET /scan/activity`
- `GET /scan/prices/history`
- `GET /scan/search`
- `GET /events`
- `GET /stream/events`
- `GET /community/overview`
- `GET /community/leaderboard`
- `GET /community/roadmap`
- `GET /metrics`
- `GET /slo`
- `GET /private/chain`
- `GET /private/governance`
- `GET /private/pending-blocks`
- `GET /private/assets`
- `GET /private/view`
- `GET /private/domains`
- `GET /private/rwa/policy`
- `GET /private/rwa/listings`
- `GET /private/ai/models`
- `GET /private/ai/jobs`

## Big blockchain execution docs

- `docs/EVM_COMPATIBILITY_ROADMAP.md`
- `docs/BIG_BLOCKCHAIN_EXECUTION_PLAN.md`
- `docs/AI_NATIVE_GAMEPLAN.md`
- `docs/PRIVATE_CHAIN_OPERATING_MODEL.md`
- `docs/TOKEN_PRICING_BOOTSTRAP.md`
- `docs/MAINNET_HARDENING_RUNBOOK.md`
- `docs/PERFORMANCE_RUNBOOK.md`
- `docs/PLATFORM_EXECUTION_PLAN.md`

This remains a production-style prototype and still needs full operational hardening before mainnet use.
