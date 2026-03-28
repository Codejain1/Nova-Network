# JITO Go-Live and Chainlist Plan

## Reality check first

- Chainlist listing does not force-add your network to every wallet automatically.
- Chainlist helps discovery; wallets and dapps still decide whether/how to integrate.
- For wallet auto-add flows, dapps use `wallet_addEthereumChain` (EIP-3085) and user approval.

## Phase 1: Go live with public endpoints

Before any listing PR, deploy public HTTPS endpoints:

1. Public JSON-RPC URL (gateway): `https://rpc.flowpe.io`
2. Public explorer URL: `https://explorer.flowpe.io` (or `/explorer` route)
3. Stable chain metadata:
   - Chain name: `JITO Public Network`
   - Chain ID: `149` (or your final permanent ID)
   - Native currency: `JITO`

Localhost URLs (`127.0.0.1`) are not acceptable for public listings.

### Deploy stack

Use the production compose file:

```bash
docker compose -f docker-compose.live.yml up -d --build
```

Set required envs (`.env`):

```bash
PUBLIC_CONSENSUS=poa
PUBLIC_VALIDATORS=W...
AUTO_MINE=true
AUTO_MINE_MINER=W...
CHAIN_ID=149
CHAIN_NAME=JITO Public Network
TOKEN_NAME=JITO
TOKEN_SYMBOL=JITO
```

## Phase 2: Validate production readiness

Check health and core RPC:

```bash
curl -s https://rpc.flowpe.io/health
curl -s -X POST https://rpc.flowpe.io \
  -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'
curl -s https://explorer.flowpe.io/chain/info
```

Minimum readiness before listing:

- 7+ days of stable uptime
- No frequent chain resets/replays
- Final chain ID locked
- Explorer + RPC latency acceptable

## Phase 3: Submit to chain registries

### 1) Ethereum chain registry (upstream source used by many list sites)

- Repo: `ethereum-lists/chains`
- Add file: `_data/chains/eip155-<chainId>.json`
- Use template: `docs/chainlist/eip155-149.json`

### 2) DefiLlama chainlist RPC source

- Repo: `DefiLlama/chainlist`
- PR template asks for provider website + privacy policy
- Use template: `docs/chainlist/defillama-rpc-submission.md`

## Phase 4: Wallet-side onboarding

- Publish a small dapp page with an "Add JITO Network" button using `wallet_addEthereumChain`.
- Keep chain metadata consistent everywhere:
  - chainId
  - rpcUrls
  - blockExplorerUrls
  - nativeCurrency

Inconsistent metadata is a common reason for wallet failures.
