# EVM Compatibility Roadmap

This repo now includes a starter JSON-RPC gateway (`evm_gateway.py`) so wallets and tools can begin integration with an EVM-style interface.

## Current state (implemented)

- Read-oriented JSON-RPC gateway translating public chain data into Ethereum-like responses.
- `eth_sendRawTransaction` bridge for EVM value transfer transactions.
- CLI command: `python cli.py evm-gateway-start ...`
- MetaMask custom network can connect to chain metadata and read block/tx state.
- `eth_sendTransaction` remains blocked until wallet/key management integration is added.

## Phase 1: Production-grade read compatibility

1. Complete method coverage for common explorer/indexer calls.
2. Add LRU cache and request budget controls for gateway performance.
3. Add API metrics (`latency`, `errors`, `method_count`) and rate limits.
4. Add integration tests against common wallet RPC probes.

## Phase 2: Signing and transaction ingress compatibility

1. Expand tx ingress beyond value transfer into contract deploy/call semantics.
2. Add mempool replacement logic (`nonce`, fee bump, dropped/replaced states).
3. Preserve full Ethereum receipt/log behavior for indexed tooling.
4. Harden replay protection and cross-chain signing constraints.

## Phase 3: EVM execution layer

1. Integrate an EVM interpreter/runtime.
2. Add state trie/account model and contract storage.
3. Implement gas accounting and fee market policy.
4. Add deterministic replay and state root verification.

## Phase 4: Mainnet wallet ecosystem

1. WalletConnect + MetaMask + hardware wallet test matrix.
2. RPC cluster with high availability and SLA alerts.
3. Public docs for chain config, token metadata, and node ops.
4. Production security review on RPC + execution pipeline.

## Exit criteria

- Wallet flows: send, receive, token transfer, contract deploy/call.
- Explorer parity: block, tx, token, account, logs, internal tx.
- Stable SLOs: p95 RPC latency + uptime + deterministic replay checks.
