# JITO Platform Execution Plan (30/60/90)

This plan prioritizes production reliability first, then scalability, then product growth.

## Phase 1 (Days 0-30): Reliability + Operations Baseline

### Goals
- Keep public/private chains stable under normal load.
- Remove validator/config drift across restarts.
- Ship measurable runtime observability.

### Deliverables
- Validator bootstrap from configured validator set at node startup.
- Strict signature verification enabled in production.
- Mempool TTL + max-size controls with pruning stats.
- `/public/performance`, `/status`, `/metrics`, `/events` operational dashboards.
- Runbook for incident response and node restore.

### Success Metrics
- Node uptime >= 99.9%.
- Zero unresolved validator drift incidents.
- Mempool returns to near-zero after burst tests.

## Phase 2 (Days 31-60): Throughput + State Scalability

### Goals
- Raise sustained tx throughput and reduce block latency variance.
- Prevent large-state regressions as usage grows.

### Deliverables
- Optional parallel PoW workers for nonce search.
- Async peer snapshot broadcast + health-aware sync tuning.
- Persistent mempool replay across restart.
- Storage track decision: JSON+WAL hardening vs SQLite/RocksDB migration.

### Success Metrics
- 2x+ burst throughput improvement vs phase-1 baseline.
- p95 tx inclusion latency improvement under load.
- Clean restart with no pending tx loss.

## Phase 3 (Days 61-90): Product UX + Ecosystem Readiness

### Goals
- Make investor/issuer flows usable by non-technical users.
- Improve compatibility with standard blockchain tooling.

### Deliverables
- End-user wallet UX (portfolio, transfer, transaction timeline).
- RWA flow wizard: tokenize -> list -> access pass -> buy -> settlement.
- Explorer/scanner upgrades: better address, asset, and trade views.
- EVM compatibility hardening and verification runbooks.

### Success Metrics
- New user can complete first buy in < 10 minutes.
- 90%+ successful completion rate for tokenization + trade flow in QA scripts.
- Reduced support tickets for wallet and listing errors.

## Cross-Cutting Security Track (All Phases)

- Enforce non-local/HSM signer policies for privileged wallets.
- Add key rotation and signer audit jobs.
- Move cloud KMS integrations from subprocess calls to native SDKs.

## Deployment Governance

- All releases must pass:
  - automated tests
  - smoke runbook (public tx + RWA trade + sync)
  - rollback checklist
- Use staged rollout: VM2 canary -> VM1 full rollout.
