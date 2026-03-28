# JITO Mainnet Hardening Runbook

## 1) Key management

1. Migrate validator wallets away from local private keys.
2. Use `wallet-set-signer` with `aws-kms`, `gcp-kms`, `azure-kv`, or `file-hsm`.
3. Run audit and fail deployment if local keys remain:

```bash
python cli.py wallet-security-audit --wallet-dir wallets --require-nonlocal --require-no-private-key
```

## 2) Runtime guardrails

Enable:
- `PUBLIC_CONSENSUS=poa`
- 2+ entries in `PUBLIC_VALIDATORS`
- `PUBLIC_VALIDATOR_ROTATION=true`
- `PUBLIC_FAUCET_ENABLED=false`
- `MAINNET_HARDENING=true`

## 3) Network exposure

- Prefer binding `8000/8545` to localhost and proxy through Caddy.
- Azure NSG inbound should be only: `22`, `80`, `443`.

## 4) Backups

Daily backup:

```bash
./scripts/backup_state.sh --data-dir node_data --out-dir backups --label jito-mainnet --keep 14
```

Restore drill:

```bash
./scripts/restore_state.sh --backup backups/jito-mainnet-state-<timestamp>.tar.gz --target-dir node_data --force
```

## 5) Verification

```bash
curl -sS https://explorer.flowpe.io/health
curl -sS https://rpc.flowpe.io/health
curl -sS https://explorer.flowpe.io/public/consensus
curl -sS https://explorer.flowpe.io/slo
./scripts/health_probe.sh
```

Expected:
- consensus `poa`
- validator rotation enabled
- `security.mainnet_hardening=true` in chain info
- faucet disabled
