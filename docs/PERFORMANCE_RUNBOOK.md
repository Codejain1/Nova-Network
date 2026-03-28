# Public Chain Performance Runbook

This runbook validates public-chain throughput, mempool behavior, and finalization health.

## 1) Baseline health

```bash
curl -sS https://explorer.flowpe.io/health | jq
curl -sS https://explorer.flowpe.io/status | jq '{public_height,public_pending,public_mempool,auto_mine:.auto_mine}'
curl -sS https://explorer.flowpe.io/public/consensus | jq
```

## 2) Run tx burst load test

```bash
python scripts/load_test_public.py \
  --node-url https://explorer.flowpe.io \
  --wallet-name validator1 \
  --to Weaabbad77aa5d46f5e426b366c931636520857b0 \
  --amount 0.0001 \
  --count 500
```

Output includes:
- `submission_tps`: tx enqueue rate at API layer.
- `mempool_pending_after_wait`: should return to `0` under healthy auto-mine.
- `public_performance`: chain-side avg block time + estimated TPS.

## 3) Inspect mempool policy and pruning

```bash
curl -sS https://explorer.flowpe.io/public/mempool?limit=5 | jq '{pending_count,policy}'
curl -sS https://explorer.flowpe.io/public/performance?window_blocks=120 | jq '.mempool'
```

Fields:
- `tx_ttl_seconds`: tx expiry TTL.
- `max_transactions`: mempool cap.
- `prune_stats.expired_total`: TTL expirations.
- `prune_stats.evicted_total`: size-cap evictions.

## 4) Prometheus metrics checkpoints

```bash
curl -sS https://explorer.flowpe.io/metrics | rg 'jain_public_(height|pending_tx|mempool)'
```

Key metrics:
- `jain_public_pending_tx`
- `jain_public_mempool_ttl_seconds`
- `jain_public_mempool_max_transactions`
- `jain_public_mempool_expired_total`
- `jain_public_mempool_evicted_total`

## 5) Tuning knobs (.env.live)

```env
STRICT_PUBLIC_SIGNATURES=true
PUBLIC_MEMPOOL_TTL=900
PUBLIC_MEMPOOL_MAX_SIZE=5000
PUBLIC_POW_WORKERS=1
PUBLIC_POW_NONCE_CHUNK=10000
AUTO_MINE_INTERVAL=5
AUTO_MINE_ALLOW_EMPTY=false
RATE_LIMIT_PER_MINUTE=300
```

After edits, redeploy node containers to apply changes.
