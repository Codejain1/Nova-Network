# Running a NOVA Validator Node

Validators secure the NOVA PublicPaymentChain using Proof of Authority (PoA) consensus with validator rotation. Each validator earns **22.5 NOVA per block** (~5-second block time).

---

## Economics

| Metric | Value |
|--------|-------|
| Block reward | 25.0 NOVA |
| Treasury fee | 10% (2.5 NOVA) |
| Net to validator | **22.5 NOVA/block** |
| Target block time | 5 seconds |
| Blocks/day | ~17,280 |
| NOVA/day (1 of 3 validators) | ~5,760 |
| NOVA/year (1 of 3 validators) | ~**47,400** |
| Minimum stake to nominate | **500 NOVA** |
| Votes needed for promotion | **3** |
| Unbonding period | **100 blocks (~8 min)** |

---

## Hardware Requirements

- **CPU**: 2 vCPU (Azure B2s, AWS t3.small, or equivalent)
- **RAM**: 4 GB
- **Disk**: 20 GB SSD
- **OS**: Ubuntu 22.04 LTS or macOS
- **Software**: Docker, Docker Compose v2, Python 3.10+
- **Network**: Outbound HTTPS on port 443; inbound on port 8000

---

## Step 1 — Clone and configure

```bash
git clone https://github.com/jito-labs/nova-chain.git
cd nova-chain
cp .env.live.example .env.live
```

Edit `.env.live`:
```bash
AUTO_MINE_MINER=auto              # auto-follow PoA rotation
AUTO_MINE_INTERVAL=5
PEERS=http://10.0.0.4:8000,http://10.0.0.5:8000   # existing peers
NODE_NAME=my-validator-node
```

---

## Step 2 — Generate your validator key

```python
from jito_agent import create_wallet, save_wallet

wallet = create_wallet(label="my-validator")
save_wallet(wallet, "~/.nova/validator.json")
print("Validator address:", wallet["address"])
```

Or generate on the node directly:
```bash
python3 -c "
from dual_chain import generate_wallet
import json
w = generate_wallet()
print(json.dumps(w, indent=2))
" > validator_wallet.json
```

Add to `.env.live`:
```bash
VALIDATOR_KEY_1=<base64-private-key>
```

---

## Step 3 — Start the node

```bash
docker compose -f docker-compose.live.yml --env-file .env.live up --build -d node
```

Check it's running:
```bash
curl http://localhost:8000/status | python3 -m json.tool | grep -E 'height|valid|peers'
```

You should see:
```json
{
  "public_height": 12,
  "public_valid": true,
  "peers": ["http://..."]
}
```

---

## Step 4 — Fund your validator wallet

Get 500 NOVA from the faucet:
```python
from jito_agent import NovaClient

client = NovaClient("https://explorer.flowpe.io")
client.claim_faucet("YOUR_VALIDATOR_ADDRESS")
# Returns 100 NOVA — repeat 5 times across 5 days, or earn via tasks
```

Or ask an existing validator to send NOVA directly.

Check balance:
```bash
curl "https://explorer.flowpe.io/public/balance?address=YOUR_ADDRESS"
```

---

## Step 5 — Nominate yourself as a validator

Via the node API (using a named wallet stored on the node):
```bash
curl -X POST http://localhost:8000/public/validator/nominate \
  -H "Content-Type: application/json" \
  -d '{"wallet": "validator1", "stake_amount": 500}'
```

Or via the SDK:
```python
from dual_chain import make_validator_nominate_tx
import requests

tx = make_validator_nominate_tx(wallet, stake_amount=500.0)
requests.post("https://explorer.flowpe.io/public/tx", json=tx)
```

Your 500 NOVA is now locked as stake. Check your candidacy:
```bash
curl https://explorer.flowpe.io/public/validator/candidates
```

---

## Step 6 — Get 3 community votes

Ask existing community members to vote for you:
```bash
# They run this (from a node with their wallet):
curl -X POST http://localhost:8000/public/validator/vote \
  -H "Content-Type: application/json" \
  -d '{"wallet": "voter-wallet", "candidate": "YOUR_VALIDATOR_ADDRESS"}'
```

Once you have 3 votes AND stake ≥ 500 NOVA → **auto-promoted to active validator set**.

---

## Step 7 — Verify you're in the active set

```bash
curl https://explorer.flowpe.io/status | python3 -m json.tool | grep -A 10 validators
```

You should see your address in `public_validators`.

---

## Step 8 — Add yourself to the PEERS list on other nodes

Contact other node operators to add your node's IP to their `PEERS` env var and restart. Peer sync is automatic once connected.

---

## Unstaking / Exiting

To withdraw your stake and exit the validator set:
```bash
curl -X POST http://localhost:8000/public/validator/unstake \
  -H "Content-Type: application/json" \
  -d '{"wallet": "validator1"}'
```

Your 500 NOVA is returned after the **100-block unbonding period** (~8 minutes at 5s/block).

---

## Monitoring

**Check your node:**
```bash
# Chain health
curl http://localhost:8000/status

# Last block mined by your node
curl http://localhost:8000/status | python3 -m json.tool | grep -A 10 auto_mine

# Peer sync
curl http://localhost:8000/status | python3 -m json.tool | grep -A 20 peer_health
```

**View earnings:**
```bash
curl "http://localhost:8000/public/balance?address=YOUR_ADDRESS"
```

**View reputation:**
```bash
curl "http://localhost:8000/reputation/YOUR_ADDRESS"
```

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `public_valid: false` | Check chain height — may need resync. Verify `is_valid()` passes: `docker logs nova-node \| grep valid` |
| Auto-miner not mining | Check `auto_mine.thread_alive` in `/status`. Set `AUTO_MINE_MINER=auto` in `.env.live` |
| Wrong validator turn | PoA rotation: only mine when it's your turn. `auto=true` handles this automatically |
| Peers not syncing | Verify `PEERS` env var is set and both IPs are reachable on port 8000 |
| Stake rejected | Must have ≥ 500 NOVA balance before nominating |
| "not in validator set" error | You haven't been promoted yet — need 3 votes first |

---

## Slashing (Phase 3 — not yet active)

Future slashing conditions:
- Double-signing a block at the same height → 100% slash
- Extended offline period (>1000 missed blocks) → 10% slash

---

## Links

- Explorer: https://explorer.flowpe.io
- SDK: `pip install jito-agent`
- Validator candidates: https://explorer.flowpe.io → Validators tab
- Developer guide: [ONBOARDING_GUIDE.md](ONBOARDING_GUIDE.md)
