#!/usr/bin/env python3
"""
Seed the JITO chain with demo identities, agents, tasks, proposals, and models.
Builds + signs transactions locally, submits via POST /public/tx.

Run: python3 seed_demo.py [--node https://explorer.flowpe.io] [--dry-run]
"""
import argparse, json, time, urllib.request, urllib.error, sys, os, hashlib, base64

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dual_chain import (
    make_identity_claim_tx, make_agent_register_tx,
    make_model_register_tx, make_task_delegate_tx,
    make_governance_propose_tx, make_governance_vote_tx,
    make_validator_nominate_tx, address_from_public_key,
)


def post_tx(node, tx, timeout=20):
    """Submit a pre-signed transaction to the node."""
    url = f"{node}/public/tx"
    body = json.dumps(tx).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read()), None
    except urllib.error.HTTPError as e:
        return None, f"{e.code}: {e.read().decode()[:200]}"
    except Exception as e:
        return None, str(e)


def post_json(node, path, data, timeout=20):
    url = f"{node}{path}"
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read()), None
    except urllib.error.HTTPError as e:
        return None, f"{e.code}: {e.read().decode()[:200]}"
    except Exception as e:
        return None, str(e)


def get(url, timeout=10):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.loads(r.read()), None
    except Exception as e:
        return None, str(e)


def make_wallet(seed: str) -> dict:
    seed_bytes = hashlib.sha256(seed.encode()).digest()
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
        sk = Ed25519PrivateKey.from_private_bytes(seed_bytes)
        pub_raw = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        priv_raw = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        public_key = {"kty": "ed25519", "key": base64.b64encode(pub_raw).decode("ascii")}
        private_key = {"kty": "ed25519", "key": base64.b64encode(priv_raw).decode("ascii")}
        address = address_from_public_key(public_key)
        return {"address": address, "public_key": public_key, "private_key": private_key}
    except ImportError:
        print("pip install cryptography"); sys.exit(1)


def ok(msg): print(f"  ✅ {msg}")
def skip(msg): print(f"  ⏭️  {msg}")
def fail(msg): print(f"  ❌ {msg}")
def step(msg): print(f"\n{'='*55}\n  {msg}\n{'='*55}")

def submit(node, tx, label, dry):
    if dry:
        ok(f"[dry] {label}"); return True
    # The tx from builder functions is {payload, signature, public_key}
    # node /public/tx expects the full wrapped tx
    r, e = post_tx(node, tx)
    if e:
        fail(f"{label}: {e}"); return False
    ok(f"{label}")
    return True


USERS = [
    {"seed": "alice_jito_seed", "handle": "alice", "bio": "JITO founding member. DeFi researcher."},
    {"seed": "bob_jito_seed", "handle": "bob_builder", "bio": "Smart contract dev. Building on JITO."},
    {"seed": "carol_jito_seed", "handle": "carol", "bio": "RWA specialist. Tokenizing real estate."},
    {"seed": "dave_jito_seed", "handle": "dave_validator", "bio": "Running JITO validator since genesis."},
    {"seed": "eva_jito_seed", "handle": "eva_ai", "bio": "AI researcher. Creator of JITO AI agents."},
]

AGENTS = [
    {"seed": "agent_analyst_seed", "id": "agent-data-analyst", "name": "DataAnalyst-v1",
     "caps": ["data_analysis", "statistics", "csv_processing"]},
    {"seed": "agent_writer_seed", "id": "agent-content-writer", "name": "ContentWriter-v2",
     "caps": ["writing", "summarization", "translation"]},
    {"seed": "agent_oracle_seed", "id": "agent-rwa-oracle", "name": "RWA-Oracle-v1",
     "caps": ["price_verification", "compliance_check", "asset_valuation"]},
]

MODELS = [
    {"id": "model-gpt4o-proxy", "name": "GPT-4o Proxy",
     "desc": "OpenAI GPT-4o through JITO marketplace", "caps": ["text_generation", "analysis", "coding"], "fee": 0.5},
    {"id": "model-llama-local", "name": "Llama-3-8B",
     "desc": "Open-source Llama 3 — fast and cheap", "caps": ["text_generation", "summarization"], "fee": 0.1},
]

TASKS = [
    {"title": "Analyze Q4 2024 DeFi market trends",
     "desc": "Compile key DeFi metrics from Q4 2024: TVL changes, top protocols, yield trends. 500-word summary.",
     "reward": 20.0},
    {"title": "Write JITO whitepaper executive summary",
     "desc": "300-word executive summary: dual-chain architecture, AI marketplace, RWA integration, governance.",
     "reward": 25.0},
    {"title": "Sentiment analysis of crypto Twitter Jan 2025",
     "desc": "Analyze crypto Twitter sentiment Jan 2025. JSON output with scores for BTC, ETH, SOL, JITO.",
     "reward": 15.0},
    {"title": "Carbon credit price verification",
     "desc": "Verify price for 1000 ton CO2e carbon credits from MUMB-2024-CC-0041. Cross-reference 3 exchanges.",
     "reward": 30.0},
]

PROPOSALS = [
    {"title": "Reduce block interval to 3 seconds",
     "desc": "Current 5s: reduce to 3s for faster confirmation. Impact: higher throughput.",
     "changes": {"AUTO_MINE_INTERVAL": 3}},
    {"title": "Increase faucet to 250 JITO",
     "desc": "100 JITO insufficient to post tasks + maintain balance. Proposal: 250 JITO, same 24h cooldown.",
     "changes": {"PUBLIC_FAUCET_AMOUNT": 250}},
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", default="https://explorer.flowpe.io")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    node = args.node.rstrip("/")
    dry = args.dry_run

    print(f"\n🌱 JITO Chain Seeder  |  {node}{'  [DRY RUN]' if dry else ''}")

    data, err = get(f"{node}/status")
    if err:
        print(f"❌ Node unreachable: {err}"); sys.exit(1)
    print(f"   Height: {data.get('public_height')}  Valid: {data.get('public_valid')}")

    wallets = {u["seed"]: make_wallet(u["seed"]) for u in USERS}
    agent_wallets = {a["seed"]: make_wallet(a["seed"]) for a in AGENTS}
    model_owner = wallets[USERS[4]["seed"]]

    step("1 / 7 — Faucet")
    all_seeds = [(u["seed"], u["handle"], wallets) for u in USERS] + \
                [(a["seed"], a["name"], agent_wallets) for a in AGENTS]
    for seed, label, wmap in all_seeds:
        w = wmap[seed]
        bal, _ = get(f"{node}/public/balance?address={w['address']}")
        if bal and bal.get("balance", 0) >= 50:
            skip(f"{label}: {bal['balance']} JITO"); continue
        if not dry:
            r, e = post_json(node, "/public/faucet/claim", {"address": w["address"]})
            (ok if not e else fail)(f"{label}: {'claimed 100 JITO' if not e else e}")
        else:
            ok(f"[dry] faucet → {label}")
        time.sleep(0.3)

    if not dry:
        print("  ⏳ Waiting 12s for faucet txs to be mined...")
        time.sleep(12)

    step("2 / 7 — Identities")
    for u in USERS:
        w = wallets[u["seed"]]
        ex, _ = get(f"{node}/identity/{w['address']}")
        if ex and (ex.get("handle") or ex.get("identity", {}).get("handle")):
            skip(f"@{u['handle']}: exists"); continue
        tx = make_identity_claim_tx(w, u["handle"], u["bio"])
        submit(node, tx, f"@{u['handle']}", dry)
        time.sleep(0.4)

    step("3 / 7 — AI Agents")
    for a in AGENTS:
        w = agent_wallets[a["seed"]]
        ex, _ = get(f"{node}/agents/{a['id']}")
        if ex and ex.get("agent_id"):
            skip(f"{a['name']}: exists"); continue
        tx = make_agent_register_tx(w, a["id"], a["name"], capabilities=a["caps"],
                                     version_hash=hashlib.sha256(a["id"].encode()).hexdigest()[:16])
        submit(node, tx, a["name"], dry)
        time.sleep(0.4)

    step("4 / 7 — AI Models")
    for m in MODELS:
        ex, _ = get(f"{node}/models/{m['id']}")
        if ex and ex.get("model_id"):
            skip(f"{m['name']}: exists"); continue
        tx = make_model_register_tx(model_owner, m["id"], m["name"], m["desc"],
                                     m["caps"], hashlib.sha256(m["id"].encode()).hexdigest()[:16], m["fee"])
        submit(node, tx, f"{m['name']} ({m['fee']} JITO/call)", dry)
        time.sleep(0.4)

    if not dry:
        print("  ⏳ Waiting 10s for pending txs to be mined...")
        time.sleep(10)

    step("5 / 7 — Tasks")
    # Distribute tasks across users so each wallet only needs its own reward amount
    task_owners = [wallets[USERS[i % len(USERS)]["seed"]] for i in range(len(TASKS))]
    for t, task_owner in zip(TASKS, task_owners):
        if not dry:
            bal, _ = get(f"{node}/public/balance/{task_owner['address']}")
            if bal and bal.get("balance", 0) < t["reward"]:
                fail(f"Low balance for: {t['title'][:40]}"); continue
        tx = make_task_delegate_tx(task_owner, "", t["title"], t["desc"], t["reward"])
        submit(node, tx, f"{t['title'][:45]} (+{t['reward']} JITO)", dry)
        time.sleep(0.4)

    step("6 / 7 — Governance Proposals + Votes")
    proposer = wallets[USERS[3]["seed"]]
    for p in PROPOSALS:
        tx = make_governance_propose_tx(proposer, p["title"], p["desc"], p["changes"], 200)
        ok_result = submit(node, tx, p["title"][:45], dry)
        if ok_result and not dry:
            time.sleep(0.5)
            # Have alice + bob vote yes
            props, _ = get(f"{node}/governance/proposals?status=open")
            if props and props.get("proposals"):
                last_prop = props["proposals"][0]
                prop_id = last_prop["proposal_id"]
                for voter_user in USERS[:2]:
                    vote_tx = make_governance_vote_tx(wallets[voter_user["seed"]], prop_id, True)
                    submit(node, vote_tx, f"@{voter_user['handle']} votes YES", dry)
                    time.sleep(0.2)
        time.sleep(0.4)

    step("7 / 7 — Validator Nominations")
    for u in USERS[2:4]:
        w = wallets[u["seed"]]
        tx = make_validator_nominate_tx(w)
        submit(node, tx, f"@{u['handle']} nominated", dry)
        time.sleep(0.3)

    if not dry:
        print("\n📊 Final state:")
        for endpoint, label in [("/identities", "Identities"), ("/agents", "Agents"),
                                  ("/tasks", "Tasks"), ("/governance/proposals", "Proposals"),
                                  ("/models", "Models"), ("/validator/candidates", "Candidates")]:
            d, _ = get(f"{node}{endpoint}")
            print(f"   {label}: {d.get('count', 0) if d else '?'}")

    print(f"\n   Community:  {node}/community")
    print(f"   Onboarding: {node}/onboarding\n")


if __name__ == "__main__":
    main()
