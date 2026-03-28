#!/usr/bin/env python3
"""
Seed the JITO PrivateAssetChain with realistic RWA (Real World Asset) demo data.

Assets seeded:
  1. Mumbai Carbon Credits (MUMB-2024-CC-0041)  — 1 000 tons CO₂e @ $18/ton
  2. Singapore Real Estate Fund Token (SGP-RE-001) — 10 000 tokens @ $100/token
  3. London Gold Vault Certificate (LDN-GOLD-2024) — 50 kg physical gold

Flow:
  ① Create named server wallets (issuer / validator / notary / buyer A / buyer B)
  ② Fund buyers with JUSD settlement tokens via /ui/private/rwa/fund
  ③ Tokenize each RWA asset via /ui/private/rwa/tokenize
  ④ Create marketplace listings via /ui/private/rwa/listings/create
  ⑤ Create access passes (KYC gate) via /ui/private/rwa/access/create
  ⑥ Execute purchases via /ui/private/rwa/listings/buy
  ⑦ Peer transfer between buyers via /ui/private/rwa/wallet/send
  ⑧ Print final inventory table

Run:
  python3 demo_rwa.py [--node https://explorer.flowpe.io] [--dry-run]
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple

# ── Config ────────────────────────────────────────────────────────────────

DEFAULT_NODE = "https://explorer.flowpe.io"

WALLETS = {
    "rwa_issuer":    {"label": "RWA Issuer / Tokenization Authority"},
    "rwa_validator": {"label": "RWA Validator"},
    "rwa_notary":    {"label": "RWA Notary"},
    "rwa_buyer_a":   {"label": "Institutional Buyer A (KYC'd)"},
    "rwa_buyer_b":   {"label": "Institutional Buyer B (KYC'd)"},
}

ASSETS = [
    {
        "asset_id":         "MUMB-2024-CC-0041",
        "token_symbol":     "MUMBCC",
        "asset_name":       "Mumbai Carbon Credits 2024",
        "asset_type":       "carbon_credit",
        "domain":           "rwa-carbon",
        "contract_id":      "carbon-credit-v1",
        "amount":           1000.0,
        "valuation_amount": 18000.0,
        "valuation_currency": "USD",
        "jurisdiction":     "India",
        "issuer_entity":    "Mumbai Climate Exchange",
        "legal_doc_url":    "https://explorer.flowpe.io/rwa/docs/MUMB-2024-CC-0041.pdf",
        "listing_price":    18.0,
        "listing_qty":      800.0,
        "listing_title":    "Mumbai Carbon Credits 2024 — 800 tons CO₂e",
        "listing_desc":     "Verified emission reductions from Mumbai urban reforestation. Gold Standard certified.",
        "buy_qty_a":        200.0,
        "buy_qty_b":        100.0,
        "transfer_qty":     50.0,
    },
    {
        "asset_id":         "SGP-RE-001",
        "token_symbol":     "SGPRE",
        "asset_name":       "Singapore Real Estate Fund Token",
        "asset_type":       "real_estate",
        "domain":           "rwa-realestate",
        "contract_id":      "real-estate-fund-v1",
        "amount":           10000.0,
        "valuation_amount": 1_000_000.0,
        "valuation_currency": "USD",
        "jurisdiction":     "Singapore",
        "issuer_entity":    "SGP Asset Management Pte Ltd",
        "legal_doc_url":    "https://explorer.flowpe.io/rwa/docs/SGP-RE-001.pdf",
        "listing_price":    100.0,
        "listing_qty":      5000.0,
        "listing_title":    "Singapore Commercial Real Estate Fund — 5 000 tokens",
        "listing_desc":     "Fractional ownership of grade-A commercial property in Marina Bay Financial Centre.",
        "buy_qty_a":        500.0,
        "buy_qty_b":        250.0,
        "transfer_qty":     100.0,
    },
    {
        "asset_id":         "LDN-GOLD-2024",
        "token_symbol":     "LDNGOLD",
        "asset_name":       "London Gold Vault Certificate",
        "asset_type":       "commodity",
        "domain":           "rwa-commodity",
        "contract_id":      "commodity-vault-v1",
        "amount":           50.0,
        "valuation_amount": 3_250_000.0,
        "valuation_currency": "USD",
        "jurisdiction":     "United Kingdom",
        "issuer_entity":    "London Bullion Vault Ltd",
        "legal_doc_url":    "https://explorer.flowpe.io/rwa/docs/LDN-GOLD-2024.pdf",
        "listing_price":    65000.0,
        "listing_qty":      30.0,
        "listing_title":    "London Gold Vault Certificate — 30 kg allocated gold",
        "listing_desc":     "Physical gold stored at London Bullion Market Association vault. LBMA Good Delivery standard.",
        "buy_qty_a":        5.0,
        "buy_qty_b":        2.0,
        "transfer_qty":     1.0,
    },
]

JUSD_FUND_AMOUNT = 5_000_000.0  # per buyer


# ── HTTP helpers ──────────────────────────────────────────────────────────

def post(node: str, path: str, data: Dict, timeout: int = 30) -> Tuple[Optional[Dict], Optional[str]]:
    url = f"{node}{path}"
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read()), None
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}: {e.read().decode()[:300]}"
    except Exception as e:
        return None, str(e)


def get(node: str, path: str, timeout: int = 15) -> Tuple[Optional[Dict], Optional[str]]:
    url = f"{node}{path}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.loads(r.read()), None
    except Exception as e:
        return None, str(e)


# ── Seeding steps ─────────────────────────────────────────────────────────

def step_create_wallets(node: str, dry_run: bool) -> Dict[str, Any]:
    """Create (or reuse) named server-side wallets."""
    print("\n── Step 1: Create named wallets ──────────────────────────────")
    addresses: Dict[str, str] = {}

    for name, meta in WALLETS.items():
        if dry_run:
            print(f"  [dry-run] Would create wallet '{name}'")
            addresses[name] = f"W_dry_{name}"
            continue

        resp, err = post(node, "/ui/wallets/create", {"name": name, "scheme": "ed25519"})
        if err:
            # If it already exists the node may return an error — try to fetch it
            print(f"  ℹ  '{name}': {err} (may already exist)")
            # Try to fetch existing wallet list
            wallets_resp, _ = post(node, "/ui/wallets/create", {"name": name, "scheme": "ed25519"})
        else:
            wallet = resp.get("wallet", {}) if resp else {}
            addr = wallet.get("address", "?")
            addresses[name] = addr
            print(f"  ✅ {name}: {addr}")

    # Get current wallet list to resolve addresses for pre-existing wallets
    if not dry_run:
        status_resp, _ = get(node, "/status")
        if status_resp:
            for w in status_resp.get("wallets", []):
                wname = w.get("name", "")
                if wname in WALLETS and wname not in addresses:
                    addresses[wname] = w.get("address", "?")

    return addresses


def step_fund_buyers(node: str, dry_run: bool) -> None:
    """Issue JUSD settlement tokens to buyers via /ui/private/rwa/fund."""
    print("\n── Step 2: Fund buyers with JUSD settlement tokens ───────────")
    buyers = ["rwa_buyer_a", "rwa_buyer_b"]
    for buyer in buyers:
        data = {
            "issuer_wallet_name":    "rwa_issuer",
            "recipient_wallet_name": buyer,
            "validator_wallet_name": "rwa_validator",
            "notary_wallet_name":    "rwa_notary",
            "amount":                JUSD_FUND_AMOUNT,
        }
        label = WALLETS[buyer]["label"]
        if dry_run:
            print(f"  [dry-run] Would fund {label} with {JUSD_FUND_AMOUNT:,.0f} JUSD")
            continue

        resp, err = post(node, "/ui/private/rwa/fund", data)
        if err:
            print(f"  ⚠  Fund {buyer}: {err}")
        else:
            asset_id = (resp or {}).get("asset_id", "JUSD")
            print(f"  ✅ Funded {label} — {JUSD_FUND_AMOUNT:,.0f} {asset_id}")


def step_tokenize_assets(node: str, dry_run: bool) -> Dict[str, str]:
    """Tokenize each RWA asset; returns {asset_id: token_id}."""
    print("\n── Step 3: Tokenize RWA assets ───────────────────────────────")
    token_ids: Dict[str, str] = {}

    for asset in ASSETS:
        data = {
            "issuer_wallet_name":    "rwa_issuer",
            "owner_wallet_name":     "rwa_issuer",
            "validator_wallet_name": "rwa_validator",
            "notary_wallet_name":    "rwa_notary",
            "domain":                asset["domain"],
            "contract_id":          asset["contract_id"],
            "asset_id":              asset["asset_id"],
            "amount":                asset["amount"],
            "token_symbol":          asset["token_symbol"],
            "asset_name":            asset["asset_name"],
            "asset_type":            asset["asset_type"],
            "valuation_amount":      asset["valuation_amount"],
            "valuation_currency":    asset["valuation_currency"],
            "jurisdiction":          asset["jurisdiction"],
            "legal_doc_url":         asset["legal_doc_url"],
            "issuer_entity":         asset["issuer_entity"],
            "allow_transfer":        True,
        }
        if dry_run:
            print(f"  [dry-run] Would tokenize {asset['asset_id']} ({asset['amount']} units)")
            token_ids[asset["asset_id"]] = f"tok_{asset['asset_id']}"
            continue

        resp, err = post(node, "/ui/private/rwa/tokenize", data)
        if err:
            print(f"  ⚠  Tokenize {asset['asset_id']}: {err}")
        else:
            tok = (resp or {}).get("token_id", asset["asset_id"])
            token_ids[asset["asset_id"]] = tok
            units = asset["amount"]
            val = asset["valuation_amount"]
            sym = asset["token_symbol"]
            print(f"  ✅ {asset['asset_id']} ({sym}) — {units:,.0f} units, ${val:,.0f} total valuation")

    return token_ids


def step_create_listings(node: str, dry_run: bool) -> Dict[str, str]:
    """Create marketplace listings; returns {asset_id: listing_id}."""
    print("\n── Step 4: Create marketplace listings ───────────────────────")
    listing_ids: Dict[str, str] = {}

    for asset in ASSETS:
        data = {
            "seller_wallet_name": "rwa_issuer",
            "asset_id":           asset["asset_id"],
            "quantity":           asset["listing_qty"],
            "price_per_unit":     asset["listing_price"],
            "title":              asset["listing_title"],
            "description":        asset["listing_desc"],
            "access_mode":        "access_id",  # KYC-gated
        }
        if dry_run:
            print(f"  [dry-run] Would list {asset['asset_id']} x{asset['listing_qty']} @ ${asset['listing_price']}")
            listing_ids[asset["asset_id"]] = f"LST-dry-{asset['asset_id'][:8]}"
            continue

        resp, err = post(node, "/ui/private/rwa/listings/create", data)
        if err:
            print(f"  ⚠  List {asset['asset_id']}: {err}")
        else:
            listing = (resp or {}).get("listing", {})
            lid = listing.get("id", "?")
            listing_ids[asset["asset_id"]] = lid
            total = asset["listing_qty"] * asset["listing_price"]
            print(f"  ✅ {asset['asset_id']} listed — {lid} | qty={asset['listing_qty']:,.0f} | ${total:,.0f} total")

    return listing_ids


def step_create_access_passes(node: str, dry_run: bool,
                               listing_ids: Dict[str, str]) -> Dict[str, Dict[str, str]]:
    """Create KYC access passes per buyer per listing."""
    print("\n── Step 5: Create KYC access passes ─────────────────────────")
    # passes[asset_id][buyer] = access_code
    passes: Dict[str, Dict[str, str]] = {}
    buyers = ["rwa_buyer_a", "rwa_buyer_b"]

    for asset in ASSETS:
        lid = listing_ids.get(asset["asset_id"], "")
        passes[asset["asset_id"]] = {}
        for buyer in buyers:
            data = {
                "creator_wallet_name": "rwa_issuer",
                "listing_id":          lid,
                "asset_id":            asset["asset_id"],
                "max_uses":            5,
                "note":                f"KYC pass for {buyer} — {asset['asset_id']}",
                "bind_on_first_use":   True,
                "expires_in_seconds":  86400 * 30,  # 30 days
            }
            if dry_run:
                print(f"  [dry-run] Would create access pass: {buyer} → {asset['asset_id']}")
                passes[asset["asset_id"]][buyer] = f"ACC-dry-{buyer[:8]}"
                continue

            resp, err = post(node, "/ui/private/rwa/access/create", data)
            if err:
                print(f"  ⚠  Access pass {buyer}/{asset['asset_id']}: {err}")
            else:
                code = (resp or {}).get("access_code", "?")
                passes[asset["asset_id"]][buyer] = code
                print(f"  ✅ {buyer} → {asset['asset_id']}: {code}")

    return passes


def step_buy(node: str, dry_run: bool,
             listing_ids: Dict[str, str],
             passes: Dict[str, Dict[str, str]]) -> None:
    """Simulate buyer purchases."""
    print("\n── Step 6: Execute purchase orders ──────────────────────────")
    buyer_qty = {"rwa_buyer_a": "buy_qty_a", "rwa_buyer_b": "buy_qty_b"}

    for asset in ASSETS:
        lid = listing_ids.get(asset["asset_id"], "")
        for buyer, qty_key in buyer_qty.items():
            qty = asset[qty_key]
            access_code = passes.get(asset["asset_id"], {}).get(buyer, "")
            data = {
                "listing_id":           lid,
                "buyer_wallet_name":    buyer,
                "quantity":             qty,
                "validator_wallet_name": "rwa_validator",
                "notary_wallet_name":   "rwa_notary",
                "access_code":         access_code,
            }
            cost = qty * asset["listing_price"]
            if dry_run:
                print(f"  [dry-run] {buyer} would buy {qty} {asset['asset_id']} for ${cost:,.0f}")
                continue

            resp, err = post(node, "/ui/private/rwa/listings/buy", data)
            if err:
                print(f"  ⚠  Buy {buyer}/{asset['asset_id']}: {err}")
            else:
                print(f"  ✅ {buyer} bought {qty:,.0f}× {asset['asset_id']} — ${cost:,.2f}")


def step_peer_transfer(node: str, dry_run: bool) -> None:
    """Simulate a direct wallet-to-wallet RWA transfer."""
    print("\n── Step 7: Peer transfers (buyer A → buyer B) ────────────────")

    for asset in ASSETS:
        qty = asset["transfer_qty"]
        data = {
            "from_wallet_name":      "rwa_buyer_a",
            "to":                    "@rwa_buyer_b",
            "asset_id":              asset["asset_id"],
            "amount":                qty,
            "validator_wallet_name": "rwa_validator",
            "notary_wallet_name":    "rwa_notary",
        }
        if dry_run:
            print(f"  [dry-run] Would transfer {qty} {asset['asset_id']}: buyer_a → buyer_b")
            continue

        resp, err = post(node, "/ui/private/rwa/wallet/send", data)
        if err:
            print(f"  ⚠  Transfer {asset['asset_id']}: {err}")
        else:
            print(f"  ✅ Transferred {qty} {asset['asset_id']}: rwa_buyer_a → rwa_buyer_b")


def step_print_state(node: str, dry_run: bool) -> None:
    """Print final RWA inventory."""
    print("\n── Step 8: Final RWA state ───────────────────────────────────")
    if dry_run:
        print("  [dry-run] Would fetch /private/rwa/listings")
        return

    resp, err = get(node, "/private/rwa/listings")
    if err:
        print(f"  ⚠  Could not fetch listings: {err}")
        return

    listings = (resp or {}).get("listings", [])
    if not listings:
        print("  (no listings found)")
        return

    print(f"  {'Listing ID':<22} {'Asset':<22} {'Status':<8} {'Qty avail':>12} {'Price':>12}")
    print("  " + "-" * 80)
    for lst in listings:
        lid = str(lst.get("id", ""))[:20]
        aid = str(lst.get("asset_id", ""))[:20]
        status = str(lst.get("status", ""))[:7]
        qty_a = lst.get("quantity_available", 0)
        price = lst.get("price_per_unit", 0)
        print(f"  {lid:<22} {aid:<22} {status:<8} {qty_a:>12,.2f} {price:>12,.2f}")

    print(f"\n  Total listings: {len(listings)}")


# ── Main ──────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Seed JITO PrivateAssetChain with RWA demo data")
    parser.add_argument("--node", default=DEFAULT_NODE, help="Node URL")
    parser.add_argument("--dry-run", action="store_true", help="Validate flow without hitting the chain")
    args = parser.parse_args()

    node = args.node.rstrip("/")
    dry = args.dry_run

    print(f"JITO RWA Demo Seeder")
    print(f"Node:    {node}")
    print(f"Dry run: {dry}")
    if dry:
        print("(no transactions will be submitted)\n")

    # Verify node reachable
    if not dry:
        resp, err = get(node, "/status")
        if err:
            print(f"✗ Cannot reach node: {err}")
            sys.exit(1)
        height = (resp or {}).get("height", "?")
        print(f"✓ Node reachable — chain height {height}\n")

    step_create_wallets(node, dry)
    step_fund_buyers(node, dry)
    token_ids = step_tokenize_assets(node, dry)
    listing_ids = step_create_listings(node, dry)
    passes = step_create_access_passes(node, dry, listing_ids)
    step_buy(node, dry, listing_ids, passes)
    step_peer_transfer(node, dry)
    step_print_state(node, dry)

    print("\n✅ RWA demo seeding complete.")


if __name__ == "__main__":
    main()
