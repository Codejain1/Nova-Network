import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Set
from urllib import parse, request

from auth import verify_hs256_jwt
from dual_chain import (
    PrivateAssetChain,
    PublicPaymentChain,
    SYSTEM_SENDER,
    create_wallet,
    load_wallet,
    make_agent_activity_log_tx,
    make_agent_attest_tx,
    make_agent_register_tx,
    make_ai_job_create_tx,
    make_ai_job_result_tx,
    make_ai_job_settle_tx,
    make_ai_model_register_tx,
    make_ai_provider_stake_tx,
    make_asset_issue_tx,
    make_identity_claim_tx,
    make_identity_update_tx,
    make_identity_verify_tx,
    make_task_delegate_tx,
    make_task_complete_tx,
    make_task_review_tx,
    make_task_dispute_tx,
    make_governance_propose_tx,
    make_governance_vote_tx,
    make_price_update_tx,
    make_asset_transfer_tx,
    make_payment_tx,
    make_validator_nominate_tx,
    make_validator_unstake_tx,
    make_validator_election_vote_tx,
    make_ai_oracle_assign_tx,
    make_ai_oracle_event_tx,
    make_model_register_tx,
    make_model_transfer_tx,
    make_model_revenue_share_tx,
    make_model_inference_tx,
    make_pipeline_create_tx,
    make_pipeline_step_complete_tx,
    make_pipeline_approve_tx,
    make_zk_proof_tx,
    make_zk_register_circuit_tx,
    groth16_verify,
    move_wallet_private_key_to_file_hsm,
    save_wallet,
)


def http_post_json(
    url: str,
    payload: Dict[str, Any],
    timeout: float = 4.0,
    auth_token: str = "",
    ssl_context: Optional[ssl.SSLContext] = None,
) -> Dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    req = request.Request(url, data=data, headers=headers, method="POST")
    with request.urlopen(req, timeout=timeout, context=ssl_context) as response:
        body = response.read().decode("utf-8")
    return json.loads(body) if body else {}


def http_get_json(
    url: str,
    timeout: float = 4.0,
    auth_token: str = "",
    ssl_context: Optional[ssl.SSLContext] = None,
) -> Dict[str, Any]:
    headers = {}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    req = request.Request(url, headers=headers, method="GET")
    with request.urlopen(req, timeout=timeout, context=ssl_context) as response:
        body = response.read().decode("utf-8")
    return json.loads(body) if body else {}


def load_html(name: str, fallback_title: str) -> str:
    html_path = os.path.join(os.path.dirname(__file__), name)
    if not os.path.exists(html_path):
        return f"<html><body><h1>{fallback_title} file missing</h1></body></html>"
    with open(html_path, "r", encoding="utf-8") as f:
        return f.read()


def _safe_int(raw: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


def _tx_from_to(tx: Dict[str, Any]) -> tuple[str, str]:
    tx_type = str(tx.get("type", ""))
    if tx_type in {"payment", "evm_payment"}:
        return str(tx.get("sender", "")), str(tx.get("recipient", ""))
    if tx_type == "price_update":
        return str(tx.get("oracle", "")), ""
    if tx_type == "asset_issue":
        return str(tx.get("issuer", "")), str(tx.get("owner", ""))
    if tx_type == "asset_transfer":
        return str(tx.get("from", "")), str(tx.get("to", ""))
    if tx_type == "validator_update":
        return str(tx.get("proposer", tx.get("signer", ""))), str(tx.get("validator", ""))
    if tx_type == "ai_provider_stake":
        return str(tx.get("provider", tx.get("signer", ""))), "STAKE_POOL"
    if tx_type == "ai_provider_slash":
        return str(tx.get("provider", "")), str(tx.get("recipient", tx.get("signer", "")))
    if tx_type == "ai_model_register":
        return str(tx.get("owner", tx.get("signer", ""))), str(tx.get("model_id", ""))
    if tx_type == "ai_job_create":
        return str(tx.get("requester", tx.get("signer", ""))), str(tx.get("model_id", ""))
    if tx_type == "ai_job_result":
        return str(tx.get("provider", tx.get("signer", ""))), str(tx.get("job_id", ""))
    if tx_type == "ai_job_settle":
        return str(tx.get("settler", tx.get("signer", ""))), str(tx.get("job_id", ""))
    if tx_type == "identity_claim":
        return str(tx.get("signer", "")), ""
    if tx_type == "identity_update":
        return str(tx.get("signer", "")), ""
    if tx_type == "agent_register":
        return str(tx.get("owner", tx.get("signer", ""))), str(tx.get("agent_id", ""))
    if tx_type == "agent_attest":
        return str(tx.get("attester", tx.get("signer", ""))), str(tx.get("agent_id", ""))
    if tx_type == "identity_verify":
        return str(tx.get("notary", tx.get("signer", ""))), str(tx.get("target", ""))
    if tx_type == "task_delegate":
        return str(tx.get("owner", tx.get("signer", ""))), str(tx.get("agent_id", ""))
    if tx_type == "task_complete":
        return str(tx.get("agent", tx.get("signer", ""))), str(tx.get("task_id", ""))
    if tx_type == "task_review":
        return str(tx.get("owner", tx.get("signer", ""))), str(tx.get("task_id", ""))
    if tx_type == "task_dispute":
        return str(tx.get("disputer", tx.get("signer", ""))), str(tx.get("task_id", ""))
    if tx_type == "governance_propose":
        return str(tx.get("proposer", tx.get("signer", ""))), str(tx.get("proposal_id", ""))
    if tx_type == "governance_vote":
        return str(tx.get("voter", tx.get("signer", ""))), str(tx.get("proposal_id", ""))
    if tx_type == "validator_nominate":
        return str(tx.get("candidate", tx.get("signer", ""))), str(tx.get("candidate", ""))
    if tx_type == "validator_election_vote":
        return str(tx.get("voter", tx.get("signer", ""))), str(tx.get("candidate", ""))
    if tx_type == "ai_oracle_assign":
        return str(tx.get("owner", tx.get("signer", ""))), str(tx.get("asset_id", ""))
    if tx_type == "ai_oracle_event":
        return str(tx.get("agent", tx.get("signer", ""))), str(tx.get("asset_id", ""))
    if tx_type == "model_register":
        return str(tx.get("owner", tx.get("signer", ""))), str(tx.get("model_id", ""))
    if tx_type == "model_transfer":
        return str(tx.get("owner", tx.get("signer", ""))), str(tx.get("new_owner", ""))
    if tx_type == "model_revenue_share":
        return str(tx.get("owner", tx.get("signer", ""))), str(tx.get("model_id", ""))
    if tx_type == "model_inference":
        return str(tx.get("caller", tx.get("signer", ""))), str(tx.get("model_id", ""))
    if tx_type == "pipeline_create":
        return str(tx.get("owner", tx.get("signer", ""))), str(tx.get("pipeline_id", ""))
    if tx_type == "pipeline_step_complete":
        return str(tx.get("agent", tx.get("signer", ""))), str(tx.get("pipeline_id", ""))
    if tx_type == "pipeline_approve":
        return str(tx.get("owner", tx.get("signer", ""))), str(tx.get("pipeline_id", ""))
    return str(tx.get("signer", tx.get("from", ""))), str(tx.get("to", ""))


def _tx_addresses(tx: Dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for key in (
        "sender",
        "recipient",
        "oracle",
        "issuer",
        "owner",
        "from",
        "to",
        "signer",
        "validator",
        "proposer",
        "provider",
        "requester",
        "settler",
    ):
        value = tx.get(key)
        if isinstance(value, str) and value:
            out.add(value)
    visibility = tx.get("visibility", [])
    if isinstance(visibility, list):
        for item in visibility:
            if isinstance(item, str) and item:
                out.add(item)
    return out


def _block_summary(block: Any) -> Dict[str, Any]:
    return {
        "index": block.index,
        "hash": block.hash,
        "previous_hash": block.previous_hash,
        "timestamp": block.timestamp,
        "tx_count": len(block.transactions),
        "nonce": block.nonce,
        "meta": block.meta,
    }


def _tx_summary(chain_name: str, block: Any, tx_index: int, tx: Dict[str, Any]) -> Dict[str, Any]:
    sender, recipient = _tx_from_to(tx)
    return {
        "chain": chain_name,
        "block_index": block.index,
        "block_hash": block.hash,
        "tx_index": tx_index,
        "tx_id": tx.get("id", ""),
        "type": tx.get("type", ""),
        "timestamp": float(tx.get("timestamp", block.timestamp)),
        "from": sender,
        "to": recipient,
        "amount": tx.get("amount"),
        "asset_id": tx.get("asset_id", ""),
        "symbol": tx.get("symbol", ""),
        "price": tx.get("price"),
    }


class DualChainNode:
    wallet_name_pattern = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
    portal_username_pattern = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")

    def __init__(
        self,
        data_dir: str,
        public_difficulty: int,
        public_reward: float,
        public_consensus: str = "pow",
        public_validators: Optional[list[str]] = None,
        public_validator_rotation: bool = True,
        public_finality_confirmations: int = 5,
        public_checkpoint_interval: int = 20,
        public_block_time_target: float = 5.0,
        public_faucet_enabled: bool = False,
        public_faucet_amount: float = 0.0,
        public_faucet_cooldown_seconds: float = 3600.0,
        public_faucet_daily_cap: float = 0.0,
        mainnet_hardening: bool = False,
        peer_token: str = "",
        peer_ssl_context: Optional[ssl.SSLContext] = None,
        peer_sync_enabled: bool = True,
        peer_sync_interval_seconds: float = 6.0,
        peer_lag_resync_threshold: int = 3,
        strict_public_signatures: bool = True,
        public_mempool_ttl_seconds: float = 900.0,
        public_mempool_max_transactions: int = 5000,
        public_pow_workers: int = 1,
        public_pow_nonce_chunk_size: int = 10000,
        require_hsm_signers: bool = False,
    ):
        self.data_dir = data_dir
        os.makedirs(self.data_dir, exist_ok=True)

        self.public_chain = PublicPaymentChain(
            chain_file=os.path.join(self.data_dir, "public_chain.json"),
            difficulty=public_difficulty,
            mining_reward=public_reward,
            consensus=public_consensus,
            validators=public_validators or [],
            validator_rotation=public_validator_rotation,
            finality_confirmations=public_finality_confirmations,
            checkpoint_interval=public_checkpoint_interval,
            block_time_target_seconds=public_block_time_target,
            strict_signature_validation=strict_public_signatures,
            mempool_tx_ttl_seconds=public_mempool_ttl_seconds,
            mempool_max_transactions=public_mempool_max_transactions,
            pow_parallel_workers=public_pow_workers,
            pow_nonce_chunk_size=public_pow_nonce_chunk_size,
            treasury_fee_pct=float(os.environ.get("PUBLIC_TREASURY_FEE_PCT", "0.10")),
            treasury_address=os.environ.get("TREASURY_ADDRESS", ""),
        )
        self.private_chain = PrivateAssetChain(
            chain_file=os.path.join(self.data_dir, "private_chain.json")
        )

        self.peers_file = os.path.join(self.data_dir, "peers.json")
        self.peers = self._load_peers()

        self.wallet_dir = os.path.join(self.data_dir, "wallets")
        self.hsm_dir = os.path.join(self.data_dir, "hsm_keys")
        os.makedirs(self.wallet_dir, exist_ok=True)
        os.makedirs(self.hsm_dir, exist_ok=True)

        self.peer_token = peer_token
        self.peer_ssl_context = peer_ssl_context
        self.peer_sync_enabled = bool(peer_sync_enabled)
        self.peer_sync_interval_seconds = max(1.0, float(peer_sync_interval_seconds))
        self.peer_lag_resync_threshold = max(1, int(peer_lag_resync_threshold))
        self.require_hsm_signers = bool(require_hsm_signers)
        self.lock = threading.Lock()
        self.started_at = time.time()

        self.faucet_enabled = bool(public_faucet_enabled)
        self.faucet_default_amount = max(0.0, float(public_faucet_amount))
        self.faucet_cooldown_seconds = max(0.0, float(public_faucet_cooldown_seconds))
        self.faucet_daily_cap = max(0.0, float(public_faucet_daily_cap))
        self.faucet_state_file = os.path.join(self.data_dir, "faucet_state.json")
        self.faucet_last_claim_at: Dict[str, float] = {}
        self.faucet_events: list[Dict[str, Any]] = []
        self._load_faucet_state()
        self.rwa_listings_file = os.path.join(self.data_dir, "rwa_listings.json")
        self.rwa_listings: list[Dict[str, Any]] = self._load_rwa_listings()
        self.rwa_tokens_file = os.path.join(self.data_dir, "rwa_tokens.json")
        self.rwa_tokens: list[Dict[str, Any]] = self._load_rwa_tokens()
        self.rwa_access_passes_file = os.path.join(self.data_dir, "rwa_access_passes.json")
        self.rwa_access_passes: list[Dict[str, Any]] = self._load_rwa_access_passes()
        self.portal_users_file = os.path.join(self.data_dir, "rwa_portal_users.json")
        self.portal_users: Dict[str, Dict[str, Any]] = self._load_portal_users()
        self.portal_sessions: Dict[str, Dict[str, Any]] = {}
        self.portal_session_ttl_seconds = 86400.0
        self.ai_agents_file = os.path.join(self.data_dir, "ai_agents.json")
        self.ai_agents: Dict[str, Dict[str, Any]] = self._load_ai_agents()
        self.mainnet_hardening = bool(mainnet_hardening)

        if self.mainnet_hardening:
            if public_consensus != "poa":
                raise ValueError("mainnet-hardening requires --public-consensus poa")
            if len(self.public_chain.validators) < 2:
                raise ValueError("mainnet-hardening requires at least 2 public validators")
            if not self.public_chain.validator_rotation_enabled:
                raise ValueError("mainnet-hardening requires validator rotation enabled")
            if self.faucet_enabled:
                raise ValueError("mainnet-hardening requires faucet disabled")

        self.auto_mine_enabled = False
        self.auto_mine_interval_seconds = 8.0
        self.auto_mine_miner = ""
        self.auto_mine_follow_rotation = False
        self.auto_mine_effective_miner = ""
        self.auto_mine_allow_empty_blocks = False
        self.auto_mine_last_block_hash = ""
        self.auto_mine_last_block_index = -1
        self.auto_mine_last_mined_at = 0.0
        self.auto_mine_last_error = ""
        self._auto_mine_stop = threading.Event()
        self._auto_mine_thread: Optional[threading.Thread] = None
        self._peer_sync_stop = threading.Event()
        self._peer_sync_thread: Optional[threading.Thread] = None
        self.peer_health: Dict[str, Dict[str, Any]] = {}
        self.event_seq = 0
        self.event_log: list[Dict[str, Any]] = []
        self.max_event_log_size = 2000
        self.broadcast_pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="jito-peer-bcast")
        for peer in self.peers:
            self.peer_health[peer] = self._new_peer_health()
        self._ensure_peer_sync_thread()

    def _load_peers(self) -> set[str]:
        if not os.path.exists(self.peers_file):
            return set()
        with open(self.peers_file, "r", encoding="utf-8") as f:
            return set(json.load(f).get("peers", []))

    def _save_peers(self) -> None:
        with open(self.peers_file, "w", encoding="utf-8") as f:
            json.dump({"peers": sorted(self.peers)}, f, indent=2)

    def _load_rwa_listings(self) -> list[Dict[str, Any]]:
        if not os.path.exists(self.rwa_listings_file):
            return []
        try:
            with open(self.rwa_listings_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            rows = data if isinstance(data, list) else data.get("listings", [])
            out: list[Dict[str, Any]] = []
            for row in rows:
                if not isinstance(row, dict):
                    continue
                listing_id = str(row.get("id", "")).strip()
                asset_id = str(row.get("asset_id", "")).strip()
                seller_wallet_name = str(row.get("seller_wallet_name", "")).strip()
                if not listing_id or not asset_id or not seller_wallet_name:
                    continue
                out.append(dict(row))
            return out
        except Exception:
            return []

    def _save_rwa_listings(self) -> None:
        with open(self.rwa_listings_file, "w", encoding="utf-8") as f:
            json.dump({"listings": self.rwa_listings}, f, indent=2)

    def _load_rwa_tokens(self) -> list[Dict[str, Any]]:
        if not os.path.exists(self.rwa_tokens_file):
            return []
        try:
            with open(self.rwa_tokens_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            rows = data if isinstance(data, list) else data.get("tokens", [])
            out: list[Dict[str, Any]] = []
            for row in rows:
                if not isinstance(row, dict):
                    continue
                asset_id = str(row.get("asset_id", "")).strip()
                symbol = str(row.get("symbol", "")).strip().upper()
                contract_address = str(row.get("contract_address", "")).strip().lower()
                if not asset_id or not symbol or not contract_address:
                    continue
                out.append(dict(row))
            return out
        except Exception:
            return []

    def _save_rwa_tokens(self) -> None:
        with open(self.rwa_tokens_file, "w", encoding="utf-8") as f:
            json.dump({"tokens": self.rwa_tokens}, f, indent=2)

    def _load_rwa_access_passes(self) -> list[Dict[str, Any]]:
        if not os.path.exists(self.rwa_access_passes_file):
            return []
        try:
            with open(self.rwa_access_passes_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            rows = data if isinstance(data, list) else data.get("passes", [])
            out: list[Dict[str, Any]] = []
            for row in rows:
                if not isinstance(row, dict):
                    continue
                pass_id = str(row.get("id", "")).strip()
                code_hash = str(row.get("code_hash", "")).strip()
                code_salt = str(row.get("code_salt", "")).strip()
                if not pass_id or not code_hash or not code_salt:
                    continue
                out.append(dict(row))
            return out
        except Exception:
            return []

    def _save_rwa_access_passes(self) -> None:
        with open(self.rwa_access_passes_file, "w", encoding="utf-8") as f:
            json.dump({"passes": self.rwa_access_passes}, f, indent=2)

    def _hash_access_code(self, code: str, salt_hex: str) -> str:
        salt = bytes.fromhex(salt_hex)
        digest = hashlib.sha256(salt + code.encode("utf-8")).hexdigest()
        return digest

    def _public_access_pass(self, row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": str(row.get("id", "")),
            "status": str(row.get("status", "active")),
            "created_at": float(row.get("created_at", 0.0)),
            "updated_at": float(row.get("updated_at", 0.0)),
            "created_by_wallet_name": str(row.get("created_by_wallet_name", "")),
            "created_by_address": str(row.get("created_by_address", "")),
            "listing_id": str(row.get("listing_id", "")),
            "asset_id": str(row.get("asset_id", "")),
            "domain_id": str(row.get("domain_id", "")),
            "note": str(row.get("note", "")),
            "expires_at": float(row.get("expires_at", 0.0)),
            "max_uses": int(row.get("max_uses", 1)),
            "used_count": int(row.get("used_count", 0)),
            "max_units": float(row.get("max_units", 0.0)),
            "units_used": float(row.get("units_used", 0.0)),
            "bind_on_first_use": bool(row.get("bind_on_first_use", True)),
            "bound_wallet_name": str(row.get("bound_wallet_name", "")),
            "bound_wallet_address": str(row.get("bound_wallet_address", "")),
            "last_used_at": float(row.get("last_used_at", 0.0)),
        }

    def list_rwa_access_passes(self, listing_id: str = "", include_inactive: bool = False) -> list[Dict[str, Any]]:
        rows = list(self.rwa_access_passes)
        if listing_id:
            wanted = listing_id.strip()
            rows = [row for row in rows if str(row.get("listing_id", "")).strip() == wanted]
        if not include_inactive:
            rows = [row for row in rows if str(row.get("status", "active")).strip() == "active"]
        rows.sort(key=lambda r: float(r.get("created_at", 0.0)), reverse=True)
        return [self._public_access_pass(row) for row in rows]

    def create_rwa_access_pass(
        self,
        *,
        creator_wallet_name: str,
        creator_address: str,
        listing_id: str,
        asset_id: str,
        domain_id: str,
        max_uses: int,
        max_units: float,
        expires_at: float,
        note: str,
        bind_on_first_use: bool,
    ) -> Dict[str, Any]:
        now = time.time()
        pass_id = "ACP-" + hashlib.sha256(
            f"{creator_address}:{listing_id}:{asset_id}:{domain_id}:{now}:{len(self.rwa_access_passes)}".encode("utf-8")
        ).hexdigest()[:16]
        raw_code = "NOVA-" + secrets.token_urlsafe(24).replace("-", "").replace("_", "")
        salt = secrets.token_bytes(16).hex()
        row = {
            "id": pass_id,
            "code_hash": self._hash_access_code(raw_code, salt),
            "code_salt": salt,
            "status": "active",
            "created_at": now,
            "updated_at": now,
            "created_by_wallet_name": creator_wallet_name,
            "created_by_address": creator_address,
            "listing_id": listing_id,
            "asset_id": asset_id,
            "domain_id": domain_id,
            "note": note,
            "expires_at": float(expires_at),
            "max_uses": int(max_uses),
            "used_count": 0,
            "max_units": float(max_units),
            "units_used": 0.0,
            "bind_on_first_use": bool(bind_on_first_use),
            "bound_wallet_name": "",
            "bound_wallet_address": "",
            "last_used_at": 0.0,
        }
        self.rwa_access_passes.append(row)
        self._save_rwa_access_passes()
        return {"pass": self._public_access_pass(row), "access_code": raw_code}

    def resolve_access_pass(self, code: str) -> Optional[Dict[str, Any]]:
        token = str(code).strip()
        if not token:
            return None
        for row in self.rwa_access_passes:
            salt = str(row.get("code_salt", "")).strip()
            expected = str(row.get("code_hash", "")).strip()
            if not salt or not expected:
                continue
            probe = self._hash_access_code(token, salt)
            if hmac.compare_digest(probe, expected):
                return row
        return None

    def list_rwa_tokens(self, asset_id: str = "", symbol: str = "") -> list[Dict[str, Any]]:
        rows = list(self.rwa_tokens)
        if asset_id:
            rows = [row for row in rows if str(row.get("asset_id", "")).strip() == asset_id.strip()]
        if symbol:
            wanted = symbol.strip().upper()
            rows = [row for row in rows if str(row.get("symbol", "")).strip().upper() == wanted]
        rows.sort(key=lambda r: float(r.get("deployed_at", 0.0)), reverse=True)
        return rows

    def _deterministic_contract_address(self, asset_id: str, symbol: str, domain: str) -> str:
        seed = f"{asset_id}:{symbol}:{domain}".encode("utf-8")
        return "0x" + hashlib.sha256(seed).hexdigest()[:40]

    def upsert_rwa_token_contract(
        self,
        *,
        asset_id: str,
        symbol: str,
        name: str,
        decimals: int,
        total_supply: float,
        issuer: str,
        owner: str,
        domain: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        clean_asset_id = str(asset_id).strip()
        clean_symbol = str(symbol).strip().upper()
        clean_domain = str(domain).strip()
        if not clean_asset_id or not clean_symbol or not clean_domain:
            raise ValueError("asset_id, symbol, and domain are required for token deployment.")
        if total_supply <= 0:
            raise ValueError("total_supply must be > 0")
        contract_address = self._deterministic_contract_address(clean_asset_id, clean_symbol, clean_domain)
        now = time.time()
        payload = {
            "asset_id": clean_asset_id,
            "symbol": clean_symbol,
            "name": str(name).strip() or clean_symbol,
            "decimals": int(decimals),
            "total_supply": float(total_supply),
            "issuer": str(issuer).strip(),
            "owner": str(owner).strip(),
            "domain": clean_domain,
            "metadata": dict(metadata or {}),
            "contract_address": contract_address,
            "deployment_tx_hash": "0x" + hashlib.sha256(
                f"{contract_address}:{clean_asset_id}:{total_supply}:{now}".encode("utf-8")
            ).hexdigest(),
            "deployed_at": now,
            "chain_kind": "private",
            "standard": "Nova-RWA-20",
            "transferability": "contract-governed",
        }
        replaced = False
        for idx, row in enumerate(self.rwa_tokens):
            if str(row.get("asset_id", "")).strip() == clean_asset_id:
                self.rwa_tokens[idx] = payload
                replaced = True
                break
        if not replaced:
            self.rwa_tokens.append(payload)
        self._save_rwa_tokens()
        return payload

    def _load_ai_agents(self) -> Dict[str, Dict[str, Any]]:
        if not os.path.exists(self.ai_agents_file):
            return {}
        try:
            with open(self.ai_agents_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            rows = data if isinstance(data, dict) and "agents" not in data else data.get("agents", {})
            if not isinstance(rows, dict):
                return {}
            out: Dict[str, Dict[str, Any]] = {}
            for agent_id, row in rows.items():
                if not isinstance(row, dict):
                    continue
                aid = str(agent_id).strip()
                wallet_name = str(row.get("wallet_name", "")).strip()
                wallet_address = str(row.get("wallet_address", "")).strip()
                if not aid or not wallet_name or not wallet_address:
                    continue
                out[aid] = {
                    "agent_id": aid,
                    "name": str(row.get("name", aid)).strip() or aid,
                    "wallet_name": wallet_name,
                    "wallet_address": wallet_address,
                    "role": str(row.get("role", "worker")).strip() or "worker",
                    "capabilities": list(row.get("capabilities", [])),
                    "metadata": dict(row.get("metadata", {})),
                    "created_at": float(row.get("created_at", time.time())),
                    "updated_at": float(row.get("updated_at", time.time())),
                    "last_seen_at": float(row.get("last_seen_at", 0.0)),
                }
            return out
        except Exception:
            return {}

    def _save_ai_agents(self) -> None:
        with open(self.ai_agents_file, "w", encoding="utf-8") as f:
            json.dump({"agents": self.ai_agents}, f, indent=2)

    def register_ai_agent(
        self,
        *,
        agent_id: str,
        name: str,
        wallet_name: str,
        role: str = "worker",
        capabilities: Optional[list[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        aid = str(agent_id).strip()
        if not aid:
            raise ValueError("agent_id is required.")
        wallet = self.load_named_wallet(wallet_name)
        now = time.time()
        existing = self.ai_agents.get(aid, {})
        row = {
            "agent_id": aid,
            "name": str(name).strip() or existing.get("name", aid),
            "wallet_name": str(wallet_name).strip(),
            "wallet_address": wallet["address"],
            "role": str(role).strip() or existing.get("role", "worker"),
            "capabilities": sorted({str(item).strip() for item in (capabilities or []) if str(item).strip()}),
            "metadata": dict(metadata or {}),
            "created_at": float(existing.get("created_at", now)),
            "updated_at": now,
            "last_seen_at": float(existing.get("last_seen_at", 0.0)),
        }
        self.ai_agents[aid] = row
        self._save_ai_agents()
        return dict(row)

    def list_ai_agents(self, role: str = "", wallet_name: str = "") -> list[Dict[str, Any]]:
        rows = list(self.ai_agents.values())
        if role:
            rows = [row for row in rows if str(row.get("role", "")).strip().lower() == role.strip().lower()]
        if wallet_name:
            rows = [row for row in rows if str(row.get("wallet_name", "")).strip() == wallet_name.strip()]
        rows.sort(key=lambda row: float(row.get("updated_at", 0.0)), reverse=True)
        return [dict(row) for row in rows]

    def touch_ai_agent(self, agent_id: str) -> None:
        aid = str(agent_id).strip()
        row = self.ai_agents.get(aid)
        if not row:
            return
        row["last_seen_at"] = time.time()
        row["updated_at"] = time.time()
        self._save_ai_agents()

    def _load_portal_users(self) -> Dict[str, Dict[str, Any]]:
        if not os.path.exists(self.portal_users_file):
            return {}
        try:
            with open(self.portal_users_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            raw_users = data if isinstance(data, dict) and "users" not in data else data.get("users", {})
            if not isinstance(raw_users, dict):
                return {}
            out: Dict[str, Dict[str, Any]] = {}
            for username, row in raw_users.items():
                if not isinstance(row, dict):
                    continue
                uname = str(username).strip()
                if not self.portal_username_pattern.match(uname):
                    continue
                password_hash = str(row.get("password_hash", "")).strip()
                if not password_hash:
                    continue
                wallet_names = row.get("wallet_names", [])
                if isinstance(wallet_names, str):
                    wallet_names = [item.strip() for item in wallet_names.split(",") if item.strip()]
                if not isinstance(wallet_names, list):
                    wallet_names = []
                out[uname] = {
                    "username": uname,
                    "password_hash": password_hash,
                    "wallet_names": sorted({str(item).strip() for item in wallet_names if str(item).strip()}),
                    "created_at": float(row.get("created_at", time.time())),
                    "last_login_at": float(row.get("last_login_at", 0.0)),
                }
            return out
        except Exception:
            return {}

    def _save_portal_users(self) -> None:
        with open(self.portal_users_file, "w", encoding="utf-8") as f:
            json.dump({"users": self.portal_users}, f, indent=2)

    def _password_hash(self, password: str, salt_hex: str = "", iterations: int = 200_000) -> str:
        salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations).hex()
        return f"pbkdf2_sha256${iterations}${salt.hex()}${digest}"

    def _verify_password(self, password: str, encoded: str) -> bool:
        try:
            algo, raw_iter, salt_hex, expected = encoded.split("$", 3)
            if algo != "pbkdf2_sha256":
                return False
            iterations = int(raw_iter)
            probe = self._password_hash(password, salt_hex=salt_hex, iterations=iterations)
            return hmac.compare_digest(probe, encoded)
        except Exception:
            return False

    def _normalize_wallet_name_list(self, value: Any) -> list[str]:
        if isinstance(value, str):
            names = [item.strip() for item in value.split(",") if item.strip()]
        elif isinstance(value, list):
            names = [str(item).strip() for item in value if str(item).strip()]
        else:
            names = []
        return sorted(set(names))

    def portal_user_public_info(self, username: str) -> Dict[str, Any]:
        row = self.portal_users.get(username)
        if not row:
            raise ValueError("Unknown portal user.")
        return {
            "username": row["username"],
            "wallet_names": list(row.get("wallet_names", [])),
            "created_at": float(row.get("created_at", 0.0)),
            "last_login_at": float(row.get("last_login_at", 0.0)),
        }

    def register_portal_user(self, username: str, password: str, wallet_names: Any = None) -> Dict[str, Any]:
        uname = str(username).strip()
        if not self.portal_username_pattern.match(uname):
            raise ValueError("username must match [A-Za-z0-9_.-] and be 3-64 chars.")
        if uname in self.portal_users:
            raise ValueError("username already exists.")
        pwd = str(password)
        if len(pwd) < 8:
            raise ValueError("password must be at least 8 characters.")

        normalized_wallets = self._normalize_wallet_name_list(wallet_names)
        for wallet_name in normalized_wallets:
            self.load_named_wallet(wallet_name)

        now = time.time()
        self.portal_users[uname] = {
            "username": uname,
            "password_hash": self._password_hash(pwd),
            "wallet_names": normalized_wallets,
            "created_at": now,
            "last_login_at": 0.0,
        }
        self._save_portal_users()
        return self.portal_user_public_info(uname)

    def portal_link_wallet(self, username: str, wallet_name: str) -> Dict[str, Any]:
        uname = str(username).strip()
        if uname not in self.portal_users:
            raise ValueError("Unknown portal user.")
        wname = str(wallet_name).strip()
        self.load_named_wallet(wname)
        row = self.portal_users[uname]
        wallets = set(row.get("wallet_names", []))
        wallets.add(wname)
        row["wallet_names"] = sorted(wallets)
        self._save_portal_users()
        return self.portal_user_public_info(uname)

    def _clean_portal_sessions(self) -> None:
        now = time.time()
        expired = [token for token, row in self.portal_sessions.items() if float(row.get("expires_at", 0.0)) <= now]
        for token in expired:
            self.portal_sessions.pop(token, None)

    def portal_login(self, username: str, password: str) -> Dict[str, Any]:
        uname = str(username).strip()
        row = self.portal_users.get(uname)
        if not row:
            raise ValueError("Invalid username or password.")
        if not self._verify_password(str(password), str(row.get("password_hash", ""))):
            raise ValueError("Invalid username or password.")

        self._clean_portal_sessions()
        token = "rwa_sess_" + secrets.token_urlsafe(32)
        now = time.time()
        expires_at = now + self.portal_session_ttl_seconds
        self.portal_sessions[token] = {"username": uname, "expires_at": expires_at, "issued_at": now}
        row["last_login_at"] = now
        self._save_portal_users()
        return {
            "token": token,
            "expires_at": expires_at,
            "ttl_seconds": self.portal_session_ttl_seconds,
            "user": self.portal_user_public_info(uname),
        }

    def portal_logout(self, token: str) -> None:
        self.portal_sessions.pop(str(token).strip(), None)

    def portal_session_user(self, token: str) -> Dict[str, Any]:
        self._clean_portal_sessions()
        row = self.portal_sessions.get(str(token).strip())
        if not row:
            raise ValueError("Invalid or expired session.")
        uname = str(row.get("username", "")).strip()
        return self.portal_user_public_info(uname)

    def portal_dashboard(self, username: str, include_closed: bool = True) -> Dict[str, Any]:
        user = self.portal_user_public_info(username)
        wallet_names = list(user.get("wallet_names", []))
        wallet_profiles: list[Dict[str, Any]] = []
        wallet_names_seen: set[str] = set()
        for wallet_name in wallet_names:
            try:
                wallet = self.load_named_wallet(wallet_name)
                wallet_names_seen.add(wallet_name)
                wallet_profiles.append(
                    {
                        "name": wallet_name,
                        "address": wallet["address"],
                        "scheme": wallet.get("scheme", "ed25519"),
                    }
                )
            except Exception:
                continue

        balance_map = self.private_chain.get_asset_balances(include_pending=True)
        _, asset_state = self.private_chain._build_asset_state(include_pending_txs=True)  # pylint: disable=protected-access
        holdings: list[Dict[str, Any]] = []
        total_units = 0.0
        for wallet in wallet_profiles:
            wallet_assets = balance_map.get(wallet["address"], {})
            for asset_id, amount in wallet_assets.items():
                amt = float(amount)
                if amt <= 0:
                    continue
                total_units += amt
                holdings.append(
                    {
                        "wallet_name": wallet["name"],
                        "wallet_address": wallet["address"],
                        "asset_id": asset_id,
                        "amount": amt,
                        "asset_meta": dict(asset_state.get(asset_id, {})),
                    }
                )

        listed: list[Dict[str, Any]] = []
        bought: list[Dict[str, Any]] = []
        sold: list[Dict[str, Any]] = []
        for row in self.rwa_listings:
            if not isinstance(row, dict):
                continue
            if not include_closed and str(row.get("status", "open")) != "open":
                continue
            seller_wallet_name = str(row.get("seller_wallet_name", "")).strip()
            if seller_wallet_name in wallet_names_seen:
                listed.append(dict(row))
            for trade in row.get("trades", []):
                if not isinstance(trade, dict):
                    continue
                event = {
                    "listing_id": row.get("id", ""),
                    "asset_id": row.get("asset_id", ""),
                    "seller_wallet_name": seller_wallet_name,
                    "status": row.get("status", ""),
                    "price_per_unit": row.get("price_per_unit", 0.0),
                    "currency": row.get("currency", "USD"),
                    "trade": dict(trade),
                }
                if str(trade.get("buyer_wallet_name", "")).strip() in wallet_names_seen:
                    bought.append(event)
                if seller_wallet_name in wallet_names_seen:
                    sold.append(event)

        open_listings = [row for row in listed if str(row.get("status", "open")) == "open"]
        summary = {
            "wallet_count": len(wallet_profiles),
            "holding_rows": len(holdings),
            "total_units_held": total_units,
            "listed_count": len(listed),
            "open_listing_count": len(open_listings),
            "bought_trade_count": len(bought),
            "sold_trade_count": len(sold),
        }
        holdings.sort(key=lambda item: (item["wallet_name"], item["asset_id"]))
        listed.sort(key=lambda item: float(item.get("created_at", 0.0)), reverse=True)
        bought.sort(key=lambda item: float(item["trade"].get("timestamp", 0.0)), reverse=True)
        sold.sort(key=lambda item: float(item["trade"].get("timestamp", 0.0)), reverse=True)
        return {
            "user": user,
            "wallets": wallet_profiles,
            "summary": summary,
            "holdings": holdings,
            "listed": listed,
            "bought": bought,
            "sold": sold,
        }

    def list_rwa_listings(self, include_closed: bool = False, asset_id: str = "") -> list[Dict[str, Any]]:
        rows = list(self.rwa_listings)
        if not include_closed:
            rows = [row for row in rows if str(row.get("status", "open")) == "open"]
        if asset_id:
            wanted = asset_id.strip()
            rows = [row for row in rows if str(row.get("asset_id", "")) == wanted]
        rows.sort(key=lambda r: float(r.get("created_at", 0.0)), reverse=True)
        return rows

    def add_peer(self, peer: str) -> None:
        peer_url = peer.rstrip("/")
        if not peer_url:
            return
        self.peers.add(peer_url)
        self.peer_health.setdefault(peer_url, self._new_peer_health())
        self._save_peers()

    def _new_peer_health(self) -> Dict[str, Any]:
        return {
            "status": "unknown",
            "last_ok_at": 0.0,
            "last_try_at": 0.0,
            "last_error": "",
            "latency_ms": 0.0,
            "remote_public_height": -1,
            "remote_private_height": -1,
            "local_public_height": len(self.public_chain.chain) - 1,
            "public_height_lag": 0,
            "last_update_changed": False,
        }

    def peer_health_snapshot(self) -> Dict[str, Any]:
        with self.lock:
            peers = sorted(self.peers)
            by_peer = {
                peer: dict(self.peer_health.get(peer, self._new_peer_health()))
                for peer in peers
            }
            healthy = sum(1 for row in by_peer.values() if row.get("status") == "healthy")
            return {
                "peer_count": len(peers),
                "healthy_count": healthy,
                "degraded_count": len(peers) - healthy,
                "sync_enabled": self.peer_sync_enabled,
                "sync_interval_seconds": self.peer_sync_interval_seconds,
                "lag_resync_threshold": self.peer_lag_resync_threshold,
                "peers": by_peer,
            }

    def _sync_from_peer_once(self, peer: str) -> Dict[str, Any]:
        started = time.time()
        entry = self.peer_health.setdefault(peer, self._new_peer_health())
        entry["last_try_at"] = started
        try:
            status = http_get_json(
                f"{peer}/status",
                auth_token=self.peer_token,
                ssl_context=self.peer_ssl_context,
            )
            remote_public_height = int(status.get("public_height", -1))
            remote_private_height = int(status.get("private_height", -1))
            local_public_height = len(self.public_chain.chain) - 1
            should_pull = (
                remote_public_height >= 0
                and (remote_public_height - local_public_height) >= self.peer_lag_resync_threshold
            )
            if should_pull:
                snap = http_get_json(
                    f"{peer}/snapshot",
                    auth_token=self.peer_token,
                    ssl_context=self.peer_ssl_context,
                )
                changed = self.adopt_snapshot_if_better(snap)
            else:
                changed = {
                    "public": False,
                    "private": False,
                    "rwa_listings": False,
                    "rwa_tokens": False,
                    "rwa_access_passes": False,
                    "ai_agents": False,
                }

            finished = time.time()
            local_public_height_after = len(self.public_chain.chain) - 1
            lag = max(0, remote_public_height - local_public_height_after) if remote_public_height >= 0 else 0
            entry.update(
                {
                    "status": "healthy" if lag <= self.peer_lag_resync_threshold else "degraded",
                    "last_ok_at": finished,
                    "last_error": "",
                    "latency_ms": max(0.0, (finished - started) * 1000.0),
                    "remote_public_height": remote_public_height,
                    "remote_private_height": remote_private_height,
                    "local_public_height": local_public_height_after,
                    "public_height_lag": lag,
                    "last_update_changed": bool(any(bool(v) for v in changed.values())),
                }
            )
            return changed
        except Exception as exc:  # pylint: disable=broad-except
            finished = time.time()
            entry.update(
                {
                    "status": "error",
                    "last_error": str(exc),
                    "latency_ms": max(0.0, (finished - started) * 1000.0),
                }
            )
            raise

    def _ensure_peer_sync_thread(self) -> None:
        if not self.peer_sync_enabled:
            return
        if self._peer_sync_thread and self._peer_sync_thread.is_alive():
            return
        self._peer_sync_stop.clear()
        self._peer_sync_thread = threading.Thread(
            target=self._peer_sync_loop,
            name="jito-peer-sync",
            daemon=True,
        )
        self._peer_sync_thread.start()

    def _peer_sync_loop(self) -> None:
        while not self._peer_sync_stop.is_set():
            try:
                if self.peer_sync_enabled and self.peers:
                    self.sync_from_peers()
            except Exception:
                pass
            self._peer_sync_stop.wait(self.peer_sync_interval_seconds)

    def publish_event(self, event_type: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        row = {
            "seq": 0,
            "type": str(event_type or "").strip() or "event",
            "ts": time.time(),
            "payload": dict(payload or {}),
        }
        with self.lock:
            self.event_seq += 1
            row["seq"] = self.event_seq
            self.event_log.append(row)
            if len(self.event_log) > self.max_event_log_size:
                self.event_log = self.event_log[-self.max_event_log_size :]
        return dict(row)

    def list_events_since(self, since_seq: int = 0, limit: int = 200, type_filter: str = "") -> Dict[str, Any]:
        wanted = str(type_filter or "").strip().lower()
        with self.lock:
            events = [dict(row) for row in self.event_log if int(row.get("seq", 0)) > int(since_seq)]
            if wanted:
                events = [row for row in events if str(row.get("type", "")).strip().lower() == wanted]
            events = events[: max(1, min(int(limit), 2000))]
            latest = self.event_seq
        return {
            "since_seq": int(since_seq),
            "count": len(events),
            "latest_seq": int(latest),
            "events": events,
        }

    def snapshot(self) -> Dict[str, Any]:
        return {
            "public": self.public_chain.export_state(),
            "private": self.private_chain.export_state(),
            "peers": sorted(self.peers),
            "rwa_listings": list(self.rwa_listings),
            "rwa_tokens": list(self.rwa_tokens),
            "rwa_access_passes": list(self.rwa_access_passes),
            "ai_agents": dict(self.ai_agents),
        }

    def adopt_snapshot_if_better(self, snapshot: Dict[str, Any]) -> Dict[str, bool]:
        changed = {
            "public": False,
            "private": False,
            "rwa_listings": False,
            "rwa_tokens": False,
            "rwa_access_passes": False,
            "ai_agents": False,
        }
        with self.lock:
            public_state = snapshot.get("public", {})
            private_state = snapshot.get("private", {})
            if public_state:
                changed["public"] = self.public_chain.adopt_state_if_longer(public_state)
            if private_state:
                changed["private"] = self.private_chain.adopt_state_if_longer(private_state)
            incoming_listings = snapshot.get("rwa_listings", [])
            if isinstance(incoming_listings, list):
                local_count = len(self.rwa_listings)
                incoming_count = len(incoming_listings)
                incoming_latest = max([float(item.get("updated_at", 0.0)) for item in incoming_listings if isinstance(item, dict)] + [0.0])
                local_latest = max([float(item.get("updated_at", 0.0)) for item in self.rwa_listings if isinstance(item, dict)] + [0.0])
                if incoming_count > local_count or (incoming_count == local_count and incoming_latest > local_latest):
                    self.rwa_listings = [dict(item) for item in incoming_listings if isinstance(item, dict)]
                    self._save_rwa_listings()
                    changed["rwa_listings"] = True
            incoming_tokens = snapshot.get("rwa_tokens", [])
            if isinstance(incoming_tokens, list):
                local_count = len(self.rwa_tokens)
                incoming_count = len(incoming_tokens)
                incoming_latest = max([float(item.get("deployed_at", 0.0)) for item in incoming_tokens if isinstance(item, dict)] + [0.0])
                local_latest = max([float(item.get("deployed_at", 0.0)) for item in self.rwa_tokens if isinstance(item, dict)] + [0.0])
                if incoming_count > local_count or (incoming_count == local_count and incoming_latest > local_latest):
                    self.rwa_tokens = [dict(item) for item in incoming_tokens if isinstance(item, dict)]
                    self._save_rwa_tokens()
                    changed["rwa_tokens"] = True
            incoming_passes = snapshot.get("rwa_access_passes", [])
            if isinstance(incoming_passes, list):
                local_count = len(self.rwa_access_passes)
                incoming_count = len(incoming_passes)
                incoming_latest = max([float(item.get("updated_at", 0.0)) for item in incoming_passes if isinstance(item, dict)] + [0.0])
                local_latest = max([float(item.get("updated_at", 0.0)) for item in self.rwa_access_passes if isinstance(item, dict)] + [0.0])
                if incoming_count > local_count or (incoming_count == local_count and incoming_latest > local_latest):
                    self.rwa_access_passes = [dict(item) for item in incoming_passes if isinstance(item, dict)]
                    self._save_rwa_access_passes()
                    changed["rwa_access_passes"] = True
            incoming_agents = snapshot.get("ai_agents", {})
            if isinstance(incoming_agents, dict):
                local_count = len(self.ai_agents)
                incoming_count = len(incoming_agents)
                incoming_latest = max(
                    [float(item.get("updated_at", 0.0)) for item in incoming_agents.values() if isinstance(item, dict)] + [0.0]
                )
                local_latest = max(
                    [float(item.get("updated_at", 0.0)) for item in self.ai_agents.values() if isinstance(item, dict)] + [0.0]
                )
                if incoming_count > local_count or (incoming_count == local_count and incoming_latest > local_latest):
                    self.ai_agents = {
                        str(k): dict(v)
                        for k, v in incoming_agents.items()
                        if isinstance(k, str) and isinstance(v, dict)
                    }
                    self._save_ai_agents()
                    changed["ai_agents"] = True

        for peer in snapshot.get("peers", []):
            self.peers.add(peer.rstrip("/"))
        self._save_peers()
        return changed

    def sync_from_peers(self) -> Dict[str, Any]:
        report = {
            "queried": 0,
            "public_updates": 0,
            "private_updates": 0,
            "rwa_listing_updates": 0,
            "rwa_token_updates": 0,
            "rwa_access_pass_updates": 0,
            "ai_agent_updates": 0,
            "errors": [],
        }
        for peer in list(self.peers):
            try:
                changed = self._sync_from_peer_once(peer)
                report["queried"] += 1
                report["public_updates"] += 1 if changed["public"] else 0
                report["private_updates"] += 1 if changed["private"] else 0
                report["rwa_listing_updates"] += 1 if changed.get("rwa_listings") else 0
                report["rwa_token_updates"] += 1 if changed.get("rwa_tokens") else 0
                report["rwa_access_pass_updates"] += 1 if changed.get("rwa_access_passes") else 0
                report["ai_agent_updates"] += 1 if changed.get("ai_agents") else 0
            except Exception as exc:  # pylint: disable=broad-except
                report["errors"].append(f"{peer}: {exc}")
        return report

    def broadcast_snapshot(self, source: str = "") -> None:
        payload = self.snapshot()
        payload["_propagated"] = True
        payload["_source"] = source
        for peer in list(self.peers):
            self.broadcast_pool.submit(
                http_post_json,
                f"{peer}/snapshot/push",
                payload,
                4.0,
                self.peer_token,
                self.peer_ssl_context,
            )

    def _wallet_path(self, name: str) -> str:
        if not self.wallet_name_pattern.match(name):
            raise ValueError("Wallet name must match [A-Za-z0-9_-], max length 64.")
        return os.path.join(self.wallet_dir, f"{name}.json")

    def create_named_wallet(
        self,
        name: str,
        scheme: str = "ed25519",
        use_hsm: bool = False,
        key_ref: str = "",
    ) -> Dict[str, Any]:
        path = self._wallet_path(name)
        if os.path.exists(path):
            raise ValueError(f"Wallet {name} already exists.")

        wallet = create_wallet(name=name, scheme=scheme)
        if use_hsm:
            ref = key_ref or f"{name}-k1"
            wallet = move_wallet_private_key_to_file_hsm(wallet, key_ref=ref, hsm_dir=self.hsm_dir)

        save_wallet(wallet, path)
        return self.wallet_public_info(wallet)

    def load_named_wallet(self, name: str) -> Dict[str, Any]:
        path = self._wallet_path(name)
        if not os.path.exists(path):
            raise ValueError(f"Wallet {name} not found.")
        return load_wallet(path)

    def assert_wallet_signer(self, wallet: Dict[str, Any]) -> None:
        if not self.require_hsm_signers:
            return
        signer = wallet.get("signer", {"type": "local"})
        signer_type = str(signer.get("type", "local")).strip().lower()
        if signer_type == "local":
            raise ValueError("Wallet signer policy violation: local signer disabled (require_hsm_signers=true).")

    def wallet_public_info(self, wallet: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "name": wallet.get("name", ""),
            "address": wallet["address"],
            "scheme": wallet.get("scheme", wallet.get("public_key", {}).get("kty", "unknown")),
            "public_key": wallet["public_key"],
            "signer": wallet.get("signer", {"type": "local"}),
            "hsm_ref": wallet.get("hsm_ref", ""),
        }

    def list_wallets(self) -> list[Dict[str, Any]]:
        out: list[Dict[str, Any]] = []
        for filename in sorted(os.listdir(self.wallet_dir)):
            if not filename.endswith(".json"):
                continue
            path = os.path.join(self.wallet_dir, filename)
            try:
                wallet = load_wallet(path)
                out.append(self.wallet_public_info(wallet))
            except Exception:
                continue
        return out

    def wallet_security_audit(
        self,
        require_nonlocal: bool = False,
        require_no_private_key: bool = False,
    ) -> Dict[str, Any]:
        rows: list[Dict[str, Any]] = []
        violations: list[str] = []
        for filename in sorted(os.listdir(self.wallet_dir)):
            if not filename.endswith(".json"):
                continue
            path = os.path.join(self.wallet_dir, filename)
            try:
                wallet = load_wallet(path)
            except Exception as exc:  # pylint: disable=broad-except
                violations.append(f"{filename}: unreadable ({exc})")
                continue
            signer = wallet.get("signer", {"type": "local"})
            signer_type = str(signer.get("type", "local")).strip().lower() or "local"
            has_private = bool(wallet.get("private_key"))
            key_ref = str(signer.get("key_ref", wallet.get("hsm_ref", ""))).strip()
            hsm_dir_raw = str(signer.get("hsm_dir", self.hsm_dir)).strip() or self.hsm_dir
            hsm_dir = hsm_dir_raw if os.path.isabs(hsm_dir_raw) else os.path.join(self.data_dir, hsm_dir_raw)
            hsm_key_path = os.path.join(hsm_dir, f"{key_ref}.json") if key_ref else ""
            hsm_key_found = bool(hsm_key_path) and os.path.exists(hsm_key_path)
            row = {
                "file": filename,
                "address": str(wallet.get("address", "")),
                "signer_type": signer_type,
                "has_private_key": has_private,
                "hsm_ref": key_ref,
                "hsm_key_path": hsm_key_path,
                "hsm_key_found": hsm_key_found,
            }
            rows.append(row)

            if require_nonlocal and signer_type == "local":
                violations.append(f"{filename}: signer is local")
            if require_no_private_key and has_private:
                violations.append(f"{filename}: private_key present")
            if signer_type == "file-hsm" and key_ref and not hsm_key_found:
                violations.append(f"{filename}: HSM key file missing ({hsm_key_path})")

        return {
            "wallet_dir": self.wallet_dir,
            "count": len(rows),
            "wallets": rows,
            "violation_count": len(violations),
            "violations": violations,
        }

    def find_wallet_by_address(self, address: str) -> Optional[Dict[str, Any]]:
        wanted = str(address).strip()
        if not wanted:
            return None
        for filename in sorted(os.listdir(self.wallet_dir)):
            if not filename.endswith(".json"):
                continue
            path = os.path.join(self.wallet_dir, filename)
            try:
                wallet = load_wallet(path)
            except Exception:
                continue
            if str(wallet.get("address", "")).strip() == wanted:
                return wallet
        return None

    def resolve_address_alias(self, value: str) -> str:
        raw = value.strip()
        if raw.startswith("@"):
            wallet = self.load_named_wallet(raw[1:])
            return wallet["address"]
        if raw.lower().startswith("evm:"):
            suffix = raw.split(":", 1)[1].strip()
            if re.fullmatch(r"0x[a-fA-F0-9]{40}", suffix):
                return f"EVM:{suffix.lower()}"
            return f"EVM:{suffix.lower()}" if suffix else raw
        if re.fullmatch(r"0x[a-fA-F0-9]{40}", raw):
            return f"EVM:{raw.lower()}"
        return raw

    def resolve_aliases(self, payload: Any) -> Any:
        if isinstance(payload, str):
            return self.resolve_address_alias(payload)
        if isinstance(payload, list):
            return [self.resolve_aliases(item) for item in payload]
        if isinstance(payload, dict):
            return {k: self.resolve_aliases(v) for k, v in payload.items()}
        return payload

    def _load_faucet_state(self) -> None:
        if not os.path.exists(self.faucet_state_file):
            self.faucet_last_claim_at = {}
            self.faucet_events = []
            return
        try:
            with open(self.faucet_state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            claims = data.get("last_claim_at", {})
            events = data.get("events", [])
            self.faucet_last_claim_at = {
                str(addr): float(ts)
                for addr, ts in claims.items()
                if isinstance(addr, str)
            }
            cleaned_events: list[Dict[str, Any]] = []
            for item in events:
                if not isinstance(item, dict):
                    continue
                address = str(item.get("address", "")).strip()
                try:
                    amount = float(item.get("amount", 0.0))
                    timestamp = float(item.get("timestamp", 0.0))
                except (TypeError, ValueError):
                    continue
                if not address or amount <= 0 or timestamp <= 0:
                    continue
                cleaned_events.append({"address": address, "amount": amount, "timestamp": timestamp})
            self.faucet_events = cleaned_events[-5000:]
        except Exception:
            self.faucet_last_claim_at = {}
            self.faucet_events = []

    def _save_faucet_state(self) -> None:
        payload = {
            "last_claim_at": self.faucet_last_claim_at,
            "events": self.faucet_events[-5000:],
        }
        with open(self.faucet_state_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

    def _prune_faucet_events(self, now: float) -> None:
        cutoff = now - 86400.0
        self.faucet_events = [e for e in self.faucet_events if float(e.get("timestamp", 0.0)) >= cutoff]

    def _faucet_window_total(self, now: float) -> float:
        self._prune_faucet_events(now)
        return float(sum(float(e.get("amount", 0.0)) for e in self.faucet_events))

    def faucet_status(self) -> Dict[str, Any]:
        now = time.time()
        claimed_24h = self._faucet_window_total(now)
        remaining = -1.0
        if self.faucet_daily_cap > 0:
            remaining = max(0.0, self.faucet_daily_cap - claimed_24h)
        return {
            "enabled": self.faucet_enabled,
            "default_amount": self.faucet_default_amount,
            "cooldown_seconds": self.faucet_cooldown_seconds,
            "daily_cap": self.faucet_daily_cap,
            "claimed_24h": claimed_24h,
            "remaining_24h": remaining,
            "tracked_addresses": len(self.faucet_last_claim_at),
        }

    def claim_public_faucet(self, to_address: str, amount: float = 0.0) -> Dict[str, Any]:
        if not self.faucet_enabled:
            raise ValueError("Public faucet is disabled.")

        requested = float(amount) if amount and float(amount) > 0 else self.faucet_default_amount
        if requested <= 0:
            raise ValueError("Faucet amount must be positive.")

        recipient = self.resolve_address_alias(str(to_address).strip())
        recipient = self.public_chain._normalize_address(recipient)  # pylint: disable=protected-access
        if not recipient:
            raise ValueError("Recipient address is required.")

        now = time.time()
        last = float(self.faucet_last_claim_at.get(recipient, 0.0))
        if self.faucet_cooldown_seconds > 0 and last > 0:
            elapsed = now - last
            if elapsed < self.faucet_cooldown_seconds:
                remaining = int(self.faucet_cooldown_seconds - elapsed + 0.999)
                raise ValueError(f"Faucet cooldown active. Try again in {remaining} seconds.")

        claimed_24h = self._faucet_window_total(now)
        if self.faucet_daily_cap > 0 and (claimed_24h + requested) > (self.faucet_daily_cap + 1e-12):
            raise ValueError("Faucet daily cap reached. Try again later.")

        tx_payload = {
            "type": "payment",
            "sender": "SYSTEM",
            "recipient": recipient,
            "amount": requested,
            "timestamp": now,
            "source": "faucet",
        }
        tx_id = hashlib.sha256(
            json.dumps(tx_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        tx = {**tx_payload, "id": tx_id}
        self.public_chain.add_transaction(tx)

        self.faucet_last_claim_at[recipient] = now
        self.faucet_events.append({"address": recipient, "amount": requested, "timestamp": now})
        self._prune_faucet_events(now)
        self._save_faucet_state()

        return {
            "ok": True,
            "tx_id": tx_id,
            "recipient": recipient,
            "amount": requested,
            "faucet": self.faucet_status(),
        }

    def auto_mine_status(self) -> Dict[str, Any]:
        with self.lock:
            if self.auto_mine_enabled:
                self.auto_mine_effective_miner = self._resolve_auto_mine_miner_locked()
            thread_alive = bool(self._auto_mine_thread and self._auto_mine_thread.is_alive())
            return {
                "enabled": self.auto_mine_enabled,
                "miner": self.auto_mine_miner,
                "effective_miner": self.auto_mine_effective_miner,
                "follow_rotation": self.auto_mine_follow_rotation,
                "interval_seconds": self.auto_mine_interval_seconds,
                "allow_empty_blocks": self.auto_mine_allow_empty_blocks,
                "last_block_hash": self.auto_mine_last_block_hash,
                "last_block_index": self.auto_mine_last_block_index,
                "last_mined_at": self.auto_mine_last_mined_at,
                "last_error": self.auto_mine_last_error,
                "thread_alive": thread_alive,
            }

    def _ensure_auto_mine_thread(self) -> None:
        if self._auto_mine_thread and self._auto_mine_thread.is_alive():
            return
        self._auto_mine_stop.clear()
        self._auto_mine_thread = threading.Thread(
            target=self._auto_mine_loop,
            name="jito-auto-miner",
            daemon=True,
        )
        self._auto_mine_thread.start()

    def _resolve_auto_mine_miner_locked(self) -> str:
        miner = str(self.auto_mine_miner).strip()
        if (
            self.auto_mine_follow_rotation
            and self.public_chain.consensus == "poa"
            and self.public_chain.validator_rotation_enabled
            and self.public_chain.validators
        ):
            expected = self.public_chain.expected_next_validator()
            if expected:
                miner = expected
        return miner

    def start_auto_mining(self, miner: str, interval_seconds: float, allow_empty_blocks: bool = False) -> Dict[str, Any]:
        raw_miner = str(miner).strip()
        follow_rotation = raw_miner.lower() in {"auto", "rotation", "expected"}
        if follow_rotation:
            if self.public_chain.consensus != "poa":
                raise ValueError("auto rotation miner mode is only supported for poa consensus")
            if not self.public_chain.validators:
                raise ValueError("auto rotation miner mode requires at least one validator")
            miner_address = self.public_chain.expected_next_validator() or sorted(self.public_chain.validators)[0]
        else:
            miner_address = self.resolve_address_alias(raw_miner)
        if not miner_address:
            raise ValueError("miner is required")
        interval = float(interval_seconds)
        if interval < 0.2 or interval > 3600:
            raise ValueError("interval_seconds must be between 0.2 and 3600")
        if self.public_chain.consensus == "poa" and miner_address not in self.public_chain.validators:
            raise ValueError("auto-mine miner is not in validator set for poa consensus")

        with self.lock:
            self.auto_mine_enabled = True
            self.auto_mine_miner = miner_address
            self.auto_mine_follow_rotation = follow_rotation
            self.auto_mine_effective_miner = miner_address
            self.auto_mine_interval_seconds = interval
            self.auto_mine_allow_empty_blocks = bool(allow_empty_blocks)
            self.auto_mine_last_error = ""
        self._ensure_auto_mine_thread()
        return self.auto_mine_status()

    def stop_auto_mining(self) -> Dict[str, Any]:
        with self.lock:
            self.auto_mine_enabled = False
        return self.auto_mine_status()

    def stop_background_workers(self) -> None:
        self._auto_mine_stop.set()
        thread = self._auto_mine_thread
        if thread and thread.is_alive():
            thread.join(timeout=2.0)
        self._peer_sync_stop.set()
        peer_thread = self._peer_sync_thread
        if peer_thread and peer_thread.is_alive():
            peer_thread.join(timeout=2.0)
        self.broadcast_pool.shutdown(wait=False, cancel_futures=True)
        self.public_chain.close()

    def _auto_mine_loop(self) -> None:
        next_run = time.monotonic()
        while not self._auto_mine_stop.is_set():
            with self.lock:
                enabled = self.auto_mine_enabled
                interval = max(0.2, float(self.auto_mine_interval_seconds))
                allow_empty = self.auto_mine_allow_empty_blocks
                miner = self._resolve_auto_mine_miner_locked()
                self.auto_mine_effective_miner = miner
                pending_count = len(self.public_chain.pending_transactions)

            now = time.monotonic()
            if now < next_run:
                self._auto_mine_stop.wait(min(next_run - now, 0.5))
                continue
            next_run = now + interval

            if not enabled:
                continue
            if not allow_empty and pending_count == 0:
                continue

            mined_block = None
            with self.lock:
                try:
                    if not self.auto_mine_enabled:
                        continue
                    if not self.auto_mine_allow_empty_blocks and not self.public_chain.pending_transactions:
                        continue
                    miner = self._resolve_auto_mine_miner_locked()
                    self.auto_mine_effective_miner = miner
                    mined_block = self.public_chain.mine_pending_transactions(miner)
                    self.auto_mine_last_block_hash = mined_block.hash
                    self.auto_mine_last_block_index = mined_block.index
                    self.auto_mine_last_mined_at = mined_block.timestamp
                    self.auto_mine_last_error = ""
                except Exception as exc:  # pylint: disable=broad-except
                    message = str(exc)
                    # In PoA rotation mode, a validator node should stay active even when
                    # it wakes up on another validator's turn.
                    if "proposer rotation" in message and "Expected" in message:
                        self.auto_mine_last_error = ""
                        continue
                    self.auto_mine_last_error = message
                    self.auto_mine_enabled = False

            if mined_block is not None:
                with self.lock:
                    # Keep status aligned with the next expected proposer after a successful
                    # PoA mine so API/UI consumers don't see a stale effective miner.
                    self.auto_mine_effective_miner = self._resolve_auto_mine_miner_locked()
                self.publish_event(
                    "public.block.mined",
                    {
                        "source": "auto-mine",
                        "block_index": mined_block.index,
                        "block_hash": mined_block.hash,
                        "validator": str(mined_block.meta.get("validator", "")),
                        "tx_count": len(mined_block.transactions),
                    },
                )
                self.broadcast_snapshot(source="auto-miner")


class NodeHandler(BaseHTTPRequestHandler):
    node: Optional[DualChainNode] = None
    base_url: str = ""
    ui_html: str = ""
    explorer_html: str = ""
    scanner_html: str = ""
    rwa_html: str = ""
    rwa_market_html: str = ""
    app_hub_html: str = ""
    community_html: str = ""
    passport_html: str = ""
    start_html: str = ""
    jwt_secret: str = ""
    jwt_required: bool = False
    chain_info: Dict[str, Any] = {}
    rate_limit_per_minute: int = 300
    rate_limit_tiers: Dict[str, int] = {}
    api_key_tier_map: Dict[str, str] = {}
    rate_limit_lock = threading.Lock()
    rate_limit_state: Dict[str, Dict[str, float]] = {}

    def _rwa_settlement_asset_id(self) -> str:
        public = self.chain_info.get("public_chain", {}) if isinstance(self.chain_info, dict) else {}
        native = public.get("native_token", {}) if isinstance(public, dict) else {}
        symbol = str(native.get("symbol", "NOVA")).strip().upper()
        return symbol or "NOVA"

    def _rwa_settlement_price_usd(self) -> float:
        return 1.0

    @staticmethod
    def _clean_logo_url(value: str) -> str:
        raw = str(value).strip()
        if not raw:
            return ""
        if raw.startswith(("http://", "https://", "/", "data:image/")):
            return raw
        raise ValueError("Logo URL must start with http://, https://, /, or data:image/")

    def _set_branding(self, chain_logo_url: str, token_logo_url: str) -> None:
        info = self.chain_info
        branding = info.setdefault("branding", {})
        public = info.setdefault("public_chain", {})
        native = public.setdefault("native_token", {})

        branding["chain_logo_url"] = chain_logo_url
        branding["token_logo_url"] = token_logo_url
        public["logo_url"] = chain_logo_url
        native["logo_url"] = token_logo_url

    def _coerce_string_list(self, value: Any) -> list[str]:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        return []

    def _resolve_address_tokens(self, value: Any) -> list[str]:
        assert self.node is not None
        return [self.node.resolve_address_alias(item) for item in self._coerce_string_list(value)]

    @staticmethod
    def _as_bool(value: Any, default: bool = False) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return default
        raw = str(value).strip().lower()
        if raw in {"1", "true", "yes", "y", "on"}:
            return True
        if raw in {"0", "false", "no", "n", "off"}:
            return False
        return default

    def _normalize_rwa_trade_policy(
        self,
        raw_policy: Any,
        access_mode: str,
    ) -> Dict[str, Any]:
        assert self.node is not None
        base = raw_policy if isinstance(raw_policy, dict) else {}

        require_participant = self._as_bool(base.get("require_participant", True), True)
        require_kyc = self._as_bool(base.get("require_kyc", False), False)
        require_access_code = access_mode == "access_id"

        min_order_units = float(base.get("min_order_units", 0.0) or 0.0)
        max_order_units = float(base.get("max_order_units", 0.0) or 0.0)
        if min_order_units < 0:
            min_order_units = 0.0
        if max_order_units < 0:
            max_order_units = 0.0
        if max_order_units > 0 and max_order_units < min_order_units:
            raise ValueError("policy.max_order_units must be >= policy.min_order_units.")

        allowed_wallets = set(self._resolve_address_tokens(base.get("allowed_wallets", [])))
        for name in self._coerce_string_list(base.get("allowed_wallet_names", [])):
            try:
                allowed_wallets.add(self.node.load_named_wallet(name)["address"])
            except Exception:
                continue

        allowed_jurisdictions = sorted(
            {
                str(item).strip().upper()
                for item in self._coerce_string_list(base.get("allowed_jurisdictions", []))
                if str(item).strip()
            }
        )
        blocked_jurisdictions = sorted(
            {
                str(item).strip().upper()
                for item in self._coerce_string_list(base.get("blocked_jurisdictions", []))
                if str(item).strip()
            }
        )

        return {
            "require_participant": require_participant,
            "require_kyc": require_kyc,
            "require_access_code": require_access_code,
            "min_order_units": min_order_units,
            "max_order_units": max_order_units,
            "allowed_wallets": sorted(allowed_wallets),
            "allowed_jurisdictions": allowed_jurisdictions,
            "blocked_jurisdictions": blocked_jurisdictions,
        }

    def _assert_rwa_trade_policy(
        self,
        policy: Dict[str, Any],
        buyer_wallet_name: str,
        buyer_address: str,
        quantity: float,
        access_code: str,
    ) -> None:
        assert self.node is not None
        profile = self.node.private_chain.participants.get(buyer_address, {})
        attrs = profile.get("attributes", {}) if isinstance(profile.get("attributes", {}), dict) else {}

        if bool(policy.get("require_participant", True)) and not profile:
            raise ValueError(f"Buyer wallet '{buyer_wallet_name}' is not registered as private participant.")

        min_order = float(policy.get("min_order_units", 0.0) or 0.0)
        max_order = float(policy.get("max_order_units", 0.0) or 0.0)
        if min_order > 0 and quantity + 1e-12 < min_order:
            raise ValueError(f"Order quantity below minimum. min_order_units={min_order}.")
        if max_order > 0 and quantity - 1e-12 > max_order:
            raise ValueError(f"Order quantity exceeds maximum. max_order_units={max_order}.")

        if bool(policy.get("require_access_code", False)) and not str(access_code).strip():
            raise ValueError("This listing requires an Access ID.")

        allowed_wallets = set(policy.get("allowed_wallets", []))
        if allowed_wallets and buyer_address not in allowed_wallets:
            raise ValueError("Buyer wallet is not in listing allowlist.")

        if bool(policy.get("require_kyc", False)) and not self._as_bool(attrs.get("kyc", False), False):
            raise ValueError("Buyer failed KYC policy for this listing.")

        jurisdiction = str(attrs.get("jurisdiction", attrs.get("country", ""))).strip().upper()
        allowed_jurisdictions = set(policy.get("allowed_jurisdictions", []))
        blocked_jurisdictions = set(policy.get("blocked_jurisdictions", []))
        if allowed_jurisdictions and jurisdiction not in allowed_jurisdictions:
            raise ValueError("Buyer jurisdiction is not allowed for this listing.")
        if blocked_jurisdictions and jurisdiction in blocked_jurisdictions:
            raise ValueError("Buyer jurisdiction is blocked for this listing.")

    def _compute_metadata_hash(self, metadata: Dict[str, Any]) -> str:
        raw = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def _read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        if not raw:
            return {}
        return json.loads(raw)

    def _portal_session_token(self, query: Optional[Dict[str, list[str]]] = None) -> str:
        token = self.headers.get("X-Portal-Session", "").strip()
        if token:
            return token
        auth_header = self.headers.get("Authorization", "").strip()
        if auth_header.lower().startswith("portal "):
            return auth_header.split(" ", 1)[1].strip()
        if query is not None:
            token = query.get("session", [""])[0].strip()
            if token:
                return token
        return ""

    def _require_portal_session(self, query: Optional[Dict[str, list[str]]] = None) -> Optional[Dict[str, Any]]:
        token = self._portal_session_token(query)
        if not token:
            self._send_json(
                {"ok": False, "error": "Portal session token missing. Provide X-Portal-Session header."},
                HTTPStatus.UNAUTHORIZED,
            )
            return None
        try:
            return self.node.portal_session_user(token)
        except Exception as exc:  # pylint: disable=broad-except
            self._send_json({"ok": False, "error": str(exc)}, HTTPStatus.UNAUTHORIZED)
            return None

    def _can_view_private_scanner(self, query: Optional[Dict[str, list[str]]] = None) -> bool:
        token = self._portal_session_token(query)
        if not token:
            return False
        try:
            self.node.portal_session_user(token)
            return True
        except Exception:
            return False

    def _load_signing_wallet(self, wallet_name: str) -> Dict[str, Any]:
        assert self.node is not None
        wallet = self.node.load_named_wallet(wallet_name)
        self.node.assert_wallet_signer(wallet)
        return wallet

    def _send_json(
        self,
        payload: Dict[str, Any],
        status: HTTPStatus = HTTPStatus.OK,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, text: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, raw: bytes, content_type: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _send_event_stream(self, since_seq: int = 0, type_filter: str = "", timeout_seconds: float = 25.0) -> None:
        assert self.node is not None
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        last_seq = int(max(0, since_seq))
        deadline = time.time() + max(2.0, float(timeout_seconds))
        while time.time() < deadline:
            chunk = self.node.list_events_since(last_seq, limit=200, type_filter=type_filter)
            events = chunk.get("events", [])
            if events:
                for row in events:
                    seq = int(row.get("seq", last_seq))
                    event_type = str(row.get("type", "event")).strip() or "event"
                    data = json.dumps(row, separators=(",", ":"))
                    packet = f"id: {seq}\nevent: {event_type}\ndata: {data}\n\n".encode("utf-8")
                    self.wfile.write(packet)
                    self.wfile.flush()
                    last_seq = seq
                continue
            # Keepalive comment frame.
            self.wfile.write(b": ping\n\n")
            self.wfile.flush()
            time.sleep(0.5)

    def _client_ip(self) -> str:
        forwarded_for = self.headers.get("X-Forwarded-For", "").strip()
        if forwarded_for:
            first = forwarded_for.split(",")[0].strip()
            if first:
                return first
        if self.client_address and self.client_address[0]:
            return str(self.client_address[0])
        return "unknown"

    def _rate_limit_exempt(self, path: str) -> bool:
        if path.startswith("/assets/"):
            return True
        if path.startswith("/community/"):
            return True
        if path in {
            "/health",
            "/app",
            "/app/investor",
            "/app/issuer",
            "/app/operator",
            "/app/community",
            "/ui",
            "/explorer",
            "/scanner",
            "/rwa",
            "/rwa-market",
            "/rwa-dashboard",
            "/community",
        }:
            return True
        node_token = self.headers.get("X-Node-Token", "").strip()
        if node_token:
            return True
        return False

    def _enforce_rate_limit(self, path: str) -> bool:
        api_key = self.headers.get("X-API-Key", "").strip()
        tier = "default"
        if api_key:
            mapped = self.api_key_tier_map.get(api_key)
            if mapped:
                tier = mapped
        tier_limit = self.rate_limit_tiers.get(tier, self.rate_limit_per_minute)
        limit = int(tier_limit)
        if limit <= 0 or self._rate_limit_exempt(path):
            return True

        now = time.time()
        identity = f"api:{api_key}" if api_key else f"ip:{self._client_ip()}"
        key = f"{self.command}:{tier}:{identity}"
        with self.rate_limit_lock:
            row = self.rate_limit_state.get(key)
            if row is None or (now - float(row.get("window_start", 0.0))) >= 60.0:
                row = {"window_start": now, "count": 0.0}
                self.rate_limit_state[key] = row
            row["count"] = float(row.get("count", 0.0)) + 1.0
            if len(self.rate_limit_state) > 10000:
                cutoff = now - 180.0
                stale = [k for k, v in self.rate_limit_state.items() if float(v.get("window_start", 0.0)) < cutoff]
                for stale_key in stale[:2000]:
                    self.rate_limit_state.pop(stale_key, None)
            if row["count"] <= float(limit):
                return True
            retry_after = max(1, int(60.0 - (now - float(row.get("window_start", now)))))

        self._send_json(
            {
                "ok": False,
                "error": "Rate limit exceeded.",
                "retry_after_seconds": retry_after,
                "limit_per_minute": limit,
                "tier": tier,
            },
            status=HTTPStatus.TOO_MANY_REQUESTS,
            headers={"Retry-After": str(retry_after)},
        )
        return False

    def _current_chain_info(self) -> Dict[str, Any]:
        info = json.loads(json.dumps(self.chain_info))
        public = info.setdefault("public_chain", {})
        public["consensus"] = self.node.public_chain.consensus
        public["difficulty"] = self.node.public_chain.difficulty
        public["pow_parallel_workers"] = self.node.public_chain.pow_parallel_workers
        public["pow_nonce_chunk_size"] = self.node.public_chain.pow_nonce_chunk_size
        public["block_reward"] = self.node.public_chain.mining_reward
        public["validators"] = sorted(self.node.public_chain.validators)
        public["validator_count"] = len(self.node.public_chain.validators)
        public["validator_rotation"] = self.node.public_chain.validator_rotation_enabled
        public["next_expected_validator"] = self.node.public_chain.expected_next_validator()
        public["finality_confirmations"] = self.node.public_chain.finality_confirmations
        public["latest_finalized_height"] = self.node.public_chain.latest_finalized_height()
        public["checkpoint_interval"] = self.node.public_chain.checkpoint_interval
        public["checkpoints"] = self.node.public_chain.checkpoint_summary(limit=10)
        public["mempool_policy"] = self.node.public_chain.mempool_policy()
        public["ai_provider_stakes"] = self.node.public_chain.get_provider_stakes()
        public["faucet"] = self.node.faucet_status()
        private_info = info.setdefault("private_chain", {})
        private_info["gas_model"] = "no-gas"
        private_info["gas_fee_per_tx"] = 0.0
        private_info["ai_models"] = len(self.node.private_chain.model_registry)
        private_info["ai_jobs"] = len(self.node.private_chain.ai_jobs)
        private_info["ai_agents"] = len(self.node.ai_agents)
        private_info["rwa_open_listings"] = len([row for row in self.node.rwa_listings if str(row.get("status", "open")) == "open"])
        private_info["rwa_token_contracts"] = len(self.node.rwa_tokens)
        info["auto_mine"] = self.node.auto_mine_status()
        info["security"] = {
            "mainnet_hardening": self.node.mainnet_hardening,
            "faucet_enabled": self.node.faucet_enabled,
            "strict_public_signatures": self.node.public_chain.strict_signature_validation,
            "require_hsm_signers": self.node.require_hsm_signers,
        }
        return info

    def _community_overview_payload(self) -> Dict[str, Any]:
        now = time.time()
        since_24h = now - 86400.0

        with self.node.lock:
            public_height = len(self.node.public_chain.chain) - 1
            private_height = len(self.node.private_chain.chain) - 1
            validators = sorted(self.node.public_chain.validators)
            governance = self.node.private_chain.list_governance()
            proposals = governance.get("proposals", []) if isinstance(governance, dict) else []

            unique_public_addresses: Set[str] = set()
            public_user_tx = 0
            public_user_tx_24h = 0
            for block in self.node.public_chain.chain:
                for tx in block.transactions:
                    if not isinstance(tx, dict):
                        continue
                    if tx.get("type") == "payment" and tx.get("sender") == SYSTEM_SENDER:
                        continue
                    public_user_tx += 1
                    if float(tx.get("timestamp", block.timestamp)) >= since_24h:
                        public_user_tx_24h += 1
                    sender, recipient = _tx_from_to(tx)
                    for addr in (sender, recipient):
                        raw = str(addr or "").strip()
                        if raw and raw != SYSTEM_SENDER:
                            unique_public_addresses.add(raw)

            open_listings = 0
            total_trades = 0
            total_trade_notional = 0.0
            trades_24h = 0
            for listing in self.node.rwa_listings:
                if str(listing.get("status", "")).strip().lower() == "open":
                    open_listings += 1
                for trade in list(listing.get("trades", [])):
                    if not isinstance(trade, dict):
                        continue
                    total_trades += 1
                    total_trade_notional += float(
                        trade.get("settlement_amount", trade.get("total_price", 0.0)) or 0.0
                    )
                    if float(trade.get("timestamp", 0.0)) >= since_24h:
                        trades_24h += 1

            active_access_ids = 0
            for row in self.node.rwa_access_passes:
                if str(row.get("status", "active")).strip().lower() != "active":
                    continue
                expires_at = float(row.get("expires_at", 0.0) or 0.0)
                if expires_at and expires_at < now:
                    continue
                active_access_ids += 1

            event_24h = [evt for evt in self.node.event_log if float(evt.get("ts", 0.0)) >= since_24h]
            auto_mine_snapshot = {
                "enabled": self.node.auto_mine_enabled,
                "miner": self.node.auto_mine_miner,
                "effective_miner": self.node._resolve_auto_mine_miner_locked() if self.node.auto_mine_enabled else self.node.auto_mine_effective_miner,
                "follow_rotation": self.node.auto_mine_follow_rotation,
                "interval_seconds": self.node.auto_mine_interval_seconds,
                "allow_empty_blocks": self.node.auto_mine_allow_empty_blocks,
                "last_block_hash": self.node.auto_mine_last_block_hash,
                "last_block_index": self.node.auto_mine_last_block_index,
                "last_mined_at": self.node.auto_mine_last_mined_at,
                "last_error": self.node.auto_mine_last_error,
                "thread_alive": bool(self.node._auto_mine_thread and self.node._auto_mine_thread.is_alive()),
            }

            return {
                "network": {
                    "public_height": public_height,
                    "private_height": private_height,
                    "public_consensus": self.node.public_chain.consensus,
                    "validator_count": len(validators),
                    "validators": validators,
                    "next_expected_validator": self.node.public_chain.expected_next_validator(),
                    "auto_mine": auto_mine_snapshot,
                },
                "community": {
                    "wallet_count": len(self.node.list_wallets()),
                    "public_active_addresses": len(unique_public_addresses),
                    "public_user_tx_total": public_user_tx,
                    "public_user_tx_24h": public_user_tx_24h,
                    "events_24h": len(event_24h),
                    "uptime_seconds": max(0, int(now - self.node.started_at)),
                },
                "governance": {
                    "threshold": _safe_int(governance.get("governance_threshold", 0), 0, 0, 1_000_000),
                    "proposal_count": len(proposals),
                    "open_count": sum(1 for p in proposals if not p.get("executed")),
                    "executed_count": sum(1 for p in proposals if p.get("executed")),
                },
                "rwa": {
                    "token_contract_count": len(self.node.rwa_tokens),
                    "open_listing_count": open_listings,
                    "trade_count": total_trades,
                    "trade_count_24h": trades_24h,
                    "settled_notional_total": total_trade_notional,
                    "active_access_id_count": active_access_ids,
                },
                "ai": {
                    "agent_count": len(self.node.ai_agents),
                    "model_count": len(self.node.private_chain.model_registry),
                    "job_count": len(self.node.private_chain.ai_jobs),
                    "provider_stakes": self.node.public_chain.get_provider_stakes(),
                },
            }

    def _community_leaderboard_payload(self, board_type: str, limit: int = 20) -> Dict[str, Any]:
        kind = str(board_type or "validators").strip().lower()
        limit = max(1, min(int(limit), 200))
        wallets = self.node.list_wallets()
        name_by_address = {
            str(item.get("address", "")).strip(): str(item.get("name", "")).strip()
            for item in wallets
            if isinstance(item, dict)
        }

        if kind == "validators":
            rows: Dict[str, Dict[str, Any]] = {}
            with self.node.lock:
                for block in self.node.public_chain.chain:
                    meta = block.meta if isinstance(block.meta, dict) else {}
                    validator = str(meta.get("validator", "")).strip()
                    if not validator:
                        continue
                    row = rows.setdefault(
                        validator,
                        {
                            "address": validator,
                            "wallet_name": name_by_address.get(validator, ""),
                            "blocks_mined": 0,
                            "reward_total": 0.0,
                            "last_block_index": -1,
                        },
                    )
                    row["blocks_mined"] += 1
                    row["last_block_index"] = max(int(row["last_block_index"]), int(block.index))
                    for tx in block.transactions:
                        if not isinstance(tx, dict):
                            continue
                        if (
                            tx.get("type") == "payment"
                            and tx.get("sender") == SYSTEM_SENDER
                            and str(tx.get("recipient", "")).strip() == validator
                        ):
                            row["reward_total"] += float(tx.get("amount", 0.0))
                            break
            sorted_rows = sorted(
                rows.values(),
                key=lambda r: (float(r.get("blocks_mined", 0)), float(r.get("reward_total", 0.0))),
                reverse=True,
            )[:limit]
            return {"type": kind, "count": len(sorted_rows), "rows": sorted_rows}

        if kind == "traders":
            rows: Dict[str, Dict[str, Any]] = {}
            with self.node.lock:
                listings = list(self.node.rwa_listings)
            for listing in listings:
                seller_name = str(listing.get("seller_wallet_name", "")).strip()
                seller_address = str(listing.get("seller_address", "")).strip()
                for trade in list(listing.get("trades", [])):
                    if not isinstance(trade, dict):
                        continue
                    buyer_name = str(trade.get("buyer_wallet_name", "")).strip()
                    buyer_address = str(trade.get("buyer_address", "")).strip()
                    amount = float(trade.get("amount", 0.0) or 0.0)
                    notional = float(trade.get("settlement_amount", trade.get("total_price", 0.0)) or 0.0)

                    for role, key_name, key_addr in [
                        ("buyer", buyer_name, buyer_address),
                        ("seller", seller_name, seller_address),
                    ]:
                        if not key_addr and not key_name:
                            continue
                        bucket = rows.setdefault(
                            key_addr or key_name,
                            {
                                "wallet_name": key_name or name_by_address.get(key_addr, ""),
                                "address": key_addr,
                                "buy_trades": 0,
                                "sell_trades": 0,
                                "units_bought": 0.0,
                                "units_sold": 0.0,
                                "notional_total": 0.0,
                            },
                        )
                        if role == "buyer":
                            bucket["buy_trades"] += 1
                            bucket["units_bought"] += amount
                        else:
                            bucket["sell_trades"] += 1
                            bucket["units_sold"] += amount
                        bucket["notional_total"] += notional
            sorted_rows = sorted(
                rows.values(),
                key=lambda r: (float(r.get("notional_total", 0.0)), float(r.get("units_bought", 0.0) + r.get("units_sold", 0.0))),
                reverse=True,
            )[:limit]
            return {"type": kind, "count": len(sorted_rows), "rows": sorted_rows}

        if kind == "builders":
            rows: Dict[str, Dict[str, Any]] = {}
            with self.node.lock:
                governance = self.node.private_chain.list_governance()
                proposals = governance.get("proposals", []) if isinstance(governance, dict) else []
            for proposal in proposals:
                proposer = str(proposal.get("proposer", "")).strip()
                if proposer:
                    item = rows.setdefault(
                        proposer,
                        {
                            "address": proposer,
                            "wallet_name": name_by_address.get(proposer, ""),
                            "proposals_created": 0,
                            "proposals_executed": 0,
                            "approvals_given": 0,
                            "score": 0.0,
                        },
                    )
                    item["proposals_created"] += 1
                    if proposal.get("executed"):
                        item["proposals_executed"] += 1
                    item["score"] += 3.0 + (2.0 if proposal.get("executed") else 0.0)

                for approval in list(proposal.get("approvals", [])):
                    approver = str(approval.get("approver", "")).strip()
                    if not approver:
                        continue
                    item = rows.setdefault(
                        approver,
                        {
                            "address": approver,
                            "wallet_name": name_by_address.get(approver, ""),
                            "proposals_created": 0,
                            "proposals_executed": 0,
                            "approvals_given": 0,
                            "score": 0.0,
                        },
                    )
                    item["approvals_given"] += 1
                    item["score"] += 1.0
            sorted_rows = sorted(rows.values(), key=lambda r: float(r.get("score", 0.0)), reverse=True)[:limit]
            return {"type": kind, "count": len(sorted_rows), "rows": sorted_rows}

        if kind == "agents":
            rows: Dict[str, Dict[str, Any]] = {}
            with self.node.lock:
                agents = list(self.node.ai_agents.values())
                jobs = dict(self.node.private_chain.ai_jobs)

            for agent in agents:
                wallet_name = str(agent.get("wallet_name", "")).strip()
                wallet_address = str(agent.get("wallet_address", "")).strip()
                rows[wallet_name or wallet_address] = {
                    "agent_id": str(agent.get("agent_id", "")).strip(),
                    "name": str(agent.get("name", "")).strip(),
                    "role": str(agent.get("role", "")).strip(),
                    "wallet_name": wallet_name,
                    "wallet_address": wallet_address,
                    "jobs_completed": 0,
                    "jobs_settled": 0,
                    "score": 0.0,
                }

            for job in jobs.values():
                result = job.get("result", {}) if isinstance(job, dict) else {}
                settlement = job.get("settlement", {}) if isinstance(job, dict) else {}
                provider = str(result.get("provider", "")).strip()
                if provider:
                    for row in rows.values():
                        if row.get("wallet_address") == provider:
                            row["jobs_completed"] += 1
                            row["score"] += 2.0
                if settlement:
                    settler = str(settlement.get("settler", "")).strip()
                    for row in rows.values():
                        if row.get("wallet_address") == settler:
                            row["jobs_settled"] += 1
                            row["score"] += 1.0

            sorted_rows = sorted(rows.values(), key=lambda r: float(r.get("score", 0.0)), reverse=True)[:limit]
            return {"type": kind, "count": len(sorted_rows), "rows": sorted_rows}

        return {"type": kind, "count": 0, "rows": [], "error": "Unsupported leaderboard type."}

    @staticmethod
    def _community_roadmap_payload() -> Dict[str, Any]:
        return {
            "vision": "AI-native + community-centric blockchain for real-world assets and agent economies.",
            "phases": [
                {
                    "name": "Phase 1",
                    "window": "0-30 days",
                    "focus": "Reliability + baseline operations",
                    "deliverables": [
                        "validator drift prevention",
                        "strict signature enforcement",
                        "mempool controls + observability",
                    ],
                },
                {
                    "name": "Phase 2",
                    "window": "31-60 days",
                    "focus": "Throughput + state scalability",
                    "deliverables": [
                        "parallel PoW workers",
                        "async peer propagation",
                        "persistent mempool resilience",
                    ],
                },
                {
                    "name": "Phase 3",
                    "window": "61-90 days",
                    "focus": "Community economy + consumer UX",
                    "deliverables": [
                        "community governance UX",
                        "wallet + onboarding simplification",
                        "AI-agent marketplace primitives",
                    ],
                },
            ],
            "source_doc": "/docs/PLATFORM_EXECUTION_PLAN.md",
        }

    def _authorized(self, path: str) -> bool:
        if not self.jwt_secret:
            return True

        if path == "/community" or path == "/app/community" or path.startswith("/community/"):
            return True

        if path in {
            "/health",
            "/metrics",
            "/chain/info",
            "/app",
            "/app/investor",
            "/app/issuer",
            "/app/operator",
            "/app/community",
            "/ui",
            "/explorer",
            "/scanner",
            "/rwa",
            "/rwa-market",
            "/rwa-dashboard",
            "/community",
            "/private/rwa/dashboard",
            "/private/rwa/auth/me",
            "/ui/private/auth/register",
            "/ui/private/auth/login",
            "/ui/private/auth/logout",
            "/ui/private/auth/link-wallet",
        }:
            return True

        auth_header = self.headers.get("Authorization", "")
        if not auth_header:
            if self.jwt_required:
                self._send_json({"ok": False, "error": "Missing Authorization header."}, HTTPStatus.UNAUTHORIZED)
                return False
            return True

        if not auth_header.lower().startswith("bearer "):
            self._send_json({"ok": False, "error": "Authorization header must be Bearer token."}, HTTPStatus.UNAUTHORIZED)
            return False

        token = auth_header.split(" ", 1)[1].strip()
        try:
            verify_hs256_jwt(token, self.jwt_secret)
            return True
        except Exception as exc:  # pylint: disable=broad-except
            self._send_json({"ok": False, "error": f"Invalid JWT: {exc}"}, HTTPStatus.UNAUTHORIZED)
            return False

    def log_message(self, format_string: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        assert self.node is not None
        parsed = parse.urlparse(self.path)
        path = parsed.path
        query = parse.parse_qs(parsed.query)

        if path.startswith("/assets/"):
            rel = path[len("/assets/") :].strip("/")
            asset_root = os.path.join(os.path.dirname(__file__), "assets")
            local_path = os.path.normpath(os.path.join(asset_root, rel))
            if not local_path.startswith(asset_root) or not os.path.exists(local_path) or not os.path.isfile(local_path):
                self._send_json({"error": "Asset not found."}, HTTPStatus.NOT_FOUND)
                return
            ext = os.path.splitext(local_path)[1].lower()
            content_type = {
                ".css": "text/css; charset=utf-8",
                ".js": "application/javascript; charset=utf-8",
                ".png": "image/png",
                ".jpg": "image/jpeg",
                ".jpeg": "image/jpeg",
                ".svg": "image/svg+xml",
                ".webp": "image/webp",
                ".ico": "image/x-icon",
                ".json": "application/json; charset=utf-8",
            }.get(ext, "application/octet-stream")
            with open(local_path, "rb") as f:
                self._send_bytes(f.read(), content_type=content_type)
            return

        if not self._enforce_rate_limit(path):
            return

        if not self._authorized(path):
            return

        if path == "/health":
            self._send_json({"ok": True})
            return

        if path == "/app":
            self._send_html(self.app_hub_html)
            return

        if path == "/app/investor":
            self._send_html(self.rwa_market_html)
            return

        if path == "/app/issuer":
            self._send_html(self.rwa_html)
            return

        if path == "/app/operator":
            self._send_html(self.ui_html)
            return

        if path == "/app/community":
            self._send_html(self.community_html)
            return

        if path == "/api":
            address = params.get("address", "").strip() if "params" in dir() else ""
            parsed = parse.urlparse(self.path)
            qs = parse.parse_qs(parsed.query)
            address = qs.get("address", [""])[0].strip()
            with self.node.lock:
                chain = self.node.public_chain
                balance_index = dict(chain.balance_index)
                height = len(chain.chain)
                circulating = round(sum(balance_index.values()), 8)
                treasury = round(chain.treasury_balance, 8)
                total_supply = round(circulating + treasury, 8)
            if address:
                bal = round(balance_index.get(address, 0.0), 8)
                # find first tx where this address appears to determine account creation block
                created_at_block = None
                tx_count = 0
                for blk in chain.chain:
                    for tx in blk.transactions:
                        if tx.get("sender") == address or tx.get("recipient") == address or tx.get("miner") == address:
                            if created_at_block is None:
                                created_at_block = blk.index
                            tx_count += 1
                self._send_json({
                    "ok": True,
                    "address": address,
                    "balance": bal,
                    "token": "NOVA",
                    "exists": address in balance_index,
                    "created_at_block": created_at_block,
                    "tx_count": tx_count,
                })
            else:
                self._send_json({
                    "ok": True,
                    "network": "Nova Network",
                    "chain_id": 149,
                    "token": "NOVA",
                    "block_height": height,
                    "total_supply": total_supply,
                    "circulating": circulating,
                    "treasury": treasury,
                    "total_accounts": len(balance_index),
                    "usage": {
                        "account_lookup": "GET /api?address=W<address>",
                        "balance": "GET /public/balance?address=W<address>",
                        "transactions": "GET /scan/address?address=W<address>",
                    },
                })
            return

        if path == "/":
            self._send_json({
                "name": "Nova Blockchain API",
                "network": "Nova Network",
                "chain_id": 149,
                "token": "NOVA",
                "block_time_seconds": 5,
                "docs": "https://explorer.flowpe.io/explorer",
                "endpoints": {
                    "chain": {
                        "GET /health": "Node health check",
                        "GET /chain/info": "Chain + token metadata",
                        "GET /scan/summary": "Current height and tx count",
                        "GET /status": "Full node status",
                    },
                    "balances": {
                        "GET /public/balance?address=W...": "NOVA balance for address",
                        "GET /scan/address?address=W...": "Full address history",
                        "GET /public/supply": "Total supply, circulating, treasury",
                    },
                    "transactions": {
                        "POST /public/tx": "Submit signed transaction",
                        "GET /scan/tx?id=<hash>": "Transaction detail",
                        "GET /scan/transactions?chain=public&page=1": "Transaction list",
                        "GET /public/mempool": "Pending transactions",
                    },
                    "blocks": {
                        "GET /scan/blocks?chain=public&page=1": "Block list",
                        "GET /scan/block?chain=public&index=N": "Block by index",
                        "GET /scan/block?chain=public&hash=<hash>": "Block by hash",
                    },
                    "validators": {
                        "GET /public/validator/stats": "Blocks mined, earnings, uptime",
                        "GET /validator/candidates": "Nomination pool",
                        "GET /public/consensus": "Validator set + rotation",
                        "GET /public/finality": "Finality status",
                    },
                    "treasury": {
                        "GET /treasury": "Treasury balance and fee config",
                    },
                    "prices": {
                        "GET /public/prices": "All token prices",
                        "GET /public/price?symbol=NOVA": "Single token price",
                        "GET /scan/prices/history?symbol=NOVA": "Price history",
                    },
                    "zk_proofs": {
                        "GET /public/zk/circuits": "Registered ZK circuits",
                        "GET /public/zk/proofs?address=W...": "ZK proof log",
                    },
                    "search": {
                        "GET /scan/search?q=<hash|address|block>": "Universal search",
                    },
                    "events": {
                        "GET /stream/events": "Live SSE event stream (new blocks + txs)",
                    },
                    "ui": {
                        "GET /explorer": "Block explorer UI",
                        "GET /scanner": "Transaction scanner UI",
                        "GET /community": "Community hub",
                    },
                    "evm_rpc": {
                        "POST / (port 8545)": "EVM JSON-RPC (MetaMask compatible, chain_id=149)",
                    },
                },
            })
            return

        if path == "/ui":
            self._send_html(self.ui_html)
            return

        if path == "/explorer":
            self._send_html(self.explorer_html)
            return

        if path == "/scanner":
            self._send_html(self.scanner_html)
            return

        if path == "/passport":
            self._send_html(self.passport_html)
            return

        if path == "/start":
            self._send_html(self.start_html)
            return

        if path == "/rwa":
            self._send_html(self.rwa_html)
            return

        if path == "/rwa-market":
            self._send_html(self.rwa_market_html)
            return

        if path == "/rwa-dashboard":
            self._send_html(self.rwa_market_html)
            return

        if path == "/community":
            self._send_html(self.community_html)
            return

        if path == "/ui/wallets":
            self._send_json({"wallets": self.node.list_wallets()})
            return

        if path == "/audit/wallets":
            require_nonlocal = self._as_bool(query.get("require_nonlocal", ["false"])[0], False)
            require_no_private_key = self._as_bool(query.get("require_no_private_key", ["false"])[0], False)
            with self.node.lock:
                out = self.node.wallet_security_audit(
                    require_nonlocal=require_nonlocal,
                    require_no_private_key=require_no_private_key,
                )
            self._send_json(out)
            return

        if path == "/audit/security":
            wallet_audit = self.node.wallet_security_audit(
                require_nonlocal=self.node.require_hsm_signers,
                require_no_private_key=True,
            )
            out = {
                "ok": True,
                "security": {
                    "jwt_enabled": bool(self.jwt_secret),
                    "jwt_required": self.jwt_required,
                    "tls_enabled": self.base_url.startswith("https://"),
                    "strict_public_signatures": self.node.public_chain.strict_signature_validation,
                    "public_mempool_ttl_seconds": self.node.public_chain.mempool_tx_ttl_seconds,
                    "public_mempool_max_transactions": self.node.public_chain.mempool_max_transactions,
                    "require_hsm_signers": self.node.require_hsm_signers,
                    "rate_limit_default_per_minute": self.rate_limit_per_minute,
                    "rate_limit_tiers": dict(self.rate_limit_tiers),
                },
                "wallet_audit": wallet_audit,
                "peer_health": self.node.peer_health_snapshot(),
            }
            self._send_json(out)
            return

        if path == "/status":
            gov = self.node.private_chain.list_governance()
            open_count = sum(1 for p in gov["proposals"] if not p.get("executed"))
            with self.node.lock:
                self.node.public_chain.prune_mempool()
                mempool_policy = self.node.public_chain.mempool_policy()
            payload = {
                "public_height": len(self.node.public_chain.chain) - 1,
                "private_height": len(self.node.private_chain.chain) - 1,
                "public_pending": len(self.node.public_chain.pending_transactions),
                "private_pending": len(self.node.private_chain.pending_transactions),
                "public_mempool": mempool_policy,
                "private_pending_blocks": len(self.node.private_chain.pending_blocks),
                "governance_open": open_count,
                "public_valid": self.node.public_chain.is_valid(),
                "private_valid": self.node.private_chain.is_valid(),
                "peers": sorted(self.node.peers),
                "peer_health": self.node.peer_health_snapshot(),
                "security": {
                    "jwt_enabled": bool(self.jwt_secret),
                    "jwt_required": self.jwt_required,
                    "tls": self.base_url.startswith("https://"),
                },
                "uptime_seconds": max(0, int(time.time() - self.node.started_at)),
                "public_consensus": self.node.public_chain.consensus,
                "public_validators": sorted(self.node.public_chain.validators),
                "auto_mine": self.node.auto_mine_status(),
                "chain_info": self._current_chain_info(),
            }
            self._send_json(payload)
            return

        if path == "/chain/info":
            self._send_json(self._current_chain_info())
            return

        if path == "/community/overview":
            self._send_json(self._community_overview_payload())
            return

        if path == "/community/leaderboard":
            board_type = query.get("type", ["validators"])[0].strip()
            limit = _safe_int(query.get("limit", ["20"])[0], default=20, minimum=1, maximum=200)
            self._send_json(self._community_leaderboard_payload(board_type=board_type, limit=limit))
            return

        if path == "/community/roadmap":
            self._send_json(self._community_roadmap_payload())
            return

        if path == "/events":
            since_seq = _safe_int(query.get("since", ["0"])[0], default=0, minimum=0, maximum=10**12)
            limit = _safe_int(query.get("limit", ["200"])[0], default=200, minimum=1, maximum=2000)
            type_filter = query.get("type", [""])[0].strip()
            out = self.node.list_events_since(since_seq=since_seq, limit=limit, type_filter=type_filter)
            self._send_json(out)
            return

        if path == "/stream/events":
            since_seq = _safe_int(query.get("since", ["0"])[0], default=0, minimum=0, maximum=10**12)
            type_filter = query.get("type", [""])[0].strip()
            timeout_seconds = float(query.get("timeout", ["25"])[0])
            try:
                self._send_event_stream(since_seq=since_seq, type_filter=type_filter, timeout_seconds=timeout_seconds)
            except Exception:
                return
            return

        if path == "/network/peers":
            self._send_json({"peers": sorted(self.node.peers)})
            return

        if path == "/network/health":
            self._send_json(self.node.peer_health_snapshot())
            return

        if path == "/metrics":
            gov = self.node.private_chain.list_governance()
            open_count = sum(1 for p in gov["proposals"] if not p.get("executed"))
            auto = self.node.auto_mine_status()
            with self.node.lock:
                self.node.public_chain.prune_mempool()
                mempool = self.node.public_chain.mempool_policy()
            prune_stats = mempool.get("prune_stats", {})
            lines = [
                "# HELP jain_public_height Current public chain tip height.",
                "# TYPE jain_public_height gauge",
                f"jain_public_height {len(self.node.public_chain.chain) - 1}",
                "# HELP jain_private_height Current private chain tip height.",
                "# TYPE jain_private_height gauge",
                f"jain_private_height {len(self.node.private_chain.chain) - 1}",
                "# HELP jain_public_finalized_height Current finalized public block height.",
                "# TYPE jain_public_finalized_height gauge",
                f"jain_public_finalized_height {self.node.public_chain.latest_finalized_height()}",
                "# HELP jain_public_pending_tx Number of pending public transactions.",
                "# TYPE jain_public_pending_tx gauge",
                f"jain_public_pending_tx {len(self.node.public_chain.pending_transactions)}",
                "# HELP jain_public_mempool_ttl_seconds Pending transaction TTL in seconds.",
                "# TYPE jain_public_mempool_ttl_seconds gauge",
                f"jain_public_mempool_ttl_seconds {float(mempool.get('tx_ttl_seconds', 0.0))}",
                "# HELP jain_public_mempool_max_transactions Maximum configured mempool size.",
                "# TYPE jain_public_mempool_max_transactions gauge",
                f"jain_public_mempool_max_transactions {int(mempool.get('max_transactions', 0))}",
                "# HELP jain_public_mempool_expired_total Cumulative mempool tx expired by TTL.",
                "# TYPE jain_public_mempool_expired_total counter",
                f"jain_public_mempool_expired_total {float(prune_stats.get('expired_total', 0.0))}",
                "# HELP jain_public_mempool_evicted_total Cumulative mempool tx evicted by size cap.",
                "# TYPE jain_public_mempool_evicted_total counter",
                f"jain_public_mempool_evicted_total {float(prune_stats.get('evicted_total', 0.0))}",
                "# HELP jain_public_pow_parallel_workers Configured parallel worker count for PoW nonce search.",
                "# TYPE jain_public_pow_parallel_workers gauge",
                f"jain_public_pow_parallel_workers {int(self.node.public_chain.pow_parallel_workers)}",
                "# HELP jain_public_pow_nonce_chunk_size Nonce attempts per worker batch in parallel PoW mode.",
                "# TYPE jain_public_pow_nonce_chunk_size gauge",
                f"jain_public_pow_nonce_chunk_size {int(self.node.public_chain.pow_nonce_chunk_size)}",
                "# HELP jain_private_pending_tx Number of pending private transactions.",
                "# TYPE jain_private_pending_tx gauge",
                f"jain_private_pending_tx {len(self.node.private_chain.pending_transactions)}",
                "# HELP jain_private_pending_blocks Number of pending private blocks.",
                "# TYPE jain_private_pending_blocks gauge",
                f"jain_private_pending_blocks {len(self.node.private_chain.pending_blocks)}",
                "# HELP jain_governance_open Number of governance proposals not executed.",
                "# TYPE jain_governance_open gauge",
                f"jain_governance_open {open_count}",
                "# HELP jain_peers Number of configured peers.",
                "# TYPE jain_peers gauge",
                f"jain_peers {len(self.node.peers)}",
                "# HELP jain_public_validators Number of active public validators.",
                "# TYPE jain_public_validators gauge",
                f"jain_public_validators {len(self.node.public_chain.validators)}",
                "# HELP jain_ai_models Number of registered AI models on private chain.",
                "# TYPE jain_ai_models gauge",
                f"jain_ai_models {len(self.node.private_chain.model_registry)}",
                "# HELP jain_ai_jobs Number of known AI jobs on private chain.",
                "# TYPE jain_ai_jobs gauge",
                f"jain_ai_jobs {len(self.node.private_chain.ai_jobs)}",
                "# HELP jain_ai_provider_total_staked Total staked amount by AI providers.",
                "# TYPE jain_ai_provider_total_staked gauge",
                f"jain_ai_provider_total_staked {float(self.node.public_chain.get_provider_stakes().get('total_staked', 0.0))}",
                "# HELP jain_public_auto_mine_enabled Whether public auto-mine is enabled (1/0).",
                "# TYPE jain_public_auto_mine_enabled gauge",
                f"jain_public_auto_mine_enabled {1 if auto['enabled'] else 0}",
                "# HELP jain_public_auto_mine_interval_seconds Target auto-mine interval in seconds.",
                "# TYPE jain_public_auto_mine_interval_seconds gauge",
                f"jain_public_auto_mine_interval_seconds {float(auto['interval_seconds'])}",
                "# HELP jain_public_auto_mine_allow_empty_blocks Whether auto-mine allows empty blocks (1/0).",
                "# TYPE jain_public_auto_mine_allow_empty_blocks gauge",
                f"jain_public_auto_mine_allow_empty_blocks {1 if auto['allow_empty_blocks'] else 0}",
                "# HELP jain_public_auto_mine_last_mined_at Unix timestamp of last auto-mined block.",
                "# TYPE jain_public_auto_mine_last_mined_at gauge",
                f"jain_public_auto_mine_last_mined_at {float(auto['last_mined_at'])}",
            ]
            self._send_text("\n".join(lines) + "\n")
            return

        if path == "/slo":
            with self.node.lock:
                self.node.public_chain.prune_mempool()
                perf = self.node.public_chain.performance_summary(window_blocks=60)
            auto = self.node.auto_mine_status()
            self._send_json(
                {
                    "ok": True,
                    "public": perf,
                    "auto_mine": auto,
                    "targets": {
                        "target_block_time_seconds": self.node.public_chain.block_time_target_seconds,
                        "max_finality_lag_blocks": self.node.public_chain.finality_confirmations + 2,
                    },
                    "status": {
                        "block_time_ok": perf["avg_block_time_seconds"] <= (self.node.public_chain.block_time_target_seconds * 1.5)
                        if perf["avg_block_time_seconds"] > 0
                        else True,
                        "finality_lag_ok": perf["finality_lag_blocks"] <= (self.node.public_chain.finality_confirmations + 2),
                        "auto_mine_ok": bool(auto.get("enabled", False)),
                    },
                }
            )
            return

        if path == "/public/chain":
            self._send_json(self.node.public_chain.export_state())
            return

        if path == "/public/balance":
            address = query.get("address", [""])[0]
            self._send_json({"address": address, "balance": self.node.public_chain.get_balance(address)})
            return

        if path == "/public/prices":
            self._send_json(self.node.public_chain.get_latest_price())
            return

        if path == "/public/mempool":
            limit = _safe_int(query.get("limit", ["100"])[0], default=100, minimum=1, maximum=500)
            with self.node.lock:
                self.node.public_chain.prune_mempool()
                pending = list(self.node.public_chain.pending_transactions)
                mempool_policy = self.node.public_chain.mempool_policy()
            self._send_json(
                {
                    "pending_count": len(pending),
                    "limit": limit,
                    "truncated": len(pending) > limit,
                    "policy": mempool_policy,
                    "pending_transactions": pending[:limit],
                }
            )
            return

        if path == "/public/price":
            symbol = query.get("symbol", [""])[0]
            self._send_json(self.node.public_chain.get_latest_price(symbol))
            return

        if path == "/public/consensus":
            self._send_json(
                {
                    "consensus": self.node.public_chain.consensus,
                    "difficulty": self.node.public_chain.difficulty,
                    "mining_reward": self.node.public_chain.mining_reward,
                    "validators": sorted(self.node.public_chain.validators),
                    "validator_rotation": self.node.public_chain.validator_rotation_enabled,
                    "next_expected_validator": self.node.public_chain.expected_next_validator(),
                    "finality_confirmations": self.node.public_chain.finality_confirmations,
                    "latest_finalized_height": self.node.public_chain.latest_finalized_height(),
                    "checkpoint_interval": self.node.public_chain.checkpoint_interval,
                    "mempool_policy": self.node.public_chain.mempool_policy(),
                }
            )
            return

        if path == "/public/performance":
            window_blocks = _safe_int(query.get("window_blocks", ["60"])[0], default=60, minimum=1, maximum=5000)
            with self.node.lock:
                self.node.public_chain.prune_mempool()
                perf = self.node.public_chain.performance_summary(window_blocks=window_blocks)
            self._send_json(perf)
            return

        if path == "/public/finality":
            self._send_json(
                {
                    "finality_confirmations": self.node.public_chain.finality_confirmations,
                    "latest_finalized_height": self.node.public_chain.latest_finalized_height(),
                    "checkpoint_interval": self.node.public_chain.checkpoint_interval,
                    "checkpoints": self.node.public_chain.checkpoint_summary(limit=20),
                }
            )
            return

        if path == "/public/ai/stakes":
            self._send_json(self.node.public_chain.get_provider_stakes())
            return

        if path == "/public/validator/candidates":
            with self.node.lock:
                candidates_raw = dict(self.node.public_chain.validator_candidates)
                active = sorted(self.node.public_chain.validators)
            candidates = []
            for addr, data in sorted(candidates_raw.items(), key=lambda x: (-x[1].get("stake", 0), -x[1].get("votes", 0))):
                candidates.append({
                    "address": addr,
                    "votes": data.get("votes", 0),
                    "stake": float(data.get("stake", 0.0)),
                    "nominated_at": data.get("nominated_at", 0),
                    "block": data.get("block", 0),
                    "stake_locked_at_block": data.get("stake_locked_at_block", 0),
                    "is_validator": addr in self.node.public_chain.validators,
                })
            self._send_json({
                "candidates": candidates,
                "active_validators": active,
                "min_stake": 500.0,
                "vote_threshold": 3,
                "unbonding_blocks": 100,
                "total_staked": sum(c["stake"] for c in candidates),
            })
            return

        if path == "/public/agent/passport":
            parsed = parse.urlparse(self.path)
            qs = parse.parse_qs(parsed.query)
            raw_address = qs.get("address", [""])[0].strip()
            raw_agent_id = qs.get("agent_id", [""])[0].strip()
            if not raw_address and not raw_agent_id:
                self._send_json({"error": "address or agent_id required"}, HTTPStatus.BAD_REQUEST)
                return
            verbose = qs.get("verbose", ["false"])[0].lower() == "true"
            with self.node.lock:
                # Resolve agent_id → owner wallet address when address not provided
                agent_reg = {}
                if raw_agent_id and not raw_address:
                    for ag in self.node.public_chain.agent_registry.values():
                        if ag.get("agent_id") == raw_agent_id:
                            raw_address = ag.get("owner") or ag.get("wallet_address", "")
                            agent_reg = ag
                            break
                address = raw_address
                not_found = not address
                if not not_found:
                    if not agent_reg:
                        for ag in self.node.public_chain.agent_registry.values():
                            if ag.get("owner") == address or ag.get("wallet_address") == address:
                                agent_reg = ag
                                break
                    rep = dict(self.node.public_chain.reputation_index.get(address, {}))
                    log_index = self.node.public_chain.activity_log_index
                    challenge_index = self.node.public_chain.challenge_index
                    collab_index = self.node.public_chain.collab_index
                    agent_logs = [v for v in log_index.values() if v.get("agent") == address]
            if not_found:
                self._send_json({"error": "agent_id not found"}, HTTPStatus.NOT_FOUND)
                return
            platforms = list({l.get("platform") for l in agent_logs if l.get("platform")})
            response = {
                "ok": True,
                "address": address,
                "agent_id": agent_reg.get("agent_id", ""),
                "agent_name": agent_reg.get("name", ""),
                "trust_score": rep.get("trust_score", 0.0),
                "trust_tier": rep.get("trust_tier", "unverified"),
                "total_logs": rep.get("activity_logs", 0),
                "attested_logs": rep.get("attested_logs", 0),
                "stake_backed_logs": rep.get("stake_backed_logs", 0),
                "evidence_backed_logs": rep.get("evidence_backed_logs", 0),
                "challenged_logs": rep.get("challenged_unanswered_logs", 0),
                "slashed_logs": rep.get("slashed_logs", 0),
                "platforms": platforms,
                "reputation_score": rep.get("score", 0.0),
                "reputation_level": rep.get("level", "Member"),
                "badges": rep.get("badges", []),
                "last_active": rep.get("last_active", 0.0),
                "collab_sessions": rep.get("collab_sessions", 0),
            }
            if verbose:
                log_ids = {l.get("log_id") or l.get("id") for l in agent_logs}
                response["logs_detail"] = agent_logs
                response["challenges_detail"] = [
                    v for v in challenge_index.values()
                    if v.get("log_id") in log_ids
                ]
                total = len(agent_logs)
                with_evidence = sum(1 for l in agent_logs if l.get("evidence_url"))
                response["evidence_coverage"] = round(with_evidence / total, 3) if total else 0.0
                # Collaboration sessions this agent is part of
                response["collab_sessions_detail"] = [
                    v for v in collab_index.values() if address in v.get("agents", [])
                ]
                response["collab_sessions"] = len(response["collab_sessions_detail"])
            self._send_json(response)
            return

        if path == "/public/agent/leaderboard":
            parsed = parse.urlparse(self.path)
            qs = parse.parse_qs(parsed.query)
            tag = qs.get("tag", [""])[0].strip().lower()
            platform = qs.get("platform", [""])[0].strip().lower()
            limit = min(int(qs.get("limit", ["20"])[0]), 100)
            with self.node.lock:
                rep_index = dict(self.node.public_chain.reputation_index)
                log_index = dict(self.node.public_chain.activity_log_index)
                agent_reg = dict(self.node.public_chain.agent_registry)

            # Build per-agent stats
            agents = []
            addr_set = set(rep_index.keys())
            for addr in addr_set:
                r = rep_index[addr]
                if r.get("activity_logs", 0) == 0:
                    continue
                agent_logs = [v for v in log_index.values() if v.get("agent") == addr]
                # filter by tag/platform if requested
                if tag:
                    agent_logs = [l for l in agent_logs if tag in [t.lower() for t in l.get("tags", [])]]
                if platform:
                    agent_logs = [l for l in agent_logs if l.get("platform", "").lower() == platform]
                if (tag or platform) and not agent_logs:
                    continue
                agent_info = next((a for a in agent_reg.values()
                                   if a.get("owner") == addr or a.get("wallet_address") == addr), {})
                agents.append({
                    "address": addr,
                    "agent_id": agent_info.get("agent_id", ""),
                    "name": agent_info.get("name", ""),
                    "trust_score": r.get("trust_score", 0.0),
                    "trust_tier": r.get("trust_tier", "unverified"),
                    "total_logs": len(agent_logs) if (tag or platform) else r.get("activity_logs", 0),
                    "attested_logs": r.get("attested_logs", 0),
                    "stake_backed_logs": r.get("stake_backed_logs", 0),
                    "evidence_backed_logs": r.get("evidence_backed_logs", 0),
                    "challenged_logs": r.get("challenged_unanswered_logs", 0),
                    "slashed_logs": r.get("slashed_logs", 0),
                    "platforms": list({l.get("platform") for l in log_index.values()
                                       if l.get("agent") == addr and l.get("platform")}),
                    "tags": list({t for l in log_index.values()
                                  if l.get("agent") == addr for t in l.get("tags", [])}),
                    "last_active": r.get("last_active", 0.0),
                })
            agents.sort(key=lambda a: a["trust_score"], reverse=True)
            self._send_json({
                "leaderboard": agents[:limit],
                "total": len(agents),
                "filters": {"tag": tag, "platform": platform},
            })
            return

        if path == "/public/agent/discover":
            parsed = parse.urlparse(self.path)
            qs = parse.parse_qs(parsed.query)
            raw_tags = qs.get("tags", [""])[0].strip()
            filter_tags = [t.strip().lower() for t in raw_tags.split(",") if t.strip()] if raw_tags else []
            try:
                min_score = float(qs.get("min_score", ["0.0"])[0])
            except (ValueError, TypeError):
                min_score = 0.0
            min_tier = qs.get("min_tier", [""])[0].strip().lower()
            filter_platform = qs.get("platform", [""])[0].strip().lower()
            try:
                limit = min(int(qs.get("limit", ["20"])[0]), 100)
            except (ValueError, TypeError):
                limit = 20
            raw_exclude = qs.get("exclude", [""])[0].strip()
            exclude_set = {a.strip() for a in raw_exclude.split(",") if a.strip()} if raw_exclude else set()
            TIER_ORDER = ["unverified", "self-reported", "attested", "evidence-attested", "stake-backed"]
            if min_tier in TIER_ORDER:
                allowed_tiers = set(TIER_ORDER[TIER_ORDER.index(min_tier):])
            else:
                allowed_tiers = None
            with self.node.lock:
                rep_index = dict(self.node.public_chain.reputation_index)
                log_index = dict(self.node.public_chain.activity_log_index)
                agent_reg = dict(self.node.public_chain.agent_registry)
            agents = []
            for addr, r in rep_index.items():
                if addr in exclude_set:
                    continue
                if r.get("activity_logs", 0) == 0:
                    continue
                tier = r.get("trust_tier", "unverified")
                if tier in ("disputed", "slashed"):
                    continue
                if allowed_tiers is not None and tier not in allowed_tiers:
                    continue
                if r.get("trust_score", 0.0) < min_score:
                    continue
                agent_logs = [l for l in log_index.values() if l.get("agent") == addr]
                if filter_tags:
                    log_tag_sets = [{t.lower() for t in l.get("tags", [])} for l in agent_logs]
                    if not any(any(ft in ts for ft in filter_tags) for ts in log_tag_sets):
                        continue
                if filter_platform:
                    if not any(l.get("platform", "").lower() == filter_platform for l in agent_logs):
                        continue
                unique_tags = list({t for l in agent_logs for t in l.get("tags", [])})
                unique_platforms = list({l.get("platform") for l in agent_logs if l.get("platform")})
                collab_sessions = sum(
                    1 for l in agent_logs if str(l.get("external_ref", "")).startswith("collab:")
                )
                agent_info = next(
                    (a for a in agent_reg.values()
                     if a.get("owner") == addr or a.get("wallet_address") == addr),
                    {}
                )
                agents.append({
                    "address": addr,
                    "agent_id": agent_info.get("agent_id", ""),
                    "name": agent_info.get("name", ""),
                    "trust_score": r.get("trust_score", 0.0),
                    "trust_tier": tier,
                    "total_logs": r.get("activity_logs", 0),
                    "attested_logs": r.get("attested_logs", 0),
                    "evidence_backed_logs": r.get("evidence_backed_logs", 0),
                    "tags": unique_tags,
                    "platforms": unique_platforms,
                    "last_active": r.get("last_active", 0.0),
                    "collab_sessions": collab_sessions,
                })
            agents.sort(key=lambda a: a["trust_score"], reverse=True)
            self._send_json({
                "ok": True,
                "agents": agents[:limit],
                "total": len(agents),
                "filters": {
                    "tags": filter_tags,
                    "min_score": min_score,
                    "min_tier": min_tier,
                    "platform": filter_platform,
                    "limit": limit,
                    "exclude": list(exclude_set),
                },
            })
            return

        if path == "/public/agent/logs":
            parsed = parse.urlparse(self.path)
            qs = parse.parse_qs(parsed.query)
            address = qs.get("address", [""])[0].strip()
            platform = qs.get("platform", [""])[0].strip()
            action = qs.get("action_type", [""])[0].strip()
            limit = min(int(qs.get("limit", ["50"])[0]), 200)
            with self.node.lock:
                log_index = dict(self.node.public_chain.activity_log_index)
            logs = list(log_index.values())
            if address:
                logs = [l for l in logs if l.get("agent") == address]
            if platform:
                logs = [l for l in logs if l.get("platform") == platform]
            if action:
                logs = [l for l in logs if l.get("action_type") == action]
            logs.sort(key=lambda l: l.get("timestamp", 0), reverse=True)
            self._send_json({"logs": logs[:limit], "count": len(logs)})
            return

        if path == "/public/agent/rules":
            # Live chain-state rules. Every change requires M-of-N validator endorsement
            # via agent_param_propose + agent_param_endorse txs — no silent edits possible.
            with self.node.lock:
                params = dict(self.node.public_chain.agent_trust_params)
                history = list(self.node.public_chain.agent_trust_params_history)
                proposals = list(self.node.public_chain.agent_param_proposals.values())
            self._send_json({
                **params,
                "trust_tiers": [
                    "unverified", "self-reported", "attested",
                    "evidence-attested", "stake-backed", "disputed", "slashed"
                ],
                "challenge_min_stake": 0.0,
                "governance": {
                    "flow": "agent_param_propose → agent_param_endorse (M-of-N validators)",
                    "min_endorsements": params.get("param_update_min_endorsements", 2),
                    "open_proposals": [p for p in proposals if p.get("status") == "open"],
                },
                "archival_note": (
                    "Raw block txs are pruned after ~500 blocks. "
                    "activity_log_index and challenge_index are persisted indefinitely. "
                    "Use /public/agent/log?log_id= for permanent log lookup."
                ),
                "change_history": history,
            })
            return

        if path == "/public/agent/log":
            # Permanent log lookup by log_id — survives block pruning.
            parsed = parse.urlparse(self.path)
            qs = parse.parse_qs(parsed.query)
            log_id = qs.get("log_id", [""])[0].strip()
            if not log_id:
                self._send_json({"error": "log_id required"}, HTTPStatus.BAD_REQUEST)
                return
            with self.node.lock:
                log = self.node.public_chain.activity_log_index.get(log_id)
                if log:
                    log = dict(log)
            if not log:
                self._send_json({"error": "log not found"}, HTTPStatus.NOT_FOUND)
                return
            self._send_json({"ok": True, "log": log})
            return

        if path == "/public/validator/stats":
            # Per-validator performance: blocks mined, NOVA earned, uptime, last active
            with self.node.lock:
                active = sorted(self.node.public_chain.validators)
                rep = dict(self.node.public_chain.reputation_index)
                height = len(self.node.public_chain.chain) - 1
                candidates = dict(self.node.public_chain.validator_candidates)
            stats = []
            for addr in active:
                r = rep.get(addr, {})
                cand = candidates.get(addr, {})
                blocks_mined = r.get("blocks_mined", 0)
                uptime_pct = round((blocks_mined / max(height, 1)) * len(active) * 100, 2) if height > 0 else 0.0
                stats.append({
                    "address": addr,
                    "blocks_mined": blocks_mined,
                    "total_nova_earned": round(r.get("total_nova_earned", 0.0), 4),
                    "last_active": r.get("last_active", 0.0),
                    "validator_since": r.get("validator_since"),
                    "stake": float(cand.get("stake", 0.0)),
                    "reputation_score": round(r.get("score", 0.0), 2),
                    "reputation_level": r.get("level", "Member"),
                    "uptime_pct": min(uptime_pct, 100.0),
                    "badges": [b["id"] for b in r.get("badges", [])],
                })
            stats.sort(key=lambda x: -x["blocks_mined"])
            self._send_json({
                "validators": stats,
                "active_count": len(active),
                "chain_height": height,
                "block_reward_jito": self.node.public_chain.mining_reward,
                "treasury_fee_pct": self.node.public_chain.treasury_fee_pct,
                "net_reward_per_block": round(
                    self.node.public_chain.mining_reward * (1 - self.node.public_chain.treasury_fee_pct), 4
                ),
            })
            return

        if path == "/public/zk/circuits":
            with self.node.lock:
                circuits = dict(self.node.public_chain.zk_circuit_registry)
            result = []
            for cid, c in circuits.items():
                result.append({
                    "circuit_id": cid,
                    "description": c.get("description", ""),
                    "registrar": c.get("registrar", ""),
                    "registered_at_block": c.get("registered_at_block", 0),
                })
            self._send_json({"circuits": result, "count": len(result)})
            return

        if path == "/public/treasury":
            with self.node.lock:
                info = self.node.public_chain.get_treasury_info()
            self._send_json(info)
            return

        if path == "/public/supply":
            with self.node.lock:
                chain = self.node.public_chain
                circulating = round(sum(chain.balance_index.values()), 8)
                treasury = round(chain.treasury_balance, 8)
                total_supply = round(circulating + treasury, 8)
                blocks = len(chain.chain)
                reward = chain.mining_reward
            self._send_json({
                "total_supply": total_supply,
                "circulating": circulating,
                "treasury": treasury,
                "blocks_mined": blocks,
                "reward_per_block": reward,
                "token_symbol": "NOVA",
            })
            return

        if path == "/public/zk/proofs":
            addr = query.get("address", [""])[0]
            circuit = query.get("circuit_id", [""])[0]
            with self.node.lock:
                log = list(self.node.public_chain.zk_proof_log)
            if addr:
                log = [p for p in log if p.get("prover") == addr]
            if circuit:
                log = [p for p in log if p.get("circuit_id") == circuit]
            self._send_json({"proofs": log[-100:], "count": len(log)})
            return

        if path == "/identities":
            with self.node.lock:
                registry = dict(self.node.public_chain.identity_registry)
            self._send_json({"count": len(registry), "identities": list(registry.values())})
            return

        if path.startswith("/identity/handle/"):
            handle = path[len("/identity/handle/"):].strip("/").lower()
            if not handle:
                self._send_json({"error": "handle is required"}, HTTPStatus.BAD_REQUEST)
                return
            with self.node.lock:
                address = self.node.public_chain.handle_index.get(handle)
            if address is None:
                self._send_json({"error": f"Handle not found: {handle}"}, HTTPStatus.NOT_FOUND)
                return
            with self.node.lock:
                identity = self.node.public_chain.identity_registry.get(address, {})
            self._send_json({"handle": handle, "address": address, "identity": identity})
            return

        if path.startswith("/identity/"):
            address = path[len("/identity/"):].strip("/")
            if not address:
                self._send_json({"error": "address is required"}, HTTPStatus.BAD_REQUEST)
                return
            with self.node.lock:
                identity = self.node.public_chain.identity_registry.get(address)
            if identity is None:
                self._send_json({"error": f"Identity not found: {address}"}, HTTPStatus.NOT_FOUND)
                return
            self._send_json({"address": address, "identity": identity})
            return

        if path == "/agents":
            role_filter = query.get("role", [""])[0].strip()
            with self.node.lock:
                registry = dict(self.node.public_chain.agent_registry)
            rows = list(registry.values())
            if role_filter:
                rows = [r for r in rows if role_filter in r.get("capabilities", [])]
            self._send_json({"count": len(rows), "agents": rows})
            return

        if path.startswith("/agents/"):
            agent_id = path[len("/agents/"):].strip("/")
            if not agent_id:
                self._send_json({"error": "agent_id is required"}, HTTPStatus.BAD_REQUEST)
                return
            with self.node.lock:
                agent = self.node.public_chain.agent_registry.get(agent_id)
            if agent is None:
                self._send_json({"error": f"Agent not found: {agent_id}"}, HTTPStatus.NOT_FOUND)
                return
            self._send_json({"agent_id": agent_id, "agent": agent})
            return

        if path == "/reputation/leaderboard":
            limit = _safe_int(query.get("limit", ["20"])[0], default=20, minimum=1, maximum=200)
            with self.node.lock:
                rep = dict(self.node.public_chain.reputation_index)
            sorted_addrs = sorted(rep.keys(), key=lambda a: rep[a]["score"], reverse=True)[:limit]
            self._send_json({
                "leaderboard": [
                    {
                        "address": addr,
                        "score": rep[addr]["score"],
                        "level": rep[addr]["level"],
                        "badges": rep[addr]["badges"],
                        "blocks_mined": rep[addr].get("blocks_mined", 0),
                        "tasks_completed": rep[addr].get("tasks_completed", 0),
                        "governance_votes": rep[addr].get("governance_votes", 0),
                    }
                    for addr in sorted_addrs
                ]
            })
            return

        if path.startswith("/reputation/"):
            address = path[len("/reputation/"):].strip("/")
            if not address:
                self._send_json({"error": "address is required"}, HTTPStatus.BAD_REQUEST)
                return
            with self.node.lock:
                rep = self.node.public_chain.reputation_index.get(address)
            if not rep:
                self._send_json({"address": address, "score": 0.0, "level": "Member", "badges": [], "history": [], "blocks_mined": 0})
                return
            self._send_json({"address": address, **rep})
            return

        if path == "/tasks":
            status_filter = query.get("status", [""])[0].strip()
            owner_filter = query.get("owner", [""])[0].strip()
            agent_id_filter = query.get("agent_id", [""])[0].strip()
            with self.node.lock:
                tasks = list(self.node.public_chain.task_registry.values())
            if status_filter:
                tasks = [t for t in tasks if t.get("status") == status_filter]
            if owner_filter:
                tasks = [t for t in tasks if t.get("owner") == owner_filter]
            if agent_id_filter:
                tasks = [t for t in tasks if t.get("agent_id") == agent_id_filter]
            tasks_sorted = sorted(tasks, key=lambda t: t.get("created_at", 0), reverse=True)
            self._send_json({"count": len(tasks_sorted), "tasks": tasks_sorted})
            return

        if path.startswith("/tasks/"):
            task_id = path[len("/tasks/"):].strip("/")
            if not task_id:
                self._send_json({"error": "task_id is required"}, HTTPStatus.BAD_REQUEST)
                return
            with self.node.lock:
                task = self.node.public_chain.task_registry.get(task_id)
            if not task:
                self._send_json({"error": "Task not found"}, HTTPStatus.NOT_FOUND)
                return
            self._send_json(task)
            return

        if path == "/governance/proposals":
            status_filter = query.get("status", [""])[0].strip()
            with self.node.lock:
                proposals = list(self.node.public_chain.governance_proposals.values())
            if status_filter:
                proposals = [p for p in proposals if p.get("status") == status_filter]
            proposals_sorted = sorted(proposals, key=lambda p: p.get("created_at", 0), reverse=True)
            self._send_json({"count": len(proposals_sorted), "proposals": proposals_sorted})
            return

        if path.startswith("/governance/proposals/"):
            proposal_id = path[len("/governance/proposals/"):].strip("/")
            if not proposal_id:
                self._send_json({"error": "proposal_id is required"}, HTTPStatus.BAD_REQUEST)
                return
            with self.node.lock:
                prop = self.node.public_chain.governance_proposals.get(proposal_id)
            if not prop:
                self._send_json({"error": "Proposal not found"}, HTTPStatus.NOT_FOUND)
                return
            self._send_json(prop)
            return

        if path == "/activity/feed":
            limit = _safe_int(query.get("limit", ["50"])[0], default=50, minimum=1, maximum=500)
            with self.node.lock:
                feed = list(reversed(self.node.public_chain.activity_feed[-limit:]))
            self._send_json({"count": len(feed), "feed": feed})
            return

        if path == "/public/faucet/status":
            self._send_json(self.node.faucet_status())
            return

        if path == "/public/auto-mine":
            self._send_json(self.node.auto_mine_status())
            return

        if path == "/scan/summary":
            can_view_private = self._can_view_private_scanner(query)
            public_txs = sum(len(block.transactions) for block in self.node.public_chain.chain)
            private_txs = sum(len(block.transactions) for block in self.node.private_chain.chain) if can_view_private else 0
            self._send_json(
                {
                    "public_height": len(self.node.public_chain.chain) - 1,
                    "private_height": (len(self.node.private_chain.chain) - 1) if can_view_private else None,
                    "public_tx_count": public_txs,
                    "private_tx_count": private_txs,
                    "pending_public_tx": len(self.node.public_chain.pending_transactions),
                    "pending_private_tx": len(self.node.private_chain.pending_transactions) if can_view_private else 0,
                    "pending_private_blocks": len(self.node.private_chain.pending_blocks) if can_view_private else 0,
                    "next_expected_validator": self.node.public_chain.expected_next_validator(),
                    "latest_finalized_height": self.node.public_chain.latest_finalized_height(),
                    "finality_confirmations": self.node.public_chain.finality_confirmations,
                    "checkpoint_interval": self.node.public_chain.checkpoint_interval,
                    "checkpoint_count": len(self.node.public_chain.checkpoint_summary(limit=1000)),
                    "ai_models": len(self.node.private_chain.model_registry) if can_view_private else 0,
                    "ai_jobs": len(self.node.private_chain.ai_jobs) if can_view_private else 0,
                    "ai_provider_stakes": self.node.public_chain.get_provider_stakes(),
                    "auto_mine": self.node.auto_mine_status(),
                    "latest_prices": self.node.public_chain.get_latest_price(),
                    "private_visibility": "portal-session" if can_view_private else "hidden",
                }
            )
            return

        if path == "/scan/blocks":
            can_view_private = self._can_view_private_scanner(query)
            chain_name = query.get("chain", ["public"])[0].strip().lower()
            page = _safe_int(query.get("page", ["1"])[0], default=1, minimum=1, maximum=100000)
            page_size = _safe_int(query.get("page_size", ["20"])[0], default=20, minimum=1, maximum=100)
            if chain_name not in {"public", "private"}:
                self._send_json({"error": "chain must be 'public' or 'private'"}, HTTPStatus.BAD_REQUEST)
                return
            if chain_name == "private" and not can_view_private:
                self._send_json(
                    {"error": "Private scanner data requires portal session (X-Portal-Session)."},
                    HTTPStatus.FORBIDDEN,
                )
                return

            with self.node.lock:
                source = self.node.public_chain.chain if chain_name == "public" else self.node.private_chain.chain
                blocks = list(reversed(source))
            total = len(blocks)
            total_pages = (total + page_size - 1) // page_size if total else 0
            start = (page - 1) * page_size
            page_items = blocks[start : start + page_size]
            self._send_json(
                {
                    "chain": chain_name,
                    "page": page,
                    "page_size": page_size,
                    "total": total,
                    "total_pages": total_pages,
                    "blocks": [_block_summary(block) for block in page_items],
                }
            )
            return

        if path == "/scan/block":
            can_view_private = self._can_view_private_scanner(query)
            chain_name = query.get("chain", ["public"])[0].strip().lower()
            index_raw = query.get("index", [""])[0].strip()
            block_hash = query.get("hash", [""])[0].strip()
            if chain_name not in {"public", "private"}:
                self._send_json({"error": "chain must be 'public' or 'private'"}, HTTPStatus.BAD_REQUEST)
                return
            if chain_name == "private" and not can_view_private:
                self._send_json(
                    {"error": "Private scanner data requires portal session (X-Portal-Session)."},
                    HTTPStatus.FORBIDDEN,
                )
                return
            if not index_raw and not block_hash:
                self._send_json({"error": "Provide either index or hash"}, HTTPStatus.BAD_REQUEST)
                return

            with self.node.lock:
                source = self.node.public_chain.chain if chain_name == "public" else self.node.private_chain.chain
                found = None
                if index_raw:
                    wanted = _safe_int(index_raw, default=-1, minimum=-1, maximum=10**9)
                    for block in source:
                        if block.index == wanted:
                            found = block
                            break
                else:
                    for block in source:
                        if block.hash == block_hash:
                            found = block
                            break
            if not found:
                self._send_json({"error": "Block not found"}, HTTPStatus.NOT_FOUND)
                return
            self._send_json({"chain": chain_name, "block": found.to_dict()})
            return

        if path == "/scan/transactions":
            can_view_private = self._can_view_private_scanner(query)
            chain_name = query.get("chain", ["all"])[0].strip().lower()
            page = _safe_int(query.get("page", ["1"])[0], default=1, minimum=1, maximum=100000)
            page_size = _safe_int(query.get("page_size", ["25"])[0], default=25, minimum=1, maximum=200)
            address_filter = query.get("address", [""])[0].strip()
            type_filter = query.get("type", [""])[0].strip().lower()
            symbol_filter = query.get("symbol", [""])[0].strip().upper()
            if chain_name not in {"all", "public", "private"}:
                self._send_json({"error": "chain must be all/public/private"}, HTTPStatus.BAD_REQUEST)
                return
            if chain_name == "private" and not can_view_private:
                self._send_json(
                    {"error": "Private scanner data requires portal session (X-Portal-Session)."},
                    HTTPStatus.FORBIDDEN,
                )
                return

            rows: list[Dict[str, Any]] = []
            with self.node.lock:
                if chain_name in {"all", "public"}:
                    for block in self.node.public_chain.chain:
                        for tx_index, tx in enumerate(block.transactions):
                            rows.append(_tx_summary("public", block, tx_index, tx))
                if chain_name in {"all", "private"} and can_view_private:
                    for block in self.node.private_chain.chain:
                        for tx_index, tx in enumerate(block.transactions):
                            rows.append(_tx_summary("private", block, tx_index, tx))

            if address_filter:
                rows = [row for row in rows if address_filter in _tx_addresses(row)]
            if type_filter:
                rows = [row for row in rows if str(row.get("type", "")).lower() == type_filter]
            if symbol_filter:
                rows = [row for row in rows if str(row.get("symbol", "")).upper() == symbol_filter]

            rows.sort(key=lambda r: (float(r.get("timestamp", 0.0)), int(r.get("block_index", 0))), reverse=True)
            total = len(rows)
            total_pages = (total + page_size - 1) // page_size if total else 0
            start = (page - 1) * page_size
            page_rows = rows[start : start + page_size]
            self._send_json(
                {
                    "chain": chain_name,
                    "page": page,
                    "page_size": page_size,
                    "total": total,
                    "total_pages": total_pages,
                    "transactions": page_rows,
                }
            )
            return

        if path == "/scan/tx":
            tx_id = query.get("id", [""])[0].strip()
            can_view_private = self._can_view_private_scanner(query)
            if not tx_id:
                self._send_json({"error": "id query parameter is required"}, HTTPStatus.BAD_REQUEST)
                return
            wanted = tx_id.lower()

            with self.node.lock:
                pub_tip = len(self.node.public_chain.chain) - 1
                priv_tip = len(self.node.private_chain.chain) - 1
                chains_to_search = [("public", self.node.public_chain.chain, pub_tip)]
                if can_view_private:
                    chains_to_search.append(("private", self.node.private_chain.chain, priv_tip))
                for chain_name, blocks, tip in chains_to_search:
                    for block in blocks:
                        for tx_index, tx in enumerate(block.transactions):
                            tx_raw_id = str(tx.get("id", ""))
                            if tx_raw_id.lower() == wanted:
                                self._send_json(
                                    {
                                        "found": True,
                                        "chain": chain_name,
                                        "tx": tx,
                                        "location": {
                                            "block_index": block.index,
                                            "block_hash": block.hash,
                                            "tx_index": tx_index,
                                            "confirmations": tip - block.index + 1,
                                        },
                                    }
                                )
                                return
                for tx_index, tx in enumerate(self.node.public_chain.pending_transactions):
                    tx_raw_id = str(tx.get("id", ""))
                    if tx_raw_id.lower() == wanted:
                        self._send_json(
                            {
                                "found": True,
                                "chain": "public",
                                "tx": tx,
                                "location": {
                                    "block_index": None,
                                    "block_hash": None,
                                    "tx_index": tx_index,
                                    "confirmations": 0,
                                    "pending": True,
                                },
                            }
                        )
                        return
                if can_view_private:
                    for tx_index, tx in enumerate(self.node.private_chain.pending_transactions):
                        tx_raw_id = str(tx.get("id", ""))
                        if tx_raw_id.lower() == wanted:
                            self._send_json(
                                {
                                    "found": True,
                                    "chain": "private",
                                    "tx": tx,
                                    "location": {
                                        "block_index": None,
                                        "block_hash": None,
                                        "tx_index": tx_index,
                                        "confirmations": 0,
                                        "pending": True,
                                    },
                                }
                            )
                            return

            self._send_json({"found": False, "error": "Transaction not found"}, HTTPStatus.NOT_FOUND)
            return

        if path == "/scan/address":
            address = query.get("address", [""])[0].strip()
            include_private = query.get("include_private", ["false"])[0].strip().lower() == "true"
            can_view_private = self._can_view_private_scanner(query)
            include_private = include_private and can_view_private
            limit = _safe_int(query.get("limit", ["50"])[0], default=50, minimum=1, maximum=200)
            if not address:
                self._send_json({"error": "address query parameter is required"}, HTTPStatus.BAD_REQUEST)
                return

            with self.node.lock:
                public_balance = self.node.public_chain.get_balance(address)
                pending_public = [
                    tx for tx in self.node.public_chain.pending_transactions if address in _tx_addresses(tx)
                ]
                tx_rows: list[Dict[str, Any]] = []
                for block in self.node.public_chain.chain:
                    for tx_index, tx in enumerate(block.transactions):
                        if address in _tx_addresses(tx):
                            tx_rows.append(_tx_summary("public", block, tx_index, tx))
                private_balances: Dict[str, float] = {}
                if include_private:
                    for block in self.node.private_chain.chain:
                        for tx_index, tx in enumerate(block.transactions):
                            if address in _tx_addresses(tx):
                                tx_rows.append(_tx_summary("private", block, tx_index, tx))
                    private_balances = self.node.private_chain.get_asset_balances(
                        address=address,
                        include_pending=True,
                    ).get(address, {})

            tx_rows.sort(key=lambda r: float(r.get("timestamp", 0.0)), reverse=True)
            self._send_json(
                {
                    "address": address,
                    "public_balance": public_balance,
                    "pending_public_tx_count": len(pending_public),
                    "private_balances": private_balances,
                    "tx_count": len(tx_rows),
                    "transactions": tx_rows[:limit],
                    "private_visibility": "portal-session" if can_view_private else "hidden",
                }
            )
            return

        if path == "/scan/activity":
            can_view_private = self._can_view_private_scanner(query)
            chain_name = query.get("chain", ["public"])[0].strip().lower()
            window = _safe_int(query.get("window", ["30"])[0], default=30, minimum=1, maximum=1000)
            if chain_name not in {"public", "private"}:
                self._send_json({"error": "chain must be 'public' or 'private'"}, HTTPStatus.BAD_REQUEST)
                return
            if chain_name == "private" and not can_view_private:
                self._send_json(
                    {"error": "Private scanner data requires portal session (X-Portal-Session)."},
                    HTTPStatus.FORBIDDEN,
                )
                return

            with self.node.lock:
                source = self.node.public_chain.chain if chain_name == "public" else self.node.private_chain.chain
                selected = source[-window:]
                points = [
                    {
                        "index": block.index,
                        "timestamp": block.timestamp,
                        "tx_count": len(block.transactions),
                        "hash": block.hash,
                    }
                    for block in selected
                ]
            self._send_json({"chain": chain_name, "window": window, "points": points})
            return

        if path == "/scan/prices/history":
            symbol = query.get("symbol", [""])[0].strip().upper()
            limit = _safe_int(query.get("limit", ["100"])[0], default=100, minimum=1, maximum=500)
            rows: list[Dict[str, Any]] = []
            with self.node.lock:
                for block in self.node.public_chain.chain:
                    for tx in block.transactions:
                        if tx.get("type") != "price_update":
                            continue
                        if symbol and str(tx.get("symbol", "")).upper() != symbol:
                            continue
                        rows.append(
                            {
                                "tx_id": tx.get("id", ""),
                                "symbol": str(tx.get("symbol", "")).upper(),
                                "price": tx.get("price"),
                                "source": tx.get("source", ""),
                                "oracle": tx.get("oracle", ""),
                                "timestamp": tx.get("timestamp", block.timestamp),
                                "block_index": block.index,
                                "block_hash": block.hash,
                            }
                        )
            rows.sort(key=lambda r: float(r.get("timestamp", 0.0)), reverse=True)
            self._send_json({"symbol": symbol, "count": len(rows), "prices": rows[:limit]})
            return

        if path == "/scan/search":
            query_text = query.get("q", [""])[0].strip().lower()
            include_private = query.get("include_private", ["false"])[0].strip().lower() == "true"
            can_view_private = self._can_view_private_scanner(query)
            include_private = include_private and can_view_private
            limit = int(query.get("limit", ["50"])[0])
            limit = max(1, min(limit, 200))

            matches: list[Dict[str, Any]] = []

            def add_match(chain_name: str, block_idx: int, tx: Dict[str, Any]) -> None:
                if len(matches) >= limit:
                    return
                matches.append(
                    {
                        "chain": chain_name,
                        "block_index": block_idx,
                        "tx_id": tx.get("id", ""),
                        "type": tx.get("type", ""),
                        "tx": tx,
                    }
                )

            if query_text:
                for block in self.node.public_chain.chain:
                    for tx in block.transactions:
                        blob = json.dumps(tx, sort_keys=True).lower()
                        if query_text in blob:
                            add_match("public", block.index, tx)
                if include_private:
                    for block in self.node.private_chain.chain:
                        for tx in block.transactions:
                            blob = json.dumps(tx, sort_keys=True).lower()
                            if query_text in blob:
                                add_match("private", block.index, tx)
            self._send_json(
                {
                    "query": query_text,
                    "count": len(matches),
                    "matches": matches,
                    "include_private": include_private,
                    "private_visibility": "portal-session" if can_view_private else "hidden",
                }
            )
            return

        if path == "/private/chain":
            self._send_json(self.node.private_chain.export_state())
            return

        if path == "/private/governance":
            self._send_json(self.node.private_chain.list_governance())
            return

        if path == "/private/pending-blocks":
            self._send_json(
                {
                    "pending_blocks": [b.to_dict() for b in self.node.private_chain.pending_blocks],
                    "pending_finality": self.node.private_chain.pending_finality,
                }
            )
            return

        if path == "/private/assets":
            address = query.get("address", [None])[0]
            viewer = query.get("viewer", [None])[0]
            include_pending = query.get("include_pending", ["false"])[0].lower() == "true"
            self._send_json(
                self.node.private_chain.get_asset_balances(
                    address=address,
                    viewer=viewer,
                    include_pending=include_pending,
                )
            )
            return

        if path == "/private/view":
            viewer = query.get("viewer", [""])[0]
            if not viewer:
                self._send_json({"error": "viewer query parameter is required"}, HTTPStatus.BAD_REQUEST)
                return
            self._send_json(self.node.private_chain.get_private_view(viewer))
            return

        if path == "/private/ai/models":
            owner = query.get("owner", [""])[0].strip()
            limit = _safe_int(query.get("limit", ["200"])[0], default=200, minimum=1, maximum=1000)
            self._send_json(self.node.private_chain.list_ai_models(owner=owner, limit=limit))
            return

        if path == "/private/ai/agents":
            role = query.get("role", [""])[0].strip()
            wallet_name = query.get("wallet_name", [""])[0].strip()
            with self.node.lock:
                rows = self.node.list_ai_agents(role=role, wallet_name=wallet_name)
            self._send_json(
                {
                    "count": len(rows),
                    "role_filter": role,
                    "wallet_name_filter": wallet_name,
                    "agents": rows,
                }
            )
            return

        if path == "/private/ai/jobs":
            status = query.get("status", [""])[0].strip()
            participant = query.get("participant", [""])[0].strip()
            limit = _safe_int(query.get("limit", ["200"])[0], default=200, minimum=1, maximum=1000)
            self._send_json(
                self.node.private_chain.list_ai_jobs(
                    status=status,
                    participant=participant,
                    limit=limit,
                )
            )
            return

        if path == "/private/domains":
            domain_id = query.get("domain_id", [""])[0].strip()
            include_pending = query.get("include_pending", ["true"])[0].lower() == "true"
            self._send_json(self.node.private_chain.domain_summary(domain_id=domain_id, include_pending=include_pending))
            return

        if path == "/private/rwa/policy":
            settlement_asset = self._rwa_settlement_asset_id()
            settlement_contract = next(
                (
                    row
                    for row in self.node.rwa_tokens
                    if str(row.get("asset_id", "")).strip().upper() == settlement_asset
                ),
                None,
            )
            self._send_json(
                {
                    "network": self.chain_info.get("private_chain", {}).get("name", "Private RWA"),
                    "tokenization": "asset_issue + governance + validator-seal + notary-attest",
                    "gas_model": "no-gas",
                    "gas_fee_per_tx": 0.0,
                    "settlement_fee_per_tx": 0.0,
                    "settlement_token": {
                        "asset_id": settlement_asset,
                        "symbol": settlement_asset,
                        "price_usd": self._rwa_settlement_price_usd(),
                        "contract_address": (settlement_contract or {}).get("contract_address", ""),
                        "deployment_tx_hash": (settlement_contract or {}).get("deployment_tx_hash", ""),
                    },
                    "trade_model": "private DvP: buyer pays settlement token and receives asset units in same finalized block",
                    "listing_policy_schema": {
                        "require_participant": "bool",
                        "require_kyc": "bool",
                        "require_access_code": "bool (derived from access_mode=access_id)",
                        "min_order_units": "number (0 disables)",
                        "max_order_units": "number (0 disables)",
                        "allowed_wallets": "list[address|@alias]",
                        "allowed_wallet_names": "list[wallet_name]",
                        "allowed_jurisdictions": "list[country_code]",
                        "blocked_jurisdictions": "list[country_code]",
                    },
                    "default_listing_policy": self._normalize_rwa_trade_policy(raw_policy={}, access_mode="open"),
                }
            )
            return

        if path == "/private/rwa/listings":
            include_closed = query.get("include_closed", ["false"])[0].strip().lower() == "true"
            asset_id = query.get("asset_id", [""])[0].strip()
            with self.node.lock:
                listings = self.node.list_rwa_listings(include_closed=include_closed, asset_id=asset_id)
                token_by_asset = {
                    str(row.get("asset_id", "")).strip(): dict(row)
                    for row in self.node.rwa_tokens
                    if isinstance(row, dict)
                }
            enriched_listings: list[Dict[str, Any]] = []
            for row in listings:
                item = dict(row)
                item["token_contract"] = token_by_asset.get(str(item.get("asset_id", "")).strip(), {})
                item["policy"] = self._normalize_rwa_trade_policy(
                    raw_policy=item.get("policy", {}),
                    access_mode=str(item.get("access_mode", "open")).strip().lower() or "open",
                )
                enriched_listings.append(item)
            self._send_json(
                {
                    "count": len(enriched_listings),
                    "include_closed": include_closed,
                    "asset_id_filter": asset_id,
                    "listings": enriched_listings,
                }
            )
            return

        if path == "/private/rwa/tokens":
            asset_id = query.get("asset_id", [""])[0].strip()
            symbol = query.get("symbol", [""])[0].strip()
            with self.node.lock:
                rows = self.node.list_rwa_tokens(asset_id=asset_id, symbol=symbol)
            self._send_json(
                {
                    "count": len(rows),
                    "asset_id_filter": asset_id,
                    "symbol_filter": symbol.upper(),
                    "tokens": rows,
                }
            )
            return

        if path == "/private/rwa/access/passes":
            listing_id = query.get("listing_id", [""])[0].strip()
            include_inactive = query.get("include_inactive", ["false"])[0].strip().lower() == "true"
            with self.node.lock:
                rows = self.node.list_rwa_access_passes(listing_id=listing_id, include_inactive=include_inactive)
            self._send_json(
                {
                    "count": len(rows),
                    "listing_id_filter": listing_id,
                    "include_inactive": include_inactive,
                    "passes": rows,
                }
            )
            return

        if path == "/private/rwa/wallet":
            wallet_name = query.get("wallet_name", [""])[0].strip()
            address = query.get("address", [""])[0].strip()
            if not wallet_name and not address:
                self._send_json({"error": "wallet_name or address query parameter is required"}, HTTPStatus.BAD_REQUEST)
                return

            with self.node.lock:
                resolved_address = address
                if wallet_name:
                    wallet = self.node.load_named_wallet(wallet_name)
                    resolved_address = wallet["address"]
                resolved_address = self.node.resolve_address_alias(resolved_address)
                public_balance = self.node.public_chain.get_balance(resolved_address)
                private_balances = self.node.private_chain.get_asset_balances(
                    address=resolved_address,
                    include_pending=True,
                ).get(resolved_address, {})
                token_by_asset = {str(row.get("asset_id", "")).strip(): row for row in self.node.rwa_tokens}
                holdings: list[Dict[str, Any]] = []
                for item_asset_id, amount in private_balances.items():
                    amt = float(amount)
                    if amt <= 0:
                        continue
                    token = token_by_asset.get(str(item_asset_id).strip(), {})
                    holdings.append(
                        {
                            "asset_id": item_asset_id,
                            "amount": amt,
                            "token_symbol": token.get("symbol", ""),
                            "token_name": token.get("name", ""),
                            "contract_address": token.get("contract_address", ""),
                            "decimals": token.get("decimals", 18),
                        }
                    )
                transfer_history: list[Dict[str, Any]] = []
                for block in self.node.private_chain.chain:
                    for tx in block.transactions:
                        tx_type = str(tx.get("type", ""))
                        if tx_type not in {"asset_transfer", "asset_issue"}:
                            continue
                        if resolved_address not in _tx_addresses(tx):
                            continue
                        transfer_history.append(
                            {
                                "tx_id": tx.get("id", ""),
                                "type": tx_type,
                                "asset_id": tx.get("asset_id", ""),
                                "amount": tx.get("amount", 0.0),
                                "from": tx.get("from", tx.get("issuer", "")),
                                "to": tx.get("to", tx.get("owner", "")),
                                "block_index": block.index,
                                "block_hash": block.hash,
                                "timestamp": tx.get("timestamp", block.timestamp),
                            }
                        )
                transfer_history.sort(key=lambda row: float(row.get("timestamp", 0.0)), reverse=True)
            self._send_json(
                {
                    "wallet_name": wallet_name,
                    "address": resolved_address,
                    "public_balance": public_balance,
                    "holding_count": len(holdings),
                    "holdings": holdings,
                    "tx_count": len(transfer_history),
                    "transactions": transfer_history[:200],
                }
            )
            return

        if path == "/private/rwa/inventory":
            seller_wallet_name = query.get("seller_wallet_name", [""])[0].strip()
            include_closed = query.get("include_closed", ["true"])[0].strip().lower() == "true"
            listings = self.node.list_rwa_listings(include_closed=include_closed, asset_id="")

            if seller_wallet_name:
                listings = [row for row in listings if str(row.get("seller_wallet_name", "")).strip() == seller_wallet_name]

            sold_trades: list[Dict[str, Any]] = []
            listed_qty_total = 0.0
            available_qty_total = 0.0
            sold_qty_total = 0.0
            gross_settlement_total = 0.0
            settlement_asset = self._rwa_settlement_asset_id()
            for row in listings:
                quantity_total = float(row.get("quantity_total", 0.0))
                quantity_available = float(row.get("quantity_available", 0.0))
                listed_qty_total += quantity_total
                available_qty_total += quantity_available
                for trade in row.get("trades", []):
                    if not isinstance(trade, dict):
                        continue
                    sold_trades.append(
                        {
                            "listing_id": row.get("id", ""),
                            "asset_id": row.get("asset_id", ""),
                            "seller_wallet_name": row.get("seller_wallet_name", ""),
                            "trade": dict(trade),
                        }
                    )
                    sold_qty_total += float(trade.get("amount", 0.0))
                    gross_settlement_total += float(
                        trade.get(
                            "settlement_amount",
                            trade.get("total_price", 0.0),
                        )
                    )
                    settlement_asset = str(
                        trade.get(
                            "settlement_asset_id",
                            row.get("settlement_asset_id", settlement_asset),
                        )
                    ).strip() or settlement_asset

            sold_trades.sort(key=lambda row: float(row.get("trade", {}).get("timestamp", 0.0)), reverse=True)
            self._send_json(
                {
                    "seller_wallet_name": seller_wallet_name,
                    "include_closed": include_closed,
                    "listing_count": len(listings),
                    "sold_trade_count": len(sold_trades),
                    "summary": {
                        "listed_quantity_total": listed_qty_total,
                        "available_quantity_total": available_qty_total,
                        "sold_quantity_total": sold_qty_total,
                        "gross_settlement_total": gross_settlement_total,
                        "settlement_asset_id": settlement_asset,
                    },
                    "listings": listings,
                    "sold_trades": sold_trades[:500],
                }
            )
            return

        if path == "/private/rwa/auth/me":
            user = self._require_portal_session(query)
            if user is None:
                return
            self._send_json({"ok": True, "user": user})
            return

        if path == "/private/rwa/dashboard":
            include_closed = query.get("include_closed", ["true"])[0].strip().lower() == "true"
            user = self._require_portal_session(query)
            if user is None:
                return
            with self.node.lock:
                payload = self.node.portal_dashboard(user["username"], include_closed=include_closed)
            self._send_json({"ok": True, "dashboard": payload})
            return

        if path == "/snapshot":
            self._send_json(self.node.snapshot())
            return

        if path == "/treasury":
            self._send_json(self.node.public_chain.get_treasury_info())
            return

        if path == "/validator/candidates":
            with self.node.lock:
                candidates = dict(self.node.public_chain.validator_candidates)
            sorted_c = sorted(candidates.items(), key=lambda x: x[1]["votes"], reverse=True)
            result = []
            for addr, data in sorted_c:
                entry = {"address": addr, **data}
                with self.node.lock:
                    identity = self.node.public_chain.identity_registry.get(addr, {})
                if identity.get("handle"):
                    entry["handle"] = identity["handle"]
                result.append(entry)
            self._send_json({"count": len(result), "candidates": result})
            return

        if path == "/oracles":
            with self.node.lock:
                assignments = list(self.node.public_chain.oracle_assignments.values())
            summary = []
            for a in assignments:
                s = {k: v for k, v in a.items() if k != "events"}
                s["event_count"] = len(a.get("events", []))
                summary.append(s)
            self._send_json({"count": len(summary), "oracles": summary})
            return

        if path.startswith("/oracles/"):
            asset_id = path[len("/oracles/"):].strip("/")
            if not asset_id:
                self._send_json({"error": "asset_id is required"}, HTTPStatus.BAD_REQUEST)
                return
            with self.node.lock:
                assignment = self.node.public_chain.oracle_assignments.get(asset_id)
            if not assignment:
                self._send_json({"error": "No oracle assigned to this asset"}, HTTPStatus.NOT_FOUND)
                return
            self._send_json(assignment)
            return

        if path == "/models":
            qs = parse.parse_qs(parsed.query)
            owner_filter = qs.get("owner", [None])[0]
            cap_filter = qs.get("capability", [None])[0]
            with self.node.lock:
                models = list(self.node.public_chain.model_registry.values())
            if owner_filter:
                models = [m for m in models if m.get("owner") == owner_filter]
            if cap_filter:
                models = [m for m in models if cap_filter in m.get("capabilities", [])]
            models.sort(key=lambda m: m.get("inference_count", 0), reverse=True)
            self._send_json({"count": len(models), "models": models})
            return

        if path.startswith("/models/"):
            model_id = path[len("/models/"):].strip("/")
            with self.node.lock:
                model = self.node.public_chain.model_registry.get(model_id)
            if not model:
                self._send_json({"error": "Model not found"}, HTTPStatus.NOT_FOUND)
                return
            self._send_json(model)
            return

        if path == "/pipelines":
            qs = parse.parse_qs(parsed.query)
            status_filter = qs.get("status", [None])[0]
            owner_filter = qs.get("owner", [None])[0]
            with self.node.lock:
                pipelines = list(self.node.public_chain.pipeline_registry.values())
            if status_filter:
                pipelines = [p for p in pipelines if p.get("status") == status_filter]
            if owner_filter:
                pipelines = [p for p in pipelines if p.get("owner") == owner_filter]
            pipelines.sort(key=lambda p: p.get("created_at", 0), reverse=True)
            self._send_json({"count": len(pipelines), "pipelines": pipelines})
            return

        if path.startswith("/pipelines/"):
            pipeline_id = path[len("/pipelines/"):].strip("/")
            with self.node.lock:
                pipeline = self.node.public_chain.pipeline_registry.get(pipeline_id)
            if not pipeline:
                self._send_json({"error": "Pipeline not found"}, HTTPStatus.NOT_FOUND)
                return
            self._send_json(pipeline)
            return

        self._send_json({"error": f"Unknown endpoint: {path}"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        assert self.node is not None
        parsed = parse.urlparse(self.path)
        path = parsed.path

        if not self._enforce_rate_limit(path):
            return

        if not self._authorized(path):
            return

        payload = self._read_json()
        propagated = bool(payload.pop("_propagated", False))

        try:
            if path == "/network/peers/add":
                peer = str(payload.get("peer", "")).rstrip("/")
                if not peer:
                    raise ValueError("peer is required")
                self.node.add_peer(peer)
                self._send_json({"ok": True, "peers": sorted(self.node.peers)})
                return

            if path == "/network/sync":
                report = self.node.sync_from_peers()
                self._send_json({"ok": True, "report": report})
                return

            if path == "/snapshot/push":
                changed = self.node.adopt_snapshot_if_better(payload)
                self._send_json({"ok": True, "changed": changed})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/chain/branding":
                current = self._current_chain_info()
                current_branding = current.get("branding", {})
                chain_logo_url = current_branding.get("chain_logo_url", "")
                token_logo_url = current_branding.get("token_logo_url", "")
                if "chain_logo_url" in payload:
                    chain_logo_url = self._clean_logo_url(str(payload.get("chain_logo_url", "")))
                if "token_logo_url" in payload:
                    token_logo_url = self._clean_logo_url(str(payload.get("token_logo_url", "")))
                self._set_branding(chain_logo_url=chain_logo_url, token_logo_url=token_logo_url)
                self._send_json({"ok": True, "chain_info": self._current_chain_info()})
                return

            if path == "/ui/wallets/create":
                name = str(payload.get("name", "")).strip()
                scheme = str(payload.get("scheme", "ed25519")).strip()
                use_hsm = bool(payload.get("use_hsm", False))
                key_ref = str(payload.get("key_ref", "")).strip()
                with self.node.lock:
                    wallet = self.node.create_named_wallet(name=name, scheme=scheme, use_hsm=use_hsm, key_ref=key_ref)
                self._send_json({"ok": True, "wallet": wallet, "wallets": self.node.list_wallets()})
                return

            if path == "/ui/public/tx":
                wallet_name = str(payload.get("wallet_name", "")).strip()
                to = self.node.resolve_address_alias(str(payload.get("to", "")))
                amount = float(payload.get("amount", 0))
                wallet = self._load_signing_wallet(wallet_name)
                tx = make_payment_tx(wallet, to, amount)
                with self.node.lock:
                    self.node.public_chain.add_transaction(tx)
                self._send_json({"ok": True, "tx": tx})
                self.node.publish_event(
                    "public.tx.queued",
                    {
                        "tx_id": tx.get("id", ""),
                        "sender": tx.get("sender", ""),
                        "recipient": tx.get("recipient", ""),
                        "amount": tx.get("amount", 0.0),
                        "source": "ui",
                    },
                )
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/ui/public/agent/transfers/batch":
                wallet_name = str(payload.get("wallet_name", "")).strip()
                wallet = self._load_signing_wallet(wallet_name)
                transfers_raw = payload.get("transfers", [])
                if not isinstance(transfers_raw, list):
                    raise ValueError("transfers must be a list.")
                if len(transfers_raw) == 0:
                    raise ValueError("transfers list cannot be empty.")
                if len(transfers_raw) > 500:
                    raise ValueError("transfers list is too large (max 500).")
                max_total = float(payload.get("max_total_amount", 0.0) or 0.0)
                dry_run = bool(payload.get("dry_run", False))

                prepared: list[Dict[str, Any]] = []
                total_amount = 0.0
                for idx, item in enumerate(transfers_raw):
                    if not isinstance(item, dict):
                        raise ValueError(f"transfers[{idx}] must be an object.")
                    to = self.node.resolve_address_alias(str(item.get("to", "")).strip())
                    amount = float(item.get("amount", 0.0))
                    if not to or amount <= 0:
                        raise ValueError(f"Invalid transfers[{idx}] entry: to and amount>0 are required.")
                    total_amount += amount
                    prepared.append({"to": to, "amount": amount})

                if max_total > 0 and total_amount > max_total + 1e-12:
                    raise ValueError(f"Batch total {total_amount} exceeds max_total_amount {max_total}.")

                txs: list[Dict[str, Any]] = [make_payment_tx(wallet, row["to"], row["amount"]) for row in prepared]
                if not dry_run:
                    with self.node.lock:
                        for tx in txs:
                            self.node.public_chain.add_transaction(tx)
                self._send_json(
                    {
                        "ok": True,
                        "wallet_name": wallet_name,
                        "dry_run": dry_run,
                        "count": len(txs),
                        "total_amount": total_amount,
                        "tx_ids": [tx.get("id", "") for tx in txs],
                        "transactions": txs if dry_run else [],
                    }
                )
                if not dry_run:
                    for tx in txs:
                        self.node.publish_event(
                            "public.tx.queued",
                            {
                                "tx_id": tx.get("id", ""),
                                "sender": tx.get("sender", ""),
                                "recipient": tx.get("recipient", ""),
                                "amount": tx.get("amount", 0.0),
                                "source": "agent-batch",
                            },
                        )
                if not dry_run and not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/ui/public/mine":
                miner_name = str(payload.get("miner_wallet_name", "")).strip()
                miner = self.node.load_named_wallet(miner_name)["address"]
                with self.node.lock:
                    block = self.node.public_chain.mine_pending_transactions(miner)
                self._send_json({"ok": True, "block": block.to_dict()})
                self.node.publish_event(
                    "public.block.mined",
                    {
                        "source": "manual-ui",
                        "block_index": block.index,
                        "block_hash": block.hash,
                        "validator": str(block.meta.get("validator", "")),
                        "tx_count": len(block.transactions),
                    },
                )
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/ui/public/oracle/register":
                wallet_name = str(payload.get("wallet_name", "")).strip()
                wallet = self.node.load_named_wallet(wallet_name)
                with self.node.lock:
                    self.node.public_chain.register_price_oracle(wallet["address"])
                self._send_json({"ok": True, "oracle": wallet["address"]})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/ui/public/price/update":
                wallet_name = str(payload.get("wallet_name", "")).strip()
                wallet = self._load_signing_wallet(wallet_name)
                symbol = str(payload.get("symbol", "")).strip().upper()
                price = float(payload.get("price", 0))
                source = str(payload.get("source", "manual")).strip() or "manual"
                tx = make_price_update_tx(wallet, symbol=symbol, price=price, source=source)
                with self.node.lock:
                    self.node.public_chain.add_transaction(tx)
                self._send_json({"ok": True, "tx": tx})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/ui/private/register":
                wallet_name = str(payload.get("wallet_name", "")).strip()
                roles = list(payload.get("roles", ["participant"]))
                domains = list(payload.get("domains", []))
                attributes = dict(payload.get("attributes", {}))
                wallet = self.node.load_named_wallet(wallet_name)
                with self.node.lock:
                    self.node.private_chain.register_wallet(wallet, roles, domains, attributes)
                self._send_json({"ok": True})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/ui/private/auth/register":
                username = str(payload.get("username", "")).strip()
                password = str(payload.get("password", ""))
                wallet_names = payload.get("wallet_names", payload.get("wallets", []))
                with self.node.lock:
                    user = self.node.register_portal_user(
                        username=username,
                        password=password,
                        wallet_names=wallet_names,
                    )
                self._send_json({"ok": True, "user": user})
                return

            if path == "/ui/private/auth/login":
                username = str(payload.get("username", "")).strip()
                password = str(payload.get("password", ""))
                with self.node.lock:
                    out = self.node.portal_login(username=username, password=password)
                self._send_json({"ok": True, **out})
                return

            if path == "/ui/private/auth/logout":
                token = self._portal_session_token()
                if not token:
                    token = str(payload.get("token", "")).strip()
                if not token:
                    raise ValueError("session token is required for logout")
                with self.node.lock:
                    self.node.portal_logout(token)
                self._send_json({"ok": True})
                return

            if path == "/ui/private/auth/link-wallet":
                wallet_name = str(payload.get("wallet_name", "")).strip()
                if not wallet_name:
                    raise ValueError("wallet_name is required")
                user = self._require_portal_session()
                if user is None:
                    return
                with self.node.lock:
                    updated = self.node.portal_link_wallet(user["username"], wallet_name)
                self._send_json({"ok": True, "user": updated})
                return

            if path == "/ui/private/ai/agent/register":
                wallet_name = str(payload.get("wallet_name", "")).strip()
                role = str(payload.get("role", "worker")).strip() or "worker"
                agent_id = str(payload.get("agent_id", "")).strip()
                name = str(payload.get("name", "")).strip() or agent_id
                domains = payload.get("domains", [])
                if isinstance(domains, str):
                    domains = [item.strip() for item in domains.split(",") if item.strip()]
                if not isinstance(domains, list):
                    domains = []
                capabilities = payload.get("capabilities", [])
                if isinstance(capabilities, str):
                    capabilities = [item.strip() for item in capabilities.split(",") if item.strip()]
                if not isinstance(capabilities, list):
                    capabilities = []
                metadata = dict(payload.get("metadata", {})) if isinstance(payload.get("metadata", {}), dict) else {}
                if not wallet_name:
                    raise ValueError("wallet_name is required.")
                if not agent_id:
                    raise ValueError("agent_id is required.")
                with self.node.lock:
                    wallet = self.node.load_named_wallet(wallet_name)
                    self.node.private_chain.register_wallet(
                        wallet,
                        roles=["participant", role],
                        domains=domains,
                        attributes={"service": "ai-agent", "role": role},
                    )
                    agent = self.node.register_ai_agent(
                        agent_id=agent_id,
                        name=name,
                        wallet_name=wallet_name,
                        role=role,
                        capabilities=capabilities,
                        metadata=metadata,
                    )
                self._send_json({"ok": True, "agent": agent})
                self.node.publish_event(
                    "ai.agent.registered",
                    {
                        "agent_id": agent.get("agent_id", ""),
                        "wallet_name": wallet_name,
                        "role": role,
                    },
                )
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/ui/private/ai/model/register":
                owner_wallet_name = str(payload.get("owner_wallet_name", "")).strip()
                model_id = str(payload.get("model_id", "")).strip()
                model_hash = str(payload.get("model_hash", "")).strip()
                version = str(payload.get("version", "v1")).strip() or "v1"
                price_per_call = float(payload.get("price_per_call", 0.0))
                visibility = self._resolve_address_tokens(payload.get("visibility", []))
                metadata = dict(payload.get("metadata", {})) if isinstance(payload.get("metadata", {}), dict) else {}
                auto_finalize = bool(payload.get("auto_finalize", False))
                validator_wallet_name = str(payload.get("validator_wallet_name", "")).strip()
                notary_wallet_name = str(payload.get("notary_wallet_name", "")).strip()
                if not owner_wallet_name or not model_id or not model_hash:
                    raise ValueError("owner_wallet_name, model_id, and model_hash are required.")
                if price_per_call < 0:
                    raise ValueError("price_per_call must be >= 0")
                with self.node.lock:
                    owner_wallet = self._load_signing_wallet(owner_wallet_name)
                    self.node.private_chain.register_wallet(
                        owner_wallet,
                        roles=["participant"],
                        domains=[],
                        attributes={"service": "ai-model-owner", "ai_role": "provider"},
                    )
                    tx = make_ai_model_register_tx(
                        owner_wallet=owner_wallet,
                        model_id=model_id,
                        model_hash=model_hash,
                        version=version,
                        price_per_call=price_per_call,
                        visibility=visibility,
                        metadata=metadata,
                    )
                    self.node.private_chain.add_transaction(tx)
                    block_payload = None
                    finality_payload = None
                    if auto_finalize:
                        if not validator_wallet_name or not notary_wallet_name:
                            raise ValueError("validator_wallet_name and notary_wallet_name are required when auto_finalize=true.")
                        validator_wallet = self._load_signing_wallet(validator_wallet_name)
                        notary_wallet = self._load_signing_wallet(notary_wallet_name)
                        block = self.node.private_chain.seal_pending_transactions(validator_wallet)
                        finality = self.node.private_chain.attest_block(block.hash, notary_wallet, auto_finalize=True)
                        block_payload = block.to_dict()
                        finality_payload = finality
                self._send_json({"ok": True, "tx": tx, "block": block_payload, "finality": finality_payload})
                self.node.publish_event(
                    "ai.model.registered",
                    {
                        "model_id": model_id,
                        "owner_wallet_name": owner_wallet_name,
                        "tx_id": tx.get("id", ""),
                    },
                )
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/ui/private/ai/job/create":
                requester_wallet_name = str(payload.get("requester_wallet_name", "")).strip()
                job_id = str(payload.get("job_id", "")).strip()
                model_id = str(payload.get("model_id", "")).strip()
                input_hash = str(payload.get("input_hash", "")).strip()
                max_payment = float(payload.get("max_payment", 0.0))
                visibility = self._resolve_address_tokens(payload.get("visibility", []))
                metadata = dict(payload.get("metadata", {})) if isinstance(payload.get("metadata", {}), dict) else {}
                auto_finalize = bool(payload.get("auto_finalize", False))
                validator_wallet_name = str(payload.get("validator_wallet_name", "")).strip()
                notary_wallet_name = str(payload.get("notary_wallet_name", "")).strip()
                if not requester_wallet_name or not job_id or not model_id or not input_hash:
                    raise ValueError("requester_wallet_name, job_id, model_id, and input_hash are required.")
                if max_payment < 0:
                    raise ValueError("max_payment must be >= 0")
                with self.node.lock:
                    requester_wallet = self._load_signing_wallet(requester_wallet_name)
                    self.node.private_chain.register_wallet(
                        requester_wallet,
                        roles=["participant"],
                        domains=[],
                        attributes={"service": "ai-requester", "ai_role": "requester"},
                    )
                    tx = make_ai_job_create_tx(
                        requester_wallet=requester_wallet,
                        job_id=job_id,
                        model_id=model_id,
                        input_hash=input_hash,
                        max_payment=max_payment,
                        visibility=visibility,
                        metadata=metadata,
                    )
                    self.node.private_chain.add_transaction(tx)
                    block_payload = None
                    finality_payload = None
                    if auto_finalize:
                        if not validator_wallet_name or not notary_wallet_name:
                            raise ValueError("validator_wallet_name and notary_wallet_name are required when auto_finalize=true.")
                        validator_wallet = self._load_signing_wallet(validator_wallet_name)
                        notary_wallet = self._load_signing_wallet(notary_wallet_name)
                        block = self.node.private_chain.seal_pending_transactions(validator_wallet)
                        finality = self.node.private_chain.attest_block(block.hash, notary_wallet, auto_finalize=True)
                        block_payload = block.to_dict()
                        finality_payload = finality
                self._send_json({"ok": True, "tx": tx, "block": block_payload, "finality": finality_payload})
                self.node.publish_event(
                    "ai.job.created",
                    {
                        "job_id": job_id,
                        "model_id": model_id,
                        "requester_wallet_name": requester_wallet_name,
                        "tx_id": tx.get("id", ""),
                    },
                )
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/ui/private/ai/job/result":
                provider_wallet_name = str(payload.get("provider_wallet_name", "")).strip()
                job_id = str(payload.get("job_id", "")).strip()
                result_hash = str(payload.get("result_hash", "")).strip()
                quality_score = float(payload.get("quality_score", 1.0))
                metadata = dict(payload.get("metadata", {})) if isinstance(payload.get("metadata", {}), dict) else {}
                auto_finalize = bool(payload.get("auto_finalize", False))
                validator_wallet_name = str(payload.get("validator_wallet_name", "")).strip()
                notary_wallet_name = str(payload.get("notary_wallet_name", "")).strip()
                if not provider_wallet_name or not job_id or not result_hash:
                    raise ValueError("provider_wallet_name, job_id, and result_hash are required.")
                with self.node.lock:
                    provider_wallet = self._load_signing_wallet(provider_wallet_name)
                    self.node.private_chain.register_wallet(
                        provider_wallet,
                        roles=["participant"],
                        domains=[],
                        attributes={"service": "ai-provider", "ai_role": "provider"},
                    )
                    tx = make_ai_job_result_tx(
                        provider_wallet=provider_wallet,
                        job_id=job_id,
                        result_hash=result_hash,
                        quality_score=quality_score,
                        metadata=metadata,
                    )
                    self.node.private_chain.add_transaction(tx)
                    block_payload = None
                    finality_payload = None
                    if auto_finalize:
                        if not validator_wallet_name or not notary_wallet_name:
                            raise ValueError("validator_wallet_name and notary_wallet_name are required when auto_finalize=true.")
                        validator_wallet = self._load_signing_wallet(validator_wallet_name)
                        notary_wallet = self._load_signing_wallet(notary_wallet_name)
                        block = self.node.private_chain.seal_pending_transactions(validator_wallet)
                        finality = self.node.private_chain.attest_block(block.hash, notary_wallet, auto_finalize=True)
                        block_payload = block.to_dict()
                        finality_payload = finality
                self._send_json({"ok": True, "tx": tx, "block": block_payload, "finality": finality_payload})
                self.node.publish_event(
                    "ai.job.result",
                    {
                        "job_id": job_id,
                        "provider_wallet_name": provider_wallet_name,
                        "tx_id": tx.get("id", ""),
                    },
                )
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/ui/private/ai/job/settle":
                settler_wallet_name = str(payload.get("settler_wallet_name", "")).strip()
                job_id = str(payload.get("job_id", "")).strip()
                payout = float(payload.get("payout", 0.0))
                slash_provider = float(payload.get("slash_provider", 0.0))
                reason = str(payload.get("reason", "")).strip()
                auto_finalize = bool(payload.get("auto_finalize", False))
                validator_wallet_name = str(payload.get("validator_wallet_name", "")).strip()
                notary_wallet_name = str(payload.get("notary_wallet_name", "")).strip()
                if not settler_wallet_name or not job_id:
                    raise ValueError("settler_wallet_name and job_id are required.")
                if payout < 0 or slash_provider < 0:
                    raise ValueError("payout and slash_provider must be >= 0")
                with self.node.lock:
                    settler_wallet = self._load_signing_wallet(settler_wallet_name)
                    self.node.private_chain.register_wallet(
                        settler_wallet,
                        roles=["participant"],
                        domains=[],
                        attributes={"service": "ai-settlement", "ai_role": "settler"},
                    )
                    tx = make_ai_job_settle_tx(
                        settler_wallet=settler_wallet,
                        job_id=job_id,
                        payout=payout,
                        slash_provider=slash_provider,
                        reason=reason,
                    )
                    self.node.private_chain.add_transaction(tx)
                    block_payload = None
                    finality_payload = None
                    if auto_finalize:
                        if not validator_wallet_name or not notary_wallet_name:
                            raise ValueError("validator_wallet_name and notary_wallet_name are required when auto_finalize=true.")
                        validator_wallet = self._load_signing_wallet(validator_wallet_name)
                        notary_wallet = self._load_signing_wallet(notary_wallet_name)
                        block = self.node.private_chain.seal_pending_transactions(validator_wallet)
                        finality = self.node.private_chain.attest_block(block.hash, notary_wallet, auto_finalize=True)
                        block_payload = block.to_dict()
                        finality_payload = finality
                self._send_json({"ok": True, "tx": tx, "block": block_payload, "finality": finality_payload})
                self.node.publish_event(
                    "ai.job.settled",
                    {
                        "job_id": job_id,
                        "settler_wallet_name": settler_wallet_name,
                        "tx_id": tx.get("id", ""),
                    },
                )
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/ui/public/ai/stake":
                wallet_name = str(payload.get("wallet_name", "")).strip()
                amount = float(payload.get("amount", 0.0))
                if not wallet_name:
                    raise ValueError("wallet_name is required.")
                if amount <= 0:
                    raise ValueError("amount must be > 0")
                with self.node.lock:
                    wallet = self._load_signing_wallet(wallet_name)
                    tx = make_ai_provider_stake_tx(wallet, amount)
                    self.node.public_chain.add_transaction(tx)
                self._send_json({"ok": True, "tx": tx})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/public/identity/claim":
                wallet_name = str(payload.get("wallet_name", "")).strip()
                handle = str(payload.get("handle", "")).strip()
                bio = str(payload.get("bio", "")).strip()
                links = dict(payload.get("links", {}))
                if not wallet_name or not handle:
                    raise ValueError("wallet_name and handle are required.")
                with self.node.lock:
                    wallet = self._load_signing_wallet(wallet_name)
                    tx = make_identity_claim_tx(wallet, handle=handle, bio=bio, links=links)
                    self.node.public_chain.add_transaction(tx)
                self._send_json({"ok": True, "tx": tx})
                self.node.publish_event("identity.claim", {"tx_id": tx["id"], "handle": handle, "address": wallet["address"]})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/public/identity/update":
                wallet_name = str(payload.get("wallet_name", "")).strip()
                bio = str(payload.get("bio", "")).strip()
                links = dict(payload.get("links", {}))
                if not wallet_name:
                    raise ValueError("wallet_name is required.")
                with self.node.lock:
                    wallet = self._load_signing_wallet(wallet_name)
                    tx = make_identity_update_tx(wallet, bio=bio, links=links)
                    self.node.public_chain.add_transaction(tx)
                self._send_json({"ok": True, "tx": tx})
                self.node.publish_event("identity.update", {"tx_id": tx["id"], "address": wallet["address"]})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/public/agent/register":
                wallet_name = str(payload.get("wallet_name", "")).strip()
                agent_id = str(payload.get("agent_id", "")).strip()
                name = str(payload.get("name", "")).strip()
                capabilities = list(payload.get("capabilities", []))
                version_hash = str(payload.get("version_hash", "")).strip()
                if not wallet_name or not agent_id or not name:
                    raise ValueError("wallet_name, agent_id, and name are required.")
                with self.node.lock:
                    wallet = self._load_signing_wallet(wallet_name)
                    tx = make_agent_register_tx(wallet, agent_id=agent_id, name=name, capabilities=capabilities, version_hash=version_hash)
                    self.node.public_chain.add_transaction(tx)
                self._send_json({"ok": True, "tx": tx})
                self.node.publish_event("agent.register", {"tx_id": tx["id"], "agent_id": agent_id, "owner": wallet["address"]})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/public/agent/attest":
                wallet_name = str(payload.get("wallet_name", "")).strip()
                agent_id = str(payload.get("agent_id", "")).strip()
                sentiment = str(payload.get("sentiment", "")).strip()
                note = str(payload.get("note", "")).strip()
                if not wallet_name or not agent_id or not sentiment:
                    raise ValueError("wallet_name, agent_id, and sentiment are required.")
                with self.node.lock:
                    wallet = self._load_signing_wallet(wallet_name)
                    tx = make_agent_attest_tx(wallet, agent_id=agent_id, sentiment=sentiment, note=note)
                    self.node.public_chain.add_transaction(tx)
                self._send_json({"ok": True, "tx": tx})
                self.node.publish_event("agent.attest", {"tx_id": tx["id"], "agent_id": agent_id, "sentiment": sentiment})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/public/agent/activity":
                wallet_name = str(payload.get("wallet_name", "")).strip()
                agent_id = str(payload.get("agent_id", "")).strip()
                action_type = str(payload.get("action_type", "")).strip()
                if not wallet_name or not agent_id or not action_type:
                    raise ValueError("wallet_name, agent_id, and action_type are required.")
                with self.node.lock:
                    wallet = self._load_signing_wallet(wallet_name)
                    tx = make_agent_activity_log_tx(
                        wallet,
                        agent_id=agent_id,
                        action_type=action_type,
                        input_hash=str(payload.get("input_hash", "")),
                        output_hash=str(payload.get("output_hash", "")),
                        success=bool(payload.get("success", True)),
                        duration_ms=int(payload.get("duration_ms", 0)),
                        tags=list(payload.get("tags", [])),
                        platform=str(payload.get("platform", "")),
                        note=str(payload.get("note", "")),
                    )
                    self.node.public_chain.add_transaction(tx)
                self._send_json({"ok": True, "tx": tx})
                self.node.publish_event("agent.activity", {
                    "tx_id": tx["id"], "agent_id": agent_id,
                    "action_type": action_type, "success": tx["success"],
                })
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/public/agent/log/batch":
                wallet_name = str(payload.get("wallet_name", "")).strip()
                agent_id = str(payload.get("agent_id", "")).strip()
                agent = str(payload.get("agent", "")).strip()
                logs = list(payload.get("logs", []))
                if not agent_id or not logs:
                    raise ValueError("agent_id and logs are required.")
                tx_ids = []
                with self.node.lock:
                    wallet = self._load_signing_wallet(wallet_name or agent_id)
                    for log_entry in logs:
                        action_type = str(log_entry.get("action_type", "activity")).strip()
                        tx = make_agent_activity_log_tx(
                            wallet,
                            agent_id=agent_id,
                            action_type=action_type,
                            input_hash=str(log_entry.get("input_hash", "")),
                            output_hash=str(log_entry.get("output_hash", "")),
                            evidence_url=str(log_entry.get("evidence_url", "")),
                            success=bool(log_entry.get("success", True)),
                            duration_ms=int(log_entry.get("duration_ms", 0)),
                            tags=list(log_entry.get("tags") or []),
                            external_ref=str(log_entry.get("external_ref", "")),
                            note=str(log_entry.get("note", "")),
                            stake_locked=float(log_entry.get("stake_locked", 0.0)),
                        )
                        self.node.public_chain.add_transaction(tx)
                        tx_ids.append(tx["id"])
                self._send_json({"ok": True, "tx_ids": tx_ids, "count": len(tx_ids)})
                self.node.publish_event("agent.activity.batch", {
                    "agent_id": agent_id, "count": len(tx_ids),
                })
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/public/identity/verify":
                wallet_name = str(payload.get("wallet_name", "")).strip()
                target = str(payload.get("target_address", "")).strip()
                level = str(payload.get("level", "basic")).strip() or "basic"
                if not wallet_name or not target:
                    raise ValueError("wallet_name and target_address required")
                with self.node.lock:
                    wallet = self._load_signing_wallet(wallet_name)
                    tx = make_identity_verify_tx(wallet, target, level)
                    self.node.public_chain.add_transaction(tx)
                self._send_json({"ok": True, "tx": tx["payload"] if "payload" in tx else tx})
                self.node.publish_event("identity.verify", {"tx_id": tx.get("id", ""), "target": target, "level": level})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/public/task/delegate":
                wallet_name = str(payload.get("wallet_name", "")).strip()
                agent_id = str(payload.get("agent_id", "")).strip()
                title = str(payload.get("title", "")).strip()
                description = str(payload.get("description", "")).strip()
                reward = float(payload.get("reward", 0))
                min_reputation = float(payload.get("min_reputation", 0.0))
                if not wallet_name or not title or reward <= 0:
                    raise ValueError("wallet_name, title, and reward required")
                with self.node.lock:
                    wallet = self._load_signing_wallet(wallet_name)
                    tx = make_task_delegate_tx(wallet, agent_id, title, description, reward, min_reputation)
                    self.node.public_chain.add_transaction(tx)
                tx_payload = tx.get("payload", tx)
                self._send_json({"ok": True, "task_id": tx_payload.get("task_id", ""), "tx": tx_payload})
                self.node.publish_event("task.delegate", {"tx_id": tx.get("id", ""), "title": title, "owner": wallet["address"]})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/public/task/complete":
                wallet_name = str(payload.get("wallet_name", "")).strip()
                task_id = str(payload.get("task_id", "")).strip()
                result_hash = str(payload.get("result_hash", "")).strip()
                note = str(payload.get("note", "")).strip()
                if not wallet_name or not task_id:
                    raise ValueError("wallet_name and task_id required")
                with self.node.lock:
                    wallet = self._load_signing_wallet(wallet_name)
                    tx = make_task_complete_tx(wallet, task_id, result_hash, note)
                    self.node.public_chain.add_transaction(tx)
                self._send_json({"ok": True, "tx": tx.get("payload", tx)})
                self.node.publish_event("task.complete", {"tx_id": tx.get("id", ""), "task_id": task_id})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/public/task/review":
                wallet_name = str(payload.get("wallet_name", "")).strip()
                task_id = str(payload.get("task_id", "")).strip()
                approved = bool(payload.get("approved", True))
                quality_score = int(payload.get("quality_score", 50))
                note = str(payload.get("note", "")).strip()
                if not wallet_name or not task_id:
                    raise ValueError("wallet_name and task_id required")
                with self.node.lock:
                    wallet = self._load_signing_wallet(wallet_name)
                    tx = make_task_review_tx(wallet, task_id, approved, quality_score, note)
                    self.node.public_chain.add_transaction(tx)
                self._send_json({"ok": True, "tx": tx.get("payload", tx)})
                self.node.publish_event("task.review", {"tx_id": tx.get("id", ""), "task_id": task_id, "approved": approved})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/public/task/dispute":
                wallet_name = str(payload.get("wallet_name", "")).strip()
                task_id = str(payload.get("task_id", "")).strip()
                reason = str(payload.get("reason", "")).strip()
                if not wallet_name or not task_id:
                    raise ValueError("wallet_name and task_id required")
                with self.node.lock:
                    wallet = self._load_signing_wallet(wallet_name)
                    tx = make_task_dispute_tx(wallet, task_id, reason)
                    self.node.public_chain.add_transaction(tx)
                self._send_json({"ok": True, "tx": tx.get("payload", tx)})
                self.node.publish_event("task.dispute", {"tx_id": tx.get("id", ""), "task_id": task_id})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/public/governance/propose":
                wallet_name = str(payload.get("wallet_name", "")).strip()
                title = str(payload.get("title", "")).strip()
                description = str(payload.get("description", "")).strip()
                param_changes = dict(payload.get("param_changes", {})) if isinstance(payload.get("param_changes", {}), dict) else {}
                vote_window_blocks = int(payload.get("vote_window_blocks", 100))
                if not wallet_name or not title:
                    raise ValueError("wallet_name and title required")
                with self.node.lock:
                    wallet = self._load_signing_wallet(wallet_name)
                    tx = make_governance_propose_tx(wallet, title, description, param_changes, vote_window_blocks)
                    self.node.public_chain.add_transaction(tx)
                tx_payload = tx.get("payload", tx)
                self._send_json({"ok": True, "proposal_id": tx_payload.get("proposal_id", ""), "tx": tx_payload})
                self.node.publish_event("governance.propose", {"tx_id": tx.get("id", ""), "title": title, "proposer": wallet["address"]})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/public/governance/vote":
                wallet_name = str(payload.get("wallet_name", "")).strip()
                proposal_id = str(payload.get("proposal_id", "")).strip()
                vote = bool(payload.get("vote", True))
                if not wallet_name or not proposal_id:
                    raise ValueError("wallet_name and proposal_id required")
                with self.node.lock:
                    wallet = self._load_signing_wallet(wallet_name)
                    tx = make_governance_vote_tx(wallet, proposal_id, vote)
                    self.node.public_chain.add_transaction(tx)
                self._send_json({"ok": True, "tx": tx.get("payload", tx)})
                self.node.publish_event("governance.vote", {"tx_id": tx.get("id", ""), "proposal_id": proposal_id, "vote": vote})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/ui/private/propose":
                wallet_name = str(payload.get("wallet_name", "")).strip()
                action = str(payload.get("action", "")).strip()
                proposal_payload = self.node.resolve_aliases(dict(payload.get("payload", {})))
                wallet = self._load_signing_wallet(wallet_name)
                with self.node.lock:
                    proposal = self.node.private_chain.propose_governance(wallet, action, proposal_payload)
                self._send_json({"ok": True, "proposal": proposal})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/ui/private/approve":
                wallet_name = str(payload.get("wallet_name", "")).strip()
                proposal_id = str(payload.get("proposal_id", "")).strip()
                wallet = self._load_signing_wallet(wallet_name)
                with self.node.lock:
                    proposal = self.node.private_chain.approve_governance(proposal_id, wallet)
                self._send_json({"ok": True, "proposal": proposal})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/ui/private/issue":
                wallet = self._load_signing_wallet(str(payload.get("wallet_name", "")).strip())
                owner = self.node.resolve_address_alias(str(payload.get("owner", "")))
                visibility = [self.node.resolve_address_alias(v) for v in payload.get("visibility", [])]
                tx = make_asset_issue_tx(
                    issuer_wallet=wallet,
                    asset_id=str(payload.get("asset_id", "")).strip(),
                    amount=float(payload.get("amount", 0)),
                    owner=owner,
                    domain=str(payload.get("domain", "")).strip(),
                    contract_id=str(payload.get("contract_id", "")).strip(),
                    metadata_hash=str(payload.get("metadata_hash", "")).strip(),
                    metadata=dict(payload.get("metadata", {})) if isinstance(payload.get("metadata", {}), dict) else {},
                    visibility=visibility,
                )
                with self.node.lock:
                    self.node.private_chain.add_transaction(tx)
                self._send_json({"ok": True, "tx": tx})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/ui/private/rwa/tokenize":
                issuer_name = str(payload.get("issuer_wallet_name", "")).strip()
                owner_name = str(payload.get("owner_wallet_name", "")).strip()
                validator_name = str(payload.get("validator_wallet_name", "")).strip()
                notary_name = str(payload.get("notary_wallet_name", "")).strip()
                domain = str(payload.get("domain", "")).strip()
                contract_id = str(payload.get("contract_id", "")).strip()
                asset_id = str(payload.get("asset_id", "")).strip()
                amount = float(payload.get("amount", 0.0))

                if not all([issuer_name, owner_name, validator_name, notary_name, domain, contract_id, asset_id]):
                    raise ValueError(
                        "issuer_wallet_name, owner_wallet_name, validator_wallet_name, notary_wallet_name, domain, contract_id, and asset_id are required."
                    )
                if amount <= 0:
                    raise ValueError("amount must be > 0")

                issuer_wallet = self._load_signing_wallet(issuer_name)
                owner_wallet = self._load_signing_wallet(owner_name)
                validator_wallet = self._load_signing_wallet(validator_name)
                notary_wallet = self._load_signing_wallet(notary_name)

                metadata = dict(payload.get("metadata", {})) if isinstance(payload.get("metadata", {}), dict) else {}
                metadata.setdefault("asset_name", str(payload.get("asset_name", "")).strip())
                metadata.setdefault("asset_type", str(payload.get("asset_type", "")).strip())
                metadata.setdefault("valuation_amount", float(payload.get("valuation_amount", 0.0)))
                metadata.setdefault("valuation_currency", str(payload.get("valuation_currency", "USD")).strip().upper() or "USD")
                metadata.setdefault("jurisdiction", str(payload.get("jurisdiction", "")).strip())
                metadata.setdefault("legal_doc_url", str(payload.get("legal_doc_url", "")).strip())
                metadata.setdefault("issuer_entity", str(payload.get("issuer_entity", "")).strip())
                raw_token_symbol = str(payload.get("token_symbol", metadata.get("token_symbol", ""))).strip().upper()
                if not raw_token_symbol:
                    raw_token_symbol = re.sub(r"[^A-Z0-9]", "", asset_id.upper())[:10] or "RWA"
                metadata["token_symbol"] = raw_token_symbol
                metadata.setdefault("issued_at", time.time())
                token_name = str(payload.get("token_name", "")).strip() or str(metadata.get("asset_name", "")).strip() or f"{asset_id} Token"
                token_decimals = int(payload.get("token_decimals", 18))

                visibility = self._resolve_address_tokens(payload.get("visibility", []))
                if not visibility:
                    visibility = [
                        issuer_wallet["address"],
                        owner_wallet["address"],
                        validator_wallet["address"],
                        notary_wallet["address"],
                    ]

                allow_transfer = bool(payload.get("allow_transfer", True))
                require_visibility = bool(payload.get("require_visibility", False))
                max_transfer_amount = float(payload.get("max_transfer_amount", 0.0) or 0.0)

                rules: Dict[str, Any] = {
                    "allow_transfer": allow_transfer,
                    "require_visibility": require_visibility,
                }
                if max_transfer_amount > 0:
                    rules["max_transfer_amount"] = max_transfer_amount

                metadata_hash = self._compute_metadata_hash(metadata)

                with self.node.lock:
                    self.node.private_chain.register_wallet(
                        validator_wallet,
                        roles=["participant", "validator"],
                        domains=[domain],
                        attributes={"service": "rwa-portal"},
                    )
                    self.node.private_chain.register_wallet(
                        notary_wallet,
                        roles=["participant", "validator", "notary"],
                        domains=[domain],
                        attributes={"service": "rwa-portal"},
                    )
                    self.node.private_chain.register_wallet(
                        issuer_wallet,
                        roles=["participant", "issuer"],
                        domains=[domain],
                        attributes={"service": "rwa-issuer"},
                    )
                    self.node.private_chain.register_wallet(
                        owner_wallet,
                        roles=["participant"],
                        domains=[domain],
                        attributes={"service": "rwa-owner"},
                    )

                    members = sorted(
                        {
                            issuer_wallet["address"],
                            owner_wallet["address"],
                            validator_wallet["address"],
                            notary_wallet["address"],
                            *visibility,
                        }
                    )

                    domain_proposal = self.node.private_chain.propose_governance(
                        validator_wallet,
                        "create_domain",
                        {"domain_id": domain, "members": members},
                    )
                    if not domain_proposal.get("executed"):
                        domain_proposal = self.node.private_chain.approve_governance(domain_proposal["id"], notary_wallet)
                    if not domain_proposal.get("executed"):
                        raise ValueError("create_domain proposal did not execute. Increase validator approvals or lower threshold.")

                    contract_proposal = self.node.private_chain.propose_governance(
                        validator_wallet,
                        "deploy_contract",
                        {
                            "domain_id": domain,
                            "contract_id": contract_id,
                            "rules": rules,
                        },
                    )
                    if not contract_proposal.get("executed"):
                        contract_proposal = self.node.private_chain.approve_governance(contract_proposal["id"], notary_wallet)
                    if not contract_proposal.get("executed"):
                        raise ValueError("deploy_contract proposal did not execute. Increase validator approvals or lower threshold.")

                    tx = make_asset_issue_tx(
                        issuer_wallet=issuer_wallet,
                        asset_id=asset_id,
                        amount=amount,
                        owner=owner_wallet["address"],
                        domain=domain,
                        contract_id=contract_id,
                        metadata_hash=metadata_hash,
                        metadata=metadata,
                        visibility=visibility,
                    )
                    self.node.private_chain.add_transaction(tx)
                    block = self.node.private_chain.seal_pending_transactions(validator_wallet)
                    finality = self.node.private_chain.attest_block(block.hash, notary_wallet, auto_finalize=True)
                    holdings = self.node.private_chain.get_asset_balances(
                        address=owner_wallet["address"],
                        include_pending=True,
                    )
                    summary = self.node.private_chain.domain_summary(domain_id=domain, include_pending=True)
                    token_contract = self.node.upsert_rwa_token_contract(
                        asset_id=asset_id,
                        symbol=raw_token_symbol,
                        name=token_name,
                        decimals=token_decimals,
                        total_supply=amount,
                        issuer=issuer_wallet["address"],
                        owner=owner_wallet["address"],
                        domain=domain,
                        metadata=metadata,
                    )

                self._send_json(
                    {
                        "ok": True,
                        "policy": {
                            "gas_model": "no-gas",
                            "gas_fee_per_tx": 0.0,
                            "settlement_fee_per_tx": 0.0,
                        },
                        "asset": {
                            "asset_id": asset_id,
                            "amount": amount,
                            "owner": owner_wallet["address"],
                            "domain": domain,
                            "contract_id": contract_id,
                            "metadata_hash": metadata_hash,
                            "metadata": metadata,
                            "visibility": visibility,
                            "issue_tx_id": tx.get("id", ""),
                        },
                        "token_contract": token_contract,
                        "block": block.to_dict(),
                        "finality": finality,
                        "owner_holdings": holdings,
                        "domain_summary": summary,
                    }
                )
                self.node.publish_event(
                    "rwa.asset.tokenized",
                    {
                        "asset_id": asset_id,
                        "symbol": raw_token_symbol,
                        "issuer_wallet_name": issuer_name,
                        "owner_wallet_name": owner_name,
                        "deployment_tx_hash": token_contract.get("deployment_tx_hash", ""),
                        "contract_address": token_contract.get("contract_address", ""),
                    },
                )
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/ui/private/rwa/access/create":
                creator_wallet_name = str(payload.get("creator_wallet_name", "")).strip()
                listing_id = str(payload.get("listing_id", "")).strip()
                asset_id = str(payload.get("asset_id", "")).strip()
                domain_id = str(payload.get("domain_id", "")).strip()
                max_uses = _safe_int(str(payload.get("max_uses", "1")), default=1, minimum=1, maximum=1_000_000)
                max_units = max(0.0, float(payload.get("max_units", 0.0)))
                expires_in_seconds = max(0.0, float(payload.get("expires_in_seconds", 0.0)))
                expires_at = float(payload.get("expires_at", 0.0))
                note = str(payload.get("note", "")).strip()
                bind_on_first_use = bool(payload.get("bind_on_first_use", True))

                if not creator_wallet_name:
                    raise ValueError("creator_wallet_name is required.")
                if not listing_id and not asset_id:
                    raise ValueError("listing_id or asset_id is required.")

                with self.node.lock:
                    creator_wallet = self.node.load_named_wallet(creator_wallet_name)
                    listing = None
                    if listing_id:
                        for row in self.node.rwa_listings:
                            if str(row.get("id", "")) == listing_id:
                                listing = row
                                break
                        if listing is None:
                            raise ValueError("Listing not found.")
                        seller_name = str(listing.get("seller_wallet_name", "")).strip()
                        if seller_name and seller_name != creator_wallet_name:
                            raise ValueError("Only the seller wallet can create access IDs for this listing.")
                        if not asset_id:
                            asset_id = str(listing.get("asset_id", "")).strip()
                        if not domain_id:
                            domain_id = str(dict(listing.get("asset_meta", {})).get("domain", "")).strip()
                    if not domain_id and asset_id:
                        _, assets = self.node.private_chain._build_asset_state(include_pending_txs=True)  # pylint: disable=protected-access
                        domain_id = str(dict(assets.get(asset_id, {})).get("domain", "")).strip()

                    if expires_at <= 0 and expires_in_seconds > 0:
                        expires_at = time.time() + expires_in_seconds

                    created = self.node.create_rwa_access_pass(
                        creator_wallet_name=creator_wallet_name,
                        creator_address=creator_wallet["address"],
                        listing_id=listing_id,
                        asset_id=asset_id,
                        domain_id=domain_id,
                        max_uses=max_uses,
                        max_units=max_units,
                        expires_at=expires_at,
                        note=note,
                        bind_on_first_use=bind_on_first_use,
                    )
                self._send_json({"ok": True, **created})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/ui/private/rwa/access/redeem":
                access_code = str(payload.get("access_code", "")).strip()
                buyer_wallet_name = str(payload.get("buyer_wallet_name", "")).strip()
                validator_wallet_name = str(payload.get("validator_wallet_name", "")).strip()
                notary_wallet_name = str(payload.get("notary_wallet_name", "")).strip()

                if not access_code or not buyer_wallet_name or not validator_wallet_name or not notary_wallet_name:
                    raise ValueError(
                        "access_code, buyer_wallet_name, validator_wallet_name, and notary_wallet_name are required."
                    )

                with self.node.lock:
                    row = self.node.resolve_access_pass(access_code)
                    if row is None:
                        raise ValueError("Access ID is invalid.")

                    now = time.time()
                    if float(row.get("expires_at", 0.0)) > 0 and now >= float(row.get("expires_at", 0.0)):
                        row["status"] = "expired"
                        row["updated_at"] = now
                        self.node._save_rwa_access_passes()
                        raise ValueError("Access ID has expired.")
                    if str(row.get("status", "active")) != "active":
                        raise ValueError("Access ID is not active.")

                    buyer_wallet = self.node.load_named_wallet(buyer_wallet_name)
                    validator_wallet = self.node.load_named_wallet(validator_wallet_name)
                    notary_wallet = self.node.load_named_wallet(notary_wallet_name)

                    bound_wallet = str(row.get("bound_wallet_name", "")).strip()
                    bound_address = str(row.get("bound_wallet_address", "")).strip()
                    if bound_wallet and bound_wallet != buyer_wallet_name:
                        raise ValueError(f"Access ID is already bound to wallet '{bound_wallet}'.")
                    if bound_address and bound_address != buyer_wallet["address"]:
                        raise ValueError("Access ID is already bound to another wallet address.")
                    if not bound_wallet and bool(row.get("bind_on_first_use", True)):
                        row["bound_wallet_name"] = buyer_wallet_name
                        row["bound_wallet_address"] = buyer_wallet["address"]

                    domain_id = str(row.get("domain_id", "")).strip()
                    if not domain_id:
                        listing_id = str(row.get("listing_id", "")).strip()
                        if listing_id:
                            listing = next((item for item in self.node.rwa_listings if str(item.get("id", "")) == listing_id), None)
                            if listing:
                                domain_id = str(dict(listing.get("asset_meta", {})).get("domain", "")).strip()
                    if domain_id:
                        self.node.private_chain.register_wallet(
                            buyer_wallet,
                            roles=["participant"],
                            domains=[domain_id],
                            attributes={"service": "rwa-access-id"},
                        )
                        if not self.node.private_chain._domain_has_member(domain_id, buyer_wallet["address"]):  # pylint: disable=protected-access
                            proposal = self.node.private_chain.propose_governance(
                                validator_wallet,
                                "add_domain_member",
                                {"domain_id": domain_id, "member": buyer_wallet["address"]},
                            )
                            if not proposal.get("executed"):
                                proposal = self.node.private_chain.approve_governance(proposal["id"], notary_wallet)
                            if not proposal.get("executed"):
                                raise ValueError("Could not grant domain membership from access ID.")

                    row["updated_at"] = now
                    self.node._save_rwa_access_passes()

                self._send_json(
                    {
                        "ok": True,
                        "pass": self.node._public_access_pass(row),
                        "buyer_wallet_name": buyer_wallet_name,
                        "buyer_address": buyer_wallet["address"],
                        "domain_id": domain_id,
                    }
                )
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/ui/private/rwa/access/revoke":
                pass_id = str(payload.get("pass_id", "")).strip()
                creator_wallet_name = str(payload.get("creator_wallet_name", "")).strip()
                if not pass_id or not creator_wallet_name:
                    raise ValueError("pass_id and creator_wallet_name are required.")
                with self.node.lock:
                    row = next((item for item in self.node.rwa_access_passes if str(item.get("id", "")) == pass_id), None)
                    if row is None:
                        raise ValueError("Access ID not found.")
                    if str(row.get("created_by_wallet_name", "")).strip() != creator_wallet_name:
                        raise ValueError("Only the creator wallet can revoke this access ID.")
                    row["status"] = "revoked"
                    row["updated_at"] = time.time()
                    self.node._save_rwa_access_passes()
                self._send_json({"ok": True, "pass": self.node._public_access_pass(row)})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/ui/private/rwa/listings/create":
                seller_wallet_name = str(payload.get("seller_wallet_name", "")).strip()
                asset_id = str(payload.get("asset_id", "")).strip()
                quantity = float(payload.get("quantity", 0.0))
                price_per_unit = float(payload.get("price_per_unit", 0.0))
                settlement_asset_id = str(
                    payload.get("settlement_asset_id", payload.get("settlement_token", self._rwa_settlement_asset_id()))
                ).strip().upper() or self._rwa_settlement_asset_id()
                currency = str(payload.get("currency", settlement_asset_id)).strip().upper() or settlement_asset_id
                title = str(payload.get("title", "")).strip()
                description = str(payload.get("description", "")).strip()
                visibility = self._resolve_address_tokens(payload.get("visibility", []))
                access_mode = str(payload.get("access_mode", "open")).strip().lower() or "open"

                if not seller_wallet_name or not asset_id:
                    raise ValueError("seller_wallet_name and asset_id are required.")
                if quantity <= 0:
                    raise ValueError("quantity must be > 0")
                if price_per_unit <= 0:
                    raise ValueError("price_per_unit must be > 0")
                if access_mode not in {"open", "access_id"}:
                    raise ValueError("access_mode must be 'open' or 'access_id'.")

                with self.node.lock:
                    seller_wallet = self.node.load_named_wallet(seller_wallet_name)
                    seller_address = seller_wallet["address"]
                    seller_holdings = self.node.private_chain.get_asset_balances(
                        address=seller_address,
                        include_pending=True,
                    ).get(seller_address, {})
                    available = float(seller_holdings.get(asset_id, 0.0))
                    if available + 1e-12 < quantity:
                        raise ValueError(
                            f"Insufficient seller balance for listing. Available={available}, requested={quantity}."
                        )

                    _, assets = self.node.private_chain._build_asset_state(include_pending_txs=True)  # pylint: disable=protected-access
                    asset_meta = dict(assets.get(asset_id, {}))
                    policy = self._normalize_rwa_trade_policy(
                        raw_policy=payload.get("policy", {}),
                        access_mode=access_mode,
                    )
                    now = time.time()
                    listing = {
                        "id": "LST-" + hashlib.sha256(
                            f"{seller_address}:{asset_id}:{now}:{len(self.node.rwa_listings)}".encode("utf-8")
                        ).hexdigest()[:16],
                        "status": "open",
                        "created_at": now,
                        "updated_at": now,
                        "seller_wallet_name": seller_wallet_name,
                        "seller_address": seller_address,
                        "asset_id": asset_id,
                        "title": title or asset_id,
                        "description": description,
                        "currency": currency,
                        "settlement_asset_id": settlement_asset_id,
                        "price_per_unit": price_per_unit,
                        "quantity_total": quantity,
                        "quantity_available": quantity,
                        "visibility": visibility,
                        "access_mode": access_mode,
                        "policy": policy,
                        "asset_meta": asset_meta,
                        "trades": [],
                    }
                    self.node.rwa_listings.append(listing)
                    self.node._save_rwa_listings()

                self._send_json({"ok": True, "listing": listing})
                self.node.publish_event(
                    "rwa.listing.created",
                    {
                        "listing_id": listing.get("id", ""),
                        "asset_id": asset_id,
                        "seller_wallet_name": seller_wallet_name,
                        "quantity": quantity,
                        "price_per_unit": price_per_unit,
                    },
                )
                return

            if path == "/ui/private/rwa/fund":
                issuer_wallet_name = str(payload.get("issuer_wallet_name", "")).strip()
                recipient_wallet_name = str(payload.get("recipient_wallet_name", "")).strip()
                validator_wallet_name = str(payload.get("validator_wallet_name", "")).strip()
                notary_wallet_name = str(payload.get("notary_wallet_name", "")).strip()
                amount = float(payload.get("amount", 0.0))
                asset_id = str(payload.get("asset_id", self._rwa_settlement_asset_id())).strip().upper() or self._rwa_settlement_asset_id()
                domain = str(payload.get("domain", "jito-settlement")).strip() or "jito-settlement"
                contract_id = str(payload.get("contract_id", "jito-settlement-v1")).strip() or "jito-settlement-v1"
                visibility = self._resolve_address_tokens(payload.get("visibility", []))

                if not all([issuer_wallet_name, recipient_wallet_name, validator_wallet_name, notary_wallet_name]):
                    raise ValueError(
                        "issuer_wallet_name, recipient_wallet_name, validator_wallet_name, and notary_wallet_name are required."
                    )
                if amount <= 0:
                    raise ValueError("amount must be > 0")

                issuer_wallet = self._load_signing_wallet(issuer_wallet_name)
                recipient_wallet = self._load_signing_wallet(recipient_wallet_name)
                validator_wallet = self._load_signing_wallet(validator_wallet_name)
                notary_wallet = self._load_signing_wallet(notary_wallet_name)

                metadata = {
                    "asset_name": f"{asset_id} Settlement Token",
                    "asset_type": "settlement_token",
                    "token_symbol": asset_id,
                    "price_usd": self._rwa_settlement_price_usd(),
                    "issuer_entity": "Nova Treasury",
                    "issued_at": time.time(),
                }
                metadata_hash = self._compute_metadata_hash(metadata)

                with self.node.lock:
                    self.node.private_chain.register_wallet(
                        validator_wallet,
                        roles=["participant", "validator"],
                        domains=[domain],
                        attributes={"service": "rwa-settlement"},
                    )
                    self.node.private_chain.register_wallet(
                        notary_wallet,
                        roles=["participant", "validator", "notary"],
                        domains=[domain],
                        attributes={"service": "rwa-settlement"},
                    )
                    self.node.private_chain.register_wallet(
                        issuer_wallet,
                        roles=["participant", "issuer"],
                        domains=[domain],
                        attributes={"service": "rwa-settlement-issuer"},
                    )
                    self.node.private_chain.register_wallet(
                        recipient_wallet,
                        roles=["participant"],
                        domains=[domain],
                        attributes={"service": "rwa-settlement-recipient"},
                    )

                    members = sorted(
                        {
                            issuer_wallet["address"],
                            recipient_wallet["address"],
                            validator_wallet["address"],
                            notary_wallet["address"],
                        }
                    )
                    proposal = self.node.private_chain.propose_governance(
                        validator_wallet,
                        "create_domain",
                        {"domain_id": domain, "members": members},
                    )
                    if not proposal.get("executed"):
                        proposal = self.node.private_chain.approve_governance(proposal["id"], notary_wallet)

                    proposal = self.node.private_chain.propose_governance(
                        validator_wallet,
                        "deploy_contract",
                        {
                            "domain_id": domain,
                            "contract_id": contract_id,
                            "rules": {
                                "allow_transfer": True,
                                "require_visibility": False,
                            },
                        },
                    )
                    if not proposal.get("executed"):
                        proposal = self.node.private_chain.approve_governance(proposal["id"], notary_wallet)

                    issue_tx = make_asset_issue_tx(
                        issuer_wallet=issuer_wallet,
                        asset_id=asset_id,
                        amount=amount,
                        owner=recipient_wallet["address"],
                        domain=domain,
                        contract_id=contract_id,
                        metadata_hash=metadata_hash,
                        metadata=metadata,
                        visibility=visibility,
                    )
                    self.node.private_chain.add_transaction(issue_tx)
                    block = self.node.private_chain.seal_pending_transactions(validator_wallet)
                    finality = self.node.private_chain.attest_block(block.hash, notary_wallet, auto_finalize=True)
                    recipient_holdings = self.node.private_chain.get_asset_balances(
                        address=recipient_wallet["address"],
                        include_pending=True,
                    )
                    settlement_contract = self.node.upsert_rwa_token_contract(
                        asset_id=asset_id,
                        symbol=asset_id,
                        name=f"{asset_id} Settlement Token",
                        decimals=int(payload.get("token_decimals", 18)),
                        total_supply=amount,
                        issuer=issuer_wallet["address"],
                        owner=recipient_wallet["address"],
                        domain=domain,
                        metadata=metadata,
                    )

                self._send_json(
                    {
                        "ok": True,
                        "funded": {
                            "asset_id": asset_id,
                            "amount": amount,
                            "recipient_wallet_name": recipient_wallet_name,
                            "recipient_address": recipient_wallet["address"],
                            "domain": domain,
                            "contract_id": contract_id,
                            "metadata": metadata,
                        },
                        "token_contract": settlement_contract,
                        "issue_tx": issue_tx,
                        "block": block.to_dict(),
                        "finality": finality,
                        "recipient_holdings": recipient_holdings,
                    }
                )
                self.node.publish_event(
                    "rwa.settlement.funded",
                    {
                        "asset_id": asset_id,
                        "amount": amount,
                        "recipient_wallet_name": recipient_wallet_name,
                        "issue_tx_id": issue_tx.get("id", ""),
                    },
                )
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/ui/private/rwa/listings/buy":
                listing_id = str(payload.get("listing_id", "")).strip()
                buyer_wallet_name = str(payload.get("buyer_wallet_name", "")).strip()
                quantity = float(payload.get("quantity", 0.0))
                validator_wallet_name = str(payload.get("validator_wallet_name", "")).strip()
                notary_wallet_name = str(payload.get("notary_wallet_name", "")).strip()
                visibility = self._resolve_address_tokens(payload.get("visibility", []))
                access_code = str(payload.get("access_code", "")).strip()

                if not listing_id or not buyer_wallet_name or not validator_wallet_name or not notary_wallet_name:
                    raise ValueError("listing_id, buyer_wallet_name, validator_wallet_name, and notary_wallet_name are required.")
                if quantity <= 0:
                    raise ValueError("quantity must be > 0")

                with self.node.lock:
                    listing = None
                    for row in self.node.rwa_listings:
                        if str(row.get("id", "")) == listing_id:
                            listing = row
                            break
                    if listing is None:
                        raise ValueError("Listing not found.")
                    if str(listing.get("status", "open")) != "open":
                        raise ValueError("Listing is not open.")
                    if float(listing.get("quantity_available", 0.0)) + 1e-12 < quantity:
                        raise ValueError("Requested quantity exceeds listing availability.")

                    seller_wallet = self._load_signing_wallet(str(listing.get("seller_wallet_name", "")).strip())
                    buyer_wallet = self._load_signing_wallet(buyer_wallet_name)
                    validator_wallet = self._load_signing_wallet(validator_wallet_name)
                    notary_wallet = self._load_signing_wallet(notary_wallet_name)

                    asset_id = str(listing.get("asset_id", "")).strip()
                    seller_address = seller_wallet["address"]
                    buyer_address = buyer_wallet["address"]
                    access_mode = str(listing.get("access_mode", "open")).strip().lower() or "open"
                    policy = self._normalize_rwa_trade_policy(
                        raw_policy=listing.get("policy", {}),
                        access_mode=access_mode,
                    )
                    listing["policy"] = policy
                    access_pass: Optional[Dict[str, Any]] = None

                    seller_holdings = self.node.private_chain.get_asset_balances(
                        address=seller_address,
                        include_pending=True,
                    ).get(seller_address, {})
                    seller_available = float(seller_holdings.get(asset_id, 0.0))
                    if seller_available + 1e-12 < quantity:
                        raise ValueError(
                            f"Seller no longer has enough asset units. Available={seller_available}, requested={quantity}."
                        )

                    self._assert_rwa_trade_policy(
                        policy=policy,
                        buyer_wallet_name=buyer_wallet_name,
                        buyer_address=buyer_address,
                        quantity=quantity,
                        access_code=access_code,
                    )

                    settlement_asset_id = str(
                        listing.get("settlement_asset_id", payload.get("settlement_asset_id", self._rwa_settlement_asset_id()))
                    ).strip().upper() or self._rwa_settlement_asset_id()
                    settlement_currency = str(listing.get("currency", settlement_asset_id)).strip().upper() or settlement_asset_id
                    gross_trade_value = quantity * float(listing.get("price_per_unit", 0.0))
                    if settlement_currency in {settlement_asset_id, "NOVA"}:
                        settlement_amount = gross_trade_value
                    elif settlement_currency == "USD":
                        peg = self._rwa_settlement_price_usd()
                        if peg <= 0:
                            raise ValueError("Invalid settlement token USD price configuration.")
                        settlement_amount = gross_trade_value / peg
                    else:
                        raise ValueError(
                            f"Unsupported listing currency '{settlement_currency}'. Use {settlement_asset_id} or USD."
                        )

                    holdings, assets = self.node.private_chain._build_asset_state(include_pending_txs=True)  # pylint: disable=protected-access

                    asset_meta = dict(assets.get(asset_id, {}))
                    asset_domain = str(asset_meta.get("domain", "")).strip()
                    if not asset_domain:
                        raise ValueError("Asset domain metadata missing for listing asset.")

                    def _ensure_domain_member(domain_id: str, member_address: str, label: str) -> None:
                        if self.node.private_chain._domain_has_member(domain_id, member_address):  # pylint: disable=protected-access
                            return
                        proposal = self.node.private_chain.propose_governance(
                            validator_wallet,
                            "add_domain_member",
                            {"domain_id": domain_id, "member": member_address},
                        )
                        if not proposal.get("executed"):
                            proposal = self.node.private_chain.approve_governance(proposal["id"], notary_wallet)
                        if not proposal.get("executed"):
                            raise ValueError(f"Could not add {label} to domain '{domain_id}'.")

                    if access_mode == "access_id":
                        if not access_code:
                            raise ValueError("This listing requires an Access ID.")
                        access_pass = self.node.resolve_access_pass(access_code)
                        if access_pass is None:
                            raise ValueError("Access ID is invalid.")
                        now = time.time()
                        if float(access_pass.get("expires_at", 0.0)) > 0 and now >= float(access_pass.get("expires_at", 0.0)):
                            access_pass["status"] = "expired"
                            access_pass["updated_at"] = now
                            self.node._save_rwa_access_passes()
                            raise ValueError("Access ID has expired.")
                        if str(access_pass.get("status", "active")).strip() != "active":
                            raise ValueError("Access ID is not active.")

                        pass_listing_id = str(access_pass.get("listing_id", "")).strip()
                        pass_asset_id = str(access_pass.get("asset_id", "")).strip()
                        pass_domain_id = str(access_pass.get("domain_id", "")).strip()
                        if pass_listing_id and pass_listing_id != listing_id:
                            raise ValueError("Access ID does not apply to this listing.")
                        if pass_asset_id and pass_asset_id != asset_id:
                            raise ValueError("Access ID does not apply to this asset.")
                        if pass_domain_id and pass_domain_id != asset_domain:
                            raise ValueError("Access ID domain does not match listing domain.")

                        bound_wallet_name = str(access_pass.get("bound_wallet_name", "")).strip()
                        bound_wallet_address = str(access_pass.get("bound_wallet_address", "")).strip()
                        if bound_wallet_name and bound_wallet_name != buyer_wallet_name:
                            raise ValueError(f"Access ID is already bound to wallet '{bound_wallet_name}'.")
                        if bound_wallet_address and bound_wallet_address != buyer_address:
                            raise ValueError("Access ID is already bound to another wallet address.")
                        if not bound_wallet_name and bool(access_pass.get("bind_on_first_use", True)):
                            access_pass["bound_wallet_name"] = buyer_wallet_name
                            access_pass["bound_wallet_address"] = buyer_address

                        max_uses = int(access_pass.get("max_uses", 1))
                        used_count = int(access_pass.get("used_count", 0))
                        if max_uses > 0 and used_count >= max_uses:
                            raise ValueError("Access ID usage limit reached.")

                        max_units = float(access_pass.get("max_units", 0.0))
                        units_used = float(access_pass.get("units_used", 0.0))
                        if max_units > 0 and units_used + quantity > max_units + 1e-12:
                            remaining = max(0.0, max_units - units_used)
                            raise ValueError(
                                f"Access ID unit allowance exceeded. Remaining allowed units={remaining}."
                            )

                    # Ensure delivery domain membership for both legs.
                    _ensure_domain_member(asset_domain, seller_address, "seller")
                    _ensure_domain_member(asset_domain, buyer_address, "buyer")

                    settlement_meta = assets.get(settlement_asset_id, {})
                    if not settlement_meta:
                        raise ValueError(
                            f"Settlement token '{settlement_asset_id}' is not issued yet. Fund buyer first using /ui/private/rwa/fund."
                        )
                    settlement_domain = str(settlement_meta.get("domain", "")).strip()
                    if not settlement_domain:
                        raise ValueError("Settlement token domain is missing.")
                    _ensure_domain_member(settlement_domain, seller_address, "seller")
                    _ensure_domain_member(settlement_domain, buyer_address, "buyer")

                    buyer_available = float(holdings.get(buyer_address, {}).get(settlement_asset_id, 0.0))
                    if buyer_available + 1e-12 < settlement_amount:
                        raise ValueError(
                            f"Buyer has insufficient {settlement_asset_id}. "
                            f"Available={buyer_available}, required={settlement_amount}. "
                            "Fund buyer first via /ui/private/rwa/fund."
                        )

                    trade_visibility = visibility or list(listing.get("visibility", []))
                    if not trade_visibility:
                        trade_visibility = [seller_address, buyer_address, validator_wallet["address"], notary_wallet["address"]]
                    else:
                        trade_visibility = sorted(
                            {
                                *trade_visibility,
                                seller_address,
                                buyer_address,
                                validator_wallet["address"],
                                notary_wallet["address"],
                            }
                        )

                    settlement_tx = make_asset_transfer_tx(
                        owner_wallet=buyer_wallet,
                        asset_id=settlement_asset_id,
                        amount=settlement_amount,
                        recipient=seller_address,
                        visibility=trade_visibility,
                    )

                    transfer_tx = make_asset_transfer_tx(
                        owner_wallet=seller_wallet,
                        asset_id=asset_id,
                        amount=quantity,
                        recipient=buyer_address,
                        visibility=trade_visibility,
                    )
                    working_holdings = {addr: dict(vals) for addr, vals in holdings.items()}
                    if not self.node.private_chain._validate_asset_tx(  # pylint: disable=protected-access
                        settlement_tx, working_holdings, assets, check_funds=True
                    ):
                        raise ValueError("Invalid settlement transfer transaction.")
                    self.node.private_chain._apply_asset_tx(settlement_tx, working_holdings, assets)  # pylint: disable=protected-access
                    if not self.node.private_chain._validate_asset_tx(  # pylint: disable=protected-access
                        transfer_tx, working_holdings, assets, check_funds=True
                    ):
                        raise ValueError("Invalid asset delivery transaction.")

                    try:
                        self.node.private_chain.add_transaction(settlement_tx)
                    except Exception as exc:  # pylint: disable=broad-except
                        raise ValueError(f"Settlement enqueue failed: {exc}") from exc
                    try:
                        self.node.private_chain.add_transaction(transfer_tx)
                    except Exception as exc:  # pylint: disable=broad-except
                        raise ValueError(f"Asset delivery enqueue failed: {exc}") from exc
                    sealed = self.node.private_chain.seal_pending_transactions(validator_wallet)
                    finality = self.node.private_chain.attest_block(sealed.hash, notary_wallet, auto_finalize=True)

                    listing["quantity_available"] = max(0.0, float(listing.get("quantity_available", 0.0)) - quantity)
                    listing["status"] = "sold" if listing["quantity_available"] <= 1e-12 else "open"
                    listing["updated_at"] = time.time()
                    listing.setdefault("trades", []).append(
                        {
                            "tx_id": transfer_tx.get("id", ""),
                            "buyer_wallet_name": buyer_wallet_name,
                            "buyer_address": buyer_address,
                            "amount": quantity,
                            "price_per_unit": float(listing.get("price_per_unit", 0.0)),
                            "total_price": quantity * float(listing.get("price_per_unit", 0.0)),
                            "currency": settlement_currency,
                            "settlement_asset_id": settlement_asset_id,
                            "settlement_amount": settlement_amount,
                            "settlement_tx_id": settlement_tx.get("id", ""),
                            "timestamp": time.time(),
                            "block_hash": sealed.hash,
                            "block_index": sealed.index,
                            "finalized": bool(finality.get("finalized", False)),
                            "access_pass_id": str((access_pass or {}).get("id", "")),
                        }
                    )
                    if access_pass is not None:
                        now = time.time()
                        access_pass["used_count"] = int(access_pass.get("used_count", 0)) + 1
                        access_pass["units_used"] = float(access_pass.get("units_used", 0.0)) + quantity
                        access_pass["last_used_at"] = now
                        access_pass["updated_at"] = now
                        max_uses = int(access_pass.get("max_uses", 1))
                        max_units = float(access_pass.get("max_units", 0.0))
                        if (max_uses > 0 and int(access_pass["used_count"]) >= max_uses) or (
                            max_units > 0 and float(access_pass["units_used"]) >= max_units - 1e-12
                        ):
                            access_pass["status"] = "exhausted"
                        self.node._save_rwa_access_passes()
                    self.node._save_rwa_listings()

                self._send_json(
                    {
                        "ok": True,
                        "listing": listing,
                        "settlement_tx": settlement_tx,
                        "transfer_tx": transfer_tx,
                        "block": sealed.to_dict(),
                        "finality": finality,
                        "access_pass": self.node._public_access_pass(access_pass) if access_pass else {},
                    }
                )
                self.node.publish_event(
                    "rwa.trade.executed",
                    {
                        "listing_id": listing_id,
                        "asset_id": asset_id,
                        "buyer_wallet_name": buyer_wallet_name,
                        "seller_wallet_name": listing.get("seller_wallet_name", ""),
                        "quantity": quantity,
                        "settlement_asset_id": settlement_asset_id,
                        "settlement_amount": settlement_amount,
                        "transfer_tx_id": transfer_tx.get("id", ""),
                        "settlement_tx_id": settlement_tx.get("id", ""),
                    },
                )
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/ui/private/rwa/wallet/send":
                from_wallet_name = str(payload.get("from_wallet_name", "")).strip()
                to_value = str(payload.get("to", "")).strip()
                asset_id = str(payload.get("asset_id", "")).strip()
                amount = float(payload.get("amount", 0.0))
                validator_wallet_name = str(payload.get("validator_wallet_name", "")).strip()
                notary_wallet_name = str(payload.get("notary_wallet_name", "")).strip()
                visibility = self._resolve_address_tokens(payload.get("visibility", []))

                if not all([from_wallet_name, to_value, asset_id, validator_wallet_name, notary_wallet_name]):
                    raise ValueError(
                        "from_wallet_name, to, asset_id, validator_wallet_name, and notary_wallet_name are required."
                    )
                if amount <= 0:
                    raise ValueError("amount must be > 0")

                with self.node.lock:
                    from_wallet = self._load_signing_wallet(from_wallet_name)
                    validator_wallet = self._load_signing_wallet(validator_wallet_name)
                    notary_wallet = self._load_signing_wallet(notary_wallet_name)
                    to_address = self.node.resolve_address_alias(to_value)
                    from_address = from_wallet["address"]

                    if to_address == from_address:
                        raise ValueError("sender and recipient must be different.")

                    holdings, assets = self.node.private_chain._build_asset_state(include_pending_txs=True)  # pylint: disable=protected-access
                    asset_meta = assets.get(asset_id)
                    if not asset_meta:
                        raise ValueError(f"Unknown asset_id '{asset_id}'.")
                    domain = str(asset_meta.get("domain", "")).strip()
                    if not domain:
                        raise ValueError("Asset has no associated domain.")

                    self.node.private_chain.register_wallet(
                        from_wallet,
                        roles=["participant"],
                        domains=[domain],
                        attributes={"service": "rwa-wallet"},
                    )
                    to_wallet = self.node.find_wallet_by_address(to_address)
                    if to_address not in self.node.private_chain.participants:
                        if not to_wallet:
                            raise ValueError(
                                "Recipient must be a known wallet/participant. Use @wallet alias or register recipient wallet first."
                            )
                        self.node.private_chain.register_wallet(
                            to_wallet,
                            roles=["participant"],
                            domains=[domain],
                            attributes={"service": "rwa-wallet"},
                        )

                    for member in (from_address, to_address):
                        if not self.node.private_chain._domain_has_member(domain, member):  # pylint: disable=protected-access
                            proposal = self.node.private_chain.propose_governance(
                                validator_wallet,
                                "add_domain_member",
                                {"domain_id": domain, "member": member},
                            )
                            if not proposal.get("executed"):
                                proposal = self.node.private_chain.approve_governance(proposal["id"], notary_wallet)
                            if not proposal.get("executed"):
                                raise ValueError(f"Could not add {member} to domain {domain}.")

                    tx_visibility = visibility or [from_address, to_address, validator_wallet["address"], notary_wallet["address"]]
                    tx_visibility = sorted(
                        {
                            *tx_visibility,
                            from_address,
                            to_address,
                            validator_wallet["address"],
                            notary_wallet["address"],
                        }
                    )
                    transfer_tx = make_asset_transfer_tx(
                        owner_wallet=from_wallet,
                        asset_id=asset_id,
                        amount=amount,
                        recipient=to_address,
                        visibility=tx_visibility,
                    )
                    self.node.private_chain.add_transaction(transfer_tx)
                    sealed = self.node.private_chain.seal_pending_transactions(validator_wallet)
                    finality = self.node.private_chain.attest_block(sealed.hash, notary_wallet, auto_finalize=True)
                    sender_holdings = self.node.private_chain.get_asset_balances(address=from_address, include_pending=True)
                    recipient_holdings = self.node.private_chain.get_asset_balances(address=to_address, include_pending=True)

                self._send_json(
                    {
                        "ok": True,
                        "tx": transfer_tx,
                        "block": sealed.to_dict(),
                        "finality": finality,
                        "sender_holdings": sender_holdings,
                        "recipient_holdings": recipient_holdings,
                    }
                )
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/ui/private/transfer":
                wallet = self._load_signing_wallet(str(payload.get("wallet_name", "")).strip())
                recipient = self.node.resolve_address_alias(str(payload.get("to", "")))
                visibility = [self.node.resolve_address_alias(v) for v in payload.get("visibility", [])]
                tx = make_asset_transfer_tx(
                    owner_wallet=wallet,
                    asset_id=str(payload.get("asset_id", "")).strip(),
                    amount=float(payload.get("amount", 0)),
                    recipient=recipient,
                    visibility=visibility,
                )
                with self.node.lock:
                    self.node.private_chain.add_transaction(tx)
                self._send_json({"ok": True, "tx": tx})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/ui/private/seal":
                wallet = self._load_signing_wallet(str(payload.get("wallet_name", "")).strip())
                with self.node.lock:
                    block = self.node.private_chain.seal_pending_transactions(wallet)
                self._send_json({"ok": True, "block": block.to_dict()})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/ui/private/attest":
                wallet = self._load_signing_wallet(str(payload.get("wallet_name", "")).strip())
                block_hash = str(payload.get("block_hash", "")).strip()
                if not block_hash:
                    if not self.node.private_chain.pending_blocks:
                        if self.node.private_chain.chain:
                            latest_hash = self.node.private_chain.chain[-1].hash
                            finalized = self.node.private_chain.finality_records.get(latest_hash)
                            if finalized:
                                out = dict(finalized)
                                out["finalized"] = True
                                out["already_finalized"] = True
                                out["block_hash"] = latest_hash
                                self._send_json({"ok": True, "finality": out})
                                return
                        raise ValueError("No pending private blocks to attest.")
                    block_hash = self.node.private_chain.pending_blocks[0].hash
                with self.node.lock:
                    finality = self.node.private_chain.attest_block(block_hash, wallet, auto_finalize=True)
                self._send_json({"ok": True, "finality": finality})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/public/tx":
                with self.node.lock:
                    self.node.public_chain.add_transaction(payload)
                self._send_json({"ok": True, "tx_id": payload.get("id")})
                self.node.publish_event(
                    "public.tx.queued",
                    {
                        "tx_id": payload.get("id", ""),
                        "sender": payload.get("sender", ""),
                        "recipient": payload.get("recipient", ""),
                        "amount": payload.get("amount", 0.0),
                        "source": "api",
                    },
                )
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/public/auto-mine/start":
                miner = str(payload.get("miner", "")).strip()
                interval_seconds = float(payload.get("interval_seconds", 8.0))
                allow_empty_blocks = bool(payload.get("allow_empty_blocks", False))
                status = self.node.start_auto_mining(
                    miner=miner,
                    interval_seconds=interval_seconds,
                    allow_empty_blocks=allow_empty_blocks,
                )
                self.node.publish_event("public.auto_mine.started", status)
                self._send_json({"ok": True, "auto_mine": status})
                return

            if path == "/public/auto-mine/stop":
                status = self.node.stop_auto_mining()
                self.node.publish_event("public.auto_mine.stopped", status)
                self._send_json({"ok": True, "auto_mine": status})
                return

            if path == "/public/faucet/claim":
                recipient = str(payload.get("to", payload.get("address", ""))).strip()
                amount = float(payload.get("amount", 0.0))
                with self.node.lock:
                    out = self.node.claim_public_faucet(recipient, amount=amount)
                self._send_json(out)
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/public/mine":
                miner = str(payload.get("miner", ""))
                with self.node.lock:
                    block = self.node.public_chain.mine_pending_transactions(miner)
                self._send_json({"ok": True, "block": block.to_dict()})
                self.node.publish_event(
                    "public.block.mined",
                    {
                        "source": "manual-api",
                        "block_index": block.index,
                        "block_hash": block.hash,
                        "validator": str(block.meta.get("validator", "")),
                        "tx_count": len(block.transactions),
                    },
                )
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/public/oracle/register":
                oracle = str(payload.get("oracle", "")).strip()
                with self.node.lock:
                    self.node.public_chain.register_price_oracle(oracle)
                self._send_json({"ok": True, "oracle": oracle})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            # ── Universal agent webhook ───────────────────────────────────────
            # No-code platforms (n8n, Flowise, OpenClaw, Zapier, curl) POST here.
            # The node signs on behalf of a pre-registered server-side wallet.
            # Payload: {agent_id, action_type, success, tags, note, api_key}
            if path == "/public/agent/webhook":
                import hashlib as _hashlib, secrets as _secrets, time as _time
                from dual_chain import make_agent_activity_log_tx as _make_log_tx
                webhook_key = os.environ.get("WEBHOOK_API_KEY", "")
                if webhook_key:
                    if str(payload.get("api_key", "")) != webhook_key:
                        self._send_json({"ok": False, "error": "Invalid api_key"}, HTTPStatus.UNAUTHORIZED)
                        return
                webhook_wallet_path = os.environ.get("WEBHOOK_WALLET_PATH", "webhook_wallet.json")
                if not os.path.exists(webhook_wallet_path):
                    self._send_json({"ok": False, "error": "Webhook wallet not configured. Set WEBHOOK_WALLET_PATH."}, HTTPStatus.SERVICE_UNAVAILABLE)
                    return
                with open(webhook_wallet_path) as _wf:
                    import json as _json
                    webhook_wallet = _json.load(_wf)
                agent_id = str(payload.get("agent_id", "webhook-agent")).strip()
                action_type = str(payload.get("action_type", "task_completed")).strip()
                success = bool(payload.get("success", True))
                tags = list(payload.get("tags") or [])
                note = str(payload.get("note", ""))[:256]
                duration_ms = int(payload.get("duration_ms", 0))
                tx = _make_log_tx(
                    agent_wallet=webhook_wallet, agent_id=agent_id, action_type=action_type,
                    success=success, tags=tags, note=note, duration_ms=duration_ms,
                )
                with self.node.lock:
                    self.node.public_chain.add_transaction(tx)
                self._send_json({"ok": True, "tx_id": tx.get("id"), "agent": webhook_wallet["address"]})
                return

            if path == "/public/validators/add":
                validator = str(payload.get("validator", "")).strip()
                with self.node.lock:
                    self.node.public_chain.add_validator(validator)
                self._send_json({"ok": True, "validator": validator, "validators": sorted(self.node.public_chain.validators)})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/public/validators/remove":
                validator = str(payload.get("validator", "")).strip()
                with self.node.lock:
                    self.node.public_chain.remove_validator(validator)
                self._send_json({"ok": True, "validator": validator, "validators": sorted(self.node.public_chain.validators)})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/public/price/update":
                with self.node.lock:
                    self.node.public_chain.add_transaction(payload)
                self._send_json({"ok": True, "tx_id": payload.get("id")})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/private/register":
                wallet = payload.get("wallet")
                roles = payload.get("roles", ["participant"])
                domains = payload.get("domains", [])
                attributes = payload.get("attributes", {})
                if not wallet:
                    raise ValueError("wallet is required")
                with self.node.lock:
                    self.node.private_chain.register_wallet(wallet, roles, domains, attributes)
                self._send_json({"ok": True})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/private/propose":
                wallet = payload.get("wallet")
                action = str(payload.get("action", ""))
                proposal_payload = dict(payload.get("payload", {}))
                if not wallet or not action:
                    raise ValueError("wallet and action are required")
                with self.node.lock:
                    proposal = self.node.private_chain.propose_governance(wallet, action, proposal_payload)
                self._send_json({"ok": True, "proposal": proposal})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/private/approve":
                wallet = payload.get("wallet")
                proposal_id = str(payload.get("proposal_id", ""))
                if not wallet or not proposal_id:
                    raise ValueError("wallet and proposal_id are required")
                with self.node.lock:
                    proposal = self.node.private_chain.approve_governance(proposal_id, wallet)
                self._send_json({"ok": True, "proposal": proposal})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/private/tx":
                with self.node.lock:
                    self.node.private_chain.add_transaction(payload)
                self._send_json({"ok": True, "tx_id": payload.get("id")})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/private/seal":
                wallet = payload.get("validator_wallet")
                if not wallet:
                    raise ValueError("validator_wallet is required")
                with self.node.lock:
                    block = self.node.private_chain.seal_pending_transactions(wallet)
                self._send_json({"ok": True, "block": block.to_dict()})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/private/attest":
                wallet = payload.get("notary_wallet")
                block_hash = str(payload.get("block_hash", ""))
                if not wallet or not block_hash:
                    raise ValueError("notary_wallet and block_hash are required")
                with self.node.lock:
                    finality = self.node.private_chain.attest_block(block_hash, wallet, auto_finalize=True)
                self._send_json({"ok": True, "finality": finality})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/private/finalize":
                block_hash = str(payload.get("block_hash", ""))
                if not block_hash:
                    raise ValueError("block_hash is required")
                with self.node.lock:
                    block = self.node.private_chain.finalize_block(block_hash, fail_if_insufficient=True)
                self._send_json({"ok": True, "block": block.to_dict() if block else None})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/public/validator/nominate":
                wallet_name = str(payload.get("wallet", "")).strip()
                if not wallet_name:
                    raise ValueError("wallet required")
                with self.node.lock:
                    wallet = self._load_signing_wallet(wallet_name)
                    stake_amount = float(payload.get("stake_amount", 500.0))
                    tx = make_validator_nominate_tx(wallet, stake_amount=stake_amount)
                    self.node.public_chain.add_transaction(tx)
                self._send_json({"status": "ok", "tx": tx["payload"]})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/public/validator/vote":
                wallet_name = str(payload.get("wallet", "")).strip()
                candidate = str(payload.get("candidate", payload.get("candidate_address", ""))).strip()
                if not wallet_name or not candidate:
                    raise ValueError("wallet and candidate required")
                with self.node.lock:
                    wallet = self._load_signing_wallet(wallet_name)
                    tx = make_validator_election_vote_tx(wallet, candidate)
                    self.node.public_chain.add_transaction(tx)
                self._send_json({"status": "ok", "tx": tx["payload"]})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/public/validator/unstake":
                wallet_name = str(payload.get("wallet", "")).strip()
                if not wallet_name:
                    raise ValueError("wallet required")
                with self.node.lock:
                    wallet = self._load_signing_wallet(wallet_name)
                    tx = make_validator_unstake_tx(wallet)
                    self.node.public_chain.add_transaction(tx)
                self._send_json({"status": "ok", "tx_id": tx["payload"].get("nonce", "")})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/public/oracle/assign":
                wallet_name = str(payload.get("wallet", "")).strip()
                asset_id = str(payload.get("asset_id", "")).strip()
                agent_id = str(payload.get("agent_id", ""))
                oracle_type = str(payload.get("oracle_type", "price"))
                if not wallet_name or not asset_id:
                    raise ValueError("wallet and asset_id required")
                with self.node.lock:
                    wallet = self._load_signing_wallet(wallet_name)
                    tx = make_ai_oracle_assign_tx(wallet, asset_id, agent_id, oracle_type)
                    self.node.public_chain.add_transaction(tx)
                self._send_json({"status": "ok", "tx": tx["payload"]})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/public/oracle/event":
                wallet_name = str(payload.get("wallet", "")).strip()
                asset_id = str(payload.get("asset_id", "")).strip()
                event_type = str(payload.get("event_type", "price_update"))
                value = str(payload.get("value", ""))
                note = str(payload.get("note", ""))
                if not wallet_name or not asset_id:
                    raise ValueError("wallet and asset_id required")
                with self.node.lock:
                    wallet = self._load_signing_wallet(wallet_name)
                    tx = make_ai_oracle_event_tx(wallet, asset_id, event_type, value, note)
                    self.node.public_chain.add_transaction(tx)
                self._send_json({"status": "ok", "tx": tx["payload"]})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/public/model/register":
                wallet_name = str(payload.get("wallet", "")).strip()
                model_id = str(payload.get("model_id", "")).strip() or f"model_{secrets.token_hex(4)}"
                name = str(payload.get("name", "")).strip()
                if not wallet_name or not name:
                    raise ValueError("wallet and name required")
                with self.node.lock:
                    wallet = self._load_signing_wallet(wallet_name)
                    tx = make_model_register_tx(wallet, model_id, name,
                        str(payload.get("description", "")),
                        list(payload.get("capabilities", [])),
                        str(payload.get("version_hash", "")),
                        float(payload.get("inference_fee", 0.0)))
                    self.node.public_chain.add_transaction(tx)
                self._send_json({"status": "ok", "model_id": model_id, "tx": tx["payload"]})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/public/model/transfer":
                wallet_name = str(payload.get("wallet", "")).strip()
                model_id = str(payload.get("model_id", "")).strip()
                new_owner = str(payload.get("new_owner", "")).strip()
                if not wallet_name or not model_id or not new_owner:
                    raise ValueError("wallet, model_id, new_owner required")
                with self.node.lock:
                    wallet = self._load_signing_wallet(wallet_name)
                    tx = make_model_transfer_tx(wallet, model_id, new_owner)
                    self.node.public_chain.add_transaction(tx)
                self._send_json({"status": "ok", "tx": tx["payload"]})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/public/model/revenue-share":
                wallet_name = str(payload.get("wallet", "")).strip()
                model_id = str(payload.get("model_id", "")).strip()
                shares = dict(payload.get("shares", {}))
                if not wallet_name or not model_id:
                    raise ValueError("wallet and model_id required")
                with self.node.lock:
                    wallet = self._load_signing_wallet(wallet_name)
                    tx = make_model_revenue_share_tx(wallet, model_id, shares)
                    self.node.public_chain.add_transaction(tx)
                self._send_json({"status": "ok", "tx": tx["payload"]})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/public/model/inference":
                wallet_name = str(payload.get("wallet", "")).strip()
                model_id = str(payload.get("model_id", "")).strip()
                if not wallet_name or not model_id:
                    raise ValueError("wallet and model_id required")
                with self.node.lock:
                    wallet = self._load_signing_wallet(wallet_name)
                    tx = make_model_inference_tx(wallet, model_id,
                        str(payload.get("input_hash", "")),
                        str(payload.get("output_hash", "")))
                    self.node.public_chain.add_transaction(tx)
                self._send_json({"status": "ok", "tx": tx["payload"]})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/public/pipeline/create":
                wallet_name = str(payload.get("wallet", "")).strip()
                title = str(payload.get("title", "")).strip()
                steps = list(payload.get("steps", []))
                total_reward = float(payload.get("total_reward", 0))
                pipeline_id = str(payload.get("pipeline_id", "")).strip() or f"pipe_{secrets.token_hex(4)}"
                if not wallet_name or not title or not steps or total_reward <= 0:
                    raise ValueError("wallet, title, steps, total_reward required")
                with self.node.lock:
                    wallet = self._load_signing_wallet(wallet_name)
                    tx = make_pipeline_create_tx(wallet, pipeline_id, title, steps, total_reward)
                    self.node.public_chain.add_transaction(tx)
                self._send_json({"status": "ok", "pipeline_id": pipeline_id, "tx": tx["payload"]})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/public/pipeline/step-complete":
                wallet_name = str(payload.get("wallet", "")).strip()
                pipeline_id = str(payload.get("pipeline_id", "")).strip()
                step_index = int(payload.get("step_index", 0))
                if not wallet_name or not pipeline_id:
                    raise ValueError("wallet and pipeline_id required")
                with self.node.lock:
                    wallet = self._load_signing_wallet(wallet_name)
                    tx = make_pipeline_step_complete_tx(wallet, pipeline_id, step_index,
                        str(payload.get("result_hash", "")), str(payload.get("note", "")))
                    self.node.public_chain.add_transaction(tx)
                self._send_json({"status": "ok", "tx": tx["payload"]})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            if path == "/public/pipeline/approve":
                wallet_name = str(payload.get("wallet", "")).strip()
                pipeline_id = str(payload.get("pipeline_id", "")).strip()
                if not wallet_name or not pipeline_id:
                    raise ValueError("wallet and pipeline_id required")
                with self.node.lock:
                    wallet = self._load_signing_wallet(wallet_name)
                    tx = make_pipeline_approve_tx(wallet, pipeline_id,
                        bool(payload.get("approved", True)), str(payload.get("note", "")))
                    self.node.public_chain.add_transaction(tx)
                self._send_json({"status": "ok", "tx": tx["payload"]})
                if not propagated:
                    self.node.broadcast_snapshot(source=self.base_url)
                return

            self._send_json({"error": f"Unknown endpoint: {path}"}, HTTPStatus.NOT_FOUND)
        except Exception as exc:  # pylint: disable=broad-except
            self._send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)


def run_node(
    host: str,
    port: int,
    data_dir: str,
    public_difficulty: int = 3,
    public_reward: float = 25.0,
    public_consensus: str = "pow",
    public_validators: Optional[list[str]] = None,
    public_validator_rotation: bool = True,
    public_finality_confirmations: int = 5,
    public_checkpoint_interval: int = 20,
    public_block_time_target: float = 5.0,
    public_faucet_enabled: bool = False,
    public_faucet_amount: float = 0.0,
    public_faucet_cooldown_seconds: float = 3600.0,
    public_faucet_daily_cap: float = 0.0,
    mainnet_hardening: bool = False,
    chain_name: str = "Nova Network",
    token_name: str = "NOVA",
    token_symbol: str = "NOVA",
    token_decimals: int = 18,
    chain_logo_url: str = "",
    token_logo_url: str = "",
    auto_mine: bool = False,
    auto_mine_miner: str = "",
    auto_mine_interval: float = 8.0,
    auto_mine_allow_empty: bool = False,
    peers: Optional[list[str]] = None,
    peer_token: str = "",
    peer_sync_enabled: bool = True,
    peer_sync_interval_seconds: float = 6.0,
    peer_lag_resync_threshold: int = 3,
    strict_public_signatures: bool = True,
    public_mempool_ttl_seconds: float = 900.0,
    public_mempool_max_transactions: int = 5000,
    public_pow_workers: int = 1,
    public_pow_nonce_chunk_size: int = 10000,
    require_hsm_signers: bool = False,
    jwt_secret: str = "",
    jwt_required: bool = False,
    rate_limit_per_minute: int = 300,
    rate_limit_tiers: Optional[Dict[str, int]] = None,
    api_key_tier_map: Optional[Dict[str, str]] = None,
    tls_cert: str = "",
    tls_key: str = "",
    tls_ca: str = "",
    tls_require_client_cert: bool = False,
    peer_ca: str = "",
) -> None:
    peer_ssl_context: Optional[ssl.SSLContext] = None
    if peer_ca:
        peer_ssl_context = ssl.create_default_context(cafile=peer_ca)

    node = DualChainNode(
        data_dir=data_dir,
        public_difficulty=public_difficulty,
        public_reward=public_reward,
        public_consensus=public_consensus,
        public_validators=public_validators or [],
        public_validator_rotation=public_validator_rotation,
        public_finality_confirmations=public_finality_confirmations,
        public_checkpoint_interval=public_checkpoint_interval,
        public_block_time_target=public_block_time_target,
        public_faucet_enabled=public_faucet_enabled,
        public_faucet_amount=public_faucet_amount,
        public_faucet_cooldown_seconds=public_faucet_cooldown_seconds,
        public_faucet_daily_cap=public_faucet_daily_cap,
        mainnet_hardening=mainnet_hardening,
        peer_token=peer_token,
        peer_ssl_context=peer_ssl_context,
        peer_sync_enabled=peer_sync_enabled,
        peer_sync_interval_seconds=peer_sync_interval_seconds,
        peer_lag_resync_threshold=peer_lag_resync_threshold,
        strict_public_signatures=strict_public_signatures,
        public_mempool_ttl_seconds=public_mempool_ttl_seconds,
        public_mempool_max_transactions=public_mempool_max_transactions,
        public_pow_workers=public_pow_workers,
        public_pow_nonce_chunk_size=public_pow_nonce_chunk_size,
        require_hsm_signers=require_hsm_signers,
    )

    configured_validators = sorted(
        {
            node.public_chain._normalize_address(str(v).strip())  # pylint: disable=protected-access
            for v in (public_validators or [])
            if str(v).strip()
        }
    )
    if node.public_chain.consensus == "poa" and configured_validators:
        missing = [v for v in configured_validators if v not in node.public_chain.validators]
        for validator in missing:
            node.public_chain.add_validator(validator)
        if missing:
            print(f"Validator bootstrap: added {len(missing)} missing validator(s) from config: {missing}")

    for peer in peers or []:
        node.add_peer(peer)

    NodeHandler.node = node
    NodeHandler.ui_html = load_html("web_ui.html", "UI")
    NodeHandler.explorer_html = load_html("explorer_ui.html", "Explorer")
    NodeHandler.scanner_html = load_html("scanner_ui.html", "Scanner")
    NodeHandler.rwa_html = load_html("rwa_ui.html", "RWA Portal")
    NodeHandler.rwa_market_html = load_html("rwa_market_ui.html", "RWA Market")
    NodeHandler.app_hub_html = load_html("app_hub_ui.html", "App Hub")
    NodeHandler.community_html = load_html("community_ui.html", "Community")
    NodeHandler.passport_html = load_html("passport_ui.html", "Passport")
    NodeHandler.start_html = load_html("start_ui.html", "Get Started")
    NodeHandler.jwt_secret = jwt_secret
    NodeHandler.jwt_required = jwt_required
    NodeHandler.rate_limit_per_minute = max(0, int(rate_limit_per_minute))
    NodeHandler.rate_limit_tiers = {
        str(k).strip().lower(): max(0, int(v))
        for k, v in dict(rate_limit_tiers or {}).items()
        if str(k).strip()
    }
    if "default" not in NodeHandler.rate_limit_tiers:
        NodeHandler.rate_limit_tiers["default"] = NodeHandler.rate_limit_per_minute
    NodeHandler.api_key_tier_map = {
        str(k): str(v).strip().lower()
        for k, v in dict(api_key_tier_map or {}).items()
        if str(k).strip() and str(v).strip()
    }
    NodeHandler.rate_limit_state = {}
    NodeHandler.chain_info = {
        "network_name": chain_name,
        "branding": {
            "chain_logo_url": chain_logo_url,
            "token_logo_url": token_logo_url,
        },
        "public_chain": {
            "name": chain_name,
            "consensus": node.public_chain.consensus,
            "difficulty": node.public_chain.difficulty,
            "pow_parallel_workers": node.public_chain.pow_parallel_workers,
            "pow_nonce_chunk_size": node.public_chain.pow_nonce_chunk_size,
            "block_reward": node.public_chain.mining_reward,
            "validator_count": len(node.public_chain.validators),
            "validators": sorted(node.public_chain.validators),
            "validator_rotation": node.public_chain.validator_rotation_enabled,
            "finality_confirmations": node.public_chain.finality_confirmations,
            "checkpoint_interval": node.public_chain.checkpoint_interval,
            "logo_url": chain_logo_url,
            "native_token": {
                "name": token_name,
                "symbol": token_symbol,
                "decimals": int(token_decimals),
                "gas_token": True,
                "logo_url": token_logo_url,
            },
        },
        "private_chain": {
            "name": f"{chain_name} Private RWA",
            "consensus": "validator-seal + notary-attest",
            "gas_model": "no-gas",
            "gas_fee_per_tx": 0.0,
            "rwa_open_listings": len([row for row in node.rwa_listings if str(row.get("status", "open")) == "open"]),
            "ai_models": len(node.private_chain.model_registry),
            "ai_jobs": len(node.private_chain.ai_jobs),
        },
    }

    server = ThreadingHTTPServer((host, port), NodeHandler)

    scheme = "http"
    if tls_cert and tls_key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=tls_cert, keyfile=tls_key)
        if tls_require_client_cert:
            if not tls_ca:
                raise ValueError("--tls-ca is required when --tls-require-client-cert is enabled.")
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_verify_locations(cafile=tls_ca)
        elif tls_ca:
            ctx.load_verify_locations(cafile=tls_ca)

        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        scheme = "https"

    NodeHandler.base_url = f"{scheme}://{host}:{port}"

    if auto_mine:
        selected_miner = str(auto_mine_miner).strip()
        if not selected_miner and node.public_chain.consensus == "poa":
            if node.public_chain.validator_rotation_enabled and len(node.public_chain.validators) > 1:
                selected_miner = "auto"
            elif len(node.public_chain.validators) == 1:
                selected_miner = sorted(node.public_chain.validators)[0]
        elif not selected_miner and len(node.public_chain.validators) == 1:
            selected_miner = sorted(node.public_chain.validators)[0]
        if not selected_miner:
            raise ValueError("--auto-mine-miner is required unless exactly one validator exists.")
        status = node.start_auto_mining(
            miner=selected_miner,
            interval_seconds=auto_mine_interval,
            allow_empty_blocks=auto_mine_allow_empty,
        )
        print(
            "Auto-mine: enabled "
            f"miner={status['miner']} effective={status['effective_miner']} "
            f"follow_rotation={status['follow_rotation']} interval={status['interval_seconds']}s "
            f"allow_empty={status['allow_empty_blocks']}"
        )

    print(f"Node running on {NodeHandler.base_url}")
    print(f"Data directory: {data_dir}")
    print("App Hub: /app")
    print("Investor App: /app/investor")
    print("Issuer App: /app/issuer")
    print("Operator App: /app/operator")
    print("Community Hub: /app/community")
    print("UI: /ui")
    print("RWA Portal: /rwa")
    print("RWA Market: /rwa-market")
    print("RWA Dashboard: /rwa-dashboard")
    print("Explorer: /explorer")
    print("Scanner: /scanner")
    print(
        "Security: "
        f"jwt={'on' if jwt_secret else 'off'} "
        f"jwt_required={jwt_required} "
        f"rate_limit_per_min={NodeHandler.rate_limit_per_minute} "
        f"strict_pub_sig={node.public_chain.strict_signature_validation} "
        f"mempool_ttl={node.public_chain.mempool_tx_ttl_seconds}s "
        f"mempool_max={node.public_chain.mempool_max_transactions} "
        f"pow_workers={node.public_chain.pow_parallel_workers} "
        f"pow_chunk={node.public_chain.pow_nonce_chunk_size} "
        f"hsm_only={node.require_hsm_signers} "
        f"tls={'on' if scheme == 'https' else 'off'} "
        f"mtls_required={tls_require_client_cert}"
    )
    try:
        server.serve_forever()
    finally:
        node.stop_background_workers()
        server.server_close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Dual blockchain node")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--data-dir", default="node_data")
    parser.add_argument("--public-difficulty", type=int, default=3)
    parser.add_argument("--public-reward", type=float, default=25.0)
    parser.add_argument("--public-consensus", choices=["pow", "poa"], default="pow")
    parser.add_argument("--public-validator", action="append", default=[], help="Validator address for poa mode")
    parser.add_argument(
        "--public-validator-rotation",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable strict proposer rotation in poa mode",
    )
    parser.add_argument("--public-finality-confirmations", type=int, default=5, help="Confirmations required for finalized height")
    parser.add_argument("--public-checkpoint-interval", type=int, default=20, help="Finality checkpoint interval")
    parser.add_argument("--public-block-time-target", type=float, default=5.0, help="Target block time metadata in seconds")
    parser.add_argument(
        "--public-faucet-enabled",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Enable built-in public faucet endpoint",
    )
    parser.add_argument("--public-faucet-amount", type=float, default=0.0, help="Default faucet claim amount")
    parser.add_argument("--public-faucet-cooldown", type=float, default=3600.0, help="Cooldown seconds per address")
    parser.add_argument("--public-faucet-daily-cap", type=float, default=0.0, help="24h faucet cap (0 = unlimited)")
    parser.add_argument(
        "--mainnet-hardening",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Enforce production guardrails: poa + >=2 validators + rotation + faucet disabled",
    )
    parser.add_argument("--chain-name", default="Nova Network")
    parser.add_argument("--token-name", default="NOVA")
    parser.add_argument("--token-symbol", default="NOVA")
    parser.add_argument("--token-decimals", type=int, default=18)
    parser.add_argument("--chain-logo-url", default="", help="Brand logo URL for explorer/scanner")
    parser.add_argument("--token-logo-url", default="", help="Native token logo URL for explorer/scanner")
    parser.add_argument("--auto-mine", action="store_true", help="Enable automatic public block production")
    parser.add_argument("--auto-mine-miner", default="", help="Miner/validator address used by auto-miner")
    parser.add_argument("--auto-mine-interval", type=float, default=8.0, help="Auto-miner block interval in seconds")
    parser.add_argument("--auto-mine-allow-empty", action="store_true", help="Allow empty block auto-mining")
    parser.add_argument("--peer", action="append", default=[], help="Peer node URL")
    parser.add_argument("--peer-token", default="", help="Bearer token used for outgoing peer sync calls")
    parser.add_argument(
        "--peer-sync-enabled",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable background peer sync worker",
    )
    parser.add_argument("--peer-sync-interval", type=float, default=6.0, help="Peer sync loop interval in seconds")
    parser.add_argument(
        "--peer-lag-resync-threshold",
        type=int,
        default=3,
        help="Pull snapshot when peer public height exceeds local by this many blocks",
    )
    parser.add_argument(
        "--strict-public-signatures",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Disable legacy public payment signature compatibility path",
    )
    parser.add_argument(
        "--public-mempool-ttl",
        type=float,
        default=900.0,
        help="Pending public tx TTL in seconds (0 disables expiry).",
    )
    parser.add_argument(
        "--public-mempool-max-size",
        type=int,
        default=5000,
        help="Maximum pending public tx in mempool (0 disables cap).",
    )
    parser.add_argument(
        "--public-pow-workers",
        type=int,
        default=1,
        help="Parallel worker processes for PoW nonce search (1 disables parallelism).",
    )
    parser.add_argument(
        "--public-pow-nonce-chunk",
        type=int,
        default=10000,
        help="Nonce attempts per worker batch during parallel PoW search.",
    )
    parser.add_argument(
        "--require-hsm-signers",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Reject local signer wallets for signing operations",
    )

    parser.add_argument("--jwt-secret", default="", help="Shared HS256 secret for JWT verification")
    parser.add_argument("--jwt-required", action="store_true", help="Require JWT for non-UI/non-health endpoints")
    parser.add_argument(
        "--rate-limit-per-minute",
        type=int,
        default=300,
        help="Per-IP request limit per minute for API calls (0 disables)",
    )
    parser.add_argument(
        "--rate-limit-tier",
        action="append",
        default=[],
        help="Rate tier mapping in form tier=limit (repeatable), e.g. agent=1200",
    )
    parser.add_argument(
        "--api-key-tier",
        action="append",
        default=[],
        help="API key to tier mapping in form key:tier (repeatable)",
    )

    parser.add_argument("--tls-cert", default="", help="Server TLS certificate path")
    parser.add_argument("--tls-key", default="", help="Server TLS private key path")
    parser.add_argument("--tls-ca", default="", help="CA bundle path (required for mTLS)")
    parser.add_argument("--tls-require-client-cert", action="store_true", help="Require client cert (mTLS)")
    parser.add_argument("--peer-ca", default="", help="CA file for verifying HTTPS peer certificates")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    tier_map: Dict[str, int] = {}
    for raw in args.rate_limit_tier:
        item = str(raw).strip()
        if not item or "=" not in item:
            raise ValueError("Invalid --rate-limit-tier. Use tier=limit.")
        name, limit_raw = item.split("=", 1)
        tier_name = name.strip().lower()
        if not tier_name:
            raise ValueError("Tier name cannot be empty.")
        tier_map[tier_name] = max(0, int(limit_raw.strip()))

    api_key_map: Dict[str, str] = {}
    for raw in args.api_key_tier:
        item = str(raw).strip()
        if not item or ":" not in item:
            raise ValueError("Invalid --api-key-tier. Use key:tier.")
        key, tier_name = item.split(":", 1)
        key = key.strip()
        tier_name = tier_name.strip().lower()
        if not key or not tier_name:
            raise ValueError("Invalid --api-key-tier. Both key and tier are required.")
        api_key_map[key] = tier_name

    run_node(
        host=args.host,
        port=args.port,
        data_dir=args.data_dir,
        public_difficulty=args.public_difficulty,
        public_reward=args.public_reward,
        public_consensus=args.public_consensus,
        public_validators=args.public_validator,
        public_validator_rotation=args.public_validator_rotation,
        public_finality_confirmations=args.public_finality_confirmations,
        public_checkpoint_interval=args.public_checkpoint_interval,
        public_block_time_target=args.public_block_time_target,
        public_faucet_enabled=args.public_faucet_enabled,
        public_faucet_amount=args.public_faucet_amount,
        public_faucet_cooldown_seconds=args.public_faucet_cooldown,
        public_faucet_daily_cap=args.public_faucet_daily_cap,
        mainnet_hardening=args.mainnet_hardening,
        chain_name=args.chain_name,
        token_name=args.token_name,
        token_symbol=args.token_symbol,
        token_decimals=args.token_decimals,
        chain_logo_url=args.chain_logo_url,
        token_logo_url=args.token_logo_url,
        auto_mine=args.auto_mine,
        auto_mine_miner=args.auto_mine_miner,
        auto_mine_interval=args.auto_mine_interval,
        auto_mine_allow_empty=args.auto_mine_allow_empty,
        peers=args.peer,
        peer_token=args.peer_token,
        peer_sync_enabled=args.peer_sync_enabled,
        peer_sync_interval_seconds=args.peer_sync_interval,
        peer_lag_resync_threshold=args.peer_lag_resync_threshold,
        strict_public_signatures=args.strict_public_signatures,
        public_mempool_ttl_seconds=args.public_mempool_ttl,
        public_mempool_max_transactions=args.public_mempool_max_size,
        public_pow_workers=args.public_pow_workers,
        public_pow_nonce_chunk_size=args.public_pow_nonce_chunk,
        require_hsm_signers=args.require_hsm_signers,
        jwt_secret=args.jwt_secret,
        jwt_required=args.jwt_required,
        rate_limit_per_minute=args.rate_limit_per_minute,
        rate_limit_tiers=tier_map,
        api_key_tier_map=api_key_map,
        tls_cert=args.tls_cert,
        tls_key=args.tls_key,
        tls_ca=args.tls_ca,
        tls_require_client_cert=args.tls_require_client_cert,
        peer_ca=args.peer_ca,
    )


if __name__ == "__main__":
    main()
