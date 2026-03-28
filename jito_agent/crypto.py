"""Cryptographic primitives and transaction builders for the JITO chain."""
import base64
import hashlib
import json
import secrets
import time
from typing import Any, Dict, List, Optional

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat, PrivateFormat, NoEncryption,
    )
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


# ── Helpers ────────────────────────────────────────────────────────────────

def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(raw: str) -> bytes:
    return base64.b64decode(raw.encode("ascii"))


def canonical_json(data: Dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def sha256_hex(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _payload_bytes(payload: Dict[str, Any]) -> bytes:
    return canonical_json(payload).encode("utf-8")


# ── Address / Key helpers ──────────────────────────────────────────────────

def address_from_public_key(public_key: Dict[str, Any]) -> str:
    """Derive 'W...' address from a JWK public key dict."""
    kty = public_key.get("kty")
    if kty == "ed25519":
        return "W" + sha256_hex(f"ed25519:{public_key['key']}")[:40]
    n = str(public_key["n"])
    e = str(public_key["e"])
    return "W" + sha256_hex(f"rsa-legacy:{n}:{e}")[:40]


def create_wallet(label: str = "") -> Dict[str, Any]:
    """Generate a new JITO wallet with Ed25519 keys in JWK format."""
    if not _HAS_CRYPTO:
        raise ImportError("pip install cryptography")
    sk = ed25519.Ed25519PrivateKey.generate()
    pub_raw = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    priv_raw = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_key = {"kty": "ed25519", "key": _b64e(pub_raw)}
    private_key = {"kty": "ed25519", "key": _b64e(priv_raw)}
    return {
        "address": address_from_public_key(public_key),
        "public_key": public_key,
        "private_key": private_key,
        "label": label,
    }


# ── Signing ────────────────────────────────────────────────────────────────

def sign_payload(payload: Dict[str, Any], private_key: Dict[str, Any]) -> str:
    kty = private_key.get("kty")
    if kty == "ed25519":
        if not _HAS_CRYPTO:
            raise ValueError("cryptography package required for Ed25519 signing")
        sk = ed25519.Ed25519PrivateKey.from_private_bytes(_b64d(private_key["key"]))
        return _b64e(sk.sign(_payload_bytes(payload)))
    raise ValueError(f"Unsupported key type: {kty}")


def sign_with_wallet(payload: Dict[str, Any], wallet: Dict[str, Any]) -> str:
    private_key = wallet.get("private_key")
    if not private_key:
        raise ValueError("Wallet has no private_key")
    return sign_payload(payload, private_key)


# ── Transaction builders ───────────────────────────────────────────────────
# Pattern A (identity / agent): flat tx with inline pubkey+signature+id
# Pattern B (task / model / pipeline): {payload, signature, public_key}

def _tx_a(payload: Dict[str, Any], wallet: Dict[str, Any]) -> Dict[str, Any]:
    """Build a 'flat' signed transaction (identity/agent style)."""
    # Sign only the fields the node verifies — each tx type has its own signable subset
    signable = _signable_subset(payload)
    sig = sign_with_wallet(signable, wallet)
    tx_id = sha256_hex(canonical_json({**payload, "signature": sig}))
    return {**payload, "id": tx_id, "pubkey": wallet["public_key"], "signature": sig}


# Signable subsets mirror dual_chain.py _signable_* methods exactly
_SIGNABLE_KEYS: Dict[str, List[str]] = {
    "agent_activity_log": [
        "type", "schema_version", "agent", "agent_id", "action_type", "input_hash",
        "output_hash", "evidence_hash", "evidence_url", "success", "duration_ms",
        "tags", "platform", "external_ref", "note", "stake_locked", "timestamp", "nonce",
    ],
    "agent_attest": [
        "type", "schema_version", "attester", "log_id", "sentiment", "note", "timestamp", "nonce",
    ],
    "agent_challenge": [
        "type", "schema_version", "challenger", "log_id", "stake_locked", "reason", "timestamp", "nonce",
    ],
    "agent_challenge_resolve": [
        "type", "schema_version", "resolver", "challenge_id", "verdict", "note", "timestamp", "nonce",
    ],
    "agent_param_propose": [
        "type", "schema_version", "proposer", "proposal_id", "changes", "reason",
        "vote_window_blocks", "timestamp", "nonce",
    ],
    "agent_param_endorse": [
        "type", "schema_version", "endorser", "proposal_id", "approve", "timestamp", "nonce",
    ],
}


def _signable_subset(payload: Dict[str, Any]) -> Dict[str, Any]:
    tx_type = payload.get("type", "")
    keys = _SIGNABLE_KEYS.get(tx_type)
    if keys:
        return {k: payload[k] for k in keys if k in payload}
    return payload


def _tx_b(payload: Dict[str, Any], wallet: Dict[str, Any]) -> Dict[str, Any]:
    """Build an envelope-style signed transaction (task/model/pipeline style)."""
    sig = sign_with_wallet(payload, wallet)
    return {"payload": payload, "signature": sig, "public_key": wallet["public_key"]}


def make_identity_claim_tx(wallet: Dict, handle: str, bio: str = "",
                            links: Optional[Dict] = None) -> Dict:
    payload = {
        "type": "identity_claim",
        "signer": wallet["address"],
        "handle": str(handle).strip().lower(),
        "bio": str(bio or "").strip(),
        "links": dict(links or {}),
        "timestamp": time.time(),
    }
    return _tx_a(payload, wallet)


def make_agent_register_tx(owner_wallet: Dict, agent_id: str, name: str,
                            capabilities: Optional[List[str]] = None,
                            version_hash: str = "") -> Dict:
    payload = {
        "type": "agent_register",
        "owner": owner_wallet["address"],
        "agent_id": str(agent_id).strip(),
        "name": str(name).strip(),
        "capabilities": sorted({str(c).strip() for c in (capabilities or []) if str(c).strip()}),
        "version_hash": str(version_hash or "").strip(),
        "timestamp": time.time(),
    }
    sig = sign_with_wallet(payload, owner_wallet)
    tx_id = sha256_hex(canonical_json({**payload, "signature": sig}))
    return {**payload, "id": tx_id, "signer": owner_wallet["address"],
            "pubkey": owner_wallet["public_key"], "signature": sig}


def make_task_complete_tx(agent_wallet: Dict, task_id: str,
                           result_hash: str, note: str = "") -> Dict:
    payload = {
        "type": "task_complete",
        "agent": agent_wallet["address"],
        "task_id": task_id,
        "result_hash": result_hash,
        "note": note,
        "ts": time.time(),
        "nonce": secrets.token_hex(8),
    }
    return _tx_b(payload, agent_wallet)


def make_pipeline_step_complete_tx(agent_wallet: Dict, pipeline_id: str,
                                    step_index: int, result_hash: str,
                                    note: str = "") -> Dict:
    payload = {
        "type": "pipeline_step_complete",
        "agent": agent_wallet["address"],
        "pipeline_id": pipeline_id,
        "step_index": step_index,
        "result_hash": result_hash,
        "note": note,
        "ts": time.time(),
        "nonce": secrets.token_hex(8),
    }
    return _tx_b(payload, agent_wallet)


def make_model_register_tx(owner_wallet: Dict, model_id: str, name: str,
                            description: str = "",
                            capabilities: Optional[List[str]] = None,
                            version_hash: str = "",
                            inference_fee: float = 0.0) -> Dict:
    payload = {
        "type": "model_register",
        "owner": owner_wallet["address"],
        "model_id": model_id,
        "name": name,
        "description": description,
        "capabilities": capabilities or [],
        "version_hash": version_hash,
        "inference_fee": inference_fee,
        "revenue_shares": {},
        "ts": time.time(),
        "nonce": secrets.token_hex(8),
    }
    return _tx_b(payload, owner_wallet)


def make_model_inference_tx(caller_wallet: Dict, model_id: str,
                             input_hash: str = "", output_hash: str = "") -> Dict:
    payload = {
        "type": "model_inference",
        "caller": caller_wallet["address"],
        "model_id": model_id,
        "input_hash": input_hash,
        "output_hash": output_hash,
        "ts": time.time(),
        "nonce": secrets.token_hex(8),
    }
    return _tx_b(payload, caller_wallet)


def make_governance_vote_tx(wallet: Dict, proposal_id: str, vote: bool) -> Dict:
    payload = {
        "type": "governance_vote",
        "voter": wallet["address"],
        "proposal_id": proposal_id,
        "vote": vote,
        "ts": time.time(),
        "nonce": secrets.token_hex(8),
    }
    return _tx_b(payload, wallet)


def make_agent_activity_log_tx(
    wallet: Dict,
    agent_id: str,
    action_type: str,
    input_hash: str = "",
    output_hash: str = "",
    evidence_hash: str = "",
    evidence_url: str = "",
    success: bool = True,
    duration_ms: int = 0,
    tags: List[str] = None,
    platform: str = "",
    external_ref: str = "",
    note: str = "",
    stake_locked: float = 0.0,
) -> Dict:
    payload = {
        "type": "agent_activity_log",
        "schema_version": 1,
        "agent": wallet["address"],
        "signer": wallet["address"],
        "agent_id": str(agent_id).strip(),
        "action_type": str(action_type).strip(),
        "input_hash": str(input_hash or ""),
        "output_hash": str(output_hash or ""),
        "evidence_hash": str(evidence_hash or ""),
        "evidence_url": str(evidence_url or "")[:512],
        "success": bool(success),
        "duration_ms": int(duration_ms or 0),
        "tags": list(tags or []),
        "platform": str(platform or ""),
        "external_ref": str(external_ref or "")[:256],
        "note": str(note or "")[:256],
        "stake_locked": max(0.0, float(stake_locked)),
        "timestamp": time.time(),
        "nonce": secrets.token_hex(8),
    }
    return _tx_a(payload, wallet)


def make_agent_attest_tx(wallet: Dict, log_id: str, sentiment: str, note: str = "") -> Dict:
    normalized = str(sentiment).strip().lower()
    if normalized not in {"positive", "negative"}:
        raise ValueError("sentiment must be 'positive' or 'negative'")
    payload = {
        "type": "agent_attest",
        "schema_version": 1,
        "attester": wallet["address"],
        "signer": wallet["address"],
        "log_id": str(log_id).strip(),
        "sentiment": normalized,
        "note": str(note or "")[:256],
        "timestamp": time.time(),
        "nonce": secrets.token_hex(8),
    }
    return _tx_a(payload, wallet)


def make_agent_challenge_resolve_tx(wallet: Dict, challenge_id: str,
                                     verdict: str, note: str = "") -> Dict:
    v = str(verdict).strip().lower()
    if v not in {"slash", "clear"}:
        raise ValueError("verdict must be 'slash' or 'clear'")
    payload = {
        "type": "agent_challenge_resolve",
        "schema_version": 1,
        "resolver": wallet["address"],
        "signer": wallet["address"],
        "challenge_id": str(challenge_id).strip(),
        "verdict": v,
        "note": str(note or "")[:256],
        "timestamp": time.time(),
        "nonce": secrets.token_hex(8),
    }
    return _tx_a(payload, wallet)


def make_agent_challenge_tx(wallet: Dict, log_id: str,
                             stake_locked: float = 10.0, reason: str = "") -> Dict:
    if float(stake_locked) <= 0:
        raise ValueError("challenge requires stake_locked > 0")
    payload = {
        "type": "agent_challenge",
        "schema_version": 1,
        "challenger": wallet["address"],
        "signer": wallet["address"],
        "log_id": str(log_id).strip(),
        "stake_locked": float(stake_locked),
        "reason": str(reason or "")[:256],
        "timestamp": time.time(),
        "nonce": secrets.token_hex(8),
    }
    return _tx_a(payload, wallet)


def make_agent_param_propose_tx(
    proposer_wallet: Dict,
    changes: Dict[str, Any],
    reason: str = "",
    vote_window_blocks: int = 100,
) -> Dict:
    """
    Governance step 1: propose a change to agent trust parameters.
    Only active validators may submit.  The proposer's vote is an implicit yes.
    A second validator must call make_agent_param_endorse_tx before changes apply.
    """
    proposal_id = "apu_" + secrets.token_hex(8)
    payload = {
        "type": "agent_param_propose",
        "schema_version": 1,
        "proposal_id": proposal_id,
        "proposer": proposer_wallet["address"],
        "signer": proposer_wallet["address"],
        "changes": dict(changes),
        "reason": str(reason or "")[:256],
        "vote_window_blocks": int(vote_window_blocks),
        "timestamp": time.time(),
        "nonce": secrets.token_hex(8),
    }
    return _tx_a(payload, proposer_wallet)


def make_agent_param_endorse_tx(
    endorser_wallet: Dict,
    proposal_id: str,
    approve: bool = True,
) -> Dict:
    """
    Governance step 2: endorse (approve=True) or reject (approve=False) a pending proposal.
    Only active validators may endorse.  When yes_count >= param_update_min_endorsements,
    the changes are applied immediately.
    """
    payload = {
        "type": "agent_param_endorse",
        "schema_version": 1,
        "proposal_id": str(proposal_id),
        "endorser": endorser_wallet["address"],
        "signer": endorser_wallet["address"],
        "approve": bool(approve),
        "timestamp": time.time(),
        "nonce": secrets.token_hex(8),
    }
    return _tx_a(payload, endorser_wallet)
