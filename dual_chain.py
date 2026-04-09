import base64
import hashlib
import json
import math
import os
import re
import secrets
import subprocess
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from eth_account import Account
from eth_account._utils.legacy_transactions import Transaction as LegacyTransaction
from eth_account.typed_transactions import TypedTransaction
from eth_utils import keccak as eth_keccak
from hexbytes import HexBytes


SYSTEM_SENDER = "SYSTEM"
MIN_VALIDATOR_STAKE: float = 500.0       # NOVA required to nominate as validator candidate
VALIDATOR_VOTE_THRESHOLD: int = 3        # votes needed for auto-promotion to active validator set
VALIDATOR_UNBONDING_BLOCKS: int = 100    # blocks before stake is released after unstake
AGENT_CHALLENGE_WINDOW_BLOCKS: int = 50   # blocks after which an unresolved challenge auto-slashes agent
AGENT_PARAM_UPDATE_COOLDOWN_BLOCKS: int = 10  # minimum blocks between trust parameter changes

# ---------------------------------------------------------------------------
# ZK proof support — Groth16 over BN128 curve (same as Ethereum's EIP-197)
# Proof generation is always off-chain; only ~2ms verification happens here.
# ---------------------------------------------------------------------------
try:
    from py_ecc.bn128 import (
        G1, G2, Z1, Z2,
        pairing, multiply, add, neg,
        is_on_curve, b, b2,
        FQ, FQ2, FQ12,
        field_modulus,
    )
    HAS_ZK = True
except ImportError:
    HAS_ZK = False

# Built-in ZK circuit registry — maps circuit_id → verification key
# Institutions / users can also register their own circuits on-chain.
_ZK_BUILTIN_CIRCUITS: Dict[str, Dict] = {}


def _parse_g1(point: List) -> tuple:
    """Parse a G1 point from [x, y] list of ints/strings."""
    return (FQ(int(point[0])), FQ(int(point[1])))


def _parse_g2(point: List) -> tuple:
    """Parse a G2 point from [[x0,x1],[y0,y1]] list."""
    return (
        FQ2([int(point[0][0]), int(point[0][1])]),
        FQ2([int(point[1][0]), int(point[1][1])]),
    )


def groth16_verify(vk: Dict, proof: Dict, public_inputs: List) -> bool:
    """
    Verify a Groth16 proof on BN128.

    vk (verification key):
        alpha: [x, y]           — G1 point
        beta:  [[x0,x1],[y0,y1]] — G2 point
        gamma: [[x0,x1],[y0,y1]] — G2 point
        delta: [[x0,x1],[y0,y1]] — G2 point
        ic:    [[x,y], ...]      — G1 points, len = num_public_inputs + 1

    proof:
        a: [x, y]               — G1 point
        b: [[x0,x1],[y0,y1]]    — G2 point
        c: [x, y]               — G1 point

    public_inputs: list of integers (field elements)

    Returns True iff the proof is valid.
    Groth16 check: e(A,B) == e(α,β) · e(vk_x,γ) · e(C,δ)
    """
    if not HAS_ZK:
        raise RuntimeError("py_ecc not installed — cannot verify ZK proofs")
    try:
        alpha = _parse_g1(vk["alpha"])
        beta  = _parse_g2(vk["beta"])
        gamma = _parse_g2(vk["gamma"])
        delta = _parse_g2(vk["delta"])
        ic    = [_parse_g1(p) for p in vk["ic"]]

        A = _parse_g1(proof["a"])
        B = _parse_g2(proof["b"])
        C = _parse_g1(proof["c"])

        if len(public_inputs) + 1 != len(ic):
            return False

        # Linear combination: vk_x = ic[0] + Σ public_inputs[i] * ic[i+1]
        vk_x = ic[0]
        for i, inp in enumerate(public_inputs):
            vk_x = add(vk_x, multiply(ic[i + 1], int(inp) % field_modulus))

        # Pairing check
        lhs = pairing(B, A)
        rhs = (
            pairing(beta,  alpha) *
            pairing(gamma, vk_x) *
            pairing(delta, C)
        )
        return lhs == rhs
    except Exception:
        return False


# Convenience: build a stub "always-true" VK for dev/test circuits
def _make_dev_vk(num_public_inputs: int = 1) -> Dict:
    """
    Returns a development VK that pairs with a trivial proof.
    NOT secure — only for local testing before a real trusted setup.
    """
    return {
        "alpha": [G1[0].n, G1[1].n],
        "beta":  [[G2[0].coeffs[0], G2[0].coeffs[1]],
                  [G2[1].coeffs[0], G2[1].coeffs[1]]],
        "gamma": [[G2[0].coeffs[0], G2[0].coeffs[1]],
                  [G2[1].coeffs[0], G2[1].coeffs[1]]],
        "delta": [[G2[0].coeffs[0], G2[0].coeffs[1]],
                  [G2[1].coeffs[0], G2[1].coeffs[1]]],
        "ic":    [[G1[0].n, G1[1].n]] * (num_public_inputs + 1),
        "_dev": True,
    }


try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    HAS_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover
    HAS_CRYPTOGRAPHY = False


def canonical_json(data: Dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def sha256_hex(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(raw: str) -> bytes:
    return base64.b64decode(raw.encode("ascii"))


def _payload_bytes(payload: Dict[str, Any]) -> bytes:
    return canonical_json(payload).encode("utf-8")


def _payload_hash_bytes(payload: Dict[str, Any]) -> bytes:
    return hashlib.sha256(_payload_bytes(payload)).digest()


def _miller_rabin_is_prime(n: int, rounds: int = 16) -> bool:
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        witness = True
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                witness = False
                break
        if witness:
            return False
    return True


def _generate_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _miller_rabin_is_prime(candidate):
            return candidate


def _mod_inverse(a: int, m: int) -> int:
    t, new_t = 0, 1
    r, new_r = m, a
    while new_r:
        q = r // new_r
        t, new_t = new_t, t - q * new_t
        r, new_r = new_r, r - q * new_r
    if r != 1:
        raise ValueError("No modular inverse exists.")
    if t < 0:
        t += m
    return t


def generate_rsa_keypair(bits: int = 2048) -> Tuple[int, int, int]:
    e = 65537
    while True:
        p = _generate_prime(bits // 2)
        q = _generate_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) != 1:
            continue
        d = _mod_inverse(e, phi)
        return n, e, d


def _legacy_rsa_digest_to_int(payload: Dict[str, Any]) -> int:
    return int.from_bytes(_payload_hash_bytes(payload), byteorder="big")


def address_from_public_key(public_key: Dict[str, Any]) -> str:
    kty = public_key.get("kty")
    if kty == "ed25519":
        return "W" + sha256_hex(f"ed25519:{public_key['key']}")[:40]

    n = str(public_key["n"])
    e = str(public_key["e"])
    return "W" + sha256_hex(f"rsa-legacy:{n}:{e}")[:40]


class BaseSignerProvider:
    def sign(self, payload: Dict[str, Any], signer_config: Dict[str, Any], wallet: Dict[str, Any]) -> str:
        raise NotImplementedError


class FileHSMSignerProvider(BaseSignerProvider):
    """
    Local HSM/KMS adapter mock:
    - Wallet stores signer metadata + public key, but no private key
    - Private key is loaded from hsm_dir/<key_ref>.json at signing time
    """

    def sign(self, payload: Dict[str, Any], signer_config: Dict[str, Any], wallet: Dict[str, Any]) -> str:
        key_ref = signer_config.get("key_ref")
        hsm_dir = signer_config.get("hsm_dir", "hsm_keys")
        if not key_ref:
            raise ValueError("Signer config missing key_ref.")
        key_path = os.path.join(hsm_dir, f"{key_ref}.json")
        if not os.path.exists(key_path):
            raise ValueError(f"HSM key not found: {key_path}")
        with open(key_path, "r", encoding="utf-8") as f:
            private_key = json.load(f)

        expected = address_from_public_key(wallet["public_key"])
        if wallet.get("address") != expected:
            raise ValueError("Wallet public key mismatch while using HSM signer.")

        return sign_payload(payload, private_key)


def _run_command(cmd: List[str]) -> str:
    result = subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip() or "(no stderr)"
        raise ValueError(f"Command failed ({' '.join(cmd)}): {stderr}")
    return result.stdout


class AwsKmsSignerProvider(BaseSignerProvider):
    """
    Signs payload bytes with AWS KMS via AWS CLI.

    signer_config fields:
    - key_id (required)
    - signing_algorithm (default: EDDSA)
    - region (optional)
    - profile (optional)
    """

    def sign(self, payload: Dict[str, Any], signer_config: Dict[str, Any], wallet: Dict[str, Any]) -> str:
        _ = wallet
        key_id = signer_config.get("key_id")
        signing_algorithm = signer_config.get("signing_algorithm", "EDDSA")
        region = signer_config.get("region", "")
        profile = signer_config.get("profile", "")
        if not key_id:
            raise ValueError("aws-kms signer requires key_id.")

        with tempfile.NamedTemporaryFile("wb", delete=True) as msg_file:
            msg_file.write(_payload_bytes(payload))
            msg_file.flush()

            cmd = ["aws"]
            if profile:
                cmd.extend(["--profile", profile])
            if region:
                cmd.extend(["--region", region])
            cmd.extend(
                [
                    "kms",
                    "sign",
                    "--key-id",
                    str(key_id),
                    "--message",
                    f"fileb://{msg_file.name}",
                    "--message-type",
                    "RAW",
                    "--signing-algorithm",
                    str(signing_algorithm),
                    "--output",
                    "json",
                ]
            )
            raw = _run_command(cmd)
            parsed = json.loads(raw)
            signature = parsed.get("Signature")
            if not signature:
                raise ValueError("AWS KMS sign response missing Signature.")
            return signature


class GcpKmsSignerProvider(BaseSignerProvider):
    """
    Signs payload bytes with Google Cloud KMS via gcloud CLI.

    signer_config fields:
    - location (required)
    - keyring (required)
    - key (required)
    - version (required)
    - project (optional)
    """

    def sign(self, payload: Dict[str, Any], signer_config: Dict[str, Any], wallet: Dict[str, Any]) -> str:
        _ = wallet
        location = signer_config.get("location")
        keyring = signer_config.get("keyring")
        key = signer_config.get("key")
        version = signer_config.get("version")
        project = signer_config.get("project", "")
        if not all([location, keyring, key, version]):
            raise ValueError("gcp-kms signer requires location, keyring, key, and version.")

        with tempfile.NamedTemporaryFile("wb", delete=True) as in_file, tempfile.NamedTemporaryFile(
            "wb", delete=True
        ) as out_file:
            in_file.write(_payload_bytes(payload))
            in_file.flush()

            cmd = [
                "gcloud",
                "kms",
                "asymmetric-sign",
                f"--location={location}",
                f"--keyring={keyring}",
                f"--key={key}",
                f"--version={version}",
                f"--input-file={in_file.name}",
                f"--signature-file={out_file.name}",
                "--quiet",
            ]
            if project:
                cmd.append(f"--project={project}")
            _run_command(cmd)

            out_file.seek(0)
            signature_bytes = out_file.read()
            if not signature_bytes:
                raise ValueError("GCP KMS sign response produced empty signature.")
            return _b64e(signature_bytes)


class AzureKvSignerProvider(BaseSignerProvider):
    """
    Signs payload hash with Azure Key Vault via az CLI.

    signer_config fields:
    - key_id (required) full key URL
    - algorithm (default: EdDSA)
    """

    def sign(self, payload: Dict[str, Any], signer_config: Dict[str, Any], wallet: Dict[str, Any]) -> str:
        _ = wallet
        key_id = signer_config.get("key_id")
        algorithm = signer_config.get("algorithm", "EdDSA")
        if not key_id:
            raise ValueError("azure-kv signer requires key_id.")

        digest_b64url = (
            base64.urlsafe_b64encode(_payload_hash_bytes(payload))
            .rstrip(b"=")
            .decode("ascii")
        )
        cmd = [
            "az",
            "keyvault",
            "key",
            "sign",
            "--id",
            str(key_id),
            "--algorithm",
            str(algorithm),
            "--value",
            digest_b64url,
            "--output",
            "json",
        ]
        raw = _run_command(cmd)
        parsed = json.loads(raw)
        result = parsed.get("result")
        if not result:
            raise ValueError("Azure Key Vault sign response missing result.")
        # Azure returns base64url; convert to standard base64 for uniform storage.
        padding = "=" * (-len(result) % 4)
        signature_bytes = base64.urlsafe_b64decode((result + padding).encode("ascii"))
        return _b64e(signature_bytes)


SIGNER_PROVIDERS: Dict[str, BaseSignerProvider] = {
    "file-hsm": FileHSMSignerProvider(),
    "aws-kms": AwsKmsSignerProvider(),
    "gcp-kms": GcpKmsSignerProvider(),
    "azure-kv": AzureKvSignerProvider(),
}


def register_signer_provider(name: str, provider: BaseSignerProvider) -> None:
    SIGNER_PROVIDERS[name] = provider


def sign_payload(payload: Dict[str, Any], private_key: Dict[str, Any]) -> str:
    kty = private_key.get("kty")

    if kty == "ed25519":
        if not HAS_CRYPTOGRAPHY:
            raise ValueError("cryptography package is required for Ed25519 signing.")
        sk = ed25519.Ed25519PrivateKey.from_private_bytes(_b64d(private_key["key"]))
        return _b64e(sk.sign(_payload_bytes(payload)))

    # Legacy compatibility path
    n = int(private_key["n"])
    d = int(private_key["d"])
    digest_int = _legacy_rsa_digest_to_int(payload)
    signature_int = pow(digest_int, d, n)
    return format(signature_int, "x")


def verify_signature(payload: Dict[str, Any], signature: str, public_key: Dict[str, Any]) -> bool:
    if not signature:
        return False

    kty = public_key.get("kty")
    if kty == "ed25519":
        if not HAS_CRYPTOGRAPHY:
            return False
        try:
            pk = ed25519.Ed25519PublicKey.from_public_bytes(_b64d(public_key["key"]))
            pk.verify(_b64d(signature), _payload_bytes(payload))
            return True
        except Exception:  # pylint: disable=broad-except
            return False

    try:
        n = int(public_key["n"])
        e = int(public_key["e"])
        signature_int = int(signature, 16)
        digest_int = _legacy_rsa_digest_to_int(payload)
        recovered = pow(signature_int, e, n)
    except (KeyError, ValueError, TypeError):
        return False
    return recovered == digest_int


def sign_with_wallet(payload: Dict[str, Any], wallet: Dict[str, Any]) -> str:
    signer = wallet.get("signer", {"type": "local"})
    signer_type = signer.get("type", "local")

    if signer_type == "local":
        private_key = wallet.get("private_key")
        if not private_key:
            raise ValueError("Wallet has no private_key for local signing.")
        return sign_payload(payload, private_key)

    provider = SIGNER_PROVIDERS.get(signer_type)
    if not provider:
        raise ValueError(f"Unsupported signer provider: {signer_type}")
    return provider.sign(payload, signer, wallet)


def create_wallet(name: str, bits: int = 2048, scheme: str = "ed25519") -> Dict[str, Any]:
    if scheme == "ed25519":
        if not HAS_CRYPTOGRAPHY:
            raise ValueError(
                "cryptography package is required for Ed25519. "
                "Use a venv and install: pip install cryptography"
            )
        sk = ed25519.Ed25519PrivateKey.generate()
        pk = sk.public_key()
        private_raw = sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_raw = pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        public_key = {"kty": "ed25519", "key": _b64e(public_raw)}
        private_key = {"kty": "ed25519", "key": _b64e(private_raw)}
    elif scheme == "rsa-legacy":
        n, e, d = generate_rsa_keypair(bits=bits)
        public_key = {"kty": "rsa-legacy", "n": str(n), "e": str(e)}
        private_key = {"kty": "rsa-legacy", "n": str(n), "d": str(d)}
    else:
        raise ValueError("Unsupported wallet scheme. Use ed25519 or rsa-legacy.")

    address = address_from_public_key(public_key)
    return {
        "name": name,
        "address": address,
        "scheme": scheme,
        "public_key": public_key,
        "private_key": private_key,
        "signer": {"type": "local"},
        "created_at": time.time(),
    }


def create_external_signer_wallet(
    name: str,
    public_key: Dict[str, Any],
    signer_type: str,
    signer_config: Dict[str, Any],
) -> Dict[str, Any]:
    address = address_from_public_key(public_key)
    return {
        "name": name,
        "address": address,
        "scheme": public_key.get("kty", "external"),
        "public_key": public_key,
        "signer": {"type": signer_type, **signer_config},
        "created_at": time.time(),
    }


def attach_signer_to_wallet(
    wallet: Dict[str, Any],
    signer_type: str,
    signer_config: Dict[str, Any],
    drop_private_key: bool = True,
) -> Dict[str, Any]:
    updated = dict(wallet)
    updated["signer"] = {"type": signer_type, **signer_config}
    if drop_private_key:
        updated.pop("private_key", None)
    return updated


def move_wallet_private_key_to_file_hsm(
    wallet: Dict[str, Any],
    key_ref: str,
    hsm_dir: str = "hsm_keys",
) -> Dict[str, Any]:
    private_key = wallet.get("private_key")
    if not private_key:
        raise ValueError("Wallet has no private key to migrate.")

    ensure_dir(hsm_dir)
    key_path = os.path.join(hsm_dir, f"{key_ref}.json")
    with open(key_path, "w", encoding="utf-8") as f:
        json.dump(private_key, f, indent=2)

    migrated = dict(wallet)
    migrated.pop("private_key", None)
    migrated["signer"] = {
        "type": "file-hsm",
        "key_ref": key_ref,
        "hsm_dir": hsm_dir,
    }
    migrated["hsm_ref"] = key_ref
    return migrated


def save_wallet(wallet: Dict[str, Any], path: str) -> None:
    ensure_dir(os.path.dirname(path) or ".")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(wallet, f, indent=2)


def load_wallet(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        wallet = json.load(f)
    expected = address_from_public_key(wallet["public_key"])
    if wallet.get("address") != expected:
        raise ValueError("Wallet address does not match its public key.")
    wallet.setdefault("signer", {"type": "local"})
    wallet.setdefault("scheme", wallet["public_key"].get("kty", "rsa-legacy"))
    return wallet


@dataclass
class Block:
    index: int
    timestamp: float
    transactions: List[Dict[str, Any]]
    previous_hash: str
    nonce: int = 0
    meta: Dict[str, Any] = field(default_factory=dict)
    hash: str = ""

    def _hashable_meta(self) -> Dict[str, Any]:
        # Keep mutable finality fields outside the block hash.
        blocked = {"finalized", "notary_approvals", "finality_threshold"}
        return {k: v for k, v in self.meta.items() if k not in blocked}

    def compute_hash(self) -> str:
        payload = {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "meta": self._hashable_meta(),
        }
        return sha256_hex(canonical_json(payload))

    def mine(self, difficulty: int) -> None:
        target = "0" * difficulty
        while True:
            block_hash = self.compute_hash()
            if block_hash.startswith(target):
                self.hash = block_hash
                return
            self.nonce += 1

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Block":
        return cls(
            index=int(data["index"]),
            timestamp=float(data["timestamp"]),
            transactions=list(data.get("transactions", [])),
            previous_hash=str(data["previous_hash"]),
            nonce=int(data.get("nonce", 0)),
            meta=dict(data.get("meta", {})),
            hash=str(data.get("hash", "")),
        )


def _pow_hash_for_nonce(block_payload: Dict[str, Any], nonce: int) -> str:
    payload = dict(block_payload)
    payload["nonce"] = int(nonce)
    return sha256_hex(canonical_json(payload))


def _pow_worker_search(
    block_payload: Dict[str, Any],
    difficulty: int,
    start_nonce: int,
    stride: int,
    max_attempts: int,
) -> Optional[Dict[str, Any]]:
    target = "0" * max(0, int(difficulty))
    nonce = int(start_nonce)
    step = max(1, int(stride))
    attempts = max(1, int(max_attempts))
    for _ in range(attempts):
        digest = _pow_hash_for_nonce(block_payload, nonce)
        if digest.startswith(target):
            return {"nonce": nonce, "hash": digest}
        nonce += step
    return None


def make_payment_tx(sender_wallet: Dict[str, Any], recipient: str, amount: float) -> Dict[str, Any]:
    recipient_raw = str(recipient or "").strip()
    if recipient_raw.startswith("EVM:"):
        recipient_raw = f"EVM:{recipient_raw[4:].strip().lower()}"
    payload = {
        "type": "payment",
        "sender": sender_wallet["address"],
        "recipient": recipient_raw,
        "amount": float(amount),
        "timestamp": time.time(),
    }
    signature = sign_with_wallet(payload, sender_wallet)
    tx_id = sha256_hex(canonical_json({**payload, "signature": signature}))
    return {
        **payload,
        "id": tx_id,
        "pubkey": sender_wallet["public_key"],
        "signature": signature,
    }


def make_payment_tx_with_fee(
    sender_wallet: Dict[str, Any],
    recipient: str,
    amount: float,
    fee: float = 0.0,
) -> Dict[str, Any]:
    recipient_raw = str(recipient or "").strip()
    if recipient_raw.startswith("EVM:"):
        recipient_raw = f"EVM:{recipient_raw[4:].strip().lower()}"
    payload = {
        "type": "payment",
        "sender": sender_wallet["address"],
        "recipient": recipient_raw,
        "amount": float(amount),
        "timestamp": time.time(),
    }
    fee_value = float(fee)
    if fee_value > 0:
        payload["fee"] = fee_value
    signature = sign_with_wallet(payload, sender_wallet)
    tx_id = sha256_hex(canonical_json({**payload, "signature": signature}))
    return {
        **payload,
        "id": tx_id,
        "pubkey": sender_wallet["public_key"],
        "signature": signature,
    }


def make_price_update_tx(
    oracle_wallet: Dict[str, Any],
    symbol: str,
    price: float,
    source: str = "manual",
) -> Dict[str, Any]:
    payload = {
        "type": "price_update",
        "oracle": oracle_wallet["address"],
        "symbol": symbol.upper(),
        "price": float(price),
        "source": source,
        "timestamp": time.time(),
    }
    signature = sign_with_wallet(payload, oracle_wallet)
    tx_id = sha256_hex(canonical_json({**payload, "signature": signature}))
    return {
        **payload,
        "id": tx_id,
        "pubkey": oracle_wallet["public_key"],
        "signature": signature,
    }


def make_asset_issue_tx(
    issuer_wallet: Dict[str, Any],
    asset_id: str,
    amount: float,
    owner: str,
    domain: str,
    contract_id: str = "",
    metadata_hash: str = "",
    metadata: Optional[Dict[str, Any]] = None,
    visibility: Optional[List[str]] = None,
) -> Dict[str, Any]:
    payload = {
        "type": "asset_issue",
        "issuer": issuer_wallet["address"],
        "owner": owner,
        "asset_id": asset_id,
        "amount": float(amount),
        "domain": domain,
        "contract_id": contract_id,
        "metadata_hash": metadata_hash,
        "metadata": dict(metadata or {}),
        "visibility": visibility or [],
        "timestamp": time.time(),
    }
    signature = sign_with_wallet(payload, issuer_wallet)
    tx_id = sha256_hex(canonical_json({**payload, "signature": signature}))
    return {
        **payload,
        "id": tx_id,
        "signer": issuer_wallet["address"],
        "pubkey": issuer_wallet["public_key"],
        "signature": signature,
    }


def make_asset_transfer_tx(
    owner_wallet: Dict[str, Any],
    asset_id: str,
    amount: float,
    recipient: str,
    visibility: Optional[List[str]] = None,
) -> Dict[str, Any]:
    payload = {
        "type": "asset_transfer",
        "asset_id": asset_id,
        "amount": float(amount),
        "from": owner_wallet["address"],
        "to": recipient,
        "visibility": visibility or [],
        "timestamp": time.time(),
    }
    signature = sign_with_wallet(payload, owner_wallet)
    tx_id = sha256_hex(canonical_json({**payload, "signature": signature}))
    return {
        **payload,
        "id": tx_id,
        "signer": owner_wallet["address"],
        "pubkey": owner_wallet["public_key"],
        "signature": signature,
    }


def make_validator_update_tx(
    validator_wallet: Dict[str, Any],
    action: str,
    validator_address: str,
) -> Dict[str, Any]:
    normalized_action = str(action).strip().lower()
    if normalized_action not in {"add", "remove"}:
        raise ValueError("action must be add/remove")
    payload = {
        "type": "validator_update",
        "action": normalized_action,
        "validator": str(validator_address).strip(),
        "proposer": validator_wallet["address"],
        "timestamp": time.time(),
    }
    signature = sign_with_wallet(payload, validator_wallet)
    tx_id = sha256_hex(canonical_json({**payload, "signature": signature}))
    return {
        **payload,
        "id": tx_id,
        "signer": validator_wallet["address"],
        "pubkey": validator_wallet["public_key"],
        "signature": signature,
    }


def make_ai_provider_stake_tx(provider_wallet: Dict[str, Any], amount: float) -> Dict[str, Any]:
    payload = {
        "type": "ai_provider_stake",
        "provider": provider_wallet["address"],
        "amount": float(amount),
        "timestamp": time.time(),
    }
    signature = sign_with_wallet(payload, provider_wallet)
    tx_id = sha256_hex(canonical_json({**payload, "signature": signature}))
    return {
        **payload,
        "id": tx_id,
        "signer": provider_wallet["address"],
        "pubkey": provider_wallet["public_key"],
        "signature": signature,
    }


def make_ai_provider_slash_tx(
    validator_wallet: Dict[str, Any],
    provider: str,
    amount: float,
    reason: str = "",
    recipient: str = "",
) -> Dict[str, Any]:
    payload = {
        "type": "ai_provider_slash",
        "provider": str(provider).strip(),
        "amount": float(amount),
        "reason": str(reason or "").strip(),
        "recipient": str(recipient or "").strip(),
        "timestamp": time.time(),
    }
    signature = sign_with_wallet(payload, validator_wallet)
    tx_id = sha256_hex(canonical_json({**payload, "signature": signature}))
    return {
        **payload,
        "id": tx_id,
        "signer": validator_wallet["address"],
        "pubkey": validator_wallet["public_key"],
        "signature": signature,
    }


def make_ai_model_register_tx(
    owner_wallet: Dict[str, Any],
    model_id: str,
    model_hash: str,
    version: str,
    price_per_call: float,
    visibility: Optional[List[str]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    payload = {
        "type": "ai_model_register",
        "model_id": str(model_id).strip(),
        "owner": owner_wallet["address"],
        "model_hash": str(model_hash).strip(),
        "version": str(version).strip(),
        "price_per_call": float(price_per_call),
        "visibility": list(visibility or []),
        "metadata": dict(metadata or {}),
        "timestamp": time.time(),
    }
    signature = sign_with_wallet(payload, owner_wallet)
    tx_id = sha256_hex(canonical_json({**payload, "signature": signature}))
    return {
        **payload,
        "id": tx_id,
        "signer": owner_wallet["address"],
        "pubkey": owner_wallet["public_key"],
        "signature": signature,
    }


def make_ai_job_create_tx(
    requester_wallet: Dict[str, Any],
    job_id: str,
    model_id: str,
    input_hash: str,
    max_payment: float,
    visibility: Optional[List[str]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    payload = {
        "type": "ai_job_create",
        "job_id": str(job_id).strip(),
        "model_id": str(model_id).strip(),
        "requester": requester_wallet["address"],
        "input_hash": str(input_hash).strip(),
        "max_payment": float(max_payment),
        "visibility": list(visibility or []),
        "metadata": dict(metadata or {}),
        "timestamp": time.time(),
    }
    signature = sign_with_wallet(payload, requester_wallet)
    tx_id = sha256_hex(canonical_json({**payload, "signature": signature}))
    return {
        **payload,
        "id": tx_id,
        "signer": requester_wallet["address"],
        "pubkey": requester_wallet["public_key"],
        "signature": signature,
    }


def make_ai_job_result_tx(
    provider_wallet: Dict[str, Any],
    job_id: str,
    result_hash: str,
    quality_score: float = 1.0,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    payload = {
        "type": "ai_job_result",
        "job_id": str(job_id).strip(),
        "provider": provider_wallet["address"],
        "result_hash": str(result_hash).strip(),
        "quality_score": float(quality_score),
        "metadata": dict(metadata or {}),
        "timestamp": time.time(),
    }
    signature = sign_with_wallet(payload, provider_wallet)
    tx_id = sha256_hex(canonical_json({**payload, "signature": signature}))
    return {
        **payload,
        "id": tx_id,
        "signer": provider_wallet["address"],
        "pubkey": provider_wallet["public_key"],
        "signature": signature,
    }


def make_ai_job_settle_tx(
    settler_wallet: Dict[str, Any],
    job_id: str,
    payout: float,
    slash_provider: float = 0.0,
    reason: str = "",
) -> Dict[str, Any]:
    payload = {
        "type": "ai_job_settle",
        "job_id": str(job_id).strip(),
        "settler": settler_wallet["address"],
        "payout": float(payout),
        "slash_provider": float(slash_provider),
        "reason": str(reason or "").strip(),
        "timestamp": time.time(),
    }
    signature = sign_with_wallet(payload, settler_wallet)
    tx_id = sha256_hex(canonical_json({**payload, "signature": signature}))
    return {
        **payload,
        "id": tx_id,
        "signer": settler_wallet["address"],
        "pubkey": settler_wallet["public_key"],
        "signature": signature,
    }


_HANDLE_PATTERN = re.compile(r"^[a-z0-9_]{3,32}$")


# Layer 1 — Identity Verify
def make_identity_verify_tx(notary_wallet: Dict, target_address: str, level: str = "basic") -> Dict:
    payload = {
        "type": "identity_verify",
        "notary": notary_wallet["address"],
        "target": target_address,
        "level": level,
        "ts": time.time(),
        "nonce": secrets.token_hex(8),
    }
    sig = sign_with_wallet(payload, notary_wallet)
    return {"payload": payload, "signature": sig, "public_key": notary_wallet["public_key"]}


# Layer 3 — AI Job Marketplace
def make_task_delegate_tx(owner_wallet: Dict, agent_id: str, title: str, description: str, reward: float, min_reputation: float = 0.0) -> Dict:
    task_id = "task_" + secrets.token_hex(8)
    payload = {
        "type": "task_delegate",
        "owner": owner_wallet["address"],
        "agent_id": agent_id,
        "task_id": task_id,
        "title": title,
        "description": description,
        "reward": reward,
        "min_reputation": min_reputation,
        "ts": time.time(),
        "nonce": secrets.token_hex(8),
    }
    sig = sign_with_wallet(payload, owner_wallet)
    return {"payload": payload, "signature": sig, "public_key": owner_wallet["public_key"]}


def make_task_complete_tx(agent_wallet: Dict, task_id: str, result_hash: str, note: str = "") -> Dict:
    payload = {
        "type": "task_complete",
        "agent": agent_wallet["address"],
        "task_id": task_id,
        "result_hash": result_hash,
        "note": note,
        "ts": time.time(),
        "nonce": secrets.token_hex(8),
    }
    sig = sign_with_wallet(payload, agent_wallet)
    return {"payload": payload, "signature": sig, "public_key": agent_wallet["public_key"]}


def make_task_review_tx(owner_wallet: Dict, task_id: str, approved: bool, quality_score: int, note: str = "") -> Dict:
    payload = {
        "type": "task_review",
        "owner": owner_wallet["address"],
        "task_id": task_id,
        "approved": approved,
        "quality_score": max(0, min(100, quality_score)),
        "note": note,
        "ts": time.time(),
        "nonce": secrets.token_hex(8),
    }
    sig = sign_with_wallet(payload, owner_wallet)
    return {"payload": payload, "signature": sig, "public_key": owner_wallet["public_key"]}


def make_task_dispute_tx(disputer_wallet: Dict, task_id: str, reason: str) -> Dict:
    payload = {
        "type": "task_dispute",
        "disputer": disputer_wallet["address"],
        "task_id": task_id,
        "reason": reason,
        "ts": time.time(),
        "nonce": secrets.token_hex(8),
    }
    sig = sign_with_wallet(payload, disputer_wallet)
    return {"payload": payload, "signature": sig, "public_key": disputer_wallet["public_key"]}


# Layer 4 — Governance
def make_governance_propose_tx(wallet: Dict, title: str, description: str, param_changes: Dict, vote_window_blocks: int = 100) -> Dict:
    proposal_id = "prop_" + secrets.token_hex(8)
    payload = {
        "type": "governance_propose",
        "proposer": wallet["address"],
        "proposal_id": proposal_id,
        "title": title,
        "description": description,
        "param_changes": param_changes,
        "vote_window_blocks": vote_window_blocks,
        "ts": time.time(),
        "nonce": secrets.token_hex(8),
    }
    sig = sign_with_wallet(payload, wallet)
    return {"payload": payload, "signature": sig, "public_key": wallet["public_key"]}


def make_governance_vote_tx(wallet: Dict, proposal_id: str, vote: bool) -> Dict:
    payload = {
        "type": "governance_vote",
        "voter": wallet["address"],
        "proposal_id": proposal_id,
        "vote": vote,
        "ts": time.time(),
        "nonce": secrets.token_hex(8),
    }
    sig = sign_with_wallet(payload, wallet)
    return {"payload": payload, "signature": sig, "public_key": wallet["public_key"]}


def make_identity_claim_tx(
    wallet: Dict[str, Any],
    handle: str,
    bio: str = "",
    links: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    payload = {
        "type": "identity_claim",
        "signer": wallet["address"],
        "handle": str(handle).strip().lower(),
        "bio": str(bio or "").strip(),
        "links": dict(links or {}),
        "timestamp": time.time(),
    }
    signature = sign_with_wallet(payload, wallet)
    tx_id = sha256_hex(canonical_json({**payload, "signature": signature}))
    return {**payload, "id": tx_id, "pubkey": wallet["public_key"], "signature": signature}


def make_identity_update_tx(
    wallet: Dict[str, Any],
    bio: str = "",
    links: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    payload = {
        "type": "identity_update",
        "signer": wallet["address"],
        "bio": str(bio or "").strip(),
        "links": dict(links or {}),
        "timestamp": time.time(),
    }
    signature = sign_with_wallet(payload, wallet)
    tx_id = sha256_hex(canonical_json({**payload, "signature": signature}))
    return {**payload, "id": tx_id, "pubkey": wallet["public_key"], "signature": signature}


def make_agent_register_tx(
    owner_wallet: Dict[str, Any],
    agent_id: str,
    name: str,
    capabilities: Optional[List[str]] = None,
    task_types: Optional[List[str]] = None,
    refusals: Optional[List[str]] = None,
    system_prompt_hash: str = "",
    version_hash: str = "",
) -> Dict[str, Any]:
    payload = {
        "type": "agent_register",
        "owner": owner_wallet["address"],
        "agent_id": str(agent_id).strip(),
        "name": str(name).strip(),
        "capabilities": sorted({str(c).strip() for c in (capabilities or []) if str(c).strip()}),
        "task_types": [str(t).strip() for t in (task_types or []) if str(t).strip()],
        "refusals": [str(r).strip() for r in (refusals or []) if str(r).strip()],
        "system_prompt_hash": str(system_prompt_hash or "").strip(),
        "version_hash": str(version_hash or "").strip(),
        "timestamp": time.time(),
    }
    signature = sign_with_wallet(payload, owner_wallet)
    tx_id = sha256_hex(canonical_json({**payload, "signature": signature}))
    return {**payload, "id": tx_id, "signer": owner_wallet["address"], "pubkey": owner_wallet["public_key"], "signature": signature}


def make_agent_activity_log_tx(
    agent_wallet: Dict[str, Any],
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
) -> Dict[str, Any]:
    """
    Log any off-chain (or cross-platform) agent activity to Nova chain.
    Builds portable, stake-backed reputation regardless of where work happens.

    stake_locked: NOVA locked against this log. Higher stake → higher trust tier.
                  Can be challenged — fake logs are expensive.
    evidence_url: where the off-chain evidence lives (IPFS, S3, public URL).
                  Only the hash goes on-chain; content stays off-chain.
    external_ref: pointer to external work (PR#123, job-id, task-id, etc.)
    """
    payload = {
        "type": "agent_activity_log",
        "schema_version": 1,
        "agent": agent_wallet["address"],
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
    signature = sign_with_wallet(payload, agent_wallet)
    tx_id = sha256_hex(canonical_json({**payload, "signature": signature}))
    return {**payload, "id": tx_id, "signer": agent_wallet["address"],
            "pubkey": agent_wallet["public_key"], "signature": signature}


def make_agent_challenge_resolve_tx(
    validator_wallet: Dict[str, Any],
    challenge_id: str,
    verdict: str,
    note: str = "",
) -> Dict[str, Any]:
    """
    Validator resolves a challenge.
    verdict: 'slash'  — agent had no evidence, stake slashed to challenger
             'clear'  — agent provided valid evidence, challenge dismissed
    """
    v = str(verdict).strip().lower()
    if v not in {"slash", "clear"}:
        raise ValueError("verdict must be 'slash' or 'clear'")
    payload = {
        "type": "agent_challenge_resolve",
        "schema_version": 1,
        "resolver": validator_wallet["address"],
        "challenge_id": str(challenge_id).strip(),
        "verdict": v,
        "note": str(note or "")[:256],
        "timestamp": time.time(),
        "nonce": secrets.token_hex(8),
    }
    signature = sign_with_wallet(payload, validator_wallet)
    tx_id = sha256_hex(canonical_json({**payload, "signature": signature}))
    return {**payload, "id": tx_id, "signer": validator_wallet["address"],
            "pubkey": validator_wallet["public_key"], "signature": signature}


def make_agent_challenge_tx(
    challenger_wallet: Dict[str, Any],
    log_id: str,
    stake_locked: float = 10.0,
    reason: str = "",
) -> Dict[str, Any]:
    """
    Challenge an agent activity log. Locks stake from the challenger.
    If the agent cannot produce evidence, their stake is slashed and challenger is rewarded.
    Fake/inflated logs become economically expensive.
    """
    if float(stake_locked) <= 0:
        raise ValueError("challenge requires stake_locked > 0")
    payload = {
        "type": "agent_challenge",
        "schema_version": 1,
        "challenger": challenger_wallet["address"],
        "log_id": str(log_id).strip(),
        "stake_locked": float(stake_locked),
        "reason": str(reason or "")[:256],
        "timestamp": time.time(),
        "nonce": secrets.token_hex(8),
    }
    signature = sign_with_wallet(payload, challenger_wallet)
    tx_id = sha256_hex(canonical_json({**payload, "signature": signature}))
    return {**payload, "id": tx_id, "signer": challenger_wallet["address"],
            "pubkey": challenger_wallet["public_key"], "signature": signature}


def make_agent_attest_tx(
    attester_wallet: Dict[str, Any],
    log_id: str,
    sentiment: str,
    note: str = "",
) -> Dict[str, Any]:
    """
    Attest to a specific activity log (by log_id).
    Any counterparty can attest — not just validators or agent owners.
    Attestations increase the log's trust tier and the agent's trust score.
    """
    normalized = str(sentiment).strip().lower()
    if normalized not in {"positive", "negative"}:
        raise ValueError("sentiment must be 'positive' or 'negative'")
    payload = {
        "type": "agent_attest",
        "schema_version": 1,
        "attester": attester_wallet["address"],
        "log_id": str(log_id).strip(),
        "sentiment": normalized,
        "note": str(note or "").strip()[:256],
        "timestamp": time.time(),
        "nonce": secrets.token_hex(8),
    }
    signature = sign_with_wallet(payload, attester_wallet)
    tx_id = sha256_hex(canonical_json({**payload, "signature": signature}))
    return {**payload, "id": tx_id, "signer": attester_wallet["address"],
            "pubkey": attester_wallet["public_key"], "signature": signature}


# ── Agent Trust Governance ──────────────────────────────────────────────────
# Parameter changes are governance-level events requiring multi-validator
# endorsement.  The flow is: propose → endorse (M-of-N validators) → applied.
# Both txs are immutable in the block history — there is no silent edit path.

_AGENT_PARAM_ALLOWED: Dict[str, type] = {
    "challenge_window_blocks": int,
    "auto_slash_on_window_expiry": bool,
    "slash_outcome": str,
    "param_update_min_endorsements": int,
    "validator_max_missed_blocks": int,
    "validator_missed_block_slash_pct": float,
    "zk_proof_max_age_seconds": int,
    # trust_score_weights handled separately (nested dict)
}


def make_agent_param_propose_tx(
    proposer_wallet: Dict[str, Any],
    changes: Dict[str, Any],
    reason: str = "",
    vote_window_blocks: int = 100,
) -> Dict[str, Any]:
    """
    Open a multi-validator proposal to change agent trust parameters.
    Only active validators may submit.  The proposer's vote is an implicit yes.
    A second validator must endorse with make_agent_param_endorse_tx before
    the change takes effect (threshold controlled by param_update_min_endorsements).

    changes: dict of top-level param keys → new values, e.g.
        {"challenge_window_blocks": 100}
        {"trust_score_weights": {"attested_log": 0.5, "slashed_log": -4.0}}
    """
    proposal_id = "apu_" + secrets.token_hex(8)
    payload = {
        "type": "agent_param_propose",
        "schema_version": 1,
        "proposal_id": proposal_id,
        "proposer": proposer_wallet["address"],
        "changes": dict(changes),
        "reason": str(reason or "")[:256],
        "vote_window_blocks": int(vote_window_blocks),
        "timestamp": time.time(),
        "nonce": secrets.token_hex(8),
    }
    signature = sign_with_wallet(payload, proposer_wallet)
    tx_id = sha256_hex(canonical_json({**payload, "signature": signature}))
    return {**payload, "id": tx_id, "signer": proposer_wallet["address"],
            "pubkey": proposer_wallet["public_key"], "signature": signature}


def make_agent_param_endorse_tx(
    endorser_wallet: Dict[str, Any],
    proposal_id: str,
    approve: bool = True,
) -> Dict[str, Any]:
    """
    Endorse (approve=True) or reject (approve=False) a pending agent_param_propose.
    Only active validators may endorse.  The proposer cannot endorse their own proposal
    (their vote is implicit yes).  When yes_count >= param_update_min_endorsements,
    the changes are applied immediately.
    """
    payload = {
        "type": "agent_param_endorse",
        "schema_version": 1,
        "proposal_id": proposal_id,
        "endorser": endorser_wallet["address"],
        "approve": bool(approve),
        "timestamp": time.time(),
        "nonce": secrets.token_hex(8),
    }
    signature = sign_with_wallet(payload, endorser_wallet)
    tx_id = sha256_hex(canonical_json({**payload, "signature": signature}))
    return {**payload, "id": tx_id, "signer": endorser_wallet["address"],
            "pubkey": endorser_wallet["public_key"], "signature": signature}


def make_agent_intent_post_tx(
    creator_wallet: Dict[str, Any],
    agent_id: str,
    intent: str,
    role: str = "",
    capability_tags: Optional[List[str]] = None,
    desired_collaborators: Optional[List[str]] = None,
    constraints_hash: str = "",
    reward: float = 0.0,
    expires_at: float = 0.0,
    note: str = "",
) -> Dict[str, Any]:
    payload = {
        "type": "agent_intent_post",
        "schema_version": 1,
        "intent_id": "ait_" + secrets.token_hex(8),
        "creator": creator_wallet["address"],
        "agent_id": str(agent_id).strip(),
        "intent": str(intent).strip()[:256],
        "role": str(role or "").strip()[:128],
        "capability_tags": sorted(
            {str(tag).strip().lower() for tag in (capability_tags or []) if str(tag).strip()}
        ),
        "desired_collaborators": sorted(
            {str(addr).strip() for addr in (desired_collaborators or []) if str(addr).strip()}
        ),
        "constraints_hash": str(constraints_hash or "").strip(),
        "reward": max(0.0, float(reward or 0.0)),
        "expires_at": max(0.0, float(expires_at or 0.0)),
        "note": str(note or "").strip()[:256],
        "timestamp": time.time(),
        "nonce": secrets.token_hex(8),
    }
    signature = sign_with_wallet(payload, creator_wallet)
    tx_id = sha256_hex(canonical_json({**payload, "signature": signature}))
    return {
        **payload,
        "id": tx_id,
        "signer": creator_wallet["address"],
        "pubkey": creator_wallet["public_key"],
        "signature": signature,
    }


def make_agent_session_open_tx(
    opener_wallet: Dict[str, Any],
    session_id: str = "",
    intent_id: str = "",
    objective: str = "",
    participants: Optional[List[str]] = None,
    note: str = "",
) -> Dict[str, Any]:
    participants_set = {opener_wallet["address"]}
    participants_set.update(str(addr).strip() for addr in (participants or []) if str(addr).strip())
    payload = {
        "type": "agent_session_open",
        "schema_version": 1,
        "session_id": str(session_id).strip() or ("collab:" + secrets.token_hex(8)),
        "intent_id": str(intent_id or "").strip(),
        "opener": opener_wallet["address"],
        "objective": str(objective or "").strip()[:256],
        "participants": sorted(participants_set),
        "note": str(note or "").strip()[:256],
        "timestamp": time.time(),
        "nonce": secrets.token_hex(8),
    }
    signature = sign_with_wallet(payload, opener_wallet)
    tx_id = sha256_hex(canonical_json({**payload, "signature": signature}))
    return {
        **payload,
        "id": tx_id,
        "signer": opener_wallet["address"],
        "pubkey": opener_wallet["public_key"],
        "signature": signature,
    }


def make_agent_artifact_commit_tx(
    agent_wallet: Dict[str, Any],
    session_id: str,
    artifact_type: str,
    output_hash: str = "",
    evidence_hash: str = "",
    evidence_url: str = "",
    label: str = "",
    note: str = "",
) -> Dict[str, Any]:
    payload = {
        "type": "agent_artifact_commit",
        "schema_version": 1,
        "artifact_id": "aar_" + secrets.token_hex(8),
        "session_id": str(session_id).strip(),
        "agent": agent_wallet["address"],
        "artifact_type": str(artifact_type or "artifact").strip()[:64],
        "output_hash": str(output_hash or "").strip(),
        "evidence_hash": str(evidence_hash or "").strip(),
        "evidence_url": str(evidence_url or "").strip()[:512],
        "label": str(label or artifact_type or "artifact").strip()[:128],
        "note": str(note or "").strip()[:256],
        "timestamp": time.time(),
        "nonce": secrets.token_hex(8),
    }
    signature = sign_with_wallet(payload, agent_wallet)
    tx_id = sha256_hex(canonical_json({**payload, "signature": signature}))
    return {
        **payload,
        "id": tx_id,
        "signer": agent_wallet["address"],
        "pubkey": agent_wallet["public_key"],
        "signature": signature,
    }


def make_agent_session_close_tx(
    closer_wallet: Dict[str, Any],
    session_id: str,
    outcome: str = "success",
    summary_hash: str = "",
    note: str = "",
) -> Dict[str, Any]:
    normalized_outcome = str(outcome or "success").strip().lower()
    if normalized_outcome not in {"success", "partial", "failure", "cancelled"}:
        raise ValueError("outcome must be one of success, partial, failure, cancelled")
    payload = {
        "type": "agent_session_close",
        "schema_version": 1,
        "session_id": str(session_id).strip(),
        "closer": closer_wallet["address"],
        "outcome": normalized_outcome,
        "summary_hash": str(summary_hash or "").strip(),
        "note": str(note or "").strip()[:256],
        "timestamp": time.time(),
        "nonce": secrets.token_hex(8),
    }
    signature = sign_with_wallet(payload, closer_wallet)
    tx_id = sha256_hex(canonical_json({**payload, "signature": signature}))
    return {
        **payload,
        "id": tx_id,
        "signer": closer_wallet["address"],
        "pubkey": closer_wallet["public_key"],
        "signature": signature,
    }


def make_agent_session_settle_tx(
    settler_wallet: Dict[str, Any],
    session_id: str,
    payouts: Optional[Dict[str, float]] = None,
    contribution_weights: Optional[Dict[str, float]] = None,
    verdict: str = "success",
    note: str = "",
) -> Dict[str, Any]:
    normalized_payouts = {
        str(addr).strip(): max(0.0, float(amount or 0.0))
        for addr, amount in dict(payouts or {}).items()
        if str(addr).strip()
    }
    normalized_weights = {
        str(addr).strip(): max(0.0, float(weight or 0.0))
        for addr, weight in dict(contribution_weights or {}).items()
        if str(addr).strip()
    }
    payload = {
        "type": "agent_session_settle",
        "schema_version": 1,
        "session_id": str(session_id).strip(),
        "settler": settler_wallet["address"],
        "payouts": normalized_payouts,
        "contribution_weights": normalized_weights,
        "verdict": str(verdict or "success").strip().lower()[:64],
        "note": str(note or "").strip()[:256],
        "timestamp": time.time(),
        "nonce": secrets.token_hex(8),
    }
    signature = sign_with_wallet(payload, settler_wallet)
    tx_id = sha256_hex(canonical_json({**payload, "signature": signature}))
    return {
        **payload,
        "id": tx_id,
        "signer": settler_wallet["address"],
        "pubkey": settler_wallet["public_key"],
        "signature": signature,
    }


# ── Treasury / Validator Election ──────────────────────────────────────────

def make_validator_nominate_tx(wallet: Dict, stake_amount: float = MIN_VALIDATOR_STAKE) -> Dict:
    if float(stake_amount) < MIN_VALIDATOR_STAKE:
        raise ValueError(f"Minimum validator stake is {MIN_VALIDATOR_STAKE} NOVA")
    payload = {
        "type": "validator_nominate",
        "candidate": wallet["address"],
        "stake_amount": float(stake_amount),
        "ts": time.time(),
        "nonce": secrets.token_hex(8),
    }
    sig = sign_with_wallet(payload, wallet)
    return {"payload": payload, "signature": sig, "public_key": wallet["public_key"]}


def make_validator_unstake_tx(wallet: Dict) -> Dict:
    """Withdraw from validator candidate pool and begin unbonding period."""
    payload = {
        "type": "validator_unstake",
        "candidate": wallet["address"],
        "ts": time.time(),
        "nonce": secrets.token_hex(8),
    }
    sig = sign_with_wallet(payload, wallet)
    return {"payload": payload, "signature": sig, "public_key": wallet["public_key"]}


# ---------------------------------------------------------------------------
# ZK proof transaction builders
# Three built-in use cases:
#   zk_task_complete  — AI agent proves it completed a task (without revealing output)
#   zk_kyc_identity   — User proves KYC cleared without revealing personal data
#   zk_balance_proof  — Address proves it holds >= threshold without revealing exact balance
#
# All three share the same on-chain tx structure; only circuit_id differs.
# ---------------------------------------------------------------------------

def make_zk_proof_tx(
    wallet: Dict,
    circuit_id: str,
    proof: Dict,
    public_inputs: List,
    metadata: Optional[Dict] = None,
) -> Dict:
    """
    Submit a ZK proof on-chain.
    proof      — Groth16 proof dict with keys a, b, c (curve points)
    public_inputs — list of field-element integers (what the circuit reveals)
    metadata   — optional dict stored with tx (e.g. task_id, corridor_id)
    """
    payload = {
        "type": "zk_proof",
        "circuit_id": circuit_id,
        "prover": wallet["address"],
        "proof": proof,
        "public_inputs": public_inputs,
        "metadata": metadata or {},
        "ts": time.time(),
        "nonce": secrets.token_hex(8),
    }
    sig = sign_with_wallet(payload, wallet)
    return {"payload": payload, "signature": sig, "public_key": wallet["public_key"]}


def make_zk_task_complete_tx(
    wallet: Dict,
    task_id: str,
    output_hash: str,          # sha256(task_output) — stays private
    proof: Dict,
    public_inputs: List,       # [task_id_commitment, output_hash_commitment]
) -> Dict:
    """Prove an AI task was completed correctly without revealing the output."""
    return make_zk_proof_tx(
        wallet,
        circuit_id="zk_task_complete_v1",
        proof=proof,
        public_inputs=public_inputs,
        metadata={"task_id": task_id, "output_hash": output_hash},
    )


def make_zk_kyc_tx(
    wallet: Dict,
    institution_id: str,       # e.g. "HDFC_BANK"
    kyc_level: int,            # 1=basic, 2=full, 3=accredited
    proof: Dict,
    public_inputs: List,       # [institution_commitment, level]
) -> Dict:
    """Prove KYC was cleared at an institution without revealing personal data."""
    return make_zk_proof_tx(
        wallet,
        circuit_id="zk_kyc_identity_v1",
        proof=proof,
        public_inputs=public_inputs,
        metadata={"institution_id": institution_id, "kyc_level": kyc_level},
    )


def make_zk_balance_proof_tx(
    wallet: Dict,
    threshold: float,          # prove balance >= threshold
    proof: Dict,
    public_inputs: List,       # [address_commitment, threshold]
) -> Dict:
    """Prove balance >= threshold without revealing exact amount."""
    return make_zk_proof_tx(
        wallet,
        circuit_id="zk_balance_proof_v1",
        proof=proof,
        public_inputs=public_inputs,
        metadata={"threshold": threshold},
    )


def make_zk_register_circuit_tx(
    wallet: Dict,
    circuit_id: str,
    vk: Dict,
    description: str = "",
) -> Dict:
    """Register a new ZK circuit verification key on-chain."""
    payload = {
        "type": "zk_register_circuit",
        "circuit_id": circuit_id,
        "vk": vk,
        "description": description,
        "registrar": wallet["address"],
        "ts": time.time(),
        "nonce": secrets.token_hex(8),
    }
    sig = sign_with_wallet(payload, wallet)
    return {"payload": payload, "signature": sig, "public_key": wallet["public_key"]}


def make_validator_election_vote_tx(wallet: Dict, candidate: str) -> Dict:
    payload = {
        "type": "validator_election_vote",
        "voter": wallet["address"],
        "candidate": candidate,
        "ts": time.time(),
        "nonce": secrets.token_hex(8),
    }
    sig = sign_with_wallet(payload, wallet)
    return {"payload": payload, "signature": sig, "public_key": wallet["public_key"]}

# ── AI Oracle ───────────────────────────────────────────────────────────────

def make_ai_oracle_assign_tx(owner_wallet: Dict, asset_id: str, agent_id: str, oracle_type: str = "price") -> Dict:
    payload = {
        "type": "ai_oracle_assign",
        "owner": owner_wallet["address"],
        "asset_id": asset_id,
        "agent_id": agent_id,
        "oracle_type": oracle_type,  # "price" | "compliance" | "condition"
        "ts": time.time(),
        "nonce": secrets.token_hex(8),
    }
    sig = sign_with_wallet(payload, owner_wallet)
    return {"payload": payload, "signature": sig, "public_key": owner_wallet["public_key"]}

def make_ai_oracle_event_tx(agent_wallet: Dict, asset_id: str, event_type: str, value: str, note: str = "") -> Dict:
    payload = {
        "type": "ai_oracle_event",
        "agent": agent_wallet["address"],
        "asset_id": asset_id,
        "event_type": event_type,  # "price_update" | "compliance_passed" | "compliance_failed" | "condition_update"
        "value": value,
        "note": note,
        "ts": time.time(),
        "nonce": secrets.token_hex(8),
    }
    sig = sign_with_wallet(payload, agent_wallet)
    return {"payload": payload, "signature": sig, "public_key": agent_wallet["public_key"]}


# ── AI Model Ownership ─────────────────────────────────────────────────────

def make_model_register_tx(owner_wallet: Dict, model_id: str, name: str, description: str,
                            capabilities: List[str] = None, version_hash: str = "",
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
    sig = sign_with_wallet(payload, owner_wallet)
    return {"payload": payload, "signature": sig, "public_key": owner_wallet["public_key"]}

def make_model_transfer_tx(owner_wallet: Dict, model_id: str, new_owner: str) -> Dict:
    payload = {
        "type": "model_transfer",
        "owner": owner_wallet["address"],
        "model_id": model_id,
        "new_owner": new_owner,
        "ts": time.time(),
        "nonce": secrets.token_hex(8),
    }
    sig = sign_with_wallet(payload, owner_wallet)
    return {"payload": payload, "signature": sig, "public_key": owner_wallet["public_key"]}

def make_model_revenue_share_tx(owner_wallet: Dict, model_id: str, shares: Dict[str, float]) -> Dict:
    """shares: {address: pct} — must sum <= 1.0. Remainder goes to owner."""
    payload = {
        "type": "model_revenue_share",
        "owner": owner_wallet["address"],
        "model_id": model_id,
        "shares": shares,
        "ts": time.time(),
        "nonce": secrets.token_hex(8),
    }
    sig = sign_with_wallet(payload, owner_wallet)
    return {"payload": payload, "signature": sig, "public_key": owner_wallet["public_key"]}

def make_model_inference_tx(caller_wallet: Dict, model_id: str, input_hash: str, output_hash: str = "") -> Dict:
    """Record an inference call and trigger revenue distribution."""
    payload = {
        "type": "model_inference",
        "caller": caller_wallet["address"],
        "model_id": model_id,
        "input_hash": input_hash,
        "output_hash": output_hash,
        "ts": time.time(),
        "nonce": secrets.token_hex(8),
    }
    sig = sign_with_wallet(payload, caller_wallet)
    return {"payload": payload, "signature": sig, "public_key": caller_wallet["public_key"]}

# ── Multi-Agent Pipeline ────────────────────────────────────────────────────

def make_pipeline_create_tx(owner_wallet: Dict, pipeline_id: str, title: str,
                             steps: List[Dict], total_reward: float) -> Dict:
    """
    steps: list of {agent_id, description, reward_pct}
    reward_pct across all steps must sum to 1.0
    """
    payload = {
        "type": "pipeline_create",
        "owner": owner_wallet["address"],
        "pipeline_id": pipeline_id,
        "title": title,
        "steps": steps,
        "total_reward": total_reward,
        "ts": time.time(),
        "nonce": secrets.token_hex(8),
    }
    sig = sign_with_wallet(payload, owner_wallet)
    return {"payload": payload, "signature": sig, "public_key": owner_wallet["public_key"]}

def make_pipeline_step_complete_tx(agent_wallet: Dict, pipeline_id: str, step_index: int,
                                    result_hash: str, note: str = "") -> Dict:
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
    sig = sign_with_wallet(payload, agent_wallet)
    return {"payload": payload, "signature": sig, "public_key": agent_wallet["public_key"]}

def make_pipeline_approve_tx(owner_wallet: Dict, pipeline_id: str, approved: bool, note: str = "") -> Dict:
    payload = {
        "type": "pipeline_approve",
        "owner": owner_wallet["address"],
        "pipeline_id": pipeline_id,
        "approved": approved,
        "note": note,
        "ts": time.time(),
        "nonce": secrets.token_hex(8),
    }
    sig = sign_with_wallet(payload, owner_wallet)
    return {"payload": payload, "signature": sig, "public_key": owner_wallet["public_key"]}


class PublicPaymentChain:
    def __init__(
        self,
        chain_file: str,
        difficulty: int = 3,
        mining_reward: float = 25.0,
        consensus: str = "pow",
        validators: Optional[List[str]] = None,
        validator_rotation: bool = True,
        finality_confirmations: int = 5,
        checkpoint_interval: int = 20,
        block_time_target_seconds: float = 5.0,
        persist_batch_seconds: float = 0.5,
        max_dirty_ops_before_flush: int = 32,
        strict_signature_validation: bool = False,
        mempool_tx_ttl_seconds: float = 900.0,
        mempool_max_transactions: int = 5000,
        pow_parallel_workers: int = 1,
        pow_nonce_chunk_size: int = 10000,
        treasury_fee_pct: float = 0.0,
        treasury_address: str = "",
    ):
        self.chain_file = chain_file
        self.mempool_wal_file = f"{chain_file}.mempool.wal"
        self.difficulty = difficulty
        self.mining_reward = mining_reward
        self.consensus = str(consensus or "pow").strip().lower()
        if self.consensus not in {"pow", "poa"}:
            raise ValueError("Unsupported public consensus. Use 'pow' or 'poa'.")
        self.validators: Set[str] = set(validators or [])
        self.initial_validators: Set[str] = set(validators or [])
        self.validator_rotation_enabled = bool(validator_rotation)
        self.finality_confirmations = max(1, int(finality_confirmations))
        self.checkpoint_interval = max(1, int(checkpoint_interval))
        self.block_time_target_seconds = max(0.2, float(block_time_target_seconds))
        self.tx_priority_policy = "fee-desc"
        self.strict_signature_validation = bool(strict_signature_validation)
        self.mempool_tx_ttl_seconds = max(0.0, float(mempool_tx_ttl_seconds))
        self.mempool_max_transactions = max(0, int(mempool_max_transactions))
        self.pow_parallel_workers = max(1, int(pow_parallel_workers))
        self.pow_nonce_chunk_size = max(128, int(pow_nonce_chunk_size))
        self.mempool_prune_stats: Dict[str, float] = {
            "expired_total": 0.0,
            "evicted_total": 0.0,
            "last_pruned_at": 0.0,
            "last_expired": 0.0,
            "last_evicted": 0.0,
        }
        self.chain: List[Block] = []
        self.pending_transactions: List[Dict[str, Any]] = []
        self.price_oracles: Set[str] = set()
        self.latest_prices: Dict[str, Dict[str, Any]] = {}
        self.provider_stakes: Dict[str, float] = {}
        self.provider_slash_events: List[Dict[str, Any]] = []
        self.identity_registry: Dict[str, Dict[str, Any]] = {}
        self.handle_index: Dict[str, str] = {}
        self.agent_registry: Dict[str, Dict[str, Any]] = {}
        self.agent_register_history: List[Dict[str, Any]] = []
        # Layer 2 — Reputation
        self.reputation_index: Dict[str, Dict[str, Any]] = {}
        # Layer 3 — AI Job Marketplace
        self.task_registry: Dict[str, Dict[str, Any]] = {}
        # Layer 4 — Governance
        self.governance_proposals: Dict[str, Dict[str, Any]] = {}
        # Layer 6 — Activity Feed
        self.activity_feed: List[Dict] = []
        # Treasury
        self.treasury_balance: float = 0.0
        self.treasury_epoch_size: int = 100  # blocks per epoch
        self.treasury_fee_pct: float = float(treasury_fee_pct)
        self.treasury_address: str = str(treasury_address or "")
        # Validator election
        self.validator_candidates: Dict[str, Dict[str, Any]] = {}  # address -> {votes, voters}
        # AI Oracle
        self.oracle_assignments: Dict[str, Dict[str, Any]] = {}  # asset_id -> {agent_id, oracle_type, owner, events}
        # Model Ownership Registry
        self.model_registry: Dict[str, Dict[str, Any]] = {}  # model_id -> model data
        # Multi-Agent Pipelines
        self.pipeline_registry: Dict[str, Dict[str, Any]] = {}  # pipeline_id -> pipeline data
        # ZK Proof Layer
        self.zk_circuit_registry: Dict[str, Dict[str, Any]] = {}  # circuit_id -> {vk, description, registrar}
        self.zk_proof_log: List[Dict[str, Any]] = []              # recent verified proofs (capped at 1000)
        self.activity_log_index: Dict[str, Dict[str, Any]] = {}   # log_id -> log record + trust state
        self.challenge_index: Dict[str, Dict[str, Any]] = {}      # challenge_id -> challenge record
        self.collab_index: Dict[str, Dict[str, Any]] = {}  # collab_id -> {agents, logs, created_at, last_active}
        self.intent_index: Dict[str, Dict[str, Any]] = {}  # intent_id -> intent record
        self.artifact_index: Dict[str, Dict[str, Any]] = {}  # artifact_id -> committed session artifact
        self.agent_param_proposals: Dict[str, Dict[str, Any]] = {}  # proposal_id -> proposal record
        # Agent trust governance: all parameters that affect scoring/disputes live here.
        # Changes require an agent_param_propose tx + M-of-N validator endorsements.
        self.agent_trust_params: Dict[str, Any] = {
            "schema_version": 1,
            "challenge_window_blocks": AGENT_CHALLENGE_WINDOW_BLOCKS,
            "trust_score_weights": {
                "activity_log": 0.1,
                "attested_log": 0.4,
                "stake_backed_log": 0.3,
                "evidence_backed_log": 0.2,
                "challenged_unanswered_log": -1.5,
                "slashed_log": -3.0,
                "negative_attestation": -0.3,  # per negative peer review
            },
            "auto_slash_on_window_expiry": True,
            "slash_outcome": "agent_stake_to_challenger_plus_refund",
            "param_update_min_endorsements": 2,
            # Time-decay: trust score decays when an agent is inactive.
            # Every decay_epoch_blocks idle blocks, the score is multiplied by
            # (1 - decay_rate_per_epoch). Agents active each epoch are unaffected.
            "decay_epoch_blocks": 1000,      # ~83 min at 5 s/block
            "decay_rate_per_epoch": 0.01,    # 1 % loss per idle epoch (floor 10 %)  # including the proposer's implicit yes
            # Validator liveness: missed-block tracking and slashing
            "validator_max_missed_blocks": 5,        # consecutive misses before removal
            "validator_missed_block_slash_pct": 0.1, # fraction of balance slashed on removal
            # ZK proof freshness: reject proofs older than this many seconds
            "zk_proof_max_age_seconds": 3600,
        }
        self.agent_trust_params_history: List[Dict[str, Any]] = []  # [{block, endorsements, changes, ts}]
        # Orphaned blocks: competing tips received from peers during fork detection.
        # Keyed by block index → list of {hash, validator, timestamp, previous_hash}.
        self.orphan_blocks: Dict[int, List[Dict[str, Any]]] = {}
        self.balance_index: Dict[str, float] = {}
        self.pending_spend_index: Dict[str, float] = {}
        self.evm_next_nonce_index: Dict[str, int] = {}
        self._public_tx_count_total = 0
        self._total_minted_supply = 0.0
        self.state_version = 0
        self.persist_batch_seconds = max(0.05, float(persist_batch_seconds))
        self.max_dirty_ops_before_flush = max(1, int(max_dirty_ops_before_flush))
        self._last_persist_at = 0.0
        self._dirty_ops = 0
        self._pow_pool: Optional[ProcessPoolExecutor] = None
        self._pow_pool_workers = 0

        # Replay-prevention set for ZK proofs — populated by _rebuild_runtime_indexes
        # on file load, or stays empty for a fresh chain (no proofs yet)
        self.zk_proof_hashes: set = set()

        if os.path.exists(self.chain_file):
            self._load()
        else:
            self._create_genesis_block()
            self._touch_and_save(force=True)

    def _normalize_address(self, address: str) -> str:
        raw = str(address or "").strip()
        if raw.startswith("EVM:"):
            suffix = raw[4:].strip()
            if suffix.startswith("0x"):
                return f"EVM:{suffix.lower()}"
            return f"EVM:{suffix.lower()}"
        return raw

    def _normalize_hex(self, value: str) -> str:
        raw = str(value or "").strip().lower()
        if raw.startswith("0x"):
            return raw
        return f"0x{raw}"

    def _decode_raw_evm_tx(self, raw_tx: str) -> Dict[str, Any]:
        raw_hex = self._normalize_hex(raw_tx)
        raw_bytes = HexBytes(raw_hex)
        if len(raw_bytes) < 8:
            raise ValueError("raw transaction too short")

        sender_evm = Account.recover_transaction(raw_bytes).lower()
        tx_hash = self._normalize_hex(eth_keccak(raw_bytes).hex())

        tx_payload: Dict[str, Any]
        first = raw_bytes[0]
        if first in {1, 2, 3}:
            typed = TypedTransaction.from_bytes(raw_bytes).as_dict()
            tx_payload = dict(typed)
            tx_payload["tx_type"] = int(first)
        else:
            legacy = LegacyTransaction.from_bytes(raw_bytes).as_dict()
            tx_payload = dict(legacy)
            tx_payload["tx_type"] = 0

        recipient_evm = ""
        to_raw = tx_payload.get("to")
        if to_raw is not None:
            to_hex = HexBytes(to_raw).hex()
            if to_hex:
                recipient_evm = self._normalize_hex(to_hex[-40:].rjust(40, "0"))

        value_wei = int(tx_payload.get("value", 0))
        nonce = int(tx_payload.get("nonce", 0))
        if "chainId" in tx_payload:
            chain_id = int(tx_payload.get("chainId", 0))
        else:
            try:
                v_value = int(tx_payload.get("v", 0))
                chain_id = (v_value - 35) // 2 if v_value >= 35 else 0
            except (TypeError, ValueError):
                chain_id = 0

        return {
            "sender_evm": sender_evm,
            "recipient_evm": recipient_evm.lower(),
            "value_wei": value_wei,
            "nonce": nonce,
            "chain_id": chain_id,
            "tx_hash": tx_hash,
        }

    def _touch_and_save(self, force: bool = False) -> None:
        self.state_version += 1
        self._dirty_ops += 1
        now = time.time()
        should_flush = force or self._dirty_ops >= self.max_dirty_ops_before_flush
        if not should_flush and (now - self._last_persist_at) >= self.persist_batch_seconds:
            should_flush = True
        if should_flush:
            self._save()
            self._last_persist_at = now
            self._dirty_ops = 0

    def _append_mempool_wal(self, record: Dict[str, Any]) -> None:
        ensure_dir(os.path.dirname(self.mempool_wal_file) or ".")
        with open(self.mempool_wal_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, separators=(",", ":")) + "\n")

    def _replay_mempool_wal(self) -> bool:
        if not os.path.exists(self.mempool_wal_file):
            return False
        changed = False
        seen_ids: Set[str] = set()
        for block in self.chain:
            for tx in block.transactions:
                tx_id = str(tx.get("id", ""))
                if tx_id:
                    seen_ids.add(tx_id)
        for tx in self.pending_transactions:
            tx_id = str(tx.get("id", ""))
            if tx_id:
                seen_ids.add(tx_id)

        try:
            with open(self.mempool_wal_file, "r", encoding="utf-8") as f:
                for raw_line in f:
                    line = raw_line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except Exception:
                        continue
                    op = str(row.get("op", "")).strip().lower()
                    if op == "add":
                        tx = row.get("tx", {})
                        if not isinstance(tx, dict):
                            continue
                        tx_id = str(tx.get("id", ""))
                        if not tx_id or tx_id in seen_ids:
                            continue
                        self.pending_transactions.append(dict(tx))
                        seen_ids.add(tx_id)
                        changed = True
                    elif op == "clear":
                        if self.pending_transactions:
                            self.pending_transactions = []
                            changed = True
            if changed:
                if self.height == len(self.chain):
                    self._rebuild_runtime_indexes()
                else:
                    self._reindex_pending_runtime_state()
            return changed
        except Exception:
            return False

    def _create_genesis_block(self) -> None:
        genesis = Block(
            index=0,
            timestamp=time.time(),
            transactions=[],
            previous_hash="0" * 64,
            meta={
                "network": "public-payments",
                "consensus": self.consensus,
                "validator_rotation": self.validator_rotation_enabled,
                "finality_confirmations": self.finality_confirmations,
                "checkpoint_interval": self.checkpoint_interval,
                "finalized_height": 0,
                "checkpoint_height": 0,
                "checkpoint": True,
            },
        )
        genesis.hash = genesis.compute_hash()
        self.chain = [genesis]
        self._chain_full_height = 1
        self._public_tx_count_total = 0
        self._total_minted_supply = 0.0

    def _estimated_public_tx_count_from_retained_chain(self) -> int:
        retained_total = sum(len(block.transactions) for block in self.chain)
        non_genesis_blocks = max(0, self.height - 1)
        visible_extra = sum(
            max(0, len(block.transactions) - 1)
            for block in self.chain
            if int(getattr(block, "index", 0)) > 0
        )
        return max(retained_total, non_genesis_blocks + visible_extra)

    def _estimated_total_minted_supply_from_retained_state(self) -> float:
        visible_supply = round(sum(self.balance_index.values()) + float(self.treasury_balance), 8)
        non_genesis_blocks = max(0, self.height - 1)
        reward_floor = float(non_genesis_blocks) * float(self.mining_reward)
        visible_system_mints = 0.0
        for block in self.chain:
            if int(getattr(block, "index", 0)) <= 0:
                continue
            system_payments = [
                tx for tx in block.transactions
                if tx.get("type") == "payment" and tx.get("sender") == SYSTEM_SENDER
            ]
            if not system_payments:
                continue
            reward_tx = system_payments[-1]
            visible_system_mints += max(
                0.0,
                sum(float(tx.get("amount", 0.0)) for tx in system_payments)
                - float(reward_tx.get("amount", 0.0)),
            )
        return round(max(visible_supply, reward_floor + visible_system_mints), 8)

    def _reindex_pending_runtime_state(self) -> None:
        self.pending_spend_index = {}
        for tx in self.pending_transactions:
            self._index_pending_transaction(tx)

    def _tx_seen(self, tx_id: str) -> bool:
        for tx in self.pending_transactions:
            if tx.get("id") == tx_id:
                return True
        for block in self.chain:
            for tx in block.transactions:
                if tx.get("id") == tx_id:
                    return True
        return False

    def _signable_payment(self, tx: Dict[str, Any], include_fee: bool = True) -> Dict[str, Any]:
        payload = {
            "type": "payment",
            "sender": tx["sender"],
            "recipient": tx["recipient"],
            "amount": float(tx["amount"]),
            "timestamp": float(tx["timestamp"]),
        }
        fee = self._payment_fee(tx)
        if include_fee and fee > 0:
            payload["fee"] = fee
        return payload

    def _signable_price_update(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type": "price_update",
            "oracle": tx["oracle"],
            "symbol": str(tx["symbol"]).upper(),
            "price": float(tx["price"]),
            "source": str(tx.get("source", "manual")),
            "timestamp": float(tx["timestamp"]),
        }

    def _signable_validator_update(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type": "validator_update",
            "action": str(tx.get("action", "")).strip().lower(),
            "validator": str(tx.get("validator", "")).strip(),
            "proposer": str(tx.get("proposer", "")).strip(),
            "timestamp": float(tx.get("timestamp", 0.0)),
        }

    def _signable_ai_provider_stake(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type": "ai_provider_stake",
            "provider": str(tx.get("provider", "")).strip(),
            "amount": float(tx.get("amount", 0.0)),
            "timestamp": float(tx.get("timestamp", 0.0)),
        }

    def _signable_ai_provider_slash(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type": "ai_provider_slash",
            "provider": str(tx.get("provider", "")).strip(),
            "amount": float(tx.get("amount", 0.0)),
            "reason": str(tx.get("reason", "")),
            "recipient": str(tx.get("recipient", "")),
            "timestamp": float(tx.get("timestamp", 0.0)),
        }

    def _signable_identity_claim(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type": "identity_claim",
            "signer": str(tx.get("signer", "")),
            "handle": str(tx.get("handle", "")).strip().lower(),
            "bio": str(tx.get("bio", "")),
            "links": dict(tx.get("links", {})),
            "timestamp": float(tx.get("timestamp", 0.0)),
        }

    def _signable_identity_update(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type": "identity_update",
            "signer": str(tx.get("signer", "")),
            "bio": str(tx.get("bio", "")),
            "links": dict(tx.get("links", {})),
            "timestamp": float(tx.get("timestamp", 0.0)),
        }

    def _signable_agent_register(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        signable = {
            "type": "agent_register",
            "owner": str(tx.get("owner", "")),
            "agent_id": str(tx.get("agent_id", "")),
            "name": str(tx.get("name", "")),
            "capabilities": list(tx.get("capabilities", [])),
            "version_hash": str(tx.get("version_hash", "")),
            "timestamp": float(tx.get("timestamp", 0.0)),
        }
        if "task_types" in tx:
            signable["task_types"] = list(tx.get("task_types", []))
        if "refusals" in tx:
            signable["refusals"] = list(tx.get("refusals", []))
        if "system_prompt_hash" in tx:
            signable["system_prompt_hash"] = str(tx.get("system_prompt_hash", ""))
        return signable

    def _payment_fee(self, tx: Dict[str, Any]) -> float:
        try:
            fee = float(tx.get("fee", 0.0))
        except (TypeError, ValueError):
            return -1.0
        return fee

    def _tx_effective_fee(self, tx: Dict[str, Any]) -> float:
        tx_type = tx.get("type")
        if tx_type == "payment":
            return max(0.0, self._payment_fee(tx))
        if tx_type == "evm_payment":
            return max(0.0, self._evm_gas_fee_native(tx))
        return 0.0

    def expected_proposer_for_height(
        self,
        block_height: int,
        validator_set: Optional[Set[str]] = None,
    ) -> str:
        if self.consensus != "poa":
            return ""
        active = sorted(validator_set if validator_set is not None else self.validators)
        if not active or not self.validator_rotation_enabled:
            return ""
        return active[int(block_height) % len(active)]

    def expected_next_validator(self) -> str:
        return self.expected_proposer_for_height(self.height)

    def latest_finalized_height(self) -> int:
        tip = self.height - 1
        return max(0, tip - self.finality_confirmations)

    def _checkpoint_height_at(self, block_index: int) -> int:
        finalized = max(0, int(block_index) - self.finality_confirmations)
        if finalized <= 0:
            return 0
        return finalized - (finalized % self.checkpoint_interval)

    def checkpoint_summary(self, limit: int = 20) -> List[Dict[str, Any]]:
        checkpoints: List[Dict[str, Any]] = []
        if not self.chain:
            return checkpoints
        by_index = {b.index: b for b in self.chain}
        max_finalized = self.latest_finalized_height()
        cursor = max_finalized - (max_finalized % self.checkpoint_interval)
        while cursor >= 0 and len(checkpoints) < max(1, int(limit)):
            block = by_index.get(cursor)
            if block is not None:
                checkpoints.append(
                    {
                        "height": cursor,
                        "hash": block.hash,
                        "timestamp": block.timestamp,
                        "tx_count": len(block.transactions),
                    }
                )
            if cursor == 0:
                break
            cursor -= self.checkpoint_interval
        return checkpoints

    def get_provider_stakes(self) -> Dict[str, Any]:
        by_provider = {k: float(v) for k, v in self.provider_stakes.items() if float(v) > 0}
        return {
            "total_staked": float(sum(by_provider.values())),
            "provider_count": len(by_provider),
            "stakes": by_provider,
            "recent_slash_events": self.provider_slash_events[-50:],
        }

    def get_treasury_info(self) -> Dict[str, Any]:
        top_candidates = sorted(
            self.validator_candidates.items(),
            key=lambda x: x[1]["votes"],
            reverse=True
        )[:10]
        return {
            "balance": self.treasury_balance,
            "epoch_size": self.treasury_epoch_size,
            "fee_pct": self.treasury_fee_pct,
            "address": self.treasury_address or None,
            "managed_by": "governance" if not self.treasury_address else "address",
            "top_validator_candidates": [
                {"address": addr, "votes": data["votes"], "nominated_at": data["nominated_at"]}
                for addr, data in top_candidates
            ],
        }

    def mempool_policy(self) -> Dict[str, Any]:
        return {
            "tx_ttl_seconds": float(self.mempool_tx_ttl_seconds),
            "max_transactions": int(self.mempool_max_transactions),
            "pending_count": len(self.pending_transactions),
            "prune_stats": dict(self.mempool_prune_stats),
        }

    def _ensure_pow_pool(self, workers: int) -> ProcessPoolExecutor:
        target_workers = max(1, int(workers))
        if (
            self._pow_pool is None
            or self._pow_pool_workers != target_workers
        ):
            if self._pow_pool is not None:
                self._pow_pool.shutdown(wait=False, cancel_futures=True)
            self._pow_pool = ProcessPoolExecutor(max_workers=target_workers)
            self._pow_pool_workers = target_workers
        return self._pow_pool

    def _mine_pow(self, block: Block) -> None:
        if self.difficulty <= 0 or self.pow_parallel_workers <= 1:
            block.mine(self.difficulty)
            return

        workers = min(self.pow_parallel_workers, max(1, os.cpu_count() or 1))
        if workers <= 1:
            block.mine(self.difficulty)
            return

        block_payload = {
            "index": block.index,
            "timestamp": block.timestamp,
            "transactions": block.transactions,
            "previous_hash": block.previous_hash,
            "meta": block._hashable_meta(),  # pylint: disable=protected-access
        }
        stride = workers
        chunk = max(128, int(self.pow_nonce_chunk_size))
        nonce_base = 0
        pool = self._ensure_pow_pool(workers)
        while True:
            futures = [
                pool.submit(
                    _pow_worker_search,
                    block_payload,
                    self.difficulty,
                    nonce_base + worker_idx,
                    stride,
                    chunk,
                )
                for worker_idx in range(workers)
            ]

            found: Optional[Dict[str, Any]] = None
            for future in futures:
                result = future.result()
                if result is None:
                    continue
                if found is None or int(result["nonce"]) < int(found["nonce"]):
                    found = result

            if found is not None:
                block.nonce = int(found["nonce"])
                block.hash = str(found["hash"])
                return
            nonce_base += stride * chunk

    def close(self) -> None:
        if self._pow_pool is not None:
            self._pow_pool.shutdown(wait=False, cancel_futures=True)
            self._pow_pool = None
            self._pow_pool_workers = 0

    def performance_summary(self, window_blocks: int = 60) -> Dict[str, Any]:
        window = max(1, int(window_blocks))
        height = self.height - 1
        tip = self.chain[-1] if self.chain else None
        selected = self.chain[-window:] if self.chain else []

        tx_count = 0
        reward_count = 0
        for block in selected:
            for tx in block.transactions:
                if tx.get("type") == "payment" and tx.get("sender") == SYSTEM_SENDER:
                    reward_count += 1
                    continue
                tx_count += 1

        avg_block_time = 0.0
        if len(selected) > 1:
            span = float(selected[-1].timestamp) - float(selected[0].timestamp)
            avg_block_time = span / float(len(selected) - 1) if span > 0 else 0.0

        avg_tx_per_block = tx_count / float(len(selected)) if selected else 0.0
        tps = tx_count / float(max(1e-9, (float(selected[-1].timestamp) - float(selected[0].timestamp)))) if len(selected) > 1 else 0.0

        return {
            "height": height,
            "latest_block_hash": tip.hash if tip else "",
            "latest_block_timestamp": float(tip.timestamp) if tip else 0.0,
            "latest_block_tx_count": len(tip.transactions) if tip else 0,
            "window_blocks": len(selected),
            "window_user_tx": tx_count,
            "window_reward_tx": reward_count,
            "avg_block_time_seconds": avg_block_time,
            "avg_tx_per_block": avg_tx_per_block,
            "estimated_tps": tps,
            "finality_confirmations": self.finality_confirmations,
            "latest_finalized_height": self.latest_finalized_height(),
            "finality_lag_blocks": max(0, height - self.latest_finalized_height()),
            "pending_public_tx": len(self.pending_transactions),
            "mempool": self.mempool_policy(),
            "validator_count": len(self.validators),
            "next_expected_validator": self.expected_next_validator(),
            "target_block_time_seconds": self.block_time_target_seconds,
        }

    def _validate_evm_payment_tx(
        self,
        tx: Dict[str, Any],
        balances: Dict[str, float],
        expected_nonce: Optional[int] = None,
        check_funds: bool = True,
    ) -> bool:
        required = {
            "id",
            "type",
            "sender",
            "recipient",
            "amount",
            "timestamp",
            "sender_evm",
            "recipient_evm",
            "nonce",
            "raw_tx",
        }
        if not required.issubset(tx.keys()):
            return False
        if tx.get("type") != "evm_payment":
            return False

        sender = self._normalize_address(str(tx.get("sender", "")))
        recipient = self._normalize_address(str(tx.get("recipient", "")))
        sender_evm = str(tx.get("sender_evm", "")).lower()
        recipient_evm = str(tx.get("recipient_evm", "")).lower()
        raw_tx = str(tx.get("raw_tx", ""))
        if (
            not sender
            or not recipient
            or not raw_tx
            or not sender_evm.startswith("0x")
            or len(sender_evm) != 42
            or not recipient_evm.startswith("0x")
            or len(recipient_evm) != 42
        ):
            return False

        try:
            decoded = self._decode_raw_evm_tx(raw_tx)
        except Exception:
            return False

        if decoded.get("sender_evm", "") != sender_evm:
            return False
        if decoded.get("recipient_evm", "") != recipient_evm:
            return False
        if int(decoded.get("nonce", -1)) != int(tx.get("nonce", -1)):
            return False

        tx_hash = self._normalize_hex(str(tx.get("id", "")))
        if tx_hash != str(decoded.get("tx_hash", "")):
            return False

        amount = float(tx.get("amount", 0))
        if amount <= 0:
            return False
        try:
            value_wei_from_payload = int(str(tx.get("value_wei", "0")))
        except (TypeError, ValueError):
            return False
        if int(decoded.get("value_wei", -1)) != value_wei_from_payload:
            return False
        amount_wei = int(round(amount * 1_000_000_000_000_000_000))
        if amount_wei != value_wei_from_payload:
            return False

        if tx.get("chain_id") is not None:
            try:
                declared_chain_id = int(tx.get("chain_id", 0))
            except (TypeError, ValueError):
                return False
            if declared_chain_id > 0 and int(decoded.get("chain_id", 0)) != declared_chain_id:
                return False

        gas_fee_native = self._evm_gas_fee_native(tx)
        if gas_fee_native < 0:
            return False

        try:
            nonce = int(tx.get("nonce", -1))
        except (TypeError, ValueError):
            return False
        if nonce < 0:
            return False
        if expected_nonce is not None and nonce != expected_nonce:
            return False

        total_cost = amount + gas_fee_native
        if check_funds and balances.get(sender, 0.0) < total_cost:
            return False
        return True

    def _evm_gas_fee_native(self, tx: Dict[str, Any]) -> float:
        if tx.get("type") != "evm_payment":
            return 0.0
        try:
            gas_limit = int(tx.get("gas_limit", 0))
            gas_price_wei = int(tx.get("gas_price_wei", 0))
        except (TypeError, ValueError):
            return -1.0
        if gas_limit < 0 or gas_price_wei < 0:
            return -1.0
        return (gas_limit * gas_price_wei) / 1_000_000_000_000_000_000.0

    def _validate_payment_tx(
        self,
        tx: Dict[str, Any],
        balances: Dict[str, float],
        check_funds: bool = True,
    ) -> bool:
        required = {"id", "type", "sender", "recipient", "amount", "timestamp"}
        if not required.issubset(tx.keys()):
            return False
        if tx["type"] != "payment":
            return False

        amount = float(tx["amount"])
        sender = tx["sender"]
        recipient = tx["recipient"]
        fee = self._payment_fee(tx)
        if amount <= 0 or fee < 0 or not sender or not recipient:
            return False

        if sender == SYSTEM_SENDER:
            return True

        if "pubkey" not in tx or "signature" not in tx:
            return False
        if address_from_public_key(tx["pubkey"]) != sender:
            return False
        signable_with_fee = self._signable_payment(tx, include_fee=True)
        verified = verify_signature(signable_with_fee, tx["signature"], tx["pubkey"])
        if not verified and not self.strict_signature_validation:
            # Backward compatibility path for legacy signatures that omitted fee.
            signable_legacy = self._signable_payment(tx, include_fee=False)
            verified = verify_signature(signable_legacy, tx["signature"], tx["pubkey"])
        if not verified:
            return False

        if check_funds and balances.get(sender, 0.0) < amount + fee:
            return False

        return True

    def _validate_price_update_tx(self, tx: Dict[str, Any]) -> bool:
        required = {"id", "type", "oracle", "symbol", "price", "timestamp", "pubkey", "signature"}
        if not required.issubset(tx.keys()):
            return False
        if tx["type"] != "price_update":
            return False
        oracle = str(tx.get("oracle", ""))
        symbol = str(tx.get("symbol", "")).upper()
        price = float(tx.get("price", 0))
        if not oracle or not symbol or price <= 0:
            return False
        if oracle not in self.price_oracles:
            return False
        if address_from_public_key(tx["pubkey"]) != oracle:
            return False
        return verify_signature(self._signable_price_update(tx), tx["signature"], tx["pubkey"])

    def _validate_validator_update_tx(self, tx: Dict[str, Any], validator_set: Set[str]) -> bool:
        required = {"id", "type", "action", "validator", "proposer", "timestamp", "signer", "pubkey", "signature"}
        if not required.issubset(tx.keys()):
            return False
        if tx.get("type") != "validator_update":
            return False
        action = str(tx.get("action", "")).strip().lower()
        candidate = str(tx.get("validator", "")).strip()
        proposer = str(tx.get("proposer", "")).strip()
        signer = str(tx.get("signer", "")).strip()
        if action not in {"add", "remove"}:
            return False
        if not candidate or not proposer or proposer != signer:
            return False
        if signer not in validator_set:
            return False
        if address_from_public_key(tx["pubkey"]) != signer:
            return False
        if not verify_signature(self._signable_validator_update(tx), tx["signature"], tx["pubkey"]):
            return False
        if action == "remove" and candidate in validator_set and len(validator_set) <= 1:
            return False
        return True

    def _validate_ai_provider_stake_tx(
        self,
        tx: Dict[str, Any],
        balances: Dict[str, float],
        check_funds: bool = True,
    ) -> bool:
        required = {"id", "type", "provider", "amount", "timestamp", "signer", "pubkey", "signature"}
        if not required.issubset(tx.keys()):
            return False
        if tx.get("type") != "ai_provider_stake":
            return False
        provider = self._normalize_address(str(tx.get("provider", "")))
        signer = self._normalize_address(str(tx.get("signer", "")))
        amount = float(tx.get("amount", 0.0))
        if not provider or amount <= 0:
            return False
        if provider != signer:
            return False
        if address_from_public_key(tx["pubkey"]) != signer:
            return False
        if not verify_signature(self._signable_ai_provider_stake(tx), tx["signature"], tx["pubkey"]):
            return False
        if check_funds and balances.get(provider, 0.0) < amount:
            return False
        return True

    def _validate_ai_provider_slash_tx(
        self,
        tx: Dict[str, Any],
        validator_set: Set[str],
        provider_stakes: Dict[str, float],
    ) -> bool:
        required = {"id", "type", "provider", "amount", "timestamp", "signer", "pubkey", "signature"}
        if not required.issubset(tx.keys()):
            return False
        if tx.get("type") != "ai_provider_slash":
            return False
        signer = self._normalize_address(str(tx.get("signer", "")))
        provider = self._normalize_address(str(tx.get("provider", "")))
        amount = float(tx.get("amount", 0.0))
        if signer not in validator_set:
            return False
        if not provider or amount <= 0:
            return False
        if address_from_public_key(tx["pubkey"]) != signer:
            return False
        if not verify_signature(self._signable_ai_provider_slash(tx), tx["signature"], tx["pubkey"]):
            return False
        if provider_stakes.get(provider, 0.0) + 1e-12 < amount:
            return False
        return True

    def _validate_identity_claim_tx(self, tx: Dict[str, Any]) -> bool:
        required = {"id", "type", "signer", "handle", "timestamp", "pubkey", "signature"}
        if not required.issubset(tx.keys()):
            return False
        if tx.get("type") != "identity_claim":
            return False
        signer = str(tx.get("signer", "")).strip()
        handle = str(tx.get("handle", "")).strip().lower()
        if not signer or not handle:
            return False
        if not _HANDLE_PATTERN.match(handle):
            return False
        if signer in self.identity_registry:
            return False
        if handle in self.handle_index:
            return False
        if address_from_public_key(tx["pubkey"]) != signer:
            return False
        return verify_signature(self._signable_identity_claim(tx), tx["signature"], tx["pubkey"])

    def _validate_identity_update_tx(self, tx: Dict[str, Any]) -> bool:
        required = {"id", "type", "signer", "timestamp", "pubkey", "signature"}
        if not required.issubset(tx.keys()):
            return False
        if tx.get("type") != "identity_update":
            return False
        signer = str(tx.get("signer", "")).strip()
        if not signer:
            return False
        if signer not in self.identity_registry:
            return False
        if address_from_public_key(tx["pubkey"]) != signer:
            return False
        return verify_signature(self._signable_identity_update(tx), tx["signature"], tx["pubkey"])

    def _validate_agent_register_tx(self, tx: Dict[str, Any]) -> bool:
        required = {"id", "type", "owner", "agent_id", "name", "capabilities", "version_hash", "timestamp", "signer", "pubkey", "signature"}
        if not required.issubset(tx.keys()):
            return False
        if tx.get("type") != "agent_register":
            return False
        owner = str(tx.get("owner", "")).strip()
        signer = str(tx.get("signer", "")).strip()
        agent_id = str(tx.get("agent_id", "")).strip()
        name = str(tx.get("name", "")).strip()
        if not owner or not agent_id or not name or owner != signer:
            return False
        if address_from_public_key(tx["pubkey"]) != signer:
            return False
        return verify_signature(self._signable_agent_register(tx), tx["signature"], tx["pubkey"])

    def _signable_agent_activity_log(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        return {k: tx[k] for k in [
            "type", "schema_version", "agent", "agent_id", "action_type", "input_hash",
            "output_hash", "evidence_hash", "evidence_url", "success", "duration_ms",
            "tags", "platform", "external_ref", "note", "stake_locked", "timestamp", "nonce"
        ] if k in tx}

    def _signable_agent_attest(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        return {k: tx[k] for k in [
            "type", "schema_version", "attester", "log_id", "sentiment", "note", "timestamp", "nonce"
        ] if k in tx}

    def _signable_agent_challenge(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        return {k: tx[k] for k in [
            "type", "schema_version", "challenger", "log_id", "stake_locked", "reason", "timestamp", "nonce"
        ] if k in tx}

    def _signable_agent_challenge_resolve(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        return {k: tx[k] for k in [
            "type", "schema_version", "resolver", "challenge_id", "verdict", "note", "timestamp", "nonce"
        ] if k in tx}

    def _signable_agent_intent_post(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        return {k: tx[k] for k in [
            "type", "schema_version", "intent_id", "creator", "agent_id", "intent", "role",
            "capability_tags", "desired_collaborators", "constraints_hash", "reward",
            "expires_at", "note", "timestamp", "nonce",
        ] if k in tx}

    def _signable_agent_session_open(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        return {k: tx[k] for k in [
            "type", "schema_version", "session_id", "intent_id", "opener", "objective",
            "participants", "note", "timestamp", "nonce",
        ] if k in tx}

    def _signable_agent_artifact_commit(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        return {k: tx[k] for k in [
            "type", "schema_version", "artifact_id", "session_id", "agent", "artifact_type",
            "output_hash", "evidence_hash", "evidence_url", "label", "note", "timestamp", "nonce",
        ] if k in tx}

    def _signable_agent_session_close(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        return {k: tx[k] for k in [
            "type", "schema_version", "session_id", "closer", "outcome", "summary_hash",
            "note", "timestamp", "nonce",
        ] if k in tx}

    def _signable_agent_session_settle(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        return {k: tx[k] for k in [
            "type", "schema_version", "session_id", "settler", "payouts", "contribution_weights",
            "verdict", "note", "timestamp", "nonce",
        ] if k in tx}

    # ── Agent Param Governance (multi-validator propose + endorse) ────────────

    def _signable_agent_param_propose(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        return {k: tx[k] for k in [
            "type", "schema_version", "proposal_id", "proposer", "changes",
            "reason", "vote_window_blocks", "timestamp", "nonce",
        ] if k in tx}

    def _signable_agent_param_endorse(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        return {k: tx[k] for k in [
            "type", "schema_version", "proposal_id", "endorser", "approve", "timestamp", "nonce",
        ] if k in tx}

    def _validate_agent_param_changes(self, changes: Any) -> bool:
        """Shared bounds/type validation for proposed param changes."""
        if not isinstance(changes, dict) or not changes:
            return False
        allowed_keys = set(_AGENT_PARAM_ALLOWED.keys()) | {"trust_score_weights"}
        if not set(changes.keys()).issubset(allowed_keys):
            return False
        _VALID_SLASH_OUTCOMES = {"agent_stake_to_challenger_plus_refund", "burn"}
        _known_weights = {
            "activity_log", "attested_log", "stake_backed_log",
            "evidence_backed_log", "challenged_unanswered_log", "slashed_log",
        }
        for k, v in changes.items():
            if k == "trust_score_weights":
                if not isinstance(v, dict):
                    return False
                if not set(v.keys()).issubset(_known_weights):
                    return False
                for wv in v.values():
                    if not isinstance(wv, (int, float)):
                        return False
                    if not (-100.0 <= float(wv) <= 100.0):
                        return False
            elif k == "challenge_window_blocks":
                if not isinstance(v, int):
                    return False
                if not (1 <= v <= 10_000):
                    return False
            elif k == "auto_slash_on_window_expiry":
                if not isinstance(v, bool):
                    return False
            elif k == "slash_outcome":
                if str(v) not in _VALID_SLASH_OUTCOMES:
                    return False
            elif k == "param_update_min_endorsements":
                if not isinstance(v, int):
                    return False
                if not (1 <= v <= 100):
                    return False
            elif k == "validator_max_missed_blocks":
                if not isinstance(v, int):
                    return False
                if not (1 <= v <= 1000):
                    return False
            elif k == "validator_missed_block_slash_pct":
                if not isinstance(v, (int, float)):
                    return False
                if not (0.0 < float(v) <= 1.0):
                    return False
            elif k == "zk_proof_max_age_seconds":
                if not isinstance(v, int):
                    return False
                if not (0 <= v <= 86400):
                    return False
        return True

    def _validate_agent_param_propose_tx(self, tx: Dict[str, Any]) -> bool:
        required = {"id", "type", "schema_version", "proposal_id", "proposer", "changes",
                    "vote_window_blocks", "timestamp", "nonce", "signer", "pubkey", "signature"}
        if not required.issubset(tx.keys()):
            return False
        if tx.get("type") != "agent_param_propose":
            return False
        proposer = str(tx.get("proposer", "")).strip()
        signer = str(tx.get("signer", "")).strip()
        if not proposer or proposer != signer:
            return False
        if proposer not in self.validators:
            return False
        # Reject if there is already an open proposal
        for prop in self.agent_param_proposals.values():
            if prop.get("status") == "open":
                return False
        if not self._validate_agent_param_changes(tx.get("changes")):
            return False
        # Cooldown: reject if params were applied too recently
        last_block = int(self.agent_trust_params.get("_last_update_block", 0))
        cooldown = int(self.agent_trust_params.get("_update_cooldown_blocks",
                                                    AGENT_PARAM_UPDATE_COOLDOWN_BLOCKS))
        if self.height - last_block < cooldown and last_block > 0:
            return False
        if address_from_public_key(tx["pubkey"]) != signer:
            return False
        return verify_signature(self._signable_agent_param_propose(tx), tx["signature"], tx["pubkey"])

    def _validate_agent_param_endorse_tx(self, tx: Dict[str, Any]) -> bool:
        required = {"id", "type", "schema_version", "proposal_id", "endorser",
                    "approve", "timestamp", "nonce", "signer", "pubkey", "signature"}
        if not required.issubset(tx.keys()):
            return False
        if tx.get("type") != "agent_param_endorse":
            return False
        endorser = str(tx.get("endorser", "")).strip()
        signer = str(tx.get("signer", "")).strip()
        if not endorser or endorser != signer:
            return False
        if endorser not in self.validators:
            return False
        proposal_id = str(tx.get("proposal_id", ""))
        prop = self.agent_param_proposals.get(proposal_id)
        if not prop:
            return False
        if prop.get("status") != "open":
            return False
        # Proposer already has an implicit yes — they cannot endorse again
        if endorser == prop.get("proposer"):
            return False
        # No double-endorsement
        if endorser in prop.get("endorsements", {}):
            return False
        if address_from_public_key(tx["pubkey"]) != signer:
            return False
        return verify_signature(self._signable_agent_param_endorse(tx), tx["signature"], tx["pubkey"])

    def _apply_agent_param_changes_from_proposal(self, prop: Dict[str, Any], block_index: int) -> None:
        """Apply validated param changes from a proposal and record in history."""
        changes = prop["changes"]
        applied: Dict[str, Any] = {}
        for k, v in changes.items():
            if k == "trust_score_weights":
                old = dict(self.agent_trust_params.get("trust_score_weights", {}))
                merged = {**old, **{str(wk): float(wv) for wk, wv in v.items()}}
                self.agent_trust_params["trust_score_weights"] = merged
                applied["trust_score_weights"] = {"before": old, "after": merged}
            elif k in _AGENT_PARAM_ALLOWED:
                old_val = self.agent_trust_params.get(k)
                self.agent_trust_params[k] = v
                applied[k] = {"before": old_val, "after": v}
        if applied:
            self.agent_trust_params["_last_update_block"] = block_index
            self.agent_trust_params_history.append({
                "block": block_index,
                "proposer": prop["proposer"],
                "endorsements": list(prop.get("endorsements", {}).keys()),
                "changes": applied,
                "reason": prop.get("reason", "")[:256],
                "timestamp": prop.get("timestamp", 0.0),
                "proposal_id": prop["proposal_id"],
            })
        self._add_activity(
            f"[PARAM_APPLY] Agent trust params applied from {prop['proposal_id'][:12]}: {list(applied.keys())}",
            prop.get("timestamp", 0.0),
        )

    def _apply_agent_param_propose_tx(self, tx: Dict[str, Any], block_index: int = 0) -> None:
        proposal_id = tx["proposal_id"]
        proposer = tx["proposer"]
        self.agent_param_proposals[proposal_id] = {
            "proposal_id": proposal_id,
            "proposer": proposer,
            "changes": dict(tx["changes"]),
            "reason": str(tx.get("reason", ""))[:256],
            "vote_window_blocks": int(tx.get("vote_window_blocks", 100)),
            "status": "open",
            "endorsements": {proposer: True},   # proposer's implicit yes
            "yes_count": 1,
            "no_count": 0,
            "filed_at_block": block_index,
            "closes_at_block": block_index + int(tx.get("vote_window_blocks", 100)),
            "tx_id": tx["id"],
            "timestamp": float(tx.get("timestamp", 0.0)),
        }
        self._add_activity(
            f"[PARAM_PROPOSE] Agent trust param proposal {proposal_id[:12]} filed by {proposer[:12]}",
            tx.get("timestamp", 0.0),
        )
        # If threshold is 1, the proposal self-applies on creation
        threshold = int(self.agent_trust_params.get("param_update_min_endorsements", 2))
        prop = self.agent_param_proposals[proposal_id]
        if prop["yes_count"] >= threshold:
            self._apply_agent_param_changes_from_proposal(prop, block_index)
            prop["status"] = "applied"

    def _apply_agent_param_endorse_tx(self, tx: Dict[str, Any], block_index: int = 0) -> None:
        proposal_id = tx["proposal_id"]
        endorser = tx["endorser"]
        approve = bool(tx.get("approve", True))
        prop = self.agent_param_proposals[proposal_id]
        prop["endorsements"][endorser] = approve
        if approve:
            prop["yes_count"] += 1
        else:
            prop["no_count"] += 1
        threshold = int(self.agent_trust_params.get("param_update_min_endorsements", 2))
        if prop["yes_count"] >= threshold:
            self._apply_agent_param_changes_from_proposal(prop, block_index)
            prop["status"] = "applied"
        elif prop["no_count"] > len(self.validators) - threshold:
            prop["status"] = "rejected"

    def _check_agent_param_proposals(self, block_height: int) -> None:
        """Mark open proposals as expired when their vote window passes."""
        for prop in self.agent_param_proposals.values():
            if prop.get("status") == "open" and block_height >= prop.get("closes_at_block", 0):
                prop["status"] = "expired"

    def _validate_agent_challenge_resolve_tx(self, tx: Dict[str, Any]) -> bool:
        required = {"id", "type", "resolver", "challenge_id", "verdict",
                    "timestamp", "nonce", "signer", "pubkey", "signature"}
        if not required.issubset(tx.keys()):
            return False
        if tx.get("type") != "agent_challenge_resolve":
            return False
        resolver = str(tx.get("resolver", "")).strip()
        signer = str(tx.get("signer", "")).strip()
        verdict = str(tx.get("verdict", "")).strip().lower()
        if not resolver or resolver != signer or verdict not in {"slash", "clear"}:
            return False
        if resolver not in self.validators:
            return False
        # Find the challenge in activity_log_index; reject if already resolved
        challenge_id = str(tx.get("challenge_id", "")).strip()
        found = False
        for log in self.activity_log_index.values():
            for c in log.get("challenges", []):
                if c.get("challenge_id") == challenge_id:
                    if c.get("resolved"):
                        return False  # already resolved (e.g. auto-slashed)
                    found = True
                    break
            if found:
                break
        if not found:
            return False
        if address_from_public_key(tx["pubkey"]) != signer:
            return False
        return verify_signature(self._signable_agent_challenge_resolve(tx), tx["signature"], tx["pubkey"])

    def _apply_agent_challenge_resolve_tx(self, tx: Dict[str, Any]) -> None:
        challenge_id = str(tx.get("challenge_id", "")).strip()
        verdict = str(tx.get("verdict", "")).strip().lower()
        ts = float(tx.get("timestamp", time.time()))

        # Find the challenge across all logs
        target_log = None
        target_challenge = None
        for log in self.activity_log_index.values():
            for c in log.get("challenges", []):
                if c.get("challenge_id") == challenge_id:
                    target_log = log
                    target_challenge = c
                    break
            if target_log:
                break

        if not target_log or not target_challenge:
            return

        agent_addr = target_log["agent"]
        challenger = target_challenge.get("challenger", "")
        agent_stake = float(target_log.get("stake_locked", 0.0))
        challenger_stake = float(target_challenge.get("stake_locked", 0.0))

        target_challenge["resolved"] = True
        target_challenge["verdict"] = verdict
        # Mirror resolved state into challenge_index lookup
        cid = target_challenge.get("challenge_id", "")
        if cid in self.challenge_index:
            self.challenge_index[cid]["resolved"] = True
            self.challenge_index[cid]["verdict"] = verdict

        self._ensure_reputation(agent_addr)
        r = self.reputation_index[agent_addr]

        if verdict == "slash":
            # Agent loses their locked stake to challenger
            if agent_stake > 0:
                self.balance_index[challenger] = round(
                    self.balance_index.get(challenger, 0.0) + agent_stake, 8
                )
                target_log["stake_locked"] = 0.0
            # Return challenger's stake
            self.balance_index[challenger] = round(
                self.balance_index.get(challenger, 0.0) + challenger_stake, 8
            )
            r["slashed_logs"] = r.get("slashed_logs", 0) + 1
            r["challenged_unanswered_logs"] = max(0, r.get("challenged_unanswered_logs", 0) - 1)
            target_log["trust_tier"] = "slashed"
            self._award_badge(agent_addr, "slashed", "Slashed", ts)
        else:
            # Clear: challenge dismissed, return challenger's stake to challenger
            self.balance_index[challenger] = round(
                self.balance_index.get(challenger, 0.0) + challenger_stake, 8
            )
            r["challenged_unanswered_logs"] = max(0, r.get("challenged_unanswered_logs", 0) - 1)
            target_log["trust_tier"] = "stake-backed" if target_log.get("stake_locked", 0) > 0 else "self-reported"

        self._compute_trust_score(agent_addr)
        self._add_activity(
            f"[RESOLVE:{verdict.upper()}] Challenge on agent {agent_addr[:12]} resolved", ts
        )

    def _sweep_expired_challenges(self) -> None:
        """Auto-slash agents whose challenges have passed the challenge window unresolved."""
        current_block = self.height
        window = int(self.agent_trust_params.get("challenge_window_blocks", AGENT_CHALLENGE_WINDOW_BLOCKS))
        auto_slash = bool(self.agent_trust_params.get("auto_slash_on_window_expiry", True))
        if not auto_slash:
            return
        for cid, rec in list(self.challenge_index.items()):
            if rec.get("resolved"):
                continue
            if current_block - rec.get("filed_at_block", current_block) < window:
                continue
            log_id = rec.get("log_id", "")
            log = self.activity_log_index.get(log_id)
            if not log:
                continue
            agent_addr = log["agent"]
            challenger = rec.get("challenger", "")
            self._ensure_reputation(agent_addr)
            r = self.reputation_index[agent_addr]
            # Slash agent: agent's locked stake goes to the challenger (same as manual slash)
            agent_stake = float(log.get("stake_locked", 0.0))
            if agent_stake > 0:
                self.balance_index[agent_addr] = max(
                    0.0,
                    round(self.balance_index.get(agent_addr, 0.0) - agent_stake, 8),
                )
                if challenger:
                    self.balance_index[challenger] = round(
                        self.balance_index.get(challenger, 0.0) + agent_stake, 8
                    )
                log["stake_locked"] = 0.0
            # Return challenger's own locked stake
            challenger_stake = float(rec.get("stake_locked", 0.0))
            if challenger_stake > 0 and challenger:
                self.balance_index[challenger] = round(
                    self.balance_index.get(challenger, 0.0) + challenger_stake, 8
                )
            log["trust_tier"] = "slashed"
            r["slashed_logs"] = r.get("slashed_logs", 0) + 1
            r["challenged_unanswered_logs"] = max(0, r.get("challenged_unanswered_logs", 0) - 1)
            rec["resolved"] = True
            rec["verdict"] = "slash"
            rec["auto_slashed"] = True
            # Mirror on log.challenges entry
            for c in log.get("challenges", []):
                if c.get("challenge_id") == cid:
                    c["resolved"] = True
                    c["verdict"] = "slash"
                    c["auto_slashed"] = True
                    break
            self._compute_trust_score(agent_addr)
            self._add_activity(
                f"[AUTO-SLASH] Agent {agent_addr[:12]} auto-slashed: challenge window expired", time.time()
            )

    def _check_missed_blocks(self, block: "Block") -> None:
        """
        Called once per newly appended live block (not during replay).

        Detects when a PoA validator skips their rotation turn.  Each skip
        increments ``reputation_index[addr]["consecutive_missed_blocks"]``.
        Once that counter reaches ``agent_trust_params["validator_max_missed_blocks"]``,
        the offending validator is:
          1. Slashed ``validator_missed_block_slash_pct`` of their balance
             (proceeds sent to the treasury).
          2. Removed from the active ``self.validators`` set.
          3. Their consecutive counter is reset to zero.

        A successful proposal resets the consecutive counter to zero, so a
        single skipped turn is not permanently damaging.
        """
        if self.consensus != "poa" or not self.validator_rotation_enabled:
            return
        expected = str(block.meta.get("expected_validator", "")).strip()
        actual = str(block.meta.get("validator", "")).strip()
        if not expected:
            return

        max_missed = int(self.agent_trust_params.get("validator_max_missed_blocks", 5))
        slash_pct = float(self.agent_trust_params.get("validator_missed_block_slash_pct", 0.1))

        if actual and actual != expected:
            # The expected validator skipped their turn.
            self._ensure_reputation(expected)
            r = self.reputation_index[expected]
            r["missed_blocks"] = r.get("missed_blocks", 0) + 1
            r["consecutive_missed_blocks"] = r.get("consecutive_missed_blocks", 0) + 1
            consecutive = r["consecutive_missed_blocks"]
            self._add_activity(
                f"[MISSED-BLOCK] Validator {expected[:12]} skipped turn at block {block.index} "
                f"(consecutive: {consecutive}/{max_missed})",
                block.timestamp,
            )
            if consecutive >= max_missed and expected in self.validators:
                current_balance = self.balance_index.get(expected, 0.0)
                slash_amount = round(current_balance * slash_pct, 8)
                if slash_amount > 0:
                    self.balance_index[expected] = round(current_balance - slash_amount, 8)
                    self.treasury_balance = round(self.treasury_balance + slash_amount, 8)
                self.validators.discard(expected)
                r["consecutive_missed_blocks"] = 0
                self._award_badge(expected, "validator_slashed", "Validator Slashed", block.timestamp)
                self._add_activity(
                    f"[VALIDATOR-SLASH] {expected[:12]} removed from validator set after "
                    f"{consecutive} consecutive missed blocks. "
                    f"Slashed {slash_amount:.4f} NOVA to treasury.",
                    block.timestamp,
                )
        elif actual:
            # Successful proposal — reset the miss counter for this validator.
            self._ensure_reputation(actual)
            self.reputation_index[actual]["consecutive_missed_blocks"] = 0

    def _try_fork_recovery(self, incoming_chain: List["Block"]) -> Optional[int]:
        """
        Detect a 1-deep reorg candidate: an incoming chain that shares our
        second-to-last block as its ancestor but diverges at the tip.

        Returns the fork-point height when a reorg is possible, else None.

        Triggered when::
            incoming_chain[-1].previous_hash == self.chain[-2].hash
        """
        if len(incoming_chain) < 2 or len(self.chain) < 2:
            return None
        if incoming_chain[-1].previous_hash == self.chain[-2].hash:
            return self.chain[-2].index
        return None

    def _prefer_incoming_chain(self, incoming_chain: List["Block"]) -> bool:
        """
        Tie-breaking rule for same-length fork resolution.

        PoA (rotation enabled):
            Prefer the chain whose tip was proposed by the round-correct
            validator.  If both or neither match, fall through to hash tie-break.

        PoW:
            Prefer the chain with higher cumulative work (leading-zero count
            summed across all block hashes is a lightweight proxy for total work).

        Tie / fallback:
            Prefer the chain with the lexicographically lower tip hash —
            deterministic and consistent across all honest nodes.
        """
        if not incoming_chain or not self.chain:
            return False
        incoming_tip = incoming_chain[-1]
        our_tip = self.chain[-1]
        if incoming_tip.hash == our_tip.hash:
            return False  # identical tips — no preference

        if self.consensus == "poa" and self.validator_rotation_enabled:
            tip_height = len(incoming_chain) - 1
            expected = self.expected_proposer_for_height(tip_height)
            if expected:
                incoming_correct = incoming_tip.meta.get("validator") == expected
                ours_correct = our_tip.meta.get("validator") == expected
                if incoming_correct and not ours_correct:
                    return True
                if ours_correct and not incoming_correct:
                    return False
        elif self.consensus == "pow":
            def _chain_work(chain: List["Block"]) -> int:
                # Leading zero hex digits per hash = cheap cumulative PoW proxy
                return sum(len(b.hash) - len(b.hash.lstrip("0")) for b in chain)
            incoming_work = _chain_work(incoming_chain)
            our_work = _chain_work(self.chain)
            if incoming_work != our_work:
                return incoming_work > our_work

        # Deterministic tie-break: lower hash wins (all honest nodes agree)
        return incoming_tip.hash < our_tip.hash

    def _validate_agent_activity_log_tx(self, tx: Dict[str, Any]) -> bool:
        required = {"id", "type", "agent", "agent_id", "action_type", "timestamp",
                    "nonce", "signer", "pubkey", "signature"}
        if not required.issubset(tx.keys()):
            return False
        if tx.get("type") != "agent_activity_log":
            return False
        agent = str(tx.get("agent", "")).strip()
        signer = str(tx.get("signer", "")).strip()
        if not agent or agent != signer:
            return False
        stake = float(tx.get("stake_locked", 0.0))
        if stake > 0 and self.get_balance(agent) < stake:
            return False
        if address_from_public_key(tx["pubkey"]) != signer:
            return False
        return verify_signature(self._signable_agent_activity_log(tx), tx["signature"], tx["pubkey"])

    def _ensure_collab_record(self, collab_id: str, created_at: float = 0.0) -> Dict[str, Any]:
        cid = str(collab_id).strip()
        if not cid:
            raise ValueError("collab_id is required")
        record = self.collab_index.setdefault(
            cid,
            {
                "collab_id": cid,
                "session_id": cid,
                "agents": [],
                "log_ids": [],
                "artifact_ids": [],
                "artifacts": [],
                "created_at": float(created_at or time.time()),
                "opened_at": float(created_at or time.time()),
                "last_active": float(created_at or time.time()),
                "intent_id": "",
                "objective": "",
                "opened_by": "",
                "status": "observed",
                "closed_at": 0.0,
                "closed_by": "",
                "outcome": "",
                "note": "",
                "summary_hash": "",
                "settlement": {},
            },
        )
        record.setdefault("collab_id", cid)
        record.setdefault("session_id", cid)
        record.setdefault("agents", [])
        record.setdefault("log_ids", [])
        record.setdefault("artifact_ids", [])
        record.setdefault("artifacts", [])
        record.setdefault("created_at", float(created_at or time.time()))
        record.setdefault("opened_at", float(record.get("created_at", created_at or time.time())))
        record.setdefault("last_active", float(record.get("opened_at", created_at or time.time())))
        record.setdefault("intent_id", "")
        record.setdefault("objective", "")
        record.setdefault("opened_by", "")
        record.setdefault("status", "observed")
        record.setdefault("closed_at", 0.0)
        record.setdefault("closed_by", "")
        record.setdefault("outcome", "")
        record.setdefault("note", "")
        record.setdefault("summary_hash", "")
        record.setdefault("settlement", {})
        return record

    def _refresh_collab_session_counts(self, addresses: List[str]) -> None:
        for addr in {str(value).strip() for value in addresses if str(value).strip()}:
            self._ensure_reputation(addr)
            sessions_for_agent = sum(1 for rec in self.collab_index.values() if addr in rec.get("agents", []))
            self.reputation_index[addr]["collab_sessions"] = sessions_for_agent

    def _effective_intent_status(self, intent: Dict[str, Any]) -> str:
        status = str(intent.get("status", "open")).strip().lower() or "open"
        expires_at = float(intent.get("expires_at", 0.0) or 0.0)
        if status not in {"fulfilled", "settled", "cancelled"} and expires_at > 0 and expires_at <= time.time():
            return "expired"
        return status

    def _validate_agent_intent_post_tx(self, tx: Dict[str, Any]) -> bool:
        required = {"id", "type", "intent_id", "creator", "agent_id", "intent", "timestamp",
                    "nonce", "signer", "pubkey", "signature"}
        if not required.issubset(tx.keys()):
            return False
        if tx.get("type") != "agent_intent_post":
            return False
        creator = str(tx.get("creator", "")).strip()
        signer = str(tx.get("signer", "")).strip()
        intent_id = str(tx.get("intent_id", "")).strip()
        if not creator or creator != signer or not intent_id or not str(tx.get("intent", "")).strip():
            return False
        if intent_id in self.intent_index:
            return False
        if float(tx.get("reward", 0.0)) < 0:
            return False
        if address_from_public_key(tx["pubkey"]) != signer:
            return False
        return verify_signature(self._signable_agent_intent_post(tx), tx["signature"], tx["pubkey"])

    def _validate_agent_session_open_tx(self, tx: Dict[str, Any]) -> bool:
        required = {"id", "type", "session_id", "opener", "participants", "timestamp",
                    "nonce", "signer", "pubkey", "signature"}
        if not required.issubset(tx.keys()):
            return False
        if tx.get("type") != "agent_session_open":
            return False
        opener = str(tx.get("opener", "")).strip()
        signer = str(tx.get("signer", "")).strip()
        session_id = str(tx.get("session_id", "")).strip()
        participants = [str(addr).strip() for addr in tx.get("participants", []) if str(addr).strip()]
        existing = self.collab_index.get(session_id, {})
        if not opener or opener != signer or not session_id or not participants:
            return False
        if opener not in participants:
            return False
        if len(set(participants)) != len(participants):
            return False
        if existing and existing.get("opened_by"):
            return False
        intent_id = str(tx.get("intent_id", "")).strip()
        if intent_id and intent_id not in self.intent_index:
            return False
        if address_from_public_key(tx["pubkey"]) != signer:
            return False
        return verify_signature(self._signable_agent_session_open(tx), tx["signature"], tx["pubkey"])

    def _validate_agent_artifact_commit_tx(self, tx: Dict[str, Any]) -> bool:
        required = {"id", "type", "artifact_id", "session_id", "agent", "artifact_type", "timestamp",
                    "nonce", "signer", "pubkey", "signature"}
        if not required.issubset(tx.keys()):
            return False
        if tx.get("type") != "agent_artifact_commit":
            return False
        artifact_id = str(tx.get("artifact_id", "")).strip()
        session_id = str(tx.get("session_id", "")).strip()
        agent = str(tx.get("agent", "")).strip()
        signer = str(tx.get("signer", "")).strip()
        session = self.collab_index.get(session_id, {})
        if not artifact_id or artifact_id in self.artifact_index or not session_id or agent != signer:
            return False
        if not session or agent not in session.get("agents", []):
            return False
        if str(session.get("status", "")).lower() in {"closed", "settled"}:
            return False
        if not any(str(tx.get(key, "")).strip() for key in ("output_hash", "evidence_hash", "evidence_url")):
            return False
        if address_from_public_key(tx["pubkey"]) != signer:
            return False
        return verify_signature(self._signable_agent_artifact_commit(tx), tx["signature"], tx["pubkey"])

    def _validate_agent_session_close_tx(self, tx: Dict[str, Any]) -> bool:
        required = {"id", "type", "session_id", "closer", "outcome", "timestamp",
                    "nonce", "signer", "pubkey", "signature"}
        if not required.issubset(tx.keys()):
            return False
        if tx.get("type") != "agent_session_close":
            return False
        closer = str(tx.get("closer", "")).strip()
        signer = str(tx.get("signer", "")).strip()
        session_id = str(tx.get("session_id", "")).strip()
        outcome = str(tx.get("outcome", "")).strip().lower()
        session = self.collab_index.get(session_id, {})
        allowed = {str(value).strip() for value in session.get("agents", []) if str(value).strip()}
        if session.get("opened_by"):
            allowed.add(str(session.get("opened_by", "")).strip())
        intent_id = str(session.get("intent_id", "")).strip()
        if intent_id:
            intent = self.intent_index.get(intent_id, {})
            creator = str(intent.get("creator", "")).strip()
            if creator:
                allowed.add(creator)
        if not closer or closer != signer or not session_id or outcome not in {"success", "partial", "failure", "cancelled"}:
            return False
        if not session or closer not in allowed:
            return False
        if str(session.get("status", "")).lower() in {"closed", "settled"}:
            return False
        if address_from_public_key(tx["pubkey"]) != signer:
            return False
        return verify_signature(self._signable_agent_session_close(tx), tx["signature"], tx["pubkey"])

    def _validate_agent_session_settle_tx(self, tx: Dict[str, Any]) -> bool:
        required = {"id", "type", "session_id", "settler", "payouts", "contribution_weights", "timestamp",
                    "nonce", "signer", "pubkey", "signature"}
        if not required.issubset(tx.keys()):
            return False
        if tx.get("type") != "agent_session_settle":
            return False
        settler = str(tx.get("settler", "")).strip()
        signer = str(tx.get("signer", "")).strip()
        session_id = str(tx.get("session_id", "")).strip()
        session = self.collab_index.get(session_id, {})
        participants = {str(addr).strip() for addr in session.get("agents", []) if str(addr).strip()}
        allowed = set(participants)
        opener = str(session.get("opened_by", "")).strip()
        if opener:
            allowed.add(opener)
        intent_id = str(session.get("intent_id", "")).strip()
        if intent_id:
            creator = str(self.intent_index.get(intent_id, {}).get("creator", "")).strip()
            if creator:
                allowed.add(creator)
        try:
            total_payout = sum(max(0.0, float(amount or 0.0)) for amount in dict(tx.get("payouts", {})).values())
            weight_values = [max(0.0, float(value or 0.0)) for value in dict(tx.get("contribution_weights", {})).values()]
        except (TypeError, ValueError):
            return False
        if not settler or settler != signer or not session_id:
            return False
        if not session or str(session.get("status", "")).lower() not in {"closed", "settled"}:
            return False
        if session.get("settlement"):
            return False
        if settler not in allowed:
            return False
        if any(str(addr).strip() not in participants for addr in dict(tx.get("payouts", {})).keys()):
            return False
        if any(str(addr).strip() not in participants for addr in dict(tx.get("contribution_weights", {})).keys()):
            return False
        if any(value < 0 for value in weight_values):
            return False
        available_balance = self.get_balance(settler) - self._pending_spent(settler)
        if total_payout > 0 and available_balance + 1e-12 < total_payout:
            return False
        if address_from_public_key(tx["pubkey"]) != signer:
            return False
        return verify_signature(self._signable_agent_session_settle(tx), tx["signature"], tx["pubkey"])

    def _apply_agent_activity_log_tx(self, tx: Dict[str, Any]) -> None:
        log_id = str(tx.get("id", "")).strip()
        agent_addr = str(tx.get("agent", "")).strip()
        agent_id = str(tx.get("agent_id", "")).strip()
        action_type = str(tx.get("action_type", "unknown")).strip()
        success = bool(tx.get("success", True))
        stake = float(tx.get("stake_locked", 0.0))
        ts = float(tx.get("timestamp", time.time()))

        # Lock stake from balance
        if stake > 0:
            self.balance_index[agent_addr] = round(
                self.balance_index.get(agent_addr, 0.0) - stake, 8
            )

        # Store in activity_log_index for attestation/challenge lookup
        self.activity_log_index[log_id] = {
            "log_id": log_id,
            "agent": agent_addr,
            "agent_id": agent_id,
            "action_type": action_type,
            "input_hash": str(tx.get("input_hash", "")),
            "output_hash": str(tx.get("output_hash", "")),
            "evidence_hash": str(tx.get("evidence_hash", "")),
            "evidence_url": str(tx.get("evidence_url", "")),
            "platform": str(tx.get("platform", "")),
            "external_ref": str(tx.get("external_ref", "")),
            "success": success,
            "duration_ms": int(tx.get("duration_ms", 0)),
            "stake_locked": stake,
            "timestamp": ts,
            "tags": list(tx.get("tags", [])),
            "note": str(tx.get("note", "")),
            "attestations": [],
            "challenges": [],
            "trust_tier": "stake-backed" if stake > 0 else "self-reported",
        }

        # Update reputation trust counters
        self._ensure_reputation(agent_addr)
        r = self.reputation_index[agent_addr]
        r["activity_logs"] = r.get("activity_logs", 0) + 1
        # Update success rate (rolling)
        total = r.get("activity_logs", 1)
        prev_rate = r.get("success_rate", 1.0)
        r["success_rate"] = round(((prev_rate * (total - 1)) + (1.0 if success else 0.0)) / total, 3)
        if stake > 0:
            r["stake_backed_logs"] = r.get("stake_backed_logs", 0) + 1
        if tx.get("evidence_url"):
            r["evidence_backed_logs"] = r.get("evidence_backed_logs", 0) + 1
        r["last_active"] = ts
        r["last_active_block"] = int(getattr(self, "height", 0))
        self._compute_trust_score(agent_addr)

        # Track collaboration sessions
        external_ref = str(tx.get("external_ref", ""))
        if external_ref.startswith("collab:"):
            rec = self._ensure_collab_record(external_ref, created_at=ts)
            if agent_addr not in rec["agents"]:
                rec["agents"].append(agent_addr)
            if log_id not in rec["log_ids"]:
                rec["log_ids"].append(log_id)
            rec["last_active"] = max(rec.get("last_active", ts), ts)
            self._refresh_collab_session_counts([agent_addr])

        # Update agent registry if registered
        if agent_id and agent_id in self.agent_registry:
            entry = self.agent_registry[agent_id]
            entry["activity_logs"] = entry.get("activity_logs", 0) + 1
            entry["last_active"] = ts

        # Milestone badges
        logs_count = r.get("activity_logs", 0)
        if logs_count == 1:
            self._award_badge(agent_addr, "first_activity_log", "First Off-Chain Log", ts)
        elif logs_count == 10:
            self._award_badge(agent_addr, "active_logger_10", "Active Logger", ts)
        elif logs_count == 100:
            self._award_badge(agent_addr, "veteran_logger_100", "Veteran Logger", ts)

        platform = str(tx.get("platform", "")).strip()
        icon = "OK" if success else "FAIL"
        platform_tag = f" [{platform}]" if platform else ""
        self._add_activity(
            f"[{icon}] Agent {agent_id or agent_addr[:12]} logged: {action_type}{platform_tag}", ts
        )

    def _apply_agent_activity_log_batch_tx(self, tx: Dict[str, Any]) -> None:
        """Apply a batch of activity logs submitted as a single transaction."""
        logs = tx.get("logs", [])
        for log_entry in logs:
            # Merge batch-level fields as defaults for each log entry
            merged = {
                "type": "agent_activity_log",
                "agent": tx.get("agent", ""),
                "agent_id": tx.get("agent_id", ""),
                "pubkey": tx.get("pubkey", ""),
                "id": log_entry.get("id", ""),
                "schema_version": tx.get("schema_version", "1.0"),
                **log_entry,
            }
            self._apply_agent_activity_log_tx(merged)

    def _apply_agent_intent_post_tx(self, tx: Dict[str, Any]) -> None:
        intent_id = str(tx.get("intent_id", "")).strip()
        creator = str(tx.get("creator", "")).strip()
        ts = float(tx.get("timestamp", time.time()))
        self.intent_index[intent_id] = {
            "intent_id": intent_id,
            "creator": creator,
            "agent_id": str(tx.get("agent_id", "")).strip(),
            "intent": str(tx.get("intent", "")).strip(),
            "role": str(tx.get("role", "")).strip(),
            "capability_tags": list(tx.get("capability_tags", [])),
            "desired_collaborators": list(tx.get("desired_collaborators", [])),
            "constraints_hash": str(tx.get("constraints_hash", "")).strip(),
            "reward": max(0.0, float(tx.get("reward", 0.0))),
            "expires_at": max(0.0, float(tx.get("expires_at", 0.0))),
            "note": str(tx.get("note", "")).strip(),
            "status": "open",
            "created_at": ts,
            "updated_at": ts,
            "tx_id": str(tx.get("id", "")),
            "session_ids": [],
        }
        self._add_activity(f"[INTENT] {creator[:12]} posted collaboration intent", ts)

    def _apply_agent_session_open_tx(self, tx: Dict[str, Any]) -> None:
        session_id = str(tx.get("session_id", "")).strip()
        ts = float(tx.get("timestamp", time.time()))
        participants = [str(addr).strip() for addr in tx.get("participants", []) if str(addr).strip()]
        rec = self._ensure_collab_record(session_id, created_at=ts)
        for participant in participants:
            if participant not in rec["agents"]:
                rec["agents"].append(participant)
        rec["intent_id"] = str(tx.get("intent_id", "")).strip()
        rec["objective"] = str(tx.get("objective", "")).strip()
        rec["opened_by"] = str(tx.get("opener", "")).strip()
        rec["opened_at"] = float(rec.get("opened_at", ts) or ts)
        rec["last_active"] = max(float(rec.get("last_active", 0.0) or 0.0), ts)
        rec["status"] = "open"
        if tx.get("note"):
            rec["note"] = str(tx.get("note", "")).strip()
        intent_id = str(tx.get("intent_id", "")).strip()
        if intent_id in self.intent_index:
            intent = self.intent_index[intent_id]
            intent.setdefault("session_ids", [])
            if session_id not in intent["session_ids"]:
                intent["session_ids"].append(session_id)
            intent["updated_at"] = ts
            if self._effective_intent_status(intent) == "open":
                intent["status"] = "in_progress"
        self._refresh_collab_session_counts(participants)
        self._add_activity(f"[SESSION] {session_id[:18]} opened with {len(rec['agents'])} participants", ts)

    def _apply_agent_artifact_commit_tx(self, tx: Dict[str, Any]) -> None:
        artifact_id = str(tx.get("artifact_id", "")).strip()
        session_id = str(tx.get("session_id", "")).strip()
        agent = str(tx.get("agent", "")).strip()
        ts = float(tx.get("timestamp", time.time()))
        artifact = {
            "artifact_id": artifact_id,
            "session_id": session_id,
            "agent": agent,
            "artifact_type": str(tx.get("artifact_type", "")).strip(),
            "output_hash": str(tx.get("output_hash", "")).strip(),
            "evidence_hash": str(tx.get("evidence_hash", "")).strip(),
            "evidence_url": str(tx.get("evidence_url", "")).strip(),
            "label": str(tx.get("label", "")).strip(),
            "note": str(tx.get("note", "")).strip(),
            "timestamp": ts,
            "tx_id": str(tx.get("id", "")),
        }
        self.artifact_index[artifact_id] = artifact
        rec = self._ensure_collab_record(session_id, created_at=ts)
        if artifact_id not in rec["artifact_ids"]:
            rec["artifact_ids"].append(artifact_id)
            rec["artifacts"].append(artifact)
        rec["last_active"] = max(float(rec.get("last_active", 0.0) or 0.0), ts)
        self._add_activity(f"[ARTIFACT] {agent[:12]} committed {artifact.get('artifact_type', 'artifact')}", ts)

    def _apply_agent_session_close_tx(self, tx: Dict[str, Any]) -> None:
        session_id = str(tx.get("session_id", "")).strip()
        ts = float(tx.get("timestamp", time.time()))
        rec = self._ensure_collab_record(session_id, created_at=ts)
        rec["closed_at"] = ts
        rec["closed_by"] = str(tx.get("closer", "")).strip()
        rec["outcome"] = str(tx.get("outcome", "")).strip().lower()
        rec["summary_hash"] = str(tx.get("summary_hash", "")).strip()
        rec["last_active"] = max(float(rec.get("last_active", 0.0) or 0.0), ts)
        rec["status"] = "closed"
        if tx.get("note"):
            rec["note"] = str(tx.get("note", "")).strip()
        intent_id = str(rec.get("intent_id", "")).strip()
        if intent_id in self.intent_index:
            intent = self.intent_index[intent_id]
            intent["updated_at"] = ts
            if rec["outcome"] == "success":
                intent["status"] = "fulfilled"
            elif self._effective_intent_status(intent) != "expired":
                open_sessions = [
                    sid for sid in intent.get("session_ids", [])
                    if str(self.collab_index.get(sid, {}).get("status", "")).lower() == "open"
                ]
                intent["status"] = "in_progress" if open_sessions else "open"
        self._add_activity(f"[SESSION] {session_id[:18]} closed ({rec['outcome']})", ts)

    def _apply_agent_session_settle_tx(self, tx: Dict[str, Any]) -> None:
        session_id = str(tx.get("session_id", "")).strip()
        settler = str(tx.get("settler", "")).strip()
        ts = float(tx.get("timestamp", time.time()))
        rec = self._ensure_collab_record(session_id, created_at=ts)
        payouts = {
            str(addr).strip(): max(0.0, float(amount or 0.0))
            for addr, amount in dict(tx.get("payouts", {})).items()
            if str(addr).strip()
        }
        contribution_weights = {
            str(addr).strip(): max(0.0, float(weight or 0.0))
            for addr, weight in dict(tx.get("contribution_weights", {})).items()
            if str(addr).strip()
        }
        total_payout = round(sum(payouts.values()), 8)
        if total_payout > 0:
            self.balance_index[settler] = round(self.balance_index.get(settler, 0.0) - total_payout, 8)
            for participant, amount in payouts.items():
                self.balance_index[participant] = round(self.balance_index.get(participant, 0.0) + amount, 8)
        rec["settlement"] = {
            "settler": settler,
            "payouts": payouts,
            "contribution_weights": contribution_weights,
            "verdict": str(tx.get("verdict", "")).strip().lower(),
            "note": str(tx.get("note", "")).strip(),
            "timestamp": ts,
            "tx_id": str(tx.get("id", "")),
        }
        rec["status"] = "settled"
        rec["last_active"] = max(float(rec.get("last_active", 0.0) or 0.0), ts)
        intent_id = str(rec.get("intent_id", "")).strip()
        if intent_id in self.intent_index:
            intent = self.intent_index[intent_id]
            intent["updated_at"] = ts
            if str(rec.get("outcome", "")).lower() == "success":
                intent["status"] = "settled"
        self._add_activity(f"[SETTLEMENT] {session_id[:18]} settled ({len(payouts)} payouts)", ts)

    def _apply_agent_challenge_tx(self, tx: Dict[str, Any]) -> None:
        log_id = str(tx.get("log_id", "")).strip()
        challenger = str(tx.get("challenger", "")).strip()
        stake = float(tx.get("stake_locked", 0.0))
        ts = float(tx.get("timestamp", time.time()))

        if log_id not in self.activity_log_index:
            return

        log = self.activity_log_index[log_id]
        agent_addr = log["agent"]

        # Lock challenger stake
        if stake > 0:
            self.balance_index[challenger] = round(
                self.balance_index.get(challenger, 0.0) - stake, 8
            )

        challenge_id = str(tx.get("id", ""))
        challenge_rec = {
            "challenge_id": challenge_id,
            "log_id": log_id,
            "challenger": challenger,
            "stake_locked": stake,
            "reason": str(tx.get("reason", "")),
            "timestamp": ts,
            "filed_at_block": getattr(self, "_replay_block_index", self.height),
            "resolved": False,
        }
        # Record challenge on the log and in the lookup index
        log["challenges"].append(challenge_rec)
        self.challenge_index[challenge_id] = challenge_rec
        log["trust_tier"] = "disputed"

        # Hit agent's trust score
        self._ensure_reputation(agent_addr)
        r = self.reputation_index[agent_addr]
        r["challenged_unanswered_logs"] = r.get("challenged_unanswered_logs", 0) + 1
        self._compute_trust_score(agent_addr)

        self._add_activity(
            f"[CHALLENGE] Agent {agent_addr[:12]} log challenged by {challenger[:12]}", ts
        )

    def _validate_agent_attest_tx(self, tx: Dict[str, Any]) -> bool:
        required = {"id", "type", "attester", "log_id", "sentiment", "timestamp",
                    "nonce", "signer", "pubkey", "signature"}
        if not required.issubset(tx.keys()):
            return False
        if tx.get("type") != "agent_attest":
            return False
        attester = str(tx.get("attester", "")).strip()
        signer = str(tx.get("signer", "")).strip()
        log_id = str(tx.get("log_id", "")).strip()
        sentiment = str(tx.get("sentiment", "")).strip().lower()
        if not attester or not log_id or sentiment not in {"positive", "negative"} or attester != signer:
            return False
        if log_id not in self.activity_log_index:
            return False
        if address_from_public_key(tx["pubkey"]) != signer:
            return False
        return verify_signature(self._signable_agent_attest(tx), tx["signature"], tx["pubkey"])

    def _validate_agent_challenge_tx(self, tx: Dict[str, Any]) -> bool:
        required = {"id", "type", "challenger", "log_id", "stake_locked", "timestamp",
                    "nonce", "signer", "pubkey", "signature"}
        if not required.issubset(tx.keys()):
            return False
        if tx.get("type") != "agent_challenge":
            return False
        challenger = str(tx.get("challenger", "")).strip()
        signer = str(tx.get("signer", "")).strip()
        log_id = str(tx.get("log_id", "")).strip()
        stake = float(tx.get("stake_locked", 0.0))
        if not challenger or not log_id or stake <= 0 or challenger != signer:
            return False
        if log_id not in self.activity_log_index:
            return False
        # challenger must have enough balance
        if self.get_balance(challenger) < stake:
            return False
        if address_from_public_key(tx["pubkey"]) != signer:
            return False
        return verify_signature(self._signable_agent_challenge(tx), tx["signature"], tx["pubkey"])

    def _apply_payment_tx(self, tx: Dict[str, Any], balances: Dict[str, float]) -> None:
        if tx.get("type") not in {"payment", "evm_payment"}:
            return
        amount = float(tx["amount"])
        sender = self._normalize_address(tx["sender"])
        recipient = self._normalize_address(tx["recipient"])
        gas_fee_native = self._evm_gas_fee_native(tx) if tx.get("type") == "evm_payment" else 0.0
        payment_fee = self._payment_fee(tx) if tx.get("type") == "payment" else 0.0
        if payment_fee < 0:
            payment_fee = 0.0
        if sender != SYSTEM_SENDER:
            balances[sender] = balances.get(sender, 0.0) - amount - gas_fee_native - payment_fee
        balances[recipient] = balances.get(recipient, 0.0) + amount

    def _apply_public_governance_tx(self, tx: Dict[str, Any], validator_set: Set[str]) -> None:
        if tx.get("type") != "validator_update":
            return
        action = str(tx.get("action", "")).strip().lower()
        candidate = str(tx.get("validator", "")).strip()
        if not candidate:
            return
        if action == "add":
            validator_set.add(candidate)
            return
        if action == "remove":
            if candidate in validator_set and len(validator_set) > 1:
                validator_set.remove(candidate)

    def _apply_ai_provider_tx(
        self,
        tx: Dict[str, Any],
        balances: Dict[str, float],
        provider_stakes: Dict[str, float],
        slash_events: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        tx_type = tx.get("type")
        if tx_type == "ai_provider_stake":
            provider = self._normalize_address(str(tx.get("provider", "")))
            amount = float(tx.get("amount", 0.0))
            if provider and amount > 0:
                balances[provider] = balances.get(provider, 0.0) - amount
                provider_stakes[provider] = provider_stakes.get(provider, 0.0) + amount
            return
        if tx_type != "ai_provider_slash":
            return
        provider = self._normalize_address(str(tx.get("provider", "")))
        recipient = self._normalize_address(str(tx.get("recipient", "")))
        amount = float(tx.get("amount", 0.0))
        if not provider or amount <= 0:
            return
        current = provider_stakes.get(provider, 0.0)
        provider_stakes[provider] = max(0.0, current - amount)
        if recipient and recipient != SYSTEM_SENDER:
            balances[recipient] = balances.get(recipient, 0.0) + amount
        if slash_events is not None:
            slash_events.append(
                {
                    "tx_id": tx.get("id", ""),
                    "provider": provider,
                    "amount": amount,
                    "reason": str(tx.get("reason", "")),
                    "recipient": recipient,
                    "signer": tx.get("signer", ""),
                    "timestamp": float(tx.get("timestamp", time.time())),
                }
            )

    def _apply_price_tx(self, tx: Dict[str, Any]) -> None:
        if tx.get("type") != "price_update":
            return
        symbol = str(tx["symbol"]).upper()
        self.latest_prices[symbol] = {
            "symbol": symbol,
            "price": float(tx["price"]),
            "source": str(tx.get("source", "manual")),
            "oracle": tx["oracle"],
            "timestamp": float(tx["timestamp"]),
            "tx_id": tx.get("id", ""),
        }

    def _apply_identity_tx(self, tx: Dict[str, Any]) -> None:
        tx_type = tx.get("type")
        signer = str(tx.get("signer", "")).strip()
        if not signer:
            return
        if tx_type == "identity_claim":
            handle = str(tx.get("handle", "")).strip().lower()
            self.identity_registry[signer] = {
                "address": signer,
                "handle": handle,
                "bio": str(tx.get("bio", "")),
                "links": dict(tx.get("links", {})),
                "claimed_at": float(tx.get("timestamp", time.time())),
                "tx_id": str(tx.get("id", "")),
            }
            self.handle_index[handle] = signer
        elif tx_type == "identity_update":
            if signer in self.identity_registry:
                self.identity_registry[signer]["bio"] = str(tx.get("bio", ""))
                self.identity_registry[signer]["links"] = dict(tx.get("links", {}))

    def _apply_agent_tx(self, tx: Dict[str, Any]) -> None:
        tx_type = tx.get("type")
        if tx_type == "agent_register":
            agent_id = str(tx.get("agent_id", "")).strip()
            if not agent_id:
                return
            owner = str(tx.get("owner", "")).strip()
            _registered_at = float(tx.get("timestamp", time.time()))
            _tx_id = str(tx.get("id", ""))
            self.agent_registry[agent_id] = {
                "agent_id": agent_id,
                "name": str(tx.get("name", "")),
                "owner": owner,
                "capabilities": list(tx.get("capabilities", [])),
                "task_types": list(tx.get("task_types", [])),
                "refusals": list(tx.get("refusals", [])),
                "system_prompt_hash": str(tx.get("system_prompt_hash", "")),
                "version_hash": str(tx.get("version_hash", "")),
                "wallet_address": owner,
                "registered_at": _registered_at,
                "tx_id": _tx_id,
                "attestations": [],
            }
            # Append to immutable version history — survives re-registration overwrites
            _prior = sum(1 for h in self.agent_register_history if h.get("agent_id") == agent_id)
            self.agent_register_history.append({
                "agent_id": agent_id,
                "owner": owner,
                "capabilities": list(tx.get("capabilities", [])),
                "task_types": list(tx.get("task_types", [])),
                "refusals": list(tx.get("refusals", [])),
                "system_prompt_hash": str(tx.get("system_prompt_hash", "")),
                "version_hash": str(tx.get("version_hash", "")),
                "registered_at": _registered_at,
                "tx_id": _tx_id,
                "version": _prior + 1,
            })
        elif tx_type == "agent_attest":
            log_id = str(tx.get("log_id", "")).strip()
            sentiment = str(tx.get("sentiment", "")).strip()
            attester = str(tx.get("attester", "")).strip()
            ts = float(tx.get("timestamp", time.time()))
            if log_id in self.activity_log_index:
                log = self.activity_log_index[log_id]
                log["attestations"].append({
                    "attester": attester,
                    "sentiment": sentiment,
                    "note": str(tx.get("note", "")),
                    "timestamp": ts,
                    "tx_id": str(tx.get("id", "")),
                })
                # Update trust counters on the agent
                agent_addr = log["agent"]
                if sentiment == "positive":
                    self._ensure_reputation(agent_addr)
                    r = self.reputation_index[agent_addr]
                    r["attested_logs"] = r.get("attested_logs", 0) + 1
                    # Weight attestation by attester's trust score
                    attester_rep = self.reputation_index.get(attester, {})
                    attester_score = float(attester_rep.get("trust_score", 0.1))
                    weight = max(0.1, attester_score)  # minimum weight 0.1 even for new agents
                    r["weighted_attestation_score"] = round(r.get("weighted_attestation_score", 0.0) + weight * 0.1, 3)
                    self._compute_trust_score(agent_addr)
                elif sentiment == "negative":
                    # Negative attestation: peer is saying this log is low-quality or false.
                    # Penalise proportional to attester's own trust score (high-trust peers
                    # carry more weight when they flag bad work).
                    self._ensure_reputation(agent_addr)
                    r = self.reputation_index[agent_addr]
                    r["negative_attestations"] = r.get("negative_attestations", 0) + 1
                    attester_rep = self.reputation_index.get(attester, {})
                    attester_score = float(attester_rep.get("trust_score", 0.1))
                    weight = max(0.1, attester_score)
                    # Negative review reduces the weighted attestation score (can go below 0)
                    r["weighted_attestation_score"] = round(r.get("weighted_attestation_score", 0.0) - weight * 0.05, 3)
                    self._compute_trust_score(agent_addr)

    def _ensure_reputation(self, address: str) -> None:
        if address not in self.reputation_index:
            self.reputation_index[address] = {
                "score": 0.0,
                "level": "Member",
                "badges": [],
                "history": [],
                "blocks_mined": 0,
                "total_nova_earned": 0.0,
                "tasks_completed": 0,
                "tasks_disputed": 0,
                "quality_scores": [],
                "governance_votes": 0,
                "governance_proposals": 0,
                "last_active": 0.0,
                "validator_since": None,
                # trust passport fields
                "activity_logs": 0,
                "attested_logs": 0,
                "stake_backed_logs": 0,
                "challenged_unanswered_logs": 0,
                "slashed_logs": 0,
                "evidence_backed_logs": 0,
                "trust_score": 0.0,
                "trust_tier": "unverified",
                "collab_sessions": 0,
                "success_rate": 1.0,
                "weighted_attestation_score": 0.0,
                "evidence_coverage": 0.0,
                "negative_attestations": 0,   # peer negative reviews received
                "last_active_block": 0,        # chain height at last activity log
            }

    def _compute_trust_score(self, addr: str) -> None:
        """Recompute trust_score and trust_tier on reputation_index[addr] in place."""
        self._ensure_reputation(addr)
        r = self.reputation_index[addr]
        logs = r.get("activity_logs", 0)
        attested = r.get("attested_logs", 0)
        stake_backed = r.get("stake_backed_logs", 0)
        evidence_backed = r.get("evidence_backed_logs", 0)
        challenged = r.get("challenged_unanswered_logs", 0)
        slashed = r.get("slashed_logs", 0)
        neg_attested = r.get("negative_attestations", 0)

        import math

        # Read governance-controlled weights
        w = self.agent_trust_params.get("trust_score_weights", {})
        w_activity = float(w.get("activity_log", 0.1))
        w_attested = float(w.get("attested_log", 0.4))
        w_stake = float(w.get("stake_backed_log", 0.3))
        w_evidence = float(w.get("evidence_backed_log", 0.2))
        w_challenged = float(w.get("challenged_unanswered_log", -1.5))
        w_slashed = float(w.get("slashed_log", -3.0))
        w_neg_attest = float(w.get("negative_attestation", -0.3))

        # Layer 1 — Activity: diminishing returns on raw log count (stops spam)
        base_score = math.log(logs + 1, 10) * w_activity * 5.0 if logs > 0 else 0.0

        # Layer 2 — Quality: success rate × attested logs
        success_rate = float(r.get("success_rate", 1.0))
        quality_score = success_rate * attested * w_attested * 2.0

        # Layer 3 — Network: attestations weighted by attester trust score
        network_score = float(r.get("weighted_attestation_score", 0.0))

        # Layer 4 — Evidence: what % of logs have proof
        evidence_coverage = (evidence_backed / logs) if logs > 0 else 0.0
        evidence_score = evidence_coverage * w_evidence * 10.0

        # Layer 5 — Stake signal
        stake_score = math.log(stake_backed + 1, 10) * w_stake if stake_backed > 0 else 0.0

        # Penalties (challenges, slashes, negative peer reviews)
        penalty = (
            challenged * abs(w_challenged)
            + slashed * abs(w_slashed)
            + neg_attested * abs(w_neg_attest)
        )

        raw_score = base_score + quality_score + network_score + evidence_score + stake_score - penalty

        # Time-decay: score erodes when an agent goes idle.
        # Each decay_epoch_blocks of inactivity multiplies the score by
        # (1 - decay_rate_per_epoch), floored at 10 % of raw_score.
        last_active_block = int(r.get("last_active_block", 0))
        current_block = int(getattr(self, "height", 0))
        decay_epoch_blocks = int(self.agent_trust_params.get("decay_epoch_blocks", 1000))
        decay_rate = float(self.agent_trust_params.get("decay_rate_per_epoch", 0.01))
        if decay_epoch_blocks > 0 and current_block > last_active_block:
            epochs_idle = (current_block - last_active_block) / decay_epoch_blocks
            decay_multiplier = max(0.1, (1.0 - decay_rate) ** epochs_idle)
        else:
            decay_multiplier = 1.0

        score = round(raw_score * decay_multiplier, 2)

        # Trust tier — now requires evidence coverage thresholds
        if slashed > 0:
            tier = "slashed"
        elif challenged > 0:
            tier = "disputed"
        elif stake_backed >= 1 and evidence_coverage >= 0.2:
            tier = "stake-backed"
        elif evidence_backed >= 2 and attested >= 1 and evidence_coverage >= 0.3:
            tier = "evidence-attested"
        elif attested >= 1:
            tier = "attested"
        elif logs >= 1:
            tier = "self-reported"
        else:
            tier = "unverified"

        r["trust_score"] = max(0.0, score)
        r["trust_tier"] = tier
        r["evidence_coverage"] = round(evidence_coverage, 3)
        r["success_rate"] = success_rate

    def _agent_registry_entry_for_address(self, address: str) -> Dict[str, Any]:
        for agent in self.agent_registry.values():
            owner = str(agent.get("owner", "")).strip()
            wallet_address = str(agent.get("wallet_address", "")).strip()
            if address == owner or address == wallet_address:
                return dict(agent)
        return {}

    def _finalize_capability_stats(self, stats_by_key: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        finalized: Dict[str, Dict[str, Any]] = {}
        for key, stats in stats_by_key.items():
            total = int(stats.get("total_logs", 0))
            evidenced_logs = int(stats.get("evidenced_logs", 0))
            successes = int(stats.get("successes", 0))
            finalized[key] = {
                "total_logs": total,
                "evidenced_logs": evidenced_logs,
                "attested_logs": int(stats.get("attested_logs", 0)),
                "success_rate": round(successes / total, 4) if total else 0.0,
                "evidence_rate": round(evidenced_logs / total, 4) if total else 0.0,
                "last_active": float(stats.get("last_active", 0.0)),
            }
        return finalized

    def capability_profile(self, address: str) -> Dict[str, Any]:
        """
        Evidence-backed capability profile derived from actual activity logs.
        This is the on-chain behavioral graph used by richer discovery surfaces.
        """
        address = str(address).strip()
        by_action_type: Dict[str, Dict[str, Any]] = {}
        by_tag: Dict[str, Dict[str, Any]] = {}
        logs = [v for v in self.activity_log_index.values() if v.get("agent") == address]

        def _accumulate(bucket: Dict[str, Dict[str, Any]], key: str, log: Dict[str, Any]) -> None:
            rec = bucket.setdefault(
                key,
                {
                    "total_logs": 0,
                    "evidenced_logs": 0,
                    "attested_logs": 0,
                    "successes": 0,
                    "last_active": 0.0,
                },
            )
            evidenced = bool(log.get("evidence_hash") or log.get("evidence_url"))
            attested = any(
                str(att.get("sentiment", "")).lower() == "positive"
                for att in log.get("attestations", [])
            )
            rec["total_logs"] += 1
            rec["evidenced_logs"] += int(evidenced)
            rec["attested_logs"] += int(attested)
            rec["successes"] += int(bool(log.get("success", True)))
            rec["last_active"] = max(float(rec.get("last_active", 0.0)), float(log.get("timestamp", 0.0)))

        for log in logs:
            action_type = str(log.get("action_type", "")).strip().lower()
            if action_type:
                _accumulate(by_action_type, action_type, log)
            for raw_tag in log.get("tags", []):
                tag = str(raw_tag).strip().lower()
                if tag:
                    _accumulate(by_tag, tag, log)

        collab_sessions_detail = [
            dict(rec) for rec in self.collab_index.values() if address in rec.get("agents", [])
        ]
        collab_partners = sorted({
            str(agent).strip()
            for rec in collab_sessions_detail
            for agent in rec.get("agents", [])
            if str(agent).strip() and str(agent).strip() != address
        })
        reg = self._agent_registry_entry_for_address(address)
        return {
            "address": address,
            "agent_id": reg.get("agent_id", ""),
            "name": reg.get("name", ""),
            "declared_capabilities": list(reg.get("capabilities", [])),
            "task_types": list(reg.get("task_types", [])),
            "refusals": list(reg.get("refusals", [])),
            "system_prompt_hash": str(reg.get("system_prompt_hash", "")),
            "by_action_type": self._finalize_capability_stats(by_action_type),
            "by_tag": self._finalize_capability_stats(by_tag),
            "collab_partners": collab_partners,
            "collab_sessions_detail": collab_sessions_detail,
        }

    def discover_agents(
        self,
        tags: Optional[List[str]] = None,
        min_score: float = 0.0,
        min_tier: str = "",
        platform: str = "",
        limit: int = 20,
        exclude: Optional[List[str]] = None,
        capability: str = "",
        min_log_count: int = 1,
        min_evidence_count: int = 0,
        has_collaborated: bool = False,
        collaborated_with: str = "",
    ) -> List[Dict[str, Any]]:
        """Discover agents by trust, observed capabilities, and collaboration history."""
        filter_tags = [str(tag).strip().lower() for tag in (tags or []) if str(tag).strip()]
        filter_platform = str(platform or "").strip().lower()
        capability = str(capability or "").strip().lower()
        exclude_set = {str(addr).strip() for addr in (exclude or []) if str(addr).strip()}
        collaborated_with = str(collaborated_with or "").strip()

        tier_order = ["unverified", "self-reported", "attested", "evidence-attested", "stake-backed"]
        if min_tier in tier_order:
            allowed_tiers = set(tier_order[tier_order.index(min_tier):])
        else:
            allowed_tiers = None

        results: List[Dict[str, Any]] = []
        for addr, rep in self.reputation_index.items():
            if addr in exclude_set:
                continue
            if rep.get("activity_logs", 0) == 0:
                continue
            tier = str(rep.get("trust_tier", "unverified"))
            if tier in {"disputed", "slashed"}:
                continue
            if allowed_tiers is not None and tier not in allowed_tiers:
                continue
            if float(rep.get("trust_score", 0.0)) < float(min_score):
                continue

            agent_logs = [log for log in self.activity_log_index.values() if log.get("agent") == addr]
            if filter_tags:
                tag_sets = [{str(tag).lower() for tag in log.get("tags", [])} for log in agent_logs]
                if not any(any(tag in tag_set for tag in filter_tags) for tag_set in tag_sets):
                    continue
            if filter_platform and not any(
                str(log.get("platform", "")).lower() == filter_platform for log in agent_logs
            ):
                continue

            capability_profile = None
            capability_stats = None
            if capability or has_collaborated or collaborated_with:
                capability_profile = self.capability_profile(addr)

            if capability:
                capability_stats = (
                    capability_profile["by_action_type"].get(capability)
                    or capability_profile["by_tag"].get(capability)
                )
                if capability_stats is None:
                    continue
                if int(capability_stats.get("total_logs", 0)) < max(1, int(min_log_count)):
                    continue
                if int(capability_stats.get("evidenced_logs", 0)) < max(0, int(min_evidence_count)):
                    continue

            if has_collaborated and not capability_profile.get("collab_partners", []):
                continue
            if collaborated_with and collaborated_with not in capability_profile.get("collab_partners", []):
                continue

            reg = self._agent_registry_entry_for_address(addr)
            result = {
                "address": addr,
                "agent_id": reg.get("agent_id", ""),
                "name": reg.get("name", ""),
                "trust_score": float(rep.get("trust_score", 0.0)),
                "trust_tier": tier,
                "total_logs": int(rep.get("activity_logs", 0)),
                "attested_logs": int(rep.get("attested_logs", 0)),
                "stake_backed_logs": int(rep.get("stake_backed_logs", 0)),
                "evidence_backed_logs": int(rep.get("evidence_backed_logs", 0)),
                "challenged_logs": int(rep.get("challenged_unanswered_logs", 0)),
                "slashed_logs": int(rep.get("slashed_logs", 0)),
                "platforms": sorted({log.get("platform") for log in agent_logs if log.get("platform")}),
                "tags": sorted({tag for log in agent_logs for tag in log.get("tags", [])}),
                "last_active": float(rep.get("last_active", 0.0)),
                "collab_sessions": sum(
                    1 for rec in self.collab_index.values() if addr in rec.get("agents", [])
                ),
                "declared_capabilities": list(reg.get("capabilities", [])),
                "task_types": list(reg.get("task_types", [])),
            }
            if capability_stats is not None:
                result["capability_stats"] = capability_stats
            if capability_profile is not None:
                result["capability_profile"] = capability_profile
            results.append(result)

        results.sort(key=lambda item: item["trust_score"], reverse=True)
        return results[: max(1, min(int(limit), 100))]

    def list_agent_intents(
        self,
        creator: str = "",
        status: str = "",
        capability: str = "",
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        creator = str(creator or "").strip()
        status = str(status or "").strip().lower()
        capability = str(capability or "").strip().lower()
        rows: List[Dict[str, Any]] = []
        for intent in self.intent_index.values():
            if creator and str(intent.get("creator", "")).strip() != creator:
                continue
            effective_status = self._effective_intent_status(intent)
            if status and effective_status != status:
                continue
            tags = [str(tag).strip().lower() for tag in intent.get("capability_tags", []) if str(tag).strip()]
            if capability and capability not in tags:
                continue
            rows.append({**dict(intent), "status": effective_status})
        rows.sort(key=lambda item: float(item.get("created_at", 0.0)), reverse=True)
        return rows[: max(1, min(int(limit), 100))]

    def get_agent_session(self, session_id: str) -> Dict[str, Any]:
        session_id = str(session_id or "").strip()
        if not session_id:
            return {}
        rec = self.collab_index.get(session_id)
        if not rec:
            return {}
        return dict(rec)

    def list_agent_sessions(
        self,
        participant: str = "",
        status: str = "",
        intent_id: str = "",
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        participant = str(participant or "").strip()
        status = str(status or "").strip().lower()
        intent_id = str(intent_id or "").strip()
        rows: List[Dict[str, Any]] = []
        for rec in self.collab_index.values():
            participants = {str(addr).strip() for addr in rec.get("agents", []) if str(addr).strip()}
            rec_status = str(rec.get("status", "")).strip().lower()
            if participant and participant not in participants:
                continue
            if status and rec_status != status:
                continue
            if intent_id and str(rec.get("intent_id", "")).strip() != intent_id:
                continue
            rows.append(dict(rec))
        rows.sort(key=lambda item: float(item.get("last_active", item.get("created_at", 0.0))), reverse=True)
        return rows[: max(1, min(int(limit), 100))]

    def _add_reputation(self, address: str, delta: float, reason: str, ts: float) -> None:
        self._ensure_reputation(address)
        r = self.reputation_index[address]
        r["score"] = round(r["score"] + delta, 2)
        r["history"].append({"delta": delta, "reason": reason, "ts": ts})
        if len(r["history"]) > 200:
            r["history"] = r["history"][-200:]
        score = r["score"]
        if score >= 5000:
            r["level"] = "Legend"
        elif score >= 2000:
            r["level"] = "Master"
        elif score >= 500:
            r["level"] = "Expert"
        elif score >= 100:
            r["level"] = "Builder"
        else:
            r["level"] = "Member"

    def _award_badge(self, address: str, badge_id: str, label: str, ts: float) -> None:
        self._ensure_reputation(address)
        existing = [b["id"] for b in self.reputation_index[address]["badges"]]
        if badge_id not in existing:
            badge = {"id": badge_id, "label": label, "ts": ts}
            self.reputation_index[address]["badges"].append(badge)
            self._add_activity(f"🏆 {address[:12]}... earned badge: {label}", ts)

    def _add_activity(self, message: str, ts: float) -> None:
        self.activity_feed.append({"message": message, "ts": ts})
        if len(self.activity_feed) > 500:
            self.activity_feed = self.activity_feed[-500:]

    def _signable_identity_verify(self, payload: Dict) -> Dict:
        return {k: payload[k] for k in ["type", "notary", "target", "level", "ts", "nonce"]}

    def _signable_task_delegate(self, payload: Dict) -> Dict:
        return {k: payload[k] for k in ["type", "owner", "agent_id", "task_id", "title", "description", "reward", "min_reputation", "ts", "nonce"]}

    def _signable_task_complete(self, payload: Dict) -> Dict:
        return {k: payload[k] for k in ["type", "agent", "task_id", "result_hash", "note", "ts", "nonce"]}

    def _signable_task_review(self, payload: Dict) -> Dict:
        return {k: payload[k] for k in ["type", "owner", "task_id", "approved", "quality_score", "note", "ts", "nonce"]}

    def _signable_task_dispute(self, payload: Dict) -> Dict:
        return {k: payload[k] for k in ["type", "disputer", "task_id", "reason", "ts", "nonce"]}

    def _signable_governance_propose(self, payload: Dict) -> Dict:
        return {k: payload[k] for k in ["type", "proposer", "proposal_id", "title", "description", "param_changes", "vote_window_blocks", "ts", "nonce"]}

    def _signable_governance_vote(self, payload: Dict) -> Dict:
        return {k: payload[k] for k in ["type", "voter", "proposal_id", "vote", "ts", "nonce"]}

    def _signable_validator_nominate(self, payload: Dict) -> Dict:
        base = {k: payload[k] for k in ["type", "candidate", "ts", "nonce"]}
        if "stake_amount" in payload:
            base["stake_amount"] = float(payload["stake_amount"])
        return base

    def _signable_validator_unstake(self, payload: Dict) -> Dict:
        return {k: payload[k] for k in ["type", "candidate", "ts", "nonce"]}

    def _signable_validator_election_vote(self, payload: Dict) -> Dict:
        return {k: payload[k] for k in ["type", "voter", "candidate", "ts", "nonce"]}

    def _signable_ai_oracle_assign(self, payload: Dict) -> Dict:
        return {k: payload[k] for k in ["type", "owner", "asset_id", "agent_id", "oracle_type", "ts", "nonce"]}

    def _signable_ai_oracle_event(self, payload: Dict) -> Dict:
        return {k: payload[k] for k in ["type", "agent", "asset_id", "event_type", "value", "note", "ts", "nonce"]}

    def _signable_model_register(self, payload: Dict) -> Dict:
        return {k: payload[k] for k in ["type", "owner", "model_id", "name", "description", "capabilities", "version_hash", "inference_fee", "revenue_shares", "ts", "nonce"]}

    def _signable_model_transfer(self, payload: Dict) -> Dict:
        return {k: payload[k] for k in ["type", "owner", "model_id", "new_owner", "ts", "nonce"]}

    def _signable_model_revenue_share(self, payload: Dict) -> Dict:
        return {k: payload[k] for k in ["type", "owner", "model_id", "shares", "ts", "nonce"]}

    def _signable_model_inference(self, payload: Dict) -> Dict:
        return {k: payload[k] for k in ["type", "caller", "model_id", "input_hash", "output_hash", "ts", "nonce"]}

    def _signable_pipeline_create(self, payload: Dict) -> Dict:
        return {k: payload[k] for k in ["type", "owner", "pipeline_id", "title", "steps", "total_reward", "ts", "nonce"]}

    def _signable_pipeline_step_complete(self, payload: Dict) -> Dict:
        return {k: payload[k] for k in ["type", "agent", "pipeline_id", "step_index", "result_hash", "note", "ts", "nonce"]}

    def _signable_pipeline_approve(self, payload: Dict) -> Dict:
        return {k: payload[k] for k in ["type", "owner", "pipeline_id", "approved", "note", "ts", "nonce"]}

    # ── Model Ownership ────────────────────────────────────────────────────────

    def _validate_model_register_tx(self, payload: Dict, signature: str, public_key: Dict) -> None:
        for f in ["type", "owner", "model_id", "name", "description", "capabilities", "version_hash", "inference_fee", "revenue_shares", "ts", "nonce"]:
            if f not in payload:
                raise ValueError(f"model_register missing: {f}")
        if payload["model_id"] in self.model_registry:
            raise ValueError("model_register: model_id already exists")
        if not verify_signature(self._signable_model_register(payload), signature, public_key):
            raise ValueError("model_register: invalid signature")

    def _validate_model_transfer_tx(self, payload: Dict, signature: str, public_key: Dict) -> None:
        for f in ["type", "owner", "model_id", "new_owner", "ts", "nonce"]:
            if f not in payload:
                raise ValueError(f"model_transfer missing: {f}")
        model = self.model_registry.get(payload["model_id"])
        if not model:
            raise ValueError("model_transfer: model not found")
        if model["owner"] != payload["owner"]:
            raise ValueError("model_transfer: not the owner")
        if not verify_signature(self._signable_model_transfer(payload), signature, public_key):
            raise ValueError("model_transfer: invalid signature")

    def _validate_model_revenue_share_tx(self, payload: Dict, signature: str, public_key: Dict) -> None:
        for f in ["type", "owner", "model_id", "shares", "ts", "nonce"]:
            if f not in payload:
                raise ValueError(f"model_revenue_share missing: {f}")
        model = self.model_registry.get(payload["model_id"])
        if not model:
            raise ValueError("model_revenue_share: model not found")
        if model["owner"] != payload["owner"]:
            raise ValueError("model_revenue_share: not the owner")
        if sum(payload["shares"].values()) > 1.0:
            raise ValueError("model_revenue_share: shares sum exceeds 1.0")
        if not verify_signature(self._signable_model_revenue_share(payload), signature, public_key):
            raise ValueError("model_revenue_share: invalid signature")

    def _validate_model_inference_tx(self, payload: Dict, signature: str, public_key: Dict) -> None:
        for f in ["type", "caller", "model_id", "input_hash", "output_hash", "ts", "nonce"]:
            if f not in payload:
                raise ValueError(f"model_inference missing: {f}")
        model = self.model_registry.get(payload["model_id"])
        if not model:
            raise ValueError("model_inference: model not found")
        if model.get("inference_fee", 0) > 0 and self.get_balance(payload["caller"]) < model["inference_fee"]:
            raise ValueError("model_inference: insufficient balance for inference fee")
        if not verify_signature(self._signable_model_inference(payload), signature, public_key):
            raise ValueError("model_inference: invalid signature")

    def _validate_pipeline_create_tx(self, payload: Dict, signature: str, public_key: Dict) -> None:
        for f in ["type", "owner", "pipeline_id", "title", "steps", "total_reward", "ts", "nonce"]:
            if f not in payload:
                raise ValueError(f"pipeline_create missing: {f}")
        if payload["pipeline_id"] in self.pipeline_registry:
            raise ValueError("pipeline_create: duplicate pipeline_id")
        if not payload["steps"]:
            raise ValueError("pipeline_create: steps cannot be empty")
        if payload["total_reward"] <= 0:
            raise ValueError("pipeline_create: total_reward must be positive")
        if self.get_balance(payload["owner"]) < payload["total_reward"]:
            raise ValueError("pipeline_create: insufficient balance")
        if not verify_signature(self._signable_pipeline_create(payload), signature, public_key):
            raise ValueError("pipeline_create: invalid signature")

    def _validate_pipeline_step_complete_tx(self, payload: Dict, signature: str, public_key: Dict) -> None:
        for f in ["type", "agent", "pipeline_id", "step_index", "result_hash", "note", "ts", "nonce"]:
            if f not in payload:
                raise ValueError(f"pipeline_step_complete missing: {f}")
        pipeline = self.pipeline_registry.get(payload["pipeline_id"])
        if not pipeline:
            raise ValueError("pipeline_step_complete: pipeline not found")
        if pipeline["status"] != "active":
            raise ValueError("pipeline_step_complete: pipeline not active")
        if payload["step_index"] != pipeline["current_step"]:
            raise ValueError("pipeline_step_complete: wrong step index")
        if not verify_signature(self._signable_pipeline_step_complete(payload), signature, public_key):
            raise ValueError("pipeline_step_complete: invalid signature")

    def _validate_pipeline_approve_tx(self, payload: Dict, signature: str, public_key: Dict) -> None:
        for f in ["type", "owner", "pipeline_id", "approved", "note", "ts", "nonce"]:
            if f not in payload:
                raise ValueError(f"pipeline_approve missing: {f}")
        pipeline = self.pipeline_registry.get(payload["pipeline_id"])
        if not pipeline:
            raise ValueError("pipeline_approve: pipeline not found")
        if pipeline["owner"] != payload["owner"]:
            raise ValueError("pipeline_approve: not the owner")
        if not verify_signature(self._signable_pipeline_approve(payload), signature, public_key):
            raise ValueError("pipeline_approve: invalid signature")

    def _apply_model_register_tx(self, payload: Dict, block_height: int) -> None:
        self.model_registry[payload["model_id"]] = {
            "model_id": payload["model_id"], "owner": payload["owner"],
            "name": payload["name"], "description": payload["description"],
            "capabilities": payload["capabilities"], "version_hash": payload["version_hash"],
            "inference_fee": payload["inference_fee"], "revenue_shares": payload["revenue_shares"],
            "inference_count": 0, "total_revenue": 0.0,
            "registered_at": payload["ts"], "block_registered": block_height,
        }
        self._add_reputation(payload["owner"], 20.0, "model_registered", payload["ts"])
        owned = sum(1 for m in self.model_registry.values() if m["owner"] == payload["owner"])
        if owned == 1:
            self._award_badge(payload["owner"], "ai_pioneer", "AI Pioneer", payload["ts"])
        self._add_activity(f"🧠 AI Model registered: {payload['name']}", payload["ts"])

    def _apply_model_transfer_tx(self, payload: Dict, block_height: int) -> None:
        self.model_registry[payload["model_id"]]["owner"] = payload["new_owner"]
        self.model_registry[payload["model_id"]]["transferred_at"] = payload["ts"]
        self._add_activity(f"🔄 Model {payload['model_id']} transferred", payload["ts"])

    def _apply_model_revenue_share_tx(self, payload: Dict, block_height: int) -> None:
        self.model_registry[payload["model_id"]]["revenue_shares"] = payload["shares"]
        self._add_activity(f"💰 Revenue shares updated for {payload['model_id']}", payload["ts"])

    def _apply_model_inference_tx(self, payload: Dict, block_height: int) -> None:
        model = self.model_registry[payload["model_id"]]
        fee = model.get("inference_fee", 0.0)
        if fee > 0:
            self.balances[payload["caller"]] = self.get_balance(payload["caller"]) - fee
            shared = 0.0
            for addr, pct in model.get("revenue_shares", {}).items():
                amt = round(fee * pct, 8)
                self.balances[addr] = self.get_balance(addr) + amt
                shared += amt
            self.balances[model["owner"]] = self.get_balance(model["owner"]) + round(fee - shared, 8)
            model["total_revenue"] = round(model.get("total_revenue", 0.0) + fee, 8)
        model["inference_count"] = model.get("inference_count", 0) + 1
        self._add_reputation(payload["caller"], 0.5, "model_inference", payload["ts"])
        self._add_activity(f"⚡ Inference on {model['name']}: call #{model['inference_count']}", payload["ts"])

    def _apply_pipeline_create_tx(self, payload: Dict, block_height: int) -> None:
        self.pipeline_registry[payload["pipeline_id"]] = {
            "pipeline_id": payload["pipeline_id"], "owner": payload["owner"],
            "title": payload["title"], "steps": payload["steps"],
            "total_reward": payload["total_reward"], "current_step": 0,
            "status": "active", "step_results": [],
            "created_at": payload["ts"], "block_created": block_height,
        }
        self.balances[payload["owner"]] = self.get_balance(payload["owner"]) - payload["total_reward"]
        self._add_reputation(payload["owner"], 5.0, "pipeline_created", payload["ts"])
        self._add_activity(f"🔗 Pipeline: {payload['title']} ({len(payload['steps'])} steps, {payload['total_reward']} NOVA)", payload["ts"])

    def _apply_pipeline_step_complete_tx(self, payload: Dict, block_height: int) -> None:
        pipeline = self.pipeline_registry[payload["pipeline_id"]]
        step_idx = payload["step_index"]
        step = pipeline["steps"][step_idx]
        pipeline["step_results"].append({"step_index": step_idx, "agent": payload["agent"],
            "result_hash": payload["result_hash"], "note": payload["note"], "ts": payload["ts"]})
        reward_pct = step.get("reward_pct", 1.0 / len(pipeline["steps"]))
        step_reward = round(pipeline["total_reward"] * reward_pct, 8)
        self.balances[payload["agent"]] = self.get_balance(payload["agent"]) + step_reward
        self._add_reputation(payload["agent"], 10.0, f"pipeline_step_{step_idx}_done", payload["ts"])
        next_step = step_idx + 1
        if next_step >= len(pipeline["steps"]):
            pipeline["status"] = "completed"
            pipeline["completed_at"] = payload["ts"]
            self._add_activity(f"✅ Pipeline completed: {pipeline['title']}", payload["ts"])
        else:
            pipeline["current_step"] = next_step
            self._add_activity(f"➡️ Pipeline {pipeline['title']}: step {step_idx+1}/{len(pipeline['steps'])} done", payload["ts"])

    def _apply_pipeline_approve_tx(self, payload: Dict, block_height: int) -> None:
        pipeline = self.pipeline_registry[payload["pipeline_id"]]
        pipeline["status"] = "approved" if payload["approved"] else "rejected"
        self._add_reputation(payload["owner"], 5.0, "pipeline_reviewed", payload["ts"])
        icon = "🏆" if payload["approved"] else "❌"
        self._add_activity(f"{icon} Pipeline {'approved' if payload['approved'] else 'rejected'}: {pipeline['title']}", payload["ts"])

    # ------------------------------------------------------------------
    # ZK Proof tx — validate + apply
    # ------------------------------------------------------------------

    def _signable_zk_proof(self, payload: Dict) -> Dict:
        return {k: payload[k] for k in
                ("type", "circuit_id", "prover", "public_inputs", "ts", "nonce")}

    def _signable_zk_register_circuit(self, payload: Dict) -> Dict:
        return {k: payload[k] for k in
                ("type", "circuit_id", "registrar", "ts", "nonce")}

    def _validate_zk_proof_tx(self, payload: Dict, signature: str, public_key: Dict) -> None:
        for f in ("type", "circuit_id", "prover", "proof", "public_inputs", "ts", "nonce"):
            if f not in payload:
                raise ValueError(f"zk_proof missing field: {f}")
        if not verify_signature(self._signable_zk_proof(payload), signature, public_key):
            raise ValueError("zk_proof: invalid signature")
        circuit_id = payload["circuit_id"]
        # Look up VK: first check on-chain registry, then built-in
        vk = (self.zk_circuit_registry.get(circuit_id, {}).get("vk")
              or _ZK_BUILTIN_CIRCUITS.get(circuit_id, {}).get("vk"))
        if vk is None:
            raise ValueError(f"zk_proof: unknown circuit_id {circuit_id!r}")
        # Dev VKs skip actual pairing check (for testing only)
        if vk.get("_dev"):
            return
        if not HAS_ZK:
            raise ValueError("zk_proof: ZK verification not available (install py_ecc)")
        if not groth16_verify(vk, payload["proof"], payload["public_inputs"]):
            raise ValueError("zk_proof: proof verification failed")
        # Replay prevention: reject if this exact proof was already accepted.
        # The proof hash is a SHA256 of the canonical serialised proof points —
        # any re-submission of the same (A, B, C) tuple is rejected even with
        # different public inputs, because the cryptographic binding is on the
        # proof itself.
        import hashlib as _hashlib, json as _json
        _proof_content = _json.dumps(payload["proof"], sort_keys=True)
        _proof_hash = _hashlib.sha256(_proof_content.encode()).hexdigest()
        if hasattr(self, "zk_proof_hashes") and _proof_hash in self.zk_proof_hashes:
            raise ValueError(f"zk_proof: replay detected — proof already submitted (hash={_proof_hash[:16]}...)")
        # Freshness check: reject proofs whose timestamp is outside the allowed age window.
        # This prevents delayed or pre-generated proofs from being submitted long after
        # the underlying computation occurred.
        max_age = int(self.agent_trust_params.get("zk_proof_max_age_seconds", 3600))
        if max_age > 0:
            proof_age = abs(time.time() - float(payload.get("ts", 0)))
            if proof_age > max_age:
                raise ValueError(
                    f"zk_proof: proof timestamp too old "
                    f"({proof_age:.0f}s > {max_age}s allowed)"
                )

    def _apply_zk_proof_tx(self, payload: Dict, block_height: int) -> None:
        import hashlib as _hashlib, json as _json
        _proof_content = _json.dumps(payload["proof"], sort_keys=True)
        _proof_hash = _hashlib.sha256(_proof_content.encode()).hexdigest()
        # Register in the permanent replay-prevention set
        if not hasattr(self, "zk_proof_hashes"):
            self.zk_proof_hashes: set = set()
        self.zk_proof_hashes.add(_proof_hash)
        entry = {
            "circuit_id": payload["circuit_id"],
            "prover": payload["prover"],
            "public_inputs": payload["public_inputs"],
            "proof_hash": _proof_hash,   # stored for audit + replay guard rebuild
            "metadata": payload.get("metadata", {}),
            "block_height": block_height,
            "ts": payload["ts"],
        }
        self.zk_proof_log.append(entry)
        if len(self.zk_proof_log) > 1000:
            self.zk_proof_log = self.zk_proof_log[-1000:]
        self._add_reputation(payload["prover"], 15.0, f"zk_proof:{payload['circuit_id']}", payload["ts"])
        self._add_activity(
            f"🔐 ZK proof verified: {payload['circuit_id']} by {payload['prover'][:12]}...",
            payload["ts"],
        )

    def _validate_zk_register_circuit_tx(self, payload: Dict, signature: str, public_key: Dict) -> None:
        for f in ("type", "circuit_id", "vk", "registrar", "ts", "nonce"):
            if f not in payload:
                raise ValueError(f"zk_register_circuit missing field: {f}")
        if not verify_signature(self._signable_zk_register_circuit(payload), signature, public_key):
            raise ValueError("zk_register_circuit: invalid signature")
        vk = payload["vk"]
        for k in ("alpha", "beta", "gamma", "delta", "ic"):
            if k not in vk:
                raise ValueError(f"zk_register_circuit: vk missing key {k!r}")

    def _apply_zk_register_circuit_tx(self, payload: Dict, block_height: int) -> None:
        self.zk_circuit_registry[payload["circuit_id"]] = {
            "circuit_id": payload["circuit_id"],
            "vk": payload["vk"],
            "description": payload.get("description", ""),
            "registrar": payload["registrar"],
            "registered_at_block": block_height,
            "ts": payload["ts"],
        }
        self._add_activity(
            f"📋 ZK circuit registered: {payload['circuit_id']} by {payload['registrar'][:12]}...",
            payload["ts"],
        )

    def _validate_identity_verify_tx(self, payload: Dict, signature: str, public_key: Dict) -> None:
        for f in ["type", "notary", "target", "level", "ts", "nonce"]:
            if f not in payload:
                raise ValueError(f"identity_verify missing field: {f}")
        if payload["level"] not in ("basic", "kyc", "accredited"):
            raise ValueError("identity_verify: invalid level")
        if payload["target"] not in self.identity_registry:
            raise ValueError("identity_verify: target has no identity claim")
        if not verify_signature(self._signable_identity_verify(payload), signature, public_key):
            raise ValueError("identity_verify: invalid signature")

    def _validate_task_delegate_tx(self, payload: Dict, signature: str, public_key: Dict) -> None:
        for f in ["type", "owner", "agent_id", "task_id", "title", "description", "reward", "min_reputation", "ts", "nonce"]:
            if f not in payload:
                raise ValueError(f"task_delegate missing field: {f}")
        if payload["reward"] <= 0:
            raise ValueError("task_delegate: reward must be positive")
        if payload["task_id"] in self.task_registry:
            raise ValueError("task_delegate: duplicate task_id")
        if self.get_balance(payload["owner"]) < payload["reward"]:
            raise ValueError("task_delegate: insufficient balance for reward escrow")
        if not verify_signature(self._signable_task_delegate(payload), signature, public_key):
            raise ValueError("task_delegate: invalid signature")

    def _validate_task_complete_tx(self, payload: Dict, signature: str, public_key: Dict) -> None:
        for f in ["type", "agent", "task_id", "result_hash", "note", "ts", "nonce"]:
            if f not in payload:
                raise ValueError(f"task_complete missing field: {f}")
        task = self.task_registry.get(payload["task_id"])
        if not task:
            raise ValueError("task_complete: task not found")
        if task["status"] != "open":
            raise ValueError("task_complete: task is not open")
        if task.get("agent_id") and task["agent_id"] != payload["agent"]:
            raise ValueError("task_complete: wrong agent")
        if not verify_signature(self._signable_task_complete(payload), signature, public_key):
            raise ValueError("task_complete: invalid signature")

    def _validate_task_review_tx(self, payload: Dict, signature: str, public_key: Dict) -> None:
        for f in ["type", "owner", "task_id", "approved", "quality_score", "note", "ts", "nonce"]:
            if f not in payload:
                raise ValueError(f"task_review missing field: {f}")
        task = self.task_registry.get(payload["task_id"])
        if not task:
            raise ValueError("task_review: task not found")
        if task["status"] != "completed":
            raise ValueError("task_review: task not in completed state")
        if task["owner"] != payload["owner"]:
            raise ValueError("task_review: only task owner can review")
        if not verify_signature(self._signable_task_review(payload), signature, public_key):
            raise ValueError("task_review: invalid signature")

    def _validate_task_dispute_tx(self, payload: Dict, signature: str, public_key: Dict) -> None:
        for f in ["type", "disputer", "task_id", "reason", "ts", "nonce"]:
            if f not in payload:
                raise ValueError(f"task_dispute missing field: {f}")
        task = self.task_registry.get(payload["task_id"])
        if not task:
            raise ValueError("task_dispute: task not found")
        if task["status"] not in ("completed",):
            raise ValueError("task_dispute: can only dispute completed tasks")
        if not verify_signature(self._signable_task_dispute(payload), signature, public_key):
            raise ValueError("task_dispute: invalid signature")

    def _validate_governance_propose_tx(self, payload: Dict, signature: str, public_key: Dict) -> None:
        for f in ["type", "proposer", "proposal_id", "title", "description", "param_changes", "vote_window_blocks", "ts", "nonce"]:
            if f not in payload:
                raise ValueError(f"governance_propose missing field: {f}")
        if payload["proposal_id"] in self.governance_proposals:
            raise ValueError("governance_propose: duplicate proposal_id")
        if not isinstance(payload["param_changes"], dict):
            raise ValueError("governance_propose: param_changes must be a dict")
        if not verify_signature(self._signable_governance_propose(payload), signature, public_key):
            raise ValueError("governance_propose: invalid signature")

    def _validate_governance_vote_tx(self, payload: Dict, signature: str, public_key: Dict) -> None:
        for f in ["type", "voter", "proposal_id", "vote", "ts", "nonce"]:
            if f not in payload:
                raise ValueError(f"governance_vote missing field: {f}")
        prop = self.governance_proposals.get(payload["proposal_id"])
        if not prop:
            raise ValueError("governance_vote: proposal not found")
        if prop["status"] != "open":
            raise ValueError("governance_vote: proposal is not open")
        if payload["voter"] in prop["votes"]:
            raise ValueError("governance_vote: already voted")
        if not verify_signature(self._signable_governance_vote(payload), signature, public_key):
            raise ValueError("governance_vote: invalid signature")

    def _validate_validator_nominate_tx(self, payload: Dict, signature: str, public_key: Dict) -> None:
        for f in ["type", "candidate", "ts", "nonce"]:
            if f not in payload:
                raise ValueError(f"validator_nominate missing: {f}")
        if not verify_signature(self._signable_validator_nominate(payload), signature, public_key):
            raise ValueError("validator_nominate: invalid signature")
        # Only enforce minimum stake on new txs that explicitly include stake_amount.
        # Legacy txs on the live chain may not have this field — allow them through.
        if "stake_amount" in payload:
            stake = float(payload["stake_amount"])
            if stake < MIN_VALIDATOR_STAKE:
                raise ValueError(f"validator_nominate: stake {stake} below minimum {MIN_VALIDATOR_STAKE} NOVA")

    def _validate_validator_unstake_tx(self, payload: Dict, signature: str, public_key: Dict) -> None:
        for f in ["type", "candidate", "ts", "nonce"]:
            if f not in payload:
                raise ValueError(f"validator_unstake missing: {f}")
        if not verify_signature(self._signable_validator_unstake(payload), signature, public_key):
            raise ValueError("validator_unstake: invalid signature")

    def _validate_validator_election_vote_tx(self, payload: Dict, signature: str, public_key: Dict) -> None:
        for f in ["type", "voter", "candidate", "ts", "nonce"]:
            if f not in payload:
                raise ValueError(f"validator_election_vote missing: {f}")
        if payload["candidate"] not in self.validator_candidates:
            raise ValueError("validator_election_vote: candidate not nominated")
        cand = self.validator_candidates[payload["candidate"]]
        if payload["voter"] in cand.get("voters", []):
            raise ValueError("validator_election_vote: already voted for this candidate")
        if not verify_signature(self._signable_validator_election_vote(payload), signature, public_key):
            raise ValueError("validator_election_vote: invalid signature")

    def _validate_ai_oracle_assign_tx(self, payload: Dict, signature: str, public_key: Dict) -> None:
        for f in ["type", "owner", "asset_id", "agent_id", "oracle_type", "ts", "nonce"]:
            if f not in payload:
                raise ValueError(f"ai_oracle_assign missing: {f}")
        if payload["oracle_type"] not in ("price", "compliance", "condition"):
            raise ValueError("ai_oracle_assign: invalid oracle_type")
        if not verify_signature(self._signable_ai_oracle_assign(payload), signature, public_key):
            raise ValueError("ai_oracle_assign: invalid signature")

    def _validate_ai_oracle_event_tx(self, payload: Dict, signature: str, public_key: Dict) -> None:
        for f in ["type", "agent", "asset_id", "event_type", "value", "note", "ts", "nonce"]:
            if f not in payload:
                raise ValueError(f"ai_oracle_event missing: {f}")
        assignment = self.oracle_assignments.get(payload["asset_id"])
        if not assignment:
            raise ValueError("ai_oracle_event: no oracle assigned to this asset")
        if assignment["agent_id"] != payload["agent"]:
            raise ValueError("ai_oracle_event: sender is not the assigned oracle")
        if not verify_signature(self._signable_ai_oracle_event(payload), signature, public_key):
            raise ValueError("ai_oracle_event: invalid signature")

    def _apply_identity_verify_tx(self, payload: Dict, block_height: int) -> None:
        target = payload["target"]
        notary = payload["notary"]
        ts = payload["ts"]
        if target in self.identity_registry:
            self.identity_registry[target]["verified"] = True
            self.identity_registry[target]["verification_level"] = payload["level"]
            self.identity_registry[target]["verified_by"] = notary
            self.identity_registry[target]["verified_at"] = ts
        self._add_reputation(notary, 10.0, "identity_notary_verify", ts)
        self._add_reputation(target, 25.0, "identity_verified", ts)
        handle = self.identity_registry.get(target, {}).get("handle", target[:12])
        self._add_activity(f"✅ Identity verified: {handle} ({payload['level']})", ts)

    def _apply_task_delegate_tx(self, payload: Dict, block_height: int, _balances: Optional[Dict[str, float]] = None) -> None:
        task_id = payload["task_id"]
        self.task_registry[task_id] = {
            "task_id": task_id,
            "owner": payload["owner"],
            "agent_id": payload["agent_id"],
            "title": payload["title"],
            "description": payload["description"],
            "reward": payload["reward"],
            "min_reputation": payload["min_reputation"],
            "status": "open",
            "created_at": payload["ts"],
            "completed_at": None,
            "reviewed_at": None,
            "result_hash": None,
            "quality_score": None,
            "block_created": block_height,
        }
        owner = payload["owner"]
        reward = payload["reward"]
        if _balances is not None:
            _balances[owner] = _balances.get(owner, 0.0) - reward
        else:
            self.balance_index[owner] = self.get_balance(owner) - reward
        self._add_reputation(owner, 2.0, "task_created", payload["ts"])
        self._add_activity(f"📋 New task: {payload['title']} (reward: {reward} NOVA)", payload["ts"])

    def _apply_task_complete_tx(self, payload: Dict, block_height: int) -> None:
        task = self.task_registry[payload["task_id"]]
        task["status"] = "completed"
        task["completed_at"] = payload["ts"]
        task["result_hash"] = payload["result_hash"]
        task["completed_by"] = payload["agent"]
        self._add_activity(f"🤖 Task completed: {task['title']} by {payload['agent'][:12]}...", payload["ts"])

    def _apply_task_review_tx(self, payload: Dict, block_height: int, _balances: Optional[Dict[str, float]] = None) -> None:
        task = self.task_registry[payload["task_id"]]
        agent_addr = task.get("completed_by", task.get("agent_id", ""))
        reward = task["reward"]
        ts = payload["ts"]
        task["reviewed_at"] = ts
        task["quality_score"] = payload["quality_score"]
        task["review_note"] = payload.get("note", "")
        if payload["approved"]:
            task["status"] = "approved"
            if _balances is not None:
                _balances[agent_addr] = _balances.get(agent_addr, 0.0) + reward
            else:
                self.balance_index[agent_addr] = self.get_balance(agent_addr) + reward
            quality = payload["quality_score"]
            rep_delta = 5.0 + (quality / 100.0) * 20.0
            self._add_reputation(agent_addr, rep_delta, f"task_approved_quality_{quality}", ts)
            self._add_reputation(payload["owner"], 3.0, "task_review_approved", ts)
            self._ensure_reputation(agent_addr)
            r = self.reputation_index[agent_addr]
            r["tasks_completed"] = r.get("tasks_completed", 0) + 1
            r["quality_scores"] = r.get("quality_scores", [])
            r["quality_scores"].append(quality)
            if r["tasks_completed"] == 1:
                self._award_badge(agent_addr, "first_job", "First Job", ts)
            if r["tasks_completed"] == 10:
                self._award_badge(agent_addr, "ten_jobs", "10 Jobs", ts)
            if r["tasks_completed"] == 100:
                self._award_badge(agent_addr, "century_club", "Century Club", ts)
            self._add_activity(f"✅ Task approved: {task['title']} (quality: {quality}/100)", ts)
        else:
            task["status"] = "rejected"
            owner = payload["owner"]
            if _balances is not None:
                _balances[owner] = _balances.get(owner, 0.0) + reward
            else:
                self.balance_index[owner] = self.get_balance(owner) + reward
            self._add_reputation(agent_addr, -5.0, "task_rejected", ts)
            self._ensure_reputation(agent_addr)
            self.reputation_index[agent_addr]["tasks_disputed"] = self.reputation_index[agent_addr].get("tasks_disputed", 0) + 1
            self._add_activity(f"❌ Task rejected: {task['title']}", ts)

    def _apply_task_dispute_tx(self, payload: Dict, block_height: int) -> None:
        task = self.task_registry[payload["task_id"]]
        task["status"] = "disputed"
        task["dispute_reason"] = payload["reason"]
        task["disputed_by"] = payload["disputer"]
        self._add_reputation(payload["disputer"], 1.0, "task_dispute_filed", payload["ts"])
        self._add_activity(f"⚠️ Task disputed: {task['title']}", payload["ts"])

    def _apply_governance_propose_tx(self, payload: Dict, block_height: int) -> None:
        prop_id = payload["proposal_id"]
        self.governance_proposals[prop_id] = {
            "proposal_id": prop_id,
            "proposer": payload["proposer"],
            "title": payload["title"],
            "description": payload["description"],
            "param_changes": payload["param_changes"],
            "vote_window_blocks": payload["vote_window_blocks"],
            "status": "open",
            "votes": {},
            "yes_count": 0,
            "no_count": 0,
            "created_at": payload["ts"],
            "block_created": block_height,
            "closes_at_block": block_height + payload["vote_window_blocks"],
        }
        self._add_reputation(payload["proposer"], 10.0, "governance_proposal_submitted", payload["ts"])
        self._ensure_reputation(payload["proposer"])
        r = self.reputation_index[payload["proposer"]]
        r["governance_proposals"] = r.get("governance_proposals", 0) + 1
        if r["governance_proposals"] == 1:
            self._award_badge(payload["proposer"], "governance_founder", "Governance Founder", payload["ts"])
        self._add_activity(f"⚡ New governance proposal: {payload['title']}", payload["ts"])

    def _apply_governance_vote_tx(self, payload: Dict, block_height: int) -> None:
        prop = self.governance_proposals[payload["proposal_id"]]
        voter = payload["voter"]
        vote = payload["vote"]
        prop["votes"][voter] = vote
        if vote:
            prop["yes_count"] += 1
        else:
            prop["no_count"] += 1
        self._add_reputation(voter, 5.0, "governance_voted", payload["ts"])
        self._ensure_reputation(voter)
        r = self.reputation_index[voter]
        r["governance_votes"] = r.get("governance_votes", 0) + 1
        if r["governance_votes"] == 1:
            self._award_badge(voter, "first_vote", "First Vote", payload["ts"])

    def _apply_validator_nominate_tx(self, payload: Dict, block_height: int, balances: Optional[Dict] = None) -> None:
        addr = payload["candidate"]
        stake = float(payload.get("stake_amount", 0.0))
        if addr not in self.validator_candidates:
            self.validator_candidates[addr] = {
                "votes": 0, "voters": [], "nominated_at": payload["ts"], "block": block_height,
                "stake": stake, "stake_locked_at_block": block_height,
            }
        else:
            self.validator_candidates[addr]["stake"] = stake
            self.validator_candidates[addr]["stake_locked_at_block"] = block_height
        if balances is not None and stake > 0:
            balances[addr] = max(0.0, balances.get(addr, 0.0) - stake)
        self._add_reputation(addr, 5.0, "validator_nominated", payload["ts"])
        # Permissionless admission: sufficient stake → immediate promotion, no votes needed
        if stake >= MIN_VALIDATOR_STAKE and addr not in self.validators:
            self.validators.add(addr)
            self._add_activity(f"✅ {addr[:12]}... joined validator set (stake: {stake} NOVA)", payload["ts"])
        else:
            self._add_activity(f"🗳️ {addr[:12]}... nominated as validator candidate (stake: {stake} NOVA)", payload["ts"])

    def _apply_validator_election_vote_tx(self, payload: Dict, block_height: int) -> None:
        candidate_addr = payload["candidate"]
        cand = self.validator_candidates[candidate_addr]
        cand["votes"] += 1
        cand["voters"].append(payload["voter"])
        self._add_reputation(payload["voter"], 3.0, "validator_election_voted", payload["ts"])
        self._add_activity(f"🗳️ Vote cast for validator candidate {candidate_addr[:12]}...", payload["ts"])
        # Auto-promote if vote threshold reached and sufficient stake
        if (cand["votes"] >= VALIDATOR_VOTE_THRESHOLD
                and float(cand.get("stake", 0.0)) >= MIN_VALIDATOR_STAKE
                and candidate_addr not in self.validators):
            self.validators.add(candidate_addr)
            self._add_activity(f"✅ {candidate_addr[:12]}... auto-promoted to active validator", payload["ts"])

    def _apply_validator_unstake_tx(self, payload: Dict, block_height: int, balances: Optional[Dict] = None) -> None:
        addr = payload["candidate"]
        if addr in self.validator_candidates:
            cand = self.validator_candidates[addr]
            stake = float(cand.get("stake", 0.0))
            locked_at = cand.get("stake_locked_at_block", 0)
            if block_height - locked_at >= VALIDATOR_UNBONDING_BLOCKS:
                if balances is not None and stake > 0:
                    balances[addr] = balances.get(addr, 0.0) + stake
                del self.validator_candidates[addr]
                self._add_activity(f"🔓 {addr[:12]}... unstaked and exited validator pool", payload["ts"])
            # If unbonding not complete, tx should have been rejected upstream
        self.validators.discard(addr)

    def _apply_ai_oracle_assign_tx(self, payload: Dict, block_height: int) -> None:
        asset_id = payload["asset_id"]
        self.oracle_assignments[asset_id] = {
            "asset_id": asset_id,
            "agent_id": payload["agent_id"],
            "oracle_type": payload["oracle_type"],
            "owner": payload["owner"],
            "assigned_at": payload["ts"],
            "events": [],
        }
        self._add_reputation(payload["owner"], 5.0, "oracle_assigned", payload["ts"])
        self._add_activity(f"🔮 AI Oracle assigned to asset {asset_id[:16]}... ({payload['oracle_type']})", payload["ts"])

    def _apply_ai_oracle_event_tx(self, payload: Dict, block_height: int) -> None:
        assignment = self.oracle_assignments.get(payload["asset_id"])
        event = {
            "event_type": payload["event_type"],
            "value": payload["value"],
            "note": payload["note"],
            "ts": payload["ts"],
            "block": block_height,
        }
        if assignment:
            assignment["events"].append(event)
            if len(assignment["events"]) > 1000:
                assignment["events"] = assignment["events"][-1000:]
            assignment["last_event"] = event
        self._add_reputation(payload["agent"], 2.0, f"oracle_event_{payload['event_type']}", payload["ts"])
        self._add_activity(f"🔮 Oracle event on {payload['asset_id'][:16]}...: {payload['event_type']} = {payload['value']}", payload["ts"])

    def _pending_spent(self, sender: str) -> float:
        normalized_sender = self._normalize_address(sender)
        return float(self.pending_spend_index.get(normalized_sender, 0.0))

    def _next_evm_nonce(self, sender_evm: str) -> int:
        return int(self.evm_next_nonce_index.get(str(sender_evm).lower(), 0))

    def _build_balance_state(self) -> Dict[str, float]:
        return dict(self.balance_index)

    def _index_pending_transaction(self, tx: Dict[str, Any]) -> None:
        tx_type = tx.get("type")
        if tx_type == "payment":
            sender = self._normalize_address(str(tx.get("sender", "")))
            if sender and sender != SYSTEM_SENDER:
                amount = float(tx.get("amount", 0.0))
                fee = max(0.0, self._payment_fee(tx))
                self.pending_spend_index[sender] = self.pending_spend_index.get(sender, 0.0) + amount + fee
            return
        if tx_type == "evm_payment":
            sender = self._normalize_address(str(tx.get("sender", "")))
            if sender and sender != SYSTEM_SENDER:
                amount = float(tx.get("amount", 0.0))
                fee = max(0.0, self._evm_gas_fee_native(tx))
                self.pending_spend_index[sender] = self.pending_spend_index.get(sender, 0.0) + amount + fee
            sender_evm = str(tx.get("sender_evm", "")).lower()
            if sender_evm:
                try:
                    nonce = int(tx.get("nonce", -1))
                except (TypeError, ValueError):
                    nonce = -1
                if nonce >= 0:
                    current = int(self.evm_next_nonce_index.get(sender_evm, 0))
                    if nonce + 1 > current:
                        self.evm_next_nonce_index[sender_evm] = nonce + 1
            return
        if tx_type == "ai_provider_stake":
            provider = self._normalize_address(str(tx.get("provider", "")))
            if provider:
                amount = float(tx.get("amount", 0.0))
                self.pending_spend_index[provider] = self.pending_spend_index.get(provider, 0.0) + max(0.0, amount)
            return
        if tx_type == "agent_session_settle":
            settler = self._normalize_address(str(tx.get("settler", "")))
            if settler:
                total_payout = sum(
                    max(0.0, float(amount or 0.0))
                    for amount in dict(tx.get("payouts", {})).values()
                )
                self.pending_spend_index[settler] = self.pending_spend_index.get(settler, 0.0) + total_payout

    def prune_mempool(self, now: Optional[float] = None, force_persist: bool = False) -> Dict[str, int]:
        now_ts = float(now if now is not None else time.time())
        expired = 0
        evicted = 0
        changed = False

        if self.pending_transactions and self.mempool_tx_ttl_seconds > 0:
            cutoff = now_ts - self.mempool_tx_ttl_seconds
            kept: List[Dict[str, Any]] = []
            for tx in self.pending_transactions:
                try:
                    tx_ts = float(tx.get("timestamp", 0.0))
                except (TypeError, ValueError):
                    tx_ts = 0.0
                if tx_ts > 0 and tx_ts < cutoff:
                    expired += 1
                    changed = True
                    continue
                kept.append(tx)
            self.pending_transactions = kept

        if self.pending_transactions and self.mempool_max_transactions > 0:
            max_allowed = int(self.mempool_max_transactions)
            if len(self.pending_transactions) > max_allowed:
                indexed: List[Tuple[int, Dict[str, Any]]] = list(enumerate(self.pending_transactions))

                def keep_key(item: Tuple[int, Dict[str, Any]]) -> Tuple[float, float, int]:
                    pos, tx = item
                    fee = self._tx_effective_fee(tx)
                    timestamp = float(tx.get("timestamp", 0.0))
                    return (-fee, timestamp, pos)

                indexed.sort(key=keep_key)
                keep_positions = {pos for pos, _ in indexed[:max_allowed]}
                before = len(self.pending_transactions)
                self.pending_transactions = [
                    tx for pos, tx in enumerate(self.pending_transactions) if pos in keep_positions
                ]
                evicted = before - len(self.pending_transactions)
                changed = changed or evicted > 0

        self.mempool_prune_stats["last_pruned_at"] = now_ts
        self.mempool_prune_stats["last_expired"] = float(expired)
        self.mempool_prune_stats["last_evicted"] = float(evicted)
        self.mempool_prune_stats["expired_total"] = float(
            self.mempool_prune_stats.get("expired_total", 0.0)
        ) + float(expired)
        self.mempool_prune_stats["evicted_total"] = float(
            self.mempool_prune_stats.get("evicted_total", 0.0)
        ) + float(evicted)

        if changed:
            if self.height == len(self.chain):
                self._rebuild_runtime_indexes()
            else:
                self._reindex_pending_runtime_state()
            self._touch_and_save(force=bool(force_persist))
        return {"expired": expired, "evicted": evicted, "pending": len(self.pending_transactions)}

    def _rebuild_runtime_indexes(self) -> None:
        balances: Dict[str, float] = {}
        provider_stakes: Dict[str, float] = {}
        slash_events: List[Dict[str, Any]] = []
        latest_prices: Dict[str, Dict[str, Any]] = {}
        active_validators: Set[str] = set(self.initial_validators) if self.initial_validators else set(self.validators)
        evm_next: Dict[str, int] = {}
        total_tx_count = 0
        total_minted_supply = 0.0
        self.identity_registry = {}
        self.handle_index = {}
        self.agent_registry = {}
        self.reputation_index = {}
        self.task_registry = {}
        self.governance_proposals = {}
        self.activity_feed = []
        self.treasury_balance = 0.0
        self.validator_candidates = {}
        self.oracle_assignments = {}
        self.model_registry = {}
        self.pipeline_registry = {}
        self.zk_circuit_registry = {}
        self.zk_proof_log = []
        self.zk_proof_hashes: set = set()  # permanent replay-prevention set
        self.activity_log_index = {}
        self.challenge_index = {}
        self.collab_index = {}
        self.intent_index = {}
        self.artifact_index = {}
        self.agent_param_proposals = {}
        self.balance_index = balances
        self.agent_trust_params = {
            "schema_version": 1,
            "challenge_window_blocks": AGENT_CHALLENGE_WINDOW_BLOCKS,
            "trust_score_weights": {
                "activity_log": 0.1,
                "attested_log": 0.4,
                "stake_backed_log": 0.3,
                "evidence_backed_log": 0.2,
                "challenged_unanswered_log": -1.5,
                "slashed_log": -3.0,
            },
            "auto_slash_on_window_expiry": True,
            "slash_outcome": "agent_stake_to_challenger_plus_refund",
            "param_update_min_endorsements": 2,
            "validator_max_missed_blocks": 5,
            "validator_missed_block_slash_pct": 0.1,
            "zk_proof_max_age_seconds": 3600,
        }
        self.agent_trust_params_history = []

        for block in self.chain:
            self._replay_block_index = block.index
            total_tx_count += len(block.transactions)
            system_payments = [
                tx for tx in block.transactions
                if tx.get("type") == "payment" and tx.get("sender") == SYSTEM_SENDER
            ]
            for tx in block.transactions:
                self._apply_payment_tx(tx, balances)
                self._apply_ai_provider_tx(tx, balances, provider_stakes, slash_events=slash_events)

                if tx.get("type") == "price_update":
                    symbol = str(tx["symbol"]).upper()
                    latest_prices[symbol] = {
                        "symbol": symbol,
                        "price": float(tx["price"]),
                        "source": str(tx.get("source", "manual")),
                        "oracle": tx["oracle"],
                        "timestamp": float(tx["timestamp"]),
                        "tx_id": tx.get("id", ""),
                    }
                elif tx.get("type") == "validator_update":
                    self._apply_public_governance_tx(tx, active_validators)
                elif tx.get("type") == "evm_payment":
                    sender_evm = str(tx.get("sender_evm", "")).lower()
                    if sender_evm:
                        try:
                            nonce = int(tx.get("nonce", -1))
                        except (TypeError, ValueError):
                            nonce = -1
                        if nonce >= 0:
                            evm_next[sender_evm] = max(evm_next.get(sender_evm, 0), nonce + 1)
                elif tx.get("type") in {"identity_claim", "identity_update"}:
                    self._apply_identity_tx(tx)
                elif tx.get("type") in {"agent_register", "agent_attest"}:
                    self._apply_agent_tx(tx)
                elif tx.get("type") == "agent_activity_log":
                    self._apply_agent_activity_log_tx(tx)
                elif tx.get("type") == "agent_activity_log_batch":
                    self._apply_agent_activity_log_batch_tx(tx)
                elif tx.get("type") == "agent_intent_post":
                    self._apply_agent_intent_post_tx(tx)
                elif tx.get("type") == "agent_session_open":
                    self._apply_agent_session_open_tx(tx)
                elif tx.get("type") == "agent_artifact_commit":
                    self._apply_agent_artifact_commit_tx(tx)
                elif tx.get("type") == "agent_session_close":
                    self._apply_agent_session_close_tx(tx)
                elif tx.get("type") == "agent_session_settle":
                    self._apply_agent_session_settle_tx(tx)
                elif tx.get("type") == "agent_challenge":
                    self._apply_agent_challenge_tx(tx)
                elif tx.get("type") == "agent_challenge_resolve":
                    self._apply_agent_challenge_resolve_tx(tx)
                elif tx.get("type") == "agent_param_propose":
                    self._apply_agent_param_propose_tx(tx, block.index)
                elif tx.get("type") == "agent_param_endorse":
                    self._apply_agent_param_endorse_tx(tx, block.index)
                elif tx.get("type") == "identity_verify":
                    self._apply_identity_verify_tx(tx, block.index)
                elif tx.get("type") == "task_delegate":
                    self._apply_task_delegate_tx(tx, block.index, _balances=balances)
                elif tx.get("type") == "task_complete":
                    self._apply_task_complete_tx(tx, block.index)
                elif tx.get("type") == "task_review":
                    self._apply_task_review_tx(tx, block.index, _balances=balances)
                elif tx.get("type") == "task_dispute":
                    self._apply_task_dispute_tx(tx, block.index)
                elif tx.get("type") == "governance_propose":
                    self._apply_governance_propose_tx(tx, block.index)
                elif tx.get("type") == "governance_vote":
                    self._apply_governance_vote_tx(tx, block.index)
                elif tx.get("type") == "validator_nominate":
                    self._apply_validator_nominate_tx(tx, block.index)
                elif tx.get("type") == "validator_unstake":
                    self._apply_validator_unstake_tx(tx, block.index)
                elif tx.get("type") == "validator_election_vote":
                    self._apply_validator_election_vote_tx(tx, block.index)
                elif tx.get("type") == "ai_oracle_assign":
                    self._apply_ai_oracle_assign_tx(tx, block.index)
                elif tx.get("type") == "ai_oracle_event":
                    self._apply_ai_oracle_event_tx(tx, block.index)
                elif tx.get("type") in ("model_register", "model_transfer", "model_revenue_share", "model_inference"):
                    apply_fn = {
                        "model_register": self._apply_model_register_tx,
                        "model_transfer": self._apply_model_transfer_tx,
                        "model_revenue_share": self._apply_model_revenue_share_tx,
                        "model_inference": self._apply_model_inference_tx,
                    }[tx["type"]]
                    apply_fn(tx, block.index)
                elif tx.get("type") in ("pipeline_create", "pipeline_step_complete", "pipeline_approve"):
                    apply_fn = {
                        "pipeline_create": self._apply_pipeline_create_tx,
                        "pipeline_step_complete": self._apply_pipeline_step_complete_tx,
                        "pipeline_approve": self._apply_pipeline_approve_tx,
                    }[tx["type"]]
                    apply_fn(tx, block.index)
                elif tx.get("type") == "zk_proof":
                    sig = tx.get("_signature", tx.get("signature", ""))
                    pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
                    try:
                        self._validate_zk_proof_tx(tx, sig, pk)
                    except ValueError:
                        pass  # tolerate failed ZK proof during replay
                    self._apply_zk_proof_tx(tx, block.index)
                elif tx.get("type") == "zk_register_circuit":
                    sig = tx.get("_signature", tx.get("signature", ""))
                    pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
                    try:
                        self._validate_zk_register_circuit_tx(tx, sig, pk)
                    except ValueError:
                        pass
                    self._apply_zk_register_circuit_tx(tx, block.index)

            # Treasury accumulation from block reward
            reward_txs = list(system_payments)
            if reward_txs and block.index > 0 and self.treasury_fee_pct > 0:
                reward_tx = reward_txs[-1]
                miner_amt = float(reward_tx.get("amount", 0.0))
                if miner_amt > 0:
                    # miner_reward = total * (1 - fee_pct), so total = miner_reward / (1 - fee_pct)
                    total_reward = miner_amt / (1.0 - self.treasury_fee_pct)
                    treasury_cut = round(total_reward * self.treasury_fee_pct, 8)
                    self.treasury_balance = round(self.treasury_balance + treasury_cut, 8)
            if block.index > 0:
                total_minted_supply += float(self.mining_reward)
                if reward_txs:
                    total_minted_supply += max(
                        0.0,
                        sum(float(tx.get("amount", 0.0)) for tx in reward_txs)
                        - float(reward_txs[-1].get("amount", 0.0)),
                    )

            # Reputation for mining
            reward_tx = reward_txs[-1] if reward_txs else {}
            miner = reward_tx.get("recipient", "") if reward_txs else ""
            if not miner and block.meta.get("validator"):
                miner = block.meta["validator"]
            if miner and block.index > 0:
                self._add_reputation(miner, 1.0, f"block_mined_{block.index}", block.timestamp)
                self._ensure_reputation(miner)
                r = self.reputation_index[miner]
                r["blocks_mined"] = r.get("blocks_mined", 0) + 1
                r["last_active"] = max(r.get("last_active", 0.0), block.timestamp)
                if reward_txs:
                    r["total_nova_earned"] = round(
                        r.get("total_nova_earned", 0.0) + float(reward_tx.get("amount", 0.0)), 8
                    )
                if r.get("validator_since") is None and miner in self.validators:
                    r["validator_since"] = block.timestamp
                if r["blocks_mined"] == 1:
                    self._award_badge(miner, "first_block", "First Block", block.timestamp)
                if r["blocks_mined"] == 100:
                    self._award_badge(miner, "century_miner", "Century Miner", block.timestamp)

        self.balance_index = balances
        self.provider_stakes = {k: float(v) for k, v in provider_stakes.items() if float(v) > 0}
        self.provider_slash_events = slash_events[-200:]
        self.latest_prices = latest_prices
        self.validators = set(active_validators)
        self.evm_next_nonce_index = dict(evm_next)
        self.pending_spend_index = {}
        self._public_tx_count_total = int(total_tx_count)
        self._total_minted_supply = round(float(total_minted_supply), 8)

        for tx in self.pending_transactions:
            if tx.get("type") == "price_update":
                symbol = str(tx.get("symbol", "")).upper()
                if symbol:
                    self.latest_prices[symbol] = {
                        "symbol": symbol,
                        "price": float(tx.get("price", 0.0)),
                        "source": str(tx.get("source", "manual")),
                        "oracle": tx.get("oracle", ""),
                        "timestamp": float(tx.get("timestamp", time.time())),
                        "tx_id": tx.get("id", ""),
                    }
            self._index_pending_transaction(tx)

        self._check_agent_param_proposals(self.height)
        self._sweep_expired_challenges()

    def register_price_oracle(self, oracle_address: str) -> None:
        if not oracle_address:
            raise ValueError("oracle_address is required.")
        self.price_oracles.add(oracle_address)
        self._touch_and_save()

    def add_validator(self, validator_address: str) -> None:
        address = str(validator_address or "").strip()
        if not address:
            raise ValueError("validator_address is required.")
        self.validators.add(address)
        self.initial_validators.add(address)
        self._touch_and_save()

    def remove_validator(self, validator_address: str) -> None:
        address = str(validator_address or "").strip()
        if not address:
            raise ValueError("validator_address is required.")
        if address in self.validators:
            if len(self.validators) <= 1:
                raise ValueError("Cannot remove last validator.")
            self.validators.remove(address)
            self.initial_validators.discard(address)
            self._touch_and_save()

    def get_latest_price(self, symbol: str = "") -> Dict[str, Any]:
        if symbol:
            entry = self.latest_prices.get(symbol.upper())
            return {symbol.upper(): entry} if entry else {}
        return dict(self.latest_prices)

    def add_transaction(self, tx: Dict[str, Any]) -> None:
        self.prune_mempool(force_persist=True)
        tx = dict(tx)
        # Normalize wrapped tx format: {"payload": {...}, "signature": ..., "public_key": ...}
        if "payload" in tx and "type" not in tx:
            inner = dict(tx["payload"])
            inner.setdefault("_signature", tx.get("signature", ""))
            inner.setdefault("_public_key", tx.get("public_key", {}))
            inner.setdefault("id", sha256_hex(canonical_json({"p": tx.get("payload", {}), "s": tx.get("signature", "")})))
            tx = inner
        tx_id = str(tx.get("id", ""))
        if not tx_id:
            raise ValueError("Transaction must include id.")
        if self._tx_seen(tx_id):
            raise ValueError(f"Transaction {tx_id} already exists.")

        tx_type = tx.get("type")
        if tx_type == "payment":
            tx["sender"] = self._normalize_address(str(tx.get("sender", "")))
            tx["recipient"] = self._normalize_address(str(tx.get("recipient", "")))
            balances = self._build_balance_state()
            sender = str(tx.get("sender", ""))
            balances[sender] = balances.get(sender, 0.0) - self._pending_spent(sender)
            if not self._validate_payment_tx(tx, balances, check_funds=True):
                if not self._validate_payment_tx(tx, balances, check_funds=False):
                    raise ValueError("Invalid payment transaction signature or payload.")
                amount = float(tx.get("amount", 0.0))
                fee = self._payment_fee(tx)
                available = float(balances.get(sender, 0.0))
                required = amount + max(0.0, fee)
                raise ValueError(
                    f"Insufficient public balance. available={available:.8f}, required={required:.8f}."
                )
        elif tx_type == "evm_payment":
            tx["sender"] = self._normalize_address(str(tx.get("sender", "")))
            tx["recipient"] = self._normalize_address(str(tx.get("recipient", "")))
            tx["sender_evm"] = str(tx.get("sender_evm", "")).lower()
            tx["recipient_evm"] = str(tx.get("recipient_evm", "")).lower()
            balances = self._build_balance_state()
            sender = str(tx.get("sender", ""))
            balances[sender] = balances.get(sender, 0.0) - self._pending_spent(sender)
            expected_nonce = self._next_evm_nonce(str(tx.get("sender_evm", "")))
            if not self._validate_evm_payment_tx(
                tx,
                balances,
                expected_nonce=expected_nonce,
                check_funds=True,
            ):
                if not self._validate_evm_payment_tx(
                    tx,
                    balances,
                    expected_nonce=expected_nonce,
                    check_funds=False,
                ):
                    raise ValueError("Invalid evm payment transaction signature or payload.")
                amount = float(tx.get("amount", 0.0))
                fee = self._evm_gas_fee_native(tx)
                available = float(balances.get(sender, 0.0))
                required = amount + max(0.0, fee)
                raise ValueError(
                    f"Insufficient public balance for evm payment. available={available:.8f}, required={required:.8f}."
                )
        elif tx_type == "price_update":
            if not self._validate_price_update_tx(tx):
                raise ValueError("Invalid price update transaction.")
        elif tx_type == "validator_update":
            if not self._validate_validator_update_tx(tx, self.validators):
                raise ValueError("Invalid validator update transaction.")
        elif tx_type == "ai_provider_stake":
            balances = self._build_balance_state()
            provider = self._normalize_address(str(tx.get("provider", "")))
            balances[provider] = balances.get(provider, 0.0) - self._pending_spent(provider)
            if not self._validate_ai_provider_stake_tx(tx, balances, check_funds=True):
                raise ValueError("Invalid ai provider stake transaction.")
        elif tx_type == "ai_provider_slash":
            provider_state = dict(self.provider_stakes)
            # Include queued stake/slash updates in the mempool ordering.
            for pending in self.pending_transactions:
                if pending.get("type") == "ai_provider_stake":
                    p = self._normalize_address(str(pending.get("provider", "")))
                    provider_state[p] = provider_state.get(p, 0.0) + float(pending.get("amount", 0.0))
                elif pending.get("type") == "ai_provider_slash":
                    p = self._normalize_address(str(pending.get("provider", "")))
                    provider_state[p] = max(0.0, provider_state.get(p, 0.0) - float(pending.get("amount", 0.0)))
            if not self._validate_ai_provider_slash_tx(tx, self.validators, provider_state):
                raise ValueError("Invalid ai provider slash transaction.")
        elif tx_type == "identity_claim":
            if not self._validate_identity_claim_tx(tx):
                raise ValueError("Invalid identity claim transaction.")
            self._apply_identity_tx(tx)
        elif tx_type == "identity_update":
            if not self._validate_identity_update_tx(tx):
                raise ValueError("Invalid identity update transaction.")
            self._apply_identity_tx(tx)
        elif tx_type == "agent_register":
            if not self._validate_agent_register_tx(tx):
                raise ValueError("Invalid agent register transaction.")
            self._apply_agent_tx(tx)
        elif tx_type == "agent_attest":
            if not self._validate_agent_attest_tx(tx):
                raise ValueError("Invalid agent attest transaction.")
            self._apply_agent_tx(tx)
        elif tx_type == "agent_activity_log":
            if not self._validate_agent_activity_log_tx(tx):
                raise ValueError("Invalid agent activity log transaction.")
            self._apply_agent_activity_log_tx(tx)
        elif tx_type == "agent_activity_log_batch":
            self._apply_agent_activity_log_batch_tx(tx)
        elif tx_type == "agent_intent_post":
            if not self._validate_agent_intent_post_tx(tx):
                raise ValueError("Invalid agent intent post transaction.")
            self._apply_agent_intent_post_tx(tx)
        elif tx_type == "agent_session_open":
            if not self._validate_agent_session_open_tx(tx):
                raise ValueError("Invalid agent session open transaction.")
            self._apply_agent_session_open_tx(tx)
        elif tx_type == "agent_artifact_commit":
            if not self._validate_agent_artifact_commit_tx(tx):
                raise ValueError("Invalid agent artifact commit transaction.")
            self._apply_agent_artifact_commit_tx(tx)
        elif tx_type == "agent_session_close":
            if not self._validate_agent_session_close_tx(tx):
                raise ValueError("Invalid agent session close transaction.")
            self._apply_agent_session_close_tx(tx)
        elif tx_type == "agent_session_settle":
            if not self._validate_agent_session_settle_tx(tx):
                raise ValueError("Invalid agent session settle transaction.")
            self._apply_agent_session_settle_tx(tx)
        elif tx_type == "agent_challenge":
            if not self._validate_agent_challenge_tx(tx):
                raise ValueError("Invalid agent challenge transaction.")
            self._apply_agent_challenge_tx(tx)
        elif tx_type == "agent_challenge_resolve":
            if not self._validate_agent_challenge_resolve_tx(tx):
                raise ValueError("Invalid agent challenge resolve transaction.")
            self._apply_agent_challenge_resolve_tx(tx)
        elif tx_type == "agent_param_propose":
            if not self._validate_agent_param_propose_tx(tx):
                raise ValueError("Invalid agent_param_propose transaction.")
            self._apply_agent_param_propose_tx(tx, len(self.chain))
        elif tx_type == "agent_param_endorse":
            if not self._validate_agent_param_endorse_tx(tx):
                raise ValueError("Invalid agent_param_endorse transaction.")
            self._apply_agent_param_endorse_tx(tx, len(self.chain))
        elif tx_type == "identity_verify":
            sig = tx.get("_signature", tx.get("signature", ""))
            pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
            self._validate_identity_verify_tx(tx, sig, pk)
            self._apply_identity_verify_tx(tx, len(self.chain))
        elif tx_type == "task_delegate":
            sig = tx.get("_signature", tx.get("signature", ""))
            pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
            self._validate_task_delegate_tx(tx, sig, pk)
            self._apply_task_delegate_tx(tx, len(self.chain))
        elif tx_type == "task_complete":
            sig = tx.get("_signature", tx.get("signature", ""))
            pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
            self._validate_task_complete_tx(tx, sig, pk)
            self._apply_task_complete_tx(tx, len(self.chain))
        elif tx_type == "task_review":
            sig = tx.get("_signature", tx.get("signature", ""))
            pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
            self._validate_task_review_tx(tx, sig, pk)
            self._apply_task_review_tx(tx, len(self.chain))
        elif tx_type == "task_dispute":
            sig = tx.get("_signature", tx.get("signature", ""))
            pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
            self._validate_task_dispute_tx(tx, sig, pk)
            self._apply_task_dispute_tx(tx, len(self.chain))
        elif tx_type == "governance_propose":
            sig = tx.get("_signature", tx.get("signature", ""))
            pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
            self._validate_governance_propose_tx(tx, sig, pk)
            self._apply_governance_propose_tx(tx, len(self.chain))
        elif tx_type == "governance_vote":
            sig = tx.get("_signature", tx.get("signature", ""))
            pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
            self._validate_governance_vote_tx(tx, sig, pk)
            self._apply_governance_vote_tx(tx, len(self.chain))
        elif tx_type == "validator_nominate":
            sig = tx.get("_signature", tx.get("signature", ""))
            pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
            self._validate_validator_nominate_tx(tx, sig, pk)
            self._apply_validator_nominate_tx(tx, len(self.chain))
        elif tx_type == "validator_unstake":
            sig = tx.get("_signature", tx.get("signature", ""))
            pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
            self._validate_validator_unstake_tx(tx, sig, pk)
            self._apply_validator_unstake_tx(tx, len(self.chain))
        elif tx_type == "validator_election_vote":
            sig = tx.get("_signature", tx.get("signature", ""))
            pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
            self._validate_validator_election_vote_tx(tx, sig, pk)
            self._apply_validator_election_vote_tx(tx, len(self.chain))
        elif tx_type == "ai_oracle_assign":
            sig = tx.get("_signature", tx.get("signature", ""))
            pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
            self._validate_ai_oracle_assign_tx(tx, sig, pk)
            self._apply_ai_oracle_assign_tx(tx, len(self.chain))
        elif tx_type == "ai_oracle_event":
            sig = tx.get("_signature", tx.get("signature", ""))
            pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
            self._validate_ai_oracle_event_tx(tx, sig, pk)
            self._apply_ai_oracle_event_tx(tx, len(self.chain))
        elif tx_type == "model_register":
            sig = tx.get("_signature", tx.get("signature", ""))
            pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
            self._validate_model_register_tx(tx, sig, pk)
            self._apply_model_register_tx(tx, len(self.chain))
        elif tx_type == "model_transfer":
            sig = tx.get("_signature", tx.get("signature", ""))
            pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
            self._validate_model_transfer_tx(tx, sig, pk)
            self._apply_model_transfer_tx(tx, len(self.chain))
        elif tx_type == "model_revenue_share":
            sig = tx.get("_signature", tx.get("signature", ""))
            pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
            self._validate_model_revenue_share_tx(tx, sig, pk)
            self._apply_model_revenue_share_tx(tx, len(self.chain))
        elif tx_type == "model_inference":
            sig = tx.get("_signature", tx.get("signature", ""))
            pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
            self._validate_model_inference_tx(tx, sig, pk)
            self._apply_model_inference_tx(tx, len(self.chain))
        elif tx_type == "pipeline_create":
            sig = tx.get("_signature", tx.get("signature", ""))
            pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
            self._validate_pipeline_create_tx(tx, sig, pk)
            self._apply_pipeline_create_tx(tx, len(self.chain))
        elif tx_type == "pipeline_step_complete":
            sig = tx.get("_signature", tx.get("signature", ""))
            pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
            self._validate_pipeline_step_complete_tx(tx, sig, pk)
            self._apply_pipeline_step_complete_tx(tx, len(self.chain))
        elif tx_type == "pipeline_approve":
            sig = tx.get("_signature", tx.get("signature", ""))
            pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
            self._validate_pipeline_approve_tx(tx, sig, pk)
            self._apply_pipeline_approve_tx(tx, len(self.chain))
        elif tx_type == "zk_proof":
            sig = tx.get("_signature", tx.get("signature", ""))
            pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
            self._validate_zk_proof_tx(tx, sig, pk)
            self._apply_zk_proof_tx(tx, len(self.chain))
        elif tx_type == "zk_register_circuit":
            sig = tx.get("_signature", tx.get("signature", ""))
            pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
            self._validate_zk_register_circuit_tx(tx, sig, pk)
            self._apply_zk_register_circuit_tx(tx, len(self.chain))
        else:
            raise ValueError(f"Unsupported public tx type: {tx_type}")

        self.pending_transactions.append(tx)
        self._apply_price_tx(tx)
        self._index_pending_transaction(tx)
        self._append_mempool_wal({"op": "add", "tx": tx, "at": time.time()})
        self._touch_and_save()
        self.prune_mempool(force_persist=True)

    def _sorted_pending_transactions(self) -> List[Dict[str, Any]]:
        indexed: List[Tuple[int, Dict[str, Any]]] = list(enumerate(self.pending_transactions))

        def key(item: Tuple[int, Dict[str, Any]]) -> Tuple[float, float, int]:
            pos, tx = item
            fee = self._tx_effective_fee(tx)
            timestamp = float(tx.get("timestamp", 0.0))
            return (-fee, timestamp, pos)

        indexed.sort(key=key)
        return [tx for _, tx in indexed]

    def mine_pending_transactions(self, miner_address: str) -> Block:
        self.prune_mempool(force_persist=True)
        if not miner_address:
            raise ValueError("Miner address is required.")
        miner_address = self._normalize_address(str(miner_address))
        if self.consensus == "poa" and miner_address not in self.validators:
            raise ValueError("Miner address is not in public validator set for poa consensus.")
        if self.consensus == "poa" and self.validator_rotation_enabled and self.validators:
            expected = self.expected_next_validator()
            if expected and miner_address != expected:
                raise ValueError(f"Miner must match proposer rotation. Expected {expected}.")

        ordered_pending = self._sorted_pending_transactions()

        total_fees = 0.0
        for tx in ordered_pending:
            if tx.get("type") != "evm_payment":
                total_fees += self._tx_effective_fee(tx)
                continue
            fee = self._tx_effective_fee(tx)
            if fee < 0:
                raise ValueError("Invalid fee in pending evm payment transaction.")
            tx["gas_fee_native"] = fee
            total_fees += fee

        reward = float(self.mining_reward + total_fees)
        # Treasury collects 10% of block reward
        treasury_cut = round(reward * self.treasury_fee_pct, 8)
        miner_reward = round(reward - treasury_cut, 8)
        self.treasury_balance = round(self.treasury_balance + treasury_cut, 8)
        reward_payload = {
            "type": "payment",
            "sender": SYSTEM_SENDER,
            "recipient": miner_address,
            "amount": float(miner_reward),
            "timestamp": time.time(),
        }
        reward_tx = {
            **reward_payload,
            "id": sha256_hex(canonical_json(reward_payload)),
        }

        block_index = self.height
        finalized_height = max(0, block_index - self.finality_confirmations)
        checkpoint_height = self._checkpoint_height_at(block_index)
        transactions = list(ordered_pending) + [reward_tx]
        block = Block(
            index=block_index,
            timestamp=time.time(),
            transactions=transactions,
            previous_hash=self.chain[-1].hash,
            meta={
                "consensus": self.consensus,
                "validator": miner_address if self.consensus == "poa" else "",
                "validator_rotation": self.validator_rotation_enabled,
                "expected_validator": self.expected_proposer_for_height(block_index),
                "tx_priority_policy": self.tx_priority_policy,
                "finality_confirmations": self.finality_confirmations,
                "finalized_height": finalized_height,
                "checkpoint_interval": self.checkpoint_interval,
                "checkpoint_height": checkpoint_height,
                "checkpoint": checkpoint_height == finalized_height and finalized_height >= 0,
                "block_time_target_seconds": self.block_time_target_seconds,
            },
        )
        if self.consensus == "pow":
            self._mine_pow(block)
        else:
            block.hash = block.compute_hash()
        self.chain.append(block)
        self._chain_full_height = block.index + 1
        self._public_tx_count_total = int(getattr(self, "_public_tx_count_total", 0)) + len(transactions)
        self._total_minted_supply = round(
            float(getattr(self, "_total_minted_supply", 0.0))
            + float(self.mining_reward)
            + sum(
                float(tx.get("amount", 0.0))
                for tx in ordered_pending
                if tx.get("type") == "payment" and tx.get("sender") == SYSTEM_SENDER
            ),
            8,
        )
        self.balance_index.setdefault(miner_address, 0.0)
        for tx in ordered_pending:
            tx_type = tx.get("type")
            if tx_type in {"payment", "evm_payment"}:
                self._apply_payment_tx(tx, self.balance_index)
            elif tx_type in {"ai_provider_stake", "ai_provider_slash"}:
                self._apply_ai_provider_tx(
                    tx,
                    self.balance_index,
                    self.provider_stakes,
                    slash_events=self.provider_slash_events,
                )
            elif tx_type == "validator_update":
                self._apply_public_governance_tx(tx, self.validators)
        self._apply_payment_tx(reward_tx, self.balance_index)
        self.pending_transactions = []
        if miner_address:
            self._add_reputation(miner_address, 1.0, f"block_mined_{block.index}", block.timestamp)
            self._ensure_reputation(miner_address)
            r = self.reputation_index[miner_address]
            r["blocks_mined"] = r.get("blocks_mined", 0) + 1
            r["last_active"] = max(r.get("last_active", 0.0), block.timestamp)
            r["total_nova_earned"] = round(
                r.get("total_nova_earned", 0.0) + float(reward_tx.get("amount", 0.0)),
                8,
            )
            if r.get("validator_since") is None and miner_address in self.validators:
                r["validator_since"] = block.timestamp
            if r["blocks_mined"] == 1:
                self._award_badge(miner_address, "first_block", "First Block", block.timestamp)
            if r["blocks_mined"] == 100:
                self._award_badge(miner_address, "century_miner", "Century Miner", block.timestamp)
        self._reindex_pending_runtime_state()
        self._check_agent_param_proposals(self.height)
        self._sweep_expired_challenges()
        self._check_missed_blocks(block)
        self._append_mempool_wal({"op": "clear", "block_index": block.index, "at": time.time()})
        self._touch_and_save(force=True)
        return block

    @property
    def height(self) -> int:
        """Full chain height including pruned blocks."""
        return getattr(self, "_chain_full_height", len(self.chain))

    def blocks_mined_total(self) -> int:
        return max(0, self.height - 1)

    def total_confirmed_public_transactions(self) -> int:
        return int(getattr(self, "_public_tx_count_total", self._estimated_public_tx_count_from_retained_chain()))

    def total_minted_supply(self) -> float:
        return round(
            float(getattr(self, "_total_minted_supply", self._estimated_total_minted_supply_from_retained_state())),
            8,
        )

    def get_balance(self, address: str) -> float:
        normalized = self._normalize_address(address)
        return float(self.balance_index.get(normalized, 0.0))

    def is_valid(self) -> bool:
        if not self.chain:
            return False
        if self.chain[0].hash != self.chain[0].compute_hash():
            return False

        # Save current state so we can restore it if validation fails
        _saved_identity_registry = dict(self.identity_registry)
        _saved_handle_index = dict(self.handle_index)
        _saved_agent_registry = dict(self.agent_registry)
        _saved_reputation_index = dict(self.reputation_index)
        _saved_task_registry = dict(self.task_registry)
        _saved_governance_proposals = dict(self.governance_proposals)
        _saved_activity_feed = list(self.activity_feed)
        _saved_treasury_balance = self.treasury_balance
        _saved_validator_candidates = dict(self.validator_candidates)
        _saved_oracle_assignments = dict(self.oracle_assignments)
        _saved_model_registry = dict(self.model_registry)
        _saved_pipeline_registry = dict(self.pipeline_registry)
        _saved_balance_index = dict(self.balance_index)
        _saved_latest_prices = dict(self.latest_prices)
        _saved_validators = set(self.validators)
        _saved_provider_stakes = dict(self.provider_stakes)
        _saved_provider_slash_events = list(self.provider_slash_events)
        _saved_evm_next_nonce_index = dict(self.evm_next_nonce_index)
        _saved_pending_spend_index = dict(self.pending_spend_index)
        _saved_zk_circuit_registry = dict(self.zk_circuit_registry)
        _saved_zk_proof_log = list(self.zk_proof_log)
        _saved_zk_proof_hashes = set(getattr(self, "zk_proof_hashes", set()))
        _saved_activity_log_index = dict(self.activity_log_index)
        _saved_challenge_index = dict(self.challenge_index)
        _saved_collab_index = dict(self.collab_index)
        _saved_intent_index = dict(self.intent_index)
        _saved_artifact_index = dict(self.artifact_index)
        _saved_agent_param_proposals = dict(self.agent_param_proposals)
        _saved_agent_trust_params = dict(self.agent_trust_params)
        _saved_agent_trust_params_history = list(self.agent_trust_params_history)
        _saved_public_tx_count_total = int(getattr(self, "_public_tx_count_total", 0))
        _saved_total_minted_supply = float(getattr(self, "_total_minted_supply", 0.0))

        def _restore_state() -> None:
            self.identity_registry = _saved_identity_registry
            self.handle_index = _saved_handle_index
            self.agent_registry = _saved_agent_registry
            self.reputation_index = _saved_reputation_index
            self.task_registry = _saved_task_registry
            self.governance_proposals = _saved_governance_proposals
            self.activity_feed = _saved_activity_feed
            self.treasury_balance = _saved_treasury_balance
            self.validator_candidates = _saved_validator_candidates
            self.oracle_assignments = _saved_oracle_assignments
            self.model_registry = _saved_model_registry
            self.pipeline_registry = _saved_pipeline_registry
            self.balance_index = _saved_balance_index
            self.latest_prices = _saved_latest_prices
            self.validators = _saved_validators
            self.provider_stakes = _saved_provider_stakes
            self.provider_slash_events = _saved_provider_slash_events
            self.evm_next_nonce_index = _saved_evm_next_nonce_index
            self.pending_spend_index = _saved_pending_spend_index
            self.zk_circuit_registry = _saved_zk_circuit_registry
            self.zk_proof_log = _saved_zk_proof_log
            self.zk_proof_hashes = _saved_zk_proof_hashes
            self.activity_log_index = _saved_activity_log_index
            self.challenge_index = _saved_challenge_index
            self.collab_index = _saved_collab_index
            self.intent_index = _saved_intent_index
            self.artifact_index = _saved_artifact_index
            self.agent_param_proposals = _saved_agent_param_proposals
            self.agent_trust_params = _saved_agent_trust_params
            self.agent_trust_params_history = _saved_agent_trust_params_history
            self._public_tx_count_total = _saved_public_tx_count_total
            self._total_minted_supply = _saved_total_minted_supply

        balances: Dict[str, float] = {}
        provider_stakes: Dict[str, float] = {}
        slash_events: List[Dict[str, Any]] = []
        active_validators: Set[str] = set(self.initial_validators) if self.initial_validators else set(self.validators)
        rebuilt_prices: Dict[str, Dict[str, Any]] = {}
        next_nonce_by_sender: Dict[str, int] = {}
        rebuilt_treasury: float = 0.0
        self.identity_registry = {}
        self.handle_index = {}
        self.agent_registry = {}
        self.reputation_index = {}
        self.task_registry = {}
        self.governance_proposals = {}
        self.activity_feed = []
        self.treasury_balance = 0.0
        self.validator_candidates = {}
        self.oracle_assignments = {}
        self.model_registry = {}
        self.pipeline_registry = {}
        self.zk_circuit_registry = {}
        self.zk_proof_log = []
        self.zk_proof_hashes: set = set()  # permanent replay-prevention set
        self.activity_log_index = {}
        self.challenge_index = {}
        self.collab_index = {}
        self.intent_index = {}
        self.artifact_index = {}
        # Point balance_index at the local balances dict so all _validate_*_tx
        # calls (which use self.get_balance()) see the correctly-rebuilt balances.
        self.balance_index = balances
        for i, block in enumerate(self.chain):
            if i == 0:
                continue
            prev = self.chain[i - 1]
            if block.previous_hash != prev.hash:
                _restore_state(); return False
            if block.hash != block.compute_hash():
                _restore_state(); return False
            if self.consensus == "pow":
                if not block.hash.startswith("0" * self.difficulty):
                    _restore_state(); return False
            elif self.consensus == "poa":
                validator = str(block.meta.get("validator", ""))
                if not validator or validator not in active_validators:
                    _restore_state(); return False
                if self.validator_rotation_enabled and active_validators:
                    meta_expected = str(block.meta.get("expected_validator", ""))
                    if meta_expected:
                        # expected_validator is committed into the block hash — trust it.
                        # The validator set at mining time may differ from initial_validators
                        # today (e.g. validators added/removed after this block was produced).
                        if validator != meta_expected:
                            _restore_state(); return False
                    else:
                        # Legacy block with no stored expected_validator — recompute.
                        expected = self.expected_proposer_for_height(block.index, validator_set=active_validators)
                        if expected and validator != expected:
                            _restore_state(); return False
                if block.meta.get("expected_validator", "") not in {"", validator}:
                    _restore_state(); return False
            else:
                _restore_state(); return False

            reward_candidates = [
                tx
                for tx in block.transactions
                if tx.get("type") == "payment" and tx.get("sender") == SYSTEM_SENDER
            ]
            if len(reward_candidates) != 1:
                _restore_state(); return False
            reward_tx = reward_candidates[0]
            if not block.transactions or reward_tx is not block.transactions[-1]:
                _restore_state(); return False
            if self.consensus == "poa":
                validator = str(block.meta.get("validator", ""))
                if reward_tx.get("recipient") != validator:
                    _restore_state(); return False

            expected_reward = float(self.mining_reward)
            for tx in block.transactions:
                if tx.get("type") == "payment" and tx.get("sender") == SYSTEM_SENDER:
                    continue
                fee = self._tx_effective_fee(tx)
                if fee < 0:
                    _restore_state()
                    _restore_state(); return False
                expected_reward += fee
            # Accept reward minted at any treasury fee between 0% and current fee_pct
            # to handle blocks mined before treasury was introduced.
            actual_reward = float(reward_tx.get("amount", 0.0))
            max_expected = round(expected_reward, 8)
            min_expected = round(expected_reward * (1.0 - self.treasury_fee_pct), 8)
            if actual_reward > max_expected + 1e-6 or actual_reward < min_expected - 1e-6:
                _restore_state()
                _restore_state(); return False
            rebuilt_treasury = round(rebuilt_treasury + round(expected_reward * self.treasury_fee_pct, 8), 8)

            expected_finalized = max(0, block.index - self.finality_confirmations)
            if int(block.meta.get("finalized_height", expected_finalized)) != expected_finalized:
                _restore_state(); return False

            for tx in block.transactions:
                tx_type = tx.get("type")
                if tx_type == "payment":
                    if not self._validate_payment_tx(tx, balances, check_funds=True):
                        _restore_state(); return False
                    self._apply_payment_tx(tx, balances)
                elif tx_type == "evm_payment":
                    sender_evm = str(tx.get("sender_evm", "")).lower()
                    expected_nonce = next_nonce_by_sender.get(sender_evm, 0)
                    if not self._validate_evm_payment_tx(
                        tx,
                        balances,
                        expected_nonce=expected_nonce,
                        check_funds=True,
                    ):
                        _restore_state(); return False
                    self._apply_payment_tx(tx, balances)
                    next_nonce_by_sender[sender_evm] = expected_nonce + 1
                elif tx_type == "price_update":
                    if not self._validate_price_update_tx(tx):
                        _restore_state(); return False
                    symbol = str(tx["symbol"]).upper()
                    rebuilt_prices[symbol] = {
                        "symbol": symbol,
                        "price": float(tx["price"]),
                        "source": str(tx.get("source", "manual")),
                        "oracle": tx["oracle"],
                        "timestamp": float(tx["timestamp"]),
                        "tx_id": tx.get("id", ""),
                    }
                elif tx_type == "validator_update":
                    if not self._validate_validator_update_tx(tx, active_validators):
                        _restore_state(); return False
                    self._apply_public_governance_tx(tx, active_validators)
                elif tx_type == "ai_provider_stake":
                    if not self._validate_ai_provider_stake_tx(tx, balances, check_funds=True):
                        _restore_state(); return False
                    self._apply_ai_provider_tx(tx, balances, provider_stakes, slash_events=slash_events)
                elif tx_type == "ai_provider_slash":
                    if not self._validate_ai_provider_slash_tx(tx, active_validators, provider_stakes):
                        _restore_state(); return False
                    self._apply_ai_provider_tx(tx, balances, provider_stakes, slash_events=slash_events)
                elif tx_type == "identity_claim":
                    if not self._validate_identity_claim_tx(tx):
                        _restore_state(); return False
                    self._apply_identity_tx(tx)
                elif tx_type == "identity_update":
                    if not self._validate_identity_update_tx(tx):
                        _restore_state(); return False
                    self._apply_identity_tx(tx)
                elif tx_type == "agent_register":
                    if not self._validate_agent_register_tx(tx):
                        _restore_state(); return False
                    self._apply_agent_tx(tx)
                elif tx_type == "agent_attest":
                    if not self._validate_agent_attest_tx(tx):
                        _restore_state(); return False
                    self._apply_agent_tx(tx)
                elif tx_type == "agent_intent_post":
                    if not self._validate_agent_intent_post_tx(tx):
                        _restore_state(); return False
                    self._apply_agent_intent_post_tx(tx)
                elif tx_type == "agent_session_open":
                    if not self._validate_agent_session_open_tx(tx):
                        _restore_state(); return False
                    self._apply_agent_session_open_tx(tx)
                elif tx_type == "agent_artifact_commit":
                    if not self._validate_agent_artifact_commit_tx(tx):
                        _restore_state(); return False
                    self._apply_agent_artifact_commit_tx(tx)
                elif tx_type == "agent_session_close":
                    if not self._validate_agent_session_close_tx(tx):
                        _restore_state(); return False
                    self._apply_agent_session_close_tx(tx)
                elif tx_type == "agent_session_settle":
                    if not self._validate_agent_session_settle_tx(tx):
                        _restore_state(); return False
                    self._apply_agent_session_settle_tx(tx)
                elif tx_type == "agent_challenge":
                    if not self._validate_agent_challenge_tx(tx):
                        _restore_state(); return False
                    self._apply_agent_challenge_tx(tx)
                elif tx_type == "agent_challenge_resolve":
                    if not self._validate_agent_challenge_resolve_tx(tx):
                        _restore_state(); return False
                    self._apply_agent_challenge_resolve_tx(tx)
                elif tx_type == "agent_param_propose":
                    if not self._validate_agent_param_propose_tx(tx):
                        _restore_state(); return False
                    self._apply_agent_param_propose_tx(tx, block.index)
                elif tx_type == "agent_param_endorse":
                    if not self._validate_agent_param_endorse_tx(tx):
                        _restore_state(); return False
                    self._apply_agent_param_endorse_tx(tx, block.index)
                elif tx_type == "identity_verify":
                    sig = tx.get("_signature", tx.get("signature", ""))
                    pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
                    try:
                        self._validate_identity_verify_tx(tx, sig, pk)
                    except ValueError:
                        _restore_state(); return False
                    self._apply_identity_verify_tx(tx, block.index)
                elif tx_type == "task_delegate":
                    sig = tx.get("_signature", tx.get("signature", ""))
                    pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
                    try:
                        self._validate_task_delegate_tx(tx, sig, pk)
                    except ValueError:
                        _restore_state(); return False
                    self._apply_task_delegate_tx(tx, block.index, _balances=balances)
                elif tx_type == "task_complete":
                    sig = tx.get("_signature", tx.get("signature", ""))
                    pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
                    try:
                        self._validate_task_complete_tx(tx, sig, pk)
                    except ValueError:
                        _restore_state(); return False
                    self._apply_task_complete_tx(tx, block.index)
                elif tx_type == "task_review":
                    sig = tx.get("_signature", tx.get("signature", ""))
                    pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
                    try:
                        self._validate_task_review_tx(tx, sig, pk)
                    except ValueError:
                        _restore_state(); return False
                    self._apply_task_review_tx(tx, block.index, _balances=balances)
                elif tx_type == "task_dispute":
                    sig = tx.get("_signature", tx.get("signature", ""))
                    pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
                    try:
                        self._validate_task_dispute_tx(tx, sig, pk)
                    except ValueError:
                        _restore_state(); return False
                    self._apply_task_dispute_tx(tx, block.index)
                elif tx_type == "governance_propose":
                    sig = tx.get("_signature", tx.get("signature", ""))
                    pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
                    try:
                        self._validate_governance_propose_tx(tx, sig, pk)
                    except ValueError:
                        _restore_state(); return False
                    self._apply_governance_propose_tx(tx, block.index)
                elif tx_type == "governance_vote":
                    sig = tx.get("_signature", tx.get("signature", ""))
                    pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
                    try:
                        self._validate_governance_vote_tx(tx, sig, pk)
                    except ValueError:
                        _restore_state(); return False
                    try:
                        self._apply_governance_vote_tx(tx, block.index)
                    except KeyError:
                        pass  # proposal may not exist yet during replay — tolerate orphaned votes
                elif tx_type == "validator_nominate":
                    sig = tx.get("_signature", tx.get("signature", ""))
                    pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
                    try:
                        self._validate_validator_nominate_tx(tx, sig, pk)
                    except ValueError:
                        _restore_state(); return False
                    self._apply_validator_nominate_tx(tx, block.index)
                elif tx_type == "validator_unstake":
                    sig = tx.get("_signature", tx.get("signature", ""))
                    pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
                    try:
                        self._validate_validator_unstake_tx(tx, sig, pk)
                    except ValueError:
                        _restore_state(); return False
                    self._apply_validator_unstake_tx(tx, block.index)
                elif tx_type == "validator_election_vote":
                    sig = tx.get("_signature", tx.get("signature", ""))
                    pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
                    try:
                        self._validate_validator_election_vote_tx(tx, sig, pk)
                    except ValueError:
                        _restore_state(); return False
                    self._apply_validator_election_vote_tx(tx, block.index)
                elif tx_type == "ai_oracle_assign":
                    sig = tx.get("_signature", tx.get("signature", ""))
                    pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
                    try:
                        self._validate_ai_oracle_assign_tx(tx, sig, pk)
                    except ValueError:
                        _restore_state(); return False
                    self._apply_ai_oracle_assign_tx(tx, block.index)
                elif tx_type == "ai_oracle_event":
                    sig = tx.get("_signature", tx.get("signature", ""))
                    pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
                    try:
                        self._validate_ai_oracle_event_tx(tx, sig, pk)
                    except ValueError:
                        _restore_state(); return False
                    self._apply_ai_oracle_event_tx(tx, block.index)
                elif tx_type in ("model_register", "model_transfer", "model_revenue_share", "model_inference"):
                    apply_fn = {
                        "model_register": self._apply_model_register_tx,
                        "model_transfer": self._apply_model_transfer_tx,
                        "model_revenue_share": self._apply_model_revenue_share_tx,
                        "model_inference": self._apply_model_inference_tx,
                    }[tx_type]
                    apply_fn(tx, block.index)
                elif tx_type in ("pipeline_create", "pipeline_step_complete", "pipeline_approve"):
                    apply_fn = {
                        "pipeline_create": self._apply_pipeline_create_tx,
                        "pipeline_step_complete": self._apply_pipeline_step_complete_tx,
                        "pipeline_approve": self._apply_pipeline_approve_tx,
                    }[tx_type]
                    apply_fn(tx, block.index)
                elif tx_type == "zk_proof":
                    sig = tx.get("_signature", tx.get("signature", ""))
                    pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
                    try:
                        self._validate_zk_proof_tx(tx, sig, pk)
                    except ValueError:
                        _restore_state(); return False
                    self._apply_zk_proof_tx(tx, block.index)
                elif tx_type == "zk_register_circuit":
                    sig = tx.get("_signature", tx.get("signature", ""))
                    pk = tx.get("_public_key", tx.get("public_key", tx.get("pubkey", {})))
                    try:
                        self._validate_zk_register_circuit_tx(tx, sig, pk)
                    except ValueError:
                        _restore_state(); return False
                    self._apply_zk_register_circuit_tx(tx, block.index)
                else:
                    _restore_state(); return False

        self.latest_prices = rebuilt_prices
        self.validators = set(active_validators)
        self.balance_index = dict(balances)
        self.evm_next_nonce_index = dict(next_nonce_by_sender)
        self.treasury_balance = rebuilt_treasury
        self.pending_spend_index = {}
        for tx in self.pending_transactions:
            if tx.get("type") == "price_update":
                symbol = str(tx.get("symbol", "")).upper()
                if symbol:
                    self.latest_prices[symbol] = {
                        "symbol": symbol,
                        "price": float(tx.get("price", 0.0)),
                        "source": str(tx.get("source", "manual")),
                        "oracle": tx.get("oracle", ""),
                        "timestamp": float(tx.get("timestamp", time.time())),
                        "tx_id": tx.get("id", ""),
                    }
            self._index_pending_transaction(tx)
        self.provider_stakes = {k: v for k, v in provider_stakes.items() if v > 0}
        self.provider_slash_events = slash_events[-200:]

        _restore_state()
        return True

    def export_state(self) -> Dict[str, Any]:
        return {
            "state_version": self.state_version,
            "consensus": self.consensus,
            "difficulty": self.difficulty,
            "mining_reward": self.mining_reward,
            "validator_rotation_enabled": self.validator_rotation_enabled,
            "finality_confirmations": self.finality_confirmations,
            "checkpoint_interval": self.checkpoint_interval,
            "block_time_target_seconds": self.block_time_target_seconds,
            "tx_priority_policy": self.tx_priority_policy,
            "strict_signature_validation": self.strict_signature_validation,
            "mempool_tx_ttl_seconds": self.mempool_tx_ttl_seconds,
            "mempool_max_transactions": self.mempool_max_transactions,
            "mempool_prune_stats": self.mempool_prune_stats,
            "pow_parallel_workers": self.pow_parallel_workers,
            "pow_nonce_chunk_size": self.pow_nonce_chunk_size,
            "validators": sorted(self.validators),
            "initial_validators": sorted(self.initial_validators),
            "price_oracles": sorted(self.price_oracles),
            "latest_prices": self.latest_prices,
            "provider_stakes": self.provider_stakes,
            "provider_slash_events": self.provider_slash_events[-200:],
            "identity_registry": self.identity_registry,
            "handle_index": self.handle_index,
            "agent_registry": self.agent_registry,
            "reputation_index": self.reputation_index,
            "task_registry": self.task_registry,
            "governance_proposals": self.governance_proposals,
            "activity_feed": self.activity_feed[-200:],
            "treasury_balance": self.treasury_balance,
            "validator_candidates": self.validator_candidates,
            "oracle_assignments": self.oracle_assignments,
            "model_registry": self.model_registry,
            "pipeline_registry": self.pipeline_registry,
            "zk_circuit_registry": self.zk_circuit_registry,
            "zk_proof_log": self.zk_proof_log[-200:],
            "agent_register_history": self.agent_register_history,
            "activity_log_index": self.activity_log_index,
            "challenge_index": self.challenge_index,
            "collab_index": self.collab_index,
            "intent_index": self.intent_index,
            "artifact_index": self.artifact_index,
            "agent_param_proposals": self.agent_param_proposals,
            "agent_trust_params": self.agent_trust_params,
            "agent_trust_params_history": self.agent_trust_params_history,
            "balance_index": self.balance_index,
            "chain": [b.to_dict() for b in self.chain[-500:]],
            "chain_full_height": self.height,
            "public_tx_count_total": self.total_confirmed_public_transactions(),
            "total_minted_supply": self.total_minted_supply(),
            "pending_transactions": list(self.pending_transactions),
        }

    def adopt_state_if_longer(self, data: Dict[str, Any]) -> bool:
        incoming_chain = [Block.from_dict(raw) for raw in data.get("chain", [])]
        incoming_version = int(data.get("state_version", 0))

        should_adopt = False
        if incoming_version > self.state_version:
            should_adopt = True
        elif incoming_version == self.state_version and len(incoming_chain) > len(self.chain):
            should_adopt = True

        if not should_adopt:
            return False

        old_state = self.export_state()
        try:
            self.consensus = str(data.get("consensus", self.consensus)).strip().lower()
            if self.consensus not in {"pow", "poa"}:
                raise ValueError("Incoming public consensus invalid.")
            self.difficulty = int(data.get("difficulty", self.difficulty))
            self.mining_reward = float(data.get("mining_reward", self.mining_reward))
            self.validator_rotation_enabled = bool(data.get("validator_rotation_enabled", self.validator_rotation_enabled))
            self.finality_confirmations = max(1, int(data.get("finality_confirmations", self.finality_confirmations)))
            self.checkpoint_interval = max(1, int(data.get("checkpoint_interval", self.checkpoint_interval)))
            self.block_time_target_seconds = max(0.2, float(data.get("block_time_target_seconds", self.block_time_target_seconds)))
            self.tx_priority_policy = str(data.get("tx_priority_policy", self.tx_priority_policy or "fee-desc"))
            self.strict_signature_validation = bool(data.get("strict_signature_validation", self.strict_signature_validation))
            self.mempool_tx_ttl_seconds = max(
                0.0, float(data.get("mempool_tx_ttl_seconds", self.mempool_tx_ttl_seconds))
            )
            self.mempool_max_transactions = max(
                0, int(data.get("mempool_max_transactions", self.mempool_max_transactions))
            )
            self.mempool_prune_stats = dict(data.get("mempool_prune_stats", self.mempool_prune_stats))
            self.pow_parallel_workers = max(
                1, int(data.get("pow_parallel_workers", self.pow_parallel_workers))
            )
            self.pow_nonce_chunk_size = max(
                128, int(data.get("pow_nonce_chunk_size", self.pow_nonce_chunk_size))
            )
            self.validators = set(data.get("validators", []))
            self.initial_validators = set(data.get("initial_validators", list(self.validators)))
            self.chain = incoming_chain
            self._chain_full_height = int(data.get("chain_full_height", len(incoming_chain)))
            self.pending_transactions = list(data.get("pending_transactions", []))
            self.provider_stakes = dict(data.get("provider_stakes", {}))
            self.provider_slash_events = list(data.get("provider_slash_events", []))
            self.identity_registry = dict(data.get("identity_registry", {}))
            self.handle_index = dict(data.get("handle_index", {}))
            self.agent_registry = dict(data.get("agent_registry", {}))
            self.reputation_index = dict(data.get("reputation_index", {}))
            self.task_registry = dict(data.get("task_registry", {}))
            self.governance_proposals = dict(data.get("governance_proposals", {}))
            self.activity_feed = list(data.get("activity_feed", []))
            self.treasury_balance = data.get("treasury_balance", 0.0)
            self.validator_candidates = dict(data.get("validator_candidates", {}))
            self.oracle_assignments = dict(data.get("oracle_assignments", {}))
            self.model_registry = dict(data.get("model_registry", {}))
            self.pipeline_registry = dict(data.get("pipeline_registry", {}))
            self.zk_circuit_registry = dict(data.get("zk_circuit_registry", {}))
            self.zk_proof_log = list(data.get("zk_proof_log", []))
            # Rebuild replay-prevention set from persisted proof log
            self.zk_proof_hashes = {
                e["proof_hash"] for e in self.zk_proof_log if "proof_hash" in e
            }
            self.state_version = incoming_version
            if not self.is_valid():
                raise ValueError("Incoming public chain invalid.")
            # is_valid() replays the stored chain window and recomputes balance_index
            # from only those blocks. Restore the authoritative balance_index from
            # the snapshot so accumulated history beyond the window is preserved.
            persisted_balance = data.get("balance_index", {})
            if persisted_balance:
                self.balance_index = {str(k): float(v) for k, v in persisted_balance.items()}
        except Exception as exc:  # pylint: disable=broad-except
            self._load_from_state(old_state)
            raise ValueError(str(exc)) from exc

        self._save()
        return True

    def _save(self) -> None:
        ensure_dir(os.path.dirname(self.chain_file) or ".")
        with open(self.chain_file, "w", encoding="utf-8") as f:
            json.dump(self.export_state(), f, separators=(",", ":"))
        # Compact checkpoint persisted; mempool operations before this point are durable in state.
        with open(self.mempool_wal_file, "w", encoding="utf-8") as f:
            f.write("")

    def _load_from_state(self, data: Dict[str, Any]) -> None:
        self.state_version = int(data.get("state_version", 0))
        self.consensus = str(data.get("consensus", self.consensus)).strip().lower()
        if self.consensus not in {"pow", "poa"}:
            self.consensus = "pow"
        self.difficulty = int(data.get("difficulty", self.difficulty))
        self.mining_reward = float(data.get("mining_reward", self.mining_reward))
        self.validator_rotation_enabled = bool(data.get("validator_rotation_enabled", self.validator_rotation_enabled))
        self.finality_confirmations = max(1, int(data.get("finality_confirmations", self.finality_confirmations)))
        self.checkpoint_interval = max(1, int(data.get("checkpoint_interval", self.checkpoint_interval)))
        self.block_time_target_seconds = max(0.2, float(data.get("block_time_target_seconds", self.block_time_target_seconds)))
        self.tx_priority_policy = str(data.get("tx_priority_policy", self.tx_priority_policy or "fee-desc"))
        self.strict_signature_validation = bool(data.get("strict_signature_validation", self.strict_signature_validation))
        self.mempool_tx_ttl_seconds = max(
            0.0, float(data.get("mempool_tx_ttl_seconds", self.mempool_tx_ttl_seconds))
        )
        self.mempool_max_transactions = max(
            0, int(data.get("mempool_max_transactions", self.mempool_max_transactions))
        )
        self.mempool_prune_stats = dict(data.get("mempool_prune_stats", self.mempool_prune_stats))
        self.pow_parallel_workers = max(
            1, int(data.get("pow_parallel_workers", self.pow_parallel_workers))
        )
        self.pow_nonce_chunk_size = max(
            128, int(data.get("pow_nonce_chunk_size", self.pow_nonce_chunk_size))
        )
        self.validators = set(data.get("validators", self.validators))
        self.initial_validators = set(data.get("initial_validators", list(self.validators)))
        self.price_oracles = set(data.get("price_oracles", []))
        self.latest_prices = dict(data.get("latest_prices", {}))
        self.provider_stakes = {
            self._normalize_address(str(k)): float(v)
            for k, v in dict(data.get("provider_stakes", {})).items()
            if float(v) > 0
        }
        self.provider_slash_events = list(data.get("provider_slash_events", []))
        self.identity_registry = dict(data.get("identity_registry", {}))
        self.handle_index = dict(data.get("handle_index", {}))
        self.agent_registry = dict(data.get("agent_registry", {}))
        self.reputation_index = dict(data.get("reputation_index", {}))
        self.task_registry = dict(data.get("task_registry", {}))
        self.governance_proposals = dict(data.get("governance_proposals", {}))
        self.activity_feed = list(data.get("activity_feed", []))
        self.treasury_balance = data.get("treasury_balance", 0.0)
        self.validator_candidates = data.get("validator_candidates", {})
        self.oracle_assignments = data.get("oracle_assignments", {})
        self.model_registry = dict(data.get("model_registry", {}))
        self.pipeline_registry = dict(data.get("pipeline_registry", {}))
        self.zk_circuit_registry = dict(data.get("zk_circuit_registry", {}))
        self.zk_proof_log = list(data.get("zk_proof_log", []))
        # Rebuild replay-prevention set from persisted proof log
        self.zk_proof_hashes = {
            e["proof_hash"] for e in self.zk_proof_log if "proof_hash" in e
        }
        self.agent_register_history = list(data.get("agent_register_history", []))
        self.activity_log_index = dict(data.get("activity_log_index", {}))
        self.challenge_index = dict(data.get("challenge_index", {}))
        self.collab_index = dict(data.get("collab_index", {}))
        self.intent_index = dict(data.get("intent_index", {}))
        self.artifact_index = dict(data.get("artifact_index", {}))
        self.agent_param_proposals = dict(data.get("agent_param_proposals", {}))
        if "agent_trust_params" in data:
            self.agent_trust_params.update(data["agent_trust_params"])
        self.agent_trust_params_history = list(data.get("agent_trust_params_history", []))
        self.chain = [Block.from_dict(raw) for raw in data.get("chain", [])]
        self.pending_transactions = list(data.get("pending_transactions", []))
        self._chain_full_height = int(data.get("chain_full_height", len(self.chain)))
        if not self.chain:
            self._create_genesis_block()
        persisted_balance_index = data.get("balance_index", {})
        if persisted_balance_index:
            # Fast path: use persisted state, skip full chain replay
            self.balance_index = {str(k): float(v) for k, v in persisted_balance_index.items()}
        else:
            # Fallback: rebuild from chain (first boot or migration)
            self._rebuild_runtime_indexes()
        persisted_public_tx_count = data.get("public_tx_count_total")
        if persisted_public_tx_count is not None:
            self._public_tx_count_total = int(persisted_public_tx_count)
        else:
            self._public_tx_count_total = self._estimated_public_tx_count_from_retained_chain()
        persisted_total_minted_supply = data.get("total_minted_supply")
        if persisted_total_minted_supply is not None:
            self._total_minted_supply = round(float(persisted_total_minted_supply), 8)
        else:
            self._total_minted_supply = self._estimated_total_minted_supply_from_retained_state()
        self._reindex_pending_runtime_state()
        if self.state_version == 0:
            self.state_version = len(self.chain) + len(self.pending_transactions)

    def _load(self) -> None:
        with open(self.chain_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        self._load_from_state(data)
        if self._replay_mempool_wal():
            self._save()
        self.prune_mempool(force_persist=True)


class PrivateAssetChain:
    def __init__(self, chain_file: str):
        self.chain_file = chain_file
        self.chain: List[Block] = []
        self.pending_transactions: List[Dict[str, Any]] = []
        self.pending_blocks: List[Block] = []
        self.pending_finality: Dict[str, Dict[str, Any]] = {}
        self.finality_records: Dict[str, Dict[str, Any]] = {}

        self.participants: Dict[str, Dict[str, Any]] = {}
        self.validators: Dict[str, Dict[str, Any]] = {}
        self.issuers: Set[str] = set()
        self.notaries: Dict[str, Dict[str, Any]] = {}

        self.domains: Dict[str, Dict[str, Any]] = {}

        self.governance_threshold = 2
        self.finality_threshold = 1
        self.proposals: Dict[str, Dict[str, Any]] = {}
        self.model_registry: Dict[str, Dict[str, Any]] = {}
        self.ai_jobs: Dict[str, Dict[str, Any]] = {}
        self.state_version = 0

        if os.path.exists(self.chain_file):
            self._load()
        else:
            self._create_genesis_block()
            self._touch_and_save()

    def _touch_and_save(self) -> None:
        self.state_version += 1
        self._save()

    def _create_genesis_block(self) -> None:
        genesis = Block(
            index=0,
            timestamp=time.time(),
            transactions=[],
            previous_hash="0" * 64,
            meta={"network": "private-rwa"},
        )
        genesis.hash = genesis.compute_hash()
        self.chain = [genesis]

    def _normalize_participant(self, data: Dict[str, Any]) -> Dict[str, Any]:
        if "pubkey" in data:
            return {
                "pubkey": data["pubkey"],
                "domains": sorted(set(data.get("domains", []))),
                "attributes": dict(data.get("attributes", {})),
            }
        return {
            "pubkey": data,
            "domains": [],
            "attributes": {},
        }

    def _participant_pubkey(self, address: str) -> Optional[Dict[str, Any]]:
        entry = self.participants.get(address)
        if not entry:
            return None
        return entry.get("pubkey")

    def register_wallet(
        self,
        wallet: Dict[str, Any],
        roles: Optional[List[str]] = None,
        domains: Optional[List[str]] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> None:
        address = wallet["address"]
        pubkey = wallet["public_key"]
        expected = address_from_public_key(pubkey)
        if expected != address:
            raise ValueError("Wallet address and public key mismatch.")

        existing = self.participants.get(address, {"pubkey": pubkey, "domains": [], "attributes": {}})
        existing["pubkey"] = pubkey
        existing["domains"] = sorted(set(existing.get("domains", []) + (domains or [])))
        existing_attributes = dict(existing.get("attributes", {}))
        existing_attributes.update(attributes or {})
        existing["attributes"] = existing_attributes
        self.participants[address] = existing

        for role in roles or []:
            if role == "validator":
                self.validators[address] = pubkey
                # Default validator to also be an eligible notary for simpler bootstraps.
                self.notaries.setdefault(address, pubkey)
            elif role == "issuer":
                self.issuers.add(address)
            elif role == "notary":
                self.notaries[address] = pubkey
            elif role == "participant":
                continue
            else:
                raise ValueError(f"Unsupported role: {role}")

        for domain in domains or []:
            if domain in self.domains:
                members = set(self.domains[domain].get("members", []))
                members.add(address)
                self.domains[domain]["members"] = sorted(members)

        self._touch_and_save()

    def create_domain(self, domain_id: str, members: Optional[List[str]], created_by: str) -> None:
        if not domain_id:
            raise ValueError("domain_id is required.")
        for member in members or []:
            if member not in self.participants:
                raise ValueError(f"Unknown participant in domain: {member}")

        domain = self.domains.get(domain_id)
        if not domain:
            self.domains[domain_id] = {
                "members": sorted(set(members or [])),
                "contracts": {},
                "created_by": created_by,
                "created_at": time.time(),
            }
        else:
            merged = set(domain.get("members", []))
            merged.update(members or [])
            domain["members"] = sorted(merged)

        for member in members or []:
            profile = self.participants.get(member)
            if profile is None:
                continue
            domains = set(profile.get("domains", []))
            domains.add(domain_id)
            profile["domains"] = sorted(domains)

        self._touch_and_save()

    def deploy_contract(
        self,
        domain_id: str,
        contract_id: str,
        rules: Dict[str, Any],
        deployed_by: str,
    ) -> None:
        if domain_id not in self.domains:
            raise ValueError(f"Unknown domain: {domain_id}")
        if not contract_id:
            raise ValueError("contract_id is required.")

        if "max_transfer_amount" in rules:
            rules["max_transfer_amount"] = float(rules["max_transfer_amount"])
        if "allowed_recipients" in rules:
            rules["allowed_recipients"] = sorted(set(rules["allowed_recipients"]))
        if "blocked_senders" in rules:
            rules["blocked_senders"] = sorted(set(rules["blocked_senders"]))
        if "blocked_recipients" in rules:
            rules["blocked_recipients"] = sorted(set(rules["blocked_recipients"]))

        self.domains[domain_id].setdefault("contracts", {})[contract_id] = {
            "rules": rules,
            "deployed_by": deployed_by,
            "created_at": time.time(),
        }
        self._touch_and_save()

    def _proposal_signable(self, action: str, payload: Dict[str, Any], proposer: str, created_at: float) -> Dict[str, Any]:
        return {
            "type": "governance_proposal",
            "action": action,
            "payload": payload,
            "proposer": proposer,
            "created_at": created_at,
        }

    def _approval_signable(self, proposal_id: str, approver: str, approved_at: float) -> Dict[str, Any]:
        return {
            "type": "governance_approval",
            "proposal_id": proposal_id,
            "approver": approver,
            "approved_at": approved_at,
        }

    def propose_governance(self, proposer_wallet: Dict[str, Any], action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        proposer = proposer_wallet["address"]
        if proposer not in self.validators:
            raise ValueError("Only validators can create governance proposals.")

        created_at = time.time()
        signable = self._proposal_signable(action, payload, proposer, created_at)
        signature = sign_with_wallet(signable, proposer_wallet)
        proposal_id = sha256_hex(canonical_json({**signable, "signature": signature}))

        proposal = {
            "id": proposal_id,
            "action": action,
            "payload": payload,
            "proposer": proposer,
            "pubkey": proposer_wallet["public_key"],
            "signature": signature,
            "created_at": created_at,
            "approvals": [
                {
                    "approver": proposer,
                    "pubkey": proposer_wallet["public_key"],
                    "signature": sign_with_wallet(
                        self._approval_signable(proposal_id, proposer, created_at), proposer_wallet
                    ),
                    "approved_at": created_at,
                }
            ],
            "executed": False,
            "executed_at": None,
            "result": "pending",
        }

        self.proposals[proposal_id] = proposal
        self._maybe_execute_proposal(proposal_id)
        self._touch_and_save()
        return proposal

    def approve_governance(self, proposal_id: str, approver_wallet: Dict[str, Any]) -> Dict[str, Any]:
        proposal = self.proposals.get(proposal_id)
        if not proposal:
            raise ValueError("Unknown proposal id.")
        if proposal.get("executed"):
            return proposal

        approver = approver_wallet["address"]
        if approver not in self.validators:
            raise ValueError("Only validators can approve governance proposals.")

        current = {a["approver"] for a in proposal.get("approvals", [])}
        if approver in current:
            return proposal

        approved_at = time.time()
        signable = self._approval_signable(proposal_id, approver, approved_at)
        proposal.setdefault("approvals", []).append(
            {
                "approver": approver,
                "pubkey": approver_wallet["public_key"],
                "signature": sign_with_wallet(signable, approver_wallet),
                "approved_at": approved_at,
            }
        )

        self._maybe_execute_proposal(proposal_id)
        self._touch_and_save()
        return proposal

    def _execute_proposal(self, proposal: Dict[str, Any]) -> None:
        action = proposal["action"]
        payload = dict(proposal["payload"])

        if action == "register_participant":
            wallet_like = payload.get("wallet", {})
            if not wallet_like:
                raise ValueError("register_participant requires payload.wallet")
            self.register_wallet(
                wallet=wallet_like,
                roles=payload.get("roles", ["participant"]),
                domains=payload.get("domains", []),
                attributes=payload.get("attributes", {}),
            )
            return

        if action == "create_domain":
            self.create_domain(
                domain_id=str(payload.get("domain_id", "")),
                members=list(payload.get("members", [])),
                created_by=proposal["proposer"],
            )
            return

        if action == "add_domain_member":
            domain_id = str(payload.get("domain_id", ""))
            member = str(payload.get("member", ""))
            if domain_id not in self.domains:
                raise ValueError("Unknown domain in add_domain_member")
            if member not in self.participants:
                raise ValueError("Unknown member in add_domain_member")
            members = set(self.domains[domain_id].get("members", []))
            members.add(member)
            self.domains[domain_id]["members"] = sorted(members)
            profile = self.participants[member]
            profile["domains"] = sorted(set(profile.get("domains", [])) | {domain_id})
            return

        if action == "deploy_contract":
            self.deploy_contract(
                domain_id=str(payload.get("domain_id", "")),
                contract_id=str(payload.get("contract_id", "")),
                rules=dict(payload.get("rules", {})),
                deployed_by=proposal["proposer"],
            )
            return

        if action == "set_thresholds":
            if "governance_threshold" in payload:
                self.governance_threshold = max(1, int(payload["governance_threshold"]))
            if "finality_threshold" in payload:
                self.finality_threshold = max(1, int(payload["finality_threshold"]))
            return

        raise ValueError(f"Unsupported governance action: {action}")

    def _maybe_execute_proposal(self, proposal_id: str) -> None:
        proposal = self.proposals[proposal_id]
        if proposal.get("executed"):
            return
        approvals = proposal.get("approvals", [])
        approvers = {item["approver"] for item in approvals}
        if len(approvers) < self.governance_threshold:
            return

        self._execute_proposal(proposal)
        proposal["executed"] = True
        proposal["executed_at"] = time.time()
        proposal["result"] = "executed"

    def list_governance(self) -> Dict[str, Any]:
        proposals = sorted(self.proposals.values(), key=lambda p: p.get("created_at", 0.0))
        return {
            "governance_threshold": self.governance_threshold,
            "finality_threshold": self.finality_threshold,
            "proposals": proposals,
        }

    def _tx_seen(self, tx_id: str) -> bool:
        for tx in self.pending_transactions:
            if tx.get("id") == tx_id:
                return True
        for block in self.chain:
            for tx in block.transactions:
                if tx.get("id") == tx_id:
                    return True
        for block in self.pending_blocks:
            for tx in block.transactions:
                if tx.get("id") == tx_id:
                    return True
        return False

    def _signable_asset_issue(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type": "asset_issue",
            "issuer": tx["issuer"],
            "owner": tx["owner"],
            "asset_id": tx["asset_id"],
            "amount": float(tx["amount"]),
            "domain": tx["domain"],
            "contract_id": tx.get("contract_id", ""),
            "metadata_hash": tx.get("metadata_hash", ""),
            "metadata": dict(tx.get("metadata", {})),
            "visibility": list(tx.get("visibility", [])),
            "timestamp": float(tx["timestamp"]),
        }

    def _signable_asset_transfer(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type": "asset_transfer",
            "asset_id": tx["asset_id"],
            "amount": float(tx["amount"]),
            "from": tx["from"],
            "to": tx["to"],
            "visibility": list(tx.get("visibility", [])),
            "timestamp": float(tx["timestamp"]),
        }

    def _signable_ai_model_register(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type": "ai_model_register",
            "model_id": str(tx.get("model_id", "")),
            "owner": str(tx.get("owner", "")),
            "model_hash": str(tx.get("model_hash", "")),
            "version": str(tx.get("version", "")),
            "price_per_call": float(tx.get("price_per_call", 0.0)),
            "visibility": list(tx.get("visibility", [])),
            "metadata": dict(tx.get("metadata", {})),
            "timestamp": float(tx.get("timestamp", 0.0)),
        }

    def _signable_ai_job_create(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type": "ai_job_create",
            "job_id": str(tx.get("job_id", "")),
            "model_id": str(tx.get("model_id", "")),
            "requester": str(tx.get("requester", "")),
            "input_hash": str(tx.get("input_hash", "")),
            "max_payment": float(tx.get("max_payment", 0.0)),
            "visibility": list(tx.get("visibility", [])),
            "metadata": dict(tx.get("metadata", {})),
            "timestamp": float(tx.get("timestamp", 0.0)),
        }

    def _signable_ai_job_result(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type": "ai_job_result",
            "job_id": str(tx.get("job_id", "")),
            "provider": str(tx.get("provider", "")),
            "result_hash": str(tx.get("result_hash", "")),
            "quality_score": float(tx.get("quality_score", 1.0)),
            "metadata": dict(tx.get("metadata", {})),
            "timestamp": float(tx.get("timestamp", 0.0)),
        }

    def _signable_ai_job_settle(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type": "ai_job_settle",
            "job_id": str(tx.get("job_id", "")),
            "settler": str(tx.get("settler", "")),
            "payout": float(tx.get("payout", 0.0)),
            "slash_provider": float(tx.get("slash_provider", 0.0)),
            "reason": str(tx.get("reason", "")),
            "timestamp": float(tx.get("timestamp", 0.0)),
        }

    def _verify_signer(self, tx: Dict[str, Any], payload: Dict[str, Any]) -> bool:
        signer = tx.get("signer")
        pubkey = tx.get("pubkey")
        signature = tx.get("signature")
        if not signer or not pubkey or not signature:
            return False
        if address_from_public_key(pubkey) != signer:
            return False

        registered = self._participant_pubkey(signer)
        if not registered or registered != pubkey:
            return False

        return verify_signature(payload, signature, pubkey)

    def _build_asset_state(self, include_pending_txs: bool = False) -> Tuple[Dict[str, Dict[str, float]], Dict[str, Dict[str, Any]]]:
        holdings: Dict[str, Dict[str, float]] = {}
        assets: Dict[str, Dict[str, Any]] = {}

        for block in self.chain:
            for tx in block.transactions:
                if tx.get("type") in {"asset_issue", "asset_transfer"}:
                    self._apply_asset_tx(tx, holdings, assets)

        if include_pending_txs:
            for tx in self.pending_transactions:
                if tx.get("type") in {"asset_issue", "asset_transfer"}:
                    self._apply_asset_tx(tx, holdings, assets)
            for block in self.pending_blocks:
                for tx in block.transactions:
                    if tx.get("type") in {"asset_issue", "asset_transfer"}:
                        self._apply_asset_tx(tx, holdings, assets)

        return holdings, assets

    def _apply_asset_tx(
        self,
        tx: Dict[str, Any],
        holdings: Dict[str, Dict[str, float]],
        assets: Dict[str, Dict[str, Any]],
    ) -> None:
        tx_type = tx["type"]
        asset_id = tx["asset_id"]
        amount = float(tx["amount"])

        if tx_type == "asset_issue":
            owner = tx["owner"]
            holdings.setdefault(owner, {})
            holdings[owner][asset_id] = holdings[owner].get(asset_id, 0.0) + amount
            assets[asset_id] = {
                "domain": tx["domain"],
                "contract_id": tx.get("contract_id", ""),
                "issuer": tx["issuer"],
                "metadata_hash": tx.get("metadata_hash", ""),
                "metadata": dict(tx.get("metadata", {})),
            }
            return

        sender = tx["from"]
        recipient = tx["to"]
        holdings.setdefault(sender, {})
        holdings.setdefault(recipient, {})
        holdings[sender][asset_id] = holdings[sender].get(asset_id, 0.0) - amount
        holdings[recipient][asset_id] = holdings[recipient].get(asset_id, 0.0) + amount

    def _apply_ai_tx(self, tx: Dict[str, Any]) -> None:
        tx_type = tx.get("type")
        if tx_type == "ai_model_register":
            model_id = str(tx.get("model_id", "")).strip()
            if not model_id:
                return
            self.model_registry[model_id] = {
                "model_id": model_id,
                "owner": tx.get("owner", ""),
                "model_hash": tx.get("model_hash", ""),
                "version": tx.get("version", ""),
                "price_per_call": float(tx.get("price_per_call", 0.0)),
                "visibility": list(tx.get("visibility", [])),
                "metadata": dict(tx.get("metadata", {})),
                "tx_id": tx.get("id", ""),
                "updated_at": float(tx.get("timestamp", time.time())),
            }
            return

        if tx_type == "ai_job_create":
            job_id = str(tx.get("job_id", "")).strip()
            if not job_id:
                return
            self.ai_jobs[job_id] = {
                "job_id": job_id,
                "model_id": tx.get("model_id", ""),
                "requester": tx.get("requester", ""),
                "input_hash": tx.get("input_hash", ""),
                "max_payment": float(tx.get("max_payment", 0.0)),
                "visibility": list(tx.get("visibility", [])),
                "metadata": dict(tx.get("metadata", {})),
                "status": "created",
                "result": {},
                "settlement": {},
                "created_at": float(tx.get("timestamp", time.time())),
                "updated_at": float(tx.get("timestamp", time.time())),
                "create_tx_id": tx.get("id", ""),
            }
            return

        if tx_type == "ai_job_result":
            job_id = str(tx.get("job_id", "")).strip()
            if not job_id:
                return
            job = self.ai_jobs.setdefault(
                job_id,
                {
                    "job_id": job_id,
                    "status": "unknown",
                    "result": {},
                    "settlement": {},
                },
            )
            job["status"] = "result_submitted"
            job["result"] = {
                "provider": tx.get("provider", ""),
                "result_hash": tx.get("result_hash", ""),
                "quality_score": float(tx.get("quality_score", 1.0)),
                "metadata": dict(tx.get("metadata", {})),
                "tx_id": tx.get("id", ""),
                "at": float(tx.get("timestamp", time.time())),
            }
            job["updated_at"] = float(tx.get("timestamp", time.time()))
            return

        if tx_type == "ai_job_settle":
            job_id = str(tx.get("job_id", "")).strip()
            if not job_id:
                return
            job = self.ai_jobs.setdefault(
                job_id,
                {
                    "job_id": job_id,
                    "status": "unknown",
                    "result": {},
                    "settlement": {},
                },
            )
            job["status"] = "settled"
            job["settlement"] = {
                "settler": tx.get("settler", ""),
                "payout": float(tx.get("payout", 0.0)),
                "slash_provider": float(tx.get("slash_provider", 0.0)),
                "reason": str(tx.get("reason", "")),
                "tx_id": tx.get("id", ""),
                "at": float(tx.get("timestamp", time.time())),
            }
            job["updated_at"] = float(tx.get("timestamp", time.time()))

    def _validate_ai_tx(self, tx: Dict[str, Any]) -> bool:
        tx_type = str(tx.get("type", "")).strip()
        required = {"id", "type", "timestamp", "signer", "pubkey", "signature"}
        if not required.issubset(tx.keys()):
            return False

        signer = str(tx.get("signer", "")).strip()
        if not signer:
            return False
        if signer not in self.participants and signer not in self.validators and signer not in self.notaries:
            return False
        if address_from_public_key(tx.get("pubkey", {})) != signer:
            return False

        if tx_type == "ai_model_register":
            model_id = str(tx.get("model_id", "")).strip()
            owner = str(tx.get("owner", "")).strip()
            model_hash = str(tx.get("model_hash", "")).strip()
            version = str(tx.get("version", "")).strip()
            price_per_call = float(tx.get("price_per_call", 0.0))
            if not model_id or not owner or not model_hash or not version or price_per_call < 0:
                return False
            if owner != signer:
                return False
            if owner not in self.participants:
                return False
            if model_id in self.model_registry:
                return False
            return verify_signature(self._signable_ai_model_register(tx), tx["signature"], tx["pubkey"])

        if tx_type == "ai_job_create":
            job_id = str(tx.get("job_id", "")).strip()
            model_id = str(tx.get("model_id", "")).strip()
            requester = str(tx.get("requester", "")).strip()
            input_hash = str(tx.get("input_hash", "")).strip()
            max_payment = float(tx.get("max_payment", 0.0))
            if not job_id or not model_id or not requester or not input_hash or max_payment < 0:
                return False
            if requester != signer:
                return False
            if requester not in self.participants:
                return False
            if job_id in self.ai_jobs:
                return False
            if model_id not in self.model_registry:
                return False
            return verify_signature(self._signable_ai_job_create(tx), tx["signature"], tx["pubkey"])

        if tx_type == "ai_job_result":
            job_id = str(tx.get("job_id", "")).strip()
            provider = str(tx.get("provider", "")).strip()
            result_hash = str(tx.get("result_hash", "")).strip()
            quality_score = float(tx.get("quality_score", 1.0))
            if not job_id or not provider or not result_hash:
                return False
            if provider != signer:
                return False
            if provider not in self.participants:
                return False
            job = self.ai_jobs.get(job_id)
            if not job or job.get("status") not in {"created", "result_submitted"}:
                return False
            if quality_score < 0:
                return False
            return verify_signature(self._signable_ai_job_result(tx), tx["signature"], tx["pubkey"])

        if tx_type == "ai_job_settle":
            job_id = str(tx.get("job_id", "")).strip()
            settler = str(tx.get("settler", "")).strip()
            payout = float(tx.get("payout", 0.0))
            slash_provider = float(tx.get("slash_provider", 0.0))
            if not job_id or not settler or payout < 0 or slash_provider < 0:
                return False
            if settler != signer:
                return False
            if settler not in self.validators and settler not in self.notaries:
                return False
            job = self.ai_jobs.get(job_id)
            if not job or job.get("status") != "result_submitted":
                return False
            return verify_signature(self._signable_ai_job_settle(tx), tx["signature"], tx["pubkey"])

        return False

    def _domain_has_member(self, domain_id: str, address: str) -> bool:
        domain = self.domains.get(domain_id)
        if not domain:
            return False
        return address in set(domain.get("members", []))

    def _contract_allows_transfer(
        self,
        contract_id: str,
        domain_id: str,
        tx: Dict[str, Any],
    ) -> bool:
        if not contract_id:
            return True

        domain = self.domains.get(domain_id, {})
        contracts = domain.get("contracts", {})
        contract = contracts.get(contract_id)
        if not contract:
            return False

        rules = contract.get("rules", {})
        amount = float(tx["amount"])
        sender = tx["from"]
        recipient = tx["to"]

        max_transfer = rules.get("max_transfer_amount")
        if max_transfer is not None and amount > float(max_transfer):
            return False

        allowed_recipients = set(rules.get("allowed_recipients", []))
        if allowed_recipients and recipient not in allowed_recipients:
            return False

        blocked_senders = set(rules.get("blocked_senders", []))
        if sender in blocked_senders:
            return False

        blocked_recipients = set(rules.get("blocked_recipients", []))
        if recipient in blocked_recipients:
            return False

        require_visibility = bool(rules.get("require_visibility", False))
        if require_visibility and not tx.get("visibility"):
            return False

        return True

    def _validate_asset_tx(
        self,
        tx: Dict[str, Any],
        holdings: Dict[str, Dict[str, float]],
        assets: Dict[str, Dict[str, Any]],
        check_funds: bool = True,
    ) -> bool:
        required = {"id", "type", "asset_id", "amount", "timestamp", "signer", "pubkey", "signature"}
        if not required.issubset(tx.keys()):
            return False
        if float(tx["amount"]) <= 0:
            return False

        visibility = tx.get("visibility", [])
        if any(v not in self.participants for v in visibility):
            return False

        tx_type = tx["type"]
        if tx_type == "asset_issue":
            issuer = tx.get("issuer")
            owner = tx.get("owner")
            domain = tx.get("domain")
            contract_id = tx.get("contract_id", "")
            if not issuer or not owner or not domain:
                return False
            if issuer != tx["signer"]:
                return False
            if issuer not in self.issuers:
                return False
            if owner not in self.participants:
                return False
            if domain not in self.domains:
                return False
            if not self._domain_has_member(domain, owner):
                return False
            if not self._domain_has_member(domain, issuer):
                return False

            if contract_id:
                domain_contracts = self.domains[domain].get("contracts", {})
                if contract_id not in domain_contracts:
                    return False

            payload = self._signable_asset_issue(tx)
            return self._verify_signer(tx, payload)

        if tx_type == "asset_transfer":
            sender = tx.get("from")
            recipient = tx.get("to")
            asset_id = tx.get("asset_id")
            if not sender or not recipient or not asset_id:
                return False
            if sender != tx["signer"]:
                return False
            if sender not in self.participants or recipient not in self.participants:
                return False

            asset_meta = assets.get(asset_id)
            if not asset_meta:
                return False

            domain = asset_meta["domain"]
            contract_id = asset_meta.get("contract_id", "")
            if not self._domain_has_member(domain, sender):
                return False
            if not self._domain_has_member(domain, recipient):
                return False

            payload = self._signable_asset_transfer(tx)
            if not self._verify_signer(tx, payload):
                return False
            if not self._contract_allows_transfer(contract_id, domain, tx):
                return False

            if check_funds:
                sender_bal = holdings.get(sender, {}).get(asset_id, 0.0)
                if sender_bal < float(tx["amount"]):
                    return False
            return True

        return False

    def add_transaction(self, tx: Dict[str, Any]) -> None:
        tx_id = str(tx.get("id", ""))
        if not tx_id:
            raise ValueError("Transaction must include id.")
        if self._tx_seen(tx_id):
            raise ValueError(f"Transaction {tx_id} already exists.")

        tx_type = str(tx.get("type", "")).strip()
        if tx_type in {"asset_issue", "asset_transfer"}:
            holdings, assets = self._build_asset_state(include_pending_txs=True)
            if not self._validate_asset_tx(tx, holdings, assets, check_funds=True):
                raise ValueError("Invalid private asset transaction.")
        elif tx_type in {"ai_model_register", "ai_job_create", "ai_job_result", "ai_job_settle"}:
            if not self._validate_ai_tx(tx):
                raise ValueError("Invalid private ai transaction.")
            self._apply_ai_tx(tx)
        else:
            raise ValueError(f"Unsupported private tx type: {tx_type}")

        self.pending_transactions.append(tx)
        self._touch_and_save()

    def _seal_payload(self, block: Block, validator: str) -> Dict[str, Any]:
        tx_ids = [tx["id"] for tx in block.transactions]
        return {
            "chain": "private-rwa",
            "index": block.index,
            "timestamp": block.timestamp,
            "previous_hash": block.previous_hash,
            "validator": validator,
            "tx_ids": tx_ids,
        }

    def _attestation_payload(self, block: Block) -> Dict[str, Any]:
        return {
            "chain": "private-rwa",
            "block_hash": block.hash,
            "index": block.index,
            "previous_hash": block.previous_hash,
        }

    def seal_pending_transactions(self, validator_wallet: Dict[str, Any]) -> Block:
        validator = validator_wallet["address"]
        if validator not in self.validators:
            raise ValueError("Wallet is not an authorized private validator.")

        block = Block(
            index=len(self.chain) + len(self.pending_blocks),
            timestamp=time.time(),
            transactions=list(self.pending_transactions),
            previous_hash=(self.pending_blocks[-1].hash if self.pending_blocks else self.chain[-1].hash),
            meta={
                "validator": validator,
                "validator_pubkey": validator_wallet["public_key"],
            },
        )
        block.meta["validator_signature"] = sign_with_wallet(self._seal_payload(block, validator), validator_wallet)
        block.hash = block.compute_hash()

        self.pending_blocks.append(block)
        self.pending_finality[block.hash] = {
            "threshold": self.finality_threshold,
            "notary_approvals": [],
            "created_at": time.time(),
        }
        self.pending_transactions = []

        # Auto-attest with validator if validator has notary role.
        if validator in self.notaries:
            self.attest_block(block.hash, validator_wallet, auto_finalize=True)
        else:
            self._touch_and_save()

        return block

    def attest_block(self, block_hash: str, notary_wallet: Dict[str, Any], auto_finalize: bool = True) -> Dict[str, Any]:
        notary = notary_wallet["address"]
        if notary not in self.notaries:
            raise ValueError("Wallet is not an authorized private notary.")

        block = next((b for b in self.pending_blocks if b.hash == block_hash), None)
        if not block:
            finalized = self.finality_records.get(block_hash)
            if finalized:
                out = dict(finalized)
                out["finalized"] = True
                out["already_finalized"] = True
                out["block_hash"] = block_hash
                return out
            raise ValueError("Pending block not found.")

        finality = self.pending_finality.get(block_hash)
        if not finality:
            raise ValueError("Pending finality record not found.")

        existing = {a["notary"] for a in finality.get("notary_approvals", [])}
        if notary in existing:
            return finality

        payload = self._attestation_payload(block)
        finality.setdefault("notary_approvals", []).append(
            {
                "notary": notary,
                "pubkey": notary_wallet["public_key"],
                "signature": sign_with_wallet(payload, notary_wallet),
                "approved_at": time.time(),
            }
        )

        if auto_finalize:
            self.finalize_block(block_hash, fail_if_insufficient=False)
        else:
            self._touch_and_save()
        return finality

    def finalize_block(self, block_hash: str, fail_if_insufficient: bool = True) -> Optional[Block]:
        block = next((b for b in self.pending_blocks if b.hash == block_hash), None)
        if not block:
            if fail_if_insufficient:
                raise ValueError("Pending block not found.")
            return None

        finality = self.pending_finality.get(block_hash, {})
        threshold = int(finality.get("threshold", self.finality_threshold))
        approvals = finality.get("notary_approvals", [])
        if len({a["notary"] for a in approvals}) < threshold:
            if fail_if_insufficient:
                raise ValueError("Insufficient notary approvals to finalize block.")
            self._touch_and_save()
            return None

        if block.index != len(self.chain):
            raise ValueError("Cannot finalize out-of-order pending block.")

        self.chain.append(block)
        self.pending_blocks = [b for b in self.pending_blocks if b.hash != block_hash]
        self.pending_finality.pop(block_hash, None)
        self.finality_records[block_hash] = {
            "threshold": threshold,
            "notary_approvals": approvals,
            "finalized_at": time.time(),
        }
        self._touch_and_save()
        return block

    def _tx_parties(self, tx: Dict[str, Any]) -> Set[str]:
        parties: Set[str] = set()
        for field in (
            "signer",
            "from",
            "to",
            "issuer",
            "owner",
            "requester",
            "provider",
            "settler",
        ):
            value = tx.get(field)
            if value:
                parties.add(value)
        return parties

    def _is_viewer_allowed_for_tx(self, tx: Dict[str, Any], viewer: Optional[str]) -> bool:
        if not viewer:
            return True
        if viewer in self.validators or viewer in self.notaries:
            return True

        parties = self._tx_parties(tx)
        if viewer in parties:
            return True

        visibility = set(tx.get("visibility", []))
        if visibility:
            return viewer in visibility

        if tx["type"] in {"ai_model_register", "ai_job_create", "ai_job_result", "ai_job_settle"}:
            return viewer in self._tx_parties(tx)

        if tx["type"] == "asset_issue":
            domain = tx.get("domain", "")
        else:
            _, assets = self._build_asset_state()
            domain = assets.get(tx.get("asset_id", ""), {}).get("domain", "")
        if domain:
            return self._domain_has_member(domain, viewer)
        return False

    def get_asset_balances(
        self,
        address: Optional[str] = None,
        viewer: Optional[str] = None,
        include_pending: bool = False,
    ) -> Dict[str, Dict[str, float]]:
        holdings: Dict[str, Dict[str, float]] = {}
        assets: Dict[str, Dict[str, Any]] = {}

        def apply_if_visible(tx: Dict[str, Any]) -> None:
            if self._is_viewer_allowed_for_tx(tx, viewer):
                if tx.get("type") in {"asset_issue", "asset_transfer"}:
                    self._apply_asset_tx(tx, holdings, assets)

        for block in self.chain:
            for tx in block.transactions:
                apply_if_visible(tx)

        if include_pending:
            for tx in self.pending_transactions:
                apply_if_visible(tx)
            for block in self.pending_blocks:
                for tx in block.transactions:
                    apply_if_visible(tx)

        if address:
            return {address: holdings.get(address, {})}
        return holdings

    def get_private_view(self, viewer: str) -> Dict[str, Any]:
        def filtered_block(block: Block) -> Dict[str, Any]:
            visible_txs = [tx for tx in block.transactions if self._is_viewer_allowed_for_tx(tx, viewer)]
            return {
                "index": block.index,
                "timestamp": block.timestamp,
                "previous_hash": block.previous_hash,
                "hash": block.hash,
                "meta": block.meta,
                "transactions": visible_txs,
            }

        return {
            "viewer": viewer,
            "chain": [filtered_block(b) for b in self.chain],
            "pending_blocks": [filtered_block(b) for b in self.pending_blocks],
            "pending_transactions": [
                tx for tx in self.pending_transactions if self._is_viewer_allowed_for_tx(tx, viewer)
            ],
            "balances": self.get_asset_balances(viewer=viewer),
            "ai_models": [
                model for model in self.model_registry.values()
                if (not model.get("visibility")) or viewer in set(model.get("visibility", [])) or viewer == model.get("owner")
            ],
            "ai_jobs": [
                job
                for job in self.ai_jobs.values()
                if viewer in {
                    str(job.get("requester", "")),
                    str((job.get("result") or {}).get("provider", "")),
                    str((job.get("settlement") or {}).get("settler", "")),
                }
                or viewer in set(job.get("visibility", []))
            ],
        }

    def list_ai_models(self, owner: str = "", limit: int = 200) -> Dict[str, Any]:
        owner_filter = str(owner or "").strip()
        rows = list(self.model_registry.values())
        if owner_filter:
            rows = [m for m in rows if str(m.get("owner", "")) == owner_filter]
        rows.sort(key=lambda m: float(m.get("updated_at", 0.0)), reverse=True)
        limited = rows[: max(1, min(int(limit), 1000))]
        return {
            "owner": owner_filter,
            "count": len(rows),
            "models": limited,
        }

    def list_ai_jobs(self, status: str = "", participant: str = "", limit: int = 200) -> Dict[str, Any]:
        status_filter = str(status or "").strip().lower()
        participant_filter = str(participant or "").strip()
        rows = list(self.ai_jobs.values())
        if status_filter:
            rows = [j for j in rows if str(j.get("status", "")).lower() == status_filter]
        if participant_filter:
            rows = [
                j
                for j in rows
                if participant_filter in {
                    str(j.get("requester", "")),
                    str((j.get("result") or {}).get("provider", "")),
                    str((j.get("settlement") or {}).get("settler", "")),
                }
            ]
        rows.sort(key=lambda j: float(j.get("updated_at", j.get("created_at", 0.0))), reverse=True)
        limited = rows[: max(1, min(int(limit), 1000))]
        return {
            "status": status_filter,
            "participant": participant_filter,
            "count": len(rows),
            "jobs": limited,
        }

    def domain_summary(self, domain_id: str = "", include_pending: bool = True) -> Dict[str, Any]:
        domain_filter = str(domain_id or "").strip()
        domains = self.domains
        selected_ids = [domain_filter] if domain_filter else sorted(domains.keys())

        holdings, assets = self._build_asset_state(include_pending_txs=include_pending)

        rows: List[Dict[str, Any]] = []
        for did in selected_ids:
            domain = domains.get(did)
            if not domain:
                continue

            asset_ids = sorted([aid for aid, meta in assets.items() if str(meta.get("domain", "")) == did])
            tx_count_chain = 0
            tx_count_pending = 0
            for block in self.chain:
                for tx in block.transactions:
                    if tx.get("type") == "asset_issue" and str(tx.get("domain", "")) == did:
                        tx_count_chain += 1
                    elif tx.get("type") == "asset_transfer":
                        meta = assets.get(str(tx.get("asset_id", "")), {})
                        if str(meta.get("domain", "")) == did:
                            tx_count_chain += 1
            if include_pending:
                for tx in self.pending_transactions:
                    if tx.get("type") == "asset_issue" and str(tx.get("domain", "")) == did:
                        tx_count_pending += 1
                    elif tx.get("type") == "asset_transfer":
                        meta = assets.get(str(tx.get("asset_id", "")), {})
                        if str(meta.get("domain", "")) == did:
                            tx_count_pending += 1

            member_balances: Dict[str, Dict[str, float]] = {}
            for member in domain.get("members", []):
                bal = {k: float(v) for k, v in holdings.get(member, {}).items() if abs(float(v)) > 1e-12}
                if bal:
                    member_balances[member] = bal

            rows.append(
                {
                    "domain_id": did,
                    "member_count": len(domain.get("members", [])),
                    "members": list(domain.get("members", [])),
                    "contract_count": len((domain.get("contracts") or {}).keys()),
                    "contracts": sorted((domain.get("contracts") or {}).keys()),
                    "asset_count": len(asset_ids),
                    "asset_ids": asset_ids,
                    "tx_count_chain": tx_count_chain,
                    "tx_count_pending": tx_count_pending,
                    "member_balances": member_balances,
                }
            )

        return {
            "domain_filter": domain_filter,
            "include_pending": bool(include_pending),
            "count": len(rows),
            "domains": rows,
        }

    def is_valid(self) -> bool:
        if not self.chain:
            return False
        if self.chain[0].hash != self.chain[0].compute_hash():
            return False

        holdings: Dict[str, Dict[str, float]] = {}
        assets: Dict[str, Dict[str, Any]] = {}
        rebuilt_models: Dict[str, Dict[str, Any]] = {}
        rebuilt_jobs: Dict[str, Dict[str, Any]] = {}

        for i, block in enumerate(self.chain):
            if i == 0:
                continue
            prev = self.chain[i - 1]
            if block.previous_hash != prev.hash:
                return False
            if block.hash != block.compute_hash():
                return False

            validator = block.meta.get("validator")
            validator_signature = block.meta.get("validator_signature")
            validator_pubkey = self.validators.get(validator or "")
            if not validator or not validator_signature or not validator_pubkey:
                return False

            if not verify_signature(self._seal_payload(block, validator), validator_signature, validator_pubkey):
                return False

            finality = self.finality_records.get(block.hash)
            if not finality:
                return False

            approvals = finality.get("notary_approvals", [])
            threshold = int(finality.get("threshold", 1))
            unique_notaries: Set[str] = set()
            for approval in approvals:
                notary = approval.get("notary")
                signature = approval.get("signature")
                pubkey = approval.get("pubkey")
                if not notary or not signature or not pubkey:
                    return False
                registry_pubkey = self.notaries.get(notary)
                if not registry_pubkey or registry_pubkey != pubkey:
                    return False
                if not verify_signature(self._attestation_payload(block), signature, pubkey):
                    return False
                unique_notaries.add(notary)

            if len(unique_notaries) < threshold:
                return False

            for tx in block.transactions:
                tx_type = str(tx.get("type", "")).strip()
                if tx_type in {"asset_issue", "asset_transfer"}:
                    if not self._validate_asset_tx(tx, holdings, assets, check_funds=True):
                        return False
                    self._apply_asset_tx(tx, holdings, assets)
                    continue
                if tx_type in {"ai_model_register", "ai_job_create", "ai_job_result", "ai_job_settle"}:
                    snapshot_models = self.model_registry
                    snapshot_jobs = self.ai_jobs
                    self.model_registry = rebuilt_models
                    self.ai_jobs = rebuilt_jobs
                    try:
                        if not self._validate_ai_tx(tx):
                            return False
                        self._apply_ai_tx(tx)
                        rebuilt_models = self.model_registry
                        rebuilt_jobs = self.ai_jobs
                    finally:
                        self.model_registry = snapshot_models
                        self.ai_jobs = snapshot_jobs
                    continue
                return False

        self.model_registry = rebuilt_models
        self.ai_jobs = rebuilt_jobs

        return True

    def export_state(self) -> Dict[str, Any]:
        return {
            "state_version": self.state_version,
            "participants": self.participants,
            "validators": self.validators,
            "issuers": sorted(self.issuers),
            "notaries": self.notaries,
            "domains": self.domains,
            "governance_threshold": self.governance_threshold,
            "finality_threshold": self.finality_threshold,
            "proposals": self.proposals,
            "model_registry": self.model_registry,
            "ai_jobs": self.ai_jobs,
            "chain": [b.to_dict() for b in self.chain],
            "pending_transactions": list(self.pending_transactions),
            "pending_blocks": [b.to_dict() for b in self.pending_blocks],
            "pending_finality": self.pending_finality,
            "finality_records": self.finality_records,
        }

    def adopt_state_if_longer(self, data: Dict[str, Any]) -> bool:
        incoming_chain = [Block.from_dict(raw) for raw in data.get("chain", [])]
        incoming_version = int(data.get("state_version", 0))

        should_adopt = False
        if incoming_version > self.state_version:
            should_adopt = True
        elif incoming_version == self.state_version and len(incoming_chain) > len(self.chain):
            should_adopt = True

        if not should_adopt:
            return False

        old_state = self.export_state()
        try:
            self._load_from_state(data)
            if not self.is_valid():
                raise ValueError("Incoming private chain invalid.")
            self.state_version = incoming_version
        except Exception as exc:  # pylint: disable=broad-except
            self._load_from_state(old_state)
            raise ValueError(str(exc)) from exc

        self._save()
        return True

    def _save(self) -> None:
        ensure_dir(os.path.dirname(self.chain_file) or ".")
        with open(self.chain_file, "w", encoding="utf-8") as f:
            json.dump(self.export_state(), f, separators=(",", ":"))

    def _load_from_state(self, data: Dict[str, Any]) -> None:
        raw_participants = dict(data.get("participants", {}))
        normalized: Dict[str, Dict[str, Any]] = {}
        for address, entry in raw_participants.items():
            normalized[address] = self._normalize_participant(entry)
        self.participants = normalized

        self.validators = dict(data.get("validators", {}))
        self.notaries = dict(data.get("notaries", {}))
        self.issuers = set(data.get("issuers", []))
        self.domains = dict(data.get("domains", {}))

        self.governance_threshold = max(1, int(data.get("governance_threshold", 2)))
        self.finality_threshold = max(1, int(data.get("finality_threshold", 1)))
        self.proposals = dict(data.get("proposals", {}))
        self.model_registry = dict(data.get("model_registry", {}))
        self.ai_jobs = dict(data.get("ai_jobs", {}))

        self.chain = [Block.from_dict(raw) for raw in data.get("chain", [])]
        self.pending_transactions = list(data.get("pending_transactions", []))
        self.pending_blocks = [Block.from_dict(raw) for raw in data.get("pending_blocks", [])]
        self.pending_finality = dict(data.get("pending_finality", {}))
        self.finality_records = dict(data.get("finality_records", {}))

        if not self.chain:
            self._create_genesis_block()

        # Backward compatibility migration for old state files without notary data.
        if not self.notaries and self.validators:
            self.notaries = dict(self.validators)

        if not self.finality_records and len(self.chain) > 1:
            for block in self.chain[1:]:
                validator = block.meta.get("validator")
                signature = block.meta.get("validator_signature")
                pubkey = self.validators.get(validator or "") or block.meta.get("validator_pubkey")
                if validator and signature and pubkey:
                    self.notaries.setdefault(validator, pubkey)
                    self.finality_records[block.hash] = {
                        "threshold": 1,
                        "notary_approvals": [
                            {
                                "notary": validator,
                                "pubkey": pubkey,
                                "signature": signature,
                                "approved_at": block.timestamp,
                            }
                        ],
                        "finalized_at": block.timestamp,
                    }

        if (not self.model_registry and not self.ai_jobs) and len(self.chain) > 1:
            for block in self.chain[1:]:
                for tx in block.transactions:
                    if tx.get("type") in {"ai_model_register", "ai_job_create", "ai_job_result", "ai_job_settle"}:
                        self._apply_ai_tx(tx)

        self.state_version = int(data.get("state_version", 0))
        if self.state_version == 0:
            self.state_version = (
                len(self.chain)
                + len(self.pending_transactions)
                + len(self.pending_blocks)
                + len(self.proposals)
            )

    def _load(self) -> None:
        with open(self.chain_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        self._load_from_state(data)
