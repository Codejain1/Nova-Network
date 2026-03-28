import base64
import hashlib
import hmac
import json
import time
from typing import Any, Dict, Optional


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(raw: str) -> bytes:
    padding = "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode((raw + padding).encode("ascii"))


def create_hs256_jwt(
    secret: str,
    subject: str = "user",
    ttl_seconds: int = 3600,
    extra_claims: Optional[Dict[str, Any]] = None,
) -> str:
    now = int(time.time())
    payload: Dict[str, Any] = {
        "sub": subject,
        "iat": now,
        "nbf": now,
        "exp": now + ttl_seconds,
    }
    payload.update(extra_claims or {})

    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(sig)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def verify_hs256_jwt(token: str, secret: str, leeway_seconds: int = 15) -> Dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("JWT must have 3 parts.")

    header_raw, payload_raw, sig_raw = parts
    header = json.loads(_b64url_decode(header_raw))
    payload = json.loads(_b64url_decode(payload_raw))

    if header.get("alg") != "HS256":
        raise ValueError("Unsupported JWT algorithm.")

    signing_input = f"{header_raw}.{payload_raw}".encode("ascii")
    expected_sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    actual_sig = _b64url_decode(sig_raw)
    if not hmac.compare_digest(expected_sig, actual_sig):
        raise ValueError("Invalid JWT signature.")

    now = int(time.time())
    nbf = int(payload.get("nbf", 0))
    exp = int(payload.get("exp", now + 1))
    if now + leeway_seconds < nbf:
        raise ValueError("JWT not yet valid.")
    if now - leeway_seconds >= exp:
        raise ValueError("JWT expired.")
    return payload
