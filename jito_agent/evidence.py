"""
Evidence storage backends for provable agent outputs.

After a session the agent hashes its final output, saves it (locally or to IPFS),
and attaches the evidence URL to the activity log — making every output independently
verifiable by any third party.

Usage:
    from jito_agent import NovaTracker, LocalEvidenceStore, IpfsEvidenceStore

    # Local files (dev / self-hosted)
    tracker = NovaTracker.new("my-agent", evidence_store=LocalEvidenceStore("./evidence"))

    # IPFS via local daemon
    tracker = NovaTracker.new("my-agent", evidence_store=IpfsEvidenceStore())

    # IPFS via Pinata (set PINATA_JWT env var or pass pinata_jwt=)
    tracker = NovaTracker.new("my-agent", evidence_store=IpfsEvidenceStore(pinata_jwt="Bearer ..."))

    with tracker.track("analysis", tags=["finance"]) as ctx:
        result = run_analysis(data)
        ctx.set_output(result)
    # → output saved, output_hash + evidence_url attached to the on-chain log automatically
"""

import json
import os
import ssl
import time
import urllib.request
import urllib.error
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Optional

_SSL_CTX = ssl.create_default_context()


# ── Serialization (must match tracker._hash exactly) ──────────────────────────

def _serialize(output: Any) -> str:
    """
    Canonical string representation of any output — matches the hash function in
    tracker._hash so the output_hash on-chain can be verified against evidence files.
    """
    if isinstance(output, (dict, list)):
        return json.dumps(output, sort_keys=True)
    return str(output)


# ── Base ───────────────────────────────────────────────────────────────────────

class EvidenceStore(ABC):
    """
    Abstract evidence storage backend.

    Implementors receive the raw output and its pre-computed sha256 hash
    (computed by the tracker using the same algorithm as the on-chain log),
    persist the output, and return a URL that anyone can use to fetch and
    independently verify the evidence.
    """

    @abstractmethod
    def save(self, output: Any, output_hash: str, metadata: Optional[Dict] = None) -> str:
        """
        Persist output and return an evidence_url.

        output:      the raw agent output (any JSON-serializable object or string)
        output_hash: sha256 hex of the output — matches the output_hash on-chain
        metadata:    optional dict merged into the evidence envelope
                     (e.g. agent_id, action_type, timestamp)

        Returns a URL string starting with file://, ipfs://, or https://.
        """


# ── Local file store ───────────────────────────────────────────────────────────

class LocalEvidenceStore(EvidenceStore):
    """
    Saves evidence as JSON files in a local directory.

    Suitable for development, air-gapped environments, or self-hosted nodes
    that serve the evidence directory over HTTP.

    Directory layout:
        <directory>/
            <sha256>.json   ← one file per unique output (idempotent writes)

    The returned file:// URL can be passed as evidence_url to tracker.log()
    and will be accepted by the Nova chain validator.

    Example:
        store = LocalEvidenceStore("./nova_evidence")
        tracker = NovaTracker.new("my-agent", evidence_store=store)
    """

    def __init__(self, directory: str = "./nova_evidence") -> None:
        self.directory = os.path.abspath(directory)
        os.makedirs(self.directory, exist_ok=True)

    def save(self, output: Any, output_hash: str, metadata: Optional[Dict] = None) -> str:
        """Save output to <directory>/<sha256>.json and return a file:// URL."""
        envelope = {
            "schema": "nova-evidence/1",
            "output_hash": output_hash,
            "output": _serialize(output),
            "saved_at": time.time(),
            **(metadata or {}),
        }
        file_path = os.path.join(self.directory, f"{output_hash}.json")
        if not os.path.exists(file_path):  # idempotent — don't overwrite identical content
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(envelope, f, indent=2)

        return Path(file_path).as_uri()  # file:///abs/path/<sha256>.json


# ── IPFS store ─────────────────────────────────────────────────────────────────

class IpfsEvidenceStore(EvidenceStore):
    """
    Pins evidence to IPFS and returns ipfs:// CID URLs.

    Supports two backends (auto-selected):
      • Local daemon  — default; talks to http://127.0.0.1:5001 via /api/v0/add
      • Pinata        — set pinata_jwt="Bearer <JWT>" or env var PINATA_JWT

    The CID returned is a content-addressed identifier: anyone with the CID can
    independently fetch and verify the evidence matches the output_hash on-chain.

    Examples:
        # Local daemon (ipfs daemon must be running)
        store = IpfsEvidenceStore()

        # Pinata managed pinning
        store = IpfsEvidenceStore(pinata_jwt="Bearer eyJ...")
        # or: export PINATA_JWT="Bearer eyJ..." and just IpfsEvidenceStore()
    """

    _DAEMON_ADD_PATH = "/api/v0/add?pin=true&cid-version=1"
    _PINATA_PIN_URL = "https://api.pinata.cloud/pinning/pinJSONToIPFS"

    def __init__(
        self,
        daemon_url: str = "http://127.0.0.1:5001",
        pinata_jwt: str = "",
    ) -> None:
        self.daemon_url = daemon_url.rstrip("/")
        self.pinata_jwt = pinata_jwt or os.environ.get("PINATA_JWT", "")

    def save(self, output: Any, output_hash: str, metadata: Optional[Dict] = None) -> str:
        """Pin output to IPFS and return an ipfs:// URL."""
        envelope = {
            "schema": "nova-evidence/1",
            "output_hash": output_hash,
            "output": _serialize(output),
            "saved_at": time.time(),
            **(metadata or {}),
        }
        if self.pinata_jwt:
            cid = self._pin_pinata(envelope, output_hash)
        else:
            cid = self._pin_daemon(envelope)
        return f"ipfs://{cid}"

    def _pin_daemon(self, envelope: Dict) -> str:
        """Upload to a local IPFS daemon via /api/v0/add (multipart/form-data)."""
        content = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        boundary = "----NovaBoundary"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="evidence.json"\r\n'
            f"Content-Type: application/json\r\n\r\n"
        ).encode() + content + f"\r\n--{boundary}--\r\n".encode()

        url = f"{self.daemon_url}{self._DAEMON_ADD_PATH}"
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
        try:
            kwargs = {"timeout": 30}
            if url.startswith("https"):
                kwargs["context"] = _SSL_CTX
            with urllib.request.urlopen(req, **kwargs) as r:
                resp = json.loads(r.read())
                return resp["Hash"]
        except urllib.error.URLError as e:
            raise RuntimeError(
                f"IPFS daemon unreachable at {self.daemon_url}. "
                "Is `ipfs daemon` running? Or use LocalEvidenceStore for local-only storage. "
                f"Original error: {e}"
            ) from e
        except (KeyError, json.JSONDecodeError) as e:
            raise RuntimeError(f"Unexpected IPFS daemon response: {e}") from e

    def _pin_pinata(self, envelope: Dict, output_hash: str) -> str:
        """Pin to IPFS via Pinata managed pinning service."""
        body = json.dumps({
            "pinataContent": envelope,
            "pinataMetadata": {"name": f"nova-evidence-{output_hash[:16]}"},
        }).encode("utf-8")
        jwt = self.pinata_jwt
        if not jwt.startswith("Bearer "):
            jwt = f"Bearer {jwt}"
        req = urllib.request.Request(self._PINATA_PIN_URL, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", jwt)
        try:
            kwargs = {"timeout": 30}
            if self._PINATA_PIN_URL.startswith("https"):
                kwargs["context"] = _SSL_CTX
            with urllib.request.urlopen(req, **kwargs) as r:
                resp = json.loads(r.read())
                return resp["IpfsHash"]
        except urllib.error.HTTPError as e:
            raise RuntimeError(
                f"Pinata upload failed ({e.code}): {e.read().decode()[:200]}"
            ) from e
        except (KeyError, json.JSONDecodeError) as e:
            raise RuntimeError(f"Unexpected Pinata response: {e}") from e
