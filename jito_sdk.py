"""
jito_sdk.py — Standalone read-heavy JITO node client.

This module has zero external dependencies (stdlib only) and is designed for
dashboards, monitors, and integrations that need to **query** chain state without
signing or submitting transactions.

If you are building an AI agent that logs work and builds reputation, use the
full SDK package instead — it handles signing, key management, and all trust ops:

    from jito_agent import JitoTracker, load_wallet

    tracker = JitoTracker(load_wallet("wallet.json"), agent_id="my-agent")
    tracker.log("task_completed", success=True)
    print(tracker.rules())        # live governance params
    print(tracker.get_log(id))    # permanent log lookup

This file (jito_sdk.py) is kept for environments where package installation is
not practical — Lambda functions, copy-paste deployments, strict sandboxes.
For everything else, prefer jito_agent/.
"""
import json
from typing import Any, Dict, Optional
from urllib import parse, request


class JitoClient:
    def __init__(self, node_url: str, auth_token: str = ""):
        self.node_url = node_url.rstrip("/")
        self.auth_token = auth_token.strip()

    def _headers(self, content_type: Optional[str] = None) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        if content_type:
            headers["Content-Type"] = content_type
        return headers

    def _get(self, path: str) -> Dict[str, Any]:
        req = request.Request(f"{self.node_url}{path}", headers=self._headers(), method="GET")
        with request.urlopen(req, timeout=10.0) as response:
            raw = response.read().decode("utf-8")
        return json.loads(raw) if raw else {}

    def _post(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        data = json.dumps(payload).encode("utf-8")
        req = request.Request(
            f"{self.node_url}{path}",
            data=data,
            headers=self._headers(content_type="application/json"),
            method="POST",
        )
        with request.urlopen(req, timeout=10.0) as response:
            raw = response.read().decode("utf-8")
        return json.loads(raw) if raw else {}

    # Health / metadata
    def health(self) -> Dict[str, Any]:
        return self._get("/health")

    def chain_info(self) -> Dict[str, Any]:
        return self._get("/chain/info")

    def slo(self) -> Dict[str, Any]:
        return self._get("/slo")

    # Public chain
    def public_consensus(self) -> Dict[str, Any]:
        return self._get("/public/consensus")

    def public_balance(self, address: str) -> Dict[str, Any]:
        quoted = parse.quote(address, safe="")
        return self._get(f"/public/balance?address={quoted}")

    def public_mempool(self, limit: int = 100) -> Dict[str, Any]:
        return self._get(f"/public/mempool?limit={max(1, min(int(limit), 500))}")

    def public_tx(self, tx_payload: Dict[str, Any]) -> Dict[str, Any]:
        return self._post("/public/tx", tx_payload)

    def public_mine(self, miner: str) -> Dict[str, Any]:
        return self._post("/public/mine", {"miner": miner})

    def public_finality(self) -> Dict[str, Any]:
        return self._get("/public/finality")

    def public_ai_stakes(self) -> Dict[str, Any]:
        return self._get("/public/ai/stakes")

    # Private chain
    def private_tx(self, tx_payload: Dict[str, Any]) -> Dict[str, Any]:
        return self._post("/private/tx", tx_payload)

    def private_domains(self, domain_id: str = "", include_pending: bool = True) -> Dict[str, Any]:
        q = parse.urlencode(
            {
                "domain_id": domain_id,
                "include_pending": "true" if include_pending else "false",
            }
        )
        return self._get(f"/private/domains?{q}")

    def private_ai_models(self, owner: str = "", limit: int = 200) -> Dict[str, Any]:
        q = parse.urlencode({"owner": owner, "limit": max(1, min(int(limit), 1000))})
        return self._get(f"/private/ai/models?{q}")

    def private_ai_jobs(self, status: str = "", participant: str = "", limit: int = 200) -> Dict[str, Any]:
        q = parse.urlencode(
            {
                "status": status,
                "participant": participant,
                "limit": max(1, min(int(limit), 1000)),
            }
        )
        return self._get(f"/private/ai/jobs?{q}")

    # Agent trust
    def agent_passport(self, address: str = "", agent_id: str = "",
                       verbose: bool = False) -> Dict[str, Any]:
        """Fetch portable trust passport by wallet address or agent_id string."""
        params: Dict[str, str] = {}
        if address:
            params["address"] = address
        if agent_id:
            params["agent_id"] = agent_id
        if verbose:
            params["verbose"] = "true"
        return self._get(f"/public/agent/passport?{parse.urlencode(params)}")

    def agent_rules(self) -> Dict[str, Any]:
        """Fetch live chain-state trust rules and full parameter change history."""
        return self._get("/public/agent/rules")

    def agent_log(self, log_id: str) -> Dict[str, Any]:
        """Permanent log lookup by log_id — survives block pruning."""
        return self._get(f"/public/agent/log?{parse.urlencode({'log_id': log_id})}")

    def agent_leaderboard(self, tag: str = "", platform: str = "",
                           limit: int = 20) -> Dict[str, Any]:
        """Fetch top agents by trust_score with raw counters."""
        params: Dict[str, Any] = {"limit": max(1, min(int(limit), 100))}
        if tag:
            params["tag"] = tag
        if platform:
            params["platform"] = platform
        return self._get(f"/public/agent/leaderboard?{parse.urlencode(params)}")
