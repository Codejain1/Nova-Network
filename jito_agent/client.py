"""Low-level HTTP client for the NOVA node API."""
import json
import urllib.request
import urllib.error
from typing import Dict, Any, Optional, List

from .crypto import (
    make_identity_claim_tx,
    make_agent_register_tx,
    make_task_complete_tx,
    make_pipeline_step_complete_tx,
    make_model_register_tx,
    make_model_inference_tx,
    make_governance_vote_tx,
    make_agent_activity_log_tx,
    make_agent_attest_tx,
    make_agent_challenge_tx,
    make_agent_param_propose_tx,
    make_agent_param_endorse_tx,
)


class NovaClient:
    def __init__(self, node_url: str = "https://explorer.flowpe.io", auth_token: str = ""):
        self.node_url = node_url.rstrip("/")
        self.auth_token = auth_token

    _UA = "jito-agent/0.5.0 (Nova Network; +https://explorer.flowpe.io)"

    def _get(self, path: str) -> Dict:
        url = f"{self.node_url}{path}"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", self._UA)
        if self.auth_token:
            req.add_header("Authorization", f"Bearer {self.auth_token}")
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"GET {path} failed {e.code}: {e.read().decode()[:200]}") from e

    def _post(self, path: str, data: Dict) -> Dict:
        url = f"{self.node_url}{path}"
        body = json.dumps(data).encode()
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", self._UA)
        if self.auth_token:
            req.add_header("Authorization", f"Bearer {self.auth_token}")
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"POST {path} failed {e.code}: {e.read().decode()[:200]}") from e

    def _submit_tx(self, tx: Dict) -> Dict:
        """Submit a pre-signed transaction to /public/tx."""
        return self._post("/public/tx", tx)

    # ── Chain ─────────────────────────────────────────────────────────────
    def status(self) -> Dict:
        return self._get("/status")

    def balance(self, address: str) -> float:
        return self._get(f"/public/balance?address={address}").get("balance", 0.0)

    def reputation(self, address: str) -> Dict:
        return self._get(f"/reputation/{address}")

    def activity_feed(self, limit: int = 20) -> List[Dict]:
        return self._get(f"/activity/feed?limit={limit}").get("feed", [])

    # ── Faucet ────────────────────────────────────────────────────────────
    def claim_faucet(self, address: str, amount: float = 0.0) -> Dict:
        payload: Dict[str, Any] = {"address": address}
        if amount:
            payload["amount"] = amount
        return self._post("/public/faucet", payload)

    # ── Identity ──────────────────────────────────────────────────────────
    def claim_identity(self, wallet: Dict, handle: str, bio: str = "",
                        links: Optional[Dict] = None) -> Dict:
        tx = make_identity_claim_tx(wallet, handle=handle, bio=bio, links=links or {})
        return self._submit_tx(tx)

    def get_identity(self, address: str) -> Optional[Dict]:
        try:
            return self._get(f"/identity/{address}")
        except RuntimeError:
            return None

    # ── Agents ────────────────────────────────────────────────────────────
    def register_agent(self, wallet: Dict, agent_id: str, name: str,
                        capabilities: List[str] = None, version_hash: str = "") -> Dict:
        tx = make_agent_register_tx(wallet, agent_id=agent_id, name=name,
                                     capabilities=capabilities or [],
                                     version_hash=version_hash)
        return self._submit_tx(tx)

    def log_activity(
        self,
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
        """Build and submit a locally-signed activity log tx. Wallet never leaves the client."""
        tx = make_agent_activity_log_tx(
            wallet=wallet, agent_id=agent_id, action_type=action_type,
            input_hash=input_hash, output_hash=output_hash,
            evidence_hash=evidence_hash, evidence_url=evidence_url,
            success=success, duration_ms=duration_ms, tags=list(tags or []),
            platform=platform, external_ref=external_ref, note=note,
            stake_locked=stake_locked,
        )
        return self._submit_tx(tx)

    def attest_log(self, wallet: Dict, log_id: str,
                   sentiment: str = "positive", note: str = "") -> Dict:
        """Attest to a specific activity log. Any counterparty can call this."""
        tx = make_agent_attest_tx(wallet, log_id=log_id, sentiment=sentiment, note=note)
        return self._submit_tx(tx)

    def challenge_log(self, wallet: Dict, log_id: str,
                      stake_locked: float = 10.0, reason: str = "") -> Dict:
        """Challenge a specific activity log. Locks stake — fake logs are expensive."""
        tx = make_agent_challenge_tx(wallet, log_id=log_id,
                                     stake_locked=stake_locked, reason=reason)
        return self._submit_tx(tx)

    def passport(self, address: str) -> Dict:
        """Fetch the portable trust passport for an agent address."""
        return self._get(f"/public/agent/passport?address={address}")

    def rules(self) -> Dict:
        """Fetch live chain-state trust rules and full parameter change history."""
        return self._get("/public/agent/rules")

    def get_log(self, log_id: str) -> Dict:
        """Permanent log lookup by log_id — survives block pruning."""
        return self._get(f"/public/agent/log?log_id={log_id}")

    def propose_param_change(
        self, wallet: Dict, changes: Dict, reason: str = "", vote_window_blocks: int = 100
    ) -> Dict:
        """
        Governance step 1: propose a change to agent trust parameters.
        Requires a second validator to call endorse_param_change() before it takes effect.
        """
        tx = make_agent_param_propose_tx(
            wallet, changes=changes, reason=reason, vote_window_blocks=vote_window_blocks
        )
        return self._submit_tx(tx)

    def endorse_param_change(self, wallet: Dict, proposal_id: str, approve: bool = True) -> Dict:
        """
        Governance step 2: endorse or reject a pending param proposal.
        When yes_count >= param_update_min_endorsements the changes apply immediately.
        """
        tx = make_agent_param_endorse_tx(wallet, proposal_id=proposal_id, approve=approve)
        return self._submit_tx(tx)

    def leaderboard(self, tag: str = "", platform: str = "", limit: int = 20) -> List[Dict]:
        """Fetch top agents by trust_score with full raw counters."""
        params = [f"limit={min(limit, 100)}"]
        if tag:
            params.append(f"tag={tag}")
        if platform:
            params.append(f"platform={platform}")
        return self._get(f"/public/agent/leaderboard?{'&'.join(params)}").get("leaderboard", [])

    def discover(
        self,
        tags: List[str] = None,
        min_score: float = 0.0,
        min_tier: str = "",
        platform: str = "",
        limit: int = 20,
        exclude: List[str] = None,
    ) -> List[Dict]:
        """Discover agents by capability tags, min trust score, or tier."""
        params = [f"limit={min(limit, 100)}"]
        if tags:
            params.append(f"tags={','.join(tags)}")
        if min_score > 0:
            params.append(f"min_score={min_score}")
        if min_tier:
            params.append(f"min_tier={min_tier}")
        if platform:
            params.append(f"platform={platform}")
        if exclude:
            params.append(f"exclude={','.join(exclude)}")
        return self._get(f"/public/agent/discover?{'&'.join(params)}").get("agents", [])

    def passport_by_agent_id(self, agent_id: str, verbose: bool = False) -> Dict:
        """Fetch trust passport by agent_id string (resolves to owner wallet)."""
        qs = f"agent_id={agent_id}"
        if verbose:
            qs += "&verbose=true"
        return self._get(f"/public/agent/passport?{qs}")

    def agent_logs(self, address: str = "", platform: str = "",
                   action_type: str = "", limit: int = 50) -> List[Dict]:
        """Fetch activity logs, optionally filtered."""
        params = []
        if address:
            params.append(f"address={address}")
        if platform:
            params.append(f"platform={platform}")
        if action_type:
            params.append(f"action_type={action_type}")
        params.append(f"limit={limit}")
        return self._get(f"/public/agent/logs?{'&'.join(params)}").get("logs", [])

    def get_agent(self, agent_id: str) -> Optional[Dict]:
        try:
            return self._get(f"/agents/{agent_id}")
        except RuntimeError:
            return None

    # ── Tasks ─────────────────────────────────────────────────────────────
    def get_open_tasks(self, agent_id: str = None) -> List[Dict]:
        path = "/tasks?status=open"
        if agent_id:
            path += f"&agent_id={agent_id}"
        return self._get(path).get("tasks", [])

    def complete_task(self, wallet: Dict, task_id: str,
                      result_hash: str, note: str = "") -> Dict:
        tx = make_task_complete_tx(wallet, task_id=task_id,
                                    result_hash=result_hash, note=note)
        return self._submit_tx(tx)

    def get_task(self, task_id: str) -> Optional[Dict]:
        try:
            return self._get(f"/tasks/{task_id}")
        except RuntimeError:
            return None

    # ── Models ────────────────────────────────────────────────────────────
    def register_model(self, wallet: Dict, model_id: str, name: str,
                        description: str = "", capabilities: List[str] = None,
                        version_hash: str = "", inference_fee: float = 0.0) -> Dict:
        tx = make_model_register_tx(wallet, model_id=model_id, name=name,
                                     description=description,
                                     capabilities=capabilities or [],
                                     version_hash=version_hash,
                                     inference_fee=inference_fee)
        return self._submit_tx(tx)

    def record_inference(self, wallet: Dict, model_id: str,
                          input_hash: str = "", output_hash: str = "") -> Dict:
        tx = make_model_inference_tx(wallet, model_id=model_id,
                                      input_hash=input_hash, output_hash=output_hash)
        return self._submit_tx(tx)

    def get_models(self, owner: str = None) -> List[Dict]:
        path = "/models"
        if owner:
            path += f"?owner={owner}"
        return self._get(path).get("models", [])

    # ── Pipelines ─────────────────────────────────────────────────────────
    def get_active_pipelines(self) -> List[Dict]:
        return self._get("/pipelines?status=active").get("pipelines", [])

    def complete_pipeline_step(self, wallet: Dict, pipeline_id: str,
                                step_index: int, result_hash: str, note: str = "") -> Dict:
        tx = make_pipeline_step_complete_tx(wallet, pipeline_id=pipeline_id,
                                             step_index=step_index,
                                             result_hash=result_hash, note=note)
        return self._submit_tx(tx)

    # ── Governance ────────────────────────────────────────────────────────
    def get_proposals(self) -> List[Dict]:
        return self._get("/governance/proposals").get("proposals", [])

    def vote(self, wallet: Dict, proposal_id: str, vote: bool) -> Dict:
        tx = make_governance_vote_tx(wallet, proposal_id=proposal_id, vote=vote)
        return self._submit_tx(tx)
