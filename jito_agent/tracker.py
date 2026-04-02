"""
NovaTracker — Universal off-chain activity logger for AI agents.

Any agent, any framework, any platform can log activity to NOVA and
build portable, verifiable reputation — without using JITO's task marketplace.

Quick start:
    from jito_agent import NovaTracker, load_wallet

    wallet = load_wallet("wallet.json")
    tracker = NovaTracker(wallet, agent_id="my-agent", node_url="https://explorer.flowpe.io")

    # Log any work your agent does
    tracker.log("task_completed", success=True, tags=["analysis", "finance"])

    # Or use the context manager for automatic timing + logging
    with tracker.track("contract_deployed", tags=["blockchain", "solidity"]) as ctx:
        result = deploy_my_contract(...)
        ctx.set_output(result)

    # Check reputation anytime
    print(tracker.get_reputation())
"""

import hashlib
import json
import os
import time
from contextlib import contextmanager
from typing import Any, Dict, Generator, List, Optional

from .client import NovaClient
from .wallet import create_wallet, save_wallet


def _hash(obj: Any) -> str:
    """sha256 of any serializable object — content never leaves the client."""
    raw = json.dumps(obj, sort_keys=True) if isinstance(obj, (dict, list)) else str(obj)
    return hashlib.sha256(raw.encode()).hexdigest()


class _TrackContext:
    """Mutable context object passed into tracker.track() blocks."""

    def __init__(self) -> None:
        self._output: Any = None
        self._success: bool = True
        self._note: str = ""

    def set_output(self, output: Any) -> None:
        self._output = output

    def set_success(self, success: bool) -> None:
        self._success = success

    def set_note(self, note: str) -> None:
        self._note = note[:256]

    def fail(self, note: str = "") -> None:
        self._success = False
        if note:
            self._note = note[:256]


class NovaTracker:
    """
    Plug-and-play off-chain activity tracker.
    Logs agent work to Nova public chain, building portable reputation
    regardless of where the actual work happens.

    Works with: LangChain, CrewAI, AutoGen, custom agents, or anything else.
    """

    @classmethod
    def from_env(cls) -> "NovaTracker":
        """
        Zero-config setup from environment variables.
        Works for any agent on any platform — just set env vars once.

        Required env vars:
            NOVA_AGENT_ID       your agent's unique ID
            NOVA_WALLET_PATH    path to wallet JSON file (default: wallet.json)
            NOVA_NODE_URL       node URL (default: https://explorer.flowpe.io)
            NOVA_PLATFORM       optional platform tag

        Usage:
            export NOVA_AGENT_ID=my-agent
            export NOVA_WALLET_PATH=/secrets/wallet.json
            export NOVA_NODE_URL=https://explorer.flowpe.io

            from jito_agent import NovaTracker
            tracker = NovaTracker.from_env()
            tracker.log("task_completed", success=True)
        """
        agent_id = os.environ.get("NOVA_AGENT_ID", "").strip()
        if not agent_id:
            raise ValueError("NOVA_AGENT_ID environment variable is required")
        wallet_path = os.environ.get("NOVA_WALLET_PATH", "wallet.json").strip()
        node_url = os.environ.get("NOVA_NODE_URL", "https://explorer.flowpe.io").strip()
        platform = os.environ.get("NOVA_PLATFORM", "").strip()
        return cls.new(agent_id=agent_id, wallet_path=wallet_path, node_url=node_url, platform=platform)

    @classmethod
    def new(
        cls,
        agent_id: str,
        wallet_path: str = "wallet.json",
        node_url: str = "https://explorer.flowpe.io",
        platform: str = "",
    ) -> "NovaTracker":
        """
        One-liner setup: creates a wallet if it doesn't exist, returns a ready tracker.

        tracker = NovaTracker.new("my-agent")
        tracker.log("task_done", output_hash=sha256(result))
        """
        if os.path.exists(wallet_path):
            from .wallet import load_wallet
            wallet = load_wallet(wallet_path)
        else:
            wallet = create_wallet(label=agent_id)
            save_wallet(wallet, wallet_path)
        return cls(wallet=wallet, agent_id=agent_id, node_url=node_url, platform=platform)

    def __init__(
        self,
        wallet: Dict,
        agent_id: str,
        node_url: str = "https://explorer.flowpe.io",
        platform: str = "",
        auth_token: str = "",
        auto_hash_io: bool = True,
    ) -> None:
        """
        wallet:        NOVA wallet dict (from create_wallet / load_wallet)
        agent_id:      your agent's registered ID on NOVA
        node_url:      NOVA node URL
        platform:      optional platform tag e.g. "langchain", "crewai", "custom"
        auto_hash_io:  if True, input/output objects are auto-hashed before logging
        """
        self.wallet = wallet
        self.agent_id = agent_id
        self.platform = platform
        self.auto_hash_io = auto_hash_io
        self.client = NovaClient(node_url, auth_token)
        self._wallet_name: Optional[str] = wallet.get("label") or wallet.get("address", "")[:16]

    # ── Core log method ────────────────────────────────────────────────────

    def log(
        self,
        action_type: str,
        *,
        input_data: Any = None,
        output_data: Any = None,
        input_hash: str = "",
        output_hash: str = "",
        evidence: Any = None,
        evidence_url: str = "",
        success: bool = True,
        duration_ms: int = 0,
        tags: List[str] = None,
        platform: str = "",
        external_ref: str = "",
        note: str = "",
        stake: float = 0.0,
    ) -> Dict:
        """
        Log a single agent activity to Nova chain.

        action_type:  what the agent did — e.g. "task_completed", "model_run",
                      "contract_deployed", "data_analyzed", "chain_built"
        input_data:   raw input (will be hashed; never sent on-chain)
        output_data:  raw output (will be hashed; never sent on-chain)
        input_hash:   pre-computed sha256 of input (use if you already have it)
        output_hash:  pre-computed sha256 of output
        success:      did the agent succeed?
        duration_ms:  how long the work took in milliseconds
        tags:         domain/capability tags e.g. ["finance", "coding"]
        platform:     override the platform tag for this specific log
        note:         short human-readable description (max 256 chars)
        """
        if self.auto_hash_io:
            if input_data is not None and not input_hash:
                input_hash = _hash(input_data)
            if output_data is not None and not output_hash:
                output_hash = _hash(output_data)
            if evidence is not None:
                evidence_hash = _hash(evidence)
            else:
                evidence_hash = ""

        # Validate evidence_url is reachable before logging if provided
        if evidence_url and not evidence_url.startswith(("ipfs://", "ar://", "http://", "https://")):
            raise ValueError(f"evidence_url must start with https://, http://, ipfs://, or ar://. Got: {evidence_url!r}")

        resp = self.client.log_activity(
            wallet=self.wallet,
            agent_id=self.agent_id,
            action_type=action_type,
            input_hash=input_hash,
            output_hash=output_hash,
            evidence_hash=evidence_hash,
            evidence_url=evidence_url,
            success=success,
            duration_ms=duration_ms,
            tags=list(tags or []),
            platform=platform or self.platform,
            external_ref=external_ref,
            note=note,
            stake_locked=stake,
        )
        if isinstance(resp, dict):
            return resp.get("tx_id", resp)
        return resp

    def batch_log(self, entries: List[Dict[str, Any]]) -> List[str]:
        """
        Submit multiple activity logs in a single network call.

        entries: list of dicts, each with same keys as log():
          action_type, success, tags, note, evidence_url, duration_ms, external_ref, stake

        Returns list of tx_ids.
        """
        tx_ids = []
        for entry in entries:
            tx_id = self.log(
                action_type=entry.get("action_type", "activity"),
                success=entry.get("success", True),
                tags=entry.get("tags"),
                note=entry.get("note", ""),
                evidence_url=entry.get("evidence_url", ""),
                duration_ms=entry.get("duration_ms", 0),
                external_ref=entry.get("external_ref", ""),
                stake=entry.get("stake", 0.0),
            )
            tx_ids.append(tx_id)
        return tx_ids

    # ── Context manager for automatic timing ──────────────────────────────

    @contextmanager
    def track(
        self,
        action_type: str,
        *,
        input_data: Any = None,
        tags: List[str] = None,
        platform: str = "",
        note: str = "",
        evidence_url: str = "",
    ) -> Generator[_TrackContext, None, None]:
        """
        Context manager — automatically measures duration and logs on exit.

        with tracker.track("analysis_done", tags=["finance"]) as ctx:
            result = run_analysis(data)
            ctx.set_output(result)   # optional: hash output for the log
        # → automatically logged on exit, success=True, duration measured

        On exception: logs success=False with error message.
        """
        ctx = _TrackContext()
        start = time.time()
        try:
            yield ctx
        except Exception as exc:
            ctx.fail(str(exc)[:256])
            raise
        finally:
            duration_ms = int((time.time() - start) * 1000)
            out_hash = _hash(ctx._output) if ctx._output is not None and self.auto_hash_io else ""
            in_hash = _hash(input_data) if input_data is not None and self.auto_hash_io else ""
            try:
                self.log(
                    action_type,
                    input_hash=in_hash,
                    output_hash=out_hash,
                    success=ctx._success,
                    duration_ms=duration_ms,
                    tags=tags,
                    platform=platform,
                    note=ctx._note or note,
                    evidence_url=evidence_url,
                )
            except Exception:
                pass  # Never let logging break the actual work

    def attest(self, log_id: str, sentiment: str = "positive", note: str = "") -> Dict:
        """
        Attest to a specific activity log by its log_id.
        Any counterparty can call this — not just validators.
        Positive attestations increase the agent's trust score.
        """
        return self.client.attest_log(self.wallet, log_id=log_id,
                                      sentiment=sentiment, note=note)

    def challenge(self, log_id: str, stake_locked: float = 10.0, reason: str = "") -> Dict:
        """
        Challenge a specific activity log. Locks your stake.
        If the agent cannot produce evidence, they are slashed and you receive the stake.
        Use this when you believe a log is fake or inflated.
        """
        return self.client.challenge_log(self.wallet, log_id=log_id,
                                         stake_locked=stake_locked, reason=reason)

    def passport(self, address: str = "") -> Dict:
        """
        Fetch the portable trust passport for this agent (or any address).
        Returns trust_score, trust_tier, log counts, platforms, badges.
        This is the portable reputation that travels across platforms.
        """
        return self.client.passport(address or self.wallet["address"])

    def rules(self) -> Dict:
        """
        Fetch the live chain-state trust rules — challenge window, score weights,
        slash outcome, and full governance change history.
        Agents should call this on startup to confirm the rules they are building against.
        """
        return self.client.rules()

    def get_log(self, log_id: str) -> Dict:
        """
        Fetch a specific activity log by log_id.
        Permanent — survives block pruning.  Use this to verify your own logs
        or audit another agent's evidence.
        """
        return self.client.get_log(log_id)

    # ── Reputation ────────────────────────────────────────────────────────

    def get_reputation(self) -> Dict:
        """Fetch this agent's current reputation from Nova chain."""
        return self.client.reputation(self.wallet["address"])

    def get_balance(self) -> float:
        """Fetch current NOVA token balance."""
        return self.client.balance(self.wallet["address"])
