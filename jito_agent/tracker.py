"""
NovaTracker — Universal off-chain activity logger for AI agents.

Any agent, any framework, any platform can log activity to NOVA and
build portable, verifiable reputation — without using Nova's task marketplace.

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
import logging
import os
import time
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, Callable, Dict, Generator, List, Optional

logger = logging.getLogger(__name__)

from .client import NovaClient
from .self_description import SelfDescription, derive_self_description
from .session import SessionContext
from .wallet import create_wallet, save_wallet

if TYPE_CHECKING:
    from .evidence import EvidenceStore


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
        self._tool_calls: int = 0
        self._significant: bool = False

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

    def add_tool_call(self, count: int = 1) -> None:
        """Increment the tool-call counter for this session."""
        self._tool_calls += count

    def mark_significant(self) -> None:
        """
        Explicitly mark this session as worth logging, bypassing any
        duration / tool-call thresholds set on the tracker.
        """
        self._significant = True


class NovaTracker:
    """
    Plug-and-play off-chain activity tracker.
    Logs agent work to Nova public chain, building portable reputation
    regardless of where the actual work happens.

    Works with: LangChain, CrewAI, AutoGen, custom agents, or anything else.
    """

    @classmethod
    def from_env(cls, system_prompt: str = "") -> "NovaTracker":
        """
        Zero-config setup from environment variables.
        Works for any agent on any platform — just set env vars once.

        Required env vars:
            NOVA_AGENT_ID       your agent's unique ID
            NOVA_WALLET_PATH    path to wallet JSON file (default: wallet.json)
            NOVA_NODE_URL       node URL (default: https://explorer.flowpe.io)
            NOVA_PLATFORM       optional platform tag

        Optional:
            system_prompt:  Pass the agent's system prompt and self-description
                            (capabilities, task_types, refusals) will be derived
                            automatically and stored on the tracker.

        Usage:
            export NOVA_AGENT_ID=my-agent
            export NOVA_WALLET_PATH=/secrets/wallet.json
            export NOVA_NODE_URL=https://explorer.flowpe.io

            from jito_agent import NovaTracker
            tracker = NovaTracker.from_env(system_prompt=MY_SYSTEM_PROMPT)
            tracker.log("task_completed", success=True)
        """
        agent_id = os.environ.get("NOVA_AGENT_ID", "").strip()
        if not agent_id:
            raise ValueError("NOVA_AGENT_ID environment variable is required")
        wallet_path = os.environ.get("NOVA_WALLET_PATH", "wallet.json").strip()
        node_url = os.environ.get("NOVA_NODE_URL", "https://explorer.flowpe.io").strip()
        platform = os.environ.get("NOVA_PLATFORM", "").strip()
        min_duration_s = int(os.environ.get("NOVA_MIN_DURATION_S", "0"))
        min_tool_calls = int(os.environ.get("NOVA_MIN_TOOL_CALLS", "0"))
        return cls.new(
            agent_id=agent_id,
            wallet_path=wallet_path,
            node_url=node_url,
            platform=platform,
            min_duration_s=min_duration_s,
            min_tool_calls=min_tool_calls,
            system_prompt=system_prompt,
        )

    @classmethod
    def new(
        cls,
        agent_id: str,
        wallet_path: str = "wallet.json",
        node_url: str = "https://explorer.flowpe.io",
        platform: str = "",
        min_duration_s: int = 0,
        min_tool_calls: int = 0,
        evidence_store: Optional["EvidenceStore"] = None,
        system_prompt: str = "",
        llm_fn: Optional[Callable] = None,
    ) -> "NovaTracker":
        """
        One-liner setup: creates a wallet if it doesn't exist, returns a ready tracker.

        tracker = NovaTracker.new("my-agent", min_duration_s=30, min_tool_calls=3)
        tracker.log("task_done", output_hash=sha256(result))

        Pass system_prompt to automatically derive the agent's self-description:
            tracker = NovaTracker.new("my-agent", system_prompt=MY_SYSTEM_PROMPT)
            print(tracker.self_description.capabilities)

        Pass an evidence_store to automatically save and attach outputs:
            from jito_agent import LocalEvidenceStore
            tracker = NovaTracker.new("my-agent", evidence_store=LocalEvidenceStore())
        """
        if os.path.exists(wallet_path):
            from .wallet import load_wallet
            wallet = load_wallet(wallet_path)
        else:
            wallet = create_wallet(label=agent_id)
            save_wallet(wallet, wallet_path)
        return cls(
            wallet=wallet,
            agent_id=agent_id,
            node_url=node_url,
            platform=platform,
            min_duration_s=min_duration_s,
            min_tool_calls=min_tool_calls,
            evidence_store=evidence_store,
            system_prompt=system_prompt,
            llm_fn=llm_fn,
        )

    def __init__(
        self,
        wallet: Dict,
        agent_id: str,
        node_url: str = "https://explorer.flowpe.io",
        platform: str = "",
        auth_token: str = "",
        auto_hash_io: bool = True,
        min_duration_s: int = 0,
        min_tool_calls: int = 0,
        evidence_store: Optional["EvidenceStore"] = None,
        system_prompt: str = "",
        llm_fn: Optional[Callable] = None,
    ) -> None:
        """
        wallet:          NOVA wallet dict (from create_wallet / load_wallet)
        agent_id:        your agent's registered ID on NOVA
        node_url:        NOVA node URL
        platform:        optional platform tag e.g. "langchain", "crewai", "custom"
        auto_hash_io:    if True, input/output objects are auto-hashed before logging
        min_duration_s:  only log sessions that ran for at least this many seconds
                         (0 = no duration threshold)
        min_tool_calls:  only log sessions that made at least this many tool calls
                         (0 = no tool-call threshold)
        evidence_store:  optional EvidenceStore (LocalEvidenceStore / IpfsEvidenceStore).
                         When set, ctx.set_output() outputs are automatically saved and
                         the resulting evidence_url is attached to every on-chain log.
        system_prompt:   the agent's system prompt — if supplied, capabilities,
                         task_types, and refusals are derived automatically and
                         stored on self.self_description.  The raw prompt never
                         leaves the client.
        llm_fn:          optional callable (prompt: str) -> str for LLM-assisted
                         extraction.  Omit for heuristic mode.

        Threshold logic (inside tracker.track()):
          Log if ANY of the following is true:
            - ctx.mark_significant() was called                  (agent override)
            - session duration >= min_duration_s  (when min_duration_s > 0)
            - ctx._tool_calls   >= min_tool_calls (when min_tool_calls  > 0)
          If no thresholds are set (both 0), every session is logged — same as
          the previous behaviour.
        """
        self.wallet = wallet
        self.agent_id = agent_id
        self.platform = platform
        self.auto_hash_io = auto_hash_io
        self.min_duration_s = min_duration_s
        self.min_tool_calls = min_tool_calls
        self.evidence_store = evidence_store
        self.client = NovaClient(node_url, auth_token)
        self._wallet_name: Optional[str] = wallet.get("label") or wallet.get("address", "")[:16]

        # Self-description: derived from system prompt if provided
        if system_prompt:
            self.self_description: Optional[SelfDescription] = derive_self_description(
                system_prompt, llm_fn=llm_fn
            )
        else:
            self.self_description = None

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
        save_evidence: bool = False,
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

        action_type:    what the agent did — e.g. "task_completed", "model_run",
                        "contract_deployed", "data_analyzed", "chain_built"
        input_data:     raw input (will be hashed; never sent on-chain)
        output_data:    raw output (will be hashed; never sent on-chain)
        input_hash:     pre-computed sha256 of input (use if you already have it)
        output_hash:    pre-computed sha256 of output
        save_evidence:  if True and an evidence_store is configured, persist output_data
                        and attach the returned URL as evidence_url automatically.
        success:        did the agent succeed?
        duration_ms:    how long the work took in milliseconds
        tags:           domain/capability tags e.g. ["finance", "coding"]
        platform:       override the platform tag for this specific log
        note:           short human-readable description (max 256 chars)
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

        # Save output to evidence store if requested and not already provided
        if save_evidence and output_data is not None and not evidence_url and self.evidence_store is not None:
            try:
                out_h = output_hash or _hash(output_data)
                evidence_url = self.evidence_store.save(
                    output_data,
                    out_h,
                    {"agent_id": self.agent_id, "action_type": action_type},
                )
                output_hash = out_h  # ensure hash is set
            except Exception:
                logger.warning("Evidence saving failed (best-effort)", exc_info=True)

        # Validate evidence_url scheme before logging
        _VALID_SCHEMES = ("ipfs://", "ar://", "http://", "https://", "file://")
        if evidence_url and not evidence_url.startswith(_VALID_SCHEMES):
            raise ValueError(
                f"evidence_url must start with one of {_VALID_SCHEMES}. Got: {evidence_url!r}"
            )

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

            # ── Selective logging threshold check ─────────────────────────
            # Each configured threshold (> 0) is a separate criterion.
            # We log if ANY criterion is met, or if the agent explicitly
            # called ctx.mark_significant().  When no thresholds are
            # configured (both 0) the behaviour is identical to before.
            thresholds_active = self.min_duration_s > 0 or self.min_tool_calls > 0
            duration_passes = self.min_duration_s > 0 and duration_ms >= self.min_duration_s * 1000
            tools_passes    = self.min_tool_calls > 0 and ctx._tool_calls >= self.min_tool_calls
            should_log = ctx._significant or not thresholds_active or duration_passes or tools_passes

            if should_log:
                out_hash = _hash(ctx._output) if ctx._output is not None and self.auto_hash_io else ""
                in_hash = _hash(input_data) if input_data is not None and self.auto_hash_io else ""

                # ── Evidence attachment ───────────────────────────────────────
                # If an evidence_store is configured and the agent set an output,
                # save it and attach the returned URL to the log automatically.
                final_evidence_url = evidence_url
                if ctx._output is not None and self.evidence_store is not None and not evidence_url:
                    try:
                        final_evidence_url = self.evidence_store.save(
                            ctx._output,
                            out_hash,
                            {"agent_id": self.agent_id, "action_type": action_type},
                        )
                    except Exception:
                        logger.warning("Evidence saving failed in track() (best-effort)", exc_info=True)

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
                        evidence_url=final_evidence_url,
                    )
                except Exception:
                    logger.warning("Activity log submission failed in track()", exc_info=True)

    # ── Session Intelligence ───────────────────────────────────────────────

    @contextmanager
    def session(
        self,
        task: str,
        *,
        tags: List[str] = None,
        platform: str = "",
        evidence_url: str = "",
    ) -> Generator[SessionContext, None, None]:
        """
        Context manager for full session intelligence logging.

        Captures what actually happened — not just timing and exit status:
          - What task was attempted (the task argument)
          - What tools were used (ctx.record_tool(), or auto via NovaSessionCallbackHandler)
          - What the output was (hashed client-side via ctx.set_output())
          - Whether the agent thinks it succeeded *meaningfully* (ctx.assess())

        If assess() is never called and no exception is raised -> defaults to "success".
        On unhandled exception -> assessment is set to "failure" automatically.

        Example (manual agent):
            with tracker.session("Analyze Q3 revenue, flag anomalies") as ctx:
                ctx.record_tool("sql_query")
                result = run_analysis(data)
                ctx.set_output(result)
                ctx.assess("success", "3 anomalies found, confidence 0.94")

        Example (LangChain -- automatic via NovaSessionCallbackHandler):
            handler = NovaSessionCallbackHandler(tracker, task="Analyze Q3 revenue")
            agent.invoke(input, config={"callbacks": [handler]})
        """
        ctx = SessionContext(task)
        start = time.time()
        try:
            yield ctx
        except Exception as exc:
            # Only override if the agent did not already call assess()
            if ctx._assessment == "success" and not ctx._assessment_reason:
                ctx._assessment = "failure"
                ctx._assessment_reason = str(exc)[:512]
            raise
        finally:
            duration_ms = int((time.time() - start) * 1000)
            evidence = ctx._to_evidence()
            output_hash = _hash(ctx._output) if ctx._output is not None else ""
            try:
                self.log(
                    "session_complete",
                    input_data={"task": task},
                    output_hash=output_hash,
                    evidence=evidence,
                    evidence_url=evidence_url,
                    success=ctx.meaningful_success,
                    duration_ms=duration_ms,
                    tags=list(tags or []) + ["session"],
                    platform=platform or self.platform,
                    note=ctx._note_for_log(),
                )
            except Exception:
                logger.warning("Session log submission failed", exc_info=True)

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

    def request_corroboration(self, log_id: str, peer_addresses: List[str]) -> Dict:
        """
        Log a corroboration_request event so peer agents know to attest this session.

        log_id:          tx_id / log_id of the session_complete log to be corroborated
        peer_addresses:  on-chain addresses of the agents being asked to corroborate;
                         included in the note so peers can filter the event stream

        Returns the tx_id of the corroboration_request log.

        Typical flow:
            log_id = tracker.log("session_complete", ...)
            tracker.request_corroboration(log_id, peer_addresses=["0xabc...", "0xdef..."])

            # Peer agent, on seeing the request:
            peer_tracker.corroborate(log_id, agrees=True, note="output matches our data")
        """
        note = f"peers={','.join(peer_addresses)}"[:256] if peer_addresses else ""
        return self.log(
            "corroboration_request",
            external_ref=log_id,
            tags=["corroboration"],
            note=note,
        )

    def corroborate(self, log_id: str, agrees: bool, note: str = "") -> Dict:
        """
        Another agent's verdict on a session_complete log.

        log_id:  tx_id / log_id of the session_complete log being assessed
        agrees:  True  → positive attestation (peer confirms the outcome)
                 False → negative attestation (peer disputes the outcome)
        note:    optional explanation, max 256 chars

        This is a thin wrapper around attest() that frames the semantics clearly:
        corroborate() is for session-level cross-verification, attest() is the
        general-purpose endorsement primitive.

        Returns the tx_id of the attestation transaction.
        """
        return self.attest(log_id, sentiment="positive" if agrees else "negative", note=note)

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
