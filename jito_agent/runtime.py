"""Frictionless local runtime for auto-capture, local policy, and background sync."""

import os
import time
import uuid
from contextlib import contextmanager
from typing import Any, Dict, Generator, List, Optional

from .callbacks import NovaSessionCallbackHandler
from .light_client import NovaLightClientNode
from .policy import AutoLogPolicy, PolicyDecision
from .session import SessionContext
from .tracker import NovaTracker, _hash


class RuntimeSession:
    """Mutable session observed by the runtime before local policy decides whether to submit."""

    def __init__(
        self,
        runtime: "NovaRuntime",
        task: str,
        *,
        tags: Optional[List[str]] = None,
        platform: str = "",
        external_ref: str = "",
    ) -> None:
        self.runtime = runtime
        self.task = task
        self.tags = list(tags or [])
        self.platform = platform or runtime.tracker.platform
        self.external_ref = external_ref
        self.context = SessionContext(task)
        self.started_at = time.time()
        self.confidence: Optional[float] = None
        self.artifacts: List[Dict[str, Any]] = []
        self.collaborators: List[str] = []
        self.side_effects: List[str] = []
        self.force_log = False
        self.suppress_log = False

    def record_tool(self, name: str, duration_ms: int = 0, success: bool = True) -> None:
        self.context.record_tool(name, duration_ms=duration_ms, success=success)

    def record_llm_call(self) -> None:
        self.context._record_llm_call()

    def set_output(self, output: Any) -> None:
        self.context.set_output(output)

    def assess(self, outcome: str, reason: str = "") -> None:
        self.context.assess(outcome, reason)

    def add_note(self, note: str) -> None:
        self.context.add_note(note)

    def set_confidence(self, value: float) -> None:
        self.confidence = max(0.0, min(1.0, float(value)))

    def add_collaborator(self, address: str) -> None:
        addr = str(address).strip()
        if addr and addr not in self.collaborators:
            self.collaborators.append(addr)

    def add_side_effect(self, description: str) -> None:
        desc = str(description).strip()
        if desc:
            self.side_effects.append(desc[:256])

    def add_artifact(
        self,
        output: Any = None,
        *,
        output_hash: str = "",
        evidence_url: str = "",
        artifact_type: str = "artifact",
        label: str = "",
    ) -> str:
        final_hash = str(output_hash or (_hash(output) if output is not None else "")).strip()
        artifact = {
            "type": str(artifact_type or "artifact")[:64],
            "label": str(label or artifact_type or "artifact")[:128],
            "output_hash": final_hash,
            "evidence_url": str(evidence_url or "")[:512],
        }
        self.artifacts.append(artifact)
        return final_hash

    def mark_significant(self) -> None:
        self.force_log = True

    def suppress(self) -> None:
        self.suppress_log = True

    def _evidence(self, decision: PolicyDecision) -> Dict[str, Any]:
        evidence = self.context._to_evidence()
        evidence["artifacts"] = list(self.artifacts)
        evidence["collaborators"] = list(self.collaborators)
        evidence["side_effects"] = list(self.side_effects)
        evidence["policy_reason"] = decision.reason
        evidence["score_hint"] = decision.score_hint
        if self.confidence is not None:
            evidence["confidence"] = self.confidence
        return evidence

    def finalize(self) -> Optional[str]:
        duration_ms = int((time.time() - self.started_at) * 1000)
        assessment = getattr(self.context, "_assessment", "success")
        decision = self.runtime.policy.evaluate({
            "duration_ms": duration_ms,
            "tools": list(self.context._tool_calls),
            "llm_calls": self.context._llm_calls,
            "success": self.context.meaningful_success,
            "assessment": assessment,
            "artifacts": self.artifacts,
            "collaborators": self.collaborators,
            "side_effects": self.side_effects,
            "confidence": self.confidence,
            "force_log": self.force_log,
            "suppress_log": self.suppress_log,
        })
        if not decision.should_log:
            return None

        evidence = self._evidence(decision)
        output_hash = _hash(self.context._output) if self.context._output is not None else ""
        note = self.context._note_for_log()
        tags = list(self.runtime.default_tags) + self.tags + decision.extra_tags + ["runtime"]
        payload = self.runtime._build_log_payload(
            action_type=decision.action_type,
            input_data={"task": self.task},
            output_hash=output_hash,
            evidence=evidence,
            success=self.context.meaningful_success,
            duration_ms=duration_ms,
            tags=tags,
            platform=self.platform,
            external_ref=self.external_ref,
            note=note,
        )
        return self.runtime.light_client.enqueue_log(payload)


class _RuntimeTrackerProxy:
    """Tracker-shaped object that queues logs through the runtime instead of posting immediately."""

    def __init__(self, runtime: "NovaRuntime", tags: Optional[List[str]] = None, platform: str = "") -> None:
        self.runtime = runtime
        self.default_tags = list(tags or [])
        self.platform = platform or runtime.tracker.platform

    def log(self, action_type: str, **kwargs: Any) -> str:
        tags = list(kwargs.pop("tags", []) or [])
        payload = self.runtime._build_log_payload(
            action_type=action_type,
            platform=kwargs.pop("platform", "") or self.platform,
            tags=self.default_tags + tags,
            **kwargs,
        )
        return self.runtime.light_client.enqueue_log(payload)


class NovaRuntime:
    """Frictionless runtime that auto-captures sessions and flushes them in the background."""

    def __init__(
        self,
        tracker: NovaTracker,
        *,
        policy: Optional[AutoLogPolicy] = None,
        queue_path: str = ".nova_runtime_queue.json",
        cache_path: str = ".nova_light_cache.json",
        flush_interval_s: float = 5.0,
        auto_start: bool = True,
        default_tags: Optional[List[str]] = None,
    ) -> None:
        self.tracker = tracker
        self.policy = policy or AutoLogPolicy()
        self.default_tags = list(default_tags or [])
        self.light_client = NovaLightClientNode(
            tracker,
            queue_path=queue_path,
            cache_path=cache_path,
            flush_interval_s=flush_interval_s,
        )
        if auto_start:
            self.light_client.start()

    @classmethod
    def auto(
        cls,
        agent_id: str = "",
        *,
        wallet_path: str = "",
        node_url: str = "",
        queue_path: str = "",
        cache_path: str = "",
        flush_interval_s: float = 5.0,
        default_tags: Optional[List[str]] = None,
    ) -> "NovaRuntime":
        tracker = NovaTracker.new(
            agent_id=agent_id or os.environ.get("NOVA_AGENT_ID", "").strip(),
            wallet_path=wallet_path or os.environ.get("NOVA_WALLET_PATH", "wallet.json").strip(),
            node_url=node_url or os.environ.get("NOVA_NODE_URL", "https://explorer.flowpe.io").strip(),
            platform=os.environ.get("NOVA_PLATFORM", "").strip(),
        )
        return cls(
            tracker,
            queue_path=queue_path or os.environ.get("NOVA_RUNTIME_QUEUE_PATH", ".nova_runtime_queue.json"),
            cache_path=cache_path or os.environ.get("NOVA_LIGHT_CACHE_PATH", ".nova_light_cache.json"),
            flush_interval_s=flush_interval_s,
            default_tags=default_tags,
        )

    @classmethod
    def from_env(cls, **kwargs: Any) -> "NovaRuntime":
        return cls.auto(**kwargs)

    def stop(self) -> None:
        self.light_client.stop()

    def flush(self) -> Dict[str, int]:
        return self.light_client.flush()

    def status(self) -> Dict[str, Any]:
        return self.light_client.status()

    def _build_log_payload(
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
        tags: Optional[List[str]] = None,
        platform: str = "",
        external_ref: str = "",
        note: str = "",
        stake_locked: float = 0.0,
    ) -> Dict[str, Any]:
        if self.tracker.auto_hash_io:
            if input_data is not None and not input_hash:
                input_hash = _hash(input_data)
            if output_data is not None and not output_hash:
                output_hash = _hash(output_data)
            evidence_hash = _hash(evidence) if evidence is not None else ""
        else:
            evidence_hash = ""
        return {
            "action_type": str(action_type).strip(),
            "input_hash": str(input_hash or ""),
            "output_hash": str(output_hash or ""),
            "evidence_hash": str(evidence_hash or ""),
            "evidence_url": str(evidence_url or ""),
            "success": bool(success),
            "duration_ms": int(duration_ms),
            "tags": list(tags or []),
            "platform": str(platform or self.tracker.platform),
            "external_ref": str(external_ref or ""),
            "note": str(note or "")[:256],
            "stake_locked": float(stake_locked),
        }

    def log(self, action_type: str, **kwargs: Any) -> str:
        payload = self._build_log_payload(action_type, tags=self.default_tags + list(kwargs.pop("tags", []) or []), **kwargs)
        return self.light_client.enqueue_log(payload)

    def post_intent(
        self,
        intent: str,
        *,
        role: str = "",
        tags: Optional[List[str]] = None,
        collaborators: Optional[List[str]] = None,
    ) -> str:
        note = str(intent or "").strip()[:256]
        evidence = {
            "intent": str(intent or "").strip(),
            "role": str(role or "").strip(),
            "collaborators": list(collaborators or []),
        }
        native_intent_id = ""
        try:
            response = self.tracker.client.post_intent(
                self.tracker.wallet,
                agent_id=self.tracker.agent_id,
                intent=intent,
                role=role,
                capability_tags=list(tags or []),
                desired_collaborators=list(collaborators or []),
                note=note,
            )
            if isinstance(response, dict):
                native_intent_id = str(response.get("intent_id", "")).strip()
        except Exception:
            native_intent_id = ""

        log_id = self.log(
            "intent_posted",
            input_data={"intent": intent, "role": role},
            evidence=evidence,
            tags=list(tags or []) + ["intent"],
            external_ref=f"intent:{native_intent_id}" if native_intent_id else "",
            note=note,
        )
        return native_intent_id or log_id

    @contextmanager
    def session(
        self,
        task: str,
        *,
        tags: Optional[List[str]] = None,
        platform: str = "",
        external_ref: str = "",
    ) -> Generator[RuntimeSession, None, None]:
        session = RuntimeSession(self, task, tags=tags, platform=platform, external_ref=external_ref)
        try:
            yield session
        except Exception as exc:
            if session.context._assessment == "success" and not session.context._assessment_reason:
                session.context.assess("failure", str(exc)[:512])
            raise
        finally:
            session.finalize()

    @contextmanager
    def collab_session(
        self,
        intent: str,
        *,
        role: str = "",
        participants: Optional[List[str]] = None,
        session_id: str = "",
        tags: Optional[List[str]] = None,
        platform: str = "",
    ) -> Generator[RuntimeSession, None, None]:
        collab_id = session_id.strip() or f"collab:{uuid.uuid4().hex[:16]}"
        native_opened = False
        try:
            response = self.tracker.client.open_session(
                self.tracker.wallet,
                session_id=collab_id,
                objective=intent,
                participants=list(participants or []),
                note=role,
            )
            native_opened = bool(isinstance(response, dict) and response.get("session_id"))
        except Exception:
            native_opened = False

        sess: Optional[RuntimeSession] = None
        try:
            with self.session(
                task=intent,
                tags=list(tags or []) + ["collab"],
                platform=platform,
                external_ref=collab_id,
            ) as active_session:
                sess = active_session
                if role:
                    sess.add_note(f"role={role}")
                for participant in participants or []:
                    sess.add_collaborator(participant)
                yield sess
        finally:
            if sess is not None and native_opened:
                try:
                    for artifact in sess.artifacts:
                        self.tracker.client.commit_artifact(
                            self.tracker.wallet,
                            collab_id,
                            artifact.get("type", "artifact"),
                            output_hash=artifact.get("output_hash", ""),
                            evidence_url=artifact.get("evidence_url", ""),
                            label=artifact.get("label", ""),
                        )
                    assessment = str(getattr(sess.context, "_assessment", "success") or "success").strip().lower()
                    if assessment not in {"success", "partial", "failure", "cancelled"}:
                        assessment = "success" if sess.context.meaningful_success else "failure"
                    summary_hash = _hash(sess.context._output) if sess.context._output is not None else ""
                    self.tracker.client.close_session(
                        self.tracker.wallet,
                        collab_id,
                        outcome=assessment,
                        summary_hash=summary_hash,
                        note=sess.context._assessment_reason or sess.context._note_for_log(),
                    )
                except Exception:
                    pass

    def callbacks(
        self,
        task: str = "",
        *,
        tags: Optional[List[str]] = None,
        log_llm: bool = False,
        log_tools: bool = False,
        log_chains: bool = False,
        session_tags: Optional[List[str]] = None,
    ) -> NovaSessionCallbackHandler:
        proxy = _RuntimeTrackerProxy(self, tags=self.default_tags + list(tags or []))
        return NovaSessionCallbackHandler(
            proxy,
            task=task,
            tags=[],
            log_llm=log_llm,
            log_tools=log_tools,
            log_chains=log_chains,
            session_tags=session_tags,
        )

    def wrap_callable(
        self,
        func: Any,
        *,
        action_type: str = "agent_run",
        tags: Optional[List[str]] = None,
    ) -> Any:
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            task = getattr(func, "__name__", action_type)
            with self.session(task=task, tags=list(tags or [])) as sess:
                result = func(*args, **kwargs)
                sess.set_output(result)
                sess.assess("success")
                if action_type != "session_complete":
                    sess.mark_significant()
                return result
        return wrapped
