"""
Nova Network LangChain callback handler.

Automatically logs every LLM call, tool use, and chain run to NOVA,
building portable reputation with zero changes to existing agent code.

Usage:
    from jito_agent import NovaTracker
    from jito_agent.callbacks import NovaCallbackHandler

    tracker = NovaTracker.new("my-agent")
    handler = NovaCallbackHandler(tracker)

    # Pass to any LangChain runnable / agent / chain
    chain.invoke(input, config={"callbacks": [handler]})

    # Or attach at construction time
    agent = AgentExecutor(agent=agent, tools=tools, callbacks=[handler])
"""

import time
import warnings
from typing import Any, Dict, List, Optional, Sequence, Union
from uuid import UUID

try:
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message="Core Pydantic V1 functionality isn't compatible with Python 3.14 or greater.",
            category=UserWarning,
        )
        from langchain_core.callbacks.base import BaseCallbackHandler
        from langchain_core.outputs import LLMResult
    _LANGCHAIN_AVAILABLE = True
except ImportError:
    BaseCallbackHandler = object  # type: ignore[misc,assignment]
    LLMResult = None              # type: ignore[assignment,misc]
    _LANGCHAIN_AVAILABLE = False


def _check_langchain() -> None:
    if not _LANGCHAIN_AVAILABLE:
        raise ImportError(
            "langchain-core is required for NovaCallbackHandler. "
            "Install it with: pip install langchain-core"
        )


class NovaCallbackHandler(BaseCallbackHandler):
    """
    LangChain callback handler that logs agent activity to NOVA.

    Every LLM call, tool use, and chain run is timed and logged automatically.
    Errors are logged with success=False.  Logging never raises — a NOVA
    failure will not break your agent.

    Args:
        tracker:    A NovaTracker instance (from NovaTracker.new() or __init__).
        tags:       Default tags applied to every log entry.
        log_llm:    Log LLM calls (default True).
        log_tools:  Log tool calls (default True).
        log_chains: Log chain runs (default False — noisy for nested chains).
    """

    def __init__(
        self,
        tracker: Any,
        tags: Optional[List[str]] = None,
        log_llm: bool = True,
        log_tools: bool = True,
        log_chains: bool = False,
    ) -> None:
        _check_langchain()
        super().__init__()
        self.tracker = tracker
        self.default_tags = list(tags or [])
        self.log_llm = log_llm
        self.log_tools = log_tools
        self.log_chains = log_chains
        # run_id → {"start": float, "name": str, "input_hash": str}
        self._runs: Dict[str, Dict[str, Any]] = {}

    # ── Helpers ────────────────────────────────────────────────────────────

    def _start(self, run_id: UUID, name: str, input_data: Any) -> None:
        try:
            from .tracker import _hash
            self._runs[str(run_id)] = {
                "start": time.time(),
                "name": name,
                "input_hash": _hash(input_data),
            }
        except Exception:
            pass

    def _end(
        self,
        run_id: UUID,
        action_type: str,
        output_data: Any = None,
        success: bool = True,
        note: str = "",
        extra_tags: Optional[List[str]] = None,
    ) -> None:
        try:
            key = str(run_id)
            run = self._runs.pop(key, {})
            duration_ms = int((time.time() - run.get("start", time.time())) * 1000)
            from .tracker import _hash
            self.tracker.log(
                action_type,
                input_hash=run.get("input_hash", ""),
                output_data=output_data,
                success=success,
                duration_ms=duration_ms,
                tags=self.default_tags + (extra_tags or []),
                note=(note or run.get("name", ""))[:256],
            )
        except Exception:
            pass  # never let logging break the agent

    def _fail(self, run_id: UUID, action_type: str, error: BaseException) -> None:
        try:
            key = str(run_id)
            run = self._runs.pop(key, {})
            duration_ms = int((time.time() - run.get("start", time.time())) * 1000)
            self.tracker.log(
                action_type,
                input_hash=run.get("input_hash", ""),
                success=False,
                duration_ms=duration_ms,
                tags=self.default_tags,
                note=str(error)[:256],
            )
        except Exception:
            pass

    # ── LLM ────────────────────────────────────────────────────────────────

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        *,
        run_id: UUID,
        tags: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> None:
        if not self.log_llm:
            return
        name = serialized.get("name") or serialized.get("id", ["llm"])[-1]
        self._start(run_id, name, prompts)

    def on_chat_model_start(
        self,
        serialized: Dict[str, Any],
        messages: List[List[Any]],
        *,
        run_id: UUID,
        tags: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> None:
        if not self.log_llm:
            return
        name = serialized.get("name") or serialized.get("id", ["llm"])[-1]
        self._start(run_id, name, messages)

    def on_llm_end(
        self,
        response: Any,
        *,
        run_id: UUID,
        tags: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> None:
        if not self.log_llm:
            return
        output = None
        try:
            output = response.generations[0][0].text if response.generations else None
        except Exception:
            pass
        self._end(run_id, "llm_call", output_data=output, extra_tags=["llm"])

    def on_llm_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        if not self.log_llm:
            return
        self._fail(run_id, "llm_call", error)

    # ── Tools ──────────────────────────────────────────────────────────────

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        tags: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> None:
        if not self.log_tools:
            return
        name = serialized.get("name", "tool")
        self._start(run_id, name, input_str)

    def on_tool_end(
        self,
        output: Any,
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        if not self.log_tools:
            return
        run = self._runs.get(str(run_id), {})
        tool_name = run.get("name", "tool")
        self._end(run_id, "tool_call", output_data=output,
                  extra_tags=["tool", tool_name])

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        if not self.log_tools:
            return
        self._fail(run_id, "tool_call", error)

    # ── Chains ─────────────────────────────────────────────────────────────

    def on_chain_start(
        self,
        serialized: Dict[str, Any],
        inputs: Dict[str, Any],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> None:
        if not self.log_chains:
            return
        # Only log top-level chains (no parent) to avoid noise from nested chains
        if parent_run_id is not None:
            return
        name = serialized.get("name") or serialized.get("id", ["chain"])[-1]
        self._start(run_id, name, inputs)

    def on_chain_end(
        self,
        outputs: Dict[str, Any],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        if not self.log_chains:
            return
        if parent_run_id is not None:
            return
        self._end(run_id, "chain_run", output_data=outputs, extra_tags=["chain"])

    def on_chain_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        if not self.log_chains:
            return
        if parent_run_id is not None:
            return
        self._fail(run_id, "chain_run", error)

    # ── Agent ──────────────────────────────────────────────────────────────

    def on_agent_finish(
        self,
        finish: Any,
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        # Always log agent finish — this is the meaningful unit of work
        try:
            output = getattr(finish, "return_values", {})
            log_str = getattr(finish, "log", "")
            self._end(run_id, "agent_run", output_data=output,
                      note=str(log_str)[:256], extra_tags=["agent"])
        except Exception:
            pass


class NovaSessionCallbackHandler(NovaCallbackHandler):
    """
    LangChain callback handler with full session intelligence.

    Extends NovaCallbackHandler to accumulate everything that happens during
    an agent run into a SessionContext, then logs a single "session_complete"
    event on agent_finish — instead of (or in addition to) per-event logs.

    The session log captures:
      - task:              what the agent was asked to do
      - tools_used:        {tool_name: call_count} for every tool invoked
      - llm_calls:         total number of LLM calls made
      - assessment:        "success" | "partial" | "failure"
      - assessment_reason: extracted from the agent's final log/thought
      - output_hash:       SHA256 of the agent's return values

    Assessment logic (automatic, no code changes needed):
      - Reads the agent's final "log" field (its reasoning before finishing)
      - Checks for failure signals: "could not", "failed", "unable", "error",
        "no result", "couldn't", "I don't know", "I cannot"
      - Checks for partial signals: "partial", "incomplete", "some", "part of"
      - Otherwise defaults to "success"

    Usage:
        tracker = NovaTracker.new("my-agent")
        handler = NovaSessionCallbackHandler(tracker, task="Summarize Q3 earnings")

        agent.invoke({"input": "..."}, config={"callbacks": [handler]})
        # → logs session_complete with full intelligence on agent_finish

    Args:
        tracker:        A NovaTracker instance.
        task:           What the agent was asked to do (logged as session task).
        tags:           Default tags applied to every log entry.
        log_llm:        Log individual LLM calls in addition to session (default False).
        log_tools:      Log individual tool calls in addition to session (default False).
        log_chains:     Log chain runs in addition to session (default False).
        session_tags:   Extra tags added only to the session_complete log.
    """

    # Phrases in the agent's final thought that signal non-success
    _FAILURE_SIGNALS = (
        "could not", "couldn't", "failed", "unable to", "no result",
        "i don't know", "i cannot", "i can't", "error", "not found",
        "does not exist", "no information",
    )
    _PARTIAL_SIGNALS = (
        "partial", "incomplete", "some of", "part of", "not all",
        "missing", "unavailable",
    )

    def __init__(
        self,
        tracker: Any,
        task: str = "",
        tags: "Optional[List[str]]" = None,
        log_llm: bool = False,
        log_tools: bool = False,
        log_chains: bool = False,
        session_tags: "Optional[List[str]]" = None,
    ) -> None:
        _check_langchain()
        super().__init__(
            tracker=tracker,
            tags=tags,
            log_llm=log_llm,
            log_tools=log_tools,
            log_chains=log_chains,
        )
        self._task = task
        self._session_tags: "List[str]" = list(session_tags or []) + ["session"]
        self._reset_session_state()

    def _reset_session_state(self) -> None:
        self._session_tool_calls: "List[dict]" = []   # {name, duration_ms, success}
        self._session_llm_calls: int = 0
        self._session_start: float = 0.0
        self._session_started: bool = False
        self._tool_runs: "Dict[str, Dict[str, Any]]" = {}

    def _ensure_session_started(self) -> None:
        if not self._session_started:
            self._session_start = time.time()
            self._session_started = True

    # ── Override tool hooks to accumulate session state ────────────────────

    def on_tool_start(
        self,
        serialized: "Dict[str, Any]",
        input_str: str,
        *,
        run_id: "UUID",
        tags: "Optional[List[str]]" = None,
        **kwargs: "Any",
    ) -> None:
        self._ensure_session_started()
        name = serialized.get("name") or serialized.get("id", ["tool"])[-1]
        self._tool_runs[str(run_id)] = {
            "name": name,
            "start": time.time(),
        }
        super().on_tool_start(serialized, input_str, run_id=run_id, tags=tags, **kwargs)

    def on_tool_end(
        self,
        output: "Any",
        *,
        run_id: "UUID",
        **kwargs: "Any",
    ) -> None:
        key = str(run_id)
        tool_run = self._tool_runs.pop(key, {})
        tool_duration_ms = int((time.time() - tool_run.get("start", time.time())) * 1000)
        tool_name = tool_run.get("name") or self._runs.get(key, {}).get("name", "tool")
        self._session_tool_calls.append({
            "name": tool_name,
            "duration_ms": tool_duration_ms,
            "success": True,
        })
        super().on_tool_end(output, run_id=run_id, **kwargs)

    def on_tool_error(
        self,
        error: "BaseException",
        *,
        run_id: "UUID",
        **kwargs: "Any",
    ) -> None:
        key = str(run_id)
        tool_run = self._tool_runs.pop(key, {})
        tool_duration_ms = int((time.time() - tool_run.get("start", time.time())) * 1000)
        tool_name = tool_run.get("name") or self._runs.get(key, {}).get("name", "tool")
        self._session_tool_calls.append({
            "name": tool_name,
            "duration_ms": tool_duration_ms,
            "success": False,
        })
        super().on_tool_error(error, run_id=run_id, **kwargs)

    # ── Override LLM hooks to count calls ──────────────────────────────────

    def on_llm_start(
        self,
        serialized: "Dict[str, Any]",
        prompts: "List[str]",
        *,
        run_id: "UUID",
        tags: "Optional[List[str]]" = None,
        **kwargs: "Any",
    ) -> None:
        self._ensure_session_started()
        super().on_llm_start(serialized, prompts, run_id=run_id, tags=tags, **kwargs)

    def on_llm_end(
        self,
        response: "Any",
        *,
        run_id: "UUID",
        tags: "Optional[List[str]]" = None,
        **kwargs: "Any",
    ) -> None:
        self._ensure_session_started()
        self._session_llm_calls += 1
        super().on_llm_end(response, run_id=run_id, tags=tags, **kwargs)

    def on_chat_model_start(
        self,
        serialized: "Dict[str, Any]",
        messages: "List[List[Any]]",
        *,
        run_id: "UUID",
        tags: "Optional[List[str]]" = None,
        **kwargs: "Any",
    ) -> None:
        self._ensure_session_started()
        super().on_chat_model_start(serialized, messages, run_id=run_id, tags=tags, **kwargs)

    # ── Agent finish — emit the session_complete log ───────────────────────

    def on_agent_finish(
        self,
        finish: "Any",
        *,
        run_id: "UUID",
        **kwargs: "Any",
    ) -> None:
        # Let the base handler log its own agent_run event if configured
        super().on_agent_finish(finish, run_id=run_id, **kwargs)

        try:
            from .tracker import _hash

            output = getattr(finish, "return_values", {})
            agent_thought = str(getattr(finish, "log", ""))

            # ── Self-assessment from agent's final thought ─────────────────
            thought_lower = agent_thought.lower()
            if any(sig in thought_lower for sig in self._FAILURE_SIGNALS):
                assessment = "failure"
            elif any(sig in thought_lower for sig in self._PARTIAL_SIGNALS):
                assessment = "partial"
            else:
                assessment = "success"

            # Trim the thought to a useful reason string
            reason = agent_thought.strip()
            if reason.lower().startswith("final answer:"):
                reason = reason[len("final answer:"):].strip()
            reason = reason[:512]

            # ── Build tools_used summary ───────────────────────────────────
            tools_used: "Dict[str, int]" = {}
            for tc in self._session_tool_calls:
                tools_used[tc["name"]] = tools_used.get(tc["name"], 0) + 1

            tool_success_rate = None
            if self._session_tool_calls:
                succeeded = sum(1 for tc in self._session_tool_calls if tc["success"])
                tool_success_rate = round(succeeded / len(self._session_tool_calls), 4)

            # ── Build the evidence dict (hashed, never on-chain verbatim) ──
            evidence = {
                "task": self._task,
                "tools": self._session_tool_calls,
                "tools_used": tools_used,
                "llm_calls": self._session_llm_calls,
                "assessment": assessment,
                "assessment_reason": reason,
                "tool_success_rate": tool_success_rate,
                "notes": [],
            }

            # ── One-line note for the on-chain note field ──────────────────
            tool_str = (
                ", ".join(f"{name}x{count}" for name, count in tools_used.items())
                or "none"
            )
            note = f"[{assessment}] tools={tool_str} | {reason}"[:256]

            self._ensure_session_started()
            duration_ms = int((time.time() - self._session_start) * 1000)
            output_hash = _hash(output) if output else ""

            session_log_id = self.tracker.log(
                "session_complete",
                input_data={"task": self._task} if self._task else None,
                output_hash=output_hash,
                evidence=evidence,
                success=(assessment == "success"),
                duration_ms=duration_ms,
                tags=self.default_tags + self._session_tags,
                note=note,
            )

            # ── Corroboration request ──────────────────────────────────────
            # Emit a second log so peer agents know this session is open
            # for attestation.  external_ref links back to the session log.
            self.tracker.log(
                "corroboration_request",
                external_ref=str(session_log_id) if session_log_id else "",
                tags=self.default_tags + ["corroboration"],
                note=f"corroboration open for session {session_log_id}"[:256],
                success=True,
            )
        except Exception:
            pass  # Never let session logging break the agent
        finally:
            self._reset_session_state()
