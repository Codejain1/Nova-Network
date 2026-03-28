"""
JITO LangChain callback handler.

Automatically logs every LLM call, tool use, and chain run to JITO,
building portable reputation with zero changes to existing agent code.

Usage:
    from jito_agent import JitoTracker
    from jito_agent.callbacks import JitoCallbackHandler

    tracker = JitoTracker.new("my-agent")
    handler = JitoCallbackHandler(tracker)

    # Pass to any LangChain runnable / agent / chain
    chain.invoke(input, config={"callbacks": [handler]})

    # Or attach at construction time
    agent = AgentExecutor(agent=agent, tools=tools, callbacks=[handler])
"""

import time
from typing import Any, Dict, List, Optional, Sequence, Union
from uuid import UUID

try:
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
            "langchain-core is required for JitoCallbackHandler. "
            "Install it with: pip install langchain-core"
        )


class JitoCallbackHandler(BaseCallbackHandler):
    """
    LangChain callback handler that logs agent activity to JITO.

    Every LLM call, tool use, and chain run is timed and logged automatically.
    Errors are logged with success=False.  Logging never raises — a JITO
    failure will not break your agent.

    Args:
        tracker:    A JitoTracker instance (from JitoTracker.new() or __init__).
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
