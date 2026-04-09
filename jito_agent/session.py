"""
Session Intelligence — rich context for what actually happened during an agent session.

Instead of logging "ran for 45 seconds, success", a session captures:
  - What task was attempted
  - What tools were used (name + call count + per-call success)
  - What the output was (hashed client-side, never on-chain verbatim)
  - Whether the agent thinks it succeeded *meaningfully*, not just exited cleanly

The self-assessment is the key signal. The agent must make a judgment call:
  ctx.assess("success", "all 47 rows validated, anomalies flagged with >0.9 confidence")
  ctx.assess("partial", "analysis complete but source data had gaps in Q2")
  ctx.assess("failure", "could not access required API after 3 retries")

This is different from exit status. A process can exit 0 and produce garbage output.
The session log forces the agent to reason about output quality, not just completion.

Usage (manual):
    with tracker.session("Analyze Q3 revenue and flag anomalies") as ctx:
        result = run_agent(task)
        ctx.set_output(result)
        ctx.assess("success", "Found 3 anomalies, confidence 0.94")

Usage (LangChain — fully automatic):
    handler = NovaSessionCallbackHandler(tracker, task="Analyze Q3 revenue")
    agent.invoke(input, config={"callbacks": [handler]})
    # session_complete logged automatically on agent_finish
"""

from typing import Any, Dict, List, Optional


_VALID_OUTCOMES = ("success", "partial", "failure")


class ToolCall:
    """Record of a single tool invocation within a session."""
    __slots__ = ("name", "duration_ms", "success")

    def __init__(self, name: str, duration_ms: int = 0, success: bool = True) -> None:
        self.name = name
        self.duration_ms = duration_ms
        self.success = success


class SessionContext:
    """
    Mutable context for a running agent session. Passed into tracker.session() blocks.

    The agent fills this in as work progresses:
        ctx.record_tool("web_search")              # manual tool tracking
        ctx.set_output(result)                     # set final output (will be hashed)
        ctx.assess("success", "reason here")       # self-assessment — required signal
        ctx.add_note("encountered rate limit x1")  # optional observations

    When used with NovaSessionCallbackHandler (LangChain), tool calls and LLM calls
    are recorded automatically — you only need to call assess() and set_output().
    """

    def __init__(self, task: str) -> None:
        self.task: str = task
        self._tool_calls: List[ToolCall] = []
        self._llm_calls: int = 0
        self._output: Any = None
        self._assessment: str = "success"
        self._assessment_reason: str = ""
        self._notes: List[str] = []
        self._corroborations: List[Dict] = []

    # ── Tool tracking ──────────────────────────────────────────────────────

    def record_tool(self, name: str, duration_ms: int = 0, success: bool = True) -> None:
        """
        Record a tool call. Call this each time a tool is invoked.
        Done automatically by NovaSessionCallbackHandler for LangChain agents.

        name:        tool name, e.g. "web_search", "code_interpreter", "sql_query"
        duration_ms: how long the call took (0 if unknown)
        success:     whether the tool call returned a usable result
        """
        self._tool_calls.append(ToolCall(name=name, duration_ms=duration_ms, success=success))

    def _record_llm_call(self) -> None:
        """Internal — called by NovaSessionCallbackHandler."""
        self._llm_calls += 1

    # ── Output ────────────────────────────────────────────────────────────

    def set_output(self, output: Any) -> None:
        """Set the final output of the session. Will be SHA256-hashed before logging."""
        self._output = output

    # ── Self-assessment ───────────────────────────────────────────────────

    def assess(self, outcome: str, reason: str = "") -> None:
        """
        Agent's self-assessment of whether it succeeded *meaningfully*.

        This is the most important field in the session log. It forces the agent
        to reason about output quality, not just completion status.

        outcome — one of:
            "success"  task completed, output is genuinely useful
            "partial"  made progress but could not fully complete the task
            "failure"  could not complete, or output is unreliable / incorrect

        reason (max 512 chars) — explain WHY, not just what happened:
            Good: "all 47 data points validated, report matches source figures"
            Good: "API returned partial data for Q2, marked gaps in output"
            Bad:  "exited with code 0"
            Bad:  "no errors raised"

        If assess() is never called:
            - If no exception was raised → assessment defaults to "success"
            - If an exception was raised → assessment is set to "failure" automatically
        """
        if outcome not in _VALID_OUTCOMES:
            raise ValueError(f"outcome must be one of {_VALID_OUTCOMES}, got {outcome!r}")
        self._assessment = outcome
        self._assessment_reason = reason[:512]

    def add_note(self, note: str) -> None:
        """Add a free-form observation about the session (max 256 chars each)."""
        self._notes.append(note[:256])

    def add_corroborator(self, agent_address: str, agrees: bool, note: str = "") -> None:
        """
        Record that another agent has confirmed or disputed this session's outcome.

        agent_address: on-chain address of the corroborating agent
        agrees:        True  → the peer agrees with the self-assessment
                       False → the peer disputes it
        note:          optional reason (max 256 chars)

        These are included in _to_evidence() so the full corroboration history
        is captured in the session's evidence hash.
        """
        self._corroborations.append({
            "agent_address": agent_address,
            "agrees": agrees,
            "note": note[:256],
        })

    # ── Derived properties ────────────────────────────────────────────────

    @property
    def meaningful_success(self) -> bool:
        """True only when the agent assessed this as a genuine success."""
        return self._assessment == "success"

    @property
    def tools_used(self) -> Dict[str, int]:
        """Returns {tool_name: call_count} for all tools invoked this session."""
        counts: Dict[str, int] = {}
        for tc in self._tool_calls:
            counts[tc.name] = counts.get(tc.name, 0) + 1
        return counts

    @property
    def tool_success_rate(self) -> Optional[float]:
        """Fraction of tool calls that returned a usable result. None if no tools called."""
        if not self._tool_calls:
            return None
        succeeded = sum(1 for tc in self._tool_calls if tc.success)
        return round(succeeded / len(self._tool_calls), 4)

    # ── Internal serialisation (used by tracker.session()) ────────────────

    def _to_evidence(self) -> Dict:
        """
        Structured evidence dict. Content is SHA256-hashed client-side —
        never sent on-chain verbatim. The hash is what goes on-chain.
        """
        return {
            "task": self.task,
            "tools": [
                {"name": tc.name, "duration_ms": tc.duration_ms, "success": tc.success}
                for tc in self._tool_calls
            ],
            "tools_used": self.tools_used,
            "llm_calls": self._llm_calls,
            "assessment": self._assessment,
            "assessment_reason": self._assessment_reason,
            "tool_success_rate": self.tool_success_rate,
            "notes": self._notes,
            "corroborations": list(self._corroborations),
        }

    def _note_for_log(self) -> str:
        """
        One-line summary for the on-chain note field (max 256 chars).
        Format: [assessment] tools=name×n,name×n | reason
        """
        tool_str = (
            ", ".join(f"{name}×{count}" for name, count in self.tools_used.items())
            or "none"
        )
        base = f"[{self._assessment}] tools={tool_str}"
        if self._assessment_reason:
            base = f"{base} | {self._assessment_reason}"
        return base[:256]
