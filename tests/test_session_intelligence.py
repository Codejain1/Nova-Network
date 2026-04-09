"""
Tests for Session Intelligence — SessionContext, NovaTracker.session(), and
NovaSessionCallbackHandler auto-assessment.

Covers:
  - SessionContext: tool tracking, LLM call counting, assessment validation
  - meaningful_success property reflects assessment correctly
  - tools_used aggregates call counts by name
  - tool_success_rate computed correctly (None when no tools)
  - add_note / add_corroborator appended to evidence
  - _to_evidence() structure matches expected schema
  - _note_for_log() format and 256-char truncation
  - assess() rejects invalid outcome strings
  - tracker.session() defaults to "success" when no exception raised
  - tracker.session() sets "failure" automatically on unhandled exception
  - tracker.session() does not override assess() if already called
  - NovaSessionCallbackHandler auto-assesses from agent's final thought
  - Corroboration: add_corroborator appears in _to_evidence()
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from jito_agent.session import SessionContext, ToolCall


# ---------------------------------------------------------------------------
# SessionContext — unit tests (no chain needed)
# ---------------------------------------------------------------------------

class TestSessionContextBasics(unittest.TestCase):
    """Core SessionContext behavior."""

    def test_initial_state(self):
        ctx = SessionContext("Analyze revenue data")
        self.assertEqual(ctx.task, "Analyze revenue data")
        self.assertEqual(ctx._assessment, "success")
        self.assertEqual(ctx._assessment_reason, "")
        self.assertEqual(ctx._llm_calls, 0)
        self.assertEqual(ctx._tool_calls, [])
        self.assertEqual(ctx._notes, [])
        self.assertEqual(ctx._corroborations, [])

    def test_meaningful_success_true_by_default(self):
        ctx = SessionContext("task")
        self.assertTrue(ctx.meaningful_success)

    def test_meaningful_success_false_on_failure(self):
        ctx = SessionContext("task")
        ctx.assess("failure", "could not access API")
        self.assertFalse(ctx.meaningful_success)

    def test_meaningful_success_false_on_partial(self):
        ctx = SessionContext("task")
        ctx.assess("partial", "Q2 data missing")
        self.assertFalse(ctx.meaningful_success)


class TestSessionContextToolTracking(unittest.TestCase):
    """record_tool() and derived properties."""

    def test_tools_used_empty_when_no_tools(self):
        ctx = SessionContext("task")
        self.assertEqual(ctx.tools_used, {})

    def test_tools_used_single_tool(self):
        ctx = SessionContext("task")
        ctx.record_tool("web_search")
        self.assertEqual(ctx.tools_used, {"web_search": 1})

    def test_tools_used_multiple_calls_same_tool(self):
        ctx = SessionContext("task")
        ctx.record_tool("sql_query")
        ctx.record_tool("sql_query")
        ctx.record_tool("sql_query")
        self.assertEqual(ctx.tools_used["sql_query"], 3)

    def test_tools_used_multiple_distinct_tools(self):
        ctx = SessionContext("task")
        ctx.record_tool("web_search")
        ctx.record_tool("code_interpreter")
        ctx.record_tool("web_search")
        self.assertEqual(ctx.tools_used, {"web_search": 2, "code_interpreter": 1})

    def test_tool_success_rate_none_when_no_tools(self):
        ctx = SessionContext("task")
        self.assertIsNone(ctx.tool_success_rate)

    def test_tool_success_rate_all_success(self):
        ctx = SessionContext("task")
        ctx.record_tool("tool_a", success=True)
        ctx.record_tool("tool_b", success=True)
        self.assertEqual(ctx.tool_success_rate, 1.0)

    def test_tool_success_rate_partial(self):
        ctx = SessionContext("task")
        ctx.record_tool("tool_a", success=True)
        ctx.record_tool("tool_b", success=False)
        ctx.record_tool("tool_c", success=True)
        # 2/3 = 0.6667
        self.assertAlmostEqual(ctx.tool_success_rate, 0.6667, places=3)

    def test_tool_success_rate_all_failed(self):
        ctx = SessionContext("task")
        ctx.record_tool("tool_a", success=False)
        ctx.record_tool("tool_b", success=False)
        self.assertEqual(ctx.tool_success_rate, 0.0)

    def test_record_tool_stores_duration(self):
        ctx = SessionContext("task")
        ctx.record_tool("code_interpreter", duration_ms=1234)
        tc = ctx._tool_calls[0]
        self.assertEqual(tc.duration_ms, 1234)
        self.assertEqual(tc.name, "code_interpreter")

    def test_record_llm_call_increments_counter(self):
        ctx = SessionContext("task")
        ctx._record_llm_call()
        ctx._record_llm_call()
        self.assertEqual(ctx._llm_calls, 2)


class TestSessionContextAssess(unittest.TestCase):
    """assess() validation and state changes."""

    def test_assess_success(self):
        ctx = SessionContext("task")
        ctx.assess("success", "all 47 rows validated")
        self.assertEqual(ctx._assessment, "success")
        self.assertEqual(ctx._assessment_reason, "all 47 rows validated")

    def test_assess_partial(self):
        ctx = SessionContext("task")
        ctx.assess("partial", "Q2 data had gaps")
        self.assertEqual(ctx._assessment, "partial")

    def test_assess_failure(self):
        ctx = SessionContext("task")
        ctx.assess("failure", "API unreachable after 3 retries")
        self.assertEqual(ctx._assessment, "failure")

    def test_assess_invalid_outcome_raises(self):
        ctx = SessionContext("task")
        with self.assertRaises(ValueError) as cm:
            ctx.assess("crashed")
        self.assertIn("crashed", str(cm.exception))

    def test_assess_reason_truncated_to_512(self):
        ctx = SessionContext("task")
        long_reason = "x" * 600
        ctx.assess("success", long_reason)
        self.assertEqual(len(ctx._assessment_reason), 512)

    def test_assess_overrides_previous(self):
        ctx = SessionContext("task")
        ctx.assess("success", "first call")
        ctx.assess("failure", "second call overrides")
        self.assertEqual(ctx._assessment, "failure")
        self.assertEqual(ctx._assessment_reason, "second call overrides")


class TestSessionContextNotes(unittest.TestCase):
    """add_note() behavior."""

    def test_add_note_stored(self):
        ctx = SessionContext("task")
        ctx.add_note("encountered rate limit x1")
        self.assertEqual(ctx._notes, ["encountered rate limit x1"])

    def test_add_multiple_notes(self):
        ctx = SessionContext("task")
        ctx.add_note("note 1")
        ctx.add_note("note 2")
        self.assertEqual(len(ctx._notes), 2)

    def test_note_truncated_to_256(self):
        ctx = SessionContext("task")
        long_note = "z" * 300
        ctx.add_note(long_note)
        self.assertEqual(len(ctx._notes[0]), 256)


class TestSessionContextCorroborator(unittest.TestCase):
    """add_corroborator() stores peer verdicts."""

    def test_add_corroborator_agree(self):
        ctx = SessionContext("task")
        ctx.add_corroborator("0xabc123", agrees=True, note="output confirmed")
        self.assertEqual(len(ctx._corroborations), 1)
        c = ctx._corroborations[0]
        self.assertEqual(c["agent_address"], "0xabc123")
        self.assertTrue(c["agrees"])
        self.assertEqual(c["note"], "output confirmed")

    def test_add_corroborator_disagree(self):
        ctx = SessionContext("task")
        ctx.add_corroborator("0xdef456", agrees=False, note="output incorrect")
        self.assertFalse(ctx._corroborations[0]["agrees"])

    def test_corroborator_note_truncated_to_256(self):
        ctx = SessionContext("task")
        ctx.add_corroborator("0xabc", agrees=True, note="y" * 300)
        self.assertEqual(len(ctx._corroborations[0]["note"]), 256)

    def test_multiple_corroborators(self):
        ctx = SessionContext("task")
        ctx.add_corroborator("0xa", agrees=True)
        ctx.add_corroborator("0xb", agrees=False)
        ctx.add_corroborator("0xc", agrees=True)
        self.assertEqual(len(ctx._corroborations), 3)


class TestSessionContextEvidence(unittest.TestCase):
    """_to_evidence() produces correct structure."""

    def test_evidence_contains_all_required_keys(self):
        ctx = SessionContext("Analyze Q3 revenue")
        ctx.record_tool("sql_query", duration_ms=200, success=True)
        ctx.assess("success", "3 anomalies found")
        ctx.add_note("data source: warehouse")
        ctx.add_corroborator("0xpeer1", agrees=True, note="confirmed")

        ev = ctx._to_evidence()

        for key in ("task", "tools", "tools_used", "llm_calls", "assessment",
                    "assessment_reason", "tool_success_rate", "notes", "corroborations"):
            self.assertIn(key, ev, f"Missing key: {key}")

    def test_evidence_task_matches_ctx_task(self):
        ctx = SessionContext("My task description")
        ev = ctx._to_evidence()
        self.assertEqual(ev["task"], "My task description")

    def test_evidence_tools_list_structure(self):
        ctx = SessionContext("task")
        ctx.record_tool("web_search", duration_ms=100, success=True)
        ev = ctx._to_evidence()
        self.assertEqual(len(ev["tools"]), 1)
        tool_entry = ev["tools"][0]
        self.assertIn("name", tool_entry)
        self.assertIn("duration_ms", tool_entry)
        self.assertIn("success", tool_entry)

    def test_evidence_corroborations_included(self):
        ctx = SessionContext("task")
        ctx.add_corroborator("0xpeer", agrees=True, note="verified")
        ev = ctx._to_evidence()
        self.assertEqual(len(ev["corroborations"]), 1)
        self.assertEqual(ev["corroborations"][0]["agent_address"], "0xpeer")

    def test_evidence_tool_success_rate_none_when_no_tools(self):
        ctx = SessionContext("task")
        ev = ctx._to_evidence()
        self.assertIsNone(ev["tool_success_rate"])

    def test_evidence_assessment_matches_assess_call(self):
        ctx = SessionContext("task")
        ctx.assess("partial", "incomplete data")
        ev = ctx._to_evidence()
        self.assertEqual(ev["assessment"], "partial")
        self.assertEqual(ev["assessment_reason"], "incomplete data")


class TestSessionContextNoteForLog(unittest.TestCase):
    """_note_for_log() format and truncation."""

    def test_note_format_no_tools_no_reason(self):
        ctx = SessionContext("task")
        note = ctx._note_for_log()
        self.assertIn("[success]", note)
        self.assertIn("tools=none", note)

    def test_note_format_with_tools(self):
        ctx = SessionContext("task")
        ctx.record_tool("web_search")
        ctx.record_tool("web_search")
        ctx.record_tool("sql_query")
        note = ctx._note_for_log()
        self.assertIn("web_search×2", note)
        self.assertIn("sql_query×1", note)

    def test_note_format_with_reason(self):
        ctx = SessionContext("task")
        ctx.assess("failure", "API timeout")
        note = ctx._note_for_log()
        self.assertIn("[failure]", note)
        self.assertIn("API timeout", note)

    def test_note_truncated_to_256(self):
        ctx = SessionContext("task")
        ctx.assess("success", "r" * 300)
        note = ctx._note_for_log()
        self.assertLessEqual(len(note), 256)


# ---------------------------------------------------------------------------
# NovaTracker.session() context manager
# ---------------------------------------------------------------------------

class TestTrackerSessionContextManager(unittest.TestCase):
    """tracker.session() integration — uses a mocked NovaClient."""

    def _make_tracker(self):
        from jito_agent.tracker import NovaTracker
        from jito_agent.crypto import create_wallet as _cw

        wallet = _cw("test-agent")
        tracker = NovaTracker.__new__(NovaTracker)
        tracker.wallet = wallet
        tracker.agent_id = "test-agent"
        tracker.platform = ""
        tracker.auto_hash_io = True
        tracker.min_duration_s = 0
        tracker.min_tool_calls = 0
        tracker.evidence_store = None
        tracker.self_description = None

        mock_client = MagicMock()
        mock_client.log_activity.return_value = {"tx_id": "mock-tx-001"}
        tracker.client = mock_client
        return tracker, mock_client

    def test_session_defaults_to_success(self):
        tracker, client = self._make_tracker()
        with tracker.session("Summarize Q3 earnings") as ctx:
            ctx.set_output("summary text")

        # log_activity was called
        client.log_activity.assert_called_once()
        call_kwargs = client.log_activity.call_args[1]
        self.assertTrue(call_kwargs.get("success", True))

    def test_session_logs_session_complete_action(self):
        tracker, client = self._make_tracker()
        with tracker.session("task") as ctx:
            pass

        call_kwargs = client.log_activity.call_args[1]
        self.assertEqual(call_kwargs["action_type"], "session_complete")

    def test_session_auto_failure_on_exception(self):
        tracker, client = self._make_tracker()
        try:
            with tracker.session("risky task") as ctx:
                raise RuntimeError("API exploded")
        except RuntimeError:
            pass

        call_kwargs = client.log_activity.call_args[1]
        # success=False because exception was raised
        self.assertFalse(call_kwargs.get("success", True))

    def test_session_respects_explicit_assess_on_exception(self):
        """If agent called assess() before exception, that assessment is preserved."""
        tracker, client = self._make_tracker()
        try:
            with tracker.session("task") as ctx:
                ctx.assess("partial", "processed 30 of 50 rows")
                raise RuntimeError("stopped early")
        except RuntimeError:
            pass

        # The partial assessment should be kept — not overridden by the exception handler
        # (exception handler only overrides if assessment is still default "success" with no reason)
        call_kwargs = client.log_activity.call_args[1]
        # The note should show [partial] since assess was called with a reason
        note = call_kwargs.get("note", "")
        self.assertIn("partial", note)

    def test_session_note_appears_in_log(self):
        tracker, client = self._make_tracker()
        with tracker.session("task") as ctx:
            ctx.assess("success", "completed all 47 steps")

        call_kwargs = client.log_activity.call_args[1]
        note = call_kwargs.get("note", "")
        self.assertIn("success", note)

    def test_session_tags_include_session(self):
        tracker, client = self._make_tracker()
        with tracker.session("task", tags=["finance", "q3"]) as ctx:
            pass

        call_kwargs = client.log_activity.call_args[1]
        tags = call_kwargs.get("tags", [])
        self.assertIn("session", tags)
        self.assertIn("finance", tags)
        self.assertIn("q3", tags)

    def test_session_output_is_hashed(self):
        import hashlib, json
        tracker, client = self._make_tracker()
        output = {"rows": 47, "anomalies": 3}
        with tracker.session("task") as ctx:
            ctx.set_output(output)

        call_kwargs = client.log_activity.call_args[1]
        expected_hash = hashlib.sha256(
            json.dumps(output, sort_keys=True).encode()
        ).hexdigest()
        self.assertEqual(call_kwargs.get("output_hash", ""), expected_hash)


# ---------------------------------------------------------------------------
# NovaSessionCallbackHandler auto-assessment
# ---------------------------------------------------------------------------

class TestNovaSessionCallbackHandlerAssessment(unittest.TestCase):
    """Verify the auto-assessment logic from the agent's final thought."""

    def setUp(self):
        # Import may fail if langchain-core is not installed — skip gracefully
        try:
            from jito_agent.callbacks import NovaSessionCallbackHandler
            self.HandlerClass = NovaSessionCallbackHandler
        except ImportError:
            self.skipTest("langchain-core not installed")

    def _make_handler(self, task="test task"):
        mock_tracker = MagicMock()
        mock_tracker.log.return_value = "mock-log-id"
        handler = self.HandlerClass.__new__(self.HandlerClass)
        handler.tracker = mock_tracker
        handler.default_tags = []
        handler.log_llm = False
        handler.log_tools = False
        handler.log_chains = False
        handler._task = task
        handler._session_tags = ["session"]
        handler._runs = {}
        handler._reset_session_state()
        return handler, mock_tracker

    def _get_session_evidence(self, tracker_mock):
        """Extract evidence from the session_complete log call."""
        for call in tracker_mock.log.call_args_list:
            # Positional args: call[0][0] == "session_complete"
            if call[0] and call[0][0] == "session_complete":
                return call[1].get("evidence", {})
        return {}

    def _make_finish(self, log: str, return_values=None):
        finish = MagicMock()
        finish.log = log
        finish.return_values = return_values or {"output": "result"}
        return finish

    def _fire_agent_finish(self, handler, log):
        from uuid import uuid4
        finish = self._make_finish(log)
        handler.on_agent_finish(finish, run_id=uuid4())

    def test_success_when_no_failure_signals(self):
        handler, tracker = self._make_handler()
        self._fire_agent_finish(handler, "Final answer: The analysis is complete.")
        evidence = self._get_session_evidence(tracker)
        self.assertEqual(evidence.get("assessment", ""), "success")

    def test_failure_detected_from_could_not(self):
        handler, tracker = self._make_handler()
        self._fire_agent_finish(handler, "I could not find the requested data.")
        evidence = self._get_session_evidence(tracker)
        self.assertEqual(evidence.get("assessment", ""), "failure")

    def test_failure_detected_from_unable_to(self):
        handler, tracker = self._make_handler()
        self._fire_agent_finish(handler, "I was unable to access the API.")
        evidence = self._get_session_evidence(tracker)
        self.assertEqual(evidence.get("assessment", ""), "failure")

    def test_failure_detected_from_failed(self):
        handler, tracker = self._make_handler()
        self._fire_agent_finish(handler, "The task failed due to a network error.")
        evidence = self._get_session_evidence(tracker)
        self.assertEqual(evidence.get("assessment", ""), "failure")

    def test_partial_detected_from_incomplete(self):
        handler, tracker = self._make_handler()
        self._fire_agent_finish(handler, "Analysis is incomplete — missing Q2 data.")
        evidence = self._get_session_evidence(tracker)
        self.assertEqual(evidence.get("assessment", ""), "partial")

    def test_partial_detected_from_some_of(self):
        handler, tracker = self._make_handler()
        self._fire_agent_finish(handler, "I was able to retrieve some of the records.")
        evidence = self._get_session_evidence(tracker)
        self.assertEqual(evidence.get("assessment", ""), "partial")

    def test_tool_calls_counted_in_session(self):
        handler, tracker = self._make_handler()
        from uuid import uuid4

        # Simulate two tool invocations
        tool_run_id = uuid4()
        handler.on_tool_start({"name": "web_search"}, "query", run_id=tool_run_id)
        handler.on_tool_end("results", run_id=tool_run_id)

        tool_run_id2 = uuid4()
        handler.on_tool_start({"name": "sql_query"}, "SELECT *", run_id=tool_run_id2)
        handler.on_tool_end("rows", run_id=tool_run_id2)

        self._fire_agent_finish(handler, "Analysis complete.")
        evidence = self._get_session_evidence(tracker)
        tools_used = evidence.get("tools_used", {})
        self.assertIn("web_search", tools_used)
        self.assertIn("sql_query", tools_used)

    def test_llm_calls_counted_in_session(self):
        handler, tracker = self._make_handler()
        from uuid import uuid4

        # Simulate 3 LLM calls
        for _ in range(3):
            run_id = uuid4()
            handler.on_llm_start({"name": "gpt-4"}, ["prompt"], run_id=run_id)
            mock_response = MagicMock()
            mock_response.generations = []
            handler.on_llm_end(mock_response, run_id=run_id)

        self._fire_agent_finish(handler, "Done.")
        evidence = self._get_session_evidence(tracker)
        self.assertEqual(evidence.get("llm_calls", 0), 3)

    def test_corroboration_request_emitted_after_session(self):
        handler, tracker = self._make_handler()
        self._fire_agent_finish(handler, "Task complete.")
        action_types = [c[0][0] for c in tracker.log.call_args_list if c[0]]
        self.assertIn("session_complete", action_types)
        self.assertIn("corroboration_request", action_types)

    def test_session_state_reset_after_finish(self):
        handler, tracker = self._make_handler()
        from uuid import uuid4

        run_id = uuid4()
        handler.on_tool_start({"name": "tool_x"}, "", run_id=run_id)
        handler.on_tool_end("out", run_id=run_id)
        self._fire_agent_finish(handler, "Done.")

        # State should be reset for next session
        self.assertEqual(handler._session_tool_calls, [])
        self.assertEqual(handler._session_llm_calls, 0)
        self.assertFalse(handler._session_started)


# ---------------------------------------------------------------------------
# ToolCall dataclass sanity
# ---------------------------------------------------------------------------

class TestToolCallDataclass(unittest.TestCase):

    def test_default_values(self):
        tc = ToolCall("web_search")
        self.assertEqual(tc.name, "web_search")
        self.assertEqual(tc.duration_ms, 0)
        self.assertTrue(tc.success)

    def test_custom_values(self):
        tc = ToolCall("sql_query", duration_ms=350, success=False)
        self.assertEqual(tc.name, "sql_query")
        self.assertEqual(tc.duration_ms, 350)
        self.assertFalse(tc.success)


if __name__ == "__main__":
    unittest.main()
