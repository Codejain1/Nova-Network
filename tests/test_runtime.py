import tempfile
import unittest
from types import SimpleNamespace

from jito_agent import AutoLogPolicy, NovaLightClientNode, NovaRuntime, PersistentEventQueue


class _FakeClient:
    def __init__(self) -> None:
        self.logged = []
        self.intents = []
        self.sessions_opened = []
        self.artifacts = []
        self.sessions_closed = []

    def log_activity(self, **kwargs):
        self.logged.append(kwargs)
        return {"tx_id": f"tx-{len(self.logged)}"}

    def post_intent(self, wallet, **kwargs):
        record = {"wallet": wallet, **kwargs}
        self.intents.append(record)
        return {"tx_id": "intent-tx", "intent_id": "ait_test"}

    def open_session(self, wallet, **kwargs):
        record = {"wallet": wallet, **kwargs}
        self.sessions_opened.append(record)
        return {"tx_id": "session-open-tx", "session_id": kwargs.get("session_id", "collab:test")}

    def commit_artifact(self, wallet, session_id: str, artifact_type: str, **kwargs):
        record = {
            "wallet": wallet,
            "session_id": session_id,
            "artifact_type": artifact_type,
            **kwargs,
        }
        self.artifacts.append(record)
        return {"tx_id": "artifact-tx", "artifact_id": f"aar_{len(self.artifacts)}"}

    def close_session(self, wallet, session_id: str, **kwargs):
        record = {"wallet": wallet, "session_id": session_id, **kwargs}
        self.sessions_closed.append(record)
        return {"tx_id": "session-close-tx", "session_id": session_id}

    def passport(self, address: str):
        return {"address": address, "trust_score": 1.2}

    def capability_profile(self, address: str):
        return {
            "address": address,
            "by_action_type": {
                "session_complete": {
                    "total_logs": 2,
                    "evidenced_logs": 1,
                    "attested_logs": 1,
                    "success_rate": 1.0,
                    "evidence_rate": 0.5,
                    "last_active": 10.0,
                }
            },
            "by_tag": {},
            "collab_partners": ["W2"],
        }


def _fake_tracker(client: _FakeClient):
    return SimpleNamespace(
        wallet={"address": "W1"},
        agent_id="agent-1",
        platform="",
        auto_hash_io=True,
        client=client,
    )


class TestRuntimeQueue(unittest.TestCase):
    def test_persistent_queue_tracks_pending_and_delivered_items(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            queue = PersistentEventQueue(f"{tmp}/queue.json")
            item_id = queue.enqueue({"action_type": "session_complete"})
            self.assertEqual(queue.stats()["pending"], 1)

            queue.mark_delivered(item_id, result={"tx_id": "abc"})
            stats = queue.stats()
            self.assertEqual(stats["pending"], 0)
            self.assertEqual(stats["delivered"], 1)


class TestRuntimePolicy(unittest.TestCase):
    def test_policy_prefers_artifacts_and_collaboration(self) -> None:
        policy = AutoLogPolicy(min_duration_ms=99_999, min_tool_calls=99, min_llm_calls=99)
        decision = policy.evaluate({
            "duration_ms": 10,
            "tools": [],
            "llm_calls": 0,
            "success": True,
            "assessment": "success",
            "artifacts": [{"output_hash": "abc"}],
            "collaborators": [],
            "side_effects": [],
            "confidence": None,
            "force_log": False,
            "suppress_log": False,
        })
        self.assertTrue(decision.should_log)
        self.assertEqual(decision.reason, "artifact")


class TestLightClientNode(unittest.TestCase):
    def test_light_client_flushes_queue_and_caches_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            client = _FakeClient()
            light = NovaLightClientNode(
                _fake_tracker(client),
                queue_path=f"{tmp}/queue.json",
                cache_path=f"{tmp}/cache.json",
                flush_interval_s=0.25,
            )
            try:
                light.enqueue_log({
                    "action_type": "session_complete",
                    "success": True,
                    "duration_ms": 123,
                    "tags": ["runtime"],
                    "note": "done",
                })
                result = light.flush()
                self.assertEqual(result["delivered"], 1)
                self.assertEqual(len(client.logged), 1)

                passport = light.sync_passport("W1")
                profile = light.sync_capability_profile("W1")
                self.assertEqual(passport["address"], "W1")
                self.assertEqual(profile["address"], "W1")
                self.assertIsNotNone(light.cached_snapshot("passport", "W1"))
                self.assertIsNotNone(light.cached_snapshot("capability_profile", "W1"))
            finally:
                light.stop()


class TestNovaRuntime(unittest.TestCase):
    def test_runtime_session_skips_trivial_work_and_logs_meaningful_sessions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            client = _FakeClient()
            runtime = NovaRuntime(
                _fake_tracker(client),
                policy=AutoLogPolicy(min_duration_ms=99_999, min_tool_calls=99, min_llm_calls=99),
                queue_path=f"{tmp}/queue.json",
                cache_path=f"{tmp}/cache.json",
                auto_start=False,
            )
            try:
                with runtime.session("trivial task") as sess:
                    sess.assess("success", "nothing meaningful happened")
                self.assertEqual(runtime.status()["queue"]["pending"], 0)

                with runtime.session("meaningful task", external_ref="collab:demo") as sess:
                    sess.set_output({"report": "done"})
                    sess.add_artifact(output={"report": "done"}, artifact_type="report")
                    sess.add_collaborator("W2")
                    sess.assess("success", "produced report")
                self.assertEqual(runtime.status()["queue"]["pending"], 1)

                flush = runtime.flush()
                self.assertEqual(flush["delivered"], 1)
                self.assertEqual(client.logged[0]["external_ref"], "collab:demo")
                self.assertEqual(client.logged[0]["action_type"], "session_complete")
            finally:
                runtime.stop()

    def test_runtime_supports_intents_and_collab_sessions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            client = _FakeClient()
            runtime = NovaRuntime(
                _fake_tracker(client),
                queue_path=f"{tmp}/queue.json",
                cache_path=f"{tmp}/cache.json",
                auto_start=False,
            )
            try:
                runtime.post_intent("analyze protocol risk", role="auditor", collaborators=["W2"])
                with runtime.collab_session(
                    "analyze protocol risk",
                    role="auditor",
                    participants=["W2"],
                    session_id="collab:test123",
                ) as sess:
                    sess.set_output({"ok": True})
                    sess.add_artifact(output={"ok": True}, artifact_type="report")
                    sess.assess("success", "joint report produced")
                flush = runtime.flush()
                self.assertEqual(flush["delivered"], 2)
                self.assertEqual(client.intents[0]["intent"], "analyze protocol risk")
                self.assertEqual(client.sessions_opened[0]["session_id"], "collab:test123")
                self.assertEqual(client.artifacts[0]["session_id"], "collab:test123")
                self.assertEqual(client.sessions_closed[0]["session_id"], "collab:test123")
                self.assertEqual(client.logged[0]["action_type"], "intent_posted")
                self.assertEqual(client.logged[1]["external_ref"], "collab:test123")
            finally:
                runtime.stop()
