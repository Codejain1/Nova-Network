import unittest
from types import SimpleNamespace
from uuid import uuid4

import jito_agent.callbacks as callbacks_module
from jito_agent import CapabilityProfile, DiscoveryQuery, NovaClient
from jito_agent.callbacks import NovaSessionCallbackHandler


class _RecordingTracker:
    def __init__(self) -> None:
        self.calls = []

    def log(self, action_type: str, **kwargs):
        self.calls.append({"action_type": action_type, **kwargs})
        return {"tx_id": "tx-test"}


class _FakeRichClient(NovaClient):
    def __init__(self) -> None:
        super().__init__("https://example.invalid")

    def _get(self, path: str):
        if path.startswith("/public/agent/discover?"):
            return {
                "agents": [
                    {
                        "address": "A",
                        "trust_score": 2.0,
                        "trust_tier": "attested",
                        "capability_profile": {
                            "address": "A",
                            "by_action_type": {
                                "security_audit": {
                                    "total_logs": 3,
                                    "evidenced_logs": 2,
                                    "attested_logs": 1,
                                    "success_rate": 1.0,
                                    "evidence_rate": 0.6667,
                                    "last_active": 1.0,
                                }
                            },
                            "by_tag": {},
                            "collab_partners": ["C"],
                        },
                    }
                ]
            }
        raise AssertionError(f"unexpected path: {path}")

    def discover(self, **kwargs):
        return [
            {"address": "A", "trust_score": 2.0, "trust_tier": "attested"},
            {"address": "B", "trust_score": 3.0, "trust_tier": "evidence-attested"},
        ]

    def capability_profile(self, address: str, log_limit: int = 200) -> CapabilityProfile:
        if address == "A":
            return CapabilityProfile({
                "address": "A",
                "by_action_type": {
                    "security_audit": {
                        "total_logs": 3,
                        "evidenced_logs": 2,
                        "attested_logs": 1,
                        "success_rate": 1.0,
                        "evidence_rate": 0.6667,
                        "last_active": 1.0,
                    }
                },
                "by_tag": {},
                "collab_partners": ["C"],
            })
        return CapabilityProfile({
            "address": "B",
            "by_action_type": {
                "security_audit": {
                    "total_logs": 1,
                    "evidenced_logs": 0,
                    "attested_logs": 0,
                    "success_rate": 1.0,
                    "evidence_rate": 0.0,
                    "last_active": 1.0,
                }
            },
            "by_tag": {},
            "collab_partners": [],
        })


class _FakeProfileClient(NovaClient):
    def __init__(self) -> None:
        super().__init__("https://example.invalid")

    def _get(self, path: str):
        if path.startswith("/public/agent/capability_profile?address=W1"):
            return {
                "address": "W1",
                "by_action_type": {
                    "security_audit": {
                        "total_logs": 2,
                        "evidenced_logs": 2,
                        "attested_logs": 1,
                        "success_rate": 0.5,
                        "evidence_rate": 1.0,
                        "last_active": 11.0,
                    },
                    "research": {
                        "total_logs": 1,
                        "evidenced_logs": 0,
                        "attested_logs": 0,
                        "success_rate": 1.0,
                        "evidence_rate": 0.0,
                        "last_active": 12.0,
                    },
                },
                "by_tag": {
                    "security": {
                        "total_logs": 2,
                        "evidenced_logs": 2,
                        "attested_logs": 1,
                        "success_rate": 0.5,
                        "evidence_rate": 1.0,
                        "last_active": 11.0,
                    },
                    "audit": {
                        "total_logs": 1,
                        "evidenced_logs": 1,
                        "attested_logs": 1,
                        "success_rate": 1.0,
                        "evidence_rate": 1.0,
                        "last_active": 10.0,
                    },
                    "analysis": {
                        "total_logs": 1,
                        "evidenced_logs": 0,
                        "attested_logs": 0,
                        "success_rate": 1.0,
                        "evidence_rate": 0.0,
                        "last_active": 12.0,
                    },
                },
                "collab_partners": ["W2", "W3"],
            }
        if path.startswith("/public/agent/passport?address=W1&verbose=true"):
            return {
                "logs_detail": [
                    {
                        "action_type": "security_audit",
                        "tags": ["security", "audit"],
                        "success": True,
                        "timestamp": 10.0,
                        "evidence_url": "ipfs://cid1",
                        "attestations": [{"sentiment": "positive"}],
                    },
                    {
                        "action_type": "security_audit",
                        "tags": ["security"],
                        "success": False,
                        "timestamp": 11.0,
                        "evidence_hash": "abc",
                        "attestations": [],
                    },
                    {
                        "action_type": "research",
                        "tags": ["analysis"],
                        "success": True,
                        "timestamp": 12.0,
                        "attestations": [],
                    },
                ],
                "collab_sessions_detail": [
                    {"agents": ["W1", "W2"]},
                    {"agents": ["W1", "W3"]},
                ],
            }
        raise AssertionError(f"unexpected path: {path}")


class _FakeCoordinationClient(NovaClient):
    def __init__(self) -> None:
        super().__init__("https://example.invalid")
        self.submitted = []

    def _submit_tx(self, tx: dict):
        self.submitted.append(tx)
        return {"ok": True, "tx_id": tx.get("id", "")}

    def _get(self, path: str):
        if path.startswith("/public/agent/intents?"):
            return {
                "intents": [
                    {
                        "intent_id": "ait_test",
                        "creator": "W1",
                        "status": "open",
                        "capability_tags": ["security"],
                    }
                ]
            }
        if path.startswith("/public/agent/sessions?"):
            return {
                "sessions": [
                    {
                        "session_id": "collab:test",
                        "status": "settled",
                        "agents": ["W1", "W2"],
                    }
                ]
            }
        if path.startswith("/public/agent/session?session_id=collab%3Atest"):
            return {
                "ok": True,
                "session_id": "collab:test",
                "status": "settled",
                "artifact_ids": ["aar_1"],
            }
        raise AssertionError(f"unexpected path: {path}")


class TestJitoAgentSdk(unittest.TestCase):
    def test_session_callback_preserves_tool_name_when_log_tools_disabled(self) -> None:
        original = callbacks_module._LANGCHAIN_AVAILABLE
        callbacks_module._LANGCHAIN_AVAILABLE = True
        try:
            tracker = _RecordingTracker()
            handler = NovaSessionCallbackHandler(tracker, task="test run")
            run_id = uuid4()

            handler.on_tool_start({"name": "web_search"}, "query", run_id=run_id)
            handler.on_tool_end("done", run_id=run_id)
            handler.on_agent_finish(
                SimpleNamespace(return_values={"ok": True}, log="Final answer: success"),
                run_id=uuid4(),
            )

            session_calls = [call for call in tracker.calls if call["action_type"] == "session_complete"]
            self.assertEqual(len(session_calls), 1)
            call = session_calls[0]
            self.assertEqual(call["action_type"], "session_complete")
            self.assertEqual(call["evidence"]["tools_used"], {"web_search": 1})
            self.assertEqual(call["evidence"]["tools"][0]["name"], "web_search")
        finally:
            callbacks_module._LANGCHAIN_AVAILABLE = original

    def test_session_callback_resets_state_between_runs(self) -> None:
        original = callbacks_module._LANGCHAIN_AVAILABLE
        callbacks_module._LANGCHAIN_AVAILABLE = True
        try:
            tracker = _RecordingTracker()
            handler = NovaSessionCallbackHandler(tracker, task="test run")

            first_run = uuid4()
            handler.on_tool_start({"name": "web_search"}, "query", run_id=first_run)
            handler.on_tool_end("done", run_id=first_run)
            handler.on_agent_finish(
                SimpleNamespace(return_values={"ok": True}, log="success"),
                run_id=uuid4(),
            )

            handler.on_agent_finish(
                SimpleNamespace(return_values={"ok": True}, log="success"),
                run_id=uuid4(),
            )

            session_calls = [call for call in tracker.calls if call["action_type"] == "session_complete"]
            self.assertEqual(len(session_calls), 2)
            second = session_calls[1]
            self.assertEqual(second["evidence"]["tools"], [])
            self.assertEqual(second["evidence"]["tools_used"], {})
            self.assertEqual(second["evidence"]["llm_calls"], 0)
        finally:
            callbacks_module._LANGCHAIN_AVAILABLE = original

    def test_capability_profile_aggregates_logs_and_collaborators(self) -> None:
        profile = _FakeProfileClient().capability_profile("W1")

        self.assertEqual(profile.evidence_count("security_audit"), 2)
        self.assertTrue(profile.has_evidenced("security", min_count=2))
        self.assertEqual(sorted(profile.collab_partners), ["W2", "W3"])

    def test_discover_rich_filters_by_capability_and_collaboration(self) -> None:
        client = _FakeRichClient()
        query = (
            DiscoveryQuery()
            .with_capability("security_audit", min_logs=2, min_evidenced=1)
            .has_collaborated(with_address="C")
            .limit(5)
        )

        results = client.discover_rich(query)

        self.assertEqual([r["address"] for r in results], ["A"])

    def test_coordination_client_methods_submit_native_transactions(self) -> None:
        client = _FakeCoordinationClient()
        wallet = {"address": "W1", "public_key": {"kty": "ed25519", "key": "AQ=="}, "private_key": {"kty": "ed25519", "key": "AQ=="}}

        # Use a real generated wallet instead of stubbed key material to exercise signing.
        from jito_agent.crypto import create_wallet

        wallet = create_wallet("coord")

        intent = client.post_intent(wallet, "agent-1", "Analyze protocol risk", capability_tags=["security"])
        session = client.open_session(wallet, session_id="collab:test", objective="Joint audit", participants=["W2"])
        artifact = client.commit_artifact(wallet, "collab:test", "report", output_hash="hash-1")
        close = client.close_session(wallet, "collab:test", outcome="success", summary_hash="sum-1")
        settle = client.settle_session(wallet, "collab:test", payouts={"W2": 1.0}, contribution_weights={"W2": 1.0})

        self.assertEqual(intent["intent_id"], client.submitted[0]["intent_id"])
        self.assertEqual(session["session_id"], "collab:test")
        self.assertEqual(artifact["artifact_id"], client.submitted[2]["artifact_id"])
        self.assertEqual(close["session_id"], "collab:test")
        self.assertEqual(settle["session_id"], "collab:test")
        self.assertEqual(
            [tx["type"] for tx in client.submitted],
            [
                "agent_intent_post",
                "agent_session_open",
                "agent_artifact_commit",
                "agent_session_close",
                "agent_session_settle",
            ],
        )

    def test_coordination_client_query_methods_hit_expected_routes(self) -> None:
        client = _FakeCoordinationClient()

        intents = client.intents(creator="W1", status="open", capability="security", limit=5)
        sessions = client.sessions(participant="W2", status="settled", limit=5)
        session = client.session("collab:test")

        self.assertEqual(intents[0]["intent_id"], "ait_test")
        self.assertEqual(sessions[0]["session_id"], "collab:test")
        self.assertEqual(session["artifact_ids"], ["aar_1"])


if __name__ == "__main__":
    unittest.main()
