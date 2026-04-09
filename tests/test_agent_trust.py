"""
Tests for agent trust system: activity logs, attestations, challenges, auto-slash, reload,
and governance (agent_param_propose + agent_param_endorse multi-validator flow).
"""
import json
import tempfile
import unittest
from pathlib import Path

from dual_chain import (
    AGENT_CHALLENGE_WINDOW_BLOCKS,
    AGENT_PARAM_UPDATE_COOLDOWN_BLOCKS,
    PublicPaymentChain,
    create_wallet,
    make_agent_activity_log_tx,
    make_agent_attest_tx,
    make_agent_challenge_resolve_tx,
    make_agent_challenge_tx,
    make_agent_intent_post_tx,
    make_agent_param_endorse_tx,
    make_agent_param_propose_tx,
    make_agent_register_tx,
    make_agent_artifact_commit_tx,
    make_agent_session_close_tx,
    make_agent_session_open_tx,
    make_agent_session_settle_tx,
    make_payment_tx,
)


def _setup_chain(tmp: str, reward: float = 100.0) -> tuple:
    """Return (chain, validator_wallet, agent_wallet, challenger_wallet)."""
    validator = create_wallet("validator")
    agent = create_wallet("agent")
    challenger = create_wallet("challenger")

    chain = PublicPaymentChain(
        chain_file=str(Path(tmp) / "chain.json"),
        mining_reward=reward,
        consensus="poa",
        validators=[validator["address"]],
    )
    chain.add_validator(validator["address"])
    return chain, validator, agent, challenger


def _setup_chain_two_validators(tmp: str, reward: float = 100.0) -> tuple:
    """Return (chain, validator1, validator2, agent, challenger) with 2 active validators.
    Rotation is disabled so tests can mine from either validator freely."""
    v1 = create_wallet("validator1")
    v2 = create_wallet("validator2")
    agent = create_wallet("agent")
    challenger = create_wallet("challenger")

    chain = PublicPaymentChain(
        chain_file=str(Path(tmp) / "chain.json"),
        mining_reward=reward,
        consensus="poa",
        validators=[v1["address"], v2["address"]],
        validator_rotation=False,
    )
    chain.add_validator(v1["address"])
    chain.add_validator(v2["address"])
    return chain, v1, v2, agent, challenger


def _mine(chain: PublicPaymentChain, validator: dict, n: int = 1) -> None:
    """Mine n empty blocks."""
    for _ in range(n):
        chain.mine_pending_transactions(validator["address"])


def _fund(chain: PublicPaymentChain, validator: dict, target: dict, amount: float) -> None:
    """Send NOVA from validator to target, then mine."""
    chain.add_transaction(make_payment_tx(validator, target["address"], amount))
    _mine(chain, validator)


def _propose_and_apply(
    chain: PublicPaymentChain,
    proposer: dict,
    endorser: dict,
    changes: dict,
    reason: str = "",
) -> str:
    """
    Full two-step governance flow: propose (proposer) + endorse (endorser).
    Returns the proposal_id.  Assumes threshold=2.
    """
    propose_tx = make_agent_param_propose_tx(proposer, changes, reason=reason)
    chain.add_transaction(propose_tx)
    endorse_tx = make_agent_param_endorse_tx(endorser, propose_tx["proposal_id"])
    chain.add_transaction(endorse_tx)
    return propose_tx["proposal_id"]


class TestAgentTrust(unittest.TestCase):

    def test_agent_activity_log_basic(self) -> None:
        """Log accepted, stored in activity_log_index, trust_score > 0."""
        with tempfile.TemporaryDirectory() as tmp:
            chain, validator, agent, _ = _setup_chain(tmp)
            _mine(chain, validator)                    # fund validator
            _fund(chain, validator, agent, 50.0)       # give agent NOVA

            log_tx = make_agent_activity_log_tx(
                agent, "agent-001", "task_completed", success=True, note="basic test"
            )
            chain.add_transaction(log_tx)
            _mine(chain, validator)

            log_id = log_tx["id"]
            self.assertIn(log_id, chain.activity_log_index)
            rep = chain.reputation_index.get(agent["address"], {})
            self.assertEqual(rep.get("activity_logs"), 1)
            self.assertGreater(rep.get("trust_score", 0.0), 0.0)
            self.assertEqual(rep.get("trust_tier"), "self-reported")

    def test_agent_attest_updates_score(self) -> None:
        """Attestation on log_id increases attested_logs counter and trust_score."""
        with tempfile.TemporaryDirectory() as tmp:
            chain, validator, agent, challenger = _setup_chain(tmp)
            _mine(chain, validator)
            _fund(chain, validator, agent, 50.0)

            log_tx = make_agent_activity_log_tx(agent, "agent-001", "task_completed")
            chain.add_transaction(log_tx)
            _mine(chain, validator)

            score_before = chain.reputation_index[agent["address"]].get("trust_score", 0.0)

            attest_tx = make_agent_attest_tx(challenger, log_tx["id"], "positive")
            chain.add_transaction(attest_tx)
            _mine(chain, validator)

            rep = chain.reputation_index[agent["address"]]
            self.assertEqual(rep.get("attested_logs"), 1)
            self.assertGreater(rep.get("trust_score", 0.0), score_before)
            self.assertEqual(rep.get("trust_tier"), "attested")

    def test_agent_challenge_pending_then_resolved(self) -> None:
        """Challenge stored as pending, resolve_tx clears it, score updated correctly."""
        with tempfile.TemporaryDirectory() as tmp:
            chain, validator, agent, challenger = _setup_chain(tmp)
            _mine(chain, validator)
            _fund(chain, validator, agent, 50.0)
            _fund(chain, validator, challenger, 50.0)

            log_tx = make_agent_activity_log_tx(agent, "agent-001", "task_completed")
            chain.add_transaction(log_tx)
            _mine(chain, validator)

            challenge_tx = make_agent_challenge_tx(challenger, log_tx["id"], stake_locked=5.0)
            chain.add_transaction(challenge_tx)
            _mine(chain, validator)

            rep = chain.reputation_index[agent["address"]]
            self.assertEqual(rep.get("challenged_unanswered_logs"), 1)
            self.assertEqual(rep.get("trust_tier"), "disputed")

            resolve_tx = make_agent_challenge_resolve_tx(
                validator, challenge_tx["id"], verdict="clear"
            )
            chain.add_transaction(resolve_tx)
            _mine(chain, validator)

            rec = chain.challenge_index[challenge_tx["id"]]
            self.assertTrue(rec["resolved"])
            self.assertEqual(rec["verdict"], "clear")

            rep = chain.reputation_index[agent["address"]]
            self.assertEqual(rep.get("challenged_unanswered_logs"), 0)

    def test_agent_challenge_auto_slash_on_window_expiry(self) -> None:
        """Mine 50+ blocks after challenge with no resolve → agent is auto-slashed."""
        with tempfile.TemporaryDirectory() as tmp:
            chain, validator, agent, challenger = _setup_chain(tmp)
            _mine(chain, validator)
            _fund(chain, validator, agent, 50.0)
            _fund(chain, validator, challenger, 50.0)

            log_tx = make_agent_activity_log_tx(
                agent, "agent-001", "task_completed", stake_locked=10.0
            )
            chain.add_transaction(log_tx)
            _mine(chain, validator)

            challenge_tx = make_agent_challenge_tx(challenger, log_tx["id"], stake_locked=5.0)
            chain.add_transaction(challenge_tx)
            _mine(chain, validator)

            _mine(chain, validator, AGENT_CHALLENGE_WINDOW_BLOCKS + 1)

            rec = chain.challenge_index[challenge_tx["id"]]
            self.assertTrue(rec["resolved"])
            self.assertEqual(rec["verdict"], "slash")
            self.assertTrue(rec.get("auto_slashed"))

            rep = chain.reputation_index[agent["address"]]
            self.assertEqual(rep.get("slashed_logs"), 1)
            self.assertEqual(rep.get("trust_tier"), "slashed")

    def test_agent_reload_preserves_trust_state(self) -> None:
        """export_state → new chain → _load_from_state → same trust_score and log count."""
        with tempfile.TemporaryDirectory() as tmp:
            chain_file = str(Path(tmp) / "chain.json")
            chain, validator, agent, _ = _setup_chain(tmp)
            _mine(chain, validator)
            _fund(chain, validator, agent, 50.0)

            for i in range(3):
                log_tx = make_agent_activity_log_tx(agent, "agent-001", f"task_{i}")
                chain.add_transaction(log_tx)
            _mine(chain, validator)

            rep_before = dict(chain.reputation_index[agent["address"]])

            chain2 = PublicPaymentChain(
                chain_file=chain_file,
                mining_reward=100.0,
                consensus="poa",
                validators=[validator["address"]],
            )
            chain2.add_validator(validator["address"])

            rep_after = chain2.reputation_index.get(agent["address"], {})
            self.assertEqual(rep_after.get("activity_logs"), rep_before.get("activity_logs"))
            self.assertAlmostEqual(
                rep_after.get("trust_score", 0.0), rep_before.get("trust_score", 0.0), places=6
            )

    def test_agent_challenge_resolve_rejected_after_auto_slash(self) -> None:
        """Manual resolve after auto-slash is rejected (challenge already resolved)."""
        with tempfile.TemporaryDirectory() as tmp:
            chain, validator, agent, challenger = _setup_chain(tmp)
            _mine(chain, validator)
            _fund(chain, validator, agent, 50.0)
            _fund(chain, validator, challenger, 50.0)

            log_tx = make_agent_activity_log_tx(
                agent, "agent-001", "task_completed", stake_locked=10.0
            )
            chain.add_transaction(log_tx)
            _mine(chain, validator)

            challenge_tx = make_agent_challenge_tx(challenger, log_tx["id"], stake_locked=5.0)
            chain.add_transaction(challenge_tx)
            _mine(chain, validator)

            _mine(chain, validator, AGENT_CHALLENGE_WINDOW_BLOCKS + 1)

            rec = chain.challenge_index[challenge_tx["id"]]
            self.assertTrue(rec.get("auto_slashed"))

            resolve_tx = make_agent_challenge_resolve_tx(
                validator, challenge_tx["id"], verdict="clear"
            )
            with self.assertRaises(ValueError):
                chain.add_transaction(resolve_tx)

    def test_agent_trust_score_evidence_url_signal(self) -> None:
        """Log with evidence_url gets evidence_backed_logs=1 and higher score than without."""
        with tempfile.TemporaryDirectory() as tmp:
            chain, validator, agent, _ = _setup_chain(tmp)
            agent2 = create_wallet("agent2")
            _mine(chain, validator)
            _fund(chain, validator, agent, 50.0)
            _fund(chain, validator, agent2, 50.0)

            log1 = make_agent_activity_log_tx(agent, "agent-001", "task_completed")
            chain.add_transaction(log1)

            log2 = make_agent_activity_log_tx(
                agent2, "agent-002", "task_completed",
                evidence_url="https://ipfs.io/ipfs/Qm123"
            )
            chain.add_transaction(log2)
            _mine(chain, validator)

            rep1 = chain.reputation_index[agent["address"]]
            rep2 = chain.reputation_index[agent2["address"]]

            self.assertEqual(rep1.get("evidence_backed_logs", 0), 0)
            self.assertEqual(rep2.get("evidence_backed_logs", 0), 1)
            self.assertGreater(rep2.get("trust_score", 0.0), rep1.get("trust_score", 0.0))


class TestAgentGovernance(unittest.TestCase):
    """Tests for the two-step multi-validator governance flow (propose + endorse)."""

    def test_agent_param_propose_changes_window_after_endorsement(self) -> None:
        """Full two-step flow: propose + endorse changes challenge_window_blocks."""
        with tempfile.TemporaryDirectory() as tmp:
            chain, v1, v2, agent, challenger = _setup_chain_two_validators(tmp)
            _mine(chain, v1)
            _fund(chain, v1, agent, 50.0)
            _fund(chain, v1, challenger, 50.0)

            _mine(chain, v1, AGENT_PARAM_UPDATE_COOLDOWN_BLOCKS)

            proposal_id = _propose_and_apply(chain, v1, v2, {"challenge_window_blocks": 5},
                                             reason="test window reduction")
            _mine(chain, v1)

            self.assertEqual(chain.agent_trust_params["challenge_window_blocks"], 5)
            self.assertEqual(len(chain.agent_trust_params_history), 1)
            entry = chain.agent_trust_params_history[0]
            self.assertEqual(entry["proposer"], v1["address"])
            self.assertIn(v2["address"], entry["endorsements"])

            # Challenge should auto-slash after 5 blocks with new window
            log_tx = make_agent_activity_log_tx(agent, "agent-001", "task_completed", stake_locked=10.0)
            chain.add_transaction(log_tx)
            _mine(chain, v1)

            challenge_tx = make_agent_challenge_tx(challenger, log_tx["id"], stake_locked=5.0)
            chain.add_transaction(challenge_tx)
            _mine(chain, v1)

            _mine(chain, v1, 5)

            rec = chain.challenge_index[challenge_tx["id"]]
            self.assertTrue(rec["resolved"])
            self.assertEqual(rec["verdict"], "slash")

    def test_agent_param_propose_pending_until_endorsed(self) -> None:
        """Proposal stays open until endorsement; changes don't apply on propose alone."""
        with tempfile.TemporaryDirectory() as tmp:
            chain, v1, v2, _, _ = _setup_chain_two_validators(tmp)
            _mine(chain, v1)
            _mine(chain, v1, AGENT_PARAM_UPDATE_COOLDOWN_BLOCKS)

            propose_tx = make_agent_param_propose_tx(v1, {"challenge_window_blocks": 20})
            chain.add_transaction(propose_tx)
            _mine(chain, v1)

            # Not yet applied — still the default
            self.assertEqual(chain.agent_trust_params["challenge_window_blocks"],
                             AGENT_CHALLENGE_WINDOW_BLOCKS)
            proposal_id = propose_tx["proposal_id"]
            self.assertEqual(chain.agent_param_proposals[proposal_id]["status"], "open")

            # Endorse — now it applies
            endorse_tx = make_agent_param_endorse_tx(v2, proposal_id)
            chain.add_transaction(endorse_tx)
            _mine(chain, v1)

            self.assertEqual(chain.agent_trust_params["challenge_window_blocks"], 20)
            self.assertEqual(chain.agent_param_proposals[proposal_id]["status"], "applied")

    def test_agent_param_propose_non_validator_rejected(self) -> None:
        """Non-validator cannot propose trust parameter changes."""
        with tempfile.TemporaryDirectory() as tmp:
            chain, v1, v2, agent, _ = _setup_chain_two_validators(tmp)
            _mine(chain, v1)

            propose_tx = make_agent_param_propose_tx(
                agent, {"challenge_window_blocks": 5}, reason="attempt by non-validator"
            )
            with self.assertRaises(ValueError):
                chain.add_transaction(propose_tx)

    def test_agent_param_endorse_non_validator_rejected(self) -> None:
        """Non-validator cannot endorse a proposal."""
        with tempfile.TemporaryDirectory() as tmp:
            chain, v1, v2, agent, _ = _setup_chain_two_validators(tmp)
            _mine(chain, v1)
            _mine(chain, v1, AGENT_PARAM_UPDATE_COOLDOWN_BLOCKS)

            propose_tx = make_agent_param_propose_tx(v1, {"challenge_window_blocks": 20})
            chain.add_transaction(propose_tx)
            _mine(chain, v1)

            endorse_tx = make_agent_param_endorse_tx(agent, propose_tx["proposal_id"])
            with self.assertRaises(ValueError):
                chain.add_transaction(endorse_tx)

    def test_agent_param_propose_bounds_rejected(self) -> None:
        """Out-of-range or invalid-enum values are rejected on propose."""
        with tempfile.TemporaryDirectory() as tmp:
            chain, v1, v2, _, _ = _setup_chain_two_validators(tmp)
            _mine(chain, v1)
            _mine(chain, v1, AGENT_PARAM_UPDATE_COOLDOWN_BLOCKS)

            bad_cases = [
                {"challenge_window_blocks": 0},           # below minimum (1)
                {"challenge_window_blocks": 99_999},       # above maximum (10000)
                {"trust_score_weights": {"slashed_log": -200.0}},   # weight out of range
                {"slash_outcome": "steal_everything"},     # unknown enum
                {"trust_score_weights": {"unknown_key": 0.5}},      # unknown weight key
            ]
            for bad in bad_cases:
                tx = make_agent_param_propose_tx(v1, bad, reason="bad value")
                with self.assertRaises(ValueError, msg=f"Expected rejection for {bad}"):
                    chain.add_transaction(tx)

    def test_agent_param_propose_cooldown_enforced(self) -> None:
        """A new proposal within the cooldown window after a prior apply is rejected."""
        with tempfile.TemporaryDirectory() as tmp:
            chain, v1, v2, _, _ = _setup_chain_two_validators(tmp)
            _mine(chain, v1)
            _mine(chain, v1, AGENT_PARAM_UPDATE_COOLDOWN_BLOCKS)

            _propose_and_apply(chain, v1, v2, {"challenge_window_blocks": 60})
            _mine(chain, v1)

            # Immediately try again — should fail (cooldown not passed)
            tx2 = make_agent_param_propose_tx(v1, {"challenge_window_blocks": 70})
            with self.assertRaises(ValueError):
                chain.add_transaction(tx2)

    def test_agent_param_open_proposal_blocks_new_propose(self) -> None:
        """A second proposal is rejected while one is already open."""
        with tempfile.TemporaryDirectory() as tmp:
            chain, v1, v2, _, _ = _setup_chain_two_validators(tmp)
            _mine(chain, v1)
            _mine(chain, v1, AGENT_PARAM_UPDATE_COOLDOWN_BLOCKS)

            # First proposal — stays open (not endorsed yet)
            tx1 = make_agent_param_propose_tx(v1, {"challenge_window_blocks": 60})
            chain.add_transaction(tx1)
            _mine(chain, v1)

            # Second proposal while first is open → rejected
            tx2 = make_agent_param_propose_tx(v2, {"challenge_window_blocks": 70})
            with self.assertRaises(ValueError):
                chain.add_transaction(tx2)

    def test_agent_param_proposer_cannot_endorse_own_proposal(self) -> None:
        """The proposer cannot endorse their own proposal (implicit yes already counted)."""
        with tempfile.TemporaryDirectory() as tmp:
            chain, v1, v2, _, _ = _setup_chain_two_validators(tmp)
            _mine(chain, v1)
            _mine(chain, v1, AGENT_PARAM_UPDATE_COOLDOWN_BLOCKS)

            propose_tx = make_agent_param_propose_tx(v1, {"challenge_window_blocks": 20})
            chain.add_transaction(propose_tx)
            _mine(chain, v1)

            endorse_tx = make_agent_param_endorse_tx(v1, propose_tx["proposal_id"])
            with self.assertRaises(ValueError):
                chain.add_transaction(endorse_tx)

    def test_agent_param_proposal_expires_without_endorsement(self) -> None:
        """Proposal expires after vote_window_blocks with no endorsement."""
        with tempfile.TemporaryDirectory() as tmp:
            chain, v1, v2, _, _ = _setup_chain_two_validators(tmp)
            _mine(chain, v1)
            _mine(chain, v1, AGENT_PARAM_UPDATE_COOLDOWN_BLOCKS)

            propose_tx = make_agent_param_propose_tx(
                v1, {"challenge_window_blocks": 20}, vote_window_blocks=3
            )
            chain.add_transaction(propose_tx)
            _mine(chain, v1)

            _mine(chain, v1, 4)  # window=3, now expired

            proposal_id = propose_tx["proposal_id"]
            self.assertEqual(chain.agent_param_proposals[proposal_id]["status"], "expired")
            # Changes must NOT have been applied
            self.assertEqual(chain.agent_trust_params["challenge_window_blocks"],
                             AGENT_CHALLENGE_WINDOW_BLOCKS)

    def test_agent_param_history_survives_reload(self) -> None:
        """Proposal history and applied params persist across chain reload."""
        with tempfile.TemporaryDirectory() as tmp:
            chain_file = str(Path(tmp) / "chain.json")
            chain, v1, v2, _, _ = _setup_chain_two_validators(tmp)
            _mine(chain, v1)
            _mine(chain, v1, AGENT_PARAM_UPDATE_COOLDOWN_BLOCKS)

            _propose_and_apply(chain, v1, v2, {"challenge_window_blocks": 75},
                               reason="governance vote #1")
            _mine(chain, v1)

            self.assertEqual(len(chain.agent_trust_params_history), 1)

            chain2 = PublicPaymentChain(
                chain_file=chain_file,
                mining_reward=100.0,
                consensus="poa",
                validators=[v1["address"], v2["address"]],
            )
            self.assertEqual(chain2.agent_trust_params["challenge_window_blocks"], 75)
            self.assertEqual(len(chain2.agent_trust_params_history), 1)
            self.assertEqual(chain2.agent_trust_params_history[0]["reason"], "governance vote #1")

    def test_agent_param_update_affects_trust_score(self) -> None:
        """Changing a weight immediately affects subsequent trust_score computation."""
        with tempfile.TemporaryDirectory() as tmp:
            chain, v1, v2, agent, attester = _setup_chain_two_validators(tmp)
            _mine(chain, v1)
            _fund(chain, v1, agent, 50.0)

            log_tx = make_agent_activity_log_tx(agent, "agent-001", "task_completed")
            chain.add_transaction(log_tx)
            attest_tx = make_agent_attest_tx(attester, log_tx["id"], "positive")
            chain.add_transaction(attest_tx)
            _mine(chain, v1)

            score_default = chain.reputation_index[agent["address"]]["trust_score"]

            _mine(chain, v1, AGENT_PARAM_UPDATE_COOLDOWN_BLOCKS)

            # Double the attested_log weight
            _propose_and_apply(chain, v1, v2, {"trust_score_weights": {"attested_log": 0.8}})
            _mine(chain, v1)

            # Force recompute
            chain._compute_trust_score(agent["address"])
            score_after = chain.reputation_index[agent["address"]]["trust_score"]
            self.assertGreater(score_after, score_default)

    def test_passport_lookup_by_agent_id(self) -> None:
        """Chain state: agent registered with agent_id; trust logs linked to owner address."""
        with tempfile.TemporaryDirectory() as tmp:
            chain, validator, agent, _ = _setup_chain(tmp)
            _mine(chain, validator)
            _fund(chain, validator, agent, 50.0)

            reg_tx = make_agent_register_tx(agent, agent_id="my-agent-007", name="Test Agent")
            chain.add_transaction(reg_tx)
            log_tx = make_agent_activity_log_tx(agent, "my-agent-007", "task_completed")
            chain.add_transaction(log_tx)
            _mine(chain, validator)

            # Verify registry has the agent_id mapped to owner
            reg = chain.agent_registry.get("my-agent-007", {})
            self.assertEqual(reg.get("owner"), agent["address"])

            # Verify log is indexed under agent wallet address
            log = chain.activity_log_index.get(log_tx["id"])
            self.assertIsNotNone(log)
            self.assertEqual(log["agent"], agent["address"])

            # Verify trust score is on the owner address
            rep = chain.reputation_index.get(agent["address"], {})
            self.assertEqual(rep.get("activity_logs"), 1)

    def test_agent_register_accepts_self_description_fields(self) -> None:
        """New agent register metadata must validate and persist on-chain."""
        with tempfile.TemporaryDirectory() as tmp:
            chain, validator, agent, _ = _setup_chain(tmp)
            _mine(chain, validator)

            reg_tx = make_agent_register_tx(
                agent,
                agent_id="my-agent-008",
                name="Prompt-Aware Agent",
                capabilities=["analysis"],
                task_types=["summarize reports"],
                refusals=["give legal advice"],
                system_prompt_hash="abc123",
                version_hash="v1",
            )
            chain.add_transaction(reg_tx)
            _mine(chain, validator)

            reg = chain.agent_registry.get("my-agent-008", {})
            self.assertEqual(reg.get("owner"), agent["address"])
            self.assertEqual(reg.get("task_types"), ["summarize reports"])
            self.assertEqual(reg.get("refusals"), ["give legal advice"])
            self.assertEqual(reg.get("system_prompt_hash"), "abc123")

    def test_capability_profile_summarizes_logs_and_collaboration(self) -> None:
        """Capability profile should derive action/tag stats and collaboration partners."""
        with tempfile.TemporaryDirectory() as tmp:
            chain, validator, agent, collaborator = _setup_chain(tmp)
            _mine(chain, validator)
            _fund(chain, validator, agent, 50.0)
            _fund(chain, validator, collaborator, 50.0)

            collab_id = "collab:case-001"
            log_1 = make_agent_activity_log_tx(
                agent,
                "agent-cap",
                "security_audit",
                success=True,
                evidence_url="ipfs://proof-1",
                tags=["security", "audit"],
                external_ref=collab_id,
            )
            log_2 = make_agent_activity_log_tx(
                agent,
                "agent-cap",
                "security_audit",
                success=False,
                evidence_url="ipfs://proof-2",
                tags=["security"],
            )
            collab_log = make_agent_activity_log_tx(
                collaborator,
                "agent-collab",
                "threat_intel_lookup",
                success=True,
                external_ref=collab_id,
                tags=["intel"],
            )
            chain.add_transaction(log_1)
            chain.add_transaction(log_2)
            chain.add_transaction(collab_log)
            chain.add_transaction(make_agent_attest_tx(collaborator, log_1["id"], "positive"))
            _mine(chain, validator)

            profile = chain.capability_profile(agent["address"])

            self.assertEqual(profile["by_action_type"]["security_audit"]["total_logs"], 2)
            self.assertEqual(profile["by_action_type"]["security_audit"]["evidenced_logs"], 2)
            self.assertEqual(profile["by_tag"]["security"]["total_logs"], 2)
            self.assertEqual(profile["collab_partners"], [collaborator["address"]])

    def test_discover_agents_filters_by_observed_capability_and_collaboration(self) -> None:
        """Rich discovery should filter on observed capability counts, proof, and collab graph."""
        with tempfile.TemporaryDirectory() as tmp:
            chain, validator, agent, collaborator = _setup_chain(tmp)
            _mine(chain, validator)
            _fund(chain, validator, agent, 50.0)
            _fund(chain, validator, collaborator, 50.0)

            collab_id = "collab:case-002"
            chain.add_transaction(make_agent_activity_log_tx(
                agent,
                "agent-cap",
                "security_audit",
                success=True,
                evidence_url="ipfs://proof-1",
                tags=["security"],
                external_ref=collab_id,
            ))
            chain.add_transaction(make_agent_activity_log_tx(
                agent,
                "agent-cap",
                "security_audit",
                success=True,
                evidence_url="ipfs://proof-2",
                tags=["security"],
            ))
            chain.add_transaction(make_agent_activity_log_tx(
                collaborator,
                "agent-collab",
                "research",
                success=True,
                external_ref=collab_id,
                tags=["analysis"],
            ))
            _mine(chain, validator)

            results = chain.discover_agents(
                capability="security_audit",
                min_log_count=2,
                min_evidence_count=2,
                has_collaborated=True,
                collaborated_with=collaborator["address"],
            )

            self.assertEqual([row["address"] for row in results], [agent["address"]])
            self.assertEqual(results[0]["capability_stats"]["evidenced_logs"], 2)

    def test_native_coordination_flow_tracks_intents_sessions_artifacts_and_settlement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            chain, validator, agent, collaborator = _setup_chain(tmp)
            _mine(chain, validator)
            _fund(chain, validator, agent, 50.0)
            _fund(chain, validator, collaborator, 50.0)

            intent_tx = make_agent_intent_post_tx(
                agent,
                agent_id="agent-coord",
                intent="Analyze protocol risk",
                role="security-auditor",
                capability_tags=["security", "analysis"],
                desired_collaborators=[collaborator["address"]],
                reward=3.0,
            )
            chain.add_transaction(intent_tx)

            session_tx = make_agent_session_open_tx(
                agent,
                session_id="collab:test-native-001",
                intent_id=intent_tx["intent_id"],
                objective="Joint audit run",
                participants=[collaborator["address"]],
            )
            chain.add_transaction(session_tx)

            artifact_tx = make_agent_artifact_commit_tx(
                collaborator,
                session_id=session_tx["session_id"],
                artifact_type="report",
                output_hash="report-hash-001",
                evidence_url="ipfs://coord-proof-1",
                label="Joint Report",
            )
            chain.add_transaction(artifact_tx)

            close_tx = make_agent_session_close_tx(
                agent,
                session_id=session_tx["session_id"],
                outcome="success",
                summary_hash="summary-hash-001",
                note="Risk report delivered",
            )
            chain.add_transaction(close_tx)

            collaborator_balance_before = chain.get_balance(collaborator["address"])
            settle_tx = make_agent_session_settle_tx(
                agent,
                session_id=session_tx["session_id"],
                payouts={collaborator["address"]: 2.0},
                contribution_weights={agent["address"]: 0.4, collaborator["address"]: 0.6},
                verdict="success",
                note="Collaborator delivered final artifact",
            )
            chain.add_transaction(settle_tx)
            _mine(chain, validator)

            self.assertEqual(chain.intent_index[intent_tx["intent_id"]]["status"], "settled")
            session = chain.get_agent_session(session_tx["session_id"])
            self.assertEqual(session["status"], "settled")
            self.assertEqual(session["intent_id"], intent_tx["intent_id"])
            self.assertEqual(session["artifact_ids"], [artifact_tx["artifact_id"]])
            self.assertEqual(session["settlement"]["payouts"][collaborator["address"]], 2.0)
            self.assertIn(artifact_tx["artifact_id"], chain.artifact_index)
            self.assertAlmostEqual(chain.get_balance(collaborator["address"]), collaborator_balance_before + 2.0)

            intents = chain.list_agent_intents(creator=agent["address"], status="settled")
            self.assertEqual([row["intent_id"] for row in intents], [intent_tx["intent_id"]])

            sessions = chain.list_agent_sessions(participant=collaborator["address"], status="settled")
            self.assertEqual([row["session_id"] for row in sessions], [session_tx["session_id"]])

    def test_session_settlement_requires_closed_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            chain, validator, agent, collaborator = _setup_chain(tmp)
            _mine(chain, validator)
            _fund(chain, validator, agent, 50.0)
            _fund(chain, validator, collaborator, 50.0)

            session_tx = make_agent_session_open_tx(
                agent,
                session_id="collab:test-native-002",
                objective="Open session only",
                participants=[collaborator["address"]],
            )
            chain.add_transaction(session_tx)

            settle_tx = make_agent_session_settle_tx(
                agent,
                session_id=session_tx["session_id"],
                payouts={collaborator["address"]: 1.0},
                contribution_weights={collaborator["address"]: 1.0},
            )
            with self.assertRaises(ValueError):
                chain.add_transaction(settle_tx)


if __name__ == "__main__":
    unittest.main()
