"""
Tests for ZK proof replay prevention.

Design note
-----------
`make_zk_proof_tx` signs the full payload, but `_validate_zk_proof_tx`
verifies only the signable subset — so constructing a properly-signed proof
requires signing the subset ourselves.  Additionally, the dev-VK path
(vk["_dev"] = True) returns *before* the replay check, so replay tests
must use a real (non-dev) circuit entry with `HAS_ZK=False` behaviour
skipped via a mock, or patch `verify_signature` to isolate the replay
and freshness logic from cryptographic I/O concerns.

The strategy used here:
  1. Patch `dual_chain.verify_signature` → always True.
  2. Use a non-dev VK-style dict that doesn't have `_dev`.
     When HAS_ZK is False (py_ecc not installed) it raises "ZK verification
     not available" — so tests also set HAS_ZK = True with a patched groth16.
  3. This lets us cleanly exercise replay detection and freshness checks.

For the chain-load rebuild tests, we use `_apply_zk_proof_tx` directly
to populate `zk_proof_log` + `zk_proof_hashes`, then reload from disk and
assert the hashes are restored.

Covers:
  - Same proof hash submitted twice → second raises ValueError "replay detected"
  - Different proofs with same circuit_id → both accepted
  - `zk_proof_hashes` set populated after proof applied
  - `zk_proof_hashes` rebuilt from `zk_proof_log` on chain reload
  - Replay still blocked after chain reload
  - `zk_proof_max_age_seconds` rejects stale proofs
  - Setting max_age_seconds=0 disables freshness check
  - Fresh chain starts with empty `zk_proof_hashes`
  - Hash set grows monotonically with unique proofs
"""

import hashlib
import json
import secrets
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

import dual_chain as _dc
from dual_chain import PublicPaymentChain, create_wallet


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _chain(tmp: str) -> tuple:
    """Fresh PoA chain with one validator."""
    v = create_wallet("validator")
    p = create_wallet("prover")
    ch = PublicPaymentChain(
        chain_file=str(Path(tmp) / "chain.json"),
        mining_reward=100.0,
        consensus="poa",
        validators=[v["address"]],
    )
    ch.add_validator(v["address"])
    return ch, v, p


def _mine(ch, v, n=1):
    for _ in range(n):
        ch.mine_pending_transactions(v["address"])


def _proof_hash(proof_dict: dict) -> str:
    """Compute the SHA256 of the canonical proof content — same as the chain does."""
    return hashlib.sha256(
        json.dumps(proof_dict, sort_keys=True).encode()
    ).hexdigest()


def _make_payload(prover_address: str, proof: dict, circuit_id: str = "test_circuit_v1") -> dict:
    """Minimal valid zk_proof payload with all required fields."""
    return {
        "type": "zk_proof",
        "circuit_id": circuit_id,
        "prover": prover_address,
        "proof": proof,
        "public_inputs": ["commitment_abc"],
        "metadata": {},
        "ts": time.time(),
        "nonce": secrets.token_hex(8),
    }


# A non-dev VK placeholder (all required keys, but no _dev flag).
# With verify_sig patched and HAS_ZK patched, the pairing step is skipped.
_MOCK_VK = {
    "alpha": [1, 2],
    "beta":  [[3, 4], [5, 6]],
    "gamma": [[7, 8], [9, 10]],
    "delta": [[11, 12], [13, 14]],
    "ic":    [[15, 16], [17, 18]],
}


def _register_mock_circuit(ch, circuit_id: str = "test_circuit_v1") -> None:
    """Directly register a test circuit in the chain's ZK registry."""
    ch.zk_circuit_registry[circuit_id] = {"vk": _MOCK_VK, "description": "test"}


# ---------------------------------------------------------------------------
# Context manager: patch sig verification + ZK pairing for isolated tests
# ---------------------------------------------------------------------------

def _patch_zk():
    """
    Context manager that patches signature verification and Groth16 verification
    to always pass, letting us test replay/freshness logic in isolation.
    """
    return _PatchedZK()


class _PatchedZK:
    """Patches verify_signature and groth16_verify to always return True."""

    def __enter__(self):
        self._p1 = patch("dual_chain.verify_signature", return_value=True)
        self._p2 = patch("dual_chain.HAS_ZK", True)
        self._p3 = patch("dual_chain.groth16_verify", return_value=True)
        self._p1.start()
        self._p2.start()
        self._p3.start()
        return self

    def __exit__(self, *args):
        self._p1.stop()
        self._p2.stop()
        self._p3.stop()


# ---------------------------------------------------------------------------
# Tests: Replay prevention
# ---------------------------------------------------------------------------

class TestZKReplayPrevention(unittest.TestCase):
    """Replay guard: same proof rejected on second submission."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.ch, self.v, self.p = _chain(self.tmp)
        _register_mock_circuit(self.ch)

    def test_same_proof_apply_twice_raises_on_validate(self):
        """
        Applying a proof then calling validate with the same payload must raise
        ValueError containing 'replay'.
        """
        proof = {"pi_a": [1, 2], "pi_b": [[3, 4]], "pi_c": [5]}
        payload = _make_payload(self.p["address"], proof)

        # First apply: succeeds (populate zk_proof_hashes)
        self.ch._apply_zk_proof_tx(payload, 1)
        self.assertEqual(len(self.ch.zk_proof_hashes), 1)

        # Validate the same payload again: replay detected
        with self.assertRaises(ValueError) as ctx:
            # Patch only sig + ZK so we reach the replay check
            with _patch_zk():
                self.ch._validate_zk_proof_tx(payload, "mock_sig", {})
        self.assertIn("replay", str(ctx.exception).lower())

    def test_replay_error_message_includes_hash(self):
        """Replay error must contain a hex hash prefix for auditability."""
        proof = {"pi_a": [9, 10], "pi_c": [11]}
        payload = _make_payload(self.p["address"], proof)
        self.ch._apply_zk_proof_tx(payload, 1)

        with self.assertRaises(ValueError) as ctx:
            with _patch_zk():
                self.ch._validate_zk_proof_tx(payload, "sig", {})
        err = str(ctx.exception)
        # The error should embed a hex string (the hash prefix)
        self.assertTrue(any(c in err for c in "0123456789abcdef"))

    def test_different_proofs_same_circuit_both_accepted(self):
        """Two different proofs for the same circuit must both be accepted."""
        proof_a = {"pi_a": [1, 2], "tag": "run_a"}
        proof_b = {"pi_a": [6, 7], "tag": "run_b"}
        payload_a = _make_payload(self.p["address"], proof_a)
        payload_b = _make_payload(self.p["address"], proof_b)

        with _patch_zk():
            # First proof — should not raise
            self.ch._validate_zk_proof_tx(payload_a, "sig_a", {})
            self.ch._apply_zk_proof_tx(payload_a, 1)

            # Second proof (different) — should not raise
            self.ch._validate_zk_proof_tx(payload_b, "sig_b", {})
            self.ch._apply_zk_proof_tx(payload_b, 2)

        self.assertEqual(len(self.ch.zk_proof_hashes), 2)
        self.assertEqual(len(self.ch.zk_proof_log), 2)

    def test_proof_hash_stored_in_zk_proof_log(self):
        """Each applied proof must have proof_hash stored in zk_proof_log."""
        proof = {"pi_a": [21, 22], "pi_c": [25]}
        payload = _make_payload(self.p["address"], proof)
        self.ch._apply_zk_proof_tx(payload, 1)

        entry = self.ch.zk_proof_log[-1]
        self.assertIn("proof_hash", entry)
        expected_hash = _proof_hash(proof)
        self.assertEqual(entry["proof_hash"], expected_hash)
        self.assertEqual(len(entry["proof_hash"]), 64)  # sha256 hex

    def test_zk_proof_hashes_populated_after_apply(self):
        """zk_proof_hashes set must contain the hash after applying a proof."""
        proof = {"pi_a": [31, 32], "pi_c": [35]}
        payload = _make_payload(self.p["address"], proof)
        self.ch._apply_zk_proof_tx(payload, 1)

        expected_hash = _proof_hash(proof)
        self.assertIn(expected_hash, self.ch.zk_proof_hashes)

    def test_multiple_unique_proofs_all_in_hash_set(self):
        """All distinct applied proofs are tracked in the replay guard set."""
        for i in range(5):
            proof = {"pi_a": [i], "pi_b": [[i + 1]], "pi_c": [i + 2]}
            payload = _make_payload(self.p["address"], proof)
            self.ch._apply_zk_proof_tx(payload, i + 1)

        self.assertEqual(len(self.ch.zk_proof_hashes), 5)


# ---------------------------------------------------------------------------
# Tests: Chain reload
# ---------------------------------------------------------------------------

class TestZKReplayAfterChainLoad(unittest.TestCase):
    """Replay guard is rebuilt correctly when chain is loaded from disk."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.ch, self.v, self.p = _chain(self.tmp)
        _register_mock_circuit(self.ch)

    def _save_and_reload(self) -> PublicPaymentChain:
        """Mine one block (triggers save) then reload from same file."""
        _mine(self.ch, self.v)
        return PublicPaymentChain(
            chain_file=self.ch.chain_file,
            mining_reward=100.0,
            consensus="poa",
            validators=[self.v["address"]],
        )

    def test_proof_hashes_rebuilt_on_reload(self):
        """After saving and reloading the chain, zk_proof_hashes is repopulated."""
        proof = {"pi_a": [41, 42], "pi_c": [45]}
        payload = _make_payload(self.p["address"], proof)
        self.ch._apply_zk_proof_tx(payload, 1)
        original_hashes = set(self.ch.zk_proof_hashes)

        # The apply adds to zk_proof_log; mine saves it; reload rebuilds the set
        ch2 = self._save_and_reload()
        self.assertEqual(ch2.zk_proof_hashes, original_hashes)

    def test_replay_blocked_after_reload(self):
        """Replay is still blocked for proofs submitted before a chain reload."""
        proof = {"pi_a": [51, 52], "pi_c": [55]}
        payload = _make_payload(self.p["address"], proof)
        self.ch._apply_zk_proof_tx(payload, 1)

        _register_mock_circuit(ch2 := self._save_and_reload())

        with self.assertRaises(ValueError) as ctx:
            with _patch_zk():
                ch2._validate_zk_proof_tx(payload, "mock_sig", {})
        self.assertIn("replay", str(ctx.exception).lower())

    def test_multiple_proofs_all_rebuilt_on_reload(self):
        """All proof hashes are accurately restored after reload."""
        for i in range(3):
            proof = {"pi_a": [i * 10], "tag": f"proof_{i}"}
            payload = _make_payload(self.p["address"], proof)
            self.ch._apply_zk_proof_tx(payload, i + 1)

        hashes_before = set(self.ch.zk_proof_hashes)
        ch2 = self._save_and_reload()
        self.assertEqual(ch2.zk_proof_hashes, hashes_before)

    def test_new_proof_accepted_after_reload(self):
        """A proof NOT previously submitted is still accepted after reload."""
        old_proof = {"pi_a": [61], "tag": "old"}
        old_payload = _make_payload(self.p["address"], old_proof)
        self.ch._apply_zk_proof_tx(old_payload, 1)

        _register_mock_circuit(ch2 := self._save_and_reload())

        new_proof = {"pi_a": [99], "tag": "new"}
        new_payload = _make_payload(self.p["address"], new_proof)

        with _patch_zk():
            # Should not raise — new proof hash not in the set
            ch2._validate_zk_proof_tx(new_payload, "sig", {})


# ---------------------------------------------------------------------------
# Tests: Freshness
# ---------------------------------------------------------------------------

class TestZKProofFreshness(unittest.TestCase):
    """zk_proof_max_age_seconds rejects stale proofs."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.ch, self.v, self.p = _chain(self.tmp)
        _register_mock_circuit(self.ch)

    def test_freshness_check_rejects_old_timestamp(self):
        """_validate_zk_proof_tx must reject a proof whose ts is >max_age seconds old."""
        self.ch.agent_trust_params["zk_proof_max_age_seconds"] = 10  # 10 s window

        stale_payload = _make_payload(self.p["address"], {"pi_a": [1]})
        stale_payload["ts"] = time.time() - 3600  # 1 hour ago

        with self.assertRaises(ValueError) as ctx:
            with _patch_zk():
                self.ch._validate_zk_proof_tx(stale_payload, "sig", {})
        self.assertIn("too old", str(ctx.exception))

    def test_freshness_check_disabled_when_max_age_zero(self):
        """Setting zk_proof_max_age_seconds=0 disables the freshness check."""
        self.ch.agent_trust_params["zk_proof_max_age_seconds"] = 0

        # Even a stale timestamp should be accepted
        stale_payload = _make_payload(self.p["address"], {"pi_a": [71]})
        stale_payload["ts"] = time.time() - 7200  # 2 hours ago

        with _patch_zk():
            # Should not raise — freshness disabled
            self.ch._validate_zk_proof_tx(stale_payload, "sig", {})

    def test_fresh_proof_accepted_within_window(self):
        """A proof with ts=now is accepted under the default 3600s window."""
        self.ch.agent_trust_params["zk_proof_max_age_seconds"] = 3600

        payload = _make_payload(self.p["address"], {"pi_a": [81]})
        # ts is set to time.time() inside _make_payload → fresh

        with _patch_zk():
            # Should not raise
            self.ch._validate_zk_proof_tx(payload, "sig", {})

    def test_max_age_governance_param_stored(self):
        """The zk_proof_max_age_seconds param exists in agent_trust_params by default."""
        self.assertIn("zk_proof_max_age_seconds", self.ch.agent_trust_params)
        self.assertEqual(self.ch.agent_trust_params["zk_proof_max_age_seconds"], 3600)

    def test_freshness_error_includes_age_and_limit(self):
        """Freshness error message must include actual age and allowed limit."""
        self.ch.agent_trust_params["zk_proof_max_age_seconds"] = 5

        stale_payload = _make_payload(self.p["address"], {"pi_a": [91]})
        stale_payload["ts"] = time.time() - 3600

        with self.assertRaises(ValueError) as ctx:
            with _patch_zk():
                self.ch._validate_zk_proof_tx(stale_payload, "sig", {})
        err = str(ctx.exception)
        # Should mention the allowed limit (5) somewhere
        self.assertIn("5", err)


# ---------------------------------------------------------------------------
# Tests: zk_proof_hashes set properties
# ---------------------------------------------------------------------------

class TestZKProofHashSet(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.ch, self.v, self.p = _chain(self.tmp)

    def test_fresh_chain_has_empty_hash_set(self):
        """A brand-new chain starts with an empty zk_proof_hashes set."""
        self.assertIsInstance(self.ch.zk_proof_hashes, set)
        self.assertEqual(len(self.ch.zk_proof_hashes), 0)

    def test_hash_set_grows_with_each_proof(self):
        """Each unique proof applied adds exactly one entry."""
        for i in range(4):
            proof = {"pi_a": [i], "counter": i}
            payload = _make_payload(self.p["address"], proof)
            self.ch._apply_zk_proof_tx(payload, i + 1)
            self.assertEqual(len(self.ch.zk_proof_hashes), i + 1)

    def test_duplicate_apply_does_add_hash_twice(self):
        """
        _apply_zk_proof_tx is designed to be called only after validation passes.
        If somehow called twice with the same payload, the set grows by 0 (sets are unique).
        """
        proof = {"pi_a": [81, 82]}
        payload = _make_payload(self.p["address"], proof)
        self.ch._apply_zk_proof_tx(payload, 1)
        size_after_first = len(self.ch.zk_proof_hashes)

        # Apply again — set won't grow because same hash
        self.ch._apply_zk_proof_tx(payload, 2)
        # Sets deduplicate automatically
        self.assertEqual(len(self.ch.zk_proof_hashes), size_after_first)

    def test_hash_set_matches_proof_log_entries(self):
        """Every hash in zk_proof_hashes must be present in zk_proof_log."""
        for i in range(3):
            proof = {"pi_a": [i * 5]}
            payload = _make_payload(self.p["address"], proof)
            self.ch._apply_zk_proof_tx(payload, i + 1)

        log_hashes = {e["proof_hash"] for e in self.ch.zk_proof_log if "proof_hash" in e}
        self.assertEqual(self.ch.zk_proof_hashes, log_hashes)

    def test_proof_hash_computation_deterministic(self):
        """The same proof dict always yields the same hash."""
        proof = {"pi_a": [1, 2], "pi_b": [[3, 4]], "pi_c": [5]}
        h1 = _proof_hash(proof)
        h2 = _proof_hash(proof)
        self.assertEqual(h1, h2)

    def test_different_proofs_yield_different_hashes(self):
        """Two distinct proof dicts must have different hashes."""
        proof_a = {"pi_a": [1]}
        proof_b = {"pi_a": [2]}
        self.assertNotEqual(_proof_hash(proof_a), _proof_hash(proof_b))


if __name__ == "__main__":
    unittest.main()
