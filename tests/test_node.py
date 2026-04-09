import json
import tempfile
import time
import unittest
from hashlib import sha256
from json import dumps

from dual_chain import create_wallet, make_asset_issue_tx, make_payment_tx, save_wallet
from node import DualChainNode


class NodeFeatureTests(unittest.TestCase):
    def test_resolve_address_alias_canonicalizes_evm_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            node = DualChainNode(
                data_dir=tmp,
                public_difficulty=1,
                public_reward=5.0,
                public_consensus="poa",
                public_validators=[],
            )
            try:
                raw = "0xF9a1e0774f1ceD31108729D16985D47a3D03D3eA"
                self.assertEqual(
                    node.resolve_address_alias(raw),
                    "EVM:0xf9a1e0774f1ced31108729d16985d47a3d03d3ea",
                )
                self.assertEqual(
                    node.resolve_address_alias(f"EVM:{raw}"),
                    "EVM:0xf9a1e0774f1ced31108729d16985d47a3d03d3ea",
                )
            finally:
                node.stop_background_workers()

    def test_auto_mine_processes_pending_transactions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            validator = create_wallet("validator")
            alice = create_wallet("alice")
            node = DualChainNode(
                data_dir=tmp,
                public_difficulty=1,
                public_reward=5.0,
                public_consensus="poa",
                public_validators=[validator["address"]],
            )
            try:
                node.public_chain.mine_pending_transactions(validator["address"])
                tx = make_payment_tx(validator, alice["address"], 2.0)
                node.public_chain.add_transaction(tx)

                node.start_auto_mining(
                    miner=validator["address"],
                    interval_seconds=0.2,
                    allow_empty_blocks=False,
                )

                deadline = time.time() + 4.0
                while time.time() < deadline:
                    if len(node.public_chain.pending_transactions) == 0:
                        break
                    time.sleep(0.05)

                self.assertEqual(len(node.public_chain.pending_transactions), 0)
                self.assertGreaterEqual(len(node.public_chain.chain), 3)
                self.assertGreater(node.public_chain.get_balance(alice["address"]), 0)
            finally:
                node.stop_auto_mining()
                node.stop_background_workers()

    def test_auto_mine_requires_poa_validator(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            validator = create_wallet("validator")
            outsider = create_wallet("outsider")
            node = DualChainNode(
                data_dir=tmp,
                public_difficulty=1,
                public_reward=5.0,
                public_consensus="poa",
                public_validators=[validator["address"]],
            )
            try:
                with self.assertRaises(ValueError):
                    node.start_auto_mining(
                        miner=outsider["address"],
                        interval_seconds=1.0,
                        allow_empty_blocks=False,
                    )
            finally:
                node.stop_background_workers()

    def test_validator_bootstrap_from_config_adds_missing_validators(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            validator_1 = create_wallet("validator1")
            validator_2 = create_wallet("validator2")

            node_first = DualChainNode(
                data_dir=tmp,
                public_difficulty=1,
                public_reward=5.0,
                public_consensus="poa",
                public_validators=[validator_1["address"]],
                public_validator_rotation=True,
            )
            try:
                self.assertEqual(sorted(node_first.public_chain.validators), [validator_1["address"]])
            finally:
                node_first.stop_background_workers()

            node_second = DualChainNode(
                data_dir=tmp,
                public_difficulty=1,
                public_reward=5.0,
                public_consensus="poa",
                public_validators=[validator_1["address"], validator_2["address"]],
                public_validator_rotation=True,
            )
            try:
                # Simulate startup validator bootstrap logic from run_node.
                for validator in [validator_1["address"], validator_2["address"]]:
                    if validator not in node_second.public_chain.validators:
                        node_second.public_chain.add_validator(validator)
                self.assertIn(validator_1["address"], node_second.public_chain.validators)
                self.assertIn(validator_2["address"], node_second.public_chain.validators)
            finally:
                node_second.stop_background_workers()

    def test_auto_mine_auto_follows_rotation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            validator_1 = create_wallet("validator1")
            validator_2 = create_wallet("validator2")
            recipient = create_wallet("recipient")
            node = DualChainNode(
                data_dir=tmp,
                public_difficulty=1,
                public_reward=5.0,
                public_consensus="poa",
                public_validators=[validator_1["address"], validator_2["address"]],
                public_validator_rotation=True,
            )
            try:
                expected = node.public_chain.expected_next_validator()
                payload = {
                    "type": "payment",
                    "sender": "SYSTEM",
                    "recipient": recipient["address"],
                    "amount": 1.0,
                    "timestamp": time.time(),
                }
                tx_id = sha256(dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
                node.public_chain.add_transaction({**payload, "id": tx_id})
                node.start_auto_mining(miner="auto", interval_seconds=0.2, allow_empty_blocks=False)

                deadline = time.time() + 4.0
                while time.time() < deadline:
                    if len(node.public_chain.pending_transactions) == 0:
                        break
                    time.sleep(0.05)

                self.assertEqual(len(node.public_chain.pending_transactions), 0)
                self.assertEqual(node.public_chain.chain[-1].meta.get("validator"), expected)
                status = node.auto_mine_status()
                self.assertTrue(status["follow_rotation"])
                self.assertEqual(status["effective_miner"], node.public_chain.expected_next_validator())
            finally:
                node.stop_auto_mining()
                node.stop_background_workers()

    def test_public_faucet_claim_cooldown_and_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            miner = create_wallet("miner")
            claimant = create_wallet("claimant")
            node = DualChainNode(
                data_dir=tmp,
                public_difficulty=1,
                public_reward=5.0,
                public_faucet_enabled=True,
                public_faucet_amount=1.0,
                public_faucet_cooldown_seconds=0.0,
                public_faucet_daily_cap=2.0,
            )
            try:
                claim_1 = node.claim_public_faucet(claimant["address"], amount=1.5)
                self.assertTrue(claim_1["ok"])
                self.assertEqual(len(node.public_chain.pending_transactions), 1)

                with self.assertRaises(ValueError):
                    node.claim_public_faucet(claimant["address"], amount=1.0)

                node.public_chain.mine_pending_transactions(miner["address"])
                self.assertAlmostEqual(node.public_chain.get_balance(claimant["address"]), 1.5)
            finally:
                node.stop_background_workers()

    def test_auto_mine_rotation_mismatch_keeps_worker_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            validator_1 = create_wallet("validator1")
            validator_2 = create_wallet("validator2")
            recipient = create_wallet("recipient")
            node = DualChainNode(
                data_dir=tmp,
                public_difficulty=1,
                public_reward=5.0,
                public_consensus="poa",
                public_validators=[validator_1["address"], validator_2["address"]],
                public_validator_rotation=True,
            )
            try:
                expected = node.public_chain.expected_next_validator()
                wrong_miner = validator_1["address"] if expected != validator_1["address"] else validator_2["address"]
                payload = {
                    "type": "payment",
                    "sender": "SYSTEM",
                    "recipient": recipient["address"],
                    "amount": 1.0,
                    "timestamp": time.time(),
                }
                tx_id = sha256(dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
                node.public_chain.add_transaction({**payload, "id": tx_id})

                node.start_auto_mining(miner=wrong_miner, interval_seconds=0.2, allow_empty_blocks=False)
                time.sleep(0.7)

                status = node.auto_mine_status()
                self.assertTrue(status["enabled"])
                self.assertTrue(status["thread_alive"])
                self.assertEqual(len(node.public_chain.pending_transactions), 1)
            finally:
                node.stop_auto_mining()
                node.stop_background_workers()

    def test_pruned_public_chain_reload_keeps_full_height_and_can_continue_mining(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            validator = create_wallet("validator")
            node = DualChainNode(
                data_dir=tmp,
                public_difficulty=1,
                public_reward=5.0,
                public_consensus="poa",
                public_validators=[validator["address"]],
                public_validator_rotation=False,
            )
            try:
                for _ in range(520):
                    node.public_chain.mine_pending_transactions(validator["address"])
                self.assertEqual(node.public_chain.height - 1, 520)
            finally:
                node.stop_background_workers()

            reloaded = DualChainNode(
                data_dir=tmp,
                public_difficulty=1,
                public_reward=5.0,
                public_consensus="poa",
                public_validators=[validator["address"]],
                public_validator_rotation=False,
            )
            try:
                self.assertEqual(reloaded.public_chain.height - 1, 520)
                self.assertEqual(len(reloaded.public_chain.chain), 500)
                self.assertGreater(reloaded.public_chain.chain[0].index, 0)
                self.assertEqual(reloaded.public_chain.chain[-1].index, 520)

                block = reloaded.public_chain.mine_pending_transactions(validator["address"])
                self.assertEqual(block.index, 521)
                self.assertEqual(reloaded.public_chain.height - 1, 521)
                self.assertTrue(reloaded.public_chain.is_valid())
            finally:
                reloaded.stop_background_workers()

            reloaded_again = DualChainNode(
                data_dir=tmp,
                public_difficulty=1,
                public_reward=5.0,
                public_consensus="poa",
                public_validators=[validator["address"]],
                public_validator_rotation=False,
            )
            try:
                self.assertEqual(reloaded_again.public_chain.height - 1, 521)
                self.assertEqual(reloaded_again.public_chain.chain[-1].index, 521)
                self.assertTrue(reloaded_again.public_chain.is_valid())
            finally:
                reloaded_again.stop_background_workers()

    def test_pruned_public_chain_preserves_supply_and_tx_counters(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            validator_1 = create_wallet("validator1")
            validator_2 = create_wallet("validator2")
            node = DualChainNode(
                data_dir=tmp,
                public_difficulty=1,
                public_reward=25.0,
                public_consensus="poa",
                public_validators=[validator_1["address"], validator_2["address"]],
                public_validator_rotation=True,
            )
            try:
                for _ in range(520):
                    node.public_chain.mine_pending_transactions(node.public_chain.expected_next_validator())
                expected_supply = 520 * 25.0
                self.assertEqual(node.public_chain.blocks_mined_total(), 520)
                self.assertEqual(node.public_chain.total_confirmed_public_transactions(), 520)
                self.assertAlmostEqual(node.public_chain.total_minted_supply(), expected_supply)
                self.assertAlmostEqual(
                    sum(node.public_chain.balance_index.values()) + node.public_chain.treasury_balance,
                    expected_supply,
                )
            finally:
                node.stop_background_workers()

            reloaded = DualChainNode(
                data_dir=tmp,
                public_difficulty=1,
                public_reward=25.0,
                public_consensus="poa",
                public_validators=[validator_1["address"], validator_2["address"]],
                public_validator_rotation=True,
            )
            try:
                self.assertEqual(reloaded.public_chain.blocks_mined_total(), 520)
                self.assertEqual(reloaded.public_chain.total_confirmed_public_transactions(), 520)
                self.assertAlmostEqual(reloaded.public_chain.total_minted_supply(), 520 * 25.0)
                self.assertAlmostEqual(
                    sum(reloaded.public_chain.balance_index.values()) + reloaded.public_chain.treasury_balance,
                    520 * 25.0,
                )
                self.assertTrue(reloaded.public_chain.is_valid())
                self.assertAlmostEqual(reloaded.public_chain.total_minted_supply(), 520 * 25.0)
                self.assertAlmostEqual(
                    sum(reloaded.public_chain.balance_index.values()) + reloaded.public_chain.treasury_balance,
                    520 * 25.0,
                )

                next_validator = reloaded.public_chain.expected_next_validator()
                reloaded.public_chain.mine_pending_transactions(next_validator)

                self.assertEqual(reloaded.public_chain.blocks_mined_total(), 521)
                self.assertEqual(reloaded.public_chain.total_confirmed_public_transactions(), 521)
                self.assertAlmostEqual(reloaded.public_chain.total_minted_supply(), 521 * 25.0)
                self.assertAlmostEqual(
                    sum(reloaded.public_chain.balance_index.values()) + reloaded.public_chain.treasury_balance,
                    521 * 25.0,
                )
                self.assertAlmostEqual(
                    reloaded.public_chain.get_balance(next_validator),
                    261 * 22.5,
                )
            finally:
                reloaded.stop_background_workers()

    def test_pruned_public_chain_backfills_metric_fields_on_reload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            validator_1 = create_wallet("validator1")
            validator_2 = create_wallet("validator2")
            node = DualChainNode(
                data_dir=tmp,
                public_difficulty=1,
                public_reward=25.0,
                public_consensus="poa",
                public_validators=[validator_1["address"], validator_2["address"]],
                public_validator_rotation=True,
            )
            try:
                for _ in range(520):
                    node.public_chain.mine_pending_transactions(node.public_chain.expected_next_validator())
            finally:
                node.stop_background_workers()

            state_path = f"{tmp}/public_chain.json"
            with open(state_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            data.pop("public_tx_count_total", None)
            data.pop("total_minted_supply", None)
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump(data, f, separators=(",", ":"))

            reloaded = DualChainNode(
                data_dir=tmp,
                public_difficulty=1,
                public_reward=25.0,
                public_consensus="poa",
                public_validators=[validator_1["address"], validator_2["address"]],
                public_validator_rotation=True,
            )
            try:
                self.assertEqual(reloaded.public_chain.total_confirmed_public_transactions(), 520)
                self.assertAlmostEqual(reloaded.public_chain.total_minted_supply(), 520 * 25.0)
            finally:
                reloaded.stop_background_workers()

    def test_mainnet_hardening_requires_two_validators_and_no_faucet(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            validator_1 = create_wallet("validator1")
            with self.assertRaises(ValueError):
                DualChainNode(
                    data_dir=f"{tmp}/case1",
                    public_difficulty=1,
                    public_reward=5.0,
                    public_consensus="poa",
                    public_validators=[validator_1["address"]],
                    mainnet_hardening=True,
                )

            validator_2 = create_wallet("validator2")
            with self.assertRaises(ValueError):
                DualChainNode(
                    data_dir=f"{tmp}/case2",
                    public_difficulty=1,
                    public_reward=5.0,
                    public_consensus="poa",
                    public_validators=[validator_1["address"], validator_2["address"]],
                    mainnet_hardening=True,
                    public_faucet_enabled=True,
                )

            node = DualChainNode(
                data_dir=f"{tmp}/case3",
                public_difficulty=1,
                public_reward=5.0,
                public_consensus="poa",
                public_validators=[validator_1["address"], validator_2["address"]],
                public_validator_rotation=True,
                mainnet_hardening=True,
            )
            self.assertTrue(node.mainnet_hardening)
            node.stop_background_workers()

    def test_portal_auth_and_dashboard_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            node = DualChainNode(
                data_dir=tmp,
                public_difficulty=1,
                public_reward=5.0,
                public_consensus="poa",
                public_validators=[],
            )
            try:
                v1 = create_wallet("validator1")
                v2 = create_wallet("validator2")
                issuer = create_wallet("issuer")
                owner = create_wallet("owner")
                buyer = create_wallet("buyer")

                save_wallet(v1, f"{node.wallet_dir}/validator1.json")
                save_wallet(v2, f"{node.wallet_dir}/validator2.json")
                save_wallet(issuer, f"{node.wallet_dir}/issuer.json")
                save_wallet(owner, f"{node.wallet_dir}/owner.json")
                save_wallet(buyer, f"{node.wallet_dir}/buyer.json")

                node.private_chain.register_wallet(v1, roles=["participant", "validator", "notary"], domains=["rwa-us"])
                node.private_chain.register_wallet(v2, roles=["participant", "validator", "notary"], domains=["rwa-us"])
                node.private_chain.register_wallet(issuer, roles=["participant", "issuer"], domains=["rwa-us"])
                node.private_chain.register_wallet(owner, roles=["participant"], domains=["rwa-us"])
                node.private_chain.register_wallet(buyer, roles=["participant"], domains=["rwa-us"])

                proposal = node.private_chain.propose_governance(
                    v1,
                    "create_domain",
                    {
                        "domain_id": "rwa-us",
                        "members": [issuer["address"], owner["address"], buyer["address"], v1["address"], v2["address"]],
                    },
                )
                node.private_chain.approve_governance(proposal["id"], v2)
                proposal = node.private_chain.propose_governance(
                    v1,
                    "deploy_contract",
                    {"domain_id": "rwa-us", "contract_id": "rwa-standard-v1", "rules": {"allow_transfer": True}},
                )
                node.private_chain.approve_governance(proposal["id"], v2)

                tx = make_asset_issue_tx(
                    issuer_wallet=issuer,
                    asset_id="RWA-1",
                    amount=100.0,
                    owner=owner["address"],
                    domain="rwa-us",
                    contract_id="rwa-standard-v1",
                )
                node.private_chain.add_transaction(tx)
                block = node.private_chain.seal_pending_transactions(v1)
                node.private_chain.attest_block(block.hash, v2, auto_finalize=True)

                now = time.time()
                node.rwa_listings = [
                    {
                        "id": "LST-1",
                        "status": "open",
                        "created_at": now,
                        "updated_at": now,
                        "seller_wallet_name": "owner",
                        "seller_address": owner["address"],
                        "asset_id": "RWA-1",
                        "title": "RWA-1 Listing",
                        "description": "",
                        "currency": "USD",
                        "price_per_unit": 2.5,
                        "quantity_total": 20.0,
                        "quantity_available": 10.0,
                        "visibility": [],
                        "asset_meta": {},
                        "trades": [
                            {
                                "tx_id": "tx-1",
                                "buyer_wallet_name": "buyer",
                                "buyer_address": buyer["address"],
                                "amount": 10.0,
                                "price_per_unit": 2.5,
                                "total_price": 25.0,
                                "currency": "USD",
                                "timestamp": now,
                                "block_hash": block.hash,
                                "block_index": block.index,
                                "finalized": True,
                            }
                        ],
                    }
                ]

                user = node.register_portal_user("alice.user", "password123", wallet_names=["owner", "buyer"])
                self.assertEqual(user["username"], "alice.user")
                login = node.portal_login("alice.user", "password123")
                self.assertTrue(login["token"].startswith("rwa_sess_"))

                me = node.portal_session_user(login["token"])
                dash = node.portal_dashboard(me["username"])
                self.assertEqual(dash["summary"]["wallet_count"], 2)
                self.assertEqual(dash["summary"]["listed_count"], 1)
                self.assertEqual(dash["summary"]["bought_trade_count"], 1)
                self.assertEqual(dash["summary"]["sold_trade_count"], 1)
                self.assertGreaterEqual(dash["summary"]["total_units_held"], 100.0)
            finally:
                node.stop_background_workers()

    def test_rwa_access_pass_create_resolve_and_snapshot_sync(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            node_a = DualChainNode(
                data_dir=f"{tmp}/a",
                public_difficulty=1,
                public_reward=5.0,
                public_consensus="poa",
                public_validators=[],
            )
            node_b = DualChainNode(
                data_dir=f"{tmp}/b",
                public_difficulty=1,
                public_reward=5.0,
                public_consensus="poa",
                public_validators=[],
            )
            try:
                created = node_a.create_rwa_access_pass(
                    creator_wallet_name="owner1",
                    creator_address="Wowner",
                    listing_id="LST-123",
                    asset_id="RWA-XYZ",
                    domain_id="rwa-domain",
                    max_uses=2,
                    max_units=50.0,
                    expires_at=0.0,
                    note="test pass",
                    bind_on_first_use=True,
                )
                secret = created["access_code"]
                row = node_a.resolve_access_pass(secret)
                self.assertIsNotNone(row)
                self.assertEqual(str(row.get("listing_id")), "LST-123")
                self.assertIsNone(node_a.resolve_access_pass("bad-code"))

                snapshot = node_a.snapshot()
                changed = node_b.adopt_snapshot_if_better(snapshot)
                self.assertTrue(changed["rwa_access_passes"])
                listed = node_b.list_rwa_access_passes(listing_id="LST-123", include_inactive=True)
                self.assertEqual(len(listed), 1)
                self.assertNotIn("code_hash", listed[0])
                self.assertNotIn("code_salt", listed[0])
            finally:
                node_a.stop_background_workers()
                node_b.stop_background_workers()


if __name__ == "__main__":
    unittest.main(verbosity=2)
