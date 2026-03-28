import tempfile
import time
import unittest
from pathlib import Path

from eth_account import Account

from dual_chain import (
    PrivateAssetChain,
    PublicPaymentChain,
    make_ai_job_create_tx,
    make_ai_job_result_tx,
    make_ai_job_settle_tx,
    make_ai_model_register_tx,
    make_ai_provider_slash_tx,
    make_ai_provider_stake_tx,
    create_wallet,
    make_asset_issue_tx,
    make_asset_transfer_tx,
    make_payment_tx,
    make_payment_tx_with_fee,
    move_wallet_private_key_to_file_hsm,
    verify_signature,
)


class DualChainTests(unittest.TestCase):
    @staticmethod
    def _make_signed_evm_payment(
        sender_key: bytes,
        recipient_evm: str,
        amount_native: float,
        nonce: int,
        gas_limit: int = 21000,
        gas_price_wei: int = 1_000_000_000,
        chain_id: int = 149,
    ) -> dict:
        sender = Account.from_key(sender_key).address.lower()
        recipient = str(recipient_evm).lower()
        value_wei = int(round(float(amount_native) * 10**18))
        signed = Account.sign_transaction(
            {
                "type": 2,
                "chainId": int(chain_id),
                "nonce": int(nonce),
                "maxPriorityFeePerGas": int(gas_price_wei),
                "maxFeePerGas": int(gas_price_wei),
                "gas": int(gas_limit),
                "to": recipient,
                "value": int(value_wei),
                "data": "0x",
            },
            sender_key,
        )
        tx_hash = signed.hash.hex()
        if not tx_hash.startswith("0x"):
            tx_hash = "0x" + tx_hash
        return {
            "id": tx_hash,
            "type": "evm_payment",
            "sender": f"EVM:{sender}",
            "recipient": f"EVM:{recipient}",
            "amount": float(amount_native),
            "timestamp": time.time(),
            "sender_evm": sender,
            "recipient_evm": recipient,
            "value_wei": str(value_wei),
            "nonce": int(nonce),
            "gas_limit": int(gas_limit),
            "gas_price_wei": int(gas_price_wei),
            "max_fee_per_gas_wei": int(gas_price_wei),
            "max_priority_fee_per_gas_wei": int(gas_price_wei),
            "raw_tx": signed.raw_transaction.hex(),
            "evm_type": 2,
            "chain_id": int(chain_id),
        }

    def test_wallet_hsm_signing_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            wallet = create_wallet("alice", scheme="ed25519")
            migrated = move_wallet_private_key_to_file_hsm(
                wallet=wallet,
                key_ref="alice-k1",
                hsm_dir=str(Path(tmp) / "hsm"),
            )

            tx = make_payment_tx(migrated, recipient="Wbob", amount=1.5)
            signable = {
                "type": "payment",
                "sender": tx["sender"],
                "recipient": tx["recipient"],
                "amount": tx["amount"],
                "timestamp": tx["timestamp"],
            }
            self.assertTrue(verify_signature(signable, tx["signature"], tx["pubkey"]))

    def test_public_chain_flow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            chain = PublicPaymentChain(chain_file=str(Path(tmp) / "public.json"), difficulty=1, mining_reward=10)
            alice = create_wallet("alice")
            bob = create_wallet("bob")

            chain.mine_pending_transactions(alice["address"])
            chain.add_transaction(make_payment_tx(alice, bob["address"], 4))
            chain.mine_pending_transactions(alice["address"])

            self.assertAlmostEqual(chain.get_balance(alice["address"]), 16.0)
            self.assertAlmostEqual(chain.get_balance(bob["address"]), 4.0)
            self.assertTrue(chain.is_valid())

    def test_public_chain_poa_validator_flow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            alice = create_wallet("alice")
            bob = create_wallet("bob")
            validator = alice["address"]
            chain = PublicPaymentChain(
                chain_file=str(Path(tmp) / "public-poa.json"),
                difficulty=1,
                mining_reward=5,
                consensus="poa",
                validators=[validator],
            )

            with self.assertRaises(ValueError):
                chain.mine_pending_transactions("Wnot-validator")

            chain.mine_pending_transactions(validator)
            chain.add_transaction(make_payment_tx(alice, bob["address"], 1.0))
            with self.assertRaises(ValueError):
                chain.mine_pending_transactions("Wnot-validator")
            chain.mine_pending_transactions(validator)
            self.assertTrue(chain.is_valid())

    def test_private_governance_contracts_notary_finality_and_privacy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            chain = PrivateAssetChain(chain_file=str(Path(tmp) / "private.json"))

            v1 = create_wallet("v1")
            v2 = create_wallet("v2")
            issuer = create_wallet("issuer")
            alice = create_wallet("alice")
            bob = create_wallet("bob")
            outsider = create_wallet("outsider")

            chain.register_wallet(v1, roles=["participant", "validator", "notary"])
            chain.register_wallet(v2, roles=["participant", "validator", "notary"])

            def propose_and_approve(action: str, payload: dict) -> None:
                proposal = chain.propose_governance(v1, action, payload)
                chain.approve_governance(proposal["id"], v2)

            propose_and_approve(
                "register_participant",
                {"wallet": alice, "roles": ["participant"]},
            )
            propose_and_approve(
                "register_participant",
                {"wallet": bob, "roles": ["participant"]},
            )
            propose_and_approve(
                "register_participant",
                {"wallet": issuer, "roles": ["participant", "issuer"]},
            )
            propose_and_approve(
                "register_participant",
                {"wallet": outsider, "roles": ["participant"]},
            )
            propose_and_approve(
                "create_domain",
                {"domain_id": "rwa-us", "members": [issuer["address"], alice["address"], bob["address"]]},
            )
            propose_and_approve(
                "deploy_contract",
                {
                    "domain_id": "rwa-us",
                    "contract_id": "allow-bob-max100",
                    "rules": {
                        "allowed_recipients": [bob["address"]],
                        "max_transfer_amount": 100,
                    },
                },
            )
            propose_and_approve(
                "set_thresholds",
                {"finality_threshold": 2},
            )

            issue_tx = make_asset_issue_tx(
                issuer_wallet=issuer,
                asset_id="RWA-BOND-01",
                amount=500,
                owner=alice["address"],
                domain="rwa-us",
                contract_id="allow-bob-max100",
                visibility=[alice["address"], bob["address"]],
            )
            chain.add_transaction(issue_tx)
            pending_block_1 = chain.seal_pending_transactions(v1)
            self.assertEqual(len(chain.pending_blocks), 1)
            chain.attest_block(pending_block_1.hash, v2)
            self.assertEqual(len(chain.pending_blocks), 0)
            already_finalized = chain.attest_block(pending_block_1.hash, v2)
            self.assertTrue(already_finalized.get("already_finalized"))
            self.assertTrue(already_finalized.get("finalized"))

            transfer_tx = make_asset_transfer_tx(
                owner_wallet=alice,
                asset_id="RWA-BOND-01",
                amount=90,
                recipient=bob["address"],
                visibility=[alice["address"], bob["address"]],
            )
            chain.add_transaction(transfer_tx)
            pending_block_2 = chain.seal_pending_transactions(v1)
            chain.attest_block(pending_block_2.hash, v2)

            with self.assertRaises(ValueError):
                chain.add_transaction(
                    make_asset_transfer_tx(
                        owner_wallet=alice,
                        asset_id="RWA-BOND-01",
                        amount=150,
                        recipient=bob["address"],
                        visibility=[alice["address"], bob["address"]],
                    )
                )

            balances = chain.get_asset_balances()
            self.assertAlmostEqual(balances[alice["address"]]["RWA-BOND-01"], 410.0)
            self.assertAlmostEqual(balances[bob["address"]]["RWA-BOND-01"], 90.0)

            outsider_view = chain.get_private_view(outsider["address"])
            tx_count_seen = sum(len(block["transactions"]) for block in outsider_view["chain"])
            self.assertEqual(tx_count_seen, 0)

            self.assertTrue(chain.is_valid())

    def test_public_chain_evm_payment_flow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            chain = PublicPaymentChain(chain_file=str(Path(tmp) / "public.json"), difficulty=1, mining_reward=10)
            sender_account = Account.create()
            sender_ledger = f"EVM:{sender_account.address.lower()}"
            recipient_ledger = "EVM:0x2222222222222222222222222222222222222222"

            chain.mine_pending_transactions(sender_ledger)
            evm_tx = self._make_signed_evm_payment(
                sender_key=sender_account.key,
                recipient_evm="0x2222222222222222222222222222222222222222",
                amount_native=3.0,
                nonce=0,
                gas_limit=21000,
                gas_price_wei=1_000_000_000,
            )
            chain.add_transaction(evm_tx)
            chain.mine_pending_transactions(recipient_ledger)

            self.assertAlmostEqual(chain.get_balance(sender_ledger), 6.999979, places=6)
            self.assertAlmostEqual(chain.get_balance(recipient_ledger), 13.000021, places=6)

            replay = dict(evm_tx)
            replay["id"] = "0x" + ("b" * 64)
            replay["timestamp"] = time.time()
            with self.assertRaises(ValueError):
                chain.add_transaction(replay)

    def test_public_chain_evm_address_case_insensitive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            chain = PublicPaymentChain(chain_file=str(Path(tmp) / "public-case.json"), difficulty=1, mining_reward=10)
            sender_account = Account.create()
            sender_mixed = f"EVM:{sender_account.address}"
            sender_lower = f"EVM:{sender_account.address.lower()}"
            recipient = "EVM:0x2222222222222222222222222222222222222222"

            chain.mine_pending_transactions(sender_mixed)
            self.assertAlmostEqual(chain.get_balance(sender_lower), 10.0)

            tx = self._make_signed_evm_payment(
                sender_key=sender_account.key,
                recipient_evm="0x2222222222222222222222222222222222222222",
                amount_native=1.0,
                nonce=0,
                gas_limit=21000,
                gas_price_wei=1_000_000_000,
            )
            chain.add_transaction(tx)
            chain.mine_pending_transactions(sender_lower)
            self.assertTrue(chain.is_valid())

    def test_public_payment_to_mixed_case_evm_prefix_is_canonicalized_before_sign(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            chain = PublicPaymentChain(chain_file=str(Path(tmp) / "public-payment-case.json"), difficulty=1, mining_reward=10)
            alice = create_wallet("alice")
            recipient_mixed = "EVM:0xF9a1e0774f1ceD31108729D16985D47a3D03D3eA"
            recipient_lower = "EVM:0xf9a1e0774f1ced31108729d16985d47a3d03d3ea"

            chain.mine_pending_transactions(alice["address"])
            tx = make_payment_tx(alice, recipient_mixed, 1.0)
            self.assertEqual(tx["recipient"], recipient_lower)

            chain.add_transaction(tx)
            chain.mine_pending_transactions(alice["address"])

            self.assertAlmostEqual(chain.get_balance(recipient_lower), 1.0)
            self.assertTrue(chain.is_valid())

    def test_public_miner_address_normalized_for_evm(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            chain = PublicPaymentChain(chain_file=str(Path(tmp) / "public-miner-normalized.json"), difficulty=1, mining_reward=10)
            mixed = "EVM:0xAbCdEf0000000000000000000000000000000001"
            lower = "EVM:0xabcdef0000000000000000000000000000000001"
            chain.mine_pending_transactions(mixed)
            self.assertAlmostEqual(chain.get_balance(lower), 10.0)

    def test_public_mempool_ttl_prunes_old_pending(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            alice = create_wallet("alice")
            bob = create_wallet("bob")
            chain = PublicPaymentChain(
                chain_file=str(Path(tmp) / "public-mempool-ttl.json"),
                difficulty=1,
                mining_reward=5,
                mempool_tx_ttl_seconds=0.05,
                mempool_max_transactions=100,
            )

            chain.mine_pending_transactions(alice["address"])
            tx = make_payment_tx(alice, bob["address"], 1.0)
            chain.add_transaction(tx)
            self.assertEqual(len(chain.pending_transactions), 1)
            time.sleep(0.08)
            pruned = chain.prune_mempool(force_persist=True)
            self.assertGreaterEqual(pruned["expired"], 1)
            self.assertEqual(len(chain.pending_transactions), 0)

    def test_public_mempool_max_size_evicts_low_fee_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            alice = create_wallet("alice")
            bob = create_wallet("bob")
            chain = PublicPaymentChain(
                chain_file=str(Path(tmp) / "public-mempool-cap.json"),
                difficulty=1,
                mining_reward=5,
                mempool_tx_ttl_seconds=600,
                mempool_max_transactions=2,
            )

            chain.mine_pending_transactions(alice["address"])
            low = make_payment_tx_with_fee(alice, bob["address"], 1.0, fee=0.01)
            high = make_payment_tx_with_fee(alice, bob["address"], 1.0, fee=0.20)
            mid = make_payment_tx_with_fee(alice, bob["address"], 1.0, fee=0.05)
            chain.add_transaction(low)
            chain.add_transaction(high)
            chain.add_transaction(mid)

            pending_ids = {tx["id"] for tx in chain.pending_transactions}
            self.assertEqual(len(pending_ids), 2)
            self.assertIn(high["id"], pending_ids)
            self.assertIn(mid["id"], pending_ids)
            self.assertNotIn(low["id"], pending_ids)

    def test_public_pow_parallel_workers_mine_valid_block(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            alice = create_wallet("alice")
            chain = PublicPaymentChain(
                chain_file=str(Path(tmp) / "public-pow-parallel.json"),
                difficulty=1,
                mining_reward=5,
                consensus="pow",
                pow_parallel_workers=2,
                pow_nonce_chunk_size=256,
            )

            chain.mine_pending_transactions(alice["address"])
            self.assertGreaterEqual(len(chain.chain), 2)
            self.assertTrue(chain.chain[-1].hash.startswith("0"))
            self.assertEqual(chain.pow_parallel_workers, 2)
            self.assertTrue(chain.is_valid())

    def test_public_fee_priority_and_rotation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            v1 = create_wallet("v1")
            v2 = create_wallet("v2")
            alice = create_wallet("alice")
            bob = create_wallet("bob")

            chain = PublicPaymentChain(
                chain_file=str(Path(tmp) / "public-priority.json"),
                difficulty=1,
                mining_reward=5,
                consensus="poa",
                validators=[v1["address"], v2["address"]],
                validator_rotation=True,
                finality_confirmations=2,
                checkpoint_interval=2,
            )

            proposer_1 = chain.expected_next_validator()
            chain.mine_pending_transactions(proposer_1)
            proposer_2 = chain.expected_next_validator()
            with self.assertRaises(ValueError):
                chain.mine_pending_transactions(proposer_1)
            chain.mine_pending_transactions(proposer_2)

            chain.add_transaction(make_payment_tx(v1, alice["address"], 4.0))
            chain.mine_pending_transactions(chain.expected_next_validator())

            low = make_payment_tx_with_fee(alice, bob["address"], 1.0, fee=0.01)
            high = make_payment_tx_with_fee(alice, bob["address"], 1.0, fee=0.2)
            chain.add_transaction(low)
            chain.add_transaction(high)
            block = chain.mine_pending_transactions(chain.expected_next_validator())

            self.assertEqual(block.transactions[0]["id"], high["id"])
            self.assertEqual(block.transactions[1]["id"], low["id"])
            self.assertEqual(block.meta.get("finality_confirmations"), 2)
            self.assertGreaterEqual(block.meta.get("finalized_height", 0), 0)
            self.assertTrue(chain.is_valid())
            perf = chain.performance_summary(window_blocks=10)
            self.assertGreaterEqual(perf["height"], 1)
            self.assertIn("estimated_tps", perf)

    def test_public_ai_stake_and_slash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            validator = create_wallet("validator")
            provider = create_wallet("provider")
            chain = PublicPaymentChain(
                chain_file=str(Path(tmp) / "public-ai-stake.json"),
                difficulty=1,
                mining_reward=5,
                consensus="poa",
                validators=[validator["address"]],
            )

            chain.mine_pending_transactions(validator["address"])
            chain.add_transaction(make_payment_tx(validator, provider["address"], 3.0))
            chain.mine_pending_transactions(validator["address"])

            stake_tx = make_ai_provider_stake_tx(provider, 2.0)
            chain.add_transaction(stake_tx)
            chain.mine_pending_transactions(validator["address"])

            self.assertAlmostEqual(chain.get_provider_stakes()["stakes"][provider["address"]], 2.0)

            slash_tx = make_ai_provider_slash_tx(
                validator_wallet=validator,
                provider=provider["address"],
                amount=1.0,
                reason="bad-result",
            )
            chain.add_transaction(slash_tx)
            chain.mine_pending_transactions(validator["address"])
            self.assertAlmostEqual(chain.get_provider_stakes()["stakes"][provider["address"]], 1.0)
            self.assertTrue(chain.is_valid())

    def test_private_domain_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            chain = PrivateAssetChain(chain_file=str(Path(tmp) / "private-domains.json"))
            issuer = create_wallet("issuer")
            alice = create_wallet("alice")
            validator = create_wallet("validator")
            notary = create_wallet("notary")

            chain.register_wallet(issuer, roles=["participant", "issuer"])
            chain.register_wallet(alice, roles=["participant"])
            chain.register_wallet(validator, roles=["participant", "validator"])
            chain.register_wallet(notary, roles=["participant", "notary"])
            chain.create_domain("rwa-us", [issuer["address"], alice["address"]], created_by=validator["address"])

            tx = make_asset_issue_tx(
                issuer_wallet=issuer,
                asset_id="RWA-1",
                amount=100,
                owner=alice["address"],
                domain="rwa-us",
                metadata_hash="abc123",
                metadata={"valuation_amount": 1000000, "valuation_currency": "USD"},
            )
            chain.add_transaction(tx)
            block = chain.seal_pending_transactions(validator)

            summary = chain.domain_summary("rwa-us")
            self.assertEqual(summary["count"], 1)
            row = summary["domains"][0]
            self.assertEqual(row["domain_id"], "rwa-us")
            self.assertGreaterEqual(row["asset_count"], 1)
            self.assertGreaterEqual(row["tx_count_chain"], 1)
            holdings, assets = chain._build_asset_state()  # pylint: disable=protected-access
            self.assertIn("RWA-1", assets)
            self.assertEqual(assets["RWA-1"]["metadata_hash"], "abc123")
            self.assertEqual(assets["RWA-1"]["metadata"]["valuation_currency"], "USD")

    def test_private_ai_model_and_job_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            chain = PrivateAssetChain(chain_file=str(Path(tmp) / "private-ai.json"))
            v1 = create_wallet("v1")
            v2 = create_wallet("v2")
            owner = create_wallet("owner")
            requester = create_wallet("requester")
            provider = create_wallet("provider")

            chain.register_wallet(v1, roles=["participant", "validator"])
            chain.register_wallet(v2, roles=["participant", "validator", "notary"])
            chain.register_wallet(owner, roles=["participant"])
            chain.register_wallet(requester, roles=["participant"])
            chain.register_wallet(provider, roles=["participant"])

            model_tx = make_ai_model_register_tx(
                owner_wallet=owner,
                model_id="model-sentiment-v1",
                model_hash="sha256:abc123",
                version="1.0.0",
                price_per_call=0.25,
                visibility=[owner["address"], requester["address"], provider["address"]],
            )
            chain.add_transaction(model_tx)
            block = chain.seal_pending_transactions(v1)

            create_tx = make_ai_job_create_tx(
                requester_wallet=requester,
                job_id="job-1",
                model_id="model-sentiment-v1",
                input_hash="sha256:input",
                max_payment=1.0,
                visibility=[requester["address"], provider["address"]],
            )
            chain.add_transaction(create_tx)
            block = chain.seal_pending_transactions(v1)

            result_tx = make_ai_job_result_tx(
                provider_wallet=provider,
                job_id="job-1",
                result_hash="sha256:result",
                quality_score=0.99,
            )
            chain.add_transaction(result_tx)
            block = chain.seal_pending_transactions(v1)

            settle_tx = make_ai_job_settle_tx(
                settler_wallet=v1,
                job_id="job-1",
                payout=0.9,
                slash_provider=0.0,
                reason="success",
            )
            chain.add_transaction(settle_tx)
            block = chain.seal_pending_transactions(v1)

            models = chain.list_ai_models()
            jobs = chain.list_ai_jobs()
            self.assertEqual(models["count"], 1)
            self.assertEqual(jobs["count"], 1)
            self.assertEqual(jobs["jobs"][0]["status"], "settled")
            self.assertTrue(chain.is_valid())


if __name__ == "__main__":
    unittest.main(verbosity=2)
