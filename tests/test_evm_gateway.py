import unittest

from eth_account import Account

from evm_gateway import (
    JsonRpcGatewayHandler,
    as_wei,
    evm_to_ledger_account,
    is_evm_hex_address,
    iter_known_native_addresses,
    ledger_to_evm_address,
    native_to_evm_address,
    tx_from_to,
)


class EvmGatewayHelperTests(unittest.TestCase):
    def test_native_to_evm_address_is_deterministic(self) -> None:
        a1 = native_to_evm_address("Walice")
        a2 = native_to_evm_address("Walice")
        self.assertEqual(a1, a2)
        self.assertTrue(a1.startswith("0x"))
        self.assertEqual(len(a1), 42)

    def test_as_wei(self) -> None:
        self.assertEqual(as_wei(1), 10**18)
        self.assertEqual(as_wei("2.5"), 2500000000000000000)
        self.assertEqual(as_wei(-1), 0)

    def test_tx_from_to_mapping(self) -> None:
        sender, recipient = tx_from_to({"type": "payment", "sender": "W1", "recipient": "W2"})
        self.assertEqual(sender, "W1")
        self.assertEqual(recipient, "W2")

        sender, recipient = tx_from_to(
            {
                "type": "evm_payment",
                "sender_evm": "0x1111111111111111111111111111111111111111",
                "recipient_evm": "0x2222222222222222222222222222222222222222",
            }
        )
        self.assertEqual(sender, "0x1111111111111111111111111111111111111111")
        self.assertEqual(recipient, "0x2222222222222222222222222222222222222222")

        sender, recipient = tx_from_to({"type": "price_update", "oracle": "W3"})
        self.assertEqual(sender, "W3")
        self.assertTrue(recipient.startswith("0x"))

    def test_iter_known_native_addresses(self) -> None:
        state = {
            "chain": [
                {
                    "transactions": [
                        {"type": "payment", "sender": "Walice", "recipient": "Wbob"},
                        {"type": "price_update", "oracle": "Woracle"},
                    ]
                }
            ]
        }
        out = iter_known_native_addresses(state)
        self.assertIn("Walice", out)
        self.assertIn("Wbob", out)
        self.assertIn("Woracle", out)

    def test_evm_ledger_mapping(self) -> None:
        address = "0x1234567890abcdef1234567890abcdef12345678"
        self.assertTrue(is_evm_hex_address(address))
        ledger = evm_to_ledger_account(address)
        self.assertEqual(ledger, "EVM:0x1234567890abcdef1234567890abcdef12345678")
        self.assertEqual(ledger_to_evm_address(ledger), address)

    def test_decode_raw_transaction(self) -> None:
        acct = Account.create()
        signed = Account.sign_transaction(
            {
                "type": 2,
                "chainId": 77001,
                "nonce": 0,
                "maxPriorityFeePerGas": 1_000_000_000,
                "maxFeePerGas": 2_000_000_000,
                "gas": 21000,
                "to": "0x2222222222222222222222222222222222222222",
                "value": 5 * 10**18,
                "data": "0x",
            },
            acct.key,
        )

        handler = object.__new__(JsonRpcGatewayHandler)
        handler.chain_id = 77001
        parsed = handler._decode_raw_transaction(signed.raw_transaction.hex())

        self.assertEqual(parsed["sender_evm"], Account.from_key(acct.key).address.lower())
        self.assertEqual(parsed["recipient_evm"], "0x2222222222222222222222222222222222222222")
        self.assertEqual(parsed["nonce"], 0)
        self.assertEqual(parsed["value_wei"], 5 * 10**18)

    def test_outgoing_count_includes_pending(self) -> None:
        handler = object.__new__(JsonRpcGatewayHandler)
        state = {
            "chain": [
                {"transactions": [{"type": "evm_payment", "sender_evm": "0x1111111111111111111111111111111111111111", "recipient_evm": "0x2222222222222222222222222222222222222222"}]}
            ],
            "pending_transactions": [
                {"type": "evm_payment", "sender_evm": "0x1111111111111111111111111111111111111111", "recipient_evm": "0x3333333333333333333333333333333333333333"}
            ],
        }
        ledger = "EVM:0x1111111111111111111111111111111111111111"
        self.assertEqual(handler._outgoing_count(ledger, state, include_pending=False), 1)
        self.assertEqual(handler._outgoing_count(ledger, state, include_pending=True), 2)

    def test_resolve_ledger_address_canonicalizes_evm(self) -> None:
        handler = object.__new__(JsonRpcGatewayHandler)
        state = {
            "chain": [
                {
                    "transactions": [
                        {
                            "type": "payment",
                            "sender": "SYSTEM",
                            "recipient": "EVM:0xAbCdEf0000000000000000000000000000000001",
                            "amount": 1,
                        }
                    ]
                }
            ]
        }
        self.assertEqual(
            handler._resolve_ledger_address("0xAbCdEf0000000000000000000000000000000001", state),
            "EVM:0xabcdef0000000000000000000000000000000001",
        )
        self.assertEqual(
            handler._resolve_ledger_address("EVM:0xAbCdEf0000000000000000000000000000000001", state),
            "EVM:0xabcdef0000000000000000000000000000000001",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
