import argparse
import hashlib
import json
import ssl
import time
from decimal import Decimal, InvalidOperation
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional
from urllib import parse, request

from eth_account import Account
from eth_account._utils.legacy_transactions import Transaction as LegacyTransaction
from eth_account.typed_transactions import TypedTransaction
from eth_utils import keccak as eth_keccak
from hexbytes import HexBytes

ZERO_ADDR = "0x" + ("0" * 40)
ZERO_HASH = "0x" + ("0" * 64)
ZERO_BLOOM = "0x" + ("0" * 512)
EVM_LEDGER_PREFIX = "EVM:"


class UnsupportedRpcMethod(Exception):
    pass


def hex_qty(value: int) -> str:
    if value < 0:
        raise ValueError("quantity must be non-negative")
    return hex(value)


def ensure_0x(value: str) -> str:
    raw = str(value or "").strip().lower()
    if raw.startswith("0x"):
        return raw
    return f"0x{raw}"


def is_evm_hex_address(value: str) -> bool:
    raw = str(value or "").strip().lower()
    if not raw.startswith("0x") or len(raw) != 42:
        return False
    return all(c in "0123456789abcdef" for c in raw[2:])


def evm_to_ledger_account(value: str) -> str:
    address = ensure_0x(value)
    if not is_evm_hex_address(address):
        raise ValueError("Invalid EVM address")
    return f"{EVM_LEDGER_PREFIX}{address.lower()}"


def ledger_to_evm_address(value: str) -> str:
    raw = str(value or "").strip()
    if raw.startswith(EVM_LEDGER_PREFIX):
        suffix = raw[len(EVM_LEDGER_PREFIX) :].strip().lower()
        address = ensure_0x(suffix)
        if is_evm_hex_address(address):
            return address
    if is_evm_hex_address(raw):
        return raw.lower()
    return native_to_evm_address(raw)


def native_to_evm_address(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ZERO_ADDR
    if raw.startswith(EVM_LEDGER_PREFIX):
        suffix = raw[len(EVM_LEDGER_PREFIX) :].strip()
        address = ensure_0x(suffix)
        if is_evm_hex_address(address):
            return address
    if raw.startswith("0x") and len(raw) == 42:
        return raw.lower()
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return "0x" + digest[-40:]


def as_wei(value: Any) -> int:
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return 0
    if amount <= 0:
        return 0
    return int(amount * Decimal(10**18))


def tx_input_data(tx: Dict[str, Any]) -> str:
    provided = str(tx.get("input", "")).strip()
    if provided.startswith("0x"):
        return provided
    minimal = {
        "type": tx.get("type", ""),
        "symbol": tx.get("symbol", ""),
        "asset_id": tx.get("asset_id", ""),
        "source": tx.get("source", ""),
    }
    raw = json.dumps(minimal, sort_keys=True).encode("utf-8").hex()
    return f"0x{raw}"


def _as_hex_signature_field(value: Any) -> str:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = 0
    return hex_qty(max(0, parsed))


def tx_from_to(tx: Dict[str, Any]) -> tuple[str, str]:
    tx_type = str(tx.get("type", ""))
    if tx_type == "evm_payment":
        return str(tx.get("sender_evm", "")), str(tx.get("recipient_evm", ""))
    if tx_type == "payment":
        return str(tx.get("sender", "")), str(tx.get("recipient", ""))
    if tx_type == "price_update":
        return str(tx.get("oracle", "")), ZERO_ADDR
    if tx_type == "asset_issue":
        return str(tx.get("issuer", "")), str(tx.get("owner", ""))
    if tx_type == "asset_transfer":
        return str(tx.get("from", "")), str(tx.get("to", ""))
    return str(tx.get("signer", tx.get("from", ""))), str(tx.get("to", ""))


def iter_known_native_addresses(chain_state: Dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for block in chain_state.get("chain", []):
        for tx in block.get("transactions", []):
            for key in ("sender", "recipient", "oracle", "issuer", "owner", "from", "to", "signer"):
                value = tx.get(key)
                if isinstance(value, str) and value:
                    out.add(value)
            for key in ("sender_evm", "recipient_evm"):
                value = tx.get(key)
                if isinstance(value, str) and is_evm_hex_address(value):
                    out.add(evm_to_ledger_account(value))
    return out


class NodeAdapter:
    def __init__(
        self,
        node_url: str,
        auth_token: str = "",
        timeout: float = 6.0,
        ssl_context: Optional[ssl.SSLContext] = None,
    ):
        self.node_url = node_url.rstrip("/")
        self.auth_token = auth_token
        self.timeout = timeout
        self.ssl_context = ssl_context

    def get(self, path: str) -> Dict[str, Any]:
        headers: Dict[str, str] = {}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        req = request.Request(f"{self.node_url}{path}", headers=headers, method="GET")
        with request.urlopen(req, timeout=self.timeout, context=self.ssl_context) as resp:
            body = resp.read().decode("utf-8")
        return json.loads(body) if body else {}

    def post(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        raw = json.dumps(payload).encode("utf-8")
        req = request.Request(f"{self.node_url}{path}", headers=headers, data=raw, method="POST")
        with request.urlopen(req, timeout=self.timeout, context=self.ssl_context) as resp:
            body = resp.read().decode("utf-8")
        return json.loads(body) if body else {}

    def status(self) -> Dict[str, Any]:
        return self.get("/status")

    def public_chain(self) -> Dict[str, Any]:
        return self.get("/public/chain")

    def public_balance(self, address: str) -> float:
        quoted = parse.quote(address, safe="")
        out = self.get(f"/public/balance?address={quoted}")
        return float(out.get("balance", 0.0))

    def scan_block_by_hash(self, block_hash: str) -> Optional[Dict[str, Any]]:
        quoted = parse.quote(block_hash, safe="")
        try:
            out = self.get(f"/scan/block?chain=public&hash={quoted}")
            return out.get("block")
        except Exception:
            return None

    def scan_block_by_index(self, index: int) -> Optional[Dict[str, Any]]:
        try:
            out = self.get(f"/scan/block?chain=public&index={index}")
            return out.get("block")
        except Exception:
            return None

    def scan_tx(self, tx_id: str) -> Optional[Dict[str, Any]]:
        quoted = parse.quote(str(tx_id).lower(), safe="")
        try:
            return self.get(f"/scan/tx?id={quoted}")
        except Exception:
            return None


class JsonRpcGatewayHandler(BaseHTTPRequestHandler):
    adapter: Optional[NodeAdapter] = None
    chain_id: int = 149
    client_version: str = "Nova-EVM-Gateway/0.1"
    gas_price_wei: int = 1_000_000_000
    cors_origin: str = "*"

    def _set_json_headers(self, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        if self.cors_origin:
            self.send_header("Access-Control-Allow-Origin", self.cors_origin)
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
            self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.end_headers()

    def _write_json(self, payload: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if self.cors_origin:
            self.send_header("Access-Control-Allow-Origin", self.cors_origin)
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
            self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def _rpc_error(self, req_id: Any, code: int, message: str, data: Any = None) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": code, "message": message},
        }
        if data is not None:
            payload["error"]["data"] = data
        return payload

    def _rpc_ok(self, req_id: Any, result: Any) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    def _to_eth_tx(
        self,
        tx: Dict[str, Any],
        block: Optional[Dict[str, Any]],
        tx_index: Optional[int],
    ) -> Dict[str, Any]:
        sender, recipient = tx_from_to(tx)
        tx_hash = ensure_0x(tx.get("id", ""))
        tx_type = str(tx.get("type", ""))
        evm_type = int(tx.get("evm_type", 0)) if tx_type == "evm_payment" else 0
        value_wei = as_wei(tx.get("amount", 0.0)) if tx_type in {"payment", "evm_payment"} else 0
        nonce_value = max(0, tx_index or 0)
        gas_limit = 21000
        gas_price_wei = self.gas_price_wei
        max_fee_per_gas = gas_price_wei
        max_priority_fee_per_gas = 0
        if tx_type == "evm_payment":
            try:
                nonce_value = int(tx.get("nonce", nonce_value))
            except (TypeError, ValueError):
                nonce_value = max(0, tx_index or 0)
            try:
                gas_limit = int(tx.get("gas_limit", gas_limit))
            except (TypeError, ValueError):
                gas_limit = 21000
            try:
                gas_price_wei = int(tx.get("gas_price_wei", gas_price_wei))
            except (TypeError, ValueError):
                gas_price_wei = self.gas_price_wei
            try:
                max_fee_per_gas = int(tx.get("max_fee_per_gas_wei", gas_price_wei))
            except (TypeError, ValueError):
                max_fee_per_gas = gas_price_wei
            try:
                max_priority_fee_per_gas = int(tx.get("max_priority_fee_per_gas_wei", 0))
            except (TypeError, ValueError):
                max_priority_fee_per_gas = 0
        sig_v = int(tx.get("sig_v", 0)) if str(tx.get("sig_v", "")).strip() != "" else 0
        sig_r = int(tx.get("sig_r", 0)) if str(tx.get("sig_r", "")).strip() != "" else 0
        sig_s = int(tx.get("sig_s", 0)) if str(tx.get("sig_s", "")).strip() != "" else 0
        if tx_type == "evm_payment" and (sig_r == 0 or sig_s == 0):
            raw_tx = str(tx.get("raw_tx", "")).strip()
            if raw_tx:
                try:
                    parsed = self._decode_raw_transaction(raw_tx)
                    sig_v = int(parsed.get("sig_v", sig_v))
                    sig_r = int(parsed.get("sig_r", sig_r))
                    sig_s = int(parsed.get("sig_s", sig_s))
                except Exception:
                    pass

        out: Dict[str, Any] = {
            "hash": tx_hash,
            "nonce": hex_qty(max(0, nonce_value)),
            "from": ledger_to_evm_address(sender),
            "to": ledger_to_evm_address(recipient),
            "value": hex_qty(value_wei),
            "gas": hex_qty(max(21000, gas_limit)),
            "gasPrice": hex_qty(max(0, gas_price_wei)),
            "input": tx_input_data(tx),
            "transactionIndex": None if tx_index is None else hex_qty(tx_index),
            "blockHash": None,
            "blockNumber": None,
            "chainId": hex_qty(self.chain_id),
            "type": hex_qty(max(evm_type, 0)),
            "v": _as_hex_signature_field(sig_v),
            "r": _as_hex_signature_field(sig_r),
            "s": _as_hex_signature_field(sig_s),
        }
        if evm_type in {2, 3}:
            out["maxFeePerGas"] = hex_qty(max(0, max_fee_per_gas))
            out["maxPriorityFeePerGas"] = hex_qty(max(0, max_priority_fee_per_gas))
            out["accessList"] = tx.get("access_list", [])
            out["yParity"] = hex_qty(sig_v & 1)
        if block:
            out["blockHash"] = ensure_0x(block.get("hash", ""))
            out["blockNumber"] = hex_qty(int(block.get("index", 0)))
        return out

    def _block_nonce_hex(self, nonce: Any) -> str:
        try:
            value = int(nonce)
        except (TypeError, ValueError):
            value = 0
        return "0x" + format(value & ((1 << 64) - 1), "016x")

    def _tx_root(self, tx_hashes: list[str]) -> str:
        digest = hashlib.sha256("".join(tx_hashes).encode("utf-8")).hexdigest()
        return ensure_0x(digest)

    def _to_eth_block(self, block: Dict[str, Any], full_tx: bool) -> Dict[str, Any]:
        txs = block.get("transactions", [])
        tx_hashes = [ensure_0x(tx.get("id", "")) for tx in txs]
        tx_payload = [self._to_eth_tx(tx, block, idx) for idx, tx in enumerate(txs)] if full_tx else tx_hashes

        return {
            "number": hex_qty(int(block.get("index", 0))),
            "hash": ensure_0x(block.get("hash", "")),
            "parentHash": ensure_0x(block.get("previous_hash", "")),
            "nonce": self._block_nonce_hex(block.get("nonce", 0)),
            "sha3Uncles": ZERO_HASH,
            "logsBloom": ZERO_BLOOM,
            "transactionsRoot": self._tx_root(tx_hashes),
            "stateRoot": ZERO_HASH,
            "receiptsRoot": ZERO_HASH,
            "miner": ledger_to_evm_address(str(block.get("meta", {}).get("miner", ""))),
            "difficulty": hex_qty(1),
            "totalDifficulty": hex_qty(int(block.get("index", 0)) + 1),
            "extraData": "0x",
            "size": hex_qty(len(json.dumps(block))),
            "gasLimit": hex_qty(30_000_000),
            "gasUsed": hex_qty(21000 * len(txs)),
            "timestamp": hex_qty(int(float(block.get("timestamp", 0.0)))),
            "transactions": tx_payload,
            "uncles": [],
            "baseFeePerGas": hex_qty(self.gas_price_wei),
        }

    def _resolve_ledger_address(self, query_address: str, chain_state: Dict[str, Any]) -> Optional[str]:
        raw = str(query_address or "").strip()
        if not raw:
            return None
        if raw.startswith(EVM_LEDGER_PREFIX):
            suffix = raw[len(EVM_LEDGER_PREFIX) :].strip().lower()
            if is_evm_hex_address(suffix):
                return evm_to_ledger_account(suffix)
            return f"{EVM_LEDGER_PREFIX}{suffix}"
        if is_evm_hex_address(raw):
            return evm_to_ledger_account(raw)
        if raw and raw[0].lower() == "w":
            return raw

        known = iter_known_native_addresses(chain_state)
        target = ensure_0x(raw).lower() if is_evm_hex_address(raw) else raw.lower()
        for native in known:
            if native_to_evm_address(native) == target:
                return native

        return None

    def _outgoing_count(self, ledger_address: str, chain_state: Dict[str, Any], include_pending: bool = False) -> int:
        count = 0
        for block in chain_state.get("chain", []):
            for tx in block.get("transactions", []):
                sender, _ = tx_from_to(tx)
                sender_ledger = sender
                if is_evm_hex_address(sender):
                    sender_ledger = evm_to_ledger_account(sender)
                if sender_ledger == ledger_address:
                    count += 1
        if include_pending:
            for tx in chain_state.get("pending_transactions", []):
                sender, _ = tx_from_to(tx)
                sender_ledger = sender
                if is_evm_hex_address(sender):
                    sender_ledger = evm_to_ledger_account(sender)
                if sender_ledger == ledger_address:
                    count += 1
        return count

    def _parse_block_tag(self, tag: Any, tip: int) -> int:
        if tag in (None, "latest", "pending"):
            return tip
        if tag == "earliest":
            return 0
        try:
            if isinstance(tag, str) and tag.startswith("0x"):
                return int(tag, 16)
            return int(tag)
        except (ValueError, TypeError):
            return tip

    def _decode_raw_transaction(self, raw_tx: str) -> Dict[str, Any]:
        if not raw_tx:
            raise ValueError("raw transaction is required")
        raw_hex = ensure_0x(raw_tx)
        raw_bytes = HexBytes(raw_hex)
        if len(raw_bytes) < 8:
            raise ValueError("raw transaction too short")

        sender_evm = Account.recover_transaction(raw_bytes).lower()
        tx_hash = eth_keccak(raw_bytes).hex()

        tx_payload: Dict[str, Any]
        first = raw_bytes[0]
        if first in {1, 2, 3}:
            typed = TypedTransaction.from_bytes(raw_bytes).as_dict()
            tx_payload = dict(typed)
            tx_payload["tx_type"] = int(first)
        else:
            legacy = LegacyTransaction.from_bytes(raw_bytes).as_dict()
            tx_payload = dict(legacy)
            tx_payload["tx_type"] = 0

        to_raw = tx_payload.get("to")
        recipient_evm = ZERO_ADDR
        if to_raw is not None:
            to_hex = HexBytes(to_raw).hex()
            if to_hex:
                recipient_evm = ensure_0x(to_hex[-40:].rjust(40, "0"))
        if recipient_evm == ZERO_ADDR:
            raise ValueError("Contract creation raw tx is not supported in this gateway yet.")

        value_wei = int(tx_payload.get("value", 0))
        if value_wei <= 0:
            raise ValueError("Only positive-value transfer raw tx is supported.")

        nonce = int(tx_payload.get("nonce", 0))
        gas_limit = int(tx_payload.get("gas", 21000))
        if "chainId" in tx_payload:
            chain_id = int(tx_payload.get("chainId", self.chain_id))
        else:
            try:
                v_value = int(tx_payload.get("v", 0))
                chain_id = (v_value - 35) // 2 if v_value >= 35 else self.chain_id
            except (TypeError, ValueError):
                chain_id = self.chain_id
        data_hex = "0x" + HexBytes(tx_payload.get("data", b"")).hex()
        max_fee_per_gas = int(tx_payload.get("maxFeePerGas", 0)) if "maxFeePerGas" in tx_payload else 0
        max_priority_fee_per_gas = (
            int(tx_payload.get("maxPriorityFeePerGas", 0)) if "maxPriorityFeePerGas" in tx_payload else 0
        )
        if "gasPrice" in tx_payload:
            gas_price_wei = int(tx_payload.get("gasPrice", self.gas_price_wei))
        elif max_fee_per_gas > 0:
            gas_price_wei = max_fee_per_gas
        else:
            gas_price_wei = self.gas_price_wei

        amount_native = Decimal(value_wei) / Decimal(10**18)
        try:
            sig_v = int(tx_payload.get("v", 0))
        except (TypeError, ValueError):
            sig_v = 0
        try:
            sig_r = int(tx_payload.get("r", 0))
        except (TypeError, ValueError):
            sig_r = 0
        try:
            sig_s = int(tx_payload.get("s", 0))
        except (TypeError, ValueError):
            sig_s = 0
        return {
            "tx_hash": tx_hash,
            "sender_evm": sender_evm,
            "recipient_evm": recipient_evm.lower(),
            "value_wei": value_wei,
            "amount_native": float(amount_native),
            "nonce": nonce,
            "gas_limit": gas_limit,
            "gas_price_wei": gas_price_wei,
            "max_fee_per_gas_wei": max_fee_per_gas if max_fee_per_gas > 0 else gas_price_wei,
            "max_priority_fee_per_gas_wei": max_priority_fee_per_gas,
            "chain_id": chain_id,
            "data": data_hex,
            "raw_tx": raw_hex,
            "tx_type": int(tx_payload.get("tx_type", 0)),
            "sig_v": sig_v,
            "sig_r": sig_r,
            "sig_s": sig_s,
        }

    def _submit_evm_payment_tx(self, raw_tx: str) -> str:
        if self.adapter is None:
            raise RuntimeError("gateway adapter not configured")

        parsed = self._decode_raw_transaction(raw_tx)
        if parsed["chain_id"] != self.chain_id:
            raise ValueError(
                f"Raw transaction chainId {parsed['chain_id']} does not match gateway chainId {self.chain_id}."
            )

        payload = {
            "id": parsed["tx_hash"],
            "type": "evm_payment",
            "sender": evm_to_ledger_account(parsed["sender_evm"]),
            "recipient": evm_to_ledger_account(parsed["recipient_evm"]),
            "amount": parsed["amount_native"],
            "timestamp": time.time(),
            "sender_evm": parsed["sender_evm"],
            "recipient_evm": parsed["recipient_evm"],
            "value_wei": str(parsed["value_wei"]),
            "nonce": int(parsed["nonce"]),
            "gas_limit": int(parsed["gas_limit"]),
            "gas_price_wei": int(parsed["gas_price_wei"]),
            "max_fee_per_gas_wei": int(parsed.get("max_fee_per_gas_wei", parsed["gas_price_wei"])),
            "max_priority_fee_per_gas_wei": int(parsed.get("max_priority_fee_per_gas_wei", 0)),
            "input": parsed["data"],
            "raw_tx": parsed["raw_tx"],
            "evm_type": int(parsed["tx_type"]),
            "chain_id": int(parsed["chain_id"]),
            "sig_v": int(parsed.get("sig_v", 0)),
            "sig_r": int(parsed.get("sig_r", 0)),
            "sig_s": int(parsed.get("sig_s", 0)),
        }
        out = self.adapter.post("/public/tx", payload)
        if out.get("ok") is not True:
            raise ValueError(out.get("error", "Upstream rejected transaction"))
        return ensure_0x(parsed["tx_hash"])

    def _handle_method(self, method: str, params: Any) -> Any:
        if self.adapter is None:
            raise RuntimeError("gateway adapter not configured")

        status = self.adapter.status()
        tip = int(status.get("public_height", 0))

        if method == "web3_clientVersion":
            return self.client_version
        if method == "net_version":
            return str(self.chain_id)
        if method == "eth_chainId":
            return hex_qty(self.chain_id)
        if method == "eth_blockNumber":
            return hex_qty(tip)
        if method == "eth_syncing":
            return False
        if method == "eth_mining":
            return False
        if method == "net_listening":
            return True
        if method == "net_peerCount":
            return hex_qty(0)
        if method == "eth_gasPrice":
            return hex_qty(self.gas_price_wei)
        if method == "eth_maxPriorityFeePerGas":
            return hex_qty(0)
        if method == "eth_estimateGas":
            return hex_qty(21000)
        if method == "eth_getLogs":
            return []
        if method == "eth_accounts":
            return []
        if method == "eth_call":
            return "0x"
        if method == "eth_getCode":
            return "0x"
        if method == "rpc_modules":
            return {"eth": "1.0", "net": "1.0", "web3": "1.0"}

        if method == "eth_feeHistory":
            block_count = 1
            reward_points = []
            if isinstance(params, list) and params:
                try:
                    block_count = int(str(params[0]), 16) if str(params[0]).startswith("0x") else int(params[0])
                except (ValueError, TypeError):
                    block_count = 1
                if len(params) > 2 and isinstance(params[2], list):
                    reward_points = params[2]
            block_count = max(1, min(1024, block_count))
            oldest = max(0, tip - block_count + 1)
            return {
                "oldestBlock": hex_qty(oldest),
                "baseFeePerGas": [hex_qty(self.gas_price_wei)] * (block_count + 1),
                "gasUsedRatio": [0.0] * block_count,
                "reward": [[hex_qty(0) for _ in reward_points] for _ in range(block_count)],
            }

        if method == "eth_getBlockByNumber":
            block_tag = params[0] if isinstance(params, list) and params else "latest"
            full_tx = bool(params[1]) if isinstance(params, list) and len(params) > 1 else False
            idx = self._parse_block_tag(block_tag, tip)
            block = self.adapter.scan_block_by_index(idx)
            if not block:
                return None
            return self._to_eth_block(block, full_tx)

        if method == "eth_getBlockTransactionCountByNumber":
            block_tag = params[0] if isinstance(params, list) and params else "latest"
            idx = self._parse_block_tag(block_tag, tip)
            block = self.adapter.scan_block_by_index(idx)
            if not block:
                return None
            return hex_qty(len(block.get("transactions", [])))

        if method == "eth_getBlockByHash":
            block_hash = params[0] if isinstance(params, list) and params else ""
            full_tx = bool(params[1]) if isinstance(params, list) and len(params) > 1 else False
            block = self.adapter.scan_block_by_hash(str(block_hash))
            if not block:
                return None
            return self._to_eth_block(block, full_tx)

        if method in {"eth_getUncleCountByBlockNumber", "eth_getUncleCountByBlockHash"}:
            return hex_qty(0)

        if method == "eth_getBlockTransactionCountByHash":
            block_hash = params[0] if isinstance(params, list) and params else ""
            block = self.adapter.scan_block_by_hash(str(block_hash))
            if not block:
                return None
            return hex_qty(len(block.get("transactions", [])))

        if method == "eth_getTransactionByBlockNumberAndIndex":
            block_tag = params[0] if isinstance(params, list) and params else "latest"
            idx_hex = params[1] if isinstance(params, list) and len(params) > 1 else "0x0"
            idx = self._parse_block_tag(block_tag, tip)
            tx_idx = int(str(idx_hex), 16) if str(idx_hex).startswith("0x") else int(idx_hex)
            block = self.adapter.scan_block_by_index(idx)
            if not block:
                return None
            txs = block.get("transactions", [])
            if tx_idx < 0 or tx_idx >= len(txs):
                return None
            return self._to_eth_tx(txs[tx_idx], block, tx_idx)

        if method == "eth_getTransactionByBlockHashAndIndex":
            block_hash = params[0] if isinstance(params, list) and params else ""
            idx_hex = params[1] if isinstance(params, list) and len(params) > 1 else "0x0"
            tx_idx = int(str(idx_hex), 16) if str(idx_hex).startswith("0x") else int(idx_hex)
            block = self.adapter.scan_block_by_hash(str(block_hash))
            if not block:
                return None
            txs = block.get("transactions", [])
            if tx_idx < 0 or tx_idx >= len(txs):
                return None
            return self._to_eth_tx(txs[tx_idx], block, tx_idx)

        if method == "eth_getTransactionByHash":
            tx_hash = params[0] if isinstance(params, list) and params else ""
            raw = str(tx_hash)
            if raw.startswith("0x"):
                raw = raw[2:]
            raw = raw.lower()
            hit = self.adapter.scan_tx(raw)
            if not hit:
                return None
            tx = hit.get("tx", {})
            loc = hit.get("location", {})
            block = None
            block_index = loc.get("block_index")
            if block_index is not None:
                block = self.adapter.scan_block_by_index(int(block_index))
            tx_index = loc.get("tx_index")
            return self._to_eth_tx(tx, block, int(tx_index) if tx_index is not None else None)

        if method == "eth_getTransactionReceipt":
            tx_hash = params[0] if isinstance(params, list) and params else ""
            raw = str(tx_hash)
            if raw.startswith("0x"):
                raw = raw[2:]
            raw = raw.lower()
            hit = self.adapter.scan_tx(raw)
            if not hit:
                return None
            loc = hit.get("location", {})
            if loc.get("block_hash") is None:
                return None
            tx = hit.get("tx", {})
            tx_index = int(loc.get("tx_index", 0))
            block_index = int(loc.get("block_index", 0))
            sender, recipient = tx_from_to(tx)
            tx_type = int(tx.get("evm_type", 0)) if str(tx.get("type", "")) == "evm_payment" else 0
            try:
                eff_gas_price = int(tx.get("gas_price_wei", self.gas_price_wei))
            except (TypeError, ValueError):
                eff_gas_price = self.gas_price_wei
            return {
                "transactionHash": ensure_0x(tx.get("id", "")),
                "transactionIndex": hex_qty(tx_index),
                "blockHash": ensure_0x(str(loc.get("block_hash", ""))),
                "blockNumber": hex_qty(block_index),
                "from": ledger_to_evm_address(sender),
                "to": ledger_to_evm_address(recipient),
                "cumulativeGasUsed": hex_qty(21000 * (tx_index + 1)),
                "gasUsed": hex_qty(21000),
                "contractAddress": None,
                "logs": [],
                "logsBloom": ZERO_BLOOM,
                "status": "0x1",
                "effectiveGasPrice": hex_qty(max(0, eff_gas_price)),
                "type": hex_qty(max(tx_type, 0)),
            }

        if method == "eth_getTransactionCount":
            address = params[0] if isinstance(params, list) and params else ""
            block_tag = params[1] if isinstance(params, list) and len(params) > 1 else "latest"
            chain_state = self.adapter.public_chain()
            ledger = self._resolve_ledger_address(str(address), chain_state)
            if not ledger:
                return hex_qty(0)
            include_pending = str(block_tag).lower() == "pending"
            return hex_qty(self._outgoing_count(ledger, chain_state, include_pending=include_pending))

        if method == "eth_getBalance":
            address = params[0] if isinstance(params, list) and params else ""
            chain_state = self.adapter.public_chain()
            ledger = self._resolve_ledger_address(str(address), chain_state)
            if not ledger:
                return hex_qty(0)
            bal = self.adapter.public_balance(ledger)
            return hex_qty(as_wei(bal))

        if method == "eth_sendRawTransaction":
            raw_tx = params[0] if isinstance(params, list) and params else ""
            return self._submit_evm_payment_tx(str(raw_tx))

        if method == "eth_sendTransaction":
            raise NotImplementedError(
                "Use eth_sendRawTransaction. This gateway does not hold wallet private keys for unsigned sends."
            )

        raise UnsupportedRpcMethod(f"Unsupported JSON-RPC method: {method}")

    def _handle_request_obj(self, req_obj: Dict[str, Any]) -> Dict[str, Any]:
        req_id = req_obj.get("id")
        method = str(req_obj.get("method", ""))
        params = req_obj.get("params", [])
        if req_obj.get("jsonrpc") != "2.0" or not method:
            return self._rpc_error(req_id, -32600, "Invalid Request")
        try:
            result = self._handle_method(method, params)
            return self._rpc_ok(req_id, result)
        except UnsupportedRpcMethod as exc:
            return self._rpc_error(req_id, -32601, str(exc))
        except NotImplementedError as exc:
            return self._rpc_error(req_id, -32004, str(exc))
        except ValueError as exc:
            return self._rpc_error(req_id, -32602, str(exc))
        except Exception as exc:  # pylint: disable=broad-except
            return self._rpc_error(req_id, -32603, f"Internal error: {exc}")

    def do_OPTIONS(self) -> None:
        self._set_json_headers(HTTPStatus.NO_CONTENT)

    def do_GET(self) -> None:
        if self.path == "/health":
            self._write_json({"ok": True, "service": "evm-gateway"}, HTTPStatus.OK)
            return
        self._write_json({"ok": False, "error": "Use POST / for JSON-RPC"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            self._write_json(self._rpc_error(None, -32700, "Parse error"), HTTPStatus.BAD_REQUEST)
            return

        raw = self.rfile.read(length).decode("utf-8")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            self._write_json(self._rpc_error(None, -32700, "Parse error"), HTTPStatus.BAD_REQUEST)
            return

        if isinstance(payload, list):
            if not payload:
                self._write_json(self._rpc_error(None, -32600, "Invalid Request"), HTTPStatus.BAD_REQUEST)
                return
            responses = [self._handle_request_obj(item) for item in payload if isinstance(item, dict)]
            self._write_json(responses)
            return

        if not isinstance(payload, dict):
            self._write_json(self._rpc_error(None, -32600, "Invalid Request"), HTTPStatus.BAD_REQUEST)
            return

        response = self._handle_request_obj(payload)
        self._write_json(response)

    def log_message(self, format_string: str, *args: Any) -> None:
        return


def run_evm_gateway(
    host: str,
    port: int,
    node_url: str,
    chain_id: int,
    auth_token: str = "",
    peer_ca: str = "",
    cors_origin: str = "*",
) -> None:
    ssl_context = ssl.create_default_context(cafile=peer_ca) if peer_ca else None

    JsonRpcGatewayHandler.adapter = NodeAdapter(
        node_url=node_url,
        auth_token=auth_token,
        ssl_context=ssl_context,
    )
    JsonRpcGatewayHandler.chain_id = chain_id
    JsonRpcGatewayHandler.client_version = f"Nova-EVM-Gateway/0.1 chainId={chain_id}"
    JsonRpcGatewayHandler.cors_origin = cors_origin

    server = ThreadingHTTPServer((host, port), JsonRpcGatewayHandler)
    print(f"EVM JSON-RPC gateway running on http://{host}:{port}")
    print(f"Upstream node: {node_url}")
    print("Health: GET /health")
    server.serve_forever()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Starter EVM JSON-RPC gateway for Nova public chain")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8545)
    parser.add_argument("--node-url", default="http://127.0.0.1:8000")
    parser.add_argument("--chain-id", type=int, default=149)
    parser.add_argument("--auth-token", default="")
    parser.add_argument("--peer-ca", default="", help="CA file for HTTPS node verification")
    parser.add_argument("--cors-origin", default="")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    run_evm_gateway(
        host=args.host,
        port=args.port,
        node_url=args.node_url,
        chain_id=args.chain_id,
        auth_token=args.auth_token,
        peer_ca=args.peer_ca,
        cors_origin=args.cors_origin,
    )


if __name__ == "__main__":
    main()
