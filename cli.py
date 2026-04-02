import argparse
import json
import os
from typing import Any, Dict, List
from urllib import parse, request

from auth import create_hs256_jwt
from dual_chain import (
    PrivateAssetChain,
    PublicPaymentChain,
    attach_signer_to_wallet,
    create_wallet,
    load_wallet,
    make_agent_attest_tx,
    make_agent_register_tx,
    make_agent_activity_log_tx,
    make_agent_challenge_tx,
    make_agent_challenge_resolve_tx,
    make_agent_param_propose_tx,
    make_agent_param_endorse_tx,
    make_ai_job_create_tx,
    make_ai_job_result_tx,
    make_ai_job_settle_tx,
    make_ai_model_register_tx,
    make_ai_provider_slash_tx,
    make_ai_provider_stake_tx,
    make_asset_issue_tx,
    make_identity_claim_tx,
    make_identity_update_tx,
    make_identity_verify_tx,
    make_task_delegate_tx,
    make_task_complete_tx,
    make_task_review_tx,
    make_task_dispute_tx,
    make_governance_propose_tx,
    make_governance_vote_tx,
    make_price_update_tx,
    make_asset_transfer_tx,
    make_payment_tx,
    make_payment_tx_with_fee,
    make_validator_update_tx,
    make_validator_nominate_tx,
    make_validator_election_vote_tx,
    make_ai_oracle_assign_tx,
    make_ai_oracle_event_tx,
    make_model_register_tx,
    make_model_transfer_tx,
    make_model_revenue_share_tx,
    make_model_inference_tx,
    make_pipeline_create_tx,
    make_pipeline_step_complete_tx,
    make_pipeline_approve_tx,
    move_wallet_private_key_to_file_hsm,
    save_wallet,
)
from evm_gateway import run_evm_gateway
from node import run_node


def post_json(url: str, payload: Dict[str, Any], auth_token: str = "") -> Dict[str, Any]:
    headers = {"Content-Type": "application/json"}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    data = json.dumps(payload).encode("utf-8")
    req = request.Request(
        url,
        data=data,
        headers=headers,
        method="POST",
    )
    with request.urlopen(req, timeout=7.0) as response:
        raw = response.read().decode("utf-8")
    return json.loads(raw) if raw else {}


def get_json(url: str, auth_token: str = "") -> Dict[str, Any]:
    headers = {}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    req = request.Request(url, headers=headers, method="GET")
    with request.urlopen(req, timeout=7.0) as response:
        raw = response.read().decode("utf-8")
    return json.loads(raw) if raw else {}


def _parse_csv(value: str) -> List[str]:
    if not value:
        return []
    return [x.strip() for x in value.split(",") if x.strip()]


def _parse_json_dict(value: str) -> Dict[str, Any]:
    if not value:
        return {}
    payload = json.loads(value)
    if not isinstance(payload, dict):
        raise ValueError("Expected JSON object")
    return payload


def _load_payload(args: argparse.Namespace) -> Dict[str, Any]:
    if args.payload_file:
        with open(args.payload_file, "r", encoding="utf-8") as f:
            payload = json.load(f)
    else:
        payload = _parse_json_dict(args.payload_json)
    if not isinstance(payload, dict):
        raise ValueError("Payload must be a JSON object")
    return payload


def get_data_paths(data_dir: str) -> tuple[str, str]:
    os.makedirs(data_dir, exist_ok=True)
    public_file = os.path.join(data_dir, "public_chain.json")
    private_file = os.path.join(data_dir, "private_chain.json")
    return public_file, private_file


def load_local_chains(data_dir: str, difficulty: int, reward: float) -> tuple[PublicPaymentChain, PrivateAssetChain]:
    public_file, private_file = get_data_paths(data_dir)
    public_chain = PublicPaymentChain(public_file, difficulty=difficulty, mining_reward=reward)
    private_chain = PrivateAssetChain(private_file)
    return public_chain, private_chain


def cmd_wallet_create(args: argparse.Namespace) -> None:
    wallet = create_wallet(args.name, bits=args.bits, scheme=args.scheme)
    save_wallet(wallet, args.out)
    print(f"Wallet created: {wallet['name']}")
    print(f"Address: {wallet['address']}")
    print(f"Scheme: {wallet['scheme']}")
    print(f"Saved to: {args.out}")


def cmd_wallet_show(args: argparse.Namespace) -> None:
    wallet = load_wallet(args.wallet)
    safe = {
        "name": wallet.get("name"),
        "address": wallet.get("address"),
        "scheme": wallet.get("scheme"),
        "public_key": wallet.get("public_key"),
        "signer": wallet.get("signer"),
        "hsm_ref": wallet.get("hsm_ref"),
        "created_at": wallet.get("created_at"),
    }
    print(json.dumps(safe, indent=2))


def cmd_wallet_migrate_hsm(args: argparse.Namespace) -> None:
    wallet = load_wallet(args.wallet)
    migrated = move_wallet_private_key_to_file_hsm(wallet, key_ref=args.key_ref, hsm_dir=args.hsm_dir)
    out_path = args.out or args.wallet
    save_wallet(migrated, out_path)
    print(f"Wallet migrated to file-hsm signer: {out_path}")
    print(f"HSM key stored at: {args.hsm_dir}/{args.key_ref}.json")


def cmd_wallet_set_signer(args: argparse.Namespace) -> None:
    wallet = load_wallet(args.wallet)
    signer_config = _parse_json_dict(args.config_json)
    updated = attach_signer_to_wallet(
        wallet=wallet,
        signer_type=args.signer_type,
        signer_config=signer_config,
        drop_private_key=args.drop_private_key,
    )
    out_path = args.out or args.wallet
    save_wallet(updated, out_path)
    print(f"Updated wallet signer -> {args.signer_type}")
    print(f"Saved: {out_path}")


def cmd_wallet_security_audit(args: argparse.Namespace) -> None:
    wallet_dir = args.wallet_dir
    if not os.path.isdir(wallet_dir):
        raise ValueError(f"wallet dir not found: {wallet_dir}")

    rows: List[Dict[str, Any]] = []
    violations: List[str] = []
    for filename in sorted(os.listdir(wallet_dir)):
        if not filename.endswith(".json"):
            continue
        path = os.path.join(wallet_dir, filename)
        try:
            wallet = load_wallet(path)
        except Exception as exc:  # pylint: disable=broad-except
            violations.append(f"{filename}: unreadable ({exc})")
            continue
        signer = wallet.get("signer", {}) or {}
        signer_type = str(signer.get("type", "local"))
        has_private_key = bool(wallet.get("private_key"))
        row = {
            "file": filename,
            "address": wallet.get("address", ""),
            "signer_type": signer_type,
            "has_private_key": has_private_key,
            "hsm_ref": wallet.get("hsm_ref", ""),
        }
        rows.append(row)
        if args.require_nonlocal and signer_type == "local":
            violations.append(f"{filename}: signer is local")
        if args.require_no_private_key and has_private_key:
            violations.append(f"{filename}: private_key present")

    out = {
        "wallet_dir": wallet_dir,
        "count": len(rows),
        "wallets": rows,
        "violation_count": len(violations),
        "violations": violations,
    }
    print(json.dumps(out, indent=2))
    if violations:
        raise ValueError("wallet security audit failed")


def cmd_audit_wallets(args: argparse.Namespace) -> None:
    if not args.node_url:
        raise ValueError("--node-url is required for audit-wallets")
    qs = parse.urlencode(
        {
            "require_nonlocal": "true" if args.require_nonlocal else "false",
            "require_no_private_key": "true" if args.require_no_private_key else "false",
        }
    )
    out = get_json(f"{args.node_url.rstrip('/')}/audit/wallets?{qs}", auth_token=args.auth_token)
    print(json.dumps(out, indent=2))
    if args.fail_on_violations and int(out.get("violation_count", 0)) > 0:
        raise ValueError("wallet security audit failed")


def cmd_audit_security(args: argparse.Namespace) -> None:
    if not args.node_url:
        raise ValueError("--node-url is required for audit-security")
    out = get_json(f"{args.node_url.rstrip('/')}/audit/security", auth_token=args.auth_token)
    print(json.dumps(out, indent=2))


def cmd_auth_token(args: argparse.Namespace) -> None:
    extra_claims = _parse_json_dict(args.claims_json)
    token = create_hs256_jwt(
        secret=args.secret,
        subject=args.subject,
        ttl_seconds=args.ttl_seconds,
        extra_claims=extra_claims,
    )
    print(token)


def cmd_public_tx(args: argparse.Namespace) -> None:
    wallet = load_wallet(args.wallet)
    fee = float(getattr(args, "fee", 0.0))
    if fee > 0:
        tx = make_payment_tx_with_fee(wallet, args.to, args.amount, fee=fee)
    else:
        tx = make_payment_tx(wallet, args.to, args.amount)

    if args.node_url:
        response = post_json(f"{args.node_url.rstrip('/')}/public/tx", tx, auth_token=args.auth_token)
        print(json.dumps(response, indent=2))
        return

    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    public_chain.add_transaction(tx)
    print(f"Queued public tx {tx['id']}: {wallet['address']} -> {args.to} ({args.amount})")


def cmd_public_mine(args: argparse.Namespace) -> None:
    if args.node_url:
        response = post_json(
            f"{args.node_url.rstrip('/')}/public/mine",
            {"miner": args.miner},
            auth_token=args.auth_token,
        )
        print(json.dumps(response, indent=2))
        return

    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    block = public_chain.mine_pending_transactions(args.miner)
    print(f"Mined public block #{block.index} hash={block.hash}")


def cmd_public_balance(args: argparse.Namespace) -> None:
    if args.node_url:
        quoted = parse.quote(args.address, safe="")
        result = get_json(
            f"{args.node_url.rstrip('/')}/public/balance?address={quoted}",
            auth_token=args.auth_token,
        )
        print(json.dumps(result, indent=2))
        return

    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    print(f"{args.address}: {public_chain.get_balance(args.address):.4f}")


def cmd_public_validate(args: argparse.Namespace) -> None:
    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    print("VALID" if public_chain.is_valid() else "INVALID")


def cmd_public_register_oracle(args: argparse.Namespace) -> None:
    if args.wallet:
        oracle = load_wallet(args.wallet)["address"]
    else:
        oracle = args.oracle
    if not oracle:
        raise ValueError("Provide --wallet or --oracle")

    if args.node_url:
        response = post_json(
            f"{args.node_url.rstrip('/')}/public/oracle/register",
            {"oracle": oracle},
            auth_token=args.auth_token,
        )
        print(json.dumps(response, indent=2))
        return

    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    public_chain.register_price_oracle(oracle)
    print(f"Registered price oracle: {oracle}")


def cmd_public_price_update(args: argparse.Namespace) -> None:
    wallet = load_wallet(args.wallet)
    tx = make_price_update_tx(wallet, symbol=args.symbol, price=args.price, source=args.source)

    if args.node_url:
        response = post_json(
            f"{args.node_url.rstrip('/')}/public/price/update",
            tx,
            auth_token=args.auth_token,
        )
        print(json.dumps(response, indent=2))
        return

    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    public_chain.add_transaction(tx)
    print(f"Queued price update tx {tx['id']} for {args.symbol.upper()}={args.price}")


def cmd_public_price(args: argparse.Namespace) -> None:
    if args.node_url:
        if args.symbol:
            symbol = parse.quote(args.symbol.upper(), safe="")
            out = get_json(
                f"{args.node_url.rstrip('/')}/public/price?symbol={symbol}",
                auth_token=args.auth_token,
            )
        else:
            out = get_json(f"{args.node_url.rstrip('/')}/public/prices", auth_token=args.auth_token)
        print(json.dumps(out, indent=2))
        return

    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    print(json.dumps(public_chain.get_latest_price(args.symbol), indent=2))


def cmd_public_consensus(args: argparse.Namespace) -> None:
    if args.node_url:
        out = get_json(f"{args.node_url.rstrip('/')}/public/consensus", auth_token=args.auth_token)
        print(json.dumps(out, indent=2))
        return
    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    out = {
        "consensus": public_chain.consensus,
        "difficulty": public_chain.difficulty,
        "mining_reward": public_chain.mining_reward,
        "validators": sorted(public_chain.validators),
    }
    print(json.dumps(out, indent=2))


def cmd_public_finality(args: argparse.Namespace) -> None:
    if args.node_url:
        out = get_json(f"{args.node_url.rstrip('/')}/public/finality", auth_token=args.auth_token)
        print(json.dumps(out, indent=2))
        return
    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    out = {
        "finality_confirmations": public_chain.finality_confirmations,
        "latest_finalized_height": public_chain.latest_finalized_height(),
        "checkpoint_interval": public_chain.checkpoint_interval,
        "checkpoints": public_chain.checkpoint_summary(limit=20),
    }
    print(json.dumps(out, indent=2))


def cmd_public_ai_stakes(args: argparse.Namespace) -> None:
    if args.node_url:
        out = get_json(f"{args.node_url.rstrip('/')}/public/ai/stakes", auth_token=args.auth_token)
        print(json.dumps(out, indent=2))
        return
    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    print(json.dumps(public_chain.get_provider_stakes(), indent=2))


def cmd_public_faucet_status(args: argparse.Namespace) -> None:
    if not args.node_url:
        raise ValueError("--node-url is required for public-faucet-status")
    out = get_json(f"{args.node_url.rstrip('/')}/public/faucet/status", auth_token=args.auth_token)
    print(json.dumps(out, indent=2))


def cmd_public_faucet_claim(args: argparse.Namespace) -> None:
    if not args.node_url:
        raise ValueError("--node-url is required for public-faucet-claim")
    payload: Dict[str, Any] = {"to": args.to}
    if float(args.amount) > 0:
        payload["amount"] = float(args.amount)
    out = post_json(
        f"{args.node_url.rstrip('/')}/public/faucet/claim",
        payload,
        auth_token=args.auth_token,
    )
    print(json.dumps(out, indent=2))


def cmd_public_slo(args: argparse.Namespace) -> None:
    if args.node_url:
        out = get_json(f"{args.node_url.rstrip('/')}/slo", auth_token=args.auth_token)
        print(json.dumps(out, indent=2))
        return
    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    out = {"ok": True, "public": public_chain.performance_summary(window_blocks=60)}
    print(json.dumps(out, indent=2))


def cmd_public_performance(args: argparse.Namespace) -> None:
    window = max(1, int(args.window_blocks))
    if args.node_url:
        chain_state = get_json(f"{args.node_url.rstrip('/')}/public/chain", auth_token=args.auth_token)
        blocks = chain_state.get("chain", [])
        selected = blocks[-window:] if blocks else []
        tx_count = 0
        reward_count = 0
        for block in selected:
            for tx in block.get("transactions", []):
                if tx.get("type") == "payment" and tx.get("sender") == "SYSTEM":
                    reward_count += 1
                    continue
                tx_count += 1
        avg_block_time = 0.0
        tps = 0.0
        if len(selected) > 1:
            span = float(selected[-1].get("timestamp", 0.0)) - float(selected[0].get("timestamp", 0.0))
            if span > 0:
                avg_block_time = span / float(len(selected) - 1)
                tps = tx_count / span
        out = {
            "window_blocks": len(selected),
            "window_user_tx": tx_count,
            "window_reward_tx": reward_count,
            "avg_block_time_seconds": avg_block_time,
            "estimated_tps": tps,
            "latest_height": max(0, len(blocks) - 1),
        }
        print(json.dumps(out, indent=2))
        return

    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    print(json.dumps(public_chain.performance_summary(window_blocks=window), indent=2))


def cmd_public_validator_update(args: argparse.Namespace) -> None:
    wallet = load_wallet(args.wallet)
    tx = make_validator_update_tx(wallet, action=args.action, validator_address=args.validator)
    if args.node_url:
        out = post_json(f"{args.node_url.rstrip('/')}/public/tx", tx, auth_token=args.auth_token)
        print(json.dumps(out, indent=2))
        return
    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    public_chain.add_transaction(tx)
    print(json.dumps({"ok": True, "tx_id": tx["id"]}, indent=2))


def cmd_public_ai_provider_stake(args: argparse.Namespace) -> None:
    wallet = load_wallet(args.wallet)
    tx = make_ai_provider_stake_tx(wallet, amount=float(args.amount))
    if args.node_url:
        out = post_json(f"{args.node_url.rstrip('/')}/public/tx", tx, auth_token=args.auth_token)
        print(json.dumps(out, indent=2))
        return
    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    public_chain.add_transaction(tx)
    print(json.dumps({"ok": True, "tx_id": tx["id"]}, indent=2))


def cmd_public_ai_provider_slash(args: argparse.Namespace) -> None:
    wallet = load_wallet(args.wallet)
    tx = make_ai_provider_slash_tx(
        validator_wallet=wallet,
        provider=args.provider,
        amount=float(args.amount),
        reason=args.reason,
        recipient=args.recipient,
    )
    if args.node_url:
        out = post_json(f"{args.node_url.rstrip('/')}/public/tx", tx, auth_token=args.auth_token)
        print(json.dumps(out, indent=2))
        return
    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    public_chain.add_transaction(tx)
    print(json.dumps({"ok": True, "tx_id": tx["id"]}, indent=2))


def cmd_identity_claim(args: argparse.Namespace) -> None:
    wallet = load_wallet(args.wallet)
    links = _parse_json_dict(args.links_json) if args.links_json else {}
    if args.node_url:
        out = post_json(
            f"{args.node_url.rstrip('/')}/public/identity/claim",
            {"wallet_name": wallet.get("name", ""), "handle": args.handle, "bio": args.bio, "links": links},
            auth_token=args.auth_token,
        )
        print(json.dumps(out, indent=2))
        return
    tx = make_identity_claim_tx(wallet, handle=args.handle, bio=args.bio, links=links)
    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    public_chain.add_transaction(tx)
    print(json.dumps({"ok": True, "tx_id": tx["id"], "handle": args.handle}, indent=2))


def cmd_identity_update(args: argparse.Namespace) -> None:
    wallet = load_wallet(args.wallet)
    links = _parse_json_dict(args.links_json) if args.links_json else {}
    if args.node_url:
        out = post_json(
            f"{args.node_url.rstrip('/')}/public/identity/update",
            {"wallet_name": wallet.get("name", ""), "bio": args.bio, "links": links},
            auth_token=args.auth_token,
        )
        print(json.dumps(out, indent=2))
        return
    tx = make_identity_update_tx(wallet, bio=args.bio, links=links)
    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    public_chain.add_transaction(tx)
    print(json.dumps({"ok": True, "tx_id": tx["id"]}, indent=2))


def cmd_agent_register(args: argparse.Namespace) -> None:
    wallet = load_wallet(args.wallet)
    capabilities = _parse_csv(args.capabilities) if args.capabilities else []
    if args.node_url:
        out = post_json(
            f"{args.node_url.rstrip('/')}/public/agent/register",
            {"wallet_name": wallet.get("name", ""), "agent_id": args.agent_id, "name": args.name,
             "capabilities": capabilities, "version_hash": args.version_hash},
            auth_token=args.auth_token,
        )
        print(json.dumps(out, indent=2))
        return
    tx = make_agent_register_tx(wallet, agent_id=args.agent_id, name=args.name,
                                capabilities=capabilities, version_hash=args.version_hash)
    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    public_chain.add_transaction(tx)
    print(json.dumps({"ok": True, "tx_id": tx["id"], "agent_id": args.agent_id}, indent=2))


def cmd_agent_attest(args: argparse.Namespace) -> None:
    wallet = load_wallet(args.wallet)
    tx = make_agent_attest_tx(wallet, log_id=args.log_id,
                               sentiment=args.sentiment, note=args.note)
    if args.node_url:
        out = post_json(f"{args.node_url.rstrip('/')}/public/tx", tx, auth_token=args.auth_token)
        print(json.dumps(out, indent=2))
        return
    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    public_chain.add_transaction(tx)
    print(json.dumps({"ok": True, "tx_id": tx["id"]}, indent=2))


def cmd_agent_log(args: argparse.Namespace) -> None:
    wallet = load_wallet(args.wallet)
    tags = _parse_csv(args.tags) if getattr(args, "tags", "") else []
    tx = make_agent_activity_log_tx(
        wallet, agent_id=args.agent_id, action_type=args.action_type,
        output_hash=getattr(args, "output_hash", ""),
        evidence_url=getattr(args, "evidence_url", ""),
        success=not getattr(args, "failed", False),
        platform=getattr(args, "platform", ""),
        external_ref=getattr(args, "external_ref", ""),
        note=getattr(args, "note", ""),
        stake_locked=float(getattr(args, "stake", 0.0)),
        tags=tags,
    )
    if args.node_url:
        out = post_json(f"{args.node_url.rstrip('/')}/public/tx", tx, auth_token=args.auth_token)
        print(json.dumps(out, indent=2))
        return
    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    public_chain.add_transaction(tx)
    print(json.dumps({"ok": True, "log_id": tx["id"]}, indent=2))


def cmd_agent_challenge(args: argparse.Namespace) -> None:
    wallet = load_wallet(args.wallet)
    tx = make_agent_challenge_tx(
        wallet, log_id=args.log_id,
        stake_locked=float(args.stake),
        reason=getattr(args, "reason", ""),
    )
    if args.node_url:
        out = post_json(f"{args.node_url.rstrip('/')}/public/tx", tx, auth_token=args.auth_token)
        print(json.dumps(out, indent=2))
        return
    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    public_chain.add_transaction(tx)
    print(json.dumps({"ok": True, "challenge_id": tx["id"]}, indent=2))


def cmd_agent_challenge_resolve(args: argparse.Namespace) -> None:
    wallet = load_wallet(args.wallet)
    tx = make_agent_challenge_resolve_tx(
        wallet, challenge_id=args.challenge_id,
        verdict=args.verdict,
        note=getattr(args, "note", ""),
    )
    if args.node_url:
        out = post_json(f"{args.node_url.rstrip('/')}/public/tx", tx, auth_token=args.auth_token)
        print(json.dumps(out, indent=2))
        return
    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    public_chain.add_transaction(tx)
    print(json.dumps({"ok": True, "tx_id": tx["id"]}, indent=2))


def cmd_agent_param_propose(args: argparse.Namespace) -> None:
    """
    Validator governance step 1: propose a change to agent trust parameters.
    A second validator must run agent-param-endorse before changes take effect.

    Examples:
      jito agent-param-propose --wallet v.json --changes '{"challenge_window_blocks": 100}' --reason "community vote #3"
      jito agent-param-propose --wallet v.json --changes '{"trust_score_weights": {"slashed_log": -5.0}}'
    """
    import json as _json
    wallet = load_wallet(args.wallet)
    try:
        changes = _json.loads(args.changes)
    except _json.JSONDecodeError as e:
        print(f"Error: --changes must be valid JSON: {e}")
        return
    tx = make_agent_param_propose_tx(wallet, changes=changes, reason=getattr(args, "reason", ""))
    if args.node_url:
        out = post_json(f"{args.node_url.rstrip('/')}/public/tx", tx, auth_token=args.auth_token)
        print(json.dumps(out, indent=2))
        return
    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    public_chain.add_transaction(tx)
    print(json.dumps({"ok": True, "tx_id": tx["id"], "proposal_id": tx["proposal_id"], "changes": changes}, indent=2))


def cmd_agent_param_endorse(args: argparse.Namespace) -> None:
    """
    Validator governance step 2: endorse (or reject) a pending param proposal.
    When yes_count >= param_update_min_endorsements, changes are applied immediately.

    Examples:
      jito agent-param-endorse --wallet v2.json --proposal-id apu_abc123 --approve
      jito agent-param-endorse --wallet v2.json --proposal-id apu_abc123 --no-approve
    """
    wallet = load_wallet(args.wallet)
    approve = not getattr(args, "no_approve", False)
    tx = make_agent_param_endorse_tx(wallet, proposal_id=args.proposal_id, approve=approve)
    if args.node_url:
        out = post_json(f"{args.node_url.rstrip('/')}/public/tx", tx, auth_token=args.auth_token)
        print(json.dumps(out, indent=2))
        return
    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    public_chain.add_transaction(tx)
    print(json.dumps({"ok": True, "tx_id": tx["id"], "approve": approve}, indent=2))


def cmd_agent_passport(args: argparse.Namespace) -> None:
    import urllib.request as _ur
    url = f"{args.node_url.rstrip('/')}/public/agent/passport?address={args.address}"
    with _ur.urlopen(url, timeout=10) as r:
        print(r.read().decode())


def cmd_agent_node_start(args: argparse.Namespace) -> None:
    """
    Lightweight agent data node — no block production, no chain sync.
    Signs and submits activity logs to a remote NOVA node on behalf of a wallet.
    Ideal for running alongside any AI agent with minimal overhead.
    """
    import http.server
    import threading
    wallet = load_wallet(args.wallet)
    node_url = args.node_url.rstrip("/")
    print(f"Agent Data Node starting")
    print(f"  Wallet:   {wallet['address']}")
    print(f"  Agent ID: {args.agent_id}")
    print(f"  Remote:   {node_url}")
    print(f"  Port:     {args.port}")
    print()

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt, *a): pass  # suppress default logs

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            action_type = body.get("action_type", "unknown")
            tags = body.get("tags", [])
            stake = float(body.get("stake", 0.0))
            tx = make_agent_activity_log_tx(
                wallet, agent_id=args.agent_id,
                action_type=action_type,
                output_hash=body.get("output_hash", ""),
                evidence_url=body.get("evidence_url", ""),
                evidence_hash=body.get("evidence_hash", ""),
                success=body.get("success", True),
                duration_ms=int(body.get("duration_ms", 0)),
                platform=body.get("platform", args.platform),
                external_ref=body.get("external_ref", ""),
                note=body.get("note", ""),
                stake_locked=stake,
                tags=tags,
            )
            try:
                result = post_json(f"{node_url}/public/tx", tx)
                resp = json.dumps({"ok": True, "log_id": tx["id"], "result": result}).encode()
                print(f"  Logged [{action_type}] log_id={tx['id'][:16]}...")
            except Exception as e:
                resp = json.dumps({"ok": False, "error": str(e)}).encode()
                print(f"  Error logging [{action_type}]: {e}")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(resp)

        def do_GET(self):
            if self.path == "/health":
                resp = json.dumps({"ok": True, "address": wallet["address"],
                                   "agent_id": args.agent_id}).encode()
            elif self.path.startswith("/passport"):
                import urllib.request as _ur
                url = f"{node_url}/public/agent/passport?address={wallet['address']}"
                with _ur.urlopen(url, timeout=10) as r:
                    resp = r.read()
            else:
                resp = json.dumps({"error": "unknown endpoint"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(resp)

    server = http.server.ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    print(f"Agent Data Node ready at http://0.0.0.0:{args.port}")
    print(f"  POST /   {{action_type, output_hash, platform, stake, tags, ...}}")
    print(f"  GET  /health")
    print(f"  GET  /passport")
    server.serve_forever()


def cmd_identity_verify(args: argparse.Namespace) -> None:
    wallet = load_wallet(args.wallet)
    if args.node_url:
        out = post_json(
            f"{args.node_url.rstrip('/')}/public/identity/verify",
            {"wallet": wallet, "target_address": args.target, "level": args.level},
            auth_token=args.auth_token,
        )
        print(json.dumps(out, indent=2))
        return
    tx = make_identity_verify_tx(wallet, args.target, args.level)
    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    public_chain.add_transaction(tx)
    print(json.dumps({"ok": True, "tx_id": tx["id"]}, indent=2))


def cmd_task_delegate(args: argparse.Namespace) -> None:
    wallet = load_wallet(args.wallet)
    if args.node_url:
        out = post_json(
            f"{args.node_url.rstrip('/')}/public/task/delegate",
            {
                "wallet": wallet,
                "agent_id": args.agent_id or "",
                "title": args.title,
                "description": args.description or "",
                "reward": float(args.reward),
                "min_reputation": float(args.min_reputation or 0),
            },
            auth_token=args.auth_token,
        )
        print(json.dumps(out, indent=2))
        return
    tx = make_task_delegate_tx(wallet, args.agent_id or "", args.title, args.description or "",
                               float(args.reward), float(args.min_reputation or 0))
    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    public_chain.add_transaction(tx)
    print(json.dumps({"ok": True, "tx_id": tx["id"]}, indent=2))


def cmd_task_complete(args: argparse.Namespace) -> None:
    wallet = load_wallet(args.wallet)
    if args.node_url:
        out = post_json(
            f"{args.node_url.rstrip('/')}/public/task/complete",
            {
                "wallet": wallet,
                "task_id": args.task_id,
                "result_hash": args.result_hash or "",
                "note": args.note or "",
            },
            auth_token=args.auth_token,
        )
        print(json.dumps(out, indent=2))
        return
    tx = make_task_complete_tx(wallet, args.task_id, args.result_hash or "", args.note or "")
    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    public_chain.add_transaction(tx)
    print(json.dumps({"ok": True, "tx_id": tx["id"]}, indent=2))


def cmd_task_review(args: argparse.Namespace) -> None:
    wallet = load_wallet(args.wallet)
    if args.node_url:
        out = post_json(
            f"{args.node_url.rstrip('/')}/public/task/review",
            {
                "wallet": wallet,
                "task_id": args.task_id,
                "approved": args.approved,
                "quality_score": int(args.quality_score or 50),
                "note": args.note or "",
            },
            auth_token=args.auth_token,
        )
        print(json.dumps(out, indent=2))
        return
    tx = make_task_review_tx(wallet, args.task_id, args.approved, int(args.quality_score or 50), args.note or "")
    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    public_chain.add_transaction(tx)
    print(json.dumps({"ok": True, "tx_id": tx["id"]}, indent=2))


def cmd_task_dispute(args: argparse.Namespace) -> None:
    wallet = load_wallet(args.wallet)
    if args.node_url:
        out = post_json(
            f"{args.node_url.rstrip('/')}/public/task/dispute",
            {
                "wallet": wallet,
                "task_id": args.task_id,
                "reason": args.reason or "",
            },
            auth_token=args.auth_token,
        )
        print(json.dumps(out, indent=2))
        return
    tx = make_task_dispute_tx(wallet, args.task_id, args.reason or "")
    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    public_chain.add_transaction(tx)
    print(json.dumps({"ok": True, "tx_id": tx["id"]}, indent=2))


def cmd_governance_propose(args: argparse.Namespace) -> None:
    wallet = load_wallet(args.wallet)
    param_changes = json.loads(args.param_changes) if args.param_changes else {}
    if args.node_url:
        out = post_json(
            f"{args.node_url.rstrip('/')}/public/governance/propose",
            {
                "wallet": wallet,
                "title": args.title,
                "description": args.description or "",
                "param_changes": param_changes,
                "vote_window_blocks": int(args.vote_window_blocks or 100),
            },
            auth_token=args.auth_token,
        )
        print(json.dumps(out, indent=2))
        return
    tx = make_governance_propose_tx(wallet, args.title, args.description or "",
                                    param_changes, int(args.vote_window_blocks or 100))
    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    public_chain.add_transaction(tx)
    print(json.dumps({"ok": True, "tx_id": tx["id"]}, indent=2))


def cmd_governance_vote(args: argparse.Namespace) -> None:
    wallet = load_wallet(args.wallet)
    if args.node_url:
        out = post_json(
            f"{args.node_url.rstrip('/')}/public/governance/vote",
            {
                "wallet": wallet,
                "proposal_id": args.proposal_id,
                "vote": args.yes,
            },
            auth_token=args.auth_token,
        )
        print(json.dumps(out, indent=2))
        return
    tx = make_governance_vote_tx(wallet, args.proposal_id, args.yes)
    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    public_chain.add_transaction(tx)
    print(json.dumps({"ok": True, "tx_id": tx["id"]}, indent=2))


def cmd_reputation(args: argparse.Namespace) -> None:
    url = f"{args.node_url.rstrip('/')}/reputation/{args.address}"
    data = get_json(url, auth_token=args.auth_token)
    print(json.dumps(data, indent=2))


def cmd_reputation_leaderboard(args: argparse.Namespace) -> None:
    limit = args.limit or 20
    url = f"{args.node_url.rstrip('/')}/reputation/leaderboard?limit={limit}"
    data = get_json(url, auth_token=args.auth_token)
    print(json.dumps(data, indent=2))


def cmd_tasks(args: argparse.Namespace) -> None:
    params = []
    if args.status:
        params.append(f"status={args.status}")
    if args.owner:
        params.append(f"owner={args.owner}")
    qs = "?" + "&".join(params) if params else ""
    url = f"{args.node_url.rstrip('/')}/tasks{qs}"
    data = get_json(url, auth_token=args.auth_token)
    print(json.dumps(data, indent=2))


def cmd_governance_proposals(args: argparse.Namespace) -> None:
    qs = f"?status={args.status}" if args.status else ""
    url = f"{args.node_url.rstrip('/')}/governance/proposals{qs}"
    data = get_json(url, auth_token=args.auth_token)
    print(json.dumps(data, indent=2))


def cmd_activity_feed(args: argparse.Namespace) -> None:
    import datetime
    limit = args.limit or 50
    url = f"{args.node_url.rstrip('/')}/activity/feed?limit={limit}"
    data = get_json(url, auth_token=args.auth_token)
    for item in data.get("feed", []):
        ts = datetime.datetime.fromtimestamp(item["ts"]).strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] {item['message']}")


def cmd_validator_nominate(args):
    wallet = load_wallet(args.wallet)
    resp = post_json(f"{args.node_url.rstrip('/')}/public/validator/nominate", {"wallet": wallet}, auth_token=args.auth_token)
    print(json.dumps(resp, indent=2))


def cmd_validator_election_vote(args):
    wallet = load_wallet(args.wallet)
    resp = post_json(f"{args.node_url.rstrip('/')}/public/validator/vote", {"wallet": wallet, "candidate": args.candidate}, auth_token=args.auth_token)
    print(json.dumps(resp, indent=2))


def cmd_validator_candidates(args):
    data = get_json(f"{args.node_url.rstrip('/')}/validator/candidates", auth_token=args.auth_token)
    print(json.dumps(data, indent=2))


def cmd_treasury(args):
    data = get_json(f"{args.node_url.rstrip('/')}/treasury", auth_token=args.auth_token)
    print(json.dumps(data, indent=2))


def cmd_oracle_assign(args):
    wallet = load_wallet(args.wallet)
    resp = post_json(f"{args.node_url.rstrip('/')}/public/oracle/assign", {
        "wallet": wallet,
        "asset_id": args.asset_id,
        "agent_id": args.agent_id or "",
        "oracle_type": args.oracle_type,
    }, auth_token=args.auth_token)
    print(json.dumps(resp, indent=2))


def cmd_oracle_event(args):
    wallet = load_wallet(args.wallet)
    resp = post_json(f"{args.node_url.rstrip('/')}/public/oracle/event", {
        "wallet": wallet,
        "asset_id": args.asset_id,
        "event_type": args.event_type,
        "value": args.value,
        "note": args.note or "",
    }, auth_token=args.auth_token)
    print(json.dumps(resp, indent=2))


def cmd_oracles(args):
    data = get_json(f"{args.node_url.rstrip('/')}/oracles", auth_token=args.auth_token)
    print(json.dumps(data, indent=2))


def cmd_model_register(args):
    wallet = load_wallet(args.wallet)
    caps = [c.strip() for c in args.capabilities.split(",")] if args.capabilities else []
    resp = post_json(f"{args.node_url.rstrip('/')}/public/model/register", {
        "wallet": wallet,
        "model_id": args.model_id or ("model_" + __import__("secrets").token_hex(4)),
        "name": args.name,
        "description": args.description or "",
        "capabilities": caps,
        "version_hash": args.version_hash or "",
        "inference_fee": float(args.inference_fee or 0),
    }, auth_token=args.auth_token)
    print(json.dumps(resp, indent=2))

def cmd_model_transfer(args):
    wallet = load_wallet(args.wallet)
    resp = post_json(f"{args.node_url.rstrip('/')}/public/model/transfer", {
        "wallet": wallet,
        "model_id": args.model_id,
        "new_owner": args.new_owner,
    }, auth_token=args.auth_token)
    print(json.dumps(resp, indent=2))

def cmd_model_revenue_share(args):
    wallet = load_wallet(args.wallet)
    shares = json.loads(args.shares_json) if args.shares_json else {}
    resp = post_json(f"{args.node_url.rstrip('/')}/public/model/revenue-share", {
        "wallet": wallet,
        "model_id": args.model_id,
        "shares": shares,
    }, auth_token=args.auth_token)
    print(json.dumps(resp, indent=2))

def cmd_model_inference(args):
    wallet = load_wallet(args.wallet)
    resp = post_json(f"{args.node_url.rstrip('/')}/public/model/inference", {
        "wallet": wallet,
        "model_id": args.model_id,
        "input_hash": args.input_hash or "",
        "output_hash": args.output_hash or "",
    }, auth_token=args.auth_token)
    print(json.dumps(resp, indent=2))

def cmd_models(args):
    qs = ""
    if args.owner:
        qs = f"?owner={args.owner}"
    data = get_json(f"{args.node_url.rstrip('/')}/models{qs}", auth_token=args.auth_token)
    print(json.dumps(data, indent=2))

def cmd_pipeline_create(args):
    wallet = load_wallet(args.wallet)
    steps = json.loads(args.steps_json)
    resp = post_json(f"{args.node_url.rstrip('/')}/public/pipeline/create", {
        "wallet": wallet,
        "pipeline_id": args.pipeline_id or ("pipe_" + __import__("secrets").token_hex(4)),
        "title": args.title,
        "steps": steps,
        "total_reward": float(args.total_reward),
    }, auth_token=args.auth_token)
    print(json.dumps(resp, indent=2))

def cmd_pipeline_step_complete(args):
    wallet = load_wallet(args.wallet)
    resp = post_json(f"{args.node_url.rstrip('/')}/public/pipeline/step-complete", {
        "wallet": wallet,
        "pipeline_id": args.pipeline_id,
        "step_index": int(args.step_index),
        "result_hash": args.result_hash or "",
        "note": args.note or "",
    }, auth_token=args.auth_token)
    print(json.dumps(resp, indent=2))

def cmd_pipeline_approve(args):
    wallet = load_wallet(args.wallet)
    resp = post_json(f"{args.node_url.rstrip('/')}/public/pipeline/approve", {
        "wallet": wallet,
        "pipeline_id": args.pipeline_id,
        "approved": args.approved,
        "note": args.note or "",
    }, auth_token=args.auth_token)
    print(json.dumps(resp, indent=2))

def cmd_pipelines(args):
    qs = f"?status={args.status}" if args.status else ""
    data = get_json(f"{args.node_url.rstrip('/')}/pipelines{qs}", auth_token=args.auth_token)
    print(json.dumps(data, indent=2))


def cmd_public_validator_add(args: argparse.Namespace) -> None:
    validator = args.validator
    if not validator and args.wallet:
        validator = load_wallet(args.wallet)["address"]
    if not validator:
        raise ValueError("Provide --validator or --wallet")

    if args.node_url:
        out = post_json(
            f"{args.node_url.rstrip('/')}/public/validators/add",
            {"validator": validator},
            auth_token=args.auth_token,
        )
        print(json.dumps(out, indent=2))
        return

    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    public_chain.add_validator(validator)
    print(json.dumps({"ok": True, "validator": validator, "validators": sorted(public_chain.validators)}, indent=2))


def cmd_public_validator_remove(args: argparse.Namespace) -> None:
    validator = args.validator
    if not validator and args.wallet:
        validator = load_wallet(args.wallet)["address"]
    if not validator:
        raise ValueError("Provide --validator or --wallet")

    if args.node_url:
        out = post_json(
            f"{args.node_url.rstrip('/')}/public/validators/remove",
            {"validator": validator},
            auth_token=args.auth_token,
        )
        print(json.dumps(out, indent=2))
        return

    public_chain, _ = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    public_chain.remove_validator(validator)
    print(json.dumps({"ok": True, "validator": validator, "validators": sorted(public_chain.validators)}, indent=2))


def cmd_public_auto_mine_start(args: argparse.Namespace) -> None:
    if not args.node_url:
        raise ValueError("--node-url is required for public-auto-mine-start")
    payload = {
        "miner": args.miner,
        "interval_seconds": float(args.interval_seconds),
        "allow_empty_blocks": bool(args.allow_empty_blocks),
    }
    out = post_json(
        f"{args.node_url.rstrip('/')}/public/auto-mine/start",
        payload,
        auth_token=args.auth_token,
    )
    print(json.dumps(out, indent=2))


def cmd_public_auto_mine_stop(args: argparse.Namespace) -> None:
    if not args.node_url:
        raise ValueError("--node-url is required for public-auto-mine-stop")
    out = post_json(
        f"{args.node_url.rstrip('/')}/public/auto-mine/stop",
        {},
        auth_token=args.auth_token,
    )
    print(json.dumps(out, indent=2))


def cmd_public_auto_mine_status(args: argparse.Namespace) -> None:
    if not args.node_url:
        raise ValueError("--node-url is required for public-auto-mine-status")
    out = get_json(f"{args.node_url.rstrip('/')}/public/auto-mine", auth_token=args.auth_token)
    print(json.dumps(out, indent=2))


def cmd_chain_branding(args: argparse.Namespace) -> None:
    if not args.node_url:
        raise ValueError("--node-url is required for chain-branding")
    payload: Dict[str, Any] = {}
    if args.chain_logo_url is not None:
        payload["chain_logo_url"] = str(args.chain_logo_url)
    if args.token_logo_url is not None:
        payload["token_logo_url"] = str(args.token_logo_url)
    out = post_json(
        f"{args.node_url.rstrip('/')}/chain/branding",
        payload,
        auth_token=args.auth_token,
    )
    print(json.dumps(out, indent=2))


def _roles_from_flags(args: argparse.Namespace) -> List[str]:
    roles = ["participant"]
    if args.issuer:
        roles.append("issuer")
    if args.validator:
        roles.append("validator")
    if args.notary:
        roles.append("notary")
    return roles


def cmd_private_register(args: argparse.Namespace) -> None:
    wallet = load_wallet(args.wallet)
    roles = _roles_from_flags(args)
    domains = _parse_csv(args.domains)
    attributes = _parse_json_dict(args.attributes_json)
    payload = {
        "wallet": wallet,
        "roles": roles,
        "domains": domains,
        "attributes": attributes,
    }

    if args.node_url:
        response = post_json(
            f"{args.node_url.rstrip('/')}/private/register",
            payload,
            auth_token=args.auth_token,
        )
        print(json.dumps(response, indent=2))
        return

    _, private_chain = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    private_chain.register_wallet(wallet, roles=roles, domains=domains, attributes=attributes)
    print(f"Registered {wallet['address']} with roles={roles}, domains={domains}")


def cmd_private_propose(args: argparse.Namespace) -> None:
    wallet = load_wallet(args.wallet)
    proposal_payload = _load_payload(args)

    if args.node_url:
        response = post_json(
            f"{args.node_url.rstrip('/')}/private/propose",
            {"wallet": wallet, "action": args.action, "payload": proposal_payload},
            auth_token=args.auth_token,
        )
        print(json.dumps(response, indent=2))
        return

    _, private_chain = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    proposal = private_chain.propose_governance(wallet, args.action, proposal_payload)
    print(json.dumps(proposal, indent=2))


def cmd_private_approve(args: argparse.Namespace) -> None:
    wallet = load_wallet(args.wallet)

    if args.node_url:
        response = post_json(
            f"{args.node_url.rstrip('/')}/private/approve",
            {"wallet": wallet, "proposal_id": args.proposal_id},
            auth_token=args.auth_token,
        )
        print(json.dumps(response, indent=2))
        return

    _, private_chain = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    proposal = private_chain.approve_governance(args.proposal_id, wallet)
    print(json.dumps(proposal, indent=2))


def cmd_private_governance(args: argparse.Namespace) -> None:
    if args.node_url:
        response = get_json(f"{args.node_url.rstrip('/')}/private/governance", auth_token=args.auth_token)
        print(json.dumps(response, indent=2))
        return

    _, private_chain = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    print(json.dumps(private_chain.list_governance(), indent=2))


def cmd_private_issue(args: argparse.Namespace) -> None:
    wallet = load_wallet(args.wallet)
    visibility = _parse_csv(args.visibility)
    tx = make_asset_issue_tx(
        issuer_wallet=wallet,
        asset_id=args.asset_id,
        amount=args.amount,
        owner=args.owner,
        domain=args.domain,
        contract_id=args.contract_id,
        metadata_hash=args.metadata_hash,
        visibility=visibility,
    )

    if args.node_url:
        response = post_json(f"{args.node_url.rstrip('/')}/private/tx", tx, auth_token=args.auth_token)
        print(json.dumps(response, indent=2))
        return

    _, private_chain = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    private_chain.add_transaction(tx)
    print(f"Queued private issue tx {tx['id']} for asset={args.asset_id}")


def cmd_private_transfer(args: argparse.Namespace) -> None:
    wallet = load_wallet(args.wallet)
    visibility = _parse_csv(args.visibility)
    tx = make_asset_transfer_tx(
        owner_wallet=wallet,
        asset_id=args.asset_id,
        amount=args.amount,
        recipient=args.to,
        visibility=visibility,
    )

    if args.node_url:
        response = post_json(f"{args.node_url.rstrip('/')}/private/tx", tx, auth_token=args.auth_token)
        print(json.dumps(response, indent=2))
        return

    _, private_chain = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    private_chain.add_transaction(tx)
    print(f"Queued private transfer tx {tx['id']} for asset={args.asset_id}")


def cmd_private_ai_model_register(args: argparse.Namespace) -> None:
    wallet = load_wallet(args.wallet)
    visibility = _parse_csv(args.visibility)
    metadata = _parse_json_dict(args.metadata_json)
    tx = make_ai_model_register_tx(
        owner_wallet=wallet,
        model_id=args.model_id,
        model_hash=args.model_hash,
        version=args.version,
        price_per_call=args.price_per_call,
        visibility=visibility,
        metadata=metadata,
    )
    if args.node_url:
        response = post_json(f"{args.node_url.rstrip('/')}/private/tx", tx, auth_token=args.auth_token)
        print(json.dumps(response, indent=2))
        return
    _, private_chain = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    private_chain.add_transaction(tx)
    print(f"Queued private ai model register tx {tx['id']} for model={args.model_id}")


def cmd_private_ai_job_create(args: argparse.Namespace) -> None:
    wallet = load_wallet(args.wallet)
    visibility = _parse_csv(args.visibility)
    metadata = _parse_json_dict(args.metadata_json)
    tx = make_ai_job_create_tx(
        requester_wallet=wallet,
        job_id=args.job_id,
        model_id=args.model_id,
        input_hash=args.input_hash,
        max_payment=args.max_payment,
        visibility=visibility,
        metadata=metadata,
    )
    if args.node_url:
        response = post_json(f"{args.node_url.rstrip('/')}/private/tx", tx, auth_token=args.auth_token)
        print(json.dumps(response, indent=2))
        return
    _, private_chain = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    private_chain.add_transaction(tx)
    print(f"Queued private ai job create tx {tx['id']} for job={args.job_id}")


def cmd_private_ai_job_result(args: argparse.Namespace) -> None:
    wallet = load_wallet(args.wallet)
    metadata = _parse_json_dict(args.metadata_json)
    tx = make_ai_job_result_tx(
        provider_wallet=wallet,
        job_id=args.job_id,
        result_hash=args.result_hash,
        quality_score=args.quality_score,
        metadata=metadata,
    )
    if args.node_url:
        response = post_json(f"{args.node_url.rstrip('/')}/private/tx", tx, auth_token=args.auth_token)
        print(json.dumps(response, indent=2))
        return
    _, private_chain = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    private_chain.add_transaction(tx)
    print(f"Queued private ai job result tx {tx['id']} for job={args.job_id}")


def cmd_private_ai_job_settle(args: argparse.Namespace) -> None:
    wallet = load_wallet(args.wallet)
    tx = make_ai_job_settle_tx(
        settler_wallet=wallet,
        job_id=args.job_id,
        payout=args.payout,
        slash_provider=args.slash_provider,
        reason=args.reason,
    )
    if args.node_url:
        response = post_json(f"{args.node_url.rstrip('/')}/private/tx", tx, auth_token=args.auth_token)
        print(json.dumps(response, indent=2))
        return
    _, private_chain = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    private_chain.add_transaction(tx)
    print(f"Queued private ai job settle tx {tx['id']} for job={args.job_id}")


def cmd_private_ai_models(args: argparse.Namespace) -> None:
    if args.node_url:
        params = parse.urlencode({"owner": args.owner, "limit": int(args.limit)})
        url = f"{args.node_url.rstrip('/')}/private/ai/models"
        if params:
            url = f"{url}?{params}"
        print(json.dumps(get_json(url, auth_token=args.auth_token), indent=2))
        return
    _, private_chain = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    print(json.dumps(private_chain.list_ai_models(owner=args.owner, limit=args.limit), indent=2))


def cmd_private_ai_jobs(args: argparse.Namespace) -> None:
    if args.node_url:
        params = parse.urlencode(
            {
                "status": args.status,
                "participant": args.participant,
                "limit": int(args.limit),
            }
        )
        url = f"{args.node_url.rstrip('/')}/private/ai/jobs"
        if params:
            url = f"{url}?{params}"
        print(json.dumps(get_json(url, auth_token=args.auth_token), indent=2))
        return
    _, private_chain = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    print(
        json.dumps(
            private_chain.list_ai_jobs(
                status=args.status,
                participant=args.participant,
                limit=args.limit,
            ),
            indent=2,
        )
    )


def cmd_private_domains(args: argparse.Namespace) -> None:
    if args.node_url:
        params = parse.urlencode(
            {
                "domain_id": args.domain_id,
                "include_pending": "true" if args.include_pending else "false",
            }
        )
        url = f"{args.node_url.rstrip('/')}/private/domains"
        if params:
            url = f"{url}?{params}"
        print(json.dumps(get_json(url, auth_token=args.auth_token), indent=2))
        return
    _, private_chain = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    print(json.dumps(private_chain.domain_summary(domain_id=args.domain_id, include_pending=args.include_pending), indent=2))


def _resolve_block_hash(private_chain: PrivateAssetChain, explicit_hash: str) -> str:
    if explicit_hash:
        return explicit_hash
    if not private_chain.pending_blocks:
        raise ValueError("No pending private blocks available")
    return private_chain.pending_blocks[0].hash


def cmd_private_seal(args: argparse.Namespace) -> None:
    validator_wallet = load_wallet(args.wallet)

    if args.node_url:
        response = post_json(
            f"{args.node_url.rstrip('/')}/private/seal",
            {"validator_wallet": validator_wallet},
            auth_token=args.auth_token,
        )
        print(json.dumps(response, indent=2))
        return

    _, private_chain = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    block = private_chain.seal_pending_transactions(validator_wallet)
    print(f"Sealed private pending block #{block.index} hash={block.hash}")


def cmd_private_attest(args: argparse.Namespace) -> None:
    notary_wallet = load_wallet(args.wallet)

    if args.node_url:
        payload = {"notary_wallet": notary_wallet, "block_hash": args.block_hash}
        response = post_json(f"{args.node_url.rstrip('/')}/private/attest", payload, auth_token=args.auth_token)
        print(json.dumps(response, indent=2))
        return

    _, private_chain = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    block_hash = _resolve_block_hash(private_chain, args.block_hash)
    finality = private_chain.attest_block(block_hash, notary_wallet, auto_finalize=True)
    print(json.dumps(finality, indent=2))


def cmd_private_finalize(args: argparse.Namespace) -> None:
    if args.node_url:
        response = post_json(
            f"{args.node_url.rstrip('/')}/private/finalize",
            {"block_hash": args.block_hash},
            auth_token=args.auth_token,
        )
        print(json.dumps(response, indent=2))
        return

    _, private_chain = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    block_hash = _resolve_block_hash(private_chain, args.block_hash)
    block = private_chain.finalize_block(block_hash, fail_if_insufficient=True)
    print(json.dumps(block.to_dict() if block else {}, indent=2))


def cmd_private_pending(args: argparse.Namespace) -> None:
    if args.node_url:
        result = get_json(f"{args.node_url.rstrip('/')}/private/pending-blocks", auth_token=args.auth_token)
        print(json.dumps(result, indent=2))
        return

    _, private_chain = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    result = {
        "pending_blocks": [b.to_dict() for b in private_chain.pending_blocks],
        "pending_finality": private_chain.pending_finality,
    }
    print(json.dumps(result, indent=2))


def cmd_private_holdings(args: argparse.Namespace) -> None:
    if args.node_url:
        params = {}
        if args.address:
            params["address"] = args.address
        if args.viewer:
            params["viewer"] = args.viewer
        if args.include_pending:
            params["include_pending"] = "true"

        query = parse.urlencode(params)
        url = f"{args.node_url.rstrip('/')}/private/assets"
        if query:
            url = f"{url}?{query}"
        print(json.dumps(get_json(url, auth_token=args.auth_token), indent=2))
        return

    _, private_chain = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    print(
        json.dumps(
            private_chain.get_asset_balances(
                address=args.address or None,
                viewer=args.viewer or None,
                include_pending=args.include_pending,
            ),
            indent=2,
        )
    )


def cmd_private_view(args: argparse.Namespace) -> None:
    if args.node_url:
        viewer = parse.quote(args.viewer, safe="")
        result = get_json(
            f"{args.node_url.rstrip('/')}/private/view?viewer={viewer}",
            auth_token=args.auth_token,
        )
        print(json.dumps(result, indent=2))
        return

    _, private_chain = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    print(json.dumps(private_chain.get_private_view(args.viewer), indent=2))


def cmd_private_validate(args: argparse.Namespace) -> None:
    _, private_chain = load_local_chains(args.data_dir, args.public_difficulty, args.public_reward)
    print("VALID" if private_chain.is_valid() else "INVALID")


# ── Operator commands: nova init / run / status / env ─────────────────────────
# These work for anyone RUNNING agents (not building them).
# No SDK knowledge needed — just wrap any command with `nova run`.

def cmd_agent_init(args: argparse.Namespace) -> None:
    """Create a wallet for an agent and print the env vars to use it."""
    import os as _os
    from jito_agent.wallet import create_wallet as _cw, load_wallet as _lw, save_wallet as _sw

    wallet_path = args.wallet or f"{args.agent_id.replace('/', '-')}_wallet.json"
    if _os.path.exists(wallet_path):
        wallet = _lw(wallet_path)
        print(f"Wallet already exists at {wallet_path}")
    else:
        wallet = _cw(args.agent_id)
        _sw(wallet, wallet_path)
        print(f"Wallet created: {wallet_path}")

    node_url = args.node_url or "https://explorer.flowpe.io"
    print(f"\nAgent ID:  {args.agent_id}")
    print(f"Address:   {wallet['address']}")
    print(f"Node:      {node_url}")
    print(f"\n# Paste these into your shell (or .env file):")
    print(f"export NOVA_AGENT_ID={args.agent_id}")
    print(f"export NOVA_WALLET_PATH={wallet_path}")
    print(f"export NOVA_NODE_URL={node_url}")
    print(f"\n# Then run any agent with:")
    print(f"nova run --agent-id {args.agent_id} --tags <your-tags> -- <your command>")
    print(f"\n# View passport:")
    print(f"{node_url}/passport?address={wallet['address']}")


def cmd_agent_run(args: argparse.Namespace) -> None:
    """Wrap any agent command — log timing + exit code to Nova automatically."""
    import subprocess as _sp
    import time as _time
    from jito_agent import NovaTracker

    agent_id = args.agent_id or _os_getenv("NOVA_AGENT_ID")
    if not agent_id:
        raise SystemExit("--agent-id is required (or set NOVA_AGENT_ID)")

    wallet_path = args.wallet or _os_getenv("NOVA_WALLET_PATH", f"{agent_id.replace('/', '-')}_wallet.json")
    node_url = args.node_url or _os_getenv("NOVA_NODE_URL", "https://explorer.flowpe.io")
    tags = [t.strip() for t in args.tags.split(",")] if args.tags else []
    action = args.action or "agent_run"

    if not args.cmd:
        raise SystemExit("Provide the command to run after --  e.g.: nova run --agent-id x -- python agent.py")

    tracker = NovaTracker.new(agent_id=agent_id, wallet_path=wallet_path, node_url=node_url)

    print(f"[nova] Running: {' '.join(args.cmd)}")
    start = _time.time()
    result = _sp.run(args.cmd)
    duration_ms = int((_time.time() - start) * 1000)
    success = result.returncode == 0

    tx_id = tracker.log(
        action_type=action,
        success=success,
        duration_ms=duration_ms,
        tags=tags,
        note=args.note or "",
    )
    status_str = "ok" if success else f"failed (exit {result.returncode})"
    print(f"[nova] Logged: {action} — {status_str} — {duration_ms}ms — tx:{tx_id}")

    if not success:
        raise SystemExit(result.returncode)


def cmd_agent_status(args: argparse.Namespace) -> None:
    """Show trust score and reputation for an agent."""
    from jito_agent import NovaTracker

    agent_id = args.agent_id or _os_getenv("NOVA_AGENT_ID")
    if not agent_id:
        raise SystemExit("--agent-id is required (or set NOVA_AGENT_ID)")
    wallet_path = args.wallet or _os_getenv("NOVA_WALLET_PATH", f"{agent_id.replace('/', '-')}_wallet.json")
    node_url = args.node_url or _os_getenv("NOVA_NODE_URL", "https://explorer.flowpe.io")

    tracker = NovaTracker.new(agent_id=agent_id, wallet_path=wallet_path, node_url=node_url)
    rep = tracker.get_reputation()
    print(json.dumps(rep, indent=2))
    addr = tracker.wallet["address"]
    print(f"\nPassport: {node_url}/passport?address={addr}")


def cmd_agent_env(args: argparse.Namespace) -> None:
    """Print env vars for the current agent config — pipe into your shell."""
    import os as _os
    wallet_path = args.wallet or f"{args.agent_id.replace('/', '-')}_wallet.json"
    node_url = args.node_url or "https://explorer.flowpe.io"
    print(f"export NOVA_AGENT_ID={args.agent_id}")
    print(f"export NOVA_WALLET_PATH={wallet_path}")
    print(f"export NOVA_NODE_URL={node_url}")


def _os_getenv(key: str, default: str = "") -> str:
    import os as _os
    return _os.environ.get(key, default)


def cmd_network_add_peer(args: argparse.Namespace) -> None:
    response = post_json(
        f"{args.node_url.rstrip('/')}/network/peers/add",
        {"peer": args.peer},
        auth_token=args.auth_token,
    )
    print(json.dumps(response, indent=2))


def cmd_network_sync(args: argparse.Namespace) -> None:
    response = post_json(f"{args.node_url.rstrip('/')}/network/sync", {}, auth_token=args.auth_token)
    print(json.dumps(response, indent=2))


def cmd_node_start(args: argparse.Namespace) -> None:
    run_node(
        host=args.host,
        port=args.port,
        data_dir=args.data_dir,
        public_difficulty=args.public_difficulty,
        public_reward=args.public_reward,
        public_consensus=args.public_consensus,
        public_validators=args.public_validator,
        public_validator_rotation=args.public_validator_rotation,
        public_finality_confirmations=args.public_finality_confirmations,
        public_checkpoint_interval=args.public_checkpoint_interval,
        public_block_time_target=args.public_block_time_target,
        public_faucet_enabled=args.public_faucet_enabled,
        public_faucet_amount=args.public_faucet_amount,
        public_faucet_cooldown_seconds=args.public_faucet_cooldown,
        public_faucet_daily_cap=args.public_faucet_daily_cap,
        mainnet_hardening=args.mainnet_hardening,
        chain_name=args.chain_name,
        token_name=args.token_name,
        token_symbol=args.token_symbol,
        token_decimals=args.token_decimals,
        chain_logo_url=args.chain_logo_url,
        token_logo_url=args.token_logo_url,
        auto_mine=args.auto_mine,
        auto_mine_miner=args.auto_mine_miner,
        auto_mine_interval=args.auto_mine_interval,
        auto_mine_allow_empty=args.auto_mine_allow_empty,
        peers=args.peer,
        peer_token=args.peer_token,
        peer_sync_enabled=args.peer_sync_enabled,
        peer_sync_interval_seconds=args.peer_sync_interval,
        peer_lag_resync_threshold=args.peer_lag_resync_threshold,
        strict_public_signatures=args.strict_public_signatures,
        public_mempool_ttl_seconds=args.public_mempool_ttl,
        public_mempool_max_transactions=args.public_mempool_max_size,
        public_pow_workers=args.public_pow_workers,
        public_pow_nonce_chunk_size=args.public_pow_nonce_chunk,
        require_hsm_signers=args.require_hsm_signers,
        jwt_secret=args.jwt_secret,
        jwt_required=args.jwt_required,
        rate_limit_per_minute=args.rate_limit_per_minute,
        tls_cert=args.tls_cert,
        tls_key=args.tls_key,
        tls_ca=args.tls_ca,
        tls_require_client_cert=args.tls_require_client_cert,
        peer_ca=args.peer_ca,
    )


def cmd_evm_gateway_start(args: argparse.Namespace) -> None:
    node_url = str(args.rpc_node_url or args.node_url).strip()
    if not node_url:
        raise ValueError("Provide --rpc-node-url or global --node-url.")
    auth_token = str(args.rpc_auth_token or args.auth_token).strip()
    run_evm_gateway(
        host=args.host,
        port=args.port,
        node_url=node_url,
        chain_id=args.chain_id,
        auth_token=auth_token,
        peer_ca=args.peer_ca,
        cors_origin=args.cors_origin,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Dual public/private blockchain CLI")
    parser.add_argument("--data-dir", default="node_data")
    parser.add_argument("--public-difficulty", type=int, default=3)
    parser.add_argument("--public-reward", type=float, default=25.0)
    parser.add_argument("--node-url", default="")
    parser.add_argument("--auth-token", default="", help="Bearer token for authenticated node APIs")

    sub = parser.add_subparsers(dest="command", required=True)

    p_wallet_create = sub.add_parser("wallet-create", help="Create wallet")
    p_wallet_create.add_argument("--name", required=True)
    p_wallet_create.add_argument("--out", required=True)
    p_wallet_create.add_argument("--scheme", choices=["ed25519", "rsa-legacy"], default="ed25519")
    p_wallet_create.add_argument("--bits", type=int, default=2048)
    p_wallet_create.set_defaults(func=cmd_wallet_create)

    p_wallet_show = sub.add_parser("wallet-show", help="Show wallet public info")
    p_wallet_show.add_argument("--wallet", required=True)
    p_wallet_show.set_defaults(func=cmd_wallet_show)

    p_wallet_hsm = sub.add_parser("wallet-migrate-hsm", help="Move private key to local file-hsm store")
    p_wallet_hsm.add_argument("--wallet", required=True)
    p_wallet_hsm.add_argument("--key-ref", required=True)
    p_wallet_hsm.add_argument("--hsm-dir", default="hsm_keys")
    p_wallet_hsm.add_argument("--out", default="")
    p_wallet_hsm.set_defaults(func=cmd_wallet_migrate_hsm)

    p_wallet_signer = sub.add_parser("wallet-set-signer", help="Set wallet signer provider (local/file-hsm/aws-kms/gcp-kms/azure-kv)")
    p_wallet_signer.add_argument("--wallet", required=True)
    p_wallet_signer.add_argument("--signer-type", required=True)
    p_wallet_signer.add_argument("--config-json", default="{}")
    p_wallet_signer.add_argument("--drop-private-key", action="store_true")
    p_wallet_signer.add_argument("--out", default="")
    p_wallet_signer.set_defaults(func=cmd_wallet_set_signer)

    p_wallet_audit = sub.add_parser("wallet-security-audit", help="Audit wallet signer/private key posture")
    p_wallet_audit.add_argument("--wallet-dir", default="wallets")
    p_wallet_audit.add_argument("--require-nonlocal", action="store_true")
    p_wallet_audit.add_argument("--require-no-private-key", action="store_true")
    p_wallet_audit.set_defaults(func=cmd_wallet_security_audit)

    p_audit_wallets = sub.add_parser("audit-wallets", help="Run wallet signer/private-key audit against node API")
    p_audit_wallets.add_argument("--node-url", required=True)
    p_audit_wallets.add_argument("--auth-token", default="")
    p_audit_wallets.add_argument("--require-nonlocal", action="store_true")
    p_audit_wallets.add_argument("--require-no-private-key", action="store_true")
    p_audit_wallets.add_argument("--fail-on-violations", action="store_true")
    p_audit_wallets.set_defaults(func=cmd_audit_wallets)

    p_audit_security = sub.add_parser("audit-security", help="Show runtime security posture from node API")
    p_audit_security.add_argument("--node-url", required=True)
    p_audit_security.add_argument("--auth-token", default="")
    p_audit_security.set_defaults(func=cmd_audit_security)

    p_auth = sub.add_parser("auth-token", help="Generate HS256 JWT token for node auth")
    p_auth.add_argument("--secret", required=True)
    p_auth.add_argument("--subject", default="cli-user")
    p_auth.add_argument("--ttl-seconds", type=int, default=3600)
    p_auth.add_argument("--claims-json", default="{}")
    p_auth.set_defaults(func=cmd_auth_token)

    p_public_tx = sub.add_parser("public-tx", help="Create public payment tx")
    p_public_tx.add_argument("--wallet", required=True)
    p_public_tx.add_argument("--to", required=True)
    p_public_tx.add_argument("--amount", type=float, required=True)
    p_public_tx.add_argument("--fee", type=float, default=0.0, help="Optional priority fee paid to block producer")
    p_public_tx.set_defaults(func=cmd_public_tx)

    p_public_mine = sub.add_parser("public-mine", help="Mine public pending tx")
    p_public_mine.add_argument("--miner", required=True)
    p_public_mine.set_defaults(func=cmd_public_mine)

    p_public_balance = sub.add_parser("public-balance", help="Get public balance")
    p_public_balance.add_argument("--address", required=True)
    p_public_balance.set_defaults(func=cmd_public_balance)

    p_public_validate = sub.add_parser("public-validate", help="Validate public chain")
    p_public_validate.set_defaults(func=cmd_public_validate)

    p_public_oracle = sub.add_parser("public-register-oracle", help="Register oracle address allowed to post on-chain prices")
    p_public_oracle.add_argument("--wallet", default="")
    p_public_oracle.add_argument("--oracle", default="")
    p_public_oracle.set_defaults(func=cmd_public_register_oracle)

    p_public_price_update = sub.add_parser("public-price-update", help="Create on-chain price update transaction")
    p_public_price_update.add_argument("--wallet", required=True)
    p_public_price_update.add_argument("--symbol", required=True)
    p_public_price_update.add_argument("--price", type=float, required=True)
    p_public_price_update.add_argument("--source", default="manual-cli")
    p_public_price_update.set_defaults(func=cmd_public_price_update)

    p_public_price = sub.add_parser("public-price", help="Get latest on-chain prices")
    p_public_price.add_argument("--symbol", default="")
    p_public_price.set_defaults(func=cmd_public_price)

    p_public_consensus = sub.add_parser("public-consensus", help="Show public consensus mode and validators")
    p_public_consensus.set_defaults(func=cmd_public_consensus)

    p_public_finality = sub.add_parser("public-finality", help="Show public finality/checkpoint status")
    p_public_finality.set_defaults(func=cmd_public_finality)

    p_public_slo = sub.add_parser("public-slo", help="Show SLO/health summary for public chain")
    p_public_slo.set_defaults(func=cmd_public_slo)

    p_public_perf = sub.add_parser("public-performance", help="Show public throughput/performance summary")
    p_public_perf.add_argument("--window-blocks", type=int, default=60)
    p_public_perf.set_defaults(func=cmd_public_performance)

    p_public_ai_stakes = sub.add_parser("public-ai-stakes", help="Show AI provider stake/slash state")
    p_public_ai_stakes.set_defaults(func=cmd_public_ai_stakes)

    p_public_faucet_status = sub.add_parser("public-faucet-status", help="Show public faucet config and remaining cap")
    p_public_faucet_status.set_defaults(func=cmd_public_faucet_status)

    p_public_faucet_claim = sub.add_parser("public-faucet-claim", help="Claim faucet funds to an address")
    p_public_faucet_claim.add_argument("--to", required=True, help="Recipient address (or @walletName)")
    p_public_faucet_claim.add_argument("--amount", type=float, default=0.0, help="Optional claim amount (default faucet amount)")
    p_public_faucet_claim.set_defaults(func=cmd_public_faucet_claim)

    p_public_validator_update = sub.add_parser("public-validator-update", help="Queue on-chain validator add/remove tx")
    p_public_validator_update.add_argument("--wallet", required=True, help="Current validator wallet")
    p_public_validator_update.add_argument("--action", required=True, choices=["add", "remove"])
    p_public_validator_update.add_argument("--validator", required=True, help="Validator address to add/remove")
    p_public_validator_update.set_defaults(func=cmd_public_validator_update)

    p_public_ai_stake = sub.add_parser("public-ai-provider-stake", help="Queue AI provider staking tx")
    p_public_ai_stake.add_argument("--wallet", required=True, help="Provider wallet")
    p_public_ai_stake.add_argument("--amount", type=float, required=True)
    p_public_ai_stake.set_defaults(func=cmd_public_ai_provider_stake)

    p_public_ai_slash = sub.add_parser("public-ai-provider-slash", help="Queue AI provider slashing tx")
    p_public_ai_slash.add_argument("--wallet", required=True, help="Validator wallet")
    p_public_ai_slash.add_argument("--provider", required=True, help="Provider address")
    p_public_ai_slash.add_argument("--amount", type=float, required=True)
    p_public_ai_slash.add_argument("--reason", default="")
    p_public_ai_slash.add_argument("--recipient", default="", help="Optional slash recipient address")
    p_public_ai_slash.set_defaults(func=cmd_public_ai_provider_slash)

    p_identity_claim = sub.add_parser("identity-claim", help="Claim an on-chain identity handle")
    p_identity_claim.add_argument("--wallet", required=True, help="Wallet file path")
    p_identity_claim.add_argument("--handle", required=True, help="Unique handle (3-32 chars, lowercase alphanumeric + underscore)")
    p_identity_claim.add_argument("--bio", default="", help="Short bio")
    p_identity_claim.add_argument("--links-json", dest="links_json", default="", help='JSON object of links e.g. \'{"twitter":"@foo"}\'')
    p_identity_claim.set_defaults(func=cmd_identity_claim)

    p_identity_update = sub.add_parser("identity-update", help="Update bio/links for an existing identity")
    p_identity_update.add_argument("--wallet", required=True, help="Wallet file path")
    p_identity_update.add_argument("--bio", default="", help="Updated bio")
    p_identity_update.add_argument("--links-json", dest="links_json", default="", help="JSON object of links")
    p_identity_update.set_defaults(func=cmd_identity_update)

    p_agent_register = sub.add_parser("agent-register", help="Register an AI agent on-chain")
    p_agent_register.add_argument("--wallet", required=True, help="Owner wallet file path")
    p_agent_register.add_argument("--agent-id", dest="agent_id", required=True, help="Unique agent identifier")
    p_agent_register.add_argument("--name", required=True, help="Agent display name")
    p_agent_register.add_argument("--capabilities", default="", help="Comma-separated capability tags")
    p_agent_register.add_argument("--version-hash", dest="version_hash", default="", help="Version hash of agent code/model")
    p_agent_register.set_defaults(func=cmd_agent_register)

    p_agent_attest = sub.add_parser("agent-attest", help="Attest to a specific activity log (any counterparty)")
    p_agent_attest.add_argument("--wallet", required=True, help="Attester wallet file path")
    p_agent_attest.add_argument("--log-id", dest="log_id", required=True, help="Log ID to attest")
    p_agent_attest.add_argument("--sentiment", required=True, choices=["positive", "negative"])
    p_agent_attest.add_argument("--note", default="", help="Optional attestation note")
    p_agent_attest.set_defaults(func=cmd_agent_attest)

    p_agent_log = sub.add_parser("agent-log", help="Log off-chain agent activity to build portable reputation")
    p_agent_log.add_argument("--wallet", required=True)
    p_agent_log.add_argument("--agent-id", dest="agent_id", required=True)
    p_agent_log.add_argument("--action-type", dest="action_type", required=True,
                              help="e.g. task_completed, code_review, data_analysis")
    p_agent_log.add_argument("--output-hash", dest="output_hash", default="")
    p_agent_log.add_argument("--evidence-url", dest="evidence_url", default="",
                              help="URL to off-chain evidence (https://, ipfs://, ar://)")
    p_agent_log.add_argument("--platform", default="", help="e.g. langchain, crewai, github")
    p_agent_log.add_argument("--external-ref", dest="external_ref", default="",
                              help="External reference (PR#123, job-id, etc.)")
    p_agent_log.add_argument("--tags", default="", help="Comma-separated tags e.g. finance,coding")
    p_agent_log.add_argument("--stake", type=float, default=0.0, help="NOVA to lock (increases trust tier)")
    p_agent_log.add_argument("--failed", action="store_true", help="Mark activity as failed")
    p_agent_log.add_argument("--note", default="")
    p_agent_log.set_defaults(func=cmd_agent_log)

    p_agent_challenge = sub.add_parser("agent-challenge", help="Challenge a specific activity log")
    p_agent_challenge.add_argument("--wallet", required=True)
    p_agent_challenge.add_argument("--log-id", dest="log_id", required=True)
    p_agent_challenge.add_argument("--stake", type=float, required=True, help="NOVA stake to lock")
    p_agent_challenge.add_argument("--reason", default="")
    p_agent_challenge.set_defaults(func=cmd_agent_challenge)

    p_challenge_resolve = sub.add_parser("agent-challenge-resolve", help="Validator resolves a challenge (slash or clear)")
    p_challenge_resolve.add_argument("--wallet", required=True, help="Validator wallet")
    p_challenge_resolve.add_argument("--challenge-id", dest="challenge_id", required=True)
    p_challenge_resolve.add_argument("--verdict", required=True, choices=["slash", "clear"])
    p_challenge_resolve.add_argument("--note", default="")
    p_challenge_resolve.set_defaults(func=cmd_agent_challenge_resolve)

    p_param_propose = sub.add_parser(
        "agent-param-propose",
        help="Governance step 1: propose agent trust param changes (validator only)"
    )
    p_param_propose.add_argument("--wallet", required=True, help="Validator wallet file")
    p_param_propose.add_argument(
        "--changes", required=True,
        help='JSON dict of parameters to change, e.g. \'{"challenge_window_blocks": 100}\''
    )
    p_param_propose.add_argument("--reason", default="", help="Human-readable reason for the change")
    p_param_propose.add_argument("--vote-window-blocks", type=int, default=100,
                                  help="Blocks before proposal expires (default 100)")
    p_param_propose.set_defaults(func=cmd_agent_param_propose)

    p_param_endorse = sub.add_parser(
        "agent-param-endorse",
        help="Governance step 2: endorse or reject a pending param proposal (validator only)"
    )
    p_param_endorse.add_argument("--wallet", required=True, help="Validator wallet file")
    p_param_endorse.add_argument("--proposal-id", required=True, dest="proposal_id")
    p_param_endorse.add_argument("--no-approve", action="store_true", help="Vote to reject the proposal")
    p_param_endorse.set_defaults(func=cmd_agent_param_endorse)

    p_passport = sub.add_parser("agent-passport", help="Show portable trust passport for an agent")
    p_passport.add_argument("--address", required=True)
    p_passport.set_defaults(func=cmd_agent_passport)

    p_agent_node = sub.add_parser("agent-node-start", help="Start a lightweight agent data node (no block production)")
    p_agent_node.add_argument("--wallet", required=True, help="Agent wallet file")
    p_agent_node.add_argument("--agent-id", dest="agent_id", required=True)
    p_agent_node.add_argument("--port", type=int, default=8100)
    p_agent_node.add_argument("--platform", default="", help="Default platform tag for logs")
    p_agent_node.set_defaults(func=cmd_agent_node_start)

    # identity-verify
    p_identity_verify = sub.add_parser("identity-verify", help="Notary attests to identity")
    p_identity_verify.add_argument("--wallet", required=True)
    p_identity_verify.add_argument("--target", required=True, help="Address to verify")
    p_identity_verify.add_argument("--level", default="basic", choices=["basic", "kyc", "accredited"])
    p_identity_verify.set_defaults(func=cmd_identity_verify)

    # task-delegate
    p_task_delegate = sub.add_parser("task-delegate", help="Create AI job task")
    p_task_delegate.add_argument("--wallet", required=True)
    p_task_delegate.add_argument("--agent-id", dest="agent_id", default="")
    p_task_delegate.add_argument("--title", required=True)
    p_task_delegate.add_argument("--description", default="")
    p_task_delegate.add_argument("--reward", required=True, type=float)
    p_task_delegate.add_argument("--min-reputation", dest="min_reputation", default=0.0, type=float)
    p_task_delegate.set_defaults(func=cmd_task_delegate)

    # task-complete
    p_task_complete = sub.add_parser("task-complete", help="Agent submits task result")
    p_task_complete.add_argument("--wallet", required=True)
    p_task_complete.add_argument("--task-id", dest="task_id", required=True)
    p_task_complete.add_argument("--result-hash", dest="result_hash", default="")
    p_task_complete.add_argument("--note", default="")
    p_task_complete.set_defaults(func=cmd_task_complete)

    # task-review
    p_task_review = sub.add_parser("task-review", help="Owner reviews task result")
    p_task_review.add_argument("--wallet", required=True)
    p_task_review.add_argument("--task-id", dest="task_id", required=True)
    p_task_review.add_argument("--approved", action="store_true", default=True)
    p_task_review.add_argument("--rejected", dest="approved", action="store_false")
    p_task_review.add_argument("--quality-score", dest="quality_score", default=50, type=int)
    p_task_review.add_argument("--note", default="")
    p_task_review.set_defaults(func=cmd_task_review)

    # task-dispute
    p_task_dispute = sub.add_parser("task-dispute", help="Dispute a completed task")
    p_task_dispute.add_argument("--wallet", required=True)
    p_task_dispute.add_argument("--task-id", dest="task_id", required=True)
    p_task_dispute.add_argument("--reason", default="")
    p_task_dispute.set_defaults(func=cmd_task_dispute)

    # governance-propose
    p_governance_propose = sub.add_parser("governance-propose", help="Submit governance proposal")
    p_governance_propose.add_argument("--wallet", required=True)
    p_governance_propose.add_argument("--title", required=True)
    p_governance_propose.add_argument("--description", default="")
    p_governance_propose.add_argument("--param-changes", dest="param_changes", default="{}", help="JSON dict of param changes")
    p_governance_propose.add_argument("--vote-window-blocks", dest="vote_window_blocks", default=100, type=int)
    p_governance_propose.set_defaults(func=cmd_governance_propose)

    # governance-vote
    p_governance_vote = sub.add_parser("governance-vote", help="Vote on governance proposal")
    p_governance_vote.add_argument("--wallet", required=True)
    p_governance_vote.add_argument("--proposal-id", dest="proposal_id", required=True)
    p_governance_vote.add_argument("--yes", action="store_true", default=True)
    p_governance_vote.add_argument("--no", dest="yes", action="store_false")
    p_governance_vote.set_defaults(func=cmd_governance_vote)

    # reputation
    p_reputation = sub.add_parser("reputation", help="Get reputation for an address")
    p_reputation.add_argument("--address", required=True)
    p_reputation.set_defaults(func=cmd_reputation)

    # reputation-leaderboard
    p_rep_leaderboard = sub.add_parser("reputation-leaderboard", help="Show reputation leaderboard")
    p_rep_leaderboard.add_argument("--limit", default=20, type=int)
    p_rep_leaderboard.set_defaults(func=cmd_reputation_leaderboard)

    # tasks
    p_tasks = sub.add_parser("tasks", help="List AI tasks")
    p_tasks.add_argument("--status", default=None)
    p_tasks.add_argument("--owner", default=None)
    p_tasks.set_defaults(func=cmd_tasks)

    # governance-proposals
    p_gov_proposals = sub.add_parser("governance-proposals", help="List governance proposals")
    p_gov_proposals.add_argument("--status", default=None)
    p_gov_proposals.set_defaults(func=cmd_governance_proposals)

    # activity-feed
    p_activity = sub.add_parser("activity-feed", help="Show live activity feed")
    p_activity.add_argument("--limit", default=50, type=int)
    p_activity.set_defaults(func=cmd_activity_feed)

    # validator-nominate
    p_val_nominate = sub.add_parser("validator-nominate", help="Nominate yourself as validator candidate")
    p_val_nominate.add_argument("--wallet", required=True)
    p_val_nominate.set_defaults(func=cmd_validator_nominate)

    # validator-election-vote
    p_val_vote = sub.add_parser("validator-election-vote", help="Vote for a validator candidate")
    p_val_vote.add_argument("--wallet", required=True)
    p_val_vote.add_argument("--candidate", required=True)
    p_val_vote.set_defaults(func=cmd_validator_election_vote)

    # validator-candidates
    p_val_candidates = sub.add_parser("validator-candidates", help="List validator election candidates")
    p_val_candidates.set_defaults(func=cmd_validator_candidates)

    # treasury
    p_treasury = sub.add_parser("treasury", help="Show community treasury info")
    p_treasury.set_defaults(func=cmd_treasury)

    # oracle-assign
    p_oracle_assign = sub.add_parser("oracle-assign", help="Assign AI agent as RWA oracle")
    p_oracle_assign.add_argument("--wallet", required=True)
    p_oracle_assign.add_argument("--asset-id", required=True, dest="asset_id")
    p_oracle_assign.add_argument("--agent-id", default="", dest="agent_id")
    p_oracle_assign.add_argument("--oracle-type", default="price", dest="oracle_type",
                                  choices=["price", "compliance", "condition"])
    p_oracle_assign.set_defaults(func=cmd_oracle_assign)

    # oracle-event
    p_oracle_event = sub.add_parser("oracle-event", help="Fire AI oracle event on RWA asset")
    p_oracle_event.add_argument("--wallet", required=True)
    p_oracle_event.add_argument("--asset-id", required=True, dest="asset_id")
    p_oracle_event.add_argument("--event-type", required=True, dest="event_type",
                                 choices=["price_update", "compliance_passed", "compliance_failed", "condition_update"])
    p_oracle_event.add_argument("--value", required=True)
    p_oracle_event.add_argument("--note", default="")
    p_oracle_event.set_defaults(func=cmd_oracle_event)

    # oracles
    p_oracles = sub.add_parser("oracles", help="List AI oracle assignments")
    p_oracles.set_defaults(func=cmd_oracles)

    # model-register
    p_model_reg = sub.add_parser("model-register", help="Register AI model as on-chain asset")
    p_model_reg.add_argument("--wallet", required=True)
    p_model_reg.add_argument("--model-id", default=None, dest="model_id")
    p_model_reg.add_argument("--name", required=True)
    p_model_reg.add_argument("--description", default="")
    p_model_reg.add_argument("--capabilities", default="", help="Comma-separated list")
    p_model_reg.add_argument("--version-hash", default="", dest="version_hash")
    p_model_reg.add_argument("--inference-fee", default=0.0, type=float, dest="inference_fee")
    p_model_reg.set_defaults(func=cmd_model_register)

    # model-transfer
    p_model_tr = sub.add_parser("model-transfer", help="Transfer model ownership")
    p_model_tr.add_argument("--wallet", required=True)
    p_model_tr.add_argument("--model-id", required=True, dest="model_id")
    p_model_tr.add_argument("--new-owner", required=True, dest="new_owner")
    p_model_tr.set_defaults(func=cmd_model_transfer)

    # model-revenue-share
    p_model_rev = sub.add_parser("model-revenue-share", help="Set model revenue sharing")
    p_model_rev.add_argument("--wallet", required=True)
    p_model_rev.add_argument("--model-id", required=True, dest="model_id")
    p_model_rev.add_argument("--shares-json", default="{}", dest="shares_json", help='JSON e.g. {"addr": 0.2}')
    p_model_rev.set_defaults(func=cmd_model_revenue_share)

    # model-inference
    p_model_inf = sub.add_parser("model-inference", help="Record model inference call")
    p_model_inf.add_argument("--wallet", required=True)
    p_model_inf.add_argument("--model-id", required=True, dest="model_id")
    p_model_inf.add_argument("--input-hash", default="", dest="input_hash")
    p_model_inf.add_argument("--output-hash", default="", dest="output_hash")
    p_model_inf.set_defaults(func=cmd_model_inference)

    # models
    p_models = sub.add_parser("models", help="List registered AI models")
    p_models.add_argument("--owner", default=None)
    p_models.set_defaults(func=cmd_models)

    # pipeline-create
    p_pipe_create = sub.add_parser("pipeline-create", help="Create multi-agent pipeline")
    p_pipe_create.add_argument("--wallet", required=True)
    p_pipe_create.add_argument("--pipeline-id", default=None, dest="pipeline_id")
    p_pipe_create.add_argument("--title", required=True)
    p_pipe_create.add_argument("--steps-json", required=True, dest="steps_json",
                                help='JSON array: [{"agent_id":"...","description":"...","reward_pct":0.5}]')
    p_pipe_create.add_argument("--total-reward", required=True, dest="total_reward", type=float)
    p_pipe_create.set_defaults(func=cmd_pipeline_create)

    # pipeline-step-complete
    p_pipe_step = sub.add_parser("pipeline-step-complete", help="Complete a pipeline step")
    p_pipe_step.add_argument("--wallet", required=True)
    p_pipe_step.add_argument("--pipeline-id", required=True, dest="pipeline_id")
    p_pipe_step.add_argument("--step-index", required=True, type=int, dest="step_index")
    p_pipe_step.add_argument("--result-hash", default="", dest="result_hash")
    p_pipe_step.add_argument("--note", default="")
    p_pipe_step.set_defaults(func=cmd_pipeline_step_complete)

    # pipeline-approve
    p_pipe_approve = sub.add_parser("pipeline-approve", help="Approve/reject completed pipeline")
    p_pipe_approve.add_argument("--wallet", required=True)
    p_pipe_approve.add_argument("--pipeline-id", required=True, dest="pipeline_id")
    p_pipe_approve.add_argument("--approved", action="store_true", default=True)
    p_pipe_approve.add_argument("--rejected", dest="approved", action="store_false")
    p_pipe_approve.add_argument("--note", default="")
    p_pipe_approve.set_defaults(func=cmd_pipeline_approve)

    # pipelines
    p_pipelines = sub.add_parser("pipelines", help="List multi-agent pipelines")
    p_pipelines.add_argument("--status", default=None)
    p_pipelines.set_defaults(func=cmd_pipelines)

    p_public_val_add = sub.add_parser("public-validator-add", help="Add validator for poa mode")
    p_public_val_add.add_argument("--wallet", default="")
    p_public_val_add.add_argument("--validator", default="")
    p_public_val_add.set_defaults(func=cmd_public_validator_add)

    p_public_val_rm = sub.add_parser("public-validator-remove", help="Remove validator for poa mode")
    p_public_val_rm.add_argument("--wallet", default="")
    p_public_val_rm.add_argument("--validator", default="")
    p_public_val_rm.set_defaults(func=cmd_public_validator_remove)

    p_public_auto_start = sub.add_parser("public-auto-mine-start", help="Enable public auto-mining on running node")
    p_public_auto_start.add_argument("--miner", required=True, help="Miner/validator address")
    p_public_auto_start.add_argument("--interval-seconds", type=float, default=8.0)
    p_public_auto_start.add_argument("--allow-empty-blocks", action="store_true")
    p_public_auto_start.set_defaults(func=cmd_public_auto_mine_start)

    p_public_auto_stop = sub.add_parser("public-auto-mine-stop", help="Disable public auto-mining on running node")
    p_public_auto_stop.set_defaults(func=cmd_public_auto_mine_stop)

    p_public_auto_status = sub.add_parser("public-auto-mine-status", help="Show public auto-mining status")
    p_public_auto_status.set_defaults(func=cmd_public_auto_mine_status)

    p_branding = sub.add_parser("chain-branding", help="Set chain/token logo URLs used by explorer/scanner")
    p_branding.add_argument("--chain-logo-url", default=None)
    p_branding.add_argument("--token-logo-url", default=None)
    p_branding.set_defaults(func=cmd_chain_branding)

    p_private_register = sub.add_parser("private-register", help="Bootstrap register participant/issuer/validator/notary")
    p_private_register.add_argument("--wallet", required=True)
    p_private_register.add_argument("--issuer", action="store_true")
    p_private_register.add_argument("--validator", action="store_true")
    p_private_register.add_argument("--notary", action="store_true")
    p_private_register.add_argument("--domains", default="", help="Comma-separated domain ids")
    p_private_register.add_argument("--attributes-json", default="", help='JSON object, e.g. {"kyc":true}')
    p_private_register.set_defaults(func=cmd_private_register)

    p_private_propose = sub.add_parser("private-propose", help="Create governance proposal")
    p_private_propose.add_argument("--wallet", required=True)
    p_private_propose.add_argument("--action", required=True)
    p_private_propose.add_argument("--payload-json", default="{}")
    p_private_propose.add_argument("--payload-file", default="")
    p_private_propose.set_defaults(func=cmd_private_propose)

    p_private_approve = sub.add_parser("private-approve", help="Approve governance proposal")
    p_private_approve.add_argument("--wallet", required=True)
    p_private_approve.add_argument("--proposal-id", required=True)
    p_private_approve.set_defaults(func=cmd_private_approve)

    p_private_gov = sub.add_parser("private-governance", help="Show governance proposals/state")
    p_private_gov.set_defaults(func=cmd_private_governance)

    p_private_issue = sub.add_parser("private-issue", help="Issue real-world asset on private chain")
    p_private_issue.add_argument("--wallet", required=True, help="Issuer wallet")
    p_private_issue.add_argument("--asset-id", required=True)
    p_private_issue.add_argument("--amount", type=float, required=True)
    p_private_issue.add_argument("--owner", required=True, help="Owner address")
    p_private_issue.add_argument("--domain", required=True)
    p_private_issue.add_argument("--contract-id", default="")
    p_private_issue.add_argument("--metadata-hash", default="")
    p_private_issue.add_argument("--visibility", default="", help="Comma-separated addresses")
    p_private_issue.set_defaults(func=cmd_private_issue)

    p_private_transfer = sub.add_parser("private-transfer", help="Transfer private asset units")
    p_private_transfer.add_argument("--wallet", required=True, help="Current owner wallet")
    p_private_transfer.add_argument("--asset-id", required=True)
    p_private_transfer.add_argument("--amount", type=float, required=True)
    p_private_transfer.add_argument("--to", required=True)
    p_private_transfer.add_argument("--visibility", default="", help="Comma-separated addresses")
    p_private_transfer.set_defaults(func=cmd_private_transfer)

    p_private_ai_model = sub.add_parser("private-ai-model-register", help="Register AI model metadata on private chain")
    p_private_ai_model.add_argument("--wallet", required=True, help="Model owner wallet")
    p_private_ai_model.add_argument("--model-id", required=True)
    p_private_ai_model.add_argument("--model-hash", required=True)
    p_private_ai_model.add_argument("--version", required=True)
    p_private_ai_model.add_argument("--price-per-call", type=float, required=True)
    p_private_ai_model.add_argument("--visibility", default="", help="Comma-separated viewer addresses")
    p_private_ai_model.add_argument("--metadata-json", default="{}")
    p_private_ai_model.set_defaults(func=cmd_private_ai_model_register)

    p_private_ai_create = sub.add_parser("private-ai-job-create", help="Create AI job request on private chain")
    p_private_ai_create.add_argument("--wallet", required=True, help="Requester wallet")
    p_private_ai_create.add_argument("--job-id", required=True)
    p_private_ai_create.add_argument("--model-id", required=True)
    p_private_ai_create.add_argument("--input-hash", required=True)
    p_private_ai_create.add_argument("--max-payment", type=float, required=True)
    p_private_ai_create.add_argument("--visibility", default="", help="Comma-separated viewer addresses")
    p_private_ai_create.add_argument("--metadata-json", default="{}")
    p_private_ai_create.set_defaults(func=cmd_private_ai_job_create)

    p_private_ai_result = sub.add_parser("private-ai-job-result", help="Submit AI job result hash on private chain")
    p_private_ai_result.add_argument("--wallet", required=True, help="Provider wallet")
    p_private_ai_result.add_argument("--job-id", required=True)
    p_private_ai_result.add_argument("--result-hash", required=True)
    p_private_ai_result.add_argument("--quality-score", type=float, default=1.0)
    p_private_ai_result.add_argument("--metadata-json", default="{}")
    p_private_ai_result.set_defaults(func=cmd_private_ai_job_result)

    p_private_ai_settle = sub.add_parser("private-ai-job-settle", help="Settle AI job on private chain")
    p_private_ai_settle.add_argument("--wallet", required=True, help="Validator/notary wallet")
    p_private_ai_settle.add_argument("--job-id", required=True)
    p_private_ai_settle.add_argument("--payout", type=float, required=True)
    p_private_ai_settle.add_argument("--slash-provider", type=float, default=0.0)
    p_private_ai_settle.add_argument("--reason", default="")
    p_private_ai_settle.set_defaults(func=cmd_private_ai_job_settle)

    p_private_ai_models = sub.add_parser("private-ai-models", help="List registered AI models")
    p_private_ai_models.add_argument("--owner", default="")
    p_private_ai_models.add_argument("--limit", type=int, default=200)
    p_private_ai_models.set_defaults(func=cmd_private_ai_models)

    p_private_ai_jobs = sub.add_parser("private-ai-jobs", help="List AI jobs")
    p_private_ai_jobs.add_argument("--status", default="")
    p_private_ai_jobs.add_argument("--participant", default="")
    p_private_ai_jobs.add_argument("--limit", type=int, default=200)
    p_private_ai_jobs.set_defaults(func=cmd_private_ai_jobs)

    p_private_domains = sub.add_parser("private-domains", help="Show domain-wise private chain summary")
    p_private_domains.add_argument("--domain-id", default="")
    p_private_domains.add_argument("--include-pending", action="store_true")
    p_private_domains.set_defaults(func=cmd_private_domains)

    p_private_seal = sub.add_parser("private-seal", help="Seal pending private tx into pending block")
    p_private_seal.add_argument("--wallet", required=True, help="Validator wallet")
    p_private_seal.set_defaults(func=cmd_private_seal)

    p_private_attest = sub.add_parser("private-attest", help="Notary attest pending block")
    p_private_attest.add_argument("--wallet", required=True, help="Notary wallet")
    p_private_attest.add_argument("--block-hash", default="", help="Optional, default first pending")
    p_private_attest.set_defaults(func=cmd_private_attest)

    p_private_finalize = sub.add_parser("private-finalize", help="Finalize pending block")
    p_private_finalize.add_argument("--block-hash", default="", help="Optional, default first pending")
    p_private_finalize.set_defaults(func=cmd_private_finalize)

    p_private_pending = sub.add_parser("private-pending", help="Show pending private blocks/finality")
    p_private_pending.set_defaults(func=cmd_private_pending)

    p_private_holdings = sub.add_parser("private-holdings", help="Show private asset balances")
    p_private_holdings.add_argument("--address", default="")
    p_private_holdings.add_argument("--viewer", default="", help="Visibility-filtered viewer address")
    p_private_holdings.add_argument("--include-pending", action="store_true")
    p_private_holdings.set_defaults(func=cmd_private_holdings)

    p_private_view = sub.add_parser("private-view", help="Show privacy-filtered chain view for a party")
    p_private_view.add_argument("--viewer", required=True)
    p_private_view.set_defaults(func=cmd_private_view)

    p_private_validate = sub.add_parser("private-validate", help="Validate private chain")
    p_private_validate.set_defaults(func=cmd_private_validate)

    p_peer = sub.add_parser("network-add-peer", help="Add peer to a running node")
    p_peer.add_argument("--node-url", required=True)
    p_peer.add_argument("--peer", required=True)
    p_peer.set_defaults(func=cmd_network_add_peer)

    p_sync = sub.add_parser("network-sync", help="Force a sync from peers")
    p_sync.add_argument("--node-url", required=True)
    p_sync.set_defaults(func=cmd_network_sync)

    p_node = sub.add_parser("node-start", help="Start HTTP node server")
    p_node.add_argument("--host", default="127.0.0.1")
    p_node.add_argument("--port", type=int, default=8000)
    p_node.add_argument("--data-dir", default="node_data")
    p_node.add_argument("--public-difficulty", type=int, default=3)
    p_node.add_argument("--public-reward", type=float, default=25.0)
    p_node.add_argument("--public-consensus", choices=["pow", "poa"], default="pow")
    p_node.add_argument("--public-validator", action="append", default=[], help="Validator address for poa mode")
    p_node.add_argument(
        "--public-validator-rotation",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable strict proposer rotation in poa mode",
    )
    p_node.add_argument("--public-finality-confirmations", type=int, default=5)
    p_node.add_argument("--public-checkpoint-interval", type=int, default=20)
    p_node.add_argument("--public-block-time-target", type=float, default=5.0)
    p_node.add_argument(
        "--public-faucet-enabled",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Enable built-in public faucet endpoint",
    )
    p_node.add_argument("--public-faucet-amount", type=float, default=0.0, help="Default faucet claim amount")
    p_node.add_argument("--public-faucet-cooldown", type=float, default=3600.0, help="Faucet cooldown per address (seconds)")
    p_node.add_argument("--public-faucet-daily-cap", type=float, default=0.0, help="Faucet 24h cap (0 = unlimited)")
    p_node.add_argument(
        "--mainnet-hardening",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Enforce production guardrails: poa + >=2 validators + rotation + faucet disabled",
    )
    p_node.add_argument("--chain-name", default="Nova Network")
    p_node.add_argument("--token-name", default="NOVA")
    p_node.add_argument("--token-symbol", default="NOVA")
    p_node.add_argument("--token-decimals", type=int, default=18)
    p_node.add_argument("--chain-logo-url", default="", help="Brand logo URL for explorer/scanner")
    p_node.add_argument("--token-logo-url", default="", help="Native token logo URL for explorer/scanner")
    p_node.add_argument("--auto-mine", action="store_true", help="Enable automatic public mining")
    p_node.add_argument("--auto-mine-miner", default="", help="Miner address used by auto-miner")
    p_node.add_argument("--auto-mine-interval", type=float, default=8.0, help="Auto-miner block interval in seconds")
    p_node.add_argument("--auto-mine-allow-empty", action="store_true", help="Allow empty block auto-mining")
    p_node.add_argument("--peer", action="append", default=[])
    p_node.add_argument("--peer-token", default="", help="Bearer token for outgoing peer sync calls")
    p_node.add_argument(
        "--peer-sync-enabled",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable background peer sync worker",
    )
    p_node.add_argument("--peer-sync-interval", type=float, default=6.0, help="Peer sync interval in seconds")
    p_node.add_argument(
        "--peer-lag-resync-threshold",
        type=int,
        default=3,
        help="Pull full snapshot when peer public chain is this many blocks ahead",
    )
    p_node.add_argument(
        "--strict-public-signatures",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Require canonical public payment signatures (disable legacy fallback)",
    )
    p_node.add_argument(
        "--public-mempool-ttl",
        type=float,
        default=900.0,
        help="Pending public tx TTL in seconds (0 disables expiry)",
    )
    p_node.add_argument(
        "--public-mempool-max-size",
        type=int,
        default=5000,
        help="Maximum pending public tx in mempool (0 disables cap)",
    )
    p_node.add_argument(
        "--public-pow-workers",
        type=int,
        default=1,
        help="Parallel worker processes for PoW nonce search (1 disables parallel mode)",
    )
    p_node.add_argument(
        "--public-pow-nonce-chunk",
        type=int,
        default=10000,
        help="Nonce attempts per worker batch during parallel PoW search",
    )
    p_node.add_argument(
        "--require-hsm-signers",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Reject local signer wallets for transaction-authoring API calls",
    )
    p_node.add_argument("--jwt-secret", default="", help="JWT HS256 secret to verify incoming bearer tokens")
    p_node.add_argument("--jwt-required", action="store_true", help="Require JWT on non-UI/non-health endpoints")
    p_node.add_argument(
        "--rate-limit-per-minute",
        type=int,
        default=300,
        help="Per-IP API request limit per minute (0 disables)",
    )
    p_node.add_argument("--tls-cert", default="", help="TLS certificate path")
    p_node.add_argument("--tls-key", default="", help="TLS private key path")
    p_node.add_argument("--tls-ca", default="", help="CA file path for mTLS client verification")
    p_node.add_argument("--tls-require-client-cert", action="store_true", help="Enable mTLS client cert enforcement")
    p_node.add_argument("--peer-ca", default="", help="CA file for verifying HTTPS peer certificates")
    p_node.set_defaults(func=cmd_node_start)

    # ── Operator commands ──────────────────────────────────────────────────────
    p_init = sub.add_parser("init", help="Set up a Nova wallet for your agent — prints env vars to copy")
    p_init.add_argument("--agent-id", required=True, help="Unique agent identifier e.g. my-research-agent")
    p_init.add_argument("--wallet", default="", help="Wallet file path (default: <agent-id>_wallet.json)")
    p_init.add_argument("--node-url", default="", help="Nova node URL (default: https://explorer.flowpe.io)")
    p_init.set_defaults(func=cmd_agent_init)

    p_run = sub.add_parser("run", help="Wrap any agent command — auto-logs timing and result to Nova")
    p_run.add_argument("--agent-id", default="", help="Agent ID (or set NOVA_AGENT_ID env var)")
    p_run.add_argument("--wallet", default="", help="Wallet path (or set NOVA_WALLET_PATH env var)")
    p_run.add_argument("--node-url", default="", help="Nova node URL (or set NOVA_NODE_URL env var)")
    p_run.add_argument("--tags", default="", help="Comma-separated tags e.g. biology,literature-review")
    p_run.add_argument("--action", default="", help="Action label (default: agent_run)")
    p_run.add_argument("--note", default="", help="Short description of what this run does")
    p_run.add_argument("cmd", nargs=argparse.REMAINDER, help="Command to run, after --")
    p_run.set_defaults(func=cmd_agent_run)

    p_status = sub.add_parser("status", help="Show trust score and reputation for your agent")
    p_status.add_argument("--agent-id", default="", help="Agent ID (or set NOVA_AGENT_ID)")
    p_status.add_argument("--wallet", default="", help="Wallet path (or set NOVA_WALLET_PATH)")
    p_status.add_argument("--node-url", default="", help="Nova node URL (or set NOVA_NODE_URL)")
    p_status.set_defaults(func=cmd_agent_status)

    p_env = sub.add_parser("env", help="Print Nova env vars for your agent — eval or copy into .env")
    p_env.add_argument("--agent-id", required=True)
    p_env.add_argument("--wallet", default="")
    p_env.add_argument("--node-url", default="")
    p_env.set_defaults(func=cmd_agent_env)

    p_rpc = sub.add_parser("evm-gateway-start", help="Start starter EVM JSON-RPC gateway against this chain")
    p_rpc.add_argument("--host", default="127.0.0.1")
    p_rpc.add_argument("--port", type=int, default=8545)
    p_rpc.add_argument("--rpc-node-url", default="", help="Upstream node URL (defaults to global --node-url)")
    p_rpc.add_argument("--rpc-auth-token", default="", help="Bearer token for upstream node (or use global --auth-token)")
    p_rpc.add_argument("--chain-id", type=int, default=149, help="EVM chain id exposed to wallets")
    p_rpc.add_argument("--peer-ca", default="", help="CA file for HTTPS upstream node verification")
    p_rpc.add_argument("--cors-origin", default="*", help="CORS Access-Control-Allow-Origin value")
    p_rpc.set_defaults(func=cmd_evm_gateway_start)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except Exception as exc:  # pylint: disable=broad-except
        print(f"Error: {exc}")
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
