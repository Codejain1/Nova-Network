"""
nova CLI — operator commands for running agents without code changes.

nova init   — create wallet, print env vars
nova run    — wrap any command, auto-log to Nova
nova status — show trust score
nova env    — print env vars
"""
import argparse
import json
import os
import subprocess
import time


def _get_tracker(agent_id: str, wallet: str, node_url: str):
    from jito_agent import NovaTracker
    agent_id = agent_id or os.environ.get("NOVA_AGENT_ID", "")
    if not agent_id:
        raise SystemExit("--agent-id is required (or set NOVA_AGENT_ID)")
    wallet = wallet or os.environ.get("NOVA_WALLET_PATH", f"{agent_id.replace('/', '-')}_wallet.json")
    node_url = node_url or os.environ.get("NOVA_NODE_URL", "https://explorer.flowpe.io")
    return NovaTracker.new(agent_id=agent_id, wallet_path=wallet, node_url=node_url)


def _get_runtime(agent_id: str, wallet: str, node_url: str):
    from jito_agent import NovaRuntime
    agent_id = agent_id or os.environ.get("NOVA_AGENT_ID", "")
    if not agent_id:
        raise SystemExit("--agent-id is required (or set NOVA_AGENT_ID)")
    wallet = wallet or os.environ.get("NOVA_WALLET_PATH", f"{agent_id.replace('/', '-')}_wallet.json")
    node_url = node_url or os.environ.get("NOVA_NODE_URL", "https://explorer.flowpe.io")
    return NovaRuntime.auto(agent_id=agent_id, wallet_path=wallet, node_url=node_url)


def cmd_init(args):
    from jito_agent.wallet import create_wallet, load_wallet, save_wallet
    wallet_path = args.wallet or f"{args.agent_id.replace('/', '-')}_wallet.json"
    node_url = args.node_url or "https://explorer.flowpe.io"

    if os.path.exists(wallet_path):
        wallet = load_wallet(wallet_path)
        print(f"Wallet already exists: {wallet_path}")
    else:
        wallet = create_wallet(args.agent_id)
        save_wallet(wallet, wallet_path)
        print(f"Wallet created: {wallet_path}")

    print(f"\nAgent ID : {args.agent_id}")
    print(f"Address  : {wallet['address']}")
    print(f"Node     : {node_url}")
    print(f"\n# Copy into your shell or .env:")
    print(f"export NOVA_AGENT_ID={args.agent_id}")
    print(f"export NOVA_WALLET_PATH={wallet_path}")
    print(f"export NOVA_NODE_URL={node_url}")
    print(f"\n# Wrap any agent run:")
    print(f"nova run --agent-id {args.agent_id} --tags <tags> -- <your command>")
    print(f"\n# Passport:")
    print(f"{node_url}/passport?address={wallet['address']}")


def cmd_run(args):
    cmd = args.cmd
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        raise SystemExit("Provide a command after --  e.g.: nova run --agent-id x -- python agent.py")

    runtime = _get_runtime(args.agent_id, args.wallet, args.node_url)
    tags = [t.strip() for t in args.tags.split(",")] if args.tags else []
    action = args.action or "agent_run"

    print(f"[nova] Running: {' '.join(cmd)}")
    start = time.time()
    result = subprocess.run(cmd)
    duration_ms = int((time.time() - start) * 1000)
    success = result.returncode == 0

    tx_id = runtime.log(
        action_type=action,
        success=success,
        duration_ms=duration_ms,
        tags=tags + ["cli"],
        note=args.note or "",
    )
    flush_result = runtime.flush()
    runtime.stop()
    status_str = "ok" if success else f"failed (exit {result.returncode})"
    print(
        f"[nova] Logged: {action} — {status_str} — {duration_ms}ms — "
        f"queue:{tx_id} delivered:{flush_result.get('delivered', 0)}"
    )

    if not success:
        raise SystemExit(result.returncode)


def cmd_status(args):
    tracker = _get_tracker(args.agent_id, args.wallet, args.node_url)
    rep = tracker.get_reputation()
    print(json.dumps(rep, indent=2))
    print(f"\nPassport: {tracker.client.node_url}/passport?address={tracker.wallet['address']}")


def cmd_env(args):
    wallet_path = args.wallet or f"{args.agent_id.replace('/', '-')}_wallet.json"
    node_url = args.node_url or "https://explorer.flowpe.io"
    print(f"export NOVA_AGENT_ID={args.agent_id}")
    print(f"export NOVA_WALLET_PATH={wallet_path}")
    print(f"export NOVA_NODE_URL={node_url}")


def cmd_flush(args):
    runtime = _get_runtime(args.agent_id, args.wallet, args.node_url)
    result = runtime.flush()
    runtime.stop()
    print(json.dumps(result, indent=2))


def cmd_light_status(args):
    runtime = _get_runtime(args.agent_id, args.wallet, args.node_url)
    status = runtime.status()
    runtime.stop()
    print(json.dumps(status, indent=2))


def main():
    parser = argparse.ArgumentParser(
        prog="nova",
        description="Nova Network — portable trust for AI agents",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="Create agent wallet and print env vars")
    p.add_argument("--agent-id", required=True)
    p.add_argument("--wallet", default="")
    p.add_argument("--node-url", default="")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("run", help="Wrap any agent command — auto-logs to Nova")
    p.add_argument("--agent-id", default="")
    p.add_argument("--wallet", default="")
    p.add_argument("--node-url", default="")
    p.add_argument("--tags", default="", help="Comma-separated tags")
    p.add_argument("--action", default="", help="Action label (default: agent_run)")
    p.add_argument("--note", default="")
    p.add_argument("cmd", nargs=argparse.REMAINDER)
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("status", help="Show trust score and reputation")
    p.add_argument("--agent-id", default="")
    p.add_argument("--wallet", default="")
    p.add_argument("--node-url", default="")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("env", help="Print NOVA_* env vars for your agent")
    p.add_argument("--agent-id", required=True)
    p.add_argument("--wallet", default="")
    p.add_argument("--node-url", default="")
    p.set_defaults(func=cmd_env)

    p = sub.add_parser("flush", help="Flush the local Nova runtime queue")
    p.add_argument("--agent-id", default="")
    p.add_argument("--wallet", default="")
    p.add_argument("--node-url", default="")
    p.set_defaults(func=cmd_flush)

    p = sub.add_parser("light-status", help="Show local runtime queue/cache status")
    p.add_argument("--agent-id", default="")
    p.add_argument("--wallet", default="")
    p.add_argument("--node-url", default="")
    p.set_defaults(func=cmd_light_status)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
