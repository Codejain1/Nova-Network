"""
activity_tracker.py — Log off-chain agent work to NOVA for portable reputation.

This example shows how ANY agent (LangChain, CrewAI, custom, or even a human
running scripts) can build verifiable on-chain reputation — without using
Nova's task marketplace.

Usage:
    python activity_tracker.py --wallet wallet.json --node https://explorer.flowpe.io
"""
import argparse
import time

from jito_agent import NovaTracker, load_wallet, create_wallet, save_wallet


def simulate_agent_work(tracker: NovaTracker) -> None:
    """Simulates various types of off-chain work being logged."""

    print("\n── Example 1: Simple log ────────────────────────────────────")
    tracker.log(
        "task_completed",
        success=True,
        tags=["analysis", "finance"],
        note="Analyzed Q4 earnings report",
        duration_ms=1200,
    )
    print("✅ Logged: task_completed")

    print("\n── Example 2: Log with hashed I/O (privacy-preserving) ─────")
    tracker.log(
        "model_run",
        input_data={"prompt": "Summarize this document...", "length": 5000},
        output_data={"summary": "The document covers...", "tokens": 320},
        success=True,
        tags=["summarization", "nlp"],
        platform="langchain",
        duration_ms=3400,
    )
    print("✅ Logged: model_run (I/O hashed, never sent on-chain)")

    print("\n── Example 3: Context manager with automatic timing ─────────")
    with tracker.track("contract_deployed", tags=["blockchain", "solidity"]) as ctx:
        time.sleep(0.05)  # simulate deploy time
        ctx.set_output({"contract_address": "0xabc...", "gas_used": 120000})
        ctx.set_note("Deployed ERC-20 token contract")
    print("✅ Logged: contract_deployed (duration auto-measured)")

    print("\n── Example 4: Failed work still builds history ───────────────")
    with tracker.track("data_pipeline", tags=["etl", "data"]) as ctx:
        ctx.fail("Upstream API timeout after 3 retries")
    print("✅ Logged: data_pipeline (failed — logged with -0.5 rep)")

    print("\n── Example 5: Building-a-blockchain type activity ───────────")
    tracker.log(
        "blockchain_milestone",
        success=True,
        tags=["blockchain", "infrastructure", "p2p"],
        platform="custom",
        note="Dual-chain node synced 10,000 blocks",
        duration_ms=0,
    )
    print("✅ Logged: blockchain_milestone")


def main():
    parser = argparse.ArgumentParser(description="Nova off-chain activity tracker demo")
    parser.add_argument("--wallet", default="wallet.json")
    parser.add_argument("--agent-id", default="demo-tracker-agent")
    parser.add_argument("--node", default="https://explorer.flowpe.io")
    parser.add_argument("--platform", default="demo")
    args = parser.parse_args()

    # Load or create wallet
    try:
        wallet = load_wallet(args.wallet)
        print(f"Loaded wallet: {wallet['address']}")
    except FileNotFoundError:
        wallet = create_wallet(label="tracker-demo")
        save_wallet(wallet, args.wallet)
        print(f"Created wallet: {wallet['address']}")

    tracker = NovaTracker(
        wallet,
        agent_id=args.agent_id,
        node_url=args.node,
        platform=args.platform,
    )

    simulate_agent_work(tracker)

    print("\n── Reputation ────────────────────────────────────────────────")
    try:
        rep = tracker.get_reputation()
        print(f"Score:  {rep.get('score', 0)}")
        print(f"Level:  {rep.get('level', 'Member')}")
        print(f"Badges: {[b['label'] for b in rep.get('badges', [])]}")
        print(f"Logs:   {rep.get('activity_logs', 0)}")
    except Exception as e:
        print(f"Could not fetch reputation: {e}")


if __name__ == "__main__":
    main()
