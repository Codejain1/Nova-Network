"""
governance_voter.py — automatically vote YES on all open governance proposals.

Usage:
    python governance_voter.py --wallet wallet.json --node https://explorer.flowpe.io
"""
import argparse
import time

from jito_agent import JitoClient, load_wallet


def main():
    parser = argparse.ArgumentParser(description="JITO governance auto-voter")
    parser.add_argument("--wallet", default="wallet.json", help="Path to wallet JSON")
    parser.add_argument("--node", default="https://explorer.flowpe.io")
    parser.add_argument("--vote", choices=["yes", "no"], default="yes")
    parser.add_argument("--interval", type=float, default=60.0,
                        help="Poll interval in seconds")
    args = parser.parse_args()

    wallet = load_wallet(args.wallet)
    client = JitoClient(args.node)
    vote_bool = args.vote == "yes"
    voted = set()

    print(f"Governance voter started — casting '{args.vote}' on all open proposals")
    print(f"Wallet: {wallet['address']}")

    while True:
        try:
            proposals = client.get_proposals()
            open_props = [p for p in proposals
                          if p.get("status") == "active" and p["proposal_id"] not in voted]
            for prop in open_props:
                pid = prop["proposal_id"]
                title = prop.get("title", pid)
                try:
                    resp = client.vote(wallet, pid, vote=vote_bool)
                    print(f"Voted {args.vote.upper()} on '{title}' ({pid[:16]}...)")
                    voted.add(pid)
                except Exception as e:
                    print(f"  Could not vote on {pid[:16]}: {e}")
            if not open_props:
                print(f"No new proposals. Checking again in {args.interval}s...")
        except Exception as e:
            print(f"Error fetching proposals: {e}")
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
