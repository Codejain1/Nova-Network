#!/usr/bin/env python3
import argparse
import json
import sys
import time
from urllib import request, error


def _req(url: str, method: str = "GET", payload=None, token: str = ""):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = request.Request(url, data=data, headers=headers, method=method)
    try:
        with request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode("utf-8")
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code} {exc.reason}: {body}") from exc
    return json.loads(raw) if raw else {}


def main() -> int:
    ap = argparse.ArgumentParser(description="Submit a public-tx load burst and report queue/finalization metrics")
    ap.add_argument("--node-url", required=True, help="Node base URL, e.g. https://explorer.flowpe.io")
    ap.add_argument("--wallet-name", required=True, help="Sender wallet name known to /ui/public/tx")
    ap.add_argument("--to", required=True, help="Recipient address")
    ap.add_argument("--amount", type=float, default=0.0001)
    ap.add_argument("--count", type=int, default=200, help="Number of tx to submit")
    ap.add_argument("--auth-token", default="")
    ap.add_argument("--settle-timeout", type=float, default=120.0, help="Seconds to wait for mempool to drain")
    args = ap.parse_args()

    node = args.node_url.rstrip("/")

    start = time.time()
    submitted = 0
    failures = 0
    for _ in range(max(0, int(args.count))):
        body = {
            "wallet_name": args.wallet_name,
            "to": args.to,
            "amount": float(args.amount),
        }
        try:
            out = _req(f"{node}/ui/public/tx", method="POST", payload=body, token=args.auth_token)
            if out.get("ok"):
                submitted += 1
            else:
                failures += 1
        except Exception:
            failures += 1
    submit_sec = max(1e-9, time.time() - start)

    deadline = time.time() + max(1.0, float(args.settle_timeout))
    pending = -1
    while time.time() < deadline:
        try:
            mem = _req(f"{node}/public/mempool?limit=1", token=args.auth_token)
            pending = int(mem.get("pending_count", 0))
            if pending == 0:
                break
        except Exception:
            pass
        time.sleep(1.0)

    perf = {}
    try:
        perf = _req(f"{node}/public/performance?window_blocks=120", token=args.auth_token)
    except Exception:
        pass

    out = {
        "submitted": submitted,
        "failed": failures,
        "submission_seconds": round(submit_sec, 6),
        "submission_tps": round(submitted / submit_sec, 6),
        "mempool_pending_after_wait": pending,
        "public_performance": perf,
    }
    print(json.dumps(out, indent=2))
    return 0 if failures == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
