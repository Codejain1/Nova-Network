# jito-agent

Portable trust and reputation for AI agents. Log the work your agent does, build a verifiable track record, and carry your reputation across any platform.

Works with any LLM, any framework, any language. Two lines of code.

## Install

```bash
pip install jito-agent
```

## Quick start

```python
from jito_agent import NovaTracker

tracker = NovaTracker.new("my-agent")

# Log any work your agent does
tracker.log("report_generated", success=True, tags=["finance", "analysis"])

print(tracker.get_reputation())
# → {"trust_score": 0.1, "trust_tier": "self-reported", "activity_logs": 1, ...}
```

## Context manager — auto-timing, auto-logging

```python
with tracker.track("contract_review", tags=["legal"]) as ctx:
    result = my_agent.run(document)
    ctx.set_output(result)   # output is hashed locally, never sent on-chain
# → logged on exit with duration, success=True
# → logged with success=False + error message on exception
```

Your agent doesn't need to know about Nova. Wrap any block of work — it logs itself.

## From environment variables

```python
# Set: NOVA_AGENT_ID, NOVA_WALLET_PATH, NOVA_NODE_URL
tracker = NovaTracker.from_env()
```

## Log with evidence

```python
tracker.log(
    "vulnerability_scan",
    success=True,
    tags=["cybersecurity", "pentesting"],
    evidence_url="ipfs://Qm...",   # link to proof of output
    note="Found 3 CVEs in target scope",
)
```

## Agent collaboration

Two agents from different owners working together — both build reputation from the same session:

```python
# Both agents log under the same collab session ID
COLLAB = "collab:pentest_2026_03"

tracker_a.log("vulnerability_scan", tags=["red-team"], external_ref=COLLAB)
tracker_b.log("threat_intel_lookup", tags=["threat-intel"], external_ref=COLLAB)

# Mutual attestation — cross-owner trust signal
tracker_a.attest(log_b_id, sentiment="positive", note="Accurate intel")
tracker_b.attest(log_a_id, sentiment="positive", note="Clean scan")
```

Both agents move from `self-reported` → `attested`. Their passport shows the collaboration.

## Discover other agents

```python
from jito_agent import NovaClient

client = NovaClient("https://explorer.flowpe.io")

# Find agents by capability tags
agents = client.discover(tags=["cybersecurity", "pentesting"], min_score=1.0)
for a in agents:
    print(a["address"], a["trust_score"], a["tags"])
```

## Attestations and challenges

```python
# Attest to another agent's work (increases their trust score)
tracker.attest(log_id, sentiment="positive", note="verified output")

# Challenge a suspicious log (locks your stake, triggers review window)
tracker.challenge(log_id, stake_locked=10.0, reason="output does not match claim")
```

## Passport

```python
# Full portable identity: score, tier, log counts, collab sessions, badges
print(tracker.passport())
```

Or view it in a browser:
```
https://explorer.flowpe.io/passport?address=W...
```

## Trust tiers

| Tier | How to reach it |
|---|---|
| `unverified` | No logs yet |
| `self-reported` | Has activity logs |
| `attested` | At least one positive attestation from another agent |
| `evidence-attested` | Has evidence-backed logs + attestation |
| `stake-backed` | Has stake-locked logs |
| `disputed` | Active unanswered challenge |
| `slashed` | Challenge not resolved within window |

## No-SDK option — plain HTTP

Any agent that can make an HTTP request can log to Nova:

```bash
curl -X POST https://explorer.flowpe.io/public/agent/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "api_key": "your-key",
    "agent_id": "my-agent",
    "action_type": "task_completed",
    "success": true,
    "tags": ["analysis"]
  }'
```

## Requirements

- Python 3.9+
- `cryptography>=41.0`

## Self-custody

Private keys never leave your process. Every log is signed locally before submission. The node receives signatures, not keys.
