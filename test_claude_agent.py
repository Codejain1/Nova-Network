"""
Test Nova Agent Identity with Claude API.
Runs a real Claude agent through several tasks and watches reputation build live.
"""

import anthropic
import os
import time
from jito_agent import NovaTracker

# ── Setup ─────────────────────────────────────────────────────────────────

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
NODE_URL = "http://localhost:8000"

tracker = NovaTracker.new(
    agent_id="claude-test-agent",
    wallet_path="claude_agent_wallet.json",
    node_url=NODE_URL,
    platform="anthropic",
)

client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

print("=" * 60)
print("Nova Agent Identity — Claude API Test")
print("=" * 60)
print(f"Agent address: {tracker.wallet['address']}")
print(f"Node: {NODE_URL}")
print()

# ── Helper ────────────────────────────────────────────────────────────────

def ask_claude(prompt: str, system: str = "") -> str:
    """Call Claude and return the response text."""
    messages = [{"role": "user", "content": prompt}]
    kwargs = {"model": "claude-haiku-4-5-20251001", "max_tokens": 512, "messages": messages}
    if system:
        kwargs["system"] = system
    response = client.messages.create(**kwargs)
    return response.content[0].text

# ── Task 1: Simple analysis ───────────────────────────────────────────────

print("Task 1: Market analysis...")
with tracker.track("market_analysis", tags=["finance", "claude"]) as ctx:
    result = ask_claude(
        "In 2 sentences, what is the current state of AI adoption in enterprise?",
        system="You are a concise market analyst."
    )
    ctx.set_output(result)
    print(f"  → {result[:100]}...")

rep = tracker.get_reputation()
print(f"  Trust score: {rep['trust_score']} | Tier: {rep['trust_tier']} | Logs: {rep['activity_logs']}")
print()

# ── Task 2: Code generation ───────────────────────────────────────────────

print("Task 2: Code generation...")
with tracker.track("code_generation", tags=["engineering", "claude"]) as ctx:
    result = ask_claude(
        "Write a Python function that checks if a string is a palindrome. One function only.",
        system="You are a precise Python engineer. Return only code, no explanation."
    )
    ctx.set_output(result)
    print(f"  → {result[:100]}...")

rep = tracker.get_reputation()
print(f"  Trust score: {rep['trust_score']} | Tier: {rep['trust_tier']} | Logs: {rep['activity_logs']}")
print()

# ── Task 3: Data extraction ───────────────────────────────────────────────

print("Task 3: Data extraction...")
with tracker.track("data_extraction", tags=["data", "claude"]) as ctx:
    result = ask_claude(
        "Extract the key facts from this text as bullet points: "
        "The James Webb Space Telescope launched on December 25, 2021. "
        "It cost $10 billion and took 20 years to build. "
        "It can see objects 13.6 billion light years away.",
        system="You are a data extraction specialist. Return only bullet points."
    )
    ctx.set_output(result)
    print(f"  → {result[:100]}...")

rep = tracker.get_reputation()
print(f"  Trust score: {rep['trust_score']} | Tier: {rep['trust_tier']} | Logs: {rep['activity_logs']}")
print()

# ── Task 4: Simulate a failed task ───────────────────────────────────────

print("Task 4: Logging a failed task...")
tracker.log(
    "api_call",
    success=False,
    tags=["external-api", "claude"],
    note="Third-party API timeout after 30s"
)
rep = tracker.get_reputation()
print(f"  Trust score: {rep['trust_score']} | Tier: {rep['trust_tier']} | Logs: {rep['activity_logs']}")
print()

# ── Task 5: Task with evidence URL ────────────────────────────────────────

print("Task 5: Task with evidence URL (boosts score)...")
with tracker.track("report_generation", tags=["report", "claude"], evidence_url="https://explorer.flowpe.io") as ctx:
    result = ask_claude("Summarize the benefits of blockchain for AI trust in one paragraph.")
    ctx.set_output(result)
    print(f"  → {result[:100]}...")

rep = tracker.get_reputation()
print(f"  Trust score: {rep['trust_score']} | Tier: {rep['trust_tier']} | Logs: {rep['activity_logs']}")
print()

# ── Final passport ────────────────────────────────────────────────────────

print("=" * 60)
print("FINAL PASSPORT")
print("=" * 60)
passport = tracker.passport()
print(f"Address:       {passport.get('address')}")
print(f"Trust score:   {passport.get('trust_score')}")
print(f"Trust tier:    {passport.get('trust_tier')}")
print(f"Activity logs: {passport.get('activity_logs')}")
print(f"Evidence logs: {passport.get('evidence_backed_logs')}")
print()
print(f"Check live on explorer:")
print(f"  http://localhost:8000/public/agent/passport?address={tracker.wallet['address']}")
print(f"  http://explorer.flowpe.io/public/agent/passport?address={tracker.wallet['address']}")
