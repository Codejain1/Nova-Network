"""Seed Nova Network with realistic demo agents."""
import time, os, sys
sys.path.insert(0, os.path.dirname(__file__))
from jito_agent import NovaTracker

NODE = "http://localhost:8000"

AGENTS = [
    {
        "id": "sentinel-security",
        "tags": ["cybersecurity", "pentesting", "vulnerability-scan"],
        "tasks": [
            ("vulnerability_scan", "Scanned fintech API, found 2 CVEs"),
            ("penetration_test", "Full red team assessment completed"),
            ("security_report", "CVE report submitted to client"),
        ]
    },
    {
        "id": "quant-analyst",
        "tags": ["finance", "trading", "market-analysis"],
        "tasks": [
            ("market_analysis", "Analyzed EUR/USD macro signals"),
            ("portfolio_rebalance", "Rebalanced 12-asset portfolio"),
            ("risk_assessment", "VaR calculation for crypto exposure"),
        ]
    },
    {
        "id": "research-agent",
        "tags": ["research", "summarization", "literature-review"],
        "tasks": [
            ("literature_review", "Reviewed 40 papers on protein folding"),
            ("research_summary", "Generated weekly research digest"),
            ("hypothesis_generation", "Proposed 3 testable hypotheses"),
        ]
    },
    {
        "id": "code-reviewer",
        "tags": ["code-review", "engineering", "static-analysis"],
        "tasks": [
            ("code_review", "Reviewed 800-line PR, found 3 bugs"),
            ("static_analysis", "Ran security scan on dependencies"),
            ("refactor_suggestion", "Suggested 5 performance improvements"),
        ]
    },
    {
        "id": "data-pipeline",
        "tags": ["data-engineering", "etl", "pipeline"],
        "tasks": [
            ("etl_run", "Processed 2.3M records from S3"),
            ("data_validation", "Validated schema on 15 tables"),
            ("pipeline_monitor", "Detected and resolved 2 anomalies"),
        ]
    },
    {
        "id": "threat-intel",
        "tags": ["threat-intel", "malware-analysis", "cybersecurity"],
        "tasks": [
            ("threat_intel_lookup", "Correlated CVE-2024-1234 with APT-29"),
            ("malware_analysis", "Analyzed suspicious binary, identified C2"),
            ("ioc_extraction", "Extracted 47 IOCs from threat report"),
        ]
    },
    {
        "id": "climate-monitor",
        "tags": ["climate", "data-analysis", "simulation"],
        "tasks": [
            ("climate_analysis", "Analyzed ocean temp anomaly in North Atlantic"),
            ("simulation_run", "Ran 10k Monte Carlo climate simulations"),
            ("pattern_detection", "Detected El Nino precursor pattern"),
        ]
    },
    {
        "id": "legal-reviewer",
        "tags": ["legal", "contract-review", "compliance"],
        "tasks": [
            ("contract_review", "Reviewed SaaS agreement, flagged 4 clauses"),
            ("compliance_check", "GDPR compliance audit for EU operations"),
            ("legal_summary", "Summarized 200-page regulatory filing"),
        ]
    },
]

def seed():
    print("Seeding Nova Network with demo agents...")
    wallets_created = []

    for agent_data in AGENTS:
        agent_id = agent_data["id"]
        wallet_path = f"/tmp/seed_{agent_id}.json"

        print(f"\n-> {agent_id}")
        tracker = NovaTracker.new(agent_id, wallet_path=wallet_path, node_url=NODE)
        wallets_created.append(tracker.wallet["address"])

        for action_type, note in agent_data["tasks"]:
            tx_id = tracker.log(
                action_type,
                success=True,
                tags=agent_data["tags"],
                note=note,
            )
            print(f"  logged {action_type}: {tx_id[:16]}...")
            time.sleep(1)  # don't flood

        time.sleep(6)  # wait for block

    print(f"\nSeeded {len(AGENTS)} agents")
    print("Addresses:")
    for addr in wallets_created:
        print(f"  {addr}")

if __name__ == "__main__":
    seed()
