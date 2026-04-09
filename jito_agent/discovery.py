"""
Evidence-based agent discovery — Layer 5 of the Nova Network trust stack.

The problem with the existing discover() endpoint: tags are operator-declared.
An agent that says it does "security audits" may have zero evidence of ever doing one.

This module enables queries grounded in what agents have *actually logged and proved*:

    "Find agents with 20+ security audits backed by evidence"
    "Find agents that have collaborated with agent X before"
    "Find agents whose security work has been attested by others"

How it works:
  - Nova stores every logged activity with optional evidence_hash/evidence_url
  - The node exposes /public/agent/capability_profile and richer /public/agent/discover filters
  - DiscoveryQuery translates structured intent into those evidence-aware query params

Usage:
    from jito_agent import DiscoveryQuery

    # Find agents with 20+ security audits backed by evidence
    query = (
        DiscoveryQuery()
        .with_capability("security", min_logs=20, min_evidenced=20)
        .with_trust(min_tier="attested")
    )
    agents = client.discover_rich(query)

    # Find agents who have collaborated with a specific address
    query = DiscoveryQuery().has_collaborated(with_address="0xabc...")
    agents = client.discover_rich(query)

    # Find agents with a strong data-analysis track record
    query = (
        DiscoveryQuery()
        .with_capability("data-analysis", min_logs=10, min_evidenced=5)
        .with_trust(min_score=15.0)
        .limit(5)
    )
    agents = client.discover_rich(query)
"""

from typing import Dict, List, Optional


class DiscoveryQuery:
    """
    Fluent builder for evidence-based agent discovery.

    Every filter is grounded in actual logged behavior — not declared tags.
    Filters are AND-combined: an agent must satisfy all of them.

    Examples:
        # Agents with 20+ evidenced security logs, attested trust tier
        query = (
            DiscoveryQuery()
            .with_capability("security", min_logs=20, min_evidenced=20)
            .with_trust(min_tier="attested")
        )

        # Agents who collaborated with 0xabc...
        query = DiscoveryQuery().has_collaborated(with_address="0xabc...")

        # Broad search: any agent that has collaborated at all
        query = DiscoveryQuery().has_collaborated().with_trust(min_score=5.0)
    """

    def __init__(self) -> None:
        self._capability: str = ""
        self._min_log_count: int = 1
        self._min_evidence_count: int = 0
        self._min_score: float = 0.0
        self._min_tier: str = ""
        self._platform: str = ""
        self._has_collaborated: bool = False
        self._collaborated_with: str = ""
        self._exclude: List[str] = []
        self._limit: int = 20
        self._tags: List[str] = []

    def with_capability(
        self,
        capability: str,
        min_logs: int = 1,
        min_evidenced: int = 0,
    ) -> "DiscoveryQuery":
        """
        Filter to agents who have actually logged activity for this capability.

        capability:    A tag name (e.g. "security", "data-analysis") or action_type
                       (e.g. "security_audit", "session_complete"). The node matches
                       against both activity log tags and action_type.
        min_logs:      Minimum number of logs matching this capability. Default 1.
                       Example: min_logs=20 → "done this at least 20 times"
        min_evidenced: Minimum number of those logs that carry evidence_hash or
                       evidence_url. Default 0.
                       Example: min_evidenced=20 → "20 of those logs have proof"

        Note: This is not the same as the declared `capabilities` field in agent
        registration. This counts actual logged activity.
        """
        self._capability = capability.strip().lower()
        self._min_log_count = max(1, min_logs)
        self._min_evidence_count = max(0, min_evidenced)
        return self

    def with_trust(
        self,
        min_score: float = 0.0,
        min_tier: str = "",
    ) -> "DiscoveryQuery":
        """
        Filter by trust score or trust tier.

        min_score: Minimum Nova trust_score (float). Higher = more trusted.
        min_tier:  Minimum tier. Accepted values (ordered lowest → highest):
                   "unverified", "self-reported", "attested",
                   "evidence-attested", "stake-backed"
                   Agents at or above this tier are included.
        """
        self._min_score = float(min_score)
        self._min_tier = min_tier.strip().lower()
        return self

    def with_tags(self, *tags: str) -> "DiscoveryQuery":
        """
        Filter to agents whose logs contain at least one of these tags.
        Tags are matched against activity log tags (not declared registration tags).
        For evidence-grounded filtering, prefer with_capability() instead.
        """
        self._tags = [t.strip().lower() for t in tags if t.strip()]
        return self

    def has_collaborated(self, with_address: str = "") -> "DiscoveryQuery":
        """
        Filter to agents who have participated in at least one collaboration session.

        with_address: If provided, filter to agents who specifically collaborated
                      with this wallet address (they share a collab: external_ref).
                      If empty, any collaboration session qualifies.

        Collaboration sessions are detected via external_ref="collab:<session_id>"
        on activity logs. Two agents that reference the same collab ID appear in the
        same collab_index entry on the node.
        """
        self._has_collaborated = True
        self._collaborated_with = with_address.strip()
        return self

    def on_platform(self, platform: str) -> "DiscoveryQuery":
        """Filter to agents who have logged activity on this platform."""
        self._platform = platform.strip().lower()
        return self

    def exclude(self, *addresses: str) -> "DiscoveryQuery":
        """Exclude specific agent wallet addresses from results."""
        self._exclude.extend(a.strip() for a in addresses if a.strip())
        return self

    def limit(self, n: int) -> "DiscoveryQuery":
        """Maximum number of results to return (default 20, max 100)."""
        self._limit = min(max(1, n), 100)
        return self

    def to_params(self) -> Dict[str, str]:
        """
        Serialize this query to URL query parameters for the
        /public/agent/discover endpoint.
        """
        params: Dict[str, str] = {}
        params["limit"] = str(self._limit)

        if self._capability:
            params["capability"] = self._capability
            params["min_log_count"] = str(self._min_log_count)
            if self._min_evidence_count > 0:
                params["min_evidence_count"] = str(self._min_evidence_count)

        if self._tags:
            params["tags"] = ",".join(self._tags)

        if self._min_score > 0:
            params["min_score"] = str(self._min_score)
        if self._min_tier:
            params["min_tier"] = self._min_tier
        if self._platform:
            params["platform"] = self._platform
        if self._has_collaborated:
            params["has_collaborated"] = "true"
        if self._collaborated_with:
            params["collaborated_with"] = self._collaborated_with
        if self._exclude:
            params["exclude"] = ",".join(self._exclude)

        return params

    def describe(self) -> str:
        """Human-readable description of this query for debugging."""
        parts = []
        if self._capability:
            parts.append(
                f"capability={self._capability!r} "
                f"(min_logs={self._min_log_count}, min_evidenced={self._min_evidence_count})"
            )
        if self._tags:
            parts.append(f"tags={self._tags}")
        if self._min_tier:
            parts.append(f"min_tier={self._min_tier!r}")
        if self._min_score > 0:
            parts.append(f"min_score={self._min_score}")
        if self._has_collaborated:
            if self._collaborated_with:
                parts.append(f"collaborated_with={self._collaborated_with!r}")
            else:
                parts.append("has_collaborated=true")
        if self._platform:
            parts.append(f"platform={self._platform!r}")
        if self._exclude:
            parts.append(f"exclude={self._exclude}")
        return "DiscoveryQuery(" + ", ".join(parts) + ")" if parts else "DiscoveryQuery(all)"


class CapabilityStats:
    """
    Evidence-backed stats for a single capability (action_type or tag).
    Returned as part of a CapabilityProfile.
    """
    __slots__ = (
        "total_logs", "evidenced_logs", "attested_logs",
        "success_rate", "evidence_rate", "last_active",
    )

    def __init__(self, data: Dict) -> None:
        self.total_logs: int = data.get("total_logs", 0)
        self.evidenced_logs: int = data.get("evidenced_logs", 0)
        self.attested_logs: int = data.get("attested_logs", 0)
        self.success_rate: float = data.get("success_rate", 0.0)
        self.evidence_rate: float = data.get("evidence_rate", 0.0)
        self.last_active: float = data.get("last_active", 0.0)

    def __repr__(self) -> str:
        return (
            f"CapabilityStats(total={self.total_logs}, "
            f"evidenced={self.evidenced_logs}, "
            f"attested={self.attested_logs}, "
            f"success={self.success_rate:.1%})"
        )


class CapabilityProfile:
    """
    Evidence-backed capability profile for an agent.
    Derived entirely from actual activity logs — not declared registration data.

    Retrieved via client.capability_profile(address).

    Answers questions like:
      - "What has this agent actually done, and how many times?"
      - "How much of their work has external proof?"
      - "Which other agents have they worked with?"

    Attributes:
        address:        Agent wallet address
        by_action_type: Stats per action_type key (e.g. "session_complete", "security_audit")
        by_tag:         Stats per tag (e.g. "security", "data-analysis")
        collab_partners: Wallet addresses of agents they have collaborated with
    """

    def __init__(self, data: Dict) -> None:
        self.address: str = data.get("address", "")
        self.by_action_type: Dict[str, CapabilityStats] = {
            k: CapabilityStats(v) for k, v in data.get("by_action_type", {}).items()
        }
        self.by_tag: Dict[str, CapabilityStats] = {
            k: CapabilityStats(v) for k, v in data.get("by_tag", {}).items()
        }
        self.collab_partners: List[str] = data.get("collab_partners", [])

    def has_evidenced(self, capability: str, min_count: int = 1) -> bool:
        """
        Returns True if this agent has at least min_count evidenced logs
        for the given capability (checked in both action_type and tag dimensions).
        """
        cap = capability.lower()
        for dim in (self.by_action_type, self.by_tag):
            stats = dim.get(cap)
            if stats and stats.evidenced_logs >= min_count:
                return True
        return False

    def evidence_count(self, capability: str) -> int:
        """Return the number of evidenced logs for this capability."""
        cap = capability.lower()
        for dim in (self.by_action_type, self.by_tag):
            stats = dim.get(cap)
            if stats:
                return stats.evidenced_logs
        return 0

    def top_capabilities(self, n: int = 5, by: str = "total_logs") -> List[str]:
        """
        Return the top N capability names by a given metric.
        by: "total_logs" | "evidenced_logs" | "attested_logs"
        """
        all_caps: Dict[str, CapabilityStats] = {}
        all_caps.update(self.by_action_type)
        all_caps.update(self.by_tag)
        return sorted(
            all_caps.keys(),
            key=lambda k: getattr(all_caps[k], by, 0),
            reverse=True,
        )[:n]

    def __repr__(self) -> str:
        top = self.top_capabilities(3)
        return (
            f"CapabilityProfile(address={self.address[:12]}..., "
            f"top={top}, "
            f"collab_partners={len(self.collab_partners)})"
        )
