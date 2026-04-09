"""Local policy engine for deciding which agent sessions deserve on-chain logs."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PolicyDecision:
    should_log: bool
    reason: str
    action_type: str = "session_complete"
    extra_tags: List[str] = field(default_factory=list)
    score_hint: str = "self-reported"


@dataclass
class AutoLogPolicy:
    """
    Heuristics for low-friction logging.
    The agent decides what to submit locally; stronger trust still depends on proof/attestation.
    """

    min_duration_ms: int = 15_000
    min_tool_calls: int = 1
    min_llm_calls: int = 2
    log_failures: bool = True
    log_with_artifacts: bool = True
    log_with_collaboration: bool = True
    log_with_side_effects: bool = True
    confidence_threshold: float = 0.75

    def evaluate(self, session: Dict[str, Any]) -> PolicyDecision:
        if session.get("suppress_log"):
            return PolicyDecision(False, "suppressed-by-agent")
        if session.get("force_log"):
            return PolicyDecision(True, "forced-by-agent", extra_tags=["significant"])

        success = bool(session.get("success", True))
        duration_ms = int(session.get("duration_ms", 0))
        llm_calls = int(session.get("llm_calls", 0))
        tool_calls = len(session.get("tools", []))
        artifacts = list(session.get("artifacts", []))
        collaborators = list(session.get("collaborators", []))
        side_effects = list(session.get("side_effects", []))
        confidence = session.get("confidence")
        assessment = str(session.get("assessment", "success"))

        if self.log_failures and (not success or assessment == "failure"):
            return PolicyDecision(True, "failure", extra_tags=["failure"], score_hint="challengeable")
        if self.log_with_collaboration and collaborators:
            return PolicyDecision(True, "collaboration", extra_tags=["collab"], score_hint="collaborative")
        if self.log_with_artifacts and artifacts:
            return PolicyDecision(True, "artifact", extra_tags=["artifact"], score_hint="evidence-backed")
        if self.log_with_side_effects and side_effects:
            return PolicyDecision(True, "side-effect", extra_tags=["side-effect"], score_hint="evidence-backed")
        if duration_ms >= self.min_duration_ms:
            return PolicyDecision(True, "duration-threshold", extra_tags=["long-run"])
        if tool_calls >= self.min_tool_calls:
            return PolicyDecision(True, "tool-threshold", extra_tags=["tool-use"])
        if llm_calls >= self.min_llm_calls:
            return PolicyDecision(True, "llm-threshold", extra_tags=["multi-llm"])
        if confidence is not None and float(confidence) >= self.confidence_threshold:
            return PolicyDecision(True, "confidence-threshold", extra_tags=["high-confidence"])
        return PolicyDecision(False, "below-threshold")
