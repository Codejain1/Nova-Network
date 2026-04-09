"""
Agent self-description: derives capabilities, task types, and refusals
from a system prompt — no external LLM required.

Usage (heuristic only — zero deps):
    from jito_agent.self_description import derive_self_description

    desc = derive_self_description(system_prompt)
    print(desc.capabilities)  # ["coding", "analysis", "finance"]
    print(desc.task_types)    # ["answer coding questions", "analyze financial data"]
    print(desc.refusals)      # ["provide legal advice", "generate harmful content"]

Usage (LLM-enhanced — pass any callable that takes a str and returns a str):
    def call_claude(prompt: str) -> str:
        import anthropic
        client = anthropic.Anthropic()
        msg = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
        )
        return msg.content[0].text

    desc = derive_self_description(system_prompt, llm_fn=call_claude)

The system_prompt_hash (SHA-256) is always stored on-chain — the raw prompt never leaves
the client, preserving the same privacy model as input/output hashing.
"""

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple


# ── Capability taxonomy ────────────────────────────────────────────────────
# Maps keyword substrings (lowercased) → canonical capability tag.
# Longer/more specific keys should appear before shorter ones when overlap
# is possible — dict ordering is insertion order in Python 3.7+.
_CAPABILITY_MAP: Dict[str, str] = {
    # programming languages / frameworks
    "machine learning": "ml",
    "deep learning": "ml",
    "neural network": "ml",
    "language model": "nlp",
    "natural language": "nlp",
    "javascript": "coding",
    "typescript": "coding",
    "python": "coding",
    "golang": "coding",
    "rust": "coding",
    "java": "coding",
    "c++": "coding",
    "react": "coding",
    "node.js": "coding",
    # coding / engineering
    " code": "coding",
    "coding": "coding",
    "programming": "coding",
    "software engineer": "coding",
    "develop": "coding",
    "debug": "debugging",
    "unit test": "testing",
    "testing": "testing",
    "docker": "devops",
    "kubernetes": "devops",
    "ci/cd": "devops",
    "deploy": "devops",
    "infrastructure": "devops",
    # data / analytics / ml
    "data analys": "data-analysis",
    "data scien": "data-analysis",
    "analyz": "analysis",
    "analytics": "analysis",
    "sql": "data-analysis",
    "database": "data-analysis",
    "pandas": "data-analysis",
    "spark": "data-analysis",
    "nlp": "nlp",
    "sentiment": "nlp",
    "classif": "ml",
    "model train": "ml",
    # finance / trading / crypto
    "financial": "finance",
    "financ": "finance",
    "trading": "trading",
    "invest": "finance",
    "portfolio": "finance",
    "stock": "trading",
    "market": "trading",
    "crypto": "crypto",
    "blockchain": "blockchain",
    "defi": "defi",
    "smart contract": "blockchain",
    "solidity": "blockchain",
    "web3": "blockchain",
    # writing / content
    "summariz": "summarization",
    "translat": "translation",
    "content creat": "writing",
    "copywriting": "writing",
    "writ": "writing",
    "document": "writing",
    "email": "writing",
    "blog": "writing",
    "proofread": "writing",
    "edit": "writing",
    # research
    "research": "research",
    "web search": "web-search",
    "retriev": "research",
    "search": "research",
    "fact-check": "research",
    # security
    "cybersecurity": "security",
    "penetration": "security",
    "pentest": "security",
    "vulnerabilit": "security",
    "security": "security",
    # customer / support
    "customer support": "customer-support",
    "helpdesk": "customer-support",
    "customer service": "customer-support",
    "support ticket": "customer-support",
    # planning / productivity
    "schedul": "scheduling",
    "calendar": "scheduling",
    "project manag": "planning",
    "planning": "planning",
    "automat": "automation",
    "workflow": "automation",
    # general / agentic
    "tool use": "tool-use",
    "tool call": "tool-use",
    "api integrat": "api-integration",
    "reasoning": "reasoning",
    "question answer": "qa",
    "question and answer": "qa",
    "answer question": "qa",
    "chat": "chat",
    "conversational": "chat",
    "agent": "agentic",
    "multiagent": "agentic",
    "multi-agent": "agentic",
}

# Regex patterns that introduce capability phrases.
# Group 1 captures the raw capability phrase.
_CAPABILITY_PATTERNS: List[str] = [
    # "you can analyze data"  /  "you are able to write code"
    r"you (?:are (?:able|capable) to|can|will|specialize in|focus on|excel at"
    r"|have expertise in|are trained to|are designed to)\s+(.+?)(?:[.,;]|$)",
    # "capabilities include: X, Y"  /  "your capabilities are X"
    r"(?:my |your )?capabilities? (?:include|are|:)[:\s]+(.+?)(?:\.|$)",
    # "designed to / for X"
    r"designed (?:to|for)\s+(.+?)(?:[.,;]|$)",
    # "specialized in X"  /  "expert in X"
    r"(?:specializ\w* in|expert in|skilled in|proficient in|knowledgeable (?:in|about))\s+(.+?)(?:[.,;]|$)",
    # "I am a [role] that [does X]"  — captures the clause after "that/who"
    r"(?:you are|i am) (?:a|an) \w+(?: \w+)* (?:that|who) (.+?)(?:[.,;]|$)",
]

# Regex patterns that introduce task-type phrases.
_TASK_PATTERNS: List[str] = [
    r"(?:you (?:help|assist|handle|process|answer|generate|analyze|analyse|create|write"
    r"|review|build|provide|explain|summarize|translate|research))\s+(.+?)(?:[.,;]|$)",
    r"(?:your (?:job|role|purpose|goal|task|mission|function|responsibility)"
    r" (?:is|involves?))\s+(?:to\s+)?(.+?)(?:\.|$)",
    r"(?:help(?:ing)?|assist(?:ing)?|support(?:ing)?) (?:users?|people|humans?|customers?)"
    r" (?:with|to)\s+(.+?)(?:[.,;]|$)",
    r"(?:you will help|you'll help)\s+(.+?)(?:[.,;]|$)",
]

# Regex patterns that introduce refusal phrases.
_REFUSAL_PATTERNS: List[str] = [
    r"(?:you (?:will not|won't|cannot|can't|do not|don't|must not|mustn't"
    r"|should not|shouldn't|are not (?:able|allowed|permitted) to"
    r"|refuse to|avoid|decline to))\s+(.+?)(?:[.,;]|$)",
    r"(?:never)\s+(.+?)(?:[.,;]|$)",
    r"(?:prohibited from|forbidden from|not allowed to|not permitted to)\s+(.+?)(?:[.,;]|$)",
    r"(?:refus(?:e|ing) to)\s+(.+?)(?:[.,;]|$)",
    r"do not (?:and will not|ever)\s+(.+?)(?:[.,;]|$)",
    r"(?:under no circumstances)\s+(?:will you\s+)?(.+?)(?:[.,;]|$)",
    r"(?:i (?:will not|won't|cannot|can't|do not|don't|must not))\s+(.+?)(?:[.,;]|$)",
]


@dataclass
class SelfDescription:
    """
    Derived self-description extracted from an agent's system prompt.

    Attributes:
        capabilities:       Canonical capability tags the agent self-assigns.
                            e.g. ["coding", "analysis", "finance"]
        task_types:         Short phrases describing the tasks the agent handles.
                            e.g. ["answer coding questions", "analyze financial data"]
        refusals:           Short phrases for what the agent refuses or cannot do.
                            e.g. ["provide legal advice", "generate harmful content"]
        system_prompt_hash: SHA-256 hex of the raw system prompt.
                            Stored on-chain; the raw prompt never leaves the client.
        method:             How the description was derived: "heuristic" or "llm".
        version:            Monotonically incrementing version counter.
                            Starts at 1; increments each time the prompt changes and
                            derive_self_description_update() produces a new description.
        extracted_at:       Unix timestamp of when this version was extracted.
        previous_hash:      system_prompt_hash of the immediately prior version,
                            forming a verifiable chain of custody across re-extractions.
                            Empty string for the first version.
    """
    capabilities: List[str] = field(default_factory=list)
    task_types: List[str] = field(default_factory=list)
    refusals: List[str] = field(default_factory=list)
    system_prompt_hash: str = ""
    method: str = "heuristic"
    version: int = 1
    extracted_at: float = 0.0
    previous_hash: str = ""

    def to_dict(self) -> Dict:
        return {
            "capabilities": self.capabilities,
            "task_types": self.task_types,
            "refusals": self.refusals,
            "system_prompt_hash": self.system_prompt_hash,
            "method": self.method,
            "version": self.version,
            "extracted_at": self.extracted_at,
            "previous_hash": self.previous_hash,
        }


# ── Heuristic extraction ───────────────────────────────────────────────────

def _extract_phrases(text: str, patterns: List[str]) -> List[str]:
    """Run all patterns against text, returning matched group 1 phrases."""
    phrases = []
    for pat in patterns:
        for m in re.finditer(pat, text, re.IGNORECASE | re.MULTILINE):
            phrase = m.group(1).strip().rstrip(".,;:!?")
            if phrase and len(phrase) > 3:
                phrases.append(phrase)
    return phrases


def _map_to_tags(phrases: List[str]) -> List[str]:
    """Map a list of free-text phrases to canonical capability tags."""
    tags: set = set()
    combined = " ".join(phrases).lower()
    for keyword, tag in _CAPABILITY_MAP.items():
        if keyword in combined:
            tags.add(tag)
    return sorted(tags)


def _clean_phrase(phrase: str, max_len: int = 80) -> str:
    """Normalize a phrase: strip leading articles, collapse whitespace."""
    phrase = re.sub(
        r"^(with|the|a|an|to|for|any|all|some|their|your|my|our|users?)\s+",
        "",
        phrase,
        flags=re.IGNORECASE,
    )
    return " ".join(phrase.split())[:max_len].strip()


def _heuristic(prompt: str) -> Tuple[List[str], List[str], List[str]]:
    """
    Pure regex/keyword heuristic — no network calls, no external deps.
    Returns (capabilities, task_types, refusals).
    """
    cap_phrases = _extract_phrases(prompt, _CAPABILITY_PATTERNS)
    task_phrases = _extract_phrases(prompt, _TASK_PATTERNS)
    refusal_phrases = _extract_phrases(prompt, _REFUSAL_PATTERNS)

    # Capability tags: mapped from all extracted phrases + full prompt keywords
    capabilities = _map_to_tags(cap_phrases + task_phrases + [prompt])

    # Task types: deduplicated short phrases
    task_types: List[str] = list(
        dict.fromkeys(
            _clean_phrase(p)
            for p in task_phrases
            if len(_clean_phrase(p)) > 4
        )
    )[:10]

    # Refusals: deduplicated short phrases
    refusals: List[str] = list(
        dict.fromkeys(
            _clean_phrase(p)
            for p in refusal_phrases
            if len(_clean_phrase(p)) > 4
        )
    )[:10]

    return capabilities, task_types, refusals


# ── LLM-enhanced extraction ────────────────────────────────────────────────

_LLM_PROMPT = """\
You are analyzing an AI agent's system prompt to produce its self-description.

System prompt:
---
{system_prompt}
---

Return ONLY a valid JSON object with exactly these three keys:

{{
  "capabilities": ["<lowercase-tag>", ...],
  "task_types":   ["<short phrase>", ...],
  "refusals":     ["<short phrase>", ...]
}}

Rules:
- capabilities: lowercase single-word or hyphenated tags, ≤ 10 items
  (e.g. "coding", "finance", "data-analysis", "nlp", "writing")
- task_types: plain-English short phrases, ≤ 10 items
  (e.g. "answer coding questions", "summarize documents")
- refusals: plain-English short phrases, ≤ 10 items
  (e.g. "provide legal advice", "generate harmful content")
- Return only the JSON — no markdown fences, no explanation."""


def _llm_extract(
    prompt: str,
    llm_fn: Callable[[str], str],
) -> Tuple[List[str], List[str], List[str]]:
    """
    Use a caller-supplied LLM function for structured extraction.
    Falls back to heuristic if the LLM output is unparseable.
    """
    llm_input = _LLM_PROMPT.format(system_prompt=prompt[:4000])
    raw = llm_fn(llm_input).strip()
    # Strip markdown code fences if the model added them anyway
    raw = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw, flags=re.MULTILINE).strip()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return _heuristic(prompt)  # graceful fallback

    capabilities = sorted({
        str(c).strip().lower()
        for c in data.get("capabilities", [])
        if str(c).strip()
    })[:10]
    task_types = [
        str(t).strip() for t in data.get("task_types", []) if str(t).strip()
    ][:10]
    refusals = [
        str(r).strip() for r in data.get("refusals", []) if str(r).strip()
    ][:10]
    return capabilities, task_types, refusals


# ── Public API ─────────────────────────────────────────────────────────────

def derive_self_description(
    system_prompt: str,
    llm_fn: Optional[Callable[[str], str]] = None,
) -> SelfDescription:
    """
    Derive an agent's self-description from its system prompt.

    The raw prompt never leaves the client — only its SHA-256 hash is stored
    on-chain, consistent with Nova's privacy-first logging model.

    Args:
        system_prompt:  The agent's full system prompt text.
        llm_fn:         Optional callable ``(prompt: str) -> str``.
                        When provided, an LLM is used for richer extraction.
                        Without it, a pure heuristic (regex + keyword map)
                        is used — no external dependencies required.

    Returns:
        SelfDescription with:
            .capabilities       — canonical capability tags
            .task_types         — what kinds of tasks the agent handles
            .refusals           — what the agent refuses or cannot do
            .system_prompt_hash — SHA-256 of the raw prompt
            .method             — "heuristic" or "llm"

    Examples::

        # Zero-dep heuristic mode
        desc = derive_self_description(system_prompt)

        # LLM-enhanced (works with any LLM)
        import anthropic
        client = anthropic.Anthropic()

        def call_claude(prompt: str) -> str:
            msg = client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=512,
                messages=[{"role": "user", "content": prompt}],
            )
            return msg.content[0].text

        desc = derive_self_description(system_prompt, llm_fn=call_claude)
        print(desc.capabilities)  # ["coding", "analysis"]
        print(desc.task_types)    # ["write and review code", "analyze datasets"]
        print(desc.refusals)      # ["provide medical advice"]
    """
    if not system_prompt or not system_prompt.strip():
        return SelfDescription(system_prompt_hash="")

    prompt_hash = hashlib.sha256(system_prompt.encode()).hexdigest()

    if llm_fn is not None:
        try:
            capabilities, task_types, refusals = _llm_extract(system_prompt, llm_fn)
            method = "llm"
        except Exception:
            capabilities, task_types, refusals = _heuristic(system_prompt)
            method = "heuristic"
    else:
        capabilities, task_types, refusals = _heuristic(system_prompt)
        method = "heuristic"

    return SelfDescription(
        capabilities=capabilities,
        task_types=task_types,
        refusals=refusals,
        system_prompt_hash=prompt_hash,
        method=method,
        version=1,
        extracted_at=time.time(),
        previous_hash="",
    )


# ── Versioning helpers ─────────────────────────────────────────────────────────

def derive_self_description_update(
    new_prompt: str,
    previous: SelfDescription,
    llm_fn: Optional[Callable[[str], str]] = None,
) -> Tuple[SelfDescription, bool]:
    """
    Re-extract the self-description only if the system prompt has changed.

    Compares the SHA-256 of *new_prompt* against *previous.system_prompt_hash*.
    If identical, returns the previous description unchanged (``changed=False``),
    so callers can skip an unnecessary re-registration on-chain.

    When the prompt has changed:
    - A fresh extraction is performed (heuristic or LLM-enhanced).
    - ``version`` is incremented from the previous version.
    - ``extracted_at`` is set to the current time.
    - ``previous_hash`` is set to *previous.system_prompt_hash*, forming a
      chain-of-custody link between versions.

    Args:
        new_prompt:  The agent's current system prompt.
        previous:    The last known SelfDescription for this agent.
        llm_fn:      Optional LLM callable — same semantics as derive_self_description().

    Returns:
        ``(description, changed)`` where ``changed`` is ``True`` when re-extraction
        happened and a new on-chain registration is warranted.

    Example::

        desc, changed = derive_self_description_update(new_prompt, tracker.self_description)
        if changed:
            tracker.self_description = desc
            client.register_agent(wallet, agent_id, name,
                                   capabilities=desc.capabilities,
                                   system_prompt_hash=desc.system_prompt_hash)
    """
    new_hash = hashlib.sha256(new_prompt.encode()).hexdigest()
    if new_hash == previous.system_prompt_hash:
        return previous, False

    fresh = derive_self_description(new_prompt, llm_fn=llm_fn)
    fresh.version = previous.version + 1
    fresh.extracted_at = time.time()
    fresh.previous_hash = previous.system_prompt_hash
    return fresh, True


def staleness_days(desc: SelfDescription) -> float:
    """
    Return how many days have elapsed since this description was last extracted.

    Returns ``float('inf')`` if ``extracted_at`` is unset (legacy descriptions
    created before versioning was added).

    Example::

        if staleness_days(tracker.self_description) > 30:
            desc, changed = derive_self_description_update(new_prompt, tracker.self_description)
    """
    if not desc.extracted_at:
        return float("inf")
    return (time.time() - desc.extracted_at) / 86400.0


def capability_diff(old: SelfDescription, new: SelfDescription) -> Dict:
    """
    Compute the diff between two SelfDescription versions' capability sets.

    Returns a dict with three sorted lists:
    - ``added``:     capabilities present in *new* but not *old*
    - ``removed``:   capabilities present in *old* but not *new*
    - ``unchanged``: capabilities present in both

    Example::

        diff = capability_diff(v1, v2)
        print("gained:", diff["added"])    # ["blockchain", "defi"]
        print("lost:",   diff["removed"])  # ["trading"]
    """
    old_set = set(old.capabilities)
    new_set = set(new.capabilities)
    return {
        "added": sorted(new_set - old_set),
        "removed": sorted(old_set - new_set),
        "unchanged": sorted(old_set & new_set),
    }
