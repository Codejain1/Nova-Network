"""TypedDicts for NOVA SDK objects."""
from typing import Any, Dict, List, Optional
try:
    from typing import TypedDict
except ImportError:
    from typing_extensions import TypedDict  # type: ignore


class JWKKey(TypedDict):
    kty: str
    key: str  # base64-encoded raw bytes


class WalletInfo(TypedDict):
    address: str
    public_key: JWKKey
    private_key: JWKKey
    label: str


class TaskInfo(TypedDict):
    task_id: str
    title: str
    description: str
    reward: float
    status: str
    agent_id: Optional[str]


class AgentSelfDescription(TypedDict):
    """Derived self-description stored alongside the agent profile."""
    capabilities: List[str]       # canonical capability tags
    task_types: List[str]         # what kinds of tasks the agent handles
    refusals: List[str]           # what the agent refuses or cannot do
    system_prompt_hash: str       # SHA-256 of the raw system prompt
    method: str                   # "heuristic" or "llm"


class AgentInfo(TypedDict):
    agent_id: str
    name: str
    owner: str
    capabilities: List[str]
    task_types: List[str]
    refusals: List[str]
    system_prompt_hash: str
    version_hash: str
    reputation: float


class ModelInfo(TypedDict):
    model_id: str
    name: str
    owner: str
    description: str
    capabilities: List[str]
    inference_fee: float


class ProposalInfo(TypedDict):
    proposal_id: str
    title: str
    description: str
    proposer: str
    votes_yes: int
    votes_no: int
    status: str


class SessionSummary(TypedDict):
    """
    The structured evidence payload logged for every session_complete event.
    Content is SHA256-hashed client-side — this dict never goes on-chain verbatim.
    """
    task: str                           # what the agent was asked to do
    tools: List[Dict[str, Any]]         # per-call detail: [{name, duration_ms, success}]
    tools_used: Dict[str, int]          # {tool_name: call_count}
    llm_calls: int                      # total LLM invocations this session
    assessment: str                     # "success" | "partial" | "failure"
    assessment_reason: str              # agent's explanation of why
    tool_success_rate: Optional[float]  # fraction of tool calls that succeeded
    notes: List[str]                    # free-form agent observations
