"""TypedDicts for JITO SDK objects."""
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


class AgentInfo(TypedDict):
    agent_id: str
    name: str
    owner: str
    capabilities: List[str]
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
