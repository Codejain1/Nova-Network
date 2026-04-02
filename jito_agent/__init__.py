"""
Nova Agent SDK — portable trust and reputation for AI agents.

Works with any agent, any framework, any LLM.

Quick start:
    from jito_agent import NovaTracker

    tracker = NovaTracker.new("my-agent")

    # Log any work your agent does
    tracker.log("task_completed", success=True, tags=["analysis"])

    # Or use the context manager — auto-times and logs on exit
    with tracker.track("contract_review", tags=["legal"]) as ctx:
        result = my_agent.run(task)
        ctx.set_output(result)

    print(tracker.get_reputation())
"""

from .wallet import create_wallet, load_wallet, save_wallet
from .client import NovaClient
from .agent import NovaAgent
from .tracker import NovaTracker
from .types import WalletInfo, TaskInfo, AgentInfo, ModelInfo, ProposalInfo
from .callbacks import NovaCallbackHandler
from .crypto import (
    make_agent_activity_log_tx,
    make_agent_attest_tx,
    make_agent_challenge_tx,
    make_agent_challenge_resolve_tx,
    make_agent_param_propose_tx,
    make_agent_param_endorse_tx,
    make_agent_register_tx,
)

__version__ = "0.5.0"
__all__ = [
    # Core
    "NovaTracker",
    "NovaCallbackHandler",
    "NovaAgent",
    "NovaClient",
    # Wallet
    "create_wallet", "load_wallet", "save_wallet",
    # Types
    "WalletInfo", "TaskInfo", "AgentInfo", "ModelInfo", "ProposalInfo",
    # Transaction builders (for custom integrations)
    "make_agent_activity_log_tx",
    "make_agent_attest_tx",
    "make_agent_challenge_tx",
    "make_agent_challenge_resolve_tx",
    "make_agent_param_propose_tx",
    "make_agent_param_endorse_tx",
    "make_agent_register_tx",
]
