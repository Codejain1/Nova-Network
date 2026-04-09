"""High-level NovaAgent — main interface for AI developers."""
import hashlib
import json
import time
from typing import Callable, Dict, List, Any, Optional

from .client import NovaClient
from .self_description import SelfDescription, derive_self_description


class NovaAgent:
    """
    A Nova Network-connected AI agent.

    Quick start:
        agent = NovaAgent(wallet, node_url="https://explorer.flowpe.io")
        agent.register(name="My AI", capabilities=["analysis"])

        # Manual poll
        for task in agent.poll_tasks():
            result = my_ai(task["description"])
            agent.complete_task(task["task_id"], result)

        # Auto loop
        agent.run(lambda task: my_ai(task["description"]))
    """

    def __init__(self, wallet: Dict, node_url: str = "https://explorer.flowpe.io",
                 agent_id: str = None, auth_token: str = ""):
        self.wallet = wallet
        self.address = wallet["address"]
        self.client = NovaClient(node_url, auth_token)
        self.agent_id = agent_id or f"agent_{self.address[:16]}"

    def register(self, name: str, capabilities: List[str] = None,
                  bio: str = "", handle: str = None, version_hash: str = "",
                  system_prompt: str = "",
                  llm_fn: Optional[Callable[[str], str]] = None) -> "NovaAgent":
        """
        Register identity + agent on-chain. Safe to call multiple times.

        When ``system_prompt`` is provided the agent reads its own prompt and
        derives its self-description (capabilities, task_types, refusals)
        automatically.  Any ``capabilities`` you pass are merged with the
        derived ones so manual overrides still work.

        Args:
            system_prompt:  The agent's system prompt.  The raw text never
                            leaves the client — only its SHA-256 hash is stored
                            on-chain.
            llm_fn:         Optional callable ``(prompt: str) -> str`` for
                            LLM-enhanced extraction.  Omit for heuristic mode.
        """
        self_desc: Optional[SelfDescription] = None
        if system_prompt:
            self_desc = derive_self_description(system_prompt, llm_fn=llm_fn)
            method_label = self_desc.method
            # Merge: explicit caps override derived ones, derived fill the rest
            merged_caps = sorted(
                set(self_desc.capabilities) | {c for c in (capabilities or []) if c}
            )
            print(f"🔍 Self-description derived ({method_label}): "
                  f"{len(merged_caps)} capabilities, "
                  f"{len(self_desc.task_types)} task types, "
                  f"{len(self_desc.refusals)} refusals")
        else:
            merged_caps = list(capabilities or [])

        if handle:
            try:
                self.client.claim_identity(self.wallet, handle, bio)
                print(f"✅ Identity: @{handle}")
            except Exception as e:
                print(f"ℹ️  Identity: {e}")
        try:
            self.client.register_agent(
                self.wallet, self.agent_id, name,
                capabilities=merged_caps,
                task_types=self_desc.task_types if self_desc else [],
                refusals=self_desc.refusals if self_desc else [],
                system_prompt_hash=self_desc.system_prompt_hash if self_desc else "",
                version_hash=version_hash,
            )
            print(f"✅ Agent registered: {name} ({self.agent_id})")
        except Exception as e:
            print(f"ℹ️  Agent: {e}")
        return self

    def get_reputation(self) -> Dict:
        return self.client.reputation(self.address)

    def get_balance(self) -> float:
        return self.client.balance(self.address)

    def poll_tasks(self, min_reward: float = 0.0) -> List[Dict]:
        tasks = self.client.get_open_tasks(agent_id=self.agent_id)
        if min_reward > 0:
            tasks = [t for t in tasks if t.get("reward", 0) >= min_reward]
        return tasks

    def complete_task(self, task_id: str, result: Any, note: str = "") -> Dict:
        """Submit result — automatically hashes it."""
        result_str = json.dumps(result, sort_keys=True) if isinstance(result, (dict, list)) else str(result)
        result_hash = hashlib.sha256(result_str.encode()).hexdigest()
        resp = self.client.complete_task(self.wallet, task_id, result_hash, note)
        print(f"✅ Task {task_id[:16]} completed")
        return resp

    def complete_pipeline_step(self, pipeline_id: str, step_index: int,
                                result: Any, note: str = "") -> Dict:
        result_str = json.dumps(result, sort_keys=True) if isinstance(result, (dict, list)) else str(result)
        result_hash = hashlib.sha256(result_str.encode()).hexdigest()
        return self.client.complete_pipeline_step(
            self.wallet, pipeline_id, step_index, result_hash, note)

    def run(self, handler: Callable[[Dict], Any], poll_interval: float = 10.0,
             min_reward: float = 0.0, max_tasks: Optional[int] = None) -> None:
        """Blocking task loop. Polls and calls handler(task) for each new task."""
        print(f"🤖 {self.agent_id} running (poll every {poll_interval}s)...")
        completed = 0
        seen = set()
        while True:
            try:
                for task in self.poll_tasks(min_reward=min_reward):
                    tid = task["task_id"]
                    if tid in seen:
                        continue
                    seen.add(tid)
                    print(f"📋 {task.get('title', tid)} (+{task.get('reward', 0)} NOVA)")
                    try:
                        result = handler(task)
                        self.complete_task(tid, result)
                        completed += 1
                    except Exception as e:
                        print(f"❌ Handler error: {e}")
                    if max_tasks and completed >= max_tasks:
                        print(f"Done. Completed {completed} tasks.")
                        return
            except Exception as e:
                print(f"⚠️  Poll error: {e}")
            time.sleep(poll_interval)
