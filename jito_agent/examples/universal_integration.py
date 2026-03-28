"""
Universal Nova Agent Identity — works with any framework, any language.

Nova gives every AI agent a verifiable identity and trust score.
It doesn't matter how your agent is built — the identity travels with it.

────────────────────────────────────────────────────────────────────────────
PATTERN 1: Zero-config via environment variables (recommended)
────────────────────────────────────────────────────────────────────────────
Set these once in your environment, Docker, or .env file:

    export NOVA_AGENT_ID=my-agent
    export NOVA_WALLET_PATH=/secrets/nova_wallet.json
    export NOVA_NODE_URL=https://explorer.flowpe.io

Then in any Python agent — 2 lines:

    from jito_agent import JitoTracker
    tracker = JitoTracker.from_env()
    tracker.log("task_completed", success=True)

────────────────────────────────────────────────────────────────────────────
PATTERN 2: Manual setup (custom agents, raw API calls)
────────────────────────────────────────────────────────────────────────────
"""

# ── Any custom agent ──────────────────────────────────────────────────────

def example_custom_agent():
    from jito_agent import JitoTracker

    tracker = JitoTracker.new("my-custom-agent")

    # Manual log — use after anything your agent does
    result = run_my_agent("analyze this document")
    tracker.log("document_analysis", success=True, tags=["analysis"])

    # Context manager — auto-times, logs failure on exception
    with tracker.track("contract_review", tags=["legal"]) as ctx:
        result = run_my_agent("review contract")
        ctx.set_output(result)

    print(tracker.get_reputation())


# ── OpenAI raw API ────────────────────────────────────────────────────────

def example_openai_raw():
    import time
    from openai import OpenAI
    from jito_agent import JitoTracker

    tracker = JitoTracker.from_env()
    client = OpenAI()

    start = time.time()
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Summarize quantum computing"}]
    )
    duration_ms = int((time.time() - start) * 1000)

    tracker.log(
        "llm_call",
        success=True,
        duration_ms=duration_ms,
        tags=["openai", "gpt-4o"],
        note=response.choices[0].message.content[:100],
    )


# ── Anthropic raw API ─────────────────────────────────────────────────────

def example_anthropic_raw():
    import time
    import anthropic
    from jito_agent import JitoTracker

    tracker = JitoTracker.from_env()
    client = anthropic.Anthropic()

    with tracker.track("llm_call", tags=["anthropic", "claude"]) as ctx:
        response = client.messages.create(
            model="claude-opus-4-6",
            max_tokens=1024,
            messages=[{"role": "user", "content": "Explain black holes"}]
        )
        ctx.set_output(response.content[0].text)


# ── LangChain (zero code change) ──────────────────────────────────────────

def example_langchain():
    from jito_agent import JitoTracker
    from jito_agent.callbacks import JitoCallbackHandler
    from langchain_openai import ChatOpenAI
    from langchain_core.messages import HumanMessage

    tracker = JitoTracker.from_env()
    handler = JitoCallbackHandler(tracker, tags=["langchain"])

    llm = ChatOpenAI(model="gpt-4o-mini")
    response = llm.invoke(
        [HumanMessage(content="Hello")],
        config={"callbacks": [handler]},
    )


# ── CrewAI ────────────────────────────────────────────────────────────────

def example_crewai():
    from jito_agent import JitoTracker
    from jito_agent.integrations.crewai import NovaCrewCallback

    tracker = JitoTracker.from_env()
    callback = NovaCrewCallback(tracker, tags=["crewai"])

    # from crewai import Crew, Agent, Task
    # crew = Crew(agents=[...], tasks=[...], callbacks=[callback])
    # crew.kickoff()


# ── AutoGen ───────────────────────────────────────────────────────────────

def example_autogen():
    from jito_agent import JitoTracker
    from jito_agent.integrations.autogen import NovaAutogenHook

    tracker = JitoTracker.from_env()
    hook = NovaAutogenHook(tracker, tags=["autogen"])

    # import autogen
    # agent = autogen.AssistantAgent(name="assistant", ...)
    # hook.instrument(agent)  # one line — zero other changes


# ── OpenAI wrapper (auto-logs every call) ─────────────────────────────────

def example_openai_wrapper():
    from openai import OpenAI
    from jito_agent import JitoTracker
    from jito_agent.integrations.openai import NovaOpenAIWrapper

    tracker = JitoTracker.from_env()
    client = NovaOpenAIWrapper(tracker, OpenAI(), tags=["openai"])

    # Exact same API — every call is auto-logged
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Hello"}]
    )


# ── n8n / Flowise / OpenClaw / any no-code platform ──────────────────────
"""
For no-code platforms, use the webhook endpoint on the Nova node.
No SDK needed — just an HTTP POST.

Set up once on the node:
    export WEBHOOK_API_KEY=your-secret-key
    export WEBHOOK_WALLET_PATH=/data/webhook_wallet.json

Then from any tool that can make HTTP requests:

    curl -X POST https://explorer.flowpe.io/public/agent/webhook \\
      -H "Content-Type: application/json" \\
      -d '{
        "api_key": "your-secret-key",
        "agent_id": "my-n8n-agent",
        "action_type": "task_completed",
        "success": true,
        "tags": ["n8n", "automation"],
        "note": "Processed 50 records"
      }'

Response:
    {"ok": true, "tx_id": "abc123...", "agent": "W..."}

Works with: n8n HTTP node, Flowise HTTP node, OpenClaw webhooks,
            Zapier webhooks, Make.com HTTP, any curl command.
"""


# ── Any language via raw HTTP ─────────────────────────────────────────────
"""
If you're not using Python or JS, use the webhook endpoint.
Here's the same call in different languages:

JavaScript/Node.js:
    await fetch("https://explorer.flowpe.io/public/agent/webhook", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            api_key: "your-secret-key",
            agent_id: "my-agent",
            action_type: "task_completed",
            success: true,
            tags: ["node"]
        })
    });

Go:
    http.Post("https://explorer.flowpe.io/public/agent/webhook",
        "application/json",
        strings.NewReader(`{"agent_id":"my-agent","action_type":"task_completed","success":true}`))

Ruby:
    Net::HTTP.post(URI("https://explorer.flowpe.io/public/agent/webhook"),
        {agent_id: "my-agent", action_type: "task_completed", success: true}.to_json,
        "Content-Type" => "application/json")
"""


def run_my_agent(task: str) -> str:
    return f"result of: {task}"
