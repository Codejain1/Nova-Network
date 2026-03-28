"""
LangChain integration example — zero changes to existing agent code.

Install:
    pip install jito-agent langchain-core langchain-openai

Run:
    OPENAI_API_KEY=sk-... python langchain_integration.py
"""

from jito_agent import JitoTracker
from jito_agent.callbacks import JitoCallbackHandler


def main() -> None:
    # 1. Set up tracker once — wallet.json is created on first run
    tracker = JitoTracker.new("my-langchain-agent")
    handler = JitoCallbackHandler(tracker, tags=["langchain"])

    # 2. Build your LangChain agent exactly as you normally would
    from langchain_openai import ChatOpenAI
    from langchain_core.messages import HumanMessage

    llm = ChatOpenAI(model="gpt-4o-mini")

    # 3. Pass the handler — nothing else changes
    response = llm.invoke(
        [HumanMessage(content="Summarize quantum computing in one sentence.")],
        config={"callbacks": [handler]},
    )
    print(response.content)

    # Every LLM call is now logged. Check reputation:
    print(tracker.get_reputation())


if __name__ == "__main__":
    main()
