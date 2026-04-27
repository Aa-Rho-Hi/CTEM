import asyncio
from types import SimpleNamespace
from uuid import uuid4

from app.agents.base import BaseAgent


class FakeSession:
    def __init__(self):
        self.added = []

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        return None


def test_agent_replans_after_missing_target(monkeypatch):
    agent = BaseAgent(
        tenant_id=str(uuid4()),
        tool_whitelist=["nmap", "graphrag_query"],
        safety_ceiling=70,
        agent_id=str(uuid4()),
    )
    session = FakeSession()

    async def fake_llm_plan(goal, context):
        if "Observation" in goal:
            return "Use graphrag_query for context instead."
        return "Use nmap against the target."

    async def fake_query(session_obj, query, tenant_id):
        return {"nodes": [{"id": "n1", "asset_id": "asset-1", "is_crown_jewel": False, "is_choke_point": False, "centrality_score": 0.1}], "edges": [], "query": query}

    monkeypatch.setattr(agent, "_llm_plan", fake_llm_plan)
    monkeypatch.setattr(agent, "_query_graphrag", fake_query)

    result = asyncio.run(agent.run(goal="inspect exposure posture", session=session, tenant_id=agent.tenant_id))

    assert result.decision == "execute:graphrag_query"
    assert "Graph query returned" in result.outcome
    assert len(session.added) >= 2


def test_persisted_agent_run_requires_session():
    agent = BaseAgent(
        tenant_id=str(uuid4()),
        tool_whitelist=["graphrag_query"],
        safety_ceiling=70,
        agent_id=str(uuid4()),
    )

    try:
        asyncio.run(agent.run(goal="inspect exposure posture"))
    except RuntimeError as exc:
        assert "database session" in str(exc)
    else:
        raise AssertionError("Expected persisted agent run without session to fail closed")
