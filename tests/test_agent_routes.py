import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

from app.models.entities import Agent, AgentDecision, AttackGraphEdge, AttackGraphNode
from app.routes.agents import (
    AgentCreateRequest,
    AgentRunRequest,
    create_agent,
    get_agent_catalogue,
    decommission_agent,
    get_agent,
    list_agents,
    run_agent,
)


class FakeScalarResult:
    def __init__(self, rows):
        self.rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self.rows)

    def scalar_one_or_none(self):
        return self.rows[0] if self.rows else None


class FakeSession:
    def __init__(self):
        self.agents = []
        self.decisions = []
        self.nodes = []
        self.edges = []
        self.added = []

    async def execute(self, statement):
        entity = statement.column_descriptions[0]["entity"]
        if entity is Agent:
            return FakeScalarResult(self.agents)
        if entity is AgentDecision:
            agent_id = statement._where_criteria[0].right.value
            rows = [item for item in self.decisions if item.agent_id == agent_id]
            limit_clause = statement._limit_clause.value if statement._limit_clause is not None else len(rows)
            offset_clause = statement._offset_clause.value if statement._offset_clause is not None else 0
            return FakeScalarResult(rows[offset_clause : offset_clause + limit_clause])
        if entity is AttackGraphNode:
            return FakeScalarResult(self.nodes)
        if entity is AttackGraphEdge:
            return FakeScalarResult(self.edges)
        raise AssertionError(f"Unexpected entity: {entity}")

    async def get(self, model, key):
        if model is Agent:
            return next((item for item in self.agents if str(item.id) == str(key)), None)
        return None

    def add(self, obj):
        self.added.append(obj)
        if isinstance(obj, Agent):
            self.agents.append(obj)
        elif isinstance(obj, AgentDecision):
            self.decisions.append(obj)
        elif isinstance(obj, AttackGraphNode):
            self.nodes.append(obj)
        elif isinstance(obj, AttackGraphEdge):
            self.edges.append(obj)

    async def flush(self):
        return None

    async def commit(self):
        return None


def _user():
    return SimpleNamespace(user_id=str(uuid4()), tenant_id=uuid4())


def test_create_agent():
    session = FakeSession()
    response = asyncio.run(
        create_agent(
            AgentCreateRequest(
                name="intern-pt-agent",
                agent_type="pt_agent",
                tool_whitelist=["nmap", "burp_suite"],
                safety_ceiling=85,
            ),
            session=session,
            current_user=_user(),
        )
    )
    assert response["name"] == "intern-pt-agent"
    assert response["agent_type"] == "pt_agent"
    assert session.agents


def test_get_agent_catalogue():
    payload = asyncio.run(get_agent_catalogue())
    assert len(payload["platform_tools"]) == 16
    assert any(item["id"] == "pt_agent" for item in payload["agent_types"])


def test_decommission_preserves_config():
    session = FakeSession()
    agent = Agent(
        id=uuid4(),
        tenant_id=uuid4(),
        name="agent-1",
        tool_whitelist=["nmap"],
        safety_ceiling=85,
        is_active=True,
        config_json={"agent_type": "pt_agent", "schedule": "daily"},
    )
    session.agents.append(agent)
    response = asyncio.run(decommission_agent(str(agent.id), session=session, current_user=_user()))
    assert response["is_active"] is False
    assert session.agents[0].config_json["schedule"] == "daily"


def test_decommission_not_delete():
    session = FakeSession()
    agent = Agent(
        id=uuid4(),
        tenant_id=uuid4(),
        name="agent-1",
        tool_whitelist=["nmap"],
        safety_ceiling=85,
        is_active=True,
        config_json={"agent_type": "pt_agent"},
    )
    session.agents.append(agent)
    asyncio.run(decommission_agent(str(agent.id), session=session, current_user=_user()))
    fetched = asyncio.run(get_agent(str(agent.id), session=session))
    assert fetched["id"] == str(agent.id)
    assert fetched["is_active"] is False


def test_run_agent_returns_result():
    session = FakeSession()
    tenant_id = uuid4()
    agent = Agent(
        id=uuid4(),
        tenant_id=tenant_id,
        name="agent-1",
        tool_whitelist=["graphrag_query", "attack_graph_query"],
        safety_ceiling=85,
        is_active=True,
        config_json={"agent_type": "compliance_agent"},
        created_at=datetime.now(timezone.utc),
    )
    session.agents.append(agent)
    result = asyncio.run(
        run_agent(
            str(agent.id),
            AgentRunRequest(goal="review attack graph choke points"),
            session=session,
            current_user=SimpleNamespace(user_id=str(uuid4()), tenant_id=tenant_id),
        )
    )
    assert result.decision.startswith("execute:")
    assert "Graph query returned" in result.outcome
    assert session.decisions


def test_list_agents_returns_wrapped_items():
    session = FakeSession()
    agent = Agent(
        id=uuid4(),
        tenant_id=uuid4(),
        name="agent-1",
        tool_whitelist=["nmap"],
        safety_ceiling=85,
        is_active=True,
        config_json={"agent_type": "pt_agent"},
        created_at=datetime.now(timezone.utc),
    )
    session.agents.append(agent)
    result = asyncio.run(list_agents(session=session))
    assert "items" in result
    assert result["items"][0]["id"] == str(agent.id)


def test_run_agent_logs_finding_metadata():
    session = FakeSession()
    tenant_id = uuid4()
    agent = Agent(
        id=uuid4(),
        tenant_id=tenant_id,
        name="agent-1",
        tool_whitelist=["graphrag_query"],
        safety_ceiling=85,
        is_active=True,
        config_json={"agent_type": "compliance_agent"},
        created_at=datetime.now(timezone.utc),
    )
    session.agents.append(agent)
    asyncio.run(
        run_agent(
            str(agent.id),
            AgentRunRequest(goal="investigate finding", finding_id="finding-123"),
            session=session,
            current_user=SimpleNamespace(user_id=str(uuid4()), tenant_id=tenant_id),
        )
    )
    assert any(decision.reasoning_chain.get("finding_id") == "finding-123" for decision in session.decisions)
