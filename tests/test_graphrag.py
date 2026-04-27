import asyncio
from types import SimpleNamespace
from uuid import uuid4

from app.models.entities import AgentDecision, AttackGraphEdge, AttackGraphNode
from app.services.graphrag import GraphRAGService


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
    def __init__(self, decisions=None, nodes=None, edges=None):
        self.decisions = list(decisions or [])
        self.nodes = list(nodes or [])
        self.edges = list(edges or [])
        self.added = []

    async def execute(self, statement):
        entity = statement.column_descriptions[0]["entity"]
        if entity is AttackGraphNode:
            rows = self.nodes
            text = str(statement)
            if "attack_graph_nodes.node_type" in text and "attack_graph_nodes.reference_id" in text:
                node_type = statement._where_criteria[1].right.value
                reference_id = statement._where_criteria[2].right.value
                rows = [node for node in rows if node.node_type == node_type and node.reference_id == reference_id]
            return FakeScalarResult(rows)
        if entity is AttackGraphEdge:
            return FakeScalarResult(self.edges)
        if entity is AgentDecision:
            return FakeScalarResult(self.decisions)
        raise AssertionError(f"Unexpected entity: {entity}")

    def add(self, obj):
        self.added.append(obj)
        if isinstance(obj, AttackGraphNode):
            self.nodes.append(obj)
        elif isinstance(obj, AttackGraphEdge):
            self.edges.append(obj)

    async def flush(self):
        return None


def _decision(confidence):
    return SimpleNamespace(
        id=uuid4(),
        tenant_id=uuid4(),
        agent_id=uuid4(),
        goal="goal finding-1",
        reasoning_chain={"finding_id": "finding-1"},
        decision="execute_plan",
        confidence_score=confidence,
        outcome="plan_formed",
        created_at=None,
    )


def test_record_approval_boosts_confidence():
    decision = _decision(0.5)
    session = FakeSession(decisions=[decision])
    asyncio.run(GraphRAGService().record_approval(session, "finding-1", "rem-1", "approver-1", str(uuid4())))
    assert decision.confidence_score == 0.55


def test_record_rejection_reduces_confidence():
    decision = _decision(0.5)
    session = FakeSession(decisions=[decision])
    asyncio.run(GraphRAGService().record_rejection(session, "finding-1", "rem-1", "approver-1", "no", str(uuid4())))
    assert decision.confidence_score == 0.4


def test_confidence_capped_at_1():
    decision = _decision(1.0)
    session = FakeSession(decisions=[decision])
    asyncio.run(GraphRAGService().record_approval(session, "finding-1", "rem-1", "approver-1", str(uuid4())))
    assert decision.confidence_score == 1.0


def test_confidence_floored_at_0():
    decision = _decision(0.0)
    session = FakeSession(decisions=[decision])
    asyncio.run(GraphRAGService().record_rejection(session, "finding-1", "rem-1", "approver-1", "no", str(uuid4())))
    assert decision.confidence_score == 0.0


def test_load_decisions_matches_goal_when_metadata_missing():
    decision = _decision(0.5)
    decision.reasoning_chain = {"summary": "goal references finding-1"}
    session = FakeSession(decisions=[decision])
    asyncio.run(GraphRAGService().record_approval(session, "finding-1", "rem-1", "approver-1", str(uuid4())))
    assert decision.confidence_score == 0.55
