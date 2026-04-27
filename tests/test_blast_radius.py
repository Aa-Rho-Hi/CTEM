import asyncio
from types import SimpleNamespace
from uuid import uuid4

from app.services.blast_radius import BlastRadiusService


class FakeScalarResult:
    def __init__(self, rows):
        self.rows = rows

    def scalars(self):
        return self

    def all(self):
        return self.rows

    def scalar_one_or_none(self):
        return None


class FakeSession:
    def __init__(self, nodes, edges):
        self._nodes = nodes
        self._edges = edges
        self.added = []

    async def execute(self, statement):
        text = str(statement)
        if "attack_graph_nodes" in text:
            return FakeScalarResult(self._nodes)
        if "attack_graph_edges" in text:
            return FakeScalarResult(self._edges)
        return FakeScalarResult([])

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        return None


def test_no_downstream():
    asset_id = str(uuid4())
    nodes = [SimpleNamespace(id=uuid4(), reference_id=asset_id, attributes={"zone_id": "z1"})]
    result = asyncio.run(BlastRadiusService().compute(FakeSession(nodes, []), asset_id, str(uuid4())))
    assert result.downstream_asset_count == 0
    assert result.high_blast_radius is False


def test_crown_jewel_reachable():
    source = str(uuid4())
    target = str(uuid4())
    nodes = [
        SimpleNamespace(id=uuid4(), reference_id=source, attributes={"zone_id": "z1"}),
        SimpleNamespace(id=uuid4(), reference_id=target, attributes={"zone_id": "z2", "crown_jewel_tier_id": "tier_1"}),
    ]
    edges = [SimpleNamespace(from_node_id=nodes[0].id, to_node_id=nodes[1].id)]
    result = asyncio.run(BlastRadiusService().compute(FakeSession(nodes, edges), source, str(uuid4())))
    assert result.high_blast_radius is True
    assert result.crown_jewel_assets_at_risk == 1


def test_multi_hop():
    source = str(uuid4())
    mid = str(uuid4())
    target = str(uuid4())
    nodes = [
        SimpleNamespace(id=uuid4(), reference_id=source, attributes={"zone_id": "z1"}),
        SimpleNamespace(id=uuid4(), reference_id=mid, attributes={"zone_id": "z2"}),
        SimpleNamespace(id=uuid4(), reference_id=target, attributes={"zone_id": "z3"}),
    ]
    edges = [
        SimpleNamespace(from_node_id=nodes[0].id, to_node_id=nodes[1].id),
        SimpleNamespace(from_node_id=nodes[1].id, to_node_id=nodes[2].id),
    ]
    result = asyncio.run(BlastRadiusService().compute(FakeSession(nodes, edges), source, str(uuid4())))
    assert result.downstream_asset_count == 2
    assert set(result.affected_zones) == {"z2", "z3"}


def test_reverse_edge_not_counted_as_downstream():
    source = str(uuid4())
    upstream = str(uuid4())
    nodes = [
        SimpleNamespace(id=uuid4(), reference_id=source, attributes={"zone_id": "z1"}),
        SimpleNamespace(id=uuid4(), reference_id=upstream, attributes={"zone_id": "z0"}),
    ]
    edges = [SimpleNamespace(from_node_id=nodes[1].id, to_node_id=nodes[0].id)]
    result = asyncio.run(BlastRadiusService().compute(FakeSession(nodes, edges), source, str(uuid4())))
    assert result.downstream_asset_count == 0
    assert result.affected_zones == []
