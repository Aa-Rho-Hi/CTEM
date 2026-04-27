from types import SimpleNamespace
from uuid import uuid4
import asyncio

from app.services.attack_graph import AttackGraphService


def test_attack_graph_builds_same_zone_edges_and_choke_points():
    zone_id = uuid4()
    assets = [
        SimpleNamespace(id=uuid4(), ip_address="10.0.0.1", zone_id=zone_id, criticality_score=80, crown_jewel_tier_id=None),
        SimpleNamespace(id=uuid4(), ip_address="10.0.0.2", zone_id=zone_id, criticality_score=50, crown_jewel_tier_id=None),
        SimpleNamespace(id=uuid4(), ip_address="10.0.0.3", zone_id=zone_id, criticality_score=20, crown_jewel_tier_id=None),
    ]
    graph, centrality, choke_points = AttackGraphService().build_graph(assets)
    assert len(graph.nodes) == 3
    assert len(graph.edges) == 4
    assert graph.is_directed() is True
    assert isinstance(choke_points, set)
    assert str(assets[0].id) in choke_points
    assert centrality[str(assets[0].id)] > 0.0


def test_attack_graph_prefers_internal_relay_between_exposed_and_crown_assets():
    zone_id = uuid4()
    crown_tier_id = uuid4()
    entry_asset = SimpleNamespace(
        id=uuid4(),
        ip_address="34.82.10.14",
        zone_id=zone_id,
        criticality_score=40,
        crown_jewel_tier_id=None,
        business_context={"internet_exposed": True, "external_attack_surface": True},
    )
    relay_asset = SimpleNamespace(
        id=uuid4(),
        ip_address="10.0.0.15",
        zone_id=zone_id,
        criticality_score=92,
        crown_jewel_tier_id=None,
        business_context={"attack_path_score": 88},
    )
    crown_asset = SimpleNamespace(
        id=uuid4(),
        ip_address="10.0.0.16",
        zone_id=zone_id,
        criticality_score=99,
        crown_jewel_tier_id=crown_tier_id,
        business_context={},
    )

    graph, centrality, choke_points = AttackGraphService().build_graph([entry_asset, relay_asset, crown_asset])

    assert graph.has_edge(str(entry_asset.id), str(relay_asset.id))
    assert graph.has_edge(str(relay_asset.id), str(crown_asset.id))
    assert not graph.has_edge(str(entry_asset.id), str(crown_asset.id))
    assert str(relay_asset.id) in choke_points
    assert centrality[str(relay_asset.id)] > 0.0


def test_attack_surface_filters_assets_without_findings():
    service = AttackGraphService()
    matching_asset = SimpleNamespace(id=uuid4())
    non_matching_asset = SimpleNamespace(id=uuid4())

    filtered = service._filter_assets_for_attack_surface(
        [matching_asset, non_matching_asset],
        {str(matching_asset.id): {"related_finding_count": 1, "max_risk_score": 75}},
    )

    assert filtered == [matching_asset]


class FakeResult:
    def __init__(self, rows):
        self.rows = rows

    def scalar_one_or_none(self):
        return self.rows[0] if self.rows else None


class FakeSession:
    def __init__(self, nodes):
        self.nodes = nodes

    async def execute(self, statement):
        ref = str(statement.compile(compile_kwargs={"literal_binds": True}))
        for node in self.nodes:
            if node.reference_id in ref:
                return FakeResult([node])
        return FakeResult([])


def test_attack_graph_formats_detailed_paths():
    service = AttackGraphService()
    source_id = str(uuid4())
    target_id = str(uuid4())
    nodes = [
        SimpleNamespace(reference_id=source_id, is_choke_point=False, centrality_score=0.1, attributes={"ip": "10.0.0.1", "zone_id": "z1", "criticality_score": 50}),
        SimpleNamespace(reference_id=target_id, is_choke_point=True, centrality_score=0.9, attributes={"ip": "10.0.0.2", "zone_id": "z1", "criticality_score": 90}),
    ]

    async def fake_load_graph(session):
        import networkx as nx

        graph = nx.DiGraph()
        graph.add_edge(source_id, target_id)
        return graph

    service._load_graph = fake_load_graph
    details = asyncio.run(service.get_attack_path_details(FakeSession(nodes), source_id, target_id))
    assert details[0]["length"] == 2
    assert details[0]["nodes"][1]["is_choke_point"] is True
