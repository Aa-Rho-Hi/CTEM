from dataclasses import dataclass
from datetime import datetime, timezone

import networkx as nx
from sqlalchemy import select

from app.models.entities import Asset, AttackGraphEdge, AttackGraphNode, BlastRadiusSnapshot


@dataclass
class BlastRadiusResult:
    asset_id: str
    downstream_asset_count: int
    crown_jewel_assets_at_risk: int
    affected_zones: list[str]
    high_blast_radius: bool
    computed_at: str


class BlastRadiusService:
    def build_graph(self, nodes, edges) -> nx.DiGraph:
        graph = nx.DiGraph()
        for node in nodes:
            graph.add_node(node.reference_id, **node.attributes)
        node_index = {str(node.id): node for node in nodes}
        for edge in edges:
            source = node_index.get(str(edge.from_node_id))
            target = node_index.get(str(edge.to_node_id))
            if source and target:
                graph.add_edge(source.reference_id, target.reference_id)
        return graph

    async def compute(self, session, asset_id: str, tenant_id: str, remediation_id: str | None = None) -> BlastRadiusResult:
        nodes = (await session.execute(select(AttackGraphNode).where(AttackGraphNode.tenant_id == tenant_id))).scalars().all()
        edges = (await session.execute(select(AttackGraphEdge).where(AttackGraphEdge.tenant_id == tenant_id))).scalars().all()
        graph = self.build_graph(nodes, edges)
        descendants = nx.descendants(graph, asset_id) if asset_id in graph else set()
        descendant_nodes = [node for node in nodes if node.reference_id in descendants]
        affected_zones = sorted({node.attributes.get("zone_id") for node in descendant_nodes if node.attributes.get("zone_id")})
        crown_jewel_count = sum(1 for node in descendant_nodes if node.attributes.get("crown_jewel_tier_id"))
        result = BlastRadiusResult(
            asset_id=asset_id,
            downstream_asset_count=len(descendants),
            crown_jewel_assets_at_risk=crown_jewel_count,
            affected_zones=affected_zones,
            high_blast_radius=crown_jewel_count > 0,
            computed_at=datetime.now(timezone.utc).isoformat(),
        )
        snapshot = BlastRadiusSnapshot(
            tenant_id=tenant_id,
            remediation_id=remediation_id,
            asset_id=asset_id,
            downstream_dependency_count=result.downstream_asset_count,
            crown_jewel_count=result.crown_jewel_assets_at_risk,
            affected_zones=result.affected_zones,
            high_blast_radius=result.high_blast_radius,
            snapshot_json=result.__dict__,
        )
        session.add(snapshot)
        await session.flush()
        return result
