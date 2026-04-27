import networkx as nx
from sqlalchemy import delete, func, select

from app.models.entities import Asset, AttackGraphEdge, AttackGraphNode, CrownJewelTier, NetworkZone, Vulnerability
from app.services.scope_service import normalize_asset_business_context


class AttackGraphService:
    MAX_RENDERED_ATTACK_SURFACE_EDGES = 1500
    MAX_CHOKE_POINTS = 12

    def _filter_assets_for_attack_surface(self, assets, vulnerability_summary_map: dict[str, dict]) -> list:
        return [
            asset
            for asset in assets
            if str(asset.id) in vulnerability_summary_map
        ]

    def build_graph(self, assets) -> tuple[nx.DiGraph, dict[str, float], set[str]]:
        graph = nx.DiGraph()
        zone_map: dict[str | None, list] = {}
        asset_profiles: dict[str, dict[str, float | bool | str | None]] = {}
        for asset in assets:
            asset_id = str(asset.id)
            profile = self._build_asset_profile(asset)
            graph.add_node(
                asset_id,
                ip=asset.ip_address,
                zone_id=str(asset.zone_id) if asset.zone_id else None,
                criticality_score=asset.criticality_score,
                crown_jewel_tier_id=str(asset.crown_jewel_tier_id) if asset.crown_jewel_tier_id else None,
            )
            zone_map.setdefault(str(asset.zone_id) if asset.zone_id else None, []).append(asset)
            asset_profiles[asset_id] = profile

        for assets_in_zone in zone_map.values():
            self._connect_zone_topology(graph, assets_in_zone, asset_profiles)

        centrality = nx.betweenness_centrality(graph) if graph.nodes else {}
        top_choke_points = self._identify_choke_points(zone_map, centrality, asset_profiles)
        return graph, centrality, top_choke_points

    async def rebuild_for_tenant(self, session, tenant_id):
        assets = (await session.execute(select(Asset))).scalars().all()
        await session.execute(delete(AttackGraphEdge))
        await session.flush()  # edges must be gone before nodes due to FK
        await session.execute(delete(AttackGraphNode))
        await session.flush()
        graph, centrality, top_choke_points = self.build_graph(assets)
        node_map = {}
        for asset in assets:
            node = AttackGraphNode(
                tenant_id=tenant_id,
                node_type="asset",
                reference_id=str(asset.id),
                is_choke_point=str(asset.id) in top_choke_points,
                centrality_score=float(centrality.get(str(asset.id), 0.0)),
                attributes={
                    "ip": asset.ip_address,
                    "zone_id": str(asset.zone_id) if asset.zone_id else None,
                    "criticality_score": asset.criticality_score,
                    "crown_jewel_tier_id": str(asset.crown_jewel_tier_id) if asset.crown_jewel_tier_id else None,
                },
            )
            session.add(node)
            await session.flush()
            node_map[str(asset.id)] = node

        for source_id, target_id, edge_data in graph.edges(data=True):
            session.add(
                AttackGraphEdge(
                    tenant_id=tenant_id,
                    from_node_id=node_map[source_id].id,
                    to_node_id=node_map[target_id].id,
                    edge_type=edge_data["edge_type"],
                    attributes={},
                )
            )
        await session.flush()
        return graph

    async def get_attack_paths(self, session, source_asset_id: str, target_asset_id: str) -> list[list[str]]:
        graph = await self._load_graph(session)
        try:
            paths = nx.all_simple_paths(graph, source_asset_id, target_asset_id, cutoff=5)
            return [list(path) for path in paths]
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    async def get_attack_path_details(self, session, source_asset_id: str, target_asset_id: str) -> list[dict]:
        graph = await self._load_graph(session)
        try:
            paths = nx.all_simple_paths(graph, source_asset_id, target_asset_id, cutoff=5)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []
        detailed_paths = []
        for path in paths:
            nodes = []
            for node_id in path:
                node = (
                    await session.execute(select(AttackGraphNode).where(AttackGraphNode.reference_id == node_id))
                ).scalar_one_or_none()
                if node is None:
                    continue
                nodes.append(
                    {
                        "asset_id": node.reference_id,
                        "ip": node.attributes.get("ip"),
                        "zone_id": node.attributes.get("zone_id"),
                        "criticality_score": node.attributes.get("criticality_score"),
                        "is_choke_point": node.is_choke_point,
                        "centrality_score": node.centrality_score,
                    }
                )
            detailed_paths.append({"length": len(nodes), "nodes": nodes})
        return detailed_paths

    async def get_choke_points(self, session) -> list[dict]:
        statement = (
            select(AttackGraphNode)
            .where(AttackGraphNode.is_choke_point.is_(True))
            .order_by(AttackGraphNode.centrality_score.desc())
        )
        nodes = (await session.execute(statement)).scalars().all()
        return [
            {
                "asset_id": node.reference_id,
                "centrality_score": node.centrality_score,
                "ip": node.attributes.get("ip"),
                "zone_id": node.attributes.get("zone_id"),
                "criticality_score": node.attributes.get("criticality_score"),
                "attributes": node.attributes,
            }
            for node in nodes
        ]

    async def get_attack_surface(self, session, tenant_id) -> dict:
        assets = (await session.execute(select(Asset))).scalars().all()
        zones = {
            str(zone.id): zone
            for zone in (await session.execute(select(NetworkZone))).scalars().all()
        }
        crown_jewel_tiers = {
            str(tier.id): tier
            for tier in (await session.execute(select(CrownJewelTier))).scalars().all()
        }
        vulnerability_count_rows = (
            await session.execute(
                select(
                    Vulnerability.asset_id,
                    func.count(Vulnerability.id),
                    func.max(Vulnerability.risk_score),
                )
                .where(Vulnerability.asset_id.is_not(None))
                .group_by(Vulnerability.asset_id)
            )
        ).all()
        vulnerability_summary_map = {
            str(asset_id): {
                "related_finding_count": finding_count,
                "max_risk_score": max_risk_score or 0,
            }
            for asset_id, finding_count, max_risk_score in vulnerability_count_rows
            if asset_id is not None
        }
        top_findings_ranked = (
            select(
                Vulnerability.id.label("id"),
                Vulnerability.asset_id.label("asset_id"),
                Vulnerability.cve_id.label("cve_id"),
                Vulnerability.severity.label("severity"),
                Vulnerability.status.label("status"),
                Vulnerability.risk_score.label("risk_score"),
                func.row_number().over(
                    partition_by=Vulnerability.asset_id,
                    order_by=(Vulnerability.risk_score.desc(), Vulnerability.created_at.desc(), Vulnerability.id.desc()),
                ).label("rownum"),
            )
            .where(Vulnerability.asset_id.is_not(None))
            .subquery()
        )
        top_finding_rows = (
            await session.execute(
                select(
                    top_findings_ranked.c.id,
                    top_findings_ranked.c.asset_id,
                    top_findings_ranked.c.cve_id,
                    top_findings_ranked.c.severity,
                    top_findings_ranked.c.status,
                    top_findings_ranked.c.risk_score,
                )
                .where(top_findings_ranked.c.rownum <= 5)
                .order_by(top_findings_ranked.c.asset_id, top_findings_ranked.c.rownum)
            )
        ).all()
        vulnerability_map: dict[str, list[dict]] = {}
        for finding_id, asset_id, cve_id, severity, status, risk_score in top_finding_rows:
            if asset_id is None:
                continue
            vulnerability_map.setdefault(str(asset_id), []).append(
                {
                    "id": str(finding_id),
                    "cve_id": cve_id,
                    "severity": severity,
                    "status": status.value if hasattr(status, "value") else status,
                    "risk_score": risk_score,
                }
            )

        assets = self._filter_assets_for_attack_surface(assets, vulnerability_summary_map)
        asset_map = {str(asset.id): asset for asset in assets}
        graph, computed_centrality, computed_top_choke_points = self.build_graph(assets)
        attack_graph_nodes = (
            await session.execute(
                select(AttackGraphNode).where(AttackGraphNode.node_type == "asset")
            )
        ).scalars().all()
        graph_node_by_reference_id = {node.reference_id: node for node in attack_graph_nodes}
        if attack_graph_nodes and len(graph_node_by_reference_id) == len(asset_map):
            centrality = {
                node.reference_id: float(node.centrality_score or 0.0)
                for node in attack_graph_nodes
            }
            top_choke_points = {
                node.reference_id
                for node in attack_graph_nodes
                if node.is_choke_point
            }
        else:
            centrality = computed_centrality
            top_choke_points = computed_top_choke_points

        serialized_nodes = []
        ordered_asset_ids = sorted(
            (str(asset.id) for asset in assets),
            key=lambda asset_id: (
                float(centrality.get(asset_id, 0.0)),
                asset_map[asset_id].criticality_score,
                vulnerability_summary_map.get(asset_id, {}).get("related_finding_count", 0),
            ),
            reverse=True,
        )
        for asset_id in ordered_asset_ids:
            asset = asset_map[asset_id]
            zone_id = str(asset.zone_id) if asset.zone_id else None
            tier_id = str(asset.crown_jewel_tier_id) if asset.crown_jewel_tier_id else None
            tier_name = crown_jewel_tiers[tier_id].name if tier_id and tier_id in crown_jewel_tiers else None
            business_context = normalize_asset_business_context(asset, crown_jewel_tier_name=tier_name)
            vulnerability_summary = vulnerability_summary_map.get(asset_id, {})
            serialized_nodes.append(
                {
                    "id": asset_id,
                    "asset_id": asset_id,
                    "hostname": asset.hostname if asset else None,
                    "ip": asset.ip_address if asset else None,
                    "zone_id": zone_id,
                    "zone_name": zones[zone_id].name if zone_id and zone_id in zones else None,
                    "criticality_score": asset.criticality_score if asset else 0,
                    "centrality_score": float(centrality.get(asset_id, 0.0)),
                    "is_choke_point": asset_id in top_choke_points,
                    "is_crown_jewel": bool(business_context.get("is_crown_jewel")),
                    "crown_jewel_tier": tier_name,
                    "business_context": business_context,
                    "related_findings": vulnerability_map.get(asset_id, [])[:5],
                    "related_finding_count": vulnerability_summary.get("related_finding_count", 0),
                    "max_risk_score": vulnerability_summary.get("max_risk_score", 0),
                }
            )

        serialized_edges = self._serialize_attack_surface_edges(graph)
        total_edge_count = graph.number_of_edges()

        crown_jewel_count = sum(1 for node in serialized_nodes if node["is_crown_jewel"])
        choke_point_count = sum(1 for node in serialized_nodes if node["is_choke_point"])
        average_centrality = round(
            sum(float(node["centrality_score"]) for node in serialized_nodes) / len(serialized_nodes),
            3,
        ) if serialized_nodes else 0.0
        zone_count = len({node["zone_id"] or "unzoned" for node in serialized_nodes})

        return {
            "summary": {
                "node_count": len(serialized_nodes),
                "edge_count": total_edge_count,
                "zone_count": zone_count,
                "crown_jewel_count": crown_jewel_count,
                "choke_point_count": choke_point_count,
                "average_centrality": average_centrality,
            },
            "nodes": serialized_nodes,
            "edges": serialized_edges,
        }

    async def _load_graph(self, session):
        graph = nx.DiGraph()
        nodes = (await session.execute(select(AttackGraphNode))).scalars().all()
        edges = (await session.execute(select(AttackGraphEdge))).scalars().all()
        for node in nodes:
            graph.add_node(node.reference_id, **node.attributes)
        for edge in edges:
            source = await session.get(AttackGraphNode, edge.from_node_id)
            target = await session.get(AttackGraphNode, edge.to_node_id)
            if source and target:
                graph.add_edge(source.reference_id, target.reference_id, edge_type=edge.edge_type)
        return graph

    def _build_asset_profile(self, asset) -> dict[str, float | bool]:
        business_context = normalize_asset_business_context(asset)
        criticality_score = float(getattr(asset, "criticality_score", 0) or 0.0)
        attack_path_score = float(business_context.get("attack_path_score") or 0.0)
        internet_exposed = bool(
            business_context.get("internet_exposed")
            or business_context.get("external_attack_surface")
        )
        is_crown_jewel = bool(business_context.get("is_crown_jewel"))
        relay_score = (
            (criticality_score * 0.55)
            + (attack_path_score * 0.35)
            + (10.0 if internet_exposed else 0.0)
            - (15.0 if is_crown_jewel else 0.0)
        )
        return {
            "criticality_score": criticality_score,
            "attack_path_score": attack_path_score,
            "internet_exposed": internet_exposed,
            "is_crown_jewel": is_crown_jewel,
            "relay_score": relay_score,
        }

    def _connect_zone_topology(
        self,
        graph: nx.DiGraph,
        assets_in_zone: list,
        asset_profiles: dict[str, dict[str, float | bool | str | None]],
    ) -> None:
        if len(assets_in_zone) < 2:
            return

        asset_ids = [str(asset.id) for asset in assets_in_zone]
        internet_entry_ids = [
            asset_id
            for asset_id in asset_ids
            if bool(asset_profiles[asset_id]["internet_exposed"])
        ]
        crown_asset_ids = [
            asset_id
            for asset_id in asset_ids
            if bool(asset_profiles[asset_id]["is_crown_jewel"])
        ]
        relay_ids = self._select_zone_relays(
            asset_ids,
            asset_profiles=asset_profiles,
            prefer_internal_relays=bool(internet_entry_ids and crown_asset_ids),
        )

        if len(relay_ids) > 1:
            for source_id, target_id in zip(relay_ids, relay_ids[1:]):
                self._add_bidirectional_edge(graph, source_id, target_id, edge_type="relay_chain")

        primary_relay_id = relay_ids[0] if relay_ids else asset_ids[0]
        crown_relay_id = relay_ids[-1] if relay_ids else primary_relay_id

        for asset_id in internet_entry_ids:
            if asset_id != primary_relay_id:
                self._add_bidirectional_edge(graph, asset_id, primary_relay_id, edge_type="internet_ingress")

        for asset_id in crown_asset_ids:
            if asset_id != crown_relay_id:
                self._add_bidirectional_edge(graph, crown_relay_id, asset_id, edge_type="crown_jewel_path")

        attached_ids = set(relay_ids) | set(internet_entry_ids) | set(crown_asset_ids)
        for index, asset_id in enumerate(asset_ids):
            if asset_id in attached_ids:
                continue
            relay_id = relay_ids[index % len(relay_ids)] if relay_ids else primary_relay_id
            self._add_bidirectional_edge(graph, relay_id, asset_id, edge_type="same_zone_lateral_movement")

        if graph.out_degree(primary_relay_id) == 0 and len(asset_ids) > 1:
            for asset_id in asset_ids:
                if asset_id != primary_relay_id:
                    self._add_bidirectional_edge(graph, primary_relay_id, asset_id, edge_type="same_zone_lateral_movement")

    def _select_zone_relays(
        self,
        asset_ids: list[str],
        *,
        asset_profiles: dict[str, dict[str, float | bool | str | None]],
        prefer_internal_relays: bool,
    ) -> list[str]:
        if prefer_internal_relays:
            pool = [
                asset_id
                for asset_id in asset_ids
                if not bool(asset_profiles[asset_id]["internet_exposed"])
                and not bool(asset_profiles[asset_id]["is_crown_jewel"])
            ]
        else:
            pool = [
                asset_id
                for asset_id in asset_ids
                if not bool(asset_profiles[asset_id]["is_crown_jewel"])
            ]
        if not pool:
            pool = list(asset_ids)

        relay_count = 2 if len(asset_ids) >= 6 and len(pool) >= 2 else 1
        return sorted(
            pool,
            key=lambda asset_id: (
                float(asset_profiles[asset_id]["relay_score"]),
                float(asset_profiles[asset_id]["criticality_score"]),
                float(asset_profiles[asset_id]["attack_path_score"]),
            ),
            reverse=True,
        )[:relay_count]

    def _identify_choke_points(
        self,
        zone_map: dict[str | None, list],
        centrality: dict[str, float],
        asset_profiles: dict[str, dict[str, float | bool | str | None]],
    ) -> set[str]:
        choke_points: list[str] = []
        for assets_in_zone in zone_map.values():
            ranked_zone_assets = sorted(
                (
                    str(asset.id)
                    for asset in assets_in_zone
                    if float(centrality.get(str(asset.id), 0.0)) > 0.0
                ),
                key=lambda asset_id: (
                    float(centrality.get(asset_id, 0.0)),
                    float(asset_profiles[asset_id]["relay_score"]),
                    float(asset_profiles[asset_id]["criticality_score"]),
                ),
                reverse=True,
            )
            if not ranked_zone_assets:
                continue
            choke_points.append(ranked_zone_assets[0])
            if (
                len(assets_in_zone) >= 8
                and len(ranked_zone_assets) > 1
                and float(centrality.get(ranked_zone_assets[1], 0.0))
                >= float(centrality.get(ranked_zone_assets[0], 0.0)) * 0.75
            ):
                choke_points.append(ranked_zone_assets[1])

        ranked_global = sorted(
            set(choke_points),
            key=lambda asset_id: (
                float(centrality.get(asset_id, 0.0)),
                float(asset_profiles[asset_id]["relay_score"]),
                float(asset_profiles[asset_id]["criticality_score"]),
            ),
            reverse=True,
        )
        return set(ranked_global[: self.MAX_CHOKE_POINTS])

    def _add_bidirectional_edge(self, graph: nx.DiGraph, source_id: str, target_id: str, *, edge_type: str) -> None:
        if not source_id or not target_id or source_id == target_id:
            return
        graph.add_edge(source_id, target_id, edge_type=edge_type)
        graph.add_edge(target_id, source_id, edge_type=edge_type)

    def _serialize_attack_surface_edges(self, graph: nx.DiGraph) -> list[dict]:
        serialized_edges: list[dict] = []
        for source_id, target_id, edge_data in graph.edges(data=True):
            serialized_edges.append(
                {
                    "id": f"{source_id}:{target_id}:{edge_data.get('edge_type', 'same_zone_lateral_movement')}",
                    "source": source_id,
                    "target": target_id,
                    "edge_type": edge_data.get("edge_type", "same_zone_lateral_movement"),
                }
            )
            if len(serialized_edges) >= self.MAX_RENDERED_ATTACK_SURFACE_EDGES:
                break
        return serialized_edges
