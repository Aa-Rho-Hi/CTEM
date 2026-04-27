from uuid import UUID

from sqlalchemy import select

from app.models.entities import AgentDecision, AttackGraphEdge, AttackGraphNode
from app.schemas.common import AuditLogCreate
from app.services.audit_writer import AuditWriter


class GraphRAGService:
    async def query_context(self, session, context_query: str, tenant_id: str) -> dict:
        tenant_uuid = UUID(str(tenant_id))
        nodes = (
            await session.execute(
                select(AttackGraphNode).where(AttackGraphNode.tenant_id == tenant_uuid)
            )
        ).scalars().all()
        edges = (
            await session.execute(
                select(AttackGraphEdge).where(AttackGraphEdge.tenant_id == tenant_uuid)
            )
        ).scalars().all()
        return {
            "nodes": [
                {
                    "id": str(node.id),
                    "asset_id": node.reference_id,
                    "node_type": node.node_type,
                    "is_crown_jewel": bool(node.attributes.get("crown_jewel_tier_id")),
                    "is_choke_point": node.is_choke_point,
                    "centrality_score": node.centrality_score,
                }
                for node in nodes
            ],
            "edges": [
                {
                    "source": str(edge.from_node_id),
                    "target": str(edge.to_node_id),
                    "edge_type": edge.edge_type,
                    "weight": edge.attributes.get("weight", 1.0),
                }
                for edge in edges
            ],
            "query": context_query,
        }

    async def record_approval(
        self,
        session,
        finding_id: str,
        remediation_id: str,
        approver_id: str,
        tenant_id: str,
    ) -> None:
        finding_node = await self._get_or_create_node(session, tenant_id, "finding", finding_id)
        approver_node = await self._get_or_create_node(session, tenant_id, "user", approver_id)
        session.add(
            AttackGraphEdge(
                tenant_id=tenant_id,
                from_node_id=finding_node.id,
                to_node_id=approver_node.id,
                edge_type="approval",
                attributes={"remediation_id": remediation_id, "weight": 1.0},
            )
        )

        decisions = await self._load_decisions_for_finding(session, tenant_id, finding_id)
        for decision in decisions:
            current = 0.5 if decision.confidence_score is None else float(decision.confidence_score)
            decision.confidence_score = min(1.0, current + 0.05)

        await AuditWriter().write(
            session,
            tenant_id,
            AuditLogCreate(
                action="graphrag_approval_edge_written",
                resource_type="remediation",
                resource_id=remediation_id,
                details={"finding_id": finding_id, "approver_id": approver_id},
            ),
        )

    async def record_rejection(
        self,
        session,
        finding_id: str,
        remediation_id: str,
        approver_id: str,
        reason: str,
        tenant_id: str,
    ) -> None:
        finding_node = await self._get_or_create_node(session, tenant_id, "finding", finding_id)
        approver_node = await self._get_or_create_node(session, tenant_id, "user", approver_id)
        session.add(
            AttackGraphEdge(
                tenant_id=tenant_id,
                from_node_id=finding_node.id,
                to_node_id=approver_node.id,
                edge_type="rejection",
                attributes={"remediation_id": remediation_id, "reason": reason, "weight": -1.0},
            )
        )

        decisions = await self._load_decisions_for_finding(session, tenant_id, finding_id)
        for decision in decisions:
            current = 0.5 if decision.confidence_score is None else float(decision.confidence_score)
            decision.confidence_score = max(0.0, current - 0.1)

        await AuditWriter().write(
            session,
            tenant_id,
            AuditLogCreate(
                action="graphrag_rejection_edge_written",
                resource_type="remediation",
                resource_id=remediation_id,
                details={"finding_id": finding_id, "approver_id": approver_id, "reason": reason},
            ),
        )

    async def _get_or_create_node(self, session, tenant_id: str, node_type: str, reference_id: str) -> AttackGraphNode:
        tenant_uuid = UUID(str(tenant_id))
        node = (
            await session.execute(
                select(AttackGraphNode).where(
                    AttackGraphNode.tenant_id == tenant_uuid,
                    AttackGraphNode.node_type == node_type,
                    AttackGraphNode.reference_id == reference_id,
                )
            )
        ).scalar_one_or_none()
        if node is not None:
            return node
        node = AttackGraphNode(
            tenant_id=tenant_uuid,
            node_type=node_type,
            reference_id=reference_id,
            is_choke_point=False,
            centrality_score=0.0,
            attributes={},
        )
        session.add(node)
        await session.flush()
        return node

    async def _load_decisions_for_finding(self, session, tenant_id: str, finding_id: str) -> list[AgentDecision]:
        statement = select(AgentDecision).where(
            AgentDecision.tenant_id == UUID(str(tenant_id)),
        )
        decisions = (await session.execute(statement)).scalars().all()
        matched = [
            decision
            for decision in decisions
            if (
                (decision.reasoning_chain or {}).get("finding_id") == finding_id
                or (decision.reasoning_chain or {}).get("remediation_id") == finding_id
                or finding_id in (decision.goal or "")
                or finding_id in str((decision.reasoning_chain or {}).get("summary", ""))
            )
        ]
        return matched
