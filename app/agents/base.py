from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Any
from uuid import UUID

from app.services.audit_writer import AuditWriter
from app.services.errors import (
    ConfidenceBelowCeilingError,
    CrownJewelLockError,
    TenantBoundaryViolationError,
    ToolNotWhitelistedError,
)
from app.services.kill_switch import KillSwitchActiveError


@dataclass
class AgentAction:
    tool: str
    confidence: int
    tenant_id: str
    target_tier: str | None = None


@dataclass
class GraphContext:
    nodes: list[dict]
    edges: list[dict]


@dataclass
class AgentResult:
    decision: str
    confidence: int
    outcome: str


@dataclass
class PTProbe:
    session_id: str
    target_ip: str
    target_asset_id: str
    technique: str
    tool: str
    payload: str
    tenant_id: str


class BaseAgent:
    def __init__(self, tenant_id, tool_whitelist, safety_ceiling, agent_id, confidence_score: int = 85):
        self.tenant_id = tenant_id
        self.tool_whitelist = tool_whitelist
        self.safety_ceiling = safety_ceiling
        self.agent_id = agent_id
        self.confidence_score = confidence_score

    async def run(
        self,
        goal: str,
        session=None,
        tenant_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AgentResult:
        active_tenant_id = tenant_id or str(self.tenant_id)
        if session is None and self.agent_id:
            raise RuntimeError("Persisted agent runs require a database session for decision logging.")
        context = (
            await self._query_graphrag(session, goal, active_tenant_id)
            if session is not None
            else {"nodes": [], "edges": [], "query": goal}
        )
        metadata = metadata or {}
        reasoning_context = self._build_reasoning_context(goal, context, metadata)
        plan = await self._llm_plan(goal, context)

        if session is None:
            return AgentResult(
                decision=plan,
                confidence=self.confidence_score,
                outcome="completed",
            )

        max_attempts = 2
        current_plan = plan
        final_result = AgentResult(
            decision=current_plan,
            confidence=self.confidence_score,
            outcome="completed_without_execution",
        )

        for attempt in range(1, max_attempts + 1):
            action = self._select_action(goal, current_plan, metadata)
            reasoning_context["plan"] = current_plan
            reasoning_context["attempt"] = attempt
            reasoning_context["selected_tool"] = action.tool
            reasoning_context["selected_confidence"] = action.confidence

            await self._log_decision(
                session=session,
                tenant_id=active_tenant_id,
                goal=goal,
                reasoning=reasoning_context,
                decision=f"plan_attempt:{attempt}",
                confidence=action.confidence,
                outcome="plan_formed",
            )

            try:
                await self._enforce_boundaries(action)
            except PermissionError as exc:
                final_result = AgentResult(
                    decision=f"blocked:{action.tool}",
                    confidence=action.confidence,
                    outcome=str(exc),
                )
                await self._log_decision(
                    session=session,
                    tenant_id=active_tenant_id,
                    goal=goal,
                    reasoning=reasoning_context | {"boundary_error": str(exc)},
                    decision=f"blocked:{action.tool}",
                    confidence=action.confidence,
                    outcome=str(exc),
                )
                return final_result

            tool_result = await self._execute_authorized_tool(
                goal=goal,
                action=action,
                context=context,
                metadata=metadata,
                tenant_id=active_tenant_id,
            )
            evaluation = self._evaluate_tool_result(goal, action, tool_result)
            final_result = AgentResult(
                decision=evaluation["decision"],
                confidence=evaluation["confidence"],
                outcome=evaluation["outcome"],
            )
            await self._log_decision(
                session=session,
                tenant_id=active_tenant_id,
                goal=goal,
                reasoning=reasoning_context | {"observation": tool_result},
                decision=final_result.decision,
                confidence=final_result.confidence,
                outcome=final_result.outcome,
            )
            if not evaluation["replan"]:
                return final_result
            current_plan = await self._replan(goal, context, current_plan, tool_result)

        return final_result

    async def execute(
        self,
        goal: str,
        probe: PTProbe,
        kill_switch_svc,
        roe_svc,
        asset_svc,
        evidence_writer,
        session,
        tenant_id: str,
    ) -> AgentResult:
        # STEP 1 — Kill switch. First. Always. No exceptions.
        if await kill_switch_svc.is_active():
            raise KillSwitchActiveError("Kill switch active. PT halted immediately.")

        # STEP 2 — Pre-execution audit. BEFORE probe runs.
        from app.schemas.common import AuditLogCreate
        await AuditWriter().write(session, tenant_id, AuditLogCreate(
            action="pt_probe_attempt",
            resource_type="pt_session",
            resource_id=probe.session_id,
            user_id=self.agent_id,
            details={
                "goal": goal,
                "target_ip": probe.target_ip,
                "technique": probe.technique,
                "tool": probe.tool,
            },
        ))

        # STEP 3 — ROE validation
        roe = await roe_svc.assert_valid(session, probe.session_id, tenant_id)

        # STEP 4 — Scope check
        await roe_svc.assert_in_scope(probe.target_ip, roe)

        # STEP 5 — Tenant wall (hard boundary)
        if probe.tenant_id != str(self.tenant_id):
            raise TenantBoundaryViolationError(
                f"Probe tenant {probe.tenant_id} != agent tenant {self.tenant_id}"
            )

        # STEP 6 — Crown jewel lock (hard boundary)
        asset = await asset_svc.get(session, probe.target_asset_id, tenant_id)
        if getattr(asset, "crown_jewel_tier", None) == "tier_1":
            raise CrownJewelLockError(f"Asset {probe.target_asset_id} is crown jewel tier 1")

        # STEP 7 — Tool whitelist (hard boundary)
        if probe.tool not in self.tool_whitelist:
            raise ToolNotWhitelistedError(probe.tool, self.tool_whitelist)

        # STEP 8 — Confidence gate (soft boundary)
        if self.confidence_score < self.safety_ceiling:
            raise ConfidenceBelowCeilingError(self.confidence_score, self.safety_ceiling)

        # STEP 9 — Execute probe (dev: mock)
        result = await self._run_probe(probe)

        # STEP 10 — Evidence record
        await evidence_writer.write(
            session,
            session_id=probe.session_id,
            agent_id=self.agent_id,
            exploit_type=probe.technique,
            tool_used=probe.tool,
            payload=probe.payload,
            response=result.outcome,
            exploitation_confirmed=result.confidence >= 80,
            tenant_id=tenant_id,
        )

        # STEP 11 — Decision log
        await self._log_decision(
            session=session,
            tenant_id=tenant_id,
            goal=goal,
            reasoning=f"Probe executed: {probe.technique} on {probe.target_ip}",
            decision="execute_probe",
            confidence=self.confidence_score,
            outcome=result.outcome,
        )

        return result

    async def _run_probe(self, probe: PTProbe) -> AgentResult:
        from app.services.tool_runner import ToolRunner, ToolRunnerError, ToolNotAvailableError

        try:
            result = await ToolRunner().run(
                tool=probe.tool,
                target_ip=probe.target_ip,
                payload=probe.payload,
                technique=probe.technique,
            )
        except ToolNotAvailableError as exc:
            return AgentResult(
                decision=f"probe_skipped:{probe.technique}",
                confidence=0,
                outcome=f"tool_not_available:{exc}",
            )
        except ToolRunnerError as exc:
            return AgentResult(
                decision=f"probe_error:{probe.technique}",
                confidence=0,
                outcome=f"tool_error:{exc}",
            )

        outcome = (
            "exploitation_confirmed"
            if result.exploitation_confirmed
            else "probe_completed_no_exploitation_confirmed"
        )
        return AgentResult(
            decision=f"probe_executed:{probe.technique}",
            confidence=result.confidence,
            outcome=f"{outcome} | {result.summary}",
        )

    @staticmethod
    def _extract_target_ip(goal: str, metadata: dict[str, Any]) -> str | None:
        if metadata.get("target_ip"):
            return str(metadata["target_ip"])
        match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", goal)
        return match.group(0) if match else None

    @staticmethod
    def _extract_cve_id(goal: str, metadata: dict[str, Any]) -> str | None:
        if metadata.get("cve_id"):
            return str(metadata["cve_id"])
        match = re.search(r"\bCVE-\d{4}-\d{4,7}\b", goal, re.IGNORECASE)
        return match.group(0).upper() if match else None

    def _build_reasoning_context(self, goal: str, context: dict[str, Any], metadata: dict[str, Any]) -> dict[str, Any]:
        reasoning = {
            "summary": f"GraphRAG returned {len(context.get('nodes', []))} nodes and {len(context.get('edges', []))} edges.",
            "graph_query": context.get("query", goal),
        }
        for key in ("finding_id", "cve_id", "target_ip", "remediation_id"):
            value = metadata.get(key)
            if value:
                reasoning[key] = str(value)
        return reasoning

    def _select_action(self, goal: str, plan: str, metadata: dict[str, Any]) -> AgentAction:
        signal = f"{goal}\n{plan}".lower()
        ordered_tools: list[str] = []
        if self._extract_target_ip(goal, metadata):
            ordered_tools.extend(["nmap", "nessus", "qualys", "rapid7", "burp_suite"])
        if self._extract_cve_id(goal, metadata):
            ordered_tools.extend(["nvd_lookup", "nessus", "qualys"])
        if "compliance" in signal:
            ordered_tools.extend(["compliance_mapper", "graphrag_query"])
        if "graph" in signal or "attack path" in signal or "choke" in signal:
            ordered_tools.extend(["graphrag_query", "attack_graph_query"])
        if "patch" in signal or "deploy" in signal or "remed" in signal:
            ordered_tools.extend(["tanium_patch", "servicenow_ticket", "jira_ticket"])
        if "code" in signal or "sast" in signal:
            ordered_tools.extend(["checkmarx", "sonarqube", "veracode", "snyk"])

        ordered_tools.extend(self.tool_whitelist)
        for tool in ordered_tools:
            if tool in self.tool_whitelist:
                confidence = self.confidence_score
                if tool == "tanium_patch":
                    confidence = min(confidence, self.safety_ceiling - 1)
                return AgentAction(tool=tool, confidence=confidence, tenant_id=str(self.tenant_id))
        return AgentAction(tool=self.tool_whitelist[0], confidence=self.confidence_score, tenant_id=str(self.tenant_id))

    async def _execute_authorized_tool(
        self,
        *,
        goal: str,
        action: AgentAction,
        context: dict[str, Any],
        metadata: dict[str, Any],
        tenant_id: str,
    ) -> dict[str, Any]:
        target_ip = self._extract_target_ip(goal, metadata)
        cve_id = self._extract_cve_id(goal, metadata)
        if action.tool in {"graphrag_query", "attack_graph_query"}:
            return {
                "tool": action.tool,
                "status": "completed",
                "summary": f"Graph query returned {len(context.get('nodes', []))} nodes and {len(context.get('edges', []))} edges.",
            }
        if action.tool == "nvd_lookup":
            if not cve_id:
                return {"tool": action.tool, "status": "replan_required", "summary": "No CVE identifier found in goal."}
            try:
                from app.services.nvd_client import NvdClient

                class _NullRedis:
                    async def get(self, key):
                        return None

                    async def set(self, key, value, ex=None):
                        return None

                payload = await NvdClient(_NullRedis()).fetch(cve_id)
                return {
                    "tool": action.tool,
                    "status": "completed",
                    "summary": f"NVD lookup completed for {cve_id}.",
                    "raw": payload,
                }
            except Exception as exc:
                return {"tool": action.tool, "status": "replan_required", "summary": f"NVD lookup failed: {exc}"}
        if action.tool == "compliance_mapper":
            return {
                "tool": action.tool,
                "status": "completed",
                "summary": f"Compliance context available for tenant {tenant_id}.",
            }
        if action.tool in {"tanium_patch", "servicenow_ticket", "jira_ticket"}:
            return {
                "tool": action.tool,
                "status": "human_approval_required",
                "summary": f"{action.tool} is destructive or workflow-changing and requires human authorisation.",
            }
        if action.tool in {"nmap", "burp_suite", "snyk", "nessus", "qualys", "checkmarx", "sonarqube", "rapid7", "veracode"}:
            if not target_ip:
                return {
                    "tool": action.tool,
                    "status": "replan_required",
                    "summary": "No target IP was provided for the selected tool.",
                }
            if action.tool == "nmap":
                from app.services.tool_runner import ToolRunner, ToolNotAvailableError, ToolRunnerError

                try:
                    result = await ToolRunner().run(tool="nmap", target_ip=target_ip, payload="", technique="discovery")
                    return {
                        "tool": action.tool,
                        "status": "completed",
                        "summary": result.summary,
                        "findings": result.findings,
                        "confidence": result.confidence,
                    }
                except (ToolNotAvailableError, ToolRunnerError) as exc:
                    return {"tool": action.tool, "status": "replan_required", "summary": str(exc)}
            return {
                "tool": action.tool,
                "status": "completed",
                "summary": f"{action.tool} authorised for {target_ip}; integration execution delegated to provider workflow.",
            }
        return {"tool": action.tool, "status": "replan_required", "summary": "No executor available for selected tool."}

    def _evaluate_tool_result(self, goal: str, action: AgentAction, tool_result: dict[str, Any]) -> dict[str, Any]:
        status = tool_result.get("status", "unknown")
        if status == "completed":
            return {
                "decision": f"execute:{action.tool}",
                "confidence": int(tool_result.get("confidence", action.confidence)),
                "outcome": tool_result.get("summary", "completed"),
                "replan": False,
            }
        if status == "human_approval_required":
            return {
                "decision": f"surface_to_human:{action.tool}",
                "confidence": action.confidence,
                "outcome": tool_result.get("summary", "human approval required"),
                "replan": False,
            }
        return {
            "decision": f"replan:{action.tool}",
            "confidence": max(0, action.confidence - 10),
            "outcome": tool_result.get("summary", "replanning required"),
            "replan": True,
        }

    async def _replan(self, goal: str, context: dict[str, Any], current_plan: str, tool_result: dict[str, Any]) -> str:
        observation = tool_result.get("summary", "no observation")
        refined_goal = f"{goal}\nPrevious plan: {current_plan}\nObservation: {observation}\nReplan using another authorised tool."
        return await self._llm_plan(refined_goal, context)

    async def _query_graphrag(self, session, context_query: str, tenant_id: str) -> dict:
        from app.services.graphrag import GraphRAGService

        return await GraphRAGService().query_context(session, context_query, tenant_id)

    async def _llm_plan(self, goal: str, context: dict) -> str:
        import json

        import httpx

        from app.config import get_settings

        settings = get_settings()
        api_key = settings.openai_api_key
        if not api_key or api_key in ("placeholder", ""):
            return self._form_plan(goal, context)

        nodes = context.get("nodes", [])
        edges = context.get("edges", [])
        crown_jewels = [n for n in nodes if n.get("is_crown_jewel")]
        choke_points = [n for n in nodes if n.get("is_choke_point")]
        avg_centrality = round(
            sum(float(n.get("centrality_score", 0.0)) for n in nodes) / max(len(nodes), 1) * 100, 2
        )

        system_prompt = (
            f"You are a cybersecurity AI agent. Your available tools: {self.tool_whitelist}.\n"
            f"Attack graph: {len(nodes)} nodes, {len(edges)} edges.\n"
            f"Crown jewels ({len(crown_jewels)}): {json.dumps([n['asset_id'] for n in crown_jewels[:10]])}\n"
            f"Choke points ({len(choke_points)}): {json.dumps([n['asset_id'] for n in choke_points[:10]])}\n"
            f"Average centrality score: {avg_centrality}\n"
            "Produce a concise, actionable security plan referencing specific assets, "
            "tools from your whitelist, and prioritization rationale."
        )

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                base_url = settings.openai_base_url.rstrip("/")
                endpoints = (
                    [f"{base_url}/chat/completions"]
                    if base_url.endswith("/v1")
                    else [f"{base_url}/v1/chat/completions", f"{base_url}/chat/completions"]
                )
                for endpoint in endpoints:
                    try:
                        response = await client.post(
                            endpoint,
                            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                            json={
                                "model": settings.openai_model,
                                "messages": [
                                    {"role": "system", "content": system_prompt},
                                    {"role": "user", "content": goal},
                                ],
                                "max_tokens": 2000,
                                "temperature": 0.3,
                                "stream": False,
                            },
                        )
                        response.raise_for_status()
                        return response.json()["choices"][0]["message"]["content"].strip()
                    except Exception:
                        continue
        except Exception:
            pass
        return self._form_plan(goal, context)

    def _form_plan(self, goal: str, context: dict) -> str:
        node_count = len(context.get("nodes", []))
        nodes = context.get("nodes", [])
        crown_jewels = [node for node in nodes if node.get("is_crown_jewel")]
        choke_points = [node for node in nodes if node.get("is_choke_point")]
        avg_centrality = round(
            (sum(float(node.get("centrality_score", 0.0)) for node in nodes) / node_count) * 100,
            2,
        ) if node_count else 0.0
        goal_lower = goal.lower()

        if "score" in goal_lower:
            return (
                f"Graph score: {avg_centrality}. "
                f"Observed {node_count} nodes, {len(choke_points)} choke points, and {len(crown_jewels)} crown jewels."
            )
        if "crown jewel" in goal_lower:
            return f"Graph contains {len(crown_jewels)} crown jewels across {node_count} nodes."
        if "choke" in goal_lower:
            return f"Graph contains {len(choke_points)} choke points across {node_count} nodes."
        return (
            f"Goal: {goal}. "
            f"Graph summary: {node_count} nodes, {len(choke_points)} choke points, "
            f"{len(crown_jewels)} crown jewels, average graph score {avg_centrality}."
        )

    async def _log_decision(
        self,
        session,
        tenant_id: str,
        goal: str,
        reasoning,
        decision: str,
        confidence: int,
        outcome: str,
    ):
        # Ad hoc PT probes can run without a persisted Agent row.
        if not self.agent_id:
            return
        from app.models.entities import AgentDecision
        reasoning_chain = reasoning if isinstance(reasoning, dict) else {"summary": str(reasoning)}
        entry = AgentDecision(
            agent_id=UUID(str(self.agent_id)),
            tenant_id=UUID(str(tenant_id)),
            goal=goal,
            reasoning_chain=reasoning_chain,
            decision=decision,
            confidence_score=confidence,
            outcome=outcome,
            created_at=datetime.now(timezone.utc),
        )
        session.add(entry)
        await session.flush()

    async def _enforce_boundaries(self, action: AgentAction) -> None:
        if action.tool not in self.tool_whitelist:
            raise PermissionError("Tool not in whitelist.")
        if action.confidence < self.safety_ceiling:
            raise PermissionError("Confidence below safety ceiling.")
        if action.tenant_id != str(self.tenant_id):
            raise PermissionError("Tenant mismatch.")
        if action.target_tier == "tier_1":
            raise PermissionError("Crown jewel tier 1 actions are blocked.")
        if action.tool == "tanium_patch":
            raise PermissionError("Destructive approval required before patch execution.")
