# ATLAS-CTEM Requirements Audit

Audit date: 2026-04-06

Legend:

- `Done`: implemented in the current codebase with no major gap found during this review
- `Partial`: implemented in part, stubbed, semantically weak, or incorrect in an important edge/path
- `Missing`: no meaningful implementation found
- `Unverifiable`: cannot be proven from static code review alone

This is a code-level audit, not a runtime certification. Performance, demo UX, and infrastructure behavior can still differ from what the code suggests.

Count note:

- The source document's summary counts do not match the requirement IDs actually listed in the body.
- IDs present in the pasted document total `108`, not `111`:
- `7` business requirements
- `24` user requirements
- `55` functional requirements
- `22` non-functional requirements

## Business Requirements

| ID | Status | Evidence | Note |
| --- | --- | --- | --- |
| BR-1 | Partial | `app/routes/discover.py:78-140`; `app/routes/prioritize.py:76-309`; `app/routes/dashboard.py:14-59` | Continuous visibility exists, but updates are async/cache-based rather than provably real-time. |
| BR-2 | Partial | `app/services/risk_engine.py:95-262`; `app/routes/dashboard.py:37-50` | Risk is translated into business impact and dollar heuristics, but not full financial exposure by business grouping. |
| BR-3 | Partial | `app/tasks/remediation_exec.py:109-192`; `app/services/audit_writer.py:9-40`; `app/services/scanner_service.py:76-113` | Evidence chain exists, but verified closure is deferred in development and rescans are partly stubbed. |
| BR-4 | Partial | `app/routes/compliance.py:12-114`; `app/tasks/compliance_update.py:19-54`; `app/routes/dashboard.py:53-59` | Live posture exists, but persisted compliance scoring is incorrect and can misstate posture. |
| BR-5 | Done | `app/services/approval_service.py:53-154`; `app/services/tanium.py:18-68`; `app/agents/base.py:166-237` | Human approval is enforced before patch execution and PT is bounded by ROE and kill switch controls. |
| BR-6 | Done | `app/models/base.py:67-99`; `app/core/tenant_middleware.py:11-36` | Tenant scoping is enforced on selects and writes at the ORM/session layer. |
| BR-7 | Partial | `app/routes/integrations.py:71-200`; `app/services/itsm.py:16-92`; `app/services/tanium.py:18-68` | ITSM, endpoint, scanner, and SIEM hooks exist, but coverage is uneven and cloud-provider integration is generic. |

## User Requirements

### Security Analyst

| ID | Status | Evidence | Note |
| --- | --- | --- | --- |
| UR-SA-01 | Partial | `app/schemas/discover.py:6-9`; `app/routes/discover.py:78-84`; `app/tasks/scan_pipeline.py:997-1088` | Nine tools are declared and dispatch exists, but several tool paths are generic bridge calls or mocks. |
| UR-SA-02 | Done | `app/routes/discover.py:87-100`; `app/tasks/scan_pipeline.py:267-301` | Upload flow accepts and normalizes `.nessus`, `.xml`, `.json`, and `.csv`. |
| UR-SA-03 | Done | `app/routes/prioritize.py:76-212` | Findings list is filterable and includes severity, risk, asset, status, and source tool. |
| UR-SA-04 | Done | `app/routes/mobilize.py:55-93`; `app/services/remediation_service.py:21-72` | Remediation plan includes fix steps, rollback, business impact, and compliance impact. |
| UR-SA-05 | Partial | `app/routes/prioritize.py:286-323`; `app/services/attack_graph.py:174-332`; `app/routes/prioritize.py:224-274` | Attack surface map exists, but finding detail currently returns an empty `attack_paths` list. |
| UR-SA-06 | Partial | `app/routes/remediation.py:59-75`; `app/tasks/remediation_exec.py:128-192`; `app/services/scanner_service.py:76-113` | Re-scan/verify workflow exists, but targeted verification is unavailable in development. |
| UR-SA-07 | Done | `app/routes/kill_switch.py:18-46`; `app/services/kill_switch.py:21-54` | Analyst can view kill switch status and activate it to halt PT. |

### Approver

| ID | Status | Evidence | Note |
| --- | --- | --- | --- |
| UR-AP-01 | Done | `app/routes/mobilize.py:96-133` | Approval queue endpoint exists and returns queued remediations. |
| UR-AP-02 | Done | `app/routes/mobilize.py:136-155`; `app/routes/mobilize.py:18-52` | Full remediation plan details are available for review. |
| UR-AP-03 | Done | `app/services/blast_radius.py:33-61`; `app/routes/mobilize.py:84-85` | Blast radius analysis is computed and attached to remediation review. |
| UR-AP-04 | Partial | `app/services/dry_run.py:18-79`; `app/routes/mobilize.py:84-85` | Dry-run output exists, but it is canned simulation rather than exact change preview. |
| UR-AP-05 | Partial | `app/routes/mobilize.py:158-167`; `app/services/approval_service.py:53-154` | Reject requires a reason; approve does not capture a written rationale. |
| UR-AP-06 | Done | `app/routes/roe.py:23-43`; `app/routes/validate.py:71-103` | ROE authorization is required before PT session creation. |

### CISO / Security Leadership

| ID | Status | Evidence | Note |
| --- | --- | --- | --- |
| UR-CL-01 | Done | `app/routes/dashboard.py:14-20` | Single exposure score endpoint exists. |
| UR-CL-02 | Partial | `app/routes/dashboard.py:23-34` | Trend endpoint exists, but period handling is generic and not explicitly shaped to 7-day through 12-month reporting. |
| UR-CL-03 | Partial | `app/routes/dashboard.py:37-50` | Dollarized risk exists by severity tier only, not by asset group. |
| UR-CL-04 | Partial | `app/routes/dashboard.py:53-59`; `app/tasks/compliance_update.py:19-54` | Compliance percentage view exists, but persisted score math is wrong. |
| UR-CL-05 | Partial | `app/routes/prioritize.py:286-323`; `app/services/attack_graph.py:174-332` | Zone visibility exists; business-unit modeling is not present. |

### Platform Administrator

| ID | Status | Evidence | Note |
| --- | --- | --- | --- |
| UR-AD-01 | Done | `app/routes/auth.py:23-53`; `app/routes/users.py`; `frontend/src/app/(app)/settings/users/page.tsx` | Admin can create, edit, activate, deactivate, and re-role accounts from the application. |
| UR-AD-02 | Done | `app/routes/integrations.py`; `frontend/src/app/(app)/settings/integrations/page.tsx` | Integration management now exposes explicit tool catalog metadata and required ITS / platform-specific configuration fields. |
| UR-AD-03 | Missing | `app/routes/llm_config.py:100-164`; `app/config.py:17-42` | No route was found to switch active provider or manage credentials at runtime; config is env-driven and OpenAI-centric. |
| UR-AD-04 | Partial | `app/routes/agents.py:131-179`; `app/agents/catalog.py:4-30` | Admin can create agents with tools, safety ceiling, schedule, and trigger, but the catalog is narrower than the requirements imply. |
| UR-AD-05 | Done | `app/routes/agents.py:226-256` | Agents can be decommissioned without deletion while preserving configuration and history. |
| UR-AD-06 | Done | `app/routes/audit.py:53-96` | Audit log supports filtering by user, action, and date range. |

## Functional Requirements

### FR-1 Scope

| ID | Status | Evidence | Note |
| --- | --- | --- | --- |
| FR-SC-01 | Done | `app/routes/scope.py:58-70`; `app/services/scope_service.py:61-74` | Zones use CIDR and assets are auto-assigned by IP. |
| FR-SC-02 | Done | `app/services/scope_service.py:7-26`; `app/routes/scope.py:73-89`; `app/routes/scope.py:184-199` | Three crown-jewel tiers exist with revenue tier and data sensitivity fields. |
| FR-SC-03 | Done | `app/routes/scope.py:134-177`; `app/models/entities.py:78-87` | Business context supports industry, annual revenue, and applicable frameworks. |
| FR-SC-04 | Done | `app/routes/scope.py:171-176`; `app/services/scope_service.py:28-58` | Applicable frameworks are derived automatically from industry sector. |
| FR-SC-05 | Done | `app/routes/scope.py:202-209`; `app/services/change_window.py:13-27`; `app/services/tanium.py:40-43` | Zone-level change windows can be configured and enforced before execution. |

### FR-2 Discover

| ID | Status | Evidence | Note |
| --- | --- | --- | --- |
| FR-DI-01 | Partial | `app/schemas/discover.py:6-9`; `app/tasks/scan_pipeline.py:1045-1046` | All nine scanners are declared, but some integrations are generic HTTP bridges or mocks. |
| FR-DI-02 | Done | `app/routes/discover.py:87-100`; `app/tasks/scan_pipeline.py:267-301` | Passive uploads flow into the same normalization pipeline. |
| FR-DI-03 | Done | `app/schemas/discover.py:12-20`; `app/tasks/scan_pipeline.py:798-968` | Findings are normalized into a unified schema. |
| FR-DI-04 | Done | `app/services/deduplicator.py:9-70` | SHA-256 fingerprinting and 30-day dedup window are implemented. |
| FR-DI-05 | Done | `app/services/confidence_service.py:20-63` | Confidence uses source reliability, completeness, freshness, and consistency. |
| FR-DI-06 | Partial | `app/routes/discover.py:34-75`; `app/routes/discover.py:134-140`; `app/tasks/scan_pipeline.py:664-691` | External discovery exists, including CT-like and enumeration inputs, but daily scheduling is not proven here. |
| FR-DI-07 | Done | `app/services/discover_service.py:107-125`; `app/tasks/scan_pipeline.py:677-681` | Shadow asset detection compares cloud resources against known assets. |

### FR-3 Prioritize

| ID | Status | Evidence | Note |
| --- | --- | --- | --- |
| FR-PR-01 | Done | `app/services/risk_engine.py:184-262`; `app/tasks/risk_scoring.py:67-106` | Composite 0-100 scoring uses CVSS, EPSS, KEV, exploitability, and asset context. |
| FR-PR-02 | Partial | `app/services/risk_engine.py:20-28`; `app/services/risk_engine.py:247-251` | Crown-jewel multipliers exist, but the exact revenue-tier multiplier behavior differs from the requirement wording. |
| FR-PR-03 | Done | `app/tasks/risk_scoring.py:60-66`; `app/services/nvd_client.py:62-118` | CVSS vector, EPSS, and KEV enrichment are applied from NVD-backed fetches. |
| FR-PR-04 | Done | `app/services/nvd_client.py:75-118` | Redis caching uses a 24-hour TTL. |
| FR-PR-05 | Partial | `app/services/attack_graph.py:10-32`; `app/services/attack_graph.py:34-71` | Directed graph exists, but edges are modeled as same-zone lateral-movement cliques rather than realistic attack paths. |
| FR-PR-06 | Done | `app/services/attack_graph.py:30-32`; `app/routes/prioritize.py:277-283` | Betweenness centrality and choke-point surfacing are implemented. |
| FR-PR-07 | Done | `app/services/threat_actor.py:6-29`; `app/tasks/risk_scoring.py:121-125` | Threat actor campaign mapping and risk bonus are implemented. |
| FR-PR-08 | Done | `app/services/risk_engine.py:264-315` | False-positive scoring uses four factors and auto-closes above `0.85`. |
| FR-PR-09 | Done | `app/services/risk_engine.py:37-45` | SLA tiers map to 1/7/30/90 day buckets by risk score. |

### FR-4 Validate

| ID | Status | Evidence | Note |
| --- | --- | --- | --- |
| FR-VA-01 | Done | `app/services/validation_service.py:7-42` | EPSS, KEV, Exploit-DB, and threat-actor matches are auto-validation signals. |
| FR-VA-02 | Done | `app/routes/roe.py:23-43`; `app/routes/validate.py:71-103` | PT session creation requires active ROE. |
| FR-VA-03 | Done | `app/agents/base.py:185-190`; `app/services/roe_service.py` | PT probes are checked against authorized CIDR before execution. |
| FR-VA-04 | Done | `app/services/kill_switch.py:21-54` | Kill switch fails closed when Redis errors occur. |
| FR-VA-05 | Done | `app/agents/base.py:170-183` | PT actions are pre-logged before execution. |
| FR-VA-06 | Done | `app/services/evidence_writer.py:6-43`; `app/routes/validate.py:164-182` | Evidence record captures exploit type, tool, payload, response, and confirmation state. |

### FR-5 Mobilize

| ID | Status | Evidence | Note |
| --- | --- | --- | --- |
| FR-MO-01 | Partial | `app/services/remediation_service.py:21-72`; `app/services/llm_router.py:192-221` | AI remediation plans exist with the required fields, but provider configuration is narrower than the requirement set. |
| FR-MO-02 | Done | `app/services/llm_router.py:11-48`; `app/services/llm_router.py:74-79` | Static fallback templates exist for patch, configuration, code, and manual. |
| FR-MO-03 | Missing | `app/services/approval_service.py:17-51` | All remediations are routed to `awaiting_approval`; Low/Medium auto-approval is not implemented. |
| FR-MO-04 | Done | `app/services/blast_radius.py:33-61` | Blast radius calculates downstream dependencies and crown-jewel exposure. |
| FR-MO-05 | Partial | `app/services/dry_run.py:18-79` | Dry-run output is simulated, not an exact change plan. |
| FR-MO-06 | Done | `app/services/change_window.py:13-27`; `app/routes/remediation.py:32-38` | Execution is blocked during protected change windows. |
| FR-MO-07 | Done | `app/services/itsm.py:16-92`; `app/services/approval_service.py:100-102` | Approval triggers ServiceNow or Jira ticket creation with pre-populated fields. |

### FR-6 Auto-Remediation Execution

| ID | Status | Evidence | Note |
| --- | --- | --- | --- |
| FR-AR-01 | Done | `app/services/tanium.py:18-68` | Tanium patch execution requires explicit approval and approval audit presence. |
| FR-AR-02 | Done | `app/models/entities.py:19-27`; `app/routes/remediation.py:39-45`; `app/tasks/remediation_exec.py:67-72` | Remediation status transitions are tracked across the required lifecycle. |
| FR-AR-03 | Done | `app/tasks/remediation_exec.py:73`; `app/tasks/remediation_exec.py:128-133` | Post-execution verification triggers targeted re-scan logic. |
| FR-AR-04 | Partial | `app/tasks/remediation_exec.py:156-189`; `app/services/scanner_service.py:76-113` | Verified closure is only set on clean rescan, but real verification is unavailable in development. |
| FR-AR-05 | Partial | `app/tasks/remediation_exec.py:157-173`; `app/services/audit_writer.py:15-40` | Verification audit fields are written, but full end-to-end verified closure is not consistently reachable. |

### FR-7 Agentic AI

| ID | Status | Evidence | Note |
| --- | --- | --- | --- |
| FR-AI-01 | Done | `app/agents/base.py:57-153`; `app/agents/base.py:430-559` | Goal-driven GraphRAG -> plan -> execute -> evaluate -> replan loop exists. |
| FR-AI-02 | Done | `app/agents/base.py:98-148`; `app/models/entities.py:318-327` | Agent decisions are persisted with goal, reasoning, decision, confidence, and outcome. |
| FR-AI-03 | Done | `app/agents/base.py:551-560`; `app/agents/base.py:191-208` | Tool whitelist, safety ceiling, tenant wall, and crown-jewel lock are enforced. |
| FR-AI-04 | Done | `app/agents/base.py:554-560`; `app/services/tanium.py:22-37` | Confidence gate and destructive approval boundaries are implemented. |
| FR-AI-05 | Partial | `app/agents/catalog.py:4-30`; `app/routes/agents.py:131-179` | Admin can build agents from platform tools, but the exposed catalog is smaller than the requirement implies. |
| FR-AI-06 | Done | `app/routes/agents.py:226-256` | Decommission preserves config/history and writes audit events. |
| FR-AI-07 | Done | `app/services/graphrag.py:47-118`; `app/services/approval_service.py:92-99`; `app/services/approval_service.py:144-152` | Approval and rejection decisions write graph edges and adjust confidence. |

### FR-8 Compliance

| ID | Status | Evidence | Note |
| --- | --- | --- | --- |
| FR-CO-01 | Partial | `app/services/compliance_mapper.py:20-135`; `app/tasks/risk_scoring.py:126-130` | Mapping uses NVD-derived fields like CWE, but the logic is mostly heuristic rather than NVD-primary end-to-end. |
| FR-CO-02 | Done | `app/services/compliance_mapper.py:6-17` | All 10 frameworks are declared. |
| FR-CO-03 | Partial | `app/routes/compliance.py:12-114`; `app/tasks/compliance_update.py:19-54` | Compliance updates exist on scan/verification paths, but persisted score calculation is incorrect. |
| FR-CO-04 | Partial | `app/services/compliance_mapper.py:63-71`; `app/services/compliance_mapper.py:123-135` | PCI and HIPAA are zone-scoped, but broader zone scoping behavior is limited. |

### FR-9 Audit and Security

| ID | Status | Evidence | Note |
| --- | --- | --- | --- |
| FR-AS-01 | Partial | `app/models/base.py:85-99`; `app/services/audit_writer.py:9-40` | App-layer immutability and tamper-evident signatures exist, but DB-layer immutability was not found. |
| FR-AS-02 | Done | `app/models/base.py:67-82`; `app/models/base.py:85-93`; `app/core/tenant_middleware.py:20-36` | Tenant scoping is enforced structurally at middleware and ORM query layers. |
| FR-AS-03 | Done | `app/core/tenant_middleware.py:12-28` | JWT is required for all routes except explicit exempt paths. |
| FR-AS-04 | Done | `app/models/entities.py:11-17`; `app/core/security.py:84-97`; route-level `require_roles(...)` usage across `app/routes` | The five defined roles are modeled and enforced on routes. |
| FR-AS-05 | Done | `app/agents/base.py:170-183` | PT activity is pre-logged before execution. |

## Non-Functional Requirements

### NFR-1 Performance

| ID | Status | Evidence | Note |
| --- | --- | --- | --- |
| NFR-PE-01 | Unverifiable | `app/routes/health.py:12-25`; `app/services/health.py:9-27` | Health endpoint exists, but `<200ms` cannot be proven from static review. |
| NFR-PE-02 | Unverifiable | `app/services/nvd_client.py:75-118` | Redis caching exists, but 2ms/500ms latency targets require runtime measurement. |
| NFR-PE-03 | Unverifiable | `app/routes/mobilize.py:96-133` | Queue endpoint supports up to 1000 items, but `<3s` load time was not benchmarked here. |
| NFR-PE-04 | Done | `app/routes/discover.py:78-100`; `app/tasks/scan_pipeline.py:997-1088` | Active scans are queued through Celery tasks so the API returns quickly. |
| NFR-PE-05 | Done | `app/tasks/scan_pipeline.py:42`; `app/tasks/scan_pipeline.py:878-944` | Bulk finding inserts flush in batches of 1000. |

### NFR-2 Scalability

| ID | Status | Evidence | Note |
| --- | --- | --- | --- |
| NFR-SC-01 | Done | `k8s/api-hpa.yaml` | API HPA manifest sets 2-10 replicas at 70% CPU. |
| NFR-SC-02 | Done | `k8s/worker-hpa.yaml` | Worker HPA manifest sets 2-20 replicas at 60% CPU. |
| NFR-SC-03 | Done | `app/models/entities.py:147-161` | Vulnerabilities table defines 13 indexes matching the stated requirement count. |

### NFR-3 Reliability

| ID | Status | Evidence | Note |
| --- | --- | --- | --- |
| NFR-RE-01 | Done | `app/services/kill_switch.py:21-25`; `app/services/kill_switch.py:49-54` | Kill switch fails closed when Redis is unreachable. |
| NFR-RE-02 | Done | `app/services/llm_router.py:11-48`; `app/services/llm_router.py:216-221` | Static fallback behavior prevents LLM failure from breaking remediation planning. |
| NFR-RE-03 | Done | `app/tasks/compliance_update.py:64-72`; `app/tasks/risk_scoring.py:197-206`; `app/tasks/remediation_exec.py:34-49`; `app/tasks/remediation_exec.py:102-104`; `app/tasks/remediation_exec.py:194-197` | Celery tasks are capped at 3 retries with exponential backoff behavior. |

### NFR-4 Security

| ID | Status | Evidence | Note |
| --- | --- | --- | --- |
| NFR-SE-01 | Done | `app/config.py:11-18`; `app/config.py:44-58` | JWT secret is env-configured and has no default value in code. |
| NFR-SE-02 | Done | `app/routes/integrations.py:83-88`; `app/routes/integrations.py:131-132`; `app/models/entities.py:41`; `app/models/entities.py:379` | API keys are persisted as SHA-256 hashes rather than plaintext. |
| NFR-SE-03 | Partial | `app/services/tanium.py:61-67`; `app/routes/integrations.py:164-165`; `app/tasks/scan_pipeline.py:394`; `app/services/splunk.py:21-27` | TLS verification is mostly enabled, but not every outbound path is explicit and object storage integration was not found. |
| NFR-SE-04 | Partial | `app/tasks/scan_pipeline.py:103-127`; `app/services/tool_runner.py:40-78`; `app/routes/validate.py:113-116` | Input validation is strong in many subprocess paths, but not every external-tool invocation was exhaustively proven. |
| NFR-SE-05 | Done | `.gitignore:8` | `.env` is excluded from version control. |

### NFR-5 Observability

| ID | Status | Evidence | Note |
| --- | --- | --- | --- |
| NFR-OB-01 | Partial | `app/core/logging.py:1-17`; `app/tasks/risk_scoring.py:107-119` | JSON logging is configured, but there are still raw debug `print(...)` statements. |
| NFR-OB-02 | Partial | `app/routes/health.py:12-25`; `app/services/health.py:9-27` | Health reports database, Redis, and queue depth, but not full worker liveness. |
| NFR-OB-03 | Done | `app/agents/base.py:98-148`; `app/models/entities.py:318-327` | Agent decisions are persisted to `agent_decisions`. |

### NFR-6 Maintainability

| ID | Status | Evidence | Note |
| --- | --- | --- | --- |
| NFR-MA-01 | Done | `alembic.ini`; `migrations/versions/*` | Schema changes are tracked through Alembic migrations. |
| NFR-MA-02 | Partial | `app/agents/base.py:49-153`; `app/agents/catalog.py:68-99` | Existing agents follow a common base structure, but the requirement is about future classes and cannot be fully guaranteed here. |
| NFR-MA-03 | Partial | route patterns across `app/routes/*` | Most routes follow a shared pattern, but error formatting and middleware usage are not perfectly uniform everywhere. |

## Highest-Impact Gaps

These are the gaps most worth fixing first if the goal is to make the platform match the document more credibly:

1. Compliance score correctness
   `app/tasks/compliance_update.py:19-54`
   Stored compliance percentages are wrong because they count closed mappings instead of passing controls.
2. Approval routing
   `app/services/approval_service.py:17-51`
   Low and Medium remediations are not auto-approved.
3. Verification credibility
   `app/services/scanner_service.py:76-113`
   Development verification is explicitly unavailable, which blocks true verified-closure demos.
4. Dry-run fidelity
   `app/services/dry_run.py:18-79`
   Dry-run output is placeholder simulation, not a precise change preview.
5. Attack path semantics
   `app/services/attack_graph.py:23-32`; `app/services/attack_graph.py:302-324`
   Same-zone clique edges inflate attack-path and edge-count claims.
6. LLM/provider admin controls
   `app/routes/llm_config.py:100-164`
   Runtime provider selection and credential management are missing.
