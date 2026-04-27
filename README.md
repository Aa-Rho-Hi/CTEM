# ATLAS-CTEM

**Attack-surface Tracking and Lifecycle Automation System for Cyber Threat Exposure Management**

ATLAS-CTEM is an enterprise-grade, multi-tenant cybersecurity platform that unifies vulnerability discovery, risk prioritization, attack-path analysis, compliance governance, and AI-driven remediation into a single workflow.

---

## Features

- **Multi-format Scan Ingestion** — Nmap, Nessus, Qualys, Rapid7, Checkmarx, SonarQube, Veracode, Burp Suite, Snyk, and generic JSON/CSV
- **Composite Risk Scoring** — Multi-factor model combining CVSS, EPSS, KEV status, network exposure, and business impact (crown-jewel tiers, revenue bands)
- **Attack Graph Analysis** — NetworkX-powered lateral-movement path enumeration and betweenness-centrality choke-point detection
- **Automated Compliance Mapping** — CWE-to-control mapping across 10 frameworks: NIST CSF 2.0, PCI-DSS 4.0, HIPAA, ISO 27001:2022, CMMC, SOC 2, GDPR, CCPA, NYDFS, CRI Profile 2.0
- **Remediation Workflow** — LLM-generated remediation plans, blast-radius analysis, multi-stage approval chains, and execution via Tanium / ServiceNow / Jira
- **AI Agent Framework** — Declarative LLM agents with tool whitelists, risk ceilings, and immutable audit trails
- **Kill Switch** — Redis-backed emergency stop; fail-closed on Redis unavailability
- **RBAC & Multi-tenancy** — Six roles, full tenant isolation at the database query level
- **Immutable Audit Log** — Every state change recorded with user, action, resource, and timestamp

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend API | FastAPI (Python 3.12, async) |
| ORM | SQLAlchemy 2.0 (async) + Alembic |
| Database | PostgreSQL 15 |
| Task Queue | Celery 5 + Redis 7 |
| Graph Engine | NetworkX 3 / Neo4j 5 |
| Frontend | Next.js 16, React 19, TypeScript |
| Styling | TailwindCSS 4 + Recharts |
| Container | Docker + Docker Compose + Nginx |

---

## Quick Start

### Prerequisites

- Docker ≥ 24 and Docker Compose v2
- Git

### 1. Clone

```bash
git clone https://github.com/Aa-Rho-Hi/CTEM.git
cd CTEM
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env — set database passwords, API keys, LLM credentials
```

### 3. Start all services

```bash
docker compose up --build
```

This starts: PostgreSQL, Redis, Neo4j, FastAPI backend, Celery worker, Celery Beat scheduler, Next.js frontend, and Nginx.

### 4. Run migrations

```bash
docker compose exec api alembic upgrade head
```

### 5. Access

| Service | URL |
|---|---|
| Frontend | http://localhost:3000 |
| API docs (Swagger) | http://localhost:8000/docs |
| API docs (ReDoc) | http://localhost:8000/redoc |

---

## Environment Variables

Key variables in `.env` (see `.env.example` for the full list):

```env
DATABASE_URL=postgresql+asyncpg://user:pass@db:5432/atlas
REDIS_URL=redis://redis:6379/0
NEO4J_URI=bolt://neo4j:7687
SECRET_KEY=<random-256-bit-key>

# LLM (primary + fallbacks)
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
GROQ_API_KEY=

# NVD enrichment
NVD_API_KEY=

# Integrations (optional)
TANIUM_URL=
TANIUM_API_KEY=
SERVICENOW_INSTANCE=
SERVICENOW_USER=
SERVICENOW_PASSWORD=
JIRA_URL=
JIRA_API_TOKEN=
SPLUNK_HEC_URL=
SPLUNK_HEC_TOKEN=
```

---

## Project Structure

```
ATLAS-CTEM/
├── app/
│   ├── agents/          # AI agent framework
│   ├── application/     # Use-case orchestrators (auth, discovery, governance)
│   ├── domain/          # Pure business logic (parsers, SLA, compliance)
│   ├── infrastructure/  # Repository implementations
│   ├── models/          # SQLAlchemy ORM entities
│   ├── routes/          # FastAPI routers (15+ modules)
│   ├── schemas/         # Pydantic request/response models
│   ├── services/        # Business services (risk engine, attack graph, etc.)
│   └── tasks/           # Celery async tasks
├── frontend/            # Next.js 16 App Router application
├── migrations/          # Alembic migration versions
├── tests/               # Pytest test suite (50+ test files)
├── k8s/                 # Kubernetes manifests
├── docker-compose.yml
└── ieee_report.tex      # IEEE conference paper
```

---

## User Roles

| Role | Capabilities |
|---|---|
| `super_admin` | Full platform access, kill-switch deactivation |
| `platform_admin` | Tenant management, user administration |
| `security_analyst` | Scan ingestion, findings, remediation planning, kill-switch activation |
| `approver` | Remediation approval/rejection |
| `auditor` | Read-only access to audit logs and compliance reports |
| `client_viewer` | Dashboard and findings read-only |

---

## Supported Scanners

Nmap (XML) · Nessus (.nessus) · Qualys VMDR (XML) · Rapid7 InsightVM (JSON) · Checkmarx (JSON) · SonarQube (JSON) · Veracode (JSON) · Burp Suite (JSON/CSV) · Snyk (JSON) · Generic JSON/CSV

---

## Compliance Frameworks

NIST CSF 2.0 · PCI-DSS 4.0 · HIPAA · ISO 27001:2022 · CMMC Level 2 · SOC 2 Type II · GDPR · CCPA · NYDFS 23 NYCRR 500 · CRI Profile 2.0

---

## Running Tests

```bash
docker compose exec api pytest tests/ -v
```

---

## Kubernetes

Manifests for API and Celery worker deployments with Horizontal Pod Autoscalers are in [k8s/](k8s/).

---

## License

This project is for academic and research purposes. See individual dependency licenses for third-party components.
