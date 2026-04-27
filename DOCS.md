# ATLAS-CTEM — Developer & Operations Documentation

> Cyber Threat Exposure Management Platform  
> Stack: Next.js 16 · FastAPI · PostgreSQL 15 · Redis 7 · Celery · Neo4j

---

## Table of Contents

1. [Project Structure](#1-project-structure)
2. [Prerequisites](#2-prerequisites)
3. [Quick Start — Docker Compose](#3-quick-start--docker-compose)
4. [Local Development Setup](#4-local-development-setup)
5. [Environment Variables](#5-environment-variables)
6. [Database Setup & Migrations](#6-database-setup--migrations)
7. [Running the Services](#7-running-the-services)
8. [API Reference](#8-api-reference)
9. [User Roles & Access Control](#9-user-roles--access-control)
10. [Scan Ingestion Guide](#10-scan-ingestion-guide)
11. [Celery Tasks](#11-celery-tasks)
12. [Integrations Configuration](#12-integrations-configuration)
13. [Kill Switch](#13-kill-switch)
14. [Troubleshooting](#14-troubleshooting)

---

## 1. Project Structure

```
ATLAS-CTEM/
├── app/                        # FastAPI backend
│   ├── application/            # Use cases / orchestration layer (incremental migration)
│   ├── agents/                 # AI agent implementations & catalog
│   ├── core/                   # Security (JWT), tenant middleware, logging
│   ├── domain/                 # Framework-agnostic business rules and parsers
│   ├── infrastructure/         # Repositories + external adapters (incremental migration)
│   ├── models/                 # SQLAlchemy ORM entities + base
│   ├── routes/                 # API route handlers (15+ routers)
│   ├── schemas/                # Pydantic request/response models
│   ├── services/               # Business logic layer (35+ services)
│   └── tasks/                  # Celery async tasks
│       ├── scan_pipeline.py    # Scan ingestion + parsing
│       ├── risk_scoring.py     # Vulnerability risk scoring
│       ├── remediation_exec.py # Remediation execution
│       └── compliance_update.py
├── frontend/                   # Next.js 16 frontend
│   ├── src/
│   │   ├── app/                # Next.js App Router pages
│   │   │   ├── (app)/          # Authenticated routes (all tabs)
│   │   │   └── login/          # Public login page
│   │   ├── components/         # Shared UI components
│   │   └── lib/                # API client, auth utilities
│   └── .env.local              # Frontend environment (API URL)
├── migrations/                 # Alembic DB migration files
├── tests/                      # Pytest test suite
├── celery_app.py               # Celery app + queue configuration
├── docker-compose.yml          # Full stack Docker Compose
├── .env                        # Backend environment variables
├── .env.example                # Environment template
└── .env.docker                 # Docker-specific overrides
```

### Backend Layering Target

The current backend already separates `routes`, `services`, `models`, and `tasks`, but several route modules still query SQLAlchemy models directly and some task modules combine parsing, orchestration, persistence, and external I/O in a single file. The target structure should be:

- `presentation`: FastAPI routers, request/response schemas, middleware, auth guards.
- `application`: feature use cases that orchestrate domain rules, repositories, and side effects.
- `domain`: pure business rules, scoring logic, validation policies, and normalization rules with no FastAPI or Celery dependency.
- `infrastructure`: SQLAlchemy repositories/models, Redis, Celery, HTTP clients, scanner adapters, and LLM/integration clients.

Recommended mapping for this repo:

- `app/routes/*` stays the presentation layer until migrated to `app/presentation/http/routes/*`.
- `app/application/<feature>/use_cases.py` should own flows like register/login, scan ingestion orchestration, approval routing, and remediation execution.
- `app/services/risk_engine.py`, `app/services/normalizer.py`, `app/services/confidence_service.py`, and similar pure logic modules are the strongest domain candidates.
- `app/models/*`, Redis clients, Celery tasks, `nvd_client.py`, `llm_router.py`, `tanium.py`, `splunk.py`, and repository adapters belong in infrastructure.
- `app/tasks/scan_pipeline.py` should be split next into parser components, ingestion use cases, and persistence adapters because it currently spans multiple layers.

Current migrated slices:

- `auth`: route -> application use case -> persistence repository.
- `discover`: route -> application use case -> persistence repository, with scan payload parsing extracted into domain/application modules.
- `governance`: route -> application use case -> persistence repository, with hourly SLA maintenance handled in a dedicated task/use-case path.

Migration rule: routes should only do HTTP translation and dependency injection; use cases should coordinate work; domain code should stay framework-agnostic; infrastructure should be the only layer that knows about SQLAlchemy, Redis, Celery, or external APIs.

---

## 2. Prerequisites

| Tool | Version | Required For |
|---|---|---|
| Python | 3.11+ | Backend |
| Node.js | 18+ | Frontend |
| Docker + Docker Compose | v2+ | Containerized setup |
| PostgreSQL | 15 | Local dev (if not using Docker) |
| Redis | 7 | Local dev (if not using Docker) |

---

## 3. Quick Start — Docker Compose

The fastest way to run the full stack.

```bash
# 1. Clone the repo
cd ATLAS-CTEM

# 2. Copy environment template
cp .env.example .env

# 3. Edit .env — fill in your API keys (see Environment Variables section)
nano .env

# 4. Start all services
docker compose up

# 5. Access the app
open http://localhost:80       # via nginx proxy
open http://localhost:8000/docs # FastAPI Swagger UI
open http://localhost:5555      # Celery Flower (task monitor)
```

### Services started by Docker Compose

| Service | URL | Description |
|---|---|---|
| `api` | http://localhost:8000 | FastAPI backend |
| `worker` | — | Celery scan/remediation worker |
| `scoring-worker` | — | Celery risk scoring worker |
| `beat` | — | Celery periodic task scheduler |
| `postgres` | localhost:5432 | PostgreSQL database |
| `redis` | localhost:6379 | Redis broker/cache |
| `graphrag` | http://localhost:7474 | Neo4j browser |
| `flower` | http://localhost:5555 | Task monitoring UI |
| `nginx` | http://localhost:80 | Reverse proxy |

---

## 4. Local Development Setup

### 4.1 Backend

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate       # macOS/Linux
# venv\Scripts\activate        # Windows

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment
cp .env.example .env
# Edit .env with your values

# Run database migrations
alembic upgrade head

# Start the API server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 4.2 Celery Workers (required for scan processing)

Open **two additional terminals**:

```bash
# Terminal 2 — Main worker (scan pipeline, remediation)
source venv/bin/activate
celery -A celery_app.celery_app worker --loglevel=info --pool=solo -Q celery

# Terminal 3 — Scoring worker (risk scoring)
source venv/bin/activate
celery -A celery_app.celery_app worker --loglevel=info --pool=solo -Q scoring
```

> **Important:** If either worker is not running, uploads will queue but never process (status stays `uploaded` indefinitely).

### 4.3 Frontend

```bash
cd frontend

# Install dependencies
npm install

# Configure API URL
echo "NEXT_PUBLIC_API_URL=http://localhost:8000" > .env.local
echo "NEXT_TELEMETRY_DISABLED=1" >> .env.local

# Start dev server
npm run dev

# Open in browser
open http://localhost:3000
```

---

## 5. Environment Variables

### 5.1 Backend — `.env`

#### Database & Cache

| Variable | Example | Description |
|---|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://atlas:atlas@localhost:5432/atlas` | PostgreSQL connection string (must use asyncpg driver) |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection string (broker + backend + cache) |

#### Authentication

| Variable | Example | Description |
|---|---|---|
| `JWT_SECRET_KEY` | `<64-char hex string>` | Secret for JWT signing — generate with `openssl rand -hex 32` |
| `JWT_ALGORITHM` | `HS256` | JWT algorithm |
| `JWT_EXPIRE_MINUTES` | `60` | Token expiry in minutes |

#### LLM Provider

| Variable | Example | Description |
|---|---|---|
| `OPENAI_API_KEY` | `sk-...` | OpenAI-compatible API key (required for LLM features) |
| `OPENAI_MODEL` | `gpt-4` | Model name to use |
| `OPENAI_BASE_URL` | `https://api.openai.com/openai` | Base URL (change for Azure, local LLM, etc.) |
| `GROQ_API_KEY` | _(optional)_ | Groq fallback |
| `ANTHROPIC_API_KEY` | _(optional)_ | Anthropic fallback |
| `GEMINI_API_KEY` | _(optional)_ | Gemini fallback |

#### NVD (CVE Enrichment)

| Variable | Example | Description |
|---|---|---|
| `NVD_API_KEY` | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` | NIST NVD API key — get free key at https://nvd.nist.gov/developers/request-an-api-key |
| `NIST_NVD_BASE_URL` | `https://services.nvd.nist.gov/rest/json/cves/2.0` | NVD API endpoint |

> In `ENVIRONMENT=development`, NVD calls are mocked (no key needed).

#### Integrations

| Variable | Example | Description |
|---|---|---|
| `TANIUM_URL` | `https://tanium.example.com` | Tanium server URL |
| `TANIUM_API_KEY` | `...` | Tanium API key |
| `SERVICENOW_URL` | `https://instance.service-now.com` | ServiceNow instance URL |
| `SERVICENOW_USER` | `atlas` | ServiceNow username |
| `SERVICENOW_PASS` | `...` | ServiceNow password |
| `JIRA_URL` | `https://jira.example.com` | Jira base URL |
| `JIRA_API_KEY` | `...` | Jira API token |
| `SPLUNK_URL` | `https://splunk.example.com` | Splunk HEC URL |
| `SPLUNK_TOKEN` | `...` | Splunk HEC token |

> Set integrations to `http://mock-*` with dummy keys in development — the code uses stubs.

#### Graph Database

| Variable | Example | Description |
|---|---|---|
| `NEO4J_URL` | `bolt://localhost:7687` | Neo4j bolt URL |
| `NEO4J_USER` | `neo4j` | Neo4j username |
| `NEO4J_PASSWORD` | `...` | Neo4j password |

#### Application

| Variable | Options | Description |
|---|---|---|
| `ENVIRONMENT` | `development` / `staging` / `production` | Controls mock mode, external calls |
| `LOG_LEVEL` | `DEBUG` / `INFO` / `WARNING` | Logging verbosity |

### 5.2 Frontend — `frontend/.env.local`

| Variable | Example | Description |
|---|---|---|
| `NEXT_PUBLIC_API_URL` | `http://localhost:8000` | Backend API base URL |
| `NEXT_TELEMETRY_DISABLED` | `1` | Disable Next.js telemetry |

---

## 6. Database Setup & Migrations

### Initial Setup

```bash
# Run all migrations (creates all tables)
alembic upgrade head

# Check current migration version
alembic current

# Show migration history
alembic history
```

### Creating a New Migration

```bash
# Auto-generate from model changes
alembic revision --autogenerate -m "add column foo to vulnerabilities"

# Review the generated file in migrations/versions/
# Then apply it
alembic upgrade head
```

### Rollback

```bash
# Rollback one migration
alembic downgrade -1

# Rollback to a specific revision
alembic downgrade <revision_id>
```

### First-Time User Creation

After running migrations, create the first super_admin via the API (the register endpoint requires an existing super_admin, so use the DB directly for the very first user):

```bash
# Connect to Postgres
psql postgresql://atlas:atlas@localhost:5432/atlas

# Or via Docker
docker exec -it atlas-ctem-postgres-1 psql -U atlas -d atlas
```

Alternatively, seed via the register endpoint once you have a super_admin JWT (use a DB-created user for bootstrapping).

---

## 7. Running the Services

### Development (manual)

```bash
# 1. API
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# 2. Main Celery worker (new terminal)
celery -A celery_app.celery_app worker --loglevel=info --pool=solo -Q celery

# 3. Scoring Celery worker (new terminal)
celery -A celery_app.celery_app worker --loglevel=info --pool=solo -Q scoring

# 4. Beat scheduler (new terminal, for daily external discovery)
celery -A celery_app.celery_app beat --loglevel=info

# 5. Frontend (new terminal)
cd frontend && npm run dev
```

### Docker Compose

```bash
# Start everything
docker compose up

# Start in background
docker compose up -d

# Tail logs for a specific service
docker compose logs -f worker
docker compose logs -f scoring-worker
docker compose logs -f api

# Restart workers after code change
docker compose restart worker scoring-worker

# Stop everything
docker compose down

# Stop and remove volumes (wipes database)
docker compose down -v
```

### Monitoring Celery Tasks

```bash
# Flower UI (if running)
open http://localhost:5555

# CLI inspection
celery -A celery_app.celery_app inspect active
celery -A celery_app.celery_app inspect reserved
celery -A celery_app.celery_app inspect stats

# Purge all queued tasks (use with caution)
celery -A celery_app.celery_app purge
```

---

## 8. API Reference

### Base URL

```
http://localhost:8000
```

### Interactive Docs

```
http://localhost:8000/docs      # Swagger UI
http://localhost:8000/redoc     # ReDoc
```

### Authentication

All endpoints (except `/auth/login`) require:
```
Authorization: Bearer <jwt_token>
```

---

### Auth

#### `POST /auth/login`

```json
Request:
{
  "email": "admin@example.com",
  "password": "password"
}

Response:
{
  "access_token": "eyJ...",
  "tenant_id": "00000000-0000-0000-0000-000000000001"
}
```

#### `POST /auth/register` _(`super_admin` / `platform_admin` only)_

```json
Request:
{
  "email": "analyst@example.com",
  "password": "password",
  "role": "security_analyst",
  "tenant_id": "00000000-0000-0000-0000-000000000001"
}
```

---

### Dashboard

| Method | Endpoint | Description |
|---|---|---|
| GET | `/dashboard/exposure` | Exposure score + finding counts |
| GET | `/dashboard/compliance-summary` | Framework score radar data |
| GET | `/health` | System health (Postgres, Redis, Celery queue depth) |

---

### Discover

| Method | Endpoint | Description |
|---|---|---|
| POST | `/discover/scan/upload` | Upload scan file (multipart/form-data, field: `file`) |
| POST | `/discover/scan/active` | Trigger active scan |
| GET | `/discover/scan/{scan_id}` | Poll scan status |
| POST | `/discover/external/refresh` | Trigger external asset discovery |

#### Scan Upload Example

```bash
curl -X POST http://localhost:8000/discover/scan/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/path/to/scan.nessus"
```

#### Scan Status Response

```json
{
  "id": "d1691df0-8a1c-4efe-...",
  "source_tool": "nessus",
  "status": "uploaded | processing | ready | processed | failed",
  "finding_count": 150,
  "vulnerability_count": 142,
  "duplicate_count": 8,
  "skipped_no_cve_count": 0,
  "error": null
}
```

#### Active Scan Request

```json
{
  "source_tool": "nmap",
  "targets": ["10.0.0.1", "10.0.0.2", "192.168.1.0/24"],
  "options": {
    "ports": "22,80,443,8080"
  }
}
```

---

### Findings (Prioritize)

| Method | Endpoint | Description |
|---|---|---|
| GET | `/prioritize/findings` | Paginated finding list |
| PATCH | `/prioritize/findings/{id}/status` | Update finding status |
| GET | `/prioritize/attack-surface` | Attack graph data |

#### Query Parameters for `/prioritize/findings`

| Param | Type | Example |
|---|---|---|
| `severity` | string | `critical`, `high`, `medium`, `low` |
| `status` | string | `open`, `in_progress`, `fixed`, `verified` |
| `scan_id` | UUID | filter by originating scan |
| `page` | int | default `1` |
| `page_size` | int | default `20` |

---

### Scope

| Method | Endpoint | Description |
|---|---|---|
| GET/POST | `/scope/zones` | Network zones |
| GET/POST | `/scope/assets` | Assets |
| PATCH | `/scope/assets/{id}/crown-jewel` | Set crown jewel tier |
| GET/POST | `/scope/business-context` | Business context |
| POST | `/scope/change-windows` | Configure change windows |

---

### Mobilize

| Method | Endpoint | Description |
|---|---|---|
| GET | `/mobilize/queue` | Pending approval queue |
| GET | `/mobilize/plan/{id}` | Remediation plan detail + blast radius |
| POST | `/mobilize/approve/{id}` | Approve remediation |
| POST | `/mobilize/reject/{id}` | Reject remediation (body: `{"reason": "..."}`) |

---

### Remediation

| Method | Endpoint | Description |
|---|---|---|
| GET | `/remediation/history` | All remediation records |
| POST | `/remediation/execute/{id}` | Execute approved remediation |
| POST | `/remediation/verify/{id}` | Trigger verification |

---

### Validate (PT)

| Method | Endpoint | Description |
|---|---|---|
| GET/POST | `/validate/pt/sessions` | PT sessions |
| POST | `/validate/pt/session` | Create PT session |
| POST | `/validate/pt/probe` | Run exploitation probe |
| GET | `/validate/pt/tools` | Available PT tools |

---

### Compliance

| Method | Endpoint | Description |
|---|---|---|
| GET | `/compliance/posture` | All framework scores |
| GET | `/compliance/posture/{framework}` | Single framework score + failing controls |
| GET | `/compliance/findings/{framework}` | Findings mapped to controls |

---

### Agents

| Method | Endpoint | Description |
|---|---|---|
| GET | `/agents` | List agents |
| POST | `/agents` | Create agent |
| GET | `/agents/catalog` | Available agent types |
| POST | `/agents/run/{id}` | Run agent with goal (body: `{"goal": "..."}`) |

---

### Kill Switch

| Method | Endpoint | Roles | Description |
|---|---|---|---|
| GET | `/kill-switch/status` | All | Current state |
| POST | `/kill-switch/activate` | super_admin, security_analyst | Halt all PT + remediation |
| POST | `/kill-switch/deactivate` | super_admin only | Resume operations |

---

### Audit

| Method | Endpoint | Description |
|---|---|---|
| GET | `/audit/log` | Query audit log |

#### Query Parameters

| Param | Type | Example |
|---|---|---|
| `action` | string | search by action name |
| `from_date` | ISO datetime | `2026-01-01T00:00:00Z` |
| `to_date` | ISO datetime | |
| `resource_type` | string | `vulnerability`, `system` |

---

### Integrations

| Method | Endpoint | Description |
|---|---|---|
| GET | `/integrations` | List all integrations |
| POST | `/integrations` | Create integration |
| PUT | `/integrations/{id}` | Update integration config |
| POST | `/integrations/{id}/test` | Test connectivity |
| POST | `/integrations/{id}/deactivate` | Deactivate |

---

### Health

```
GET /health

Response:
{
  "status": "ok",
  "postgres": "ok",
  "redis": "ok",
  "celery_queue_depth": 0
}
```

---

## 9. User Roles & Access Control

| Role | Dashboard | Findings | Discover | Scope | Mobilize | Remediation | Validate | Compliance | Audit | Agents | Settings |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `super_admin` | ✓ | ✓ edit | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `platform_admin` | ✓ | ✓ | — | — | — | — | — | — | — | ✓ | ✓ |
| `security_analyst` | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ | — | ✓ | — |
| `approver` | ✓ | ✓ | — | — | ✓ | ✓ | ✓ | ✓ | — | — | — |
| `auditor` | ✓ | ✓ | — | — | — | — | ✓ | ✓ | ✓ | — | — |
| `client_viewer` | ✓ | ✓ read | — | — | — | — | — | — | — | — | — |

### Registering a New User

```bash
curl -X POST http://localhost:8000/auth/register \
  -H "Authorization: Bearer $SUPER_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "analyst@example.com",
    "password": "secure-password",
    "role": "security_analyst",
    "tenant_id": "00000000-0000-0000-0000-000000000001"
  }'
```

---

## 10. Scan Ingestion Guide

### Supported Upload Formats

| Tool | Format | Notes |
|---|---|---|
| Nmap | XML (`-oX`) | CVEs extracted from script output |
| Nessus | `.nessus` XML | Tenable Nessus export |
| Qualys | XML | Qualys scan report |
| Rapid7 | JSON / XML | InsightVM export |
| Checkmarx | JSON | Findings export |
| SonarQube | JSON | Issues export |
| Veracode | JSON | Findings export |
| Burp Suite | JSON / CSV | Issue export |
| Snyk | JSON | Issue export |
| Generic | JSON / CSV | Any findings object with `cve_id`, `asset_ip`, `severity` fields |

### Generic JSON Format

```json
[
  {
    "cve_id": "CVE-2024-1234",
    "asset_ip": "10.0.0.5",
    "port": 443,
    "severity": "high",
    "description": "Remote code execution vulnerability in OpenSSL"
  }
]
```

### Scan Status Lifecycle

```
uploaded → processing → ready → processed
                    ↘ failed (after 3 retries)
```

- `uploaded` — file received, task queued
- `processing` — worker actively parsing and ingesting
- `ready` — ingestion complete, scoring queued
- `processed` — risk scoring complete, findings visible
- `failed` — pipeline error (see `error` field in status response)

### Deduplication

A finding is deduplicated based on: `SHA-256(cve_id + asset_ip + source_tool + port)`

Duplicates within the last 30 days update `last_seen` and are counted in `duplicate_count`. They do not create new `Vulnerability` rows.

---

## 11. Celery Tasks

### Queue Architecture

```
Queue: celery         → worker container
  - process_uploaded_scan
  - process_active_scan
  - execute_remediation_task
  - verify_remediation_task
  - recalculate_all_scores
  - discover_external_attack_surface

Queue: scoring        → scoring-worker container
  - score_scan_findings
  - rescore_vulnerability
```

### Retry Policy

All tasks: `autoretry_for=(Exception,)`, `retry_backoff=True`, `max_retries=3`

After 3 failures the task is marked `FAILURE` and the associated `Scan.status` is set to `"failed"`.

### Scheduled Tasks (Celery Beat)

| Task | Schedule | Description |
|---|---|---|
| `discover_external_attack_surface` | Daily at 03:00 UTC | Certificate transparency + internet enumeration for shadow assets |

### Monitoring

```bash
# View active tasks
docker exec atlas-ctem-worker-1 celery -A celery_app.celery_app inspect active

# Purge stuck tasks from queue (emergency only)
docker exec atlas-ctem-worker-1 celery -A celery_app.celery_app purge -f

# Restart workers after code changes
docker compose restart worker scoring-worker
```

---

## 12. Integrations Configuration

Integrations are configured at runtime through the Settings UI (`super_admin` or `platform_admin`) or via the API.

### Via API

```bash
# Create an integration
curl -X POST http://localhost:8000/integrations \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Tanium Production",
    "integration_type": "tanium",
    "base_url": "https://tanium.corp.example.com",
    "api_key": "your-api-key",
    "config_json": {}
  }'

# Test connectivity
curl -X POST http://localhost:8000/integrations/{id}/test \
  -H "Authorization: Bearer $TOKEN"
```

### Integration Types

| Type | `integration_type` value | Authentication |
|---|---|---|
| Tanium | `tanium` | `api_key` |
| ServiceNow | `servicenow` | `api_key` (or username/pass in config_json) |
| Jira | `jira` | `api_key` |
| Splunk | `splunk` | `api_key` (HEC token) |
| Neo4j | `neo4j` | `api_key` (password) |

### Development Mocks

Set integration URLs to dummy values — the services use stub implementations in development:

```env
TANIUM_URL=http://mock-tanium
TANIUM_API_KEY=mock-key
SERVICENOW_URL=http://mock-snow
SERVICENOW_USER=mock
SERVICENOW_PASS=mock
```

---

## 13. Kill Switch

The kill switch is a global **emergency stop** for all PT probes and remediation execution.

### Behavior When Active

- All PT agent executions are immediately halted
- All remediation executions are blocked (HTTP 503)
- Tanium integration calls are blocked
- A red blinking banner appears on every page in the UI

### Fail-Closed

If Redis becomes unreachable, the kill switch defaults to **active** (safe state). Operations resume only when Redis connectivity is restored and the switch is explicitly deactivated.

### Usage

```bash
# Activate (super_admin or security_analyst)
curl -X POST http://localhost:8000/kill-switch/activate \
  -H "Authorization: Bearer $TOKEN"

# Deactivate (super_admin only)
curl -X POST http://localhost:8000/kill-switch/deactivate \
  -H "Authorization: Bearer $TOKEN"

# Check status (all roles)
curl http://localhost:8000/kill-switch/status \
  -H "Authorization: Bearer $TOKEN"
```

---

## 14. Troubleshooting

### Scan stuck at `uploaded` status

The Celery worker is not running or cannot connect to Redis/Postgres.

```bash
# Check worker is running
docker ps | grep worker

# Check worker logs
docker logs atlas-ctem-worker-1 --tail 50

# Check Redis connectivity
docker exec atlas-ctem-worker-1 redis-cli -h redis ping

# Restart workers
docker compose restart worker scoring-worker
```

### Scan stuck at `ready` (scoring never finishes)

The scoring worker is not running, or is stuck on a previous failing task.

```bash
# Check scoring worker
docker logs atlas-ctem-scoring-worker-1 --tail 50

# Look for repeated retry errors
docker logs atlas-ctem-scoring-worker-1 2>&1 | grep "retry\|ERROR"

# If a task is stuck in retry loop, purge it
docker exec atlas-ctem-scoring-worker-1 celery -A celery_app.celery_app purge -f

# Restart
docker compose restart scoring-worker
```

### `ForeignKeyViolationError` on attack_graph_nodes

This occurs if edges are not deleted before nodes. Fixed in `app/services/attack_graph.py` — ensure you have the latest version with `flush()` between the two DELETEs.

### `DeadlockDetectedError` in risk scoring

Caused by multiple concurrent scoring tasks running against the same DB rows. The `score_scan_findings` task now runs `rebuild_for_tenant` only once at the end of the batch (not per-vulnerability), which eliminates this issue.

### API returns 401 on all requests

Token may be expired (default 60 min). Log in again:

```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "password"}'
```

### Frontend cannot reach API

Check `frontend/.env.local`:
```
NEXT_PUBLIC_API_URL=http://localhost:8000
```

If running in Docker, the frontend container must point to the Docker service name or host network address, not `localhost`.

### Database migration errors

```bash
# Check current revision
alembic current

# Check if DB is reachable
alembic check

# If stuck mid-migration, stamp to a known revision
alembic stamp <revision_id>

# Then retry
alembic upgrade head
```

### NVD enrichment returning mock data in production

Ensure `ENVIRONMENT=production` in `.env` and `NVD_API_KEY` is set to a valid NIST API key. In `development` mode all NVD calls are intentionally mocked.

### Celery beat not triggering scheduled tasks

```bash
# Check beat is running
docker ps | grep beat

# Check beat logs
docker logs atlas-ctem-beat-1

# Verify schedule (celerybeat-schedule file should exist)
ls -la celerybeat-schedule
```

---

*For architecture details, data models, and risk scoring formulas see `ATLAS-CTEM-LLD.md`.*
