from contextlib import asynccontextmanager
import logging
from uuid import UUID

from fastapi import FastAPI
from fastapi.responses import JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from app.config import get_settings
from app.core.logging import configure_logging
from app.core.tenant_middleware import TenantScopingMiddleware
from app.models.base import get_session_factory
from app.models.entities import Tenant
from app.routes import (
    agents,
    approvals,
    assets,
    audit,
    auth,
    compliance,
    dashboard,
    discover,
    governance,
    health,
    integrations,
    kill_switch,
    llm_config,
    mobilize,
    prioritize,
    remediation,
    roe,
    scope,
    users,
    validate,
    zones,
)

settings = get_settings()
configure_logging(settings.log_level)
logger = logging.getLogger(__name__)

_DEFAULT_TENANT_ID = UUID("00000000-0000-0000-0000-000000000001")


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        async with get_session_factory()() as session:
            existing = (await session.execute(select(Tenant).where(Tenant.id == _DEFAULT_TENANT_ID))).scalar_one_or_none()
            if not existing:
                session.add(Tenant(id=_DEFAULT_TENANT_ID, name="default"))
                await session.commit()
    except Exception as exc:
        logger.warning("Skipping default tenant bootstrap because the database is unavailable: %s", exc)
    yield


app = FastAPI(title="ATLAS-CTEM", lifespan=lifespan)
# TenantScopingMiddleware must be added BEFORE CORSMiddleware so that
# Starlette's reverse execution order puts CORS outermost. This guarantees
# Access-Control-Allow-Origin headers appear on every response — including
# 401s returned by TenantScopingMiddleware — so the browser never sees a
# raw CORS failure ("Load failed") instead of the real HTTP status.
app.add_middleware(TenantScopingMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
    ],
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1):\d+",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    return JSONResponse(
        {
            "name": "ATLAS-CTEM",
            "status": "ok",
            "health": "/health",
            "docs": "/docs",
            "redoc": "/redoc",
        }
    )


@app.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)

app.include_router(health.router)
app.include_router(auth.router)
app.include_router(scope.router)
app.include_router(discover.router)
app.include_router(governance.router)
app.include_router(prioritize.router)
app.include_router(validate.router)
app.include_router(mobilize.router)
app.include_router(remediation.router)
app.include_router(agents.router)
app.include_router(compliance.router)
app.include_router(audit.router)
app.include_router(users.router)
app.include_router(integrations.router)
app.include_router(llm_config.router)
app.include_router(dashboard.router)
app.include_router(kill_switch.router)
app.include_router(roe.router)
app.include_router(approvals.router)
app.include_router(assets.router)
app.include_router(zones.router)
