from typing import Callable
from uuid import UUID

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

from app.core.security import decode_token


class TenantScopingMiddleware(BaseHTTPMiddleware):
    EXEMPT_PATHS = {
        "/",
        "/auth/login",
        "/auth/signup",
        "/health",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/favicon.ico",
    }

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request.state.tenant_id = None
        request.state.user_id = None
        request.state.role = None
        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return JSONResponse(status_code=401, content={"detail": "Authentication required."})
        try:
            payload = decode_token(auth_header.split(" ", maxsplit=1)[1])
            request.state.tenant_id = UUID(payload["tenant_id"])
            request.state.user_id = payload["sub"]
            request.state.role = payload["role"]
        except (ValueError, KeyError):
            return JSONResponse(status_code=401, content={"detail": "Invalid JWT token."})
        return await call_next(request)
