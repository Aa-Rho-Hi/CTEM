from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.tenant_middleware import TenantScopingMiddleware


def test_invalid_bearer_token_returns_401():
    app = FastAPI()
    app.add_middleware(TenantScopingMiddleware)

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    client = TestClient(app)
    response = client.get("/ping", headers={"Authorization": "Bearer invalid.token.value"})

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid JWT token."}


def test_missing_bearer_token_returns_401():
    app = FastAPI()
    app.add_middleware(TenantScopingMiddleware)

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    client = TestClient(app)
    response = client.get("/ping")

    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required."}


def test_login_path_is_exempt():
    app = FastAPI()
    app.add_middleware(TenantScopingMiddleware)

    @app.post("/auth/login")
    async def login():
        return {"ok": True}

    client = TestClient(app)
    response = client.post("/auth/login")

    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_signup_path_is_exempt():
    app = FastAPI()
    app.add_middleware(TenantScopingMiddleware)

    @app.post("/auth/signup")
    async def signup():
        return {"ok": True}

    client = TestClient(app)
    response = client.post("/auth/signup")

    assert response.status_code == 200
    assert response.json() == {"ok": True}
