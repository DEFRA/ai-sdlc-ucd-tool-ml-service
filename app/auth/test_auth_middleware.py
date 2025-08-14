from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.middleware.base import BaseHTTPMiddleware

from app.auth.auth_middleware import AuthMiddleware


class AuthMiddlewareWrapper(BaseHTTPMiddleware):
    """Wrapper to make the middleware testable with exceptions"""

    async def dispatch(self, request, call_next):
        from fastapi import HTTPException
        from fastapi.responses import JSONResponse

        middleware = AuthMiddleware(None)
        try:
            return await middleware.dispatch(request, call_next)
        except HTTPException as e:
            # In tests, we need to catch and convert HTTPException
            return JSONResponse(
                status_code=e.status_code,
                content={"detail": e.detail},
                headers=e.headers if e.headers else {},
            )


@pytest.fixture
def test_app():
    app = FastAPI()
    app.add_middleware(AuthMiddlewareWrapper)

    @app.get("/test")
    async def test_endpoint():
        return {"message": "test"}

    @app.get("/health")
    async def health_endpoint():
        return {"status": "ok"}

    @app.get("/http")
    async def http_endpoint():
        return {"message": "http"}

    @app.get("/favicon.ico")
    async def favicon_endpoint():
        return {"status": "favicon"}

    return app


@pytest.fixture
def client(test_app):
    return TestClient(test_app)


@patch("app.auth.auth_middleware.extract_bearer_token")
def test_protected_endpoint_requires_auth(mock_extract, client):
    """Test that protected endpoints require authentication"""
    from fastapi import HTTPException

    mock_extract.side_effect = HTTPException(
        status_code=401,
        detail="Authorization header required",
        headers={"WWW-Authenticate": "Bearer"},
    )

    response = client.get("/test")
    assert response.status_code == 401
    assert response.json() == {"detail": "Authorization header required"}


@patch("app.auth.auth_middleware.validate_token")
@patch("app.auth.auth_middleware.extract_bearer_token")
def test_valid_token_returns_hello_world(mock_extract, mock_validate, client):
    """Test that valid token returns hello world message"""
    mock_extract.return_value = "valid-token"
    mock_validate.return_value = {"sub": "user123", "exp": 9999999999}

    response = client.get("/test", headers={"Authorization": "Bearer valid-token"})
    assert response.status_code == 200
    assert response.json() == {"message": "Hello World! Token is valid."}


def test_public_health_endpoint_no_auth_required(client):
    """Test that /health endpoint does not require authentication"""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_public_http_endpoint_no_auth_required(client):
    """Test that /http endpoint does not require authentication"""
    response = client.get("/http")
    assert response.status_code == 200
    assert response.json() == {"message": "http"}


@patch("app.auth.auth_middleware.validate_token")
@patch("app.auth.auth_middleware.extract_bearer_token")
def test_invalid_token_returns_401(mock_extract, mock_validate, client):
    """Test that invalid token returns 401"""
    from fastapi import HTTPException

    mock_extract.return_value = "invalid-token"
    mock_validate.side_effect = HTTPException(
        status_code=401,
        detail="Invalid token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    response = client.get("/test", headers={"Authorization": "Bearer invalid-token"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid token"}
