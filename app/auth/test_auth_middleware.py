import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.auth.auth_middleware import AuthMiddleware


@pytest.fixture
def test_app():
    app = FastAPI()
    app.add_middleware(AuthMiddleware)

    @app.get("/test")
    async def test_endpoint():
        return {"message": "test"}

    @app.get("/health")
    async def health_endpoint():
        return {"status": "ok"}

    @app.get("/http")
    async def http_endpoint():
        return {"message": "http"}

    return app


@pytest.fixture
def client(test_app):
    return TestClient(test_app)


def test_protected_endpoint_requires_auth(client):
    """Test that protected endpoints require authentication"""
    response = client.get("/test")
    assert response.status_code == 401
    assert response.json() == {"detail": "Authorization header required"}


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
