from unittest.mock import patch

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

    @app.get("/favicon.ico")
    async def favicon_endpoint():
        return {"status": "favicon"}

    return app


@pytest.fixture
def client(test_app):
    return TestClient(test_app)


def test_protected_endpoint_requires_auth(client):
    """Test that protected endpoints require authentication"""
    response = client.get("/test")
    assert response.status_code == 401
    assert response.json() == {"detail": "Valid authorization token required"}


@patch("app.auth.auth_middleware.validate_token")
def test_valid_token_returns_hello_world(mock_validate, client):
    """Test that valid token returns hello world message"""
    mock_validate.return_value = True

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
def test_invalid_token_returns_401(mock_validate, client):
    """Test that invalid token returns 401"""
    mock_validate.return_value = False

    response = client.get("/test", headers={"Authorization": "Bearer invalid-token"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Valid authorization token required"}
