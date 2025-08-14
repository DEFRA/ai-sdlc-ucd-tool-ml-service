from unittest.mock import patch

from fastapi.testclient import TestClient

from .main import app

client = TestClient(app)


@patch("app.auth.jwks_verification.get_jwks_client")
@patch("app.auth.jwks_verification.jwt.decode")
def test_example(mock_decode, mock_client):
    mock_decode.return_value = {"sub": "test", "exp": 9999999999}
    mock_client.return_value.get_signing_key_from_jwt.return_value.key = "test_key"

    response = client.get(
        "/example/test", headers={"Authorization": "Bearer test.jwt.token"}
    )
    assert response.status_code == 200
    assert response.json() == {"message": "Hello World! Token is valid."}


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@patch("app.auth.jwks_verification.get_jwks_client")
@patch("app.auth.jwks_verification.jwt.decode")
def test_root(mock_decode, mock_client):
    mock_decode.return_value = {"sub": "test", "exp": 9999999999}
    mock_client.return_value.get_signing_key_from_jwt.return_value.key = "test_key"

    response = client.get("/", headers={"Authorization": "Bearer test.jwt.token"})
    assert response.status_code == 200
    assert response.json() == {"message": "Hello World! Token is valid."}
