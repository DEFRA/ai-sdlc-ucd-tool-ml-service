from fastapi.testclient import TestClient

from .main import app

client = TestClient(app)


def test_example():
    response = client.get(
        "/example/test", headers={"Authorization": "Bearer test.jwt.token"}
    )
    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_root():
    response = client.get("/", headers={"Authorization": "Bearer test.jwt.token"})
    assert response.status_code == 404
