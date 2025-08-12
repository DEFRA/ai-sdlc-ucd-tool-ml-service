from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_example():
    response = client.get("/example/test")
    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_root():
    response = client.get("/")
    assert response.status_code == 404
