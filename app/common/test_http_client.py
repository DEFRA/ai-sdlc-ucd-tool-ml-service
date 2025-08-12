import httpx

from app.common.http_client import hook_request_tracing
from app.common.tracing import ctx_trace_id


def mock_handler(request):
    request_id = request.headers.get("x-cdp-request-id", "")
    return httpx.Response(200, text=request_id)


def test_trace_id_missing():
    ctx_trace_id.set("")
    client = httpx.Client(
        event_hooks={"request": [hook_request_tracing]},
        transport=httpx.MockTransport(mock_handler),
    )
    resp = client.get("http://localhost:1234/test")
    assert resp.text == ""


def test_trace_id_set(monkeypatch):
    # Set the tracing header config for this test
    from config import config

    monkeypatch.setattr(config, "tracing_header", "x-cdp-request-id")

    ctx_trace_id.set("trace-id-value")
    client = httpx.Client(
        event_hooks={"request": [hook_request_tracing]},
        transport=httpx.MockTransport(mock_handler),
    )
    resp = client.get("http://localhost:1234/test")
    assert resp.text == "trace-id-value"
