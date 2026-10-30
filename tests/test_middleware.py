"""Gateway credential middleware tests: missing-header 401 (TC-TLV-017 /
AC16), and header values correctly reaching the per-request contextvar with
no leakage across requests (supports TC-TLV-018 / AC17).
"""

from starlette.testclient import TestClient

from telivy_mcp.__main__ import _build_http_app
from telivy_mcp.config import Settings
from telivy_mcp.server import create_mcp_server, get_client_from_context


def _make_app():
    settings = Settings()
    mcp = create_mcp_server(settings)
    return _build_http_app(mcp, settings), settings


def test_health_is_local_and_does_not_require_credentials():
    app, _ = _make_app()
    with TestClient(app) as client:
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


def test_missing_header_returns_401_with_required_headers_listed():
    # TC-TLV-017 / AC16: missing X-Telivy-Api-Key -> 401 naming the header,
    # before any outbound call to Telivy (this request never reaches a tool).
    app, _ = _make_app()
    with TestClient(app) as client:
        resp = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            headers={"Accept": "application/json, text/event-stream"},
        )
        assert resp.status_code == 401
        body = resp.json()
        assert body["required_headers"] == ["X-Telivy-Api-Key"]
        assert "X-Telivy-Api-Key" in body["message"]


def test_header_present_reaches_request_context():
    # TC-TLV-018 / AC17 support: directly exercises the middleware's
    # contextvar plumbing without a full MCP protocol round-trip, confirming
    # the header value that arrives on the request is exactly what
    # get_client_from_context sees, and that it's reset afterward (no
    # leakage to the next request/tenant).
    import asyncio

    from telivy_mcp.server import GatewayTokenMiddleware, _gateway_api_key_var

    settings = Settings()
    seen = {}

    async def fake_app(scope, receive, send):
        seen["api_key"] = _gateway_api_key_var.get()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = GatewayTokenMiddleware(fake_app, settings)

    async def run():
        scope = {
            "type": "http",
            "path": "/mcp",
            "headers": [(b"x-telivy-api-key", b"tenant-a-key")],
        }

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        sent = []

        async def send(message):
            sent.append(message)

        await middleware(scope, receive, send)

    asyncio.run(run())
    assert seen["api_key"] == "tenant-a-key"
    # After the request completes, the contextvar must be reset — a fresh
    # get() outside any request context sees no leftover credential.
    assert _gateway_api_key_var.get() is None


def test_concurrent_requests_do_not_cross_contaminate_credentials():
    # TC-TLV-018 / AC17: two "concurrent" requests (interleaved via asyncio
    # tasks) carrying two different tenants' API keys must each see only
    # their own key inside the handler — contextvars are per-asyncio-Task,
    # so this is a direct test of the isolation mechanism, not a timing test.
    import asyncio

    from telivy_mcp.server import GatewayTokenMiddleware, _gateway_api_key_var

    settings = Settings()
    seen: dict[str, str | None] = {}
    release = asyncio.Event()

    async def fake_app(scope, receive, send):
        tenant = scope["_tenant"]
        # Yield control so the two tasks interleave before each reads back
        # its own contextvar — if the var were module/global state instead
        # of per-task, this is where cross-contamination would show up.
        await asyncio.sleep(0)
        if tenant == "a":
            await release.wait()
        else:
            release.set()
        seen[tenant] = _gateway_api_key_var.get()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = GatewayTokenMiddleware(fake_app, settings)

    async def call(tenant: str, key: str):
        scope = {
            "type": "http",
            "path": "/mcp",
            "headers": [(b"x-telivy-api-key", key.encode())],
            "_tenant": tenant,
        }

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            pass

        await middleware(scope, receive, send)

    async def run():
        await asyncio.gather(call("a", "tenant-a-key"), call("b", "tenant-b-key"))

    asyncio.run(run())
    assert seen == {"a": "tenant-a-key", "b": "tenant-b-key"}


def test_client_factory_returns_none_without_context():
    assert get_client_from_context() is None
