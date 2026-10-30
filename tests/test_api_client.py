"""TelivyClient tests against a mocked transport (httpx.MockTransport): no
real network calls, no real Telivy account needed.

Covers TC-TLV-019 / AC18 (status -> error-code/retryable mapping, no raw
upstream body or credential in the message), the credential-forwarding
contract (SOP §3.1: one Header in, "x-api-key" out, never "Authorization"),
and the 429/5xx retry-with-backoff behavior (SOP §5).
"""

import httpx
import pytest
import pytest_asyncio

from telivy_mcp import api_client
from telivy_mcp.api_client import TelivyClient, TelivyError


@pytest_asyncio.fixture(autouse=True)
async def _reset_shared_client():
    # api_client keeps one module-level httpx.AsyncClient for the process
    # lifetime (by design -- it holds no credentials). Tests swap in a
    # MockTransport-backed client per test and must tear it down after, or
    # one test's transport would leak into the next.
    yield
    if api_client._http_client is not None:
        await api_client._http_client.aclose()
    api_client._http_client = None


@pytest.fixture
def _no_real_sleep(monkeypatch):
    async def instant(_seconds):
        return None

    monkeypatch.setattr(api_client.asyncio, "sleep", instant)


def _install_transport(handler):
    api_client._http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_forwards_credential_as_x_api_key_not_authorization():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["headers"] = dict(request.headers)
        return httpx.Response(200, json={"ok": True})

    _install_transport(handler)
    client = TelivyClient("tenant-secret-key")
    result = await client.get("/api/v1/security/external-scans")

    assert result == {"ok": True}
    assert seen["headers"]["x-api-key"] == "tenant-secret-key"
    assert "authorization" not in seen["headers"]


@pytest.mark.asyncio
async def test_404_maps_to_not_found_and_does_not_leak_raw_body(_no_real_sleep):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            404,
            json={
                "message": "External scan scan-x was not found.",
                "internal_trace_id": "trace-abc-123",
                "other_tenant_hint": {"domain": "someone-elses-company.com"},
            },
        )

    _install_transport(handler)
    client = TelivyClient("tenant-secret-key")

    with pytest.raises(TelivyError) as exc_info:
        await client.get("/api/v1/security/external-scans/scan-x")

    err = exc_info.value
    envelope = err.to_envelope()
    assert '"code":"not_found"' in envelope
    assert '"retryable":false' in envelope
    assert "someone-elses-company.com" not in envelope
    assert "trace-abc-123" not in envelope
    assert "tenant-secret-key" not in envelope


@pytest.mark.asyncio
async def test_non_json_body_does_not_leak_raw_body(_no_real_sleep):
    # PRD-21245 review round 1, must-fix 1: a non-JSON (e.g. HTML) error body
    # must never reach the tool-facing message verbatim.
    raw = (
        "<html><body>Upstream internal trace: req-9f3a-secret-session-xyz, "
        "backend 10.0.4.17 timed out</body></html>"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(502, content=raw, headers={"content-type": "text/html"})

    _install_transport(handler)
    client = TelivyClient("tenant-secret-key")

    with pytest.raises(TelivyError) as exc_info:
        await client.get("/api/v1/security/external-scans")

    envelope = exc_info.value.to_envelope()
    assert '"code":"upstream_error"' in envelope
    assert '"retryable":true' in envelope
    assert "req-9f3a-secret-session-xyz" not in envelope
    assert "10.0.4.17" not in envelope


@pytest.mark.asyncio
async def test_json_body_without_message_or_error_key_does_not_leak_raw_body(_no_real_sleep):
    # PRD-21245 review round 1, must-fix 1: a JSON body shaped like
    # FastAPI-style validation errors (no "message"/"error" string field)
    # must fall back to a fixed generic message, not str(detail).
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            422,
            json={
                "detail": [
                    {"loc": ["query", "limit"], "msg": "value is not a valid integer"}
                ],
                "internal_trace_id": "trace-zzz",
            },
        )

    _install_transport(handler)
    client = TelivyClient("tenant-secret-key")

    with pytest.raises(TelivyError) as exc_info:
        await client.get("/api/v1/security/external-scans")

    envelope = exc_info.value.to_envelope()
    assert '"code":"invalid_argument"' in envelope
    assert '"retryable":false' in envelope
    assert "trace-zzz" not in envelope
    assert "value is not a valid integer" not in envelope


@pytest.mark.parametrize(
    "status,expected_code,expected_retryable",
    [
        (400, "invalid_argument", False),
        (401, "unauthorized", False),
        (403, "unauthorized", False),
        (404, "not_found", False),
        (422, "invalid_argument", False),
        (429, "rate_limited", True),
        (500, "upstream_error", True),
        (503, "upstream_error", True),
    ],
)
def test_classify_matches_sop_vocabulary(status, expected_code, expected_retryable):
    code, retryable = api_client._classify(status)
    assert code == expected_code
    assert retryable is expected_retryable


@pytest.mark.asyncio
async def test_429_retries_and_eventually_succeeds(_no_real_sleep):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if len(calls) < 2:
            return httpx.Response(429, headers={"Retry-After": "1"}, json={"message": "slow down"})
        return httpx.Response(200, json={"ok": True})

    _install_transport(handler)
    client = TelivyClient("tenant-secret-key")
    result = await client.get("/api/v1/security/external-scans")

    assert result == {"ok": True}
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_429_exhausts_retries_and_raises_rate_limited(_no_real_sleep):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"message": "slow down"})

    _install_transport(handler)
    client = TelivyClient("tenant-secret-key")

    with pytest.raises(TelivyError) as exc_info:
        await client.get("/api/v1/security/external-scans")

    assert exc_info.value.status_code == 429
    code, retryable = api_client._classify(exc_info.value.status_code)
    assert code == "rate_limited" and retryable is True


@pytest.mark.asyncio
async def test_network_error_maps_to_upstream_error_retryable(_no_real_sleep):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    _install_transport(handler)
    client = TelivyClient("tenant-secret-key")

    with pytest.raises(TelivyError) as exc_info:
        await client.get("/api/v1/security/external-scans")

    assert exc_info.value.status_code == 0
    code, retryable = api_client._classify(0)
    assert code == "upstream_error" and retryable is True


@pytest.mark.asyncio
async def test_empty_body_is_not_an_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"")

    _install_transport(handler)
    client = TelivyClient("tenant-secret-key")
    result = await client.get("/api/v1/security/external-scans/scan-1/breach-data")
    assert result is None
