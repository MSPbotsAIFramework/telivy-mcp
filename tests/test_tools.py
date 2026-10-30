"""Functional tool tests: one assertion block per acceptance criterion
(TC-TLV-001..016, 018 (tool-level support), 020), plus the tools/list
snapshot and service-instructions bound.

No network calls: TelivyClient.get is monkeypatched per test to return
canned data or raise TelivyError, so these exercise the tool layer
(argument mapping, response shaping, error-envelope passthrough) without
needing a real Telivy account. The one case that does need a real account
(TC-TLV-021) is in the ledger as "manual, not run yet" and is out of scope
here by design (see PRD-21245.ac.json).
"""

import json

import pytest

from telivy_mcp._json import dump_json_capped
from telivy_mcp.api_client import TelivyClient, TelivyError
from telivy_mcp.config import Settings
from telivy_mcp.server import _gateway_api_key_var, create_mcp_server, get_client_from_context
from telivy_mcp.tools._common import clamp_limit

EXPECTED_TOOLS = {
    "telivy_list_external_scans",
    "telivy_get_external_scan",
    "telivy_get_external_scan_findings",
    "telivy_get_external_scan_breach_data",
    "telivy_list_risk_assessments",
    "telivy_get_risk_assessment",
    "telivy_get_risk_assessment_scan_status",
    "telivy_list_risk_assessment_devices",
    "telivy_get_risk_assessment_findings",
    "telivy_get_risk_assessment_pii_summary",
    "telivy_get_risk_assessment_directory_users",
    "telivy_get_finding_reference",
    "telivy_get_risk_progress_report",
}


@pytest.fixture
def mcp():
    return create_mcp_server(Settings())


@pytest.fixture(autouse=True)
def _credential_context():
    token = _gateway_api_key_var.set("test-tenant-key")
    yield
    _gateway_api_key_var.reset(token)


def _mock_get(monkeypatch, handler):
    async def fake_get(self, path, params=None):
        return handler(path, params)

    monkeypatch.setattr(TelivyClient, "get", fake_get)


def _mock_get_raises(monkeypatch, exc):
    async def fake_get(self, path, params=None):
        raise exc

    monkeypatch.setattr(TelivyClient, "get", fake_get)


async def _call(mcp, name, args=None):
    content, _structured = await mcp.call_tool(name, args or {})
    return json.loads(content[0].text)


# -- tools/list snapshot (SOP §2 shape checks, ≤20 tools, descriptions bounded) --


@pytest.mark.asyncio
async def test_tools_list_snapshot():
    mcp = create_mcp_server(Settings())
    tools = await mcp.list_tools()
    names = {t.name for t in tools}
    assert names == EXPECTED_TOOLS, f"unexpected tool set: {names}"
    assert len(tools) == 13

    for tool in tools:
        assert tool.annotations is not None and tool.annotations.readOnlyHint is True
        assert len(tool.description or "") <= 500, f"{tool.name}: description too long"
        first_line = (tool.description or "").strip().splitlines()[0]
        assert len(first_line) <= 100, f"{tool.name}: first line too long: {first_line!r}"


@pytest.mark.asyncio
async def test_service_instructions_present_and_bounded():
    mcp = create_mcp_server(Settings())
    assert mcp.instructions
    assert len(mcp.instructions) <= 1500


@pytest.mark.asyncio
async def test_no_token_envelope_when_context_missing():
    # Outside the autouse credential fixture's scope: simulate the "no
    # credential in context" branch every tool checks before calling Telivy.
    token = _gateway_api_key_var.set(None)
    try:
        assert get_client_from_context() is None
    finally:
        _gateway_api_key_var.reset(token)


# -- TC-TLV-001 / AC1: list external scans, no filters --


@pytest.mark.asyncio
async def test_tc_tlv_001_list_external_scans_default(mcp, monkeypatch):
    seen_params = {}

    def handler(path, params):
        seen_params.update(params)
        return {
            "message": "ok",
            "assessments": [
                {
                    "id": "scan-1",
                    "organizationName": "Acme Corp",
                    "domain": "acme.com",
                    "scanStatus": "completed",
                    "createdAt": "2026-10-01T00:00:00Z",
                    "updatedAt": "2026-10-02T00:00:00Z",
                }
            ],
            "total": 1,
        }

    _mock_get(monkeypatch, handler)
    result = await _call(mcp, "telivy_list_external_scans")

    assert seen_params == {
        "search": None,
        "assessmentSortBy": None,
        "sortOrder": None,
        "agencyId": None,
        "offset": None,
        "limit": 50,
    }
    assert result["total"] == 1
    assert result["has_more"] is False
    assert result["items"][0]["id"] == "scan-1"


# -- TC-TLV-002 / AC2: list external scans, filters reflected server-side --


@pytest.mark.asyncio
async def test_tc_tlv_002_list_external_scans_filters(mcp, monkeypatch):
    seen_params = {}

    def handler(path, params):
        seen_params.update(params)
        return {"assessments": [], "total": 0}

    _mock_get(monkeypatch, handler)
    await _call(
        mcp,
        "telivy_list_external_scans",
        {
            "search": "acme",
            "sort_by": "createdAt",
            "sort_order": "asc",
            "agency_id": "11111111-1111-1111-1111-111111111111",
        },
    )

    assert seen_params["search"] == "acme"
    assert seen_params["assessmentSortBy"] == "createdAt"
    assert seen_params["sortOrder"] == "ASC"
    assert seen_params["agencyId"] == "11111111-1111-1111-1111-111111111111"


# -- TC-TLV-003 / AC3: zero scans -> empty list + total 0, not an error --


@pytest.mark.asyncio
async def test_tc_tlv_003_list_external_scans_empty_tenant(mcp, monkeypatch):
    _mock_get(monkeypatch, lambda path, params: {"message": "ok", "assessments": [], "total": 0})
    result = await _call(mcp, "telivy_list_external_scans")
    assert result == {"items": [], "total": 0, "has_more": False}


# -- TC-TLV-004 / AC4: get scan detail --


@pytest.mark.asyncio
async def test_tc_tlv_004_get_external_scan_detail(mcp, monkeypatch):
    def handler(path, params):
        assert path == "/api/v1/security/external-scans/scan-1"
        return {"id": "scan-1", "domain": "acme.com", "scanStatus": "completed"}

    _mock_get(monkeypatch, handler)
    result = await _call(mcp, "telivy_get_external_scan", {"scan_id": "scan-1"})
    assert result == {"id": "scan-1", "domain": "acme.com", "scanStatus": "completed"}


# -- TC-TLV-005 / AC5: unknown/cross-tenant scan id -> structured not_found --


@pytest.mark.asyncio
async def test_tc_tlv_005_get_external_scan_not_found(mcp, monkeypatch):
    _mock_get_raises(monkeypatch, TelivyError(404, "External scan scan-x was not found."))
    result = await _call(mcp, "telivy_get_external_scan", {"scan_id": "scan-x"})
    assert result == {
        "error": {
            "code": "not_found",
            "message": "External scan scan-x was not found.",
            "retryable": False,
        }
    }


# -- TC-TLV-006 / AC6: scan findings, with and without a slug --


@pytest.mark.asyncio
async def test_tc_tlv_006_scan_findings_with_and_without_slug(mcp, monkeypatch):
    seen_paths = []

    def handler(path, params):
        seen_paths.append(path)
        if path.endswith("/findings"):
            return [{"id": "f1", "slug": "open-port", "severity": "high", "title": "Open port 22"}]
        return {"slug": "open-port", "severity": "high", "description": "SSH port is reachable."}

    _mock_get(monkeypatch, handler)
    summary = await _call(mcp, "telivy_get_external_scan_findings", {"scan_id": "scan-1"})
    assert summary == [{"id": "f1", "slug": "open-port", "severity": "high", "title": "Open port 22"}]

    detail = await _call(mcp, "telivy_get_external_scan_findings", {"scan_id": "scan-1", "slug": "open-port"})
    assert detail["slug"] == "open-port"
    assert detail["description"] == "SSH port is reachable."

    assert seen_paths == [
        "/api/v1/security/external-scans/scan-1/findings",
        "/api/v1/security/external-scans/scan-1/findings/open-port",
    ]


# -- TC-TLV-007 / AC7: breach data, empty list is success not an error --


@pytest.mark.asyncio
async def test_tc_tlv_007_breach_data_empty_is_not_an_error(mcp, monkeypatch):
    _mock_get(monkeypatch, lambda path, params: [])
    result = await _call(mcp, "telivy_get_external_scan_breach_data", {"scan_id": "scan-1"})
    assert result == []


# -- TC-TLV-008 / AC8: list risk assessments, filtered + bounded + total --


@pytest.mark.asyncio
async def test_tc_tlv_008_list_risk_assessments_filtered(mcp, monkeypatch):
    seen_params = {}

    def handler(path, params):
        seen_params.update(params)
        return {"message": "ok", "assessments": [{"id": "ra-1"}], "total": 1}

    _mock_get(monkeypatch, handler)
    result = await _call(
        mcp,
        "telivy_list_risk_assessments",
        {
            "search": "acme",
            "scan_status": ["in_progress", "report_completed"],
            "sort_by": "updatedAt",
            "sort_order": "desc",
            "offset": 0,
            "limit": 10,
        },
    )

    assert result == {"items": [{"id": "ra-1"}], "total": 1, "has_more": False}
    assert seen_params["scanStatus"] == ["in_progress", "report_completed"]
    assert seen_params["assessmentSortBy"] == "updatedAt"
    assert seen_params["sortOrder"] == "DESC"
    assert seen_params["limit"] == 10


# -- TC-TLV-009 / AC9: assessment detail + lighter scan-status call --


@pytest.mark.asyncio
async def test_tc_tlv_009_assessment_detail_and_scan_status(mcp, monkeypatch):
    def handler(path, params):
        if path.endswith("/scan-status"):
            return {"scanStatus": "in_progress"}
        return {"id": "ra-1", "scanStatus": "in_progress", "organizationName": "Acme"}

    _mock_get(monkeypatch, handler)
    detail = await _call(mcp, "telivy_get_risk_assessment", {"assessment_id": "ra-1"})
    status = await _call(mcp, "telivy_get_risk_assessment_scan_status", {"assessment_id": "ra-1"})

    assert detail["id"] == "ra-1"
    assert status == {"scanStatus": "in_progress"}


# -- TC-TLV-010 / AC10: devices, with and without a device id --


@pytest.mark.asyncio
async def test_tc_tlv_010_devices_list_and_detail(mcp, monkeypatch):
    seen_paths = []

    def handler(path, params):
        seen_paths.append(path)
        if path.endswith("/devices"):
            return [{"id": "dev-1", "hostname": "PC1"}]
        return {"id": "dev-1", "hostname": "PC1", "os": "Windows 11"}

    _mock_get(monkeypatch, handler)
    devices = await _call(mcp, "telivy_list_risk_assessment_devices", {"assessment_id": "ra-1"})
    assert devices == [{"id": "dev-1", "hostname": "PC1"}]

    device = await _call(
        mcp, "telivy_list_risk_assessment_devices", {"assessment_id": "ra-1", "device_id": "dev-1"}
    )
    assert device["os"] == "Windows 11"
    assert seen_paths == [
        "/api/v1/security/risk-assessments/ra-1/devices",
        "/api/v1/security/risk-assessments/ra-1/devices/dev-1",
    ]


# -- TC-TLV-011 / AC11: device-level findings --


@pytest.mark.asyncio
async def test_tc_tlv_011_assessment_device_findings(mcp, monkeypatch):
    _mock_get(monkeypatch, lambda path, params: [{"id": "f1", "deviceId": "dev-1"}])
    result = await _call(mcp, "telivy_get_risk_assessment_findings", {"assessment_id": "ra-1"})
    assert result == [{"id": "f1", "deviceId": "dev-1"}]


# -- TC-TLV-012 / AC12: PII summary --


@pytest.mark.asyncio
async def test_tc_tlv_012_pii_summary(mcp, monkeypatch):
    _mock_get(monkeypatch, lambda path, params: {"totalPiiRecords": 42})
    result = await _call(mcp, "telivy_get_risk_assessment_pii_summary", {"assessment_id": "ra-1"})
    assert result == {"totalPiiRecords": 42}


# -- TC-TLV-013 / AC13: directory users for m365 and google_workspace --


@pytest.mark.asyncio
async def test_tc_tlv_013_directory_users_both_providers(mcp, monkeypatch):
    seen_paths = []

    def handler(path, params):
        seen_paths.append(path)
        return {"users": []}

    _mock_get(monkeypatch, handler)
    await _call(mcp, "telivy_get_risk_assessment_directory_users", {"assessment_id": "ra-1", "provider": "m365"})
    await _call(
        mcp,
        "telivy_get_risk_assessment_directory_users",
        {"assessment_id": "ra-1", "provider": "google_workspace"},
    )

    assert seen_paths == [
        "/api/v1/security/risk-assessments/ra-1/m365-users",
        "/api/v1/security/risk-assessments/ra-1/gws-users",
    ]


# -- TC-TLV-014 / AC13: unrecognized provider -> structured invalid_argument --


@pytest.mark.asyncio
async def test_tc_tlv_014_directory_users_invalid_provider(mcp, monkeypatch):
    called_paths = []

    def handler(path, params):
        called_paths.append(path)
        return {"users": []}

    _mock_get(monkeypatch, handler)
    result = await _call(
        mcp,
        "telivy_get_risk_assessment_directory_users",
        {"assessment_id": "ra-1", "provider": "dropbox"},
    )

    assert result == {
        "error": {
            "code": "invalid_argument",
            "message": "Unrecognized provider 'dropbox'; expected one of ['google_workspace', 'm365'].",
            "retryable": False,
        }
    }
    # Never reached Telivy for a request we already know is malformed.
    assert called_paths == []


# -- TC-TLV-015 / AC14: finding reference by slug, independent of any scan --


@pytest.mark.asyncio
async def test_tc_tlv_015_finding_reference(mcp, monkeypatch):
    def handler(path, params):
        assert path == "/api/v1/security/findings/open-port"
        return {"slug": "open-port", "title": "Open port", "remediation": "Close the port or firewall it."}

    _mock_get(monkeypatch, handler)
    result = await _call(mcp, "telivy_get_finding_reference", {"slug": "open-port"})
    assert result["slug"] == "open-port"
    assert "remediation" in result


# -- TC-TLV-016 / AC15: risk progress report, single snapshot vs comparison --


@pytest.mark.asyncio
async def test_tc_tlv_016_risk_progress_report(mcp, monkeypatch):
    seen_params = []

    def handler(path, params):
        assert path == "/api/v1/security/ra-1/risk"
        seen_params.append(params)
        return {"snapshot": True, "compared": params.get("compareWithTimestampGroup") is not None}

    _mock_get(monkeypatch, handler)
    single = await _call(
        mcp, "telivy_get_risk_progress_report", {"entity_id": "ra-1", "current_timestamp_group": "2026-10"}
    )
    comparison = await _call(
        mcp,
        "telivy_get_risk_progress_report",
        {
            "entity_id": "ra-1",
            "current_timestamp_group": "2026-10",
            "compare_with_timestamp_group": "2026-09",
        },
    )

    assert single["compared"] is False
    assert comparison["compared"] is True
    assert seen_params[0]["currentTimestampGroup"] == "2026-10"
    assert seen_params[1]["compareWithTimestampGroup"] == "2026-09"


# -- TC-TLV-018 / AC17 (tool-level support): per-context client instances --
# The ASGI-level concurrency test lives in test_middleware.py; this confirms
# the tool layer's client_factory() builds a fresh, independent client
# scoped to whatever is in the contextvar at call time -- no module-level
# cache keyed by anything other than the current context.


def test_tc_tlv_018_client_factory_is_context_scoped():
    token_a = _gateway_api_key_var.set("tenant-a-key")
    client_a = get_client_from_context()
    _gateway_api_key_var.reset(token_a)

    token_b = _gateway_api_key_var.set("tenant-b-key")
    client_b = get_client_from_context()
    _gateway_api_key_var.reset(token_b)

    assert client_a._api_key == "tenant-a-key"
    assert client_b._api_key == "tenant-b-key"
    assert client_a is not client_b


# -- TC-TLV-020 / AC19: limit clamping + char-budget truncation with has_more --


@pytest.mark.parametrize(
    "given,expected",
    [(None, 50), (1, 1), (50, 50), (200, 200), (201, 200), (100_000, 200)],
)
def test_tc_tlv_020_clamp_limit(given, expected):
    assert clamp_limit(given) == expected


@pytest.mark.asyncio
async def test_tc_tlv_020_list_tool_sends_clamped_limit(mcp, monkeypatch):
    seen_params = {}

    def handler(path, params):
        seen_params.update(params)
        return {"assessments": [], "total": 0}

    _mock_get(monkeypatch, handler)
    await _call(mcp, "telivy_list_external_scans", {"limit": 5000})
    assert seen_params["limit"] == 200  # hard cap, never Telivy's own 100 default or the caller's 5000


def test_tc_tlv_020_dump_json_capped_truncates_with_has_more():
    big_items = [{"id": f"item-{i}", "note": "x" * 100} for i in range(1000)]
    payload = {"items": big_items, "total": len(big_items)}

    out = dump_json_capped(payload, max_chars=2_000)
    parsed = json.loads(out)

    assert len(out) <= 2_000
    assert parsed["truncated"] is True
    assert parsed["has_more"] is True
    assert parsed["original_count"] == 1000
    assert len(parsed["items"]) < 1000  # some items dropped, not silently -- has_more says so


def test_tc_tlv_020_dump_json_capped_passthrough_when_small():
    payload = {"items": [{"id": "only-one"}], "total": 1}
    out = dump_json_capped(payload, max_chars=20_000)
    assert json.loads(out) == payload
    assert "truncated" not in out
