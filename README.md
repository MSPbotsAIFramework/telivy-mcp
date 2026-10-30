# telivy-mcp

MCP server for **Telivy** — a third-party security-scanning vendor: external
attack-surface scanning plus an agent-based "deep scan" risk assessment
product. Exposes Telivy's read-only Security API (scans, risk assessments,
findings) as MCP tools. No write/action tools in v1 (see Scope).

<div align="center">

## MSPbots Connector

**The MCP Gateway built for MSPs: visible, controlled, and your data stays where it belongs.**

[**Get started at connect.mspbots.ai →**](https://connect.mspbots.ai)

</div>

---

MSPbots Connector gives your AI clients one MCP URL to reach your entire MSP stack (RMM, PSA, documentation, security, finance), and gives you control over who can call which tool and a record of everything that was called.

**Hosted service: [connect.mspbots.ai](https://connect.mspbots.ai)** · Free to use.

### Why Connector

![MSPbots Connector](https://stgoss.mspbots.ai/files/mcp/mspbots-mcp.png)

| | |
|---|---|
| **Visible** | Every tool call is logged: who, which vendor, when. Usage dashboard, CSV export, SIEM streaming. |
| **Controlled** | Role-based, per-tool allowlist. Deny by default. |
| **Protected** | Credentials encrypted per record. AI clients never see your vendor passwords or tokens. |
| **MSP-native** | Built for the MSP stack only: RMM, PSA, documentation, security, finance. |

### Quick start

1. **Sign up** at [connect.mspbots.ai](https://connect.mspbots.ai).
2. **Connect your vendors.** Pick from 150+ connectors and authorize each one on the vendor's own page, or bring your own API keys. No extra vendor accounts needed.
3. **Set access.** Create roles and decide which tools each role may call. Nothing is allowed until you allow it.
4. **Add your MCP URL to your AI client.** Copy the URL from your Connector dashboard into Claude, ChatGPT, Cursor, VS Code, Gemini, Codex, or any MCP-capable client.
5. **Ask your AI to do real work**, and watch every call appear in the audit log.

### Features

**Unified gateway**
- One MCP URL for all your AI clients
- 150+ connectors across the MSP stack
- Custom MCP servers supported, free
- Authorization happens on each vendor's own page; the AI never sees passwords or tokens
- Bring your own credentials: use the vendor API keys you already have
- Multiple accounts per app; connect once, reuse across AI clients
- Tool search: finds the right action for the task
- One sign-in; vendor credentials are injected behind the scenes and OAuth tokens refresh automatically

**Visibility**
- Audit log for every tool call (who, which vendor, when)
- Usage dashboard: call volume, top vendors, error rate, per-user activity
- Export audit logs to CSV, or stream to Loki, Graylog, or LogScale (SIEM)
- Optional recording of tool arguments and result summaries (off by default, enabled per organization)

**Control**
- Per-role, per-tool allowlist, deny by default
- owner / admin / member roles
- SCIM provisioning with Entra ID, Okta, JumpCloud, and Google Workspace

**Security**
- Credentials encrypted one record at a time (AES-256-GCM, per-record key)
- AI clients authenticate with OAuth 2.1 + PKCE
- Vendor responses are scanned for prompt-injection patterns and returned as structured data. This is one layer of defense, not a guarantee against every attack.
- Static egress IP for customer firewall and API allowlisting

### Pricing

**Free.**

Links: [connect.mspbots.ai](https://connect.mspbots.ai) · [mspbots.ai](https://mspbots.ai)

---

## Overview

- Stateless HTTP service. No credentials are ever persisted — each request
  supplies its own via a header, used only for the lifetime of that single
  request.
- Supports concurrent requests; per-request credential isolation is done via
  Python `contextvars`, not a global/shared client instance.
- Entry points: `POST /mcp` (MCP protocol) and `GET /health` (health check).
- Default port: `8080` (configurable via `MCP_HTTP_PORT`).

## Scope

**13 read-only tools** over Telivy's Security API, covering external
attack-surface scans and deep-scan risk assessments. No write/action tools
(create/update a scan or assessment, rescan, uninstall the deep-scan agent,
convert-to-risk-assessment, end-trial, monitoring-settings) and no
report-binary (PDF/DOCX) downloads — see Known Gaps for why.

## Authentication

Telivy exposes three auth mechanisms (static API key, OAuth2/Auth0 implicit
flow, JWT bearer); this connector uses the **static API key** path, since
that's what MSP integrations use.

### HEADER Authentication Parameters

| Header | Type | Required | Default | Allowed values | Description | Example |
|---|---|---|---|---|---|---|
| `X-Telivy-Api-Key` | string | Yes | None | None | The tenant's Telivy Security API key, forwarded upstream as-is as Telivy's own `x-api-key` header | `tlv_live_xxx` |

Missing the header returns `401`:
```json
{
  "error": "Missing credentials",
  "message": "This server requires the X-Telivy-Api-Key header",
  "required_headers": ["X-Telivy-Api-Key"],
  "optional_headers": []
}
```

Get it from: Telivy account → API settings.

## Environment Variables

| Variable | Type | Required | Default | Description |
|---|---|---|---|---|
| `MCP_HTTP_PORT` | int | No | `8080` | HTTP listen port |
| `MCP_HTTP_HOST` | string | No | `0.0.0.0` | HTTP listen address |

## MCP Endpoint

- `POST /mcp` — MCP protocol (streamable HTTP transport)
- `GET /health` — health check, returns `{"status": "ok"}`

## Tool List

Every list-style tool returns `{items: [...], total, has_more}`; the
effective page size defaults to 50 and is capped at 200 regardless of what's
requested (token economy, independent of whatever Telivy's own API would
allow). Get-by-id tools take a required id parameter.

| Category | Tool | Description | Params |
|---|---|---|---|
| external_scans | `telivy_list_external_scans` | List the calling tenant's external attack-surface scans. | search?, sort_by?, sort_order?, agency_id?, offset?, limit? |
| external_scans | `telivy_get_external_scan` | Full detail for one external scan. | scan_id |
| external_scans | `telivy_get_external_scan_findings` | Findings summary list, or one finding's detail when a slug is given. | scan_id, slug? |
| external_scans | `telivy_get_external_scan_breach_data` | Breach records for one scan (empty list if none). | scan_id |
| risk_assessments | `telivy_list_risk_assessments` | List the calling tenant's deep-scan risk assessments. | search?, scan_status?, sort_by?, sort_order?, agency_id?, offset?, limit? |
| risk_assessments | `telivy_get_risk_assessment` | Full detail for one risk assessment. | assessment_id |
| risk_assessments | `telivy_get_risk_assessment_scan_status` | Current scan-status snapshot (lighter than full detail). | assessment_id |
| risk_assessments | `telivy_list_risk_assessment_devices` | Device list, or one device's detail when a device_id is given. | assessment_id, device_id? |
| risk_assessments | `telivy_get_risk_assessment_findings` | Device-level security findings for one assessment. | assessment_id |
| risk_assessments | `telivy_get_risk_assessment_pii_summary` | PII-exposure summary for one assessment. | assessment_id |
| risk_assessments | `telivy_get_risk_assessment_directory_users` | Directory-user exposure for m365 or google_workspace. | assessment_id, provider |
| findings | `telivy_get_finding_reference` | General definition/remediation text for a finding type, by slug. | slug |
| risk_report | `telivy_get_risk_progress_report` | Risk trend snapshot, or a comparison across two points in time. | entity_id, current_timestamp_group, compare_with_timestamp_group? |

## Test Example

```bash
# Health check
curl -s http://localhost:8080/health

# Call a tool via the MCP protocol (streamable HTTP) — requires an
# initialize handshake first per the MCP spec; abbreviated example below
# shows the tool-call request body only:
curl -s -X POST http://localhost:8080/mcp \
  -H "X-Telivy-Api-Key: <api-key>" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "mcp-session-id: <session-id-from-initialize>" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "telivy_list_external_scans",
      "arguments": {}
    }
  }'
```

Expected: `200` with the tenant's scan list on a valid key; `401`
(`{"error":{"code":"unauthorized",...}}`) on an invalid key.

**No test account available yet** — self-test for this version covers every
acceptance criterion except the one end-to-end case that needs a live key
(TC-TLV-021 in the ticket's test ledger), which is flagged "needs a real
vendor account" and does not block this release per the vendor-mcp SOP's
completion criteria.

## API Reference

- Human docs: https://api-v1.telivy.com/api-docs/security
- OpenAPI spec: https://api-v1.telivy.com/api-docs/security-json

## Known Gaps

- **Write/action endpoints are out of scope by design** (not a gap to be
  filled later without a product decision): create/update a scan or
  assessment, rescan, uninstall the deep-scan agent, convert-to-risk-assessment,
  end-trial, monitoring-settings. See PRD-21245's "Decisions made by DEV01".
- **Report-binary (PDF/DOCX) downloads are excluded** — Telivy returns these
  as raw binary files, which doesn't fit an MCP tool's token-economy
  contract. A report-export tool can be added on request if a future ticket
  names that need explicitly.
- **Agent-installer version metadata (`/security/agent-versions`) is
  excluded** — it serves the deep-scan agent's own installer, not a reviewer
  of findings.
- **`agency_id` tenant-boundary assumption**: this connector treats the
  calling API key as the entire tenant boundary, and exposes `agency_id` as
  an optional filter *within* that key's own scope, not a second credential.
  If a real account later shows one key can see agencies outside the
  intended tenant, this would need a per-tenant allow-list — flag it back to
  design if discovered.
- Response field shapes are whatever Telivy's OpenAPI spec documents for
  each endpoint, passed through largely as-is (trimmed only by the shared
  page/size budget) rather than independently re-verified field-by-field.
