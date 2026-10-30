import contextvars
from collections.abc import Callable

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .api_client import TelivyClient
from .config import Settings

# Per-request credential isolation via contextvars.
# GatewayTokenMiddleware sets this before the MCP handler runs.
# Python asyncio copies context per task, so concurrent SSE connections are
# isolated (this is what AC17 / TC-TLV-018 exercises).
_gateway_api_key_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "telivy_gateway_api_key", default=None
)


def get_client_from_context() -> TelivyClient | None:
    """Resolve the active TelivyClient for the current request context."""
    api_key = _gateway_api_key_var.get()
    if not api_key:
        return None
    return TelivyClient(api_key)


class GatewayTokenMiddleware:
    """ASGI middleware.

    Reads X-Telivy-Api-Key (the only credential this connector needs — see
    SOP §3.1 "one credential field, one Header") from request headers and
    stores it in the contextvar. Returns 401 if missing on /mcp requests,
    before any outbound call to Telivy is made (AC16 / TC-TLV-017).
    """

    def __init__(self, app: ASGIApp, settings: Settings):
        self.app = app
        self.settings = settings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if not path.startswith("/mcp"):
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        api_key = request.headers.get("x-telivy-api-key")
        if not api_key:
            response = JSONResponse(
                {
                    "error": "Missing credentials",
                    "message": "This server requires the X-Telivy-Api-Key header",
                    "required_headers": ["X-Telivy-Api-Key"],
                    "optional_headers": [],
                },
                status_code=401,
            )
            await response(scope, receive, send)
            return

        ctx_token = _gateway_api_key_var.set(api_key)
        try:
            await self.app(scope, receive, send)
        finally:
            _gateway_api_key_var.reset(ctx_token)


def create_mcp_server(settings: Settings) -> FastMCP:
    """Build the FastMCP server instance and register all Telivy tools."""
    # DNS-rebinding protection is a browser-oriented safeguard that rejects
    # non-localhost Host headers with 421. Disable it so the server works
    # correctly behind a reverse proxy or docker network.
    mcp = FastMCP(
        name="telivy-mcp",
        instructions=(
            "Telivy is a third-party security-scanning vendor: external "
            "attack-surface scanning plus an agent-based 'deep scan' risk "
            "assessment product. All 13 tools are read-only queries over a "
            "tenant's own Telivy data; there are no write/action tools "
            "(no create/update/rescan/uninstall/convert/end-trial/settings "
            "calls) in this service. Tool groups: external_scans "
            "(telivy_list_external_scans to find a scan id, then "
            "telivy_get_external_scan / _findings / _breach_data for detail); "
            "risk_assessments (telivy_list_risk_assessments to find an "
            "assessment id, then telivy_get_risk_assessment / "
            "_scan_status / _devices / _findings / _pii_summary / "
            "_directory_users for detail); telivy_get_finding_reference for "
            "a finding type's general definition independent of any scan "
            "instance; telivy_get_risk_progress_report for a risk trend over "
            "time. Typical flow: list, then pass the returned id(s) into the "
            "detail tools."
        ),
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        stateless_http=True,
        json_response=True,
    )

    client_factory: Callable[[], TelivyClient | None] = get_client_from_context

    from .tools import external_scans, findings, risk_assessments, risk_report

    external_scans.register(mcp, client_factory)
    risk_assessments.register(mcp, client_factory)
    findings.register(mcp, client_factory)
    risk_report.register(mcp, client_factory)

    return mcp
