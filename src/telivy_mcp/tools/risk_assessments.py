from collections.abc import Callable
from typing import Annotated

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from .._json import dump_json_capped, error_envelope
from ..api_client import TelivyClient, TelivyError
from ._common import (
    NO_TOKEN,
    AgencyIdParam,
    LimitParam,
    OffsetParam,
    ScanStatusParam,
    SearchParam,
    SortByParam,
    SortOrderParam,
    clamp_limit,
    paged,
    sort_order_upper,
)

AssessmentIdParam = Annotated[
    str, Field(description="The risk assessment's id, from telivy_list_risk_assessments.")
]
DeviceIdParam = Annotated[
    str | None,
    Field(description="A specific device's id (from the device list). Omit to get the device list."),
]
ProviderParam = Annotated[
    str,
    Field(
        description=(
            "Which directory to pull user-exposure data from. Must be exactly 'm365' or "
            "'google_workspace'; any other value returns a structured invalid_argument error "
            "(not a protocol-level rejection) so the agent can see why."
        )
    ),
]

_PROVIDER_PATH = {"m365": "m365-users", "google_workspace": "gws-users"}


def register(mcp: FastMCP, client_factory: Callable[[], TelivyClient | None]) -> None:
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def telivy_list_risk_assessments(
        search: SearchParam = None,
        scan_status: ScanStatusParam = None,
        sort_by: SortByParam = None,
        sort_order: SortOrderParam = None,
        agency_id: AgencyIdParam = None,
        offset: OffsetParam = None,
        limit: LimitParam = None,
    ) -> str:
        """List the calling tenant's deep-scan risk assessments."""
        client = client_factory()
        if client is None:
            return NO_TOKEN
        effective_limit = clamp_limit(limit)
        params = {
            "search": search,
            "scanStatus": scan_status,
            "assessmentSortBy": sort_by,
            "sortOrder": sort_order_upper(sort_order),
            "agencyId": agency_id,
            "offset": offset,
            "limit": effective_limit,
        }
        try:
            result = await client.get("/api/v1/security/risk-assessments", params=params)
            return dump_json_capped(paged(result, offset, effective_limit))
        except TelivyError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def telivy_get_risk_assessment(assessment_id: AssessmentIdParam) -> str:
        """Full detail for one deep-scan risk assessment.

        See telivy_get_risk_assessment_scan_status for a lighter call that
        only reports whether the scan is done.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.get(f"/api/v1/security/risk-assessments/{assessment_id}")
            return dump_json_capped(result)
        except TelivyError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def telivy_get_risk_assessment_scan_status(assessment_id: AssessmentIdParam) -> str:
        """Current scan-status snapshot for one risk assessment.

        A lighter call than telivy_get_risk_assessment for an agent that
        only needs to know "is it done yet".
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.get(f"/api/v1/security/risk-assessments/{assessment_id}/scan-status")
            return dump_json_capped(result)
        except TelivyError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def telivy_list_risk_assessment_devices(
        assessment_id: AssessmentIdParam,
        device_id: DeviceIdParam = None,
    ) -> str:
        """Devices under one risk assessment.

        Without device_id: the device list. With device_id: that one
        device's detail.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        path = f"/api/v1/security/risk-assessments/{assessment_id}/devices"
        if device_id:
            path = f"{path}/{device_id}"
        try:
            result = await client.get(path)
            return dump_json_capped(result)
        except TelivyError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def telivy_get_risk_assessment_findings(assessment_id: AssessmentIdParam) -> str:
        """Device-level security findings for one risk assessment."""
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.get(f"/api/v1/security/risk-assessments/{assessment_id}/findings")
            return dump_json_capped(result)
        except TelivyError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def telivy_get_risk_assessment_pii_summary(assessment_id: AssessmentIdParam) -> str:
        """PII-exposure summary for one risk assessment."""
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.get(f"/api/v1/security/risk-assessments/{assessment_id}/pii-summary")
            return dump_json_capped(result)
        except TelivyError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def telivy_get_risk_assessment_directory_users(
        assessment_id: AssessmentIdParam,
        provider: ProviderParam,
    ) -> str:
        """Directory-user exposure data for one risk assessment.

        provider selects which directory was assessed: m365 (Microsoft 365)
        or google_workspace.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        sub_path = _PROVIDER_PATH.get(provider)
        if sub_path is None:
            return error_envelope(
                "invalid_argument",
                f"Unrecognized provider {provider!r}; expected one of {sorted(_PROVIDER_PATH)}.",
                False,
            )
        try:
            result = await client.get(f"/api/v1/security/risk-assessments/{assessment_id}/{sub_path}")
            return dump_json_capped(result)
        except TelivyError as e:
            return e.to_envelope()
