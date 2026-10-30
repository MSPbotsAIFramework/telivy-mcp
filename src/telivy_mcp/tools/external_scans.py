from collections.abc import Callable
from typing import Annotated

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from .._json import dump_json_capped
from ..api_client import TelivyClient, TelivyError
from ._common import (
    NO_TOKEN,
    AgencyIdParam,
    LimitParam,
    OffsetParam,
    SearchParam,
    SortByParam,
    SortOrderParam,
    clamp_limit,
    paged,
    sort_order_upper,
)

ScanIdParam = Annotated[str, Field(description="The external scan's id, from telivy_list_external_scans.")]
FindingSlugParam = Annotated[
    str | None,
    Field(description="A specific finding's slug (from the findings summary list). Omit to get the summary list."),
]


def register(mcp: FastMCP, client_factory: Callable[[], TelivyClient | None]) -> None:
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def telivy_list_external_scans(
        search: SearchParam = None,
        sort_by: SortByParam = None,
        sort_order: SortOrderParam = None,
        agency_id: AgencyIdParam = None,
        offset: OffsetParam = None,
        limit: LimitParam = None,
    ) -> str:
        """List the calling tenant's external attack-surface scans.

        Each item has at minimum id, organization name, domain, status, and
        created/updated timestamps. Never returns another tenant's scans.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        effective_limit = clamp_limit(limit)
        params = {
            "search": search,
            "assessmentSortBy": sort_by,
            "sortOrder": sort_order_upper(sort_order),
            "agencyId": agency_id,
            "offset": offset,
            "limit": effective_limit,
        }
        try:
            result = await client.get("/api/v1/security/external-scans", params=params)
            return dump_json_capped(paged(result, offset, effective_limit))
        except TelivyError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def telivy_get_external_scan(scan_id: ScanIdParam) -> str:
        """Full detail for one external attack-surface scan.

        Returns a structured not_found error (not another tenant's data) if
        the id doesn't exist or belongs to another tenant's key.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.get(f"/api/v1/security/external-scans/{scan_id}")
            return dump_json_capped(result)
        except TelivyError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def telivy_get_external_scan_findings(
        scan_id: ScanIdParam,
        slug: FindingSlugParam = None,
    ) -> str:
        """Security findings for one external scan.

        Without slug: a summary list (id, slug, severity, title) of the
        scan's findings. With slug: that one finding's full detail for this
        scan (see telivy_get_finding_reference for the slug's general
        definition, independent of any scan instance).
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        path = f"/api/v1/security/external-scans/{scan_id}/findings"
        if slug:
            path = f"{path}/{slug}"
        try:
            result = await client.get(path)
            return dump_json_capped(result)
        except TelivyError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def telivy_get_external_scan_breach_data(scan_id: ScanIdParam) -> str:
        """Breach records tied to one external scan.

        An empty list is a valid result when no breach data exists for the
        scan — not an error.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.get(f"/api/v1/security/external-scans/{scan_id}/breach-data")
            return dump_json_capped(result)
        except TelivyError as e:
            return e.to_envelope()
