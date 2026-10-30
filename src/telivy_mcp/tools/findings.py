from collections.abc import Callable
from typing import Annotated

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from .._json import dump_json_capped
from ..api_client import TelivyClient, TelivyError
from ._common import NO_TOKEN

SlugParam = Annotated[
    str,
    Field(description="A finding type's slug (e.g. from a scan/assessment findings list)."),
]


def register(mcp: FastMCP, client_factory: Callable[[], TelivyClient | None]) -> None:
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def telivy_get_finding_reference(slug: SlugParam) -> str:
        """General definition and remediation text for a finding type, by slug.

        Independent of any one scan or assessment instance — use this to
        look up what a finding type means in general, after seeing its slug
        in a scan's or assessment's findings list.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.get(f"/api/v1/security/findings/{slug}")
            return dump_json_capped(result)
        except TelivyError as e:
            return e.to_envelope()
