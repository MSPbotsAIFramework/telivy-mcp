from collections.abc import Callable
from typing import Annotated

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from .._json import dump_json_capped
from ..api_client import TelivyClient, TelivyError
from ._common import NO_TOKEN

EntityIdParam = Annotated[
    str, Field(description="A scan id (from telivy_list_external_scans) or assessment id (from telivy_list_risk_assessments).")
]
CurrentTimestampGroupParam = Annotated[
    str, Field(description="The timestamp group to report risk for (Telivy-defined grouping key).")
]
CompareWithTimestampGroupParam = Annotated[
    str | None,
    Field(description="A second timestamp group to compare against. Omit for a single snapshot."),
]


def register(mcp: FastMCP, client_factory: Callable[[], TelivyClient | None]) -> None:
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def telivy_get_risk_progress_report(
        entity_id: EntityIdParam,
        current_timestamp_group: CurrentTimestampGroupParam,
        compare_with_timestamp_group: CompareWithTimestampGroupParam = None,
    ) -> str:
        """Risk trend/progress report for a scan or assessment.

        With only current_timestamp_group: a single snapshot at that point.
        With compare_with_timestamp_group too: the trend comparison between
        the two points in time.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        params = {
            "currentTimestampGroup": current_timestamp_group,
            "compareWithTimestampGroup": compare_with_timestamp_group,
        }
        try:
            result = await client.get(f"/api/v1/security/{entity_id}/risk", params=params)
            return dump_json_capped(result)
        except TelivyError as e:
            return e.to_envelope()
