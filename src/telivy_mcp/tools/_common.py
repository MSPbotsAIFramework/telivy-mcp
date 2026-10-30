from typing import Annotated, Any, Literal

from pydantic import Field

from .._json import error_envelope

NO_TOKEN = error_envelope(
    "not_configured",
    "No Telivy credentials. Send the X-Telivy-Api-Key header.",
    False,
)

# Server-side defaults/caps (SOP §2.5 token economy): re-default below what
# Telivy itself would allow (Telivy's own list endpoints default to 100),
# and hard-cap regardless of what the caller asks for.
DEFAULT_LIMIT = 50
MAX_LIMIT = 200

SortOrder = Literal["asc", "desc"]
AssessmentSortBy = Literal["organizationName", "assessmentStatus", "createdAt", "updatedAt"]
ScanStatus = Literal["not_started", "in_progress", "report_completed", "archived"]

SearchParam = Annotated[
    str | None,
    Field(description="Free-text search, forwarded to Telivy's server-side filter."),
]
SortByParam = Annotated[
    AssessmentSortBy | None,
    Field(description="Field to sort by (default createdAt)."),
]
SortOrderParam = Annotated[
    SortOrder | None,
    Field(description="Sort direction (default desc)."),
]
AgencyIdParam = Annotated[
    str | None,
    Field(
        description=(
            "Filter to one agency (Telivy's agencyId, a UUID) within what this API key can "
            "already see. Not a second credential — a business-level filter inside the "
            "calling tenant's own scope."
        )
    ),
]
OffsetParam = Annotated[
    int | None,
    Field(ge=0, description="Zero-based offset: number of matching records to skip before the returned page."),
]
LimitParam = Annotated[
    int | None,
    Field(
        ge=1,
        description=f"Max records to return (default {DEFAULT_LIMIT}). Clamped to the hard cap of {MAX_LIMIT} regardless of the value passed.",
    ),
]
ScanStatusParam = Annotated[
    list[ScanStatus] | None,
    Field(description="Filter risk assessments to one or more scan-status values."),
]


def clamp_limit(limit: int | None) -> int:
    if limit is None:
        return DEFAULT_LIMIT
    return max(1, min(limit, MAX_LIMIT))


def paged(resp: Any, offset: int | None, limit: int) -> dict:
    """Normalize Telivy's {message, assessments, total} list envelope (the
    field is literally named "assessments" for both external-scan and
    risk-assessment list endpoints per Telivy's OpenAPI schema) into the
    {items, total, has_more} shape documented in the tool catalog (SOP §2.5
    "list tools return a bounded page plus a total count and has_more").
    """
    if not isinstance(resp, dict):
        return {"items": [], "total": 0, "has_more": False}
    items = resp.get("assessments")
    if items is None:
        items = resp.get("items", [])
    total = resp.get("total", len(items))
    has_more = (offset or 0) + len(items) < total
    return {"items": items, "total": total, "has_more": has_more}


def sort_order_upper(sort_order: SortOrder | None) -> str | None:
    return sort_order.upper() if sort_order else None
