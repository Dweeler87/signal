"""
GET /v1/signals — list signals with filtering and cursor pagination.

Filters (all optional, combinable):
  ?type=new_apex_domain
  ?domain=example.com
  ?apex_domain=example.com
  ?industry=technology
  ?saas_vendor=shopify
  ?hosting_provider=AWS
  ?since=2026-01-01T00:00:00Z    (ISO 8601)
  ?cursor=<opaque>               (from previous response.next_cursor)
  ?limit=100                     (default 100, max 1000)

Cursor format: base64(detected_at_iso)
Results are ordered by detected_at DESC (newest first).

Clay-friendly: flat JSON, no nested objects, consistent field names.
"""

import base64
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query

from api.deps import authenticated_key, get_ch
from api.schemas import SignalListResponse, SignalOut
from signals.watchlist import filter_signals_for_key
from signals.types import Signal, SignalType

router = APIRouter(prefix="/v1/signals", tags=["signals"])

# Signal types gated to buyer_verified=true (phishing-adjacent)
RESTRICTED_SIGNAL_TYPES = set()  # extend in Phase 5


@router.get("", response_model=SignalListResponse)
def list_signals(
    type: str | None = Query(default=None, description="Filter by signal_type"),
    domain: str | None = Query(default=None, description="Exact domain match"),
    apex_domain: str | None = Query(default=None),
    industry: str | None = Query(default=None, description="company_industry contains"),
    saas_vendor: str | None = Query(default=None),
    hosting_provider: str | None = Query(default=None),
    since: datetime | None = Query(default=None, description="ISO 8601 timestamp"),
    cursor: str | None = Query(default=None, description="Pagination cursor from next_cursor"),
    limit: int = Query(default=100, ge=1, le=1000),
    key: dict = Depends(authenticated_key),
    ch=Depends(get_ch),
):
    # Build WHERE clauses
    conditions = []
    params: dict = {}

    if type:
        conditions.append("signal_type = %(type)s")
        params["type"] = type

    if domain:
        conditions.append("domain = %(domain)s")
        params["domain"] = domain

    if apex_domain:
        conditions.append("apex_domain = %(apex_domain)s")
        params["apex_domain"] = apex_domain

    if industry:
        conditions.append("lower(company_industry) = %(industry)s")
        params["industry"] = industry.lower()

    if saas_vendor:
        conditions.append("lower(saas_vendor) = %(saas_vendor)s")
        params["saas_vendor"] = saas_vendor.lower()

    if hosting_provider:
        conditions.append("lower(hosting_provider) = %(hosting_provider)s")
        params["hosting_provider"] = hosting_provider.lower()

    if since:
        conditions.append("detected_at >= %(since)s")
        params["since"] = since.replace(tzinfo=None) if since.tzinfo else since

    # Cursor pagination (detected_at DESC)
    if cursor:
        try:
            cursor_dt = datetime.fromisoformat(
                base64.b64decode(cursor.encode()).decode()
            )
            conditions.append("detected_at < %(cursor_dt)s")
            params["cursor_dt"] = cursor_dt.replace(tzinfo=None)
        except Exception:
            pass  # invalid cursor → ignore and start from the top

    where = "WHERE " + " AND ".join(conditions) if conditions else ""

    # Total count (without cursor so callers know overall size)
    count_where = "WHERE " + " AND ".join(
        c for c in conditions if "cursor_dt" not in c
    ) if any("cursor_dt" not in c for c in conditions) else ""
    count_params = {k: v for k, v in params.items() if k != "cursor_dt"}
    total_row = ch.query(
        f"SELECT count() FROM signal.signals {count_where}",
        parameters=count_params,
    ).result_rows
    total = total_row[0][0] if total_row else 0

    # Fetch one extra to detect if there's a next page
    rows = ch.query(
        f"""
        SELECT
            signal_id, signal_type, domain, apex_domain, detected_at,
            hosting_provider, saas_vendor,
            company_name, company_industry
        FROM signal.signals
        {where}
        ORDER BY detected_at DESC
        LIMIT %(limit)s
        """,
        parameters={**params, "limit": limit + 1},
    ).result_rows

    has_more = len(rows) > limit
    rows = rows[:limit]

    signals_out = [
        SignalOut(
            signal_id=row[0],
            signal_type=row[1],
            domain=row[2],
            apex_domain=row[3],
            detected_at=row[4],
            hosting_provider=row[5] or None,
            saas_vendor=row[6] or None,
            company_name=row[7] or None,
            company_industry=row[8] or None,
        )
        for row in rows
    ]

    # Watchlist filtering: if key has watchlists, filter signals to matching ones
    watchlist_rows = ch.query(
        "SELECT pattern_type, pattern FROM signal.watchlists WHERE key_hash = %(h)s AND active = true",
        parameters={"h": key["key_hash"]},
    ).result_rows

    if watchlist_rows:
        # Convert to Signal objects for watchlist matching
        from signals.types import Signal as SigObj, SignalType as ST
        sig_objs = []
        for s in signals_out:
            try:
                sig_objs.append(SigObj(
                    signal_type=ST(s.signal_type),
                    domain=s.domain,
                    apex_domain=s.apex_domain,
                    cert_sha256_tbs=b"\x00" * 32,
                    detected_at=s.detected_at,
                    company_name=s.company_name,
                    company_industry=s.company_industry,
                    hosting_provider=s.hosting_provider,
                    saas_vendor=s.saas_vendor,
                ))
            except Exception:
                pass

        from signals.watchlist import filter_signals_for_key as wl_filter
        filtered = wl_filter(sig_objs, [(r[0], r[1]) for r in watchlist_rows])
        filtered_domains = {s.domain for s in filtered}
        signals_out = [s for s in signals_out if s.domain in filtered_domains]

    next_cursor: str | None = None
    if has_more and rows:
        last_dt = rows[-1][4]
        if hasattr(last_dt, "isoformat"):
            next_cursor = base64.b64encode(last_dt.isoformat().encode()).decode()

    return SignalListResponse(data=signals_out, next_cursor=next_cursor, total=total)
