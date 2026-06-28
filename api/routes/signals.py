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
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query, Response

from api.deps import authenticated_key, get_ch
from api.schemas import SignalListResponse, SignalOut

from signals.types import Signal, SignalType

router = APIRouter(prefix="/v1/signals", tags=["signals"])

# Signal types gated to buyer_verified=true (phishing-adjacent)
RESTRICTED_SIGNAL_TYPES = set()

# How far back each tier can query
TIER_LOOKBACK_DAYS: dict[str, int] = {
    "free": 1,
    "starter": 30,
    "pro": 90,
}

# Base scores by signal type (1-100)
_SIGNAL_SCORES: dict[str, int] = {
    "domain_velocity": 90,
    "geographic_expansion": 85,
    "fresh_domain": 80,
    "wildcard_cert_issued": 70,
    "saas_adoption_detected": 65,
    "infrastructure_expansion": 50,
    "new_apex_domain": 40,
    "new_subdomain": 20,
}

_SIGNAL_LABELS: dict[str, str] = {
    "domain_velocity": "3+ new domains in 7 days — acquisition, rebrand, or major launch",
    "geographic_expansion": "country-code domain registered — new geographic market entry",
    "fresh_domain": "domain registered ≤30 days before first cert — brand new company launching infrastructure",
    "wildcard_cert_issued": "wildcard cert issued — dynamic subdomain infrastructure build-out",
    "saas_adoption_detected": "SaaS platform adoption detected at cert issuance",
    "infrastructure_expansion": "5+ new subdomains in 24h — rapid infrastructure growth",
    "new_apex_domain": "new top-level domain registered",
    "new_subdomain": "new subdomain detected",
}


def _age_label(age: timedelta) -> tuple[str, int]:
    """Return (human label, recency boost)."""
    if age < timedelta(hours=1):
        return "detected <1h ago", 10
    if age < timedelta(hours=24):
        return f"detected {int(age.total_seconds() / 3600)}h ago", 10
    if age < timedelta(days=7):
        return f"detected {age.days}d ago", 5
    return f"detected {age.days}d ago", 0


def compute_score(signal_type: str, detected_at: datetime) -> int:
    base = _SIGNAL_SCORES.get(signal_type, 30)
    now = datetime.now(timezone.utc)
    if detected_at.tzinfo is None:
        detected_at = detected_at.replace(tzinfo=timezone.utc)
    _, boost = _age_label(now - detected_at)
    return min(100, base + boost)


def compute_score_reason(signal_type: str, detected_at: datetime) -> str:
    base = _SIGNAL_SCORES.get(signal_type, 30)
    label = _SIGNAL_LABELS.get(signal_type, signal_type)
    now = datetime.now(timezone.utc)
    if detected_at.tzinfo is None:
        detected_at = detected_at.replace(tzinfo=timezone.utc)
    age_label, boost = _age_label(now - detected_at)
    boost_str = f" +{boost} recency" if boost else ""
    return f"{label}; {age_label} (score: {base}{boost_str})"


@router.get("", response_model=SignalListResponse)
def list_signals(
    type: str | None = Query(default=None, description="Filter by signal_type"),
    domain: str | None = Query(default=None, description="Exact domain match"),
    apex_domain: str | None = Query(default=None),
    industry: str | None = Query(default=None, description="company_industry match"),
    saas_vendor: str | None = Query(default=None),
    hosting_provider: str | None = Query(default=None),
    since: datetime | None = Query(default=None, description="ISO 8601 timestamp"),
    cursor: str | None = Query(default=None, description="Pagination cursor from next_cursor"),
    limit: int = Query(default=100, ge=1, le=1000),
    key: dict = Depends(authenticated_key),
    ch=Depends(get_ch),
    response: Response = None,
):
    # Tier-based lookback window — free=24h, starter=30d, pro=90d
    tier = key.get("tier", "free")
    lookback_days = TIER_LOOKBACK_DAYS.get(tier, 1)
    lookback_cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)

    # Build WHERE clauses with table-qualified column names.
    # s = signals, d = domains (joined for fresh enrichment data).
    conditions = ["s.detected_at >= %(lookback_cutoff)s"]
    params: dict = {"lookback_cutoff": lookback_cutoff.replace(tzinfo=None)}

    if type:
        conditions.append("s.signal_type = %(type)s")
        params["type"] = type

    if domain:
        conditions.append("s.domain = %(domain)s")
        params["domain"] = domain

    if apex_domain:
        conditions.append("s.apex_domain = %(apex_domain)s")
        params["apex_domain"] = apex_domain

    if industry:
        conditions.append("lower(coalesce(d.company_industry, s.company_industry, '')) = %(industry)s")
        params["industry"] = industry.lower()

    if saas_vendor:
        conditions.append("lower(coalesce(d.saas_vendor, s.saas_vendor, '')) = %(saas_vendor)s")
        params["saas_vendor"] = saas_vendor.lower()

    if hosting_provider:
        conditions.append("lower(coalesce(d.hosting_provider, s.hosting_provider, '')) = %(hosting_provider)s")
        params["hosting_provider"] = hosting_provider.lower()

    if since:
        # Use the more restrictive of ?since= and the tier lookback window
        since_naive = since.replace(tzinfo=None) if since.tzinfo else since
        lookback_naive = lookback_cutoff.replace(tzinfo=None)
        effective_since = max(since_naive, lookback_naive)
        params["lookback_cutoff"] = effective_since

    # Cursor pagination (detected_at DESC)
    if cursor:
        try:
            cursor_dt = datetime.fromisoformat(
                base64.b64decode(cursor.encode()).decode()
            )
            conditions.append("s.detected_at < %(cursor_dt)s")
            params["cursor_dt"] = cursor_dt.replace(tzinfo=None)
        except Exception:
            pass  # invalid cursor → ignore and start from the top

    where = "WHERE " + " AND ".join(conditions) if conditions else ""

    # Domain subquery — latest enrichment data per apex domain
    domains_subq = """
        (SELECT domain, hosting_provider, saas_vendor, company_name, company_industry
         FROM signal.domains FINAL) d
    """

    # Total count (without cursor)
    count_conditions = [c for c in conditions if "cursor_dt" not in c]
    count_where = "WHERE " + " AND ".join(count_conditions) if count_conditions else ""
    count_params = {k: v for k, v in params.items() if k != "cursor_dt"}
    total_row = ch.query(
        f"""
        SELECT count()
        FROM signal.signals s
        LEFT JOIN {domains_subq} ON s.apex_domain = d.domain
        {count_where}
        """,
        parameters=count_params,
    ).result_rows
    total = total_row[0][0] if total_row else 0

    # Fetch one extra to detect if there's a next page.
    # coalesce(d.field, s.field) so fresh enrichment data overrides the snapshot.
    rows = ch.query(
        f"""
        SELECT
            s.signal_id,
            s.signal_type,
            s.domain,
            s.apex_domain,
            s.detected_at,
            coalesce(d.hosting_provider, s.hosting_provider) AS hosting_provider,
            coalesce(d.saas_vendor,      s.saas_vendor)      AS saas_vendor,
            coalesce(d.company_name,     s.company_name)     AS company_name,
            coalesce(d.company_industry, s.company_industry) AS company_industry
        FROM signal.signals s
        LEFT JOIN {domains_subq} ON s.apex_domain = d.domain
        {where}
        ORDER BY s.detected_at DESC
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
            score=compute_score(row[1], row[4]),
            score_reason=compute_score_reason(row[1], row[4]),
        )
        for row in rows
    ]

    # Watchlist filtering: if key has watchlists, filter signals to matching ones
    watchlist_rows = ch.query(
        "SELECT pattern_type, pattern FROM signal.watchlists WHERE key_hash = %(h)s AND active = true",
        parameters={"h": key["key_hash"]},
    ).result_rows

    if watchlist_rows:
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

    if response is not None:
        rl = key.get("_rl", {})
        response.headers["X-RateLimit-Limit"] = str(rl.get("limit", ""))
        response.headers["X-RateLimit-Remaining"] = str(rl.get("remaining", ""))
        response.headers["X-RateLimit-Reset"] = str(rl.get("reset", ""))

    return SignalListResponse(data=signals_out, next_cursor=next_cursor, total=total)
