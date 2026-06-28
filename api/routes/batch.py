"""
POST /v1/signals/batch — look up signals for multiple apex domains in one call.

Rate cost: 1 per domain (a 50-domain batch uses 50 daily quota).
Response groups signals by apex domain. Domains with no signals are omitted.

Clay use case: enrich a table of companies without 1-per-row API calls.
"""

from fastapi import APIRouter, Depends, Response

from api.auth import check_rate_limit
from api.deps import authenticated_key_no_rl, get_ch, get_redis
from api.routes.signals import _SCORE_SQL, compute_score, compute_score_reason
from api.schemas import BatchRequest, BatchResponse, SignalOut

router = APIRouter(prefix="/v1/signals", tags=["signals"])


@router.post("/batch", response_model=BatchResponse)
def batch_signals(
    body: BatchRequest,
    auth: tuple = Depends(authenticated_key_no_rl),
    redis=Depends(get_redis),
    ch=Depends(get_ch),
    response: Response = None,
):
    key_record, key_hash = auth
    tier = key_record.get("tier", "free")

    # Rate limit cost = number of domains requested
    rl = check_rate_limit(redis, key_hash, tier, cost=len(body.domains))
    if response is not None:
        response.headers["X-RateLimit-Limit"] = str(rl["limit"])
        response.headers["X-RateLimit-Remaining"] = str(rl["remaining"])
        response.headers["X-RateLimit-Reset"] = str(rl["reset"])

    domains = [d.strip().lower() for d in body.domains]
    placeholders = ", ".join(f"%(d{i})s" for i in range(len(domains)))
    domain_params = {f"d{i}": d for i, d in enumerate(domains)}

    extra_filters = ""
    if body.type:
        extra_filters += " AND s.signal_type = %(sig_type)s"
        domain_params["sig_type"] = body.type
    if body.score_min is not None:
        extra_filters += f" AND ({_SCORE_SQL}) >= %(score_min)s"
        domain_params["score_min"] = body.score_min

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
        LEFT JOIN (
            SELECT domain, hosting_provider, saas_vendor, company_name, company_industry
            FROM signal.domains FINAL
        ) d ON s.apex_domain = d.domain
        WHERE s.apex_domain IN ({placeholders})
        {extra_filters}
        ORDER BY s.apex_domain, s.detected_at DESC
        LIMIT %(limit_per_domain)s BY s.apex_domain
        """,
        parameters={**domain_params, "limit_per_domain": body.limit_per_domain},
    ).result_rows

    result: dict[str, list[SignalOut]] = {}
    for row in rows:
        sig = SignalOut(
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
        result.setdefault(row[3], []).append(sig)

    total = sum(len(v) for v in result.values())
    return BatchResponse(
        data=result,
        domains_with_signals=len(result),
        total_signals=total,
    )
