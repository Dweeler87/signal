"""Health check and metrics endpoints."""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends

from api.deps import get_ch, get_redis
from api.schemas import HealthResponse, MetricsResponse

router = APIRouter()


@router.get("/healthz", response_model=HealthResponse, tags=["ops"])
def healthz(ch=Depends(get_ch), redis=Depends(get_redis)):
    ch_status = "ok"
    redis_status = "ok"

    try:
        ch.query("SELECT 1")
    except Exception:
        ch_status = "error"

    try:
        redis.ping()
    except Exception:
        redis_status = "error"

    overall = "ok" if ch_status == "ok" and redis_status == "ok" else "degraded"
    return HealthResponse(status=overall, clickhouse=ch_status, redis=redis_status)


@router.get("/metrics", response_model=MetricsResponse, tags=["ops"])
def metrics(ch=Depends(get_ch)):
    total_certs = ch.query("SELECT count() FROM signal.certificates").result_rows[0][0]
    total_domains = ch.query("SELECT count() FROM signal.domains").result_rows[0][0]
    total_signals = ch.query("SELECT count() FROM signal.signals").result_rows[0][0]

    since = datetime.now(timezone.utc) - timedelta(hours=24)
    signals_24h = ch.query(
        "SELECT count() FROM signal.signals WHERE detected_at >= %(s)s",
        parameters={"s": since},
    ).result_rows[0][0]

    return MetricsResponse(
        total_certificates=total_certs,
        total_domains=total_domains,
        total_signals=total_signals,
        signals_last_24h=signals_24h,
    )
