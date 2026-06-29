"""GET /v1/account — return tier, quota usage, and key metadata."""

from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Depends

from api.auth import RATE_LIMITS, rate_limit_account
from api.deps import authenticated_key_no_rl, get_ch, get_redis

router = APIRouter(prefix="/v1/account", tags=["account"])


@router.get("")
def get_account(
    auth: tuple = Depends(authenticated_key_no_rl),
    redis=Depends(get_redis),
):
    key, key_hash = auth
    tier = key.get("tier", "free")
    label = key.get("label", "")

    today = date.today()
    rl_key = rate_limit_account(key, key_hash)
    redis_key = f"signal:rate:{rl_key}:{today.strftime('%Y%m%d')}"
    raw = redis.get(redis_key)
    quota_used = int(raw) if raw else 0

    limit = RATE_LIMITS.get(tier, 100)

    tomorrow_midnight = datetime.combine(
        date.today() + timedelta(days=1),
        datetime.min.time(),
        tzinfo=timezone.utc,
    )

    return {
        "tier": tier,
        "label": label or None,
        "quota_limit": limit,
        "quota_used": quota_used,
        "quota_remaining": max(0, limit - quota_used),
        "quota_reset": tomorrow_midnight.isoformat(),
    }
