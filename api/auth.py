"""
API key authentication and rate limiting.

Auth flow:
  Authorization: Bearer sig_<hex>
  → SHA-256(raw_key) → lookup in api_keys table
  → check not revoked
  → Redis rate-limit counter

Rate limits (requests per day):
  free:    100
  starter: 10,000
  pro:     100,000

Key format: sig_ + 64 hex chars (256 bits of entropy)
Key hash: SHA-256(raw_key).hexdigest() — stored in ClickHouse, never the raw key
"""

import hashlib
import secrets
from datetime import datetime, timezone

from fastapi import HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

RATE_LIMITS: dict[str, int] = {
    "free": 100,
    "starter": 10_000,
    "growth": 40_000,
    "pro": 100_000,
}

KEY_PREFIX = "sig_"

bearer_scheme = HTTPBearer(auto_error=False)


def generate_key() -> tuple[str, str]:
    """Return (raw_key, key_hash). raw_key is shown once; store key_hash only."""
    raw = KEY_PREFIX + secrets.token_hex(32)
    return raw, hash_key(raw)


def hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def get_key_hash(credentials: HTTPAuthorizationCredentials | None) -> str:
    """Extract and hash a Bearer token. Raises 401 if missing/malformed."""
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Pass Authorization: Bearer sig_<key>",
        )
    raw = credentials.credentials
    if not raw.startswith(KEY_PREFIX):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key format.",
        )
    return hash_key(raw)


def lookup_key(ch, key_hash: str) -> dict:
    """Look up key record. Raises 401 if not found or revoked."""
    rows = ch.query(
        "SELECT tier, buyer_verified, revoked, webhook_url, webhook_secret, label FROM signal.api_keys WHERE key_hash = %(h)s LIMIT 1",
        parameters={"h": key_hash},
    ).result_rows

    if not rows:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key.")

    tier, buyer_verified, revoked, webhook_url, webhook_secret, label = rows[0]
    if revoked:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="API key revoked.")

    return {
        "key_hash": key_hash,
        "tier": tier,
        "buyer_verified": bool(buyer_verified),
        "webhook_url": webhook_url,
        "webhook_secret": webhook_secret,
        "label": label or "",
    }


def rate_limit_account(key_record: dict, key_hash: str) -> str:
    """Return the identifier used as the rate-limit bucket.

    Self-serve keys use their signup label (signup:email) so rotating a key
    via /reissue doesn't reset the daily quota. Admin keys fall back to key_hash.
    """
    label = key_record.get("label", "")
    if label.startswith("signup:"):
        return label
    return key_hash


def check_rate_limit(redis_client, key_hash: str, tier: str, cost: int = 1) -> dict:
    """Increment daily counter by cost. Raises 429 if over limit. Returns rate limit info."""
    from datetime import date
    today = date.today()
    redis_key = f"signal:rate:{key_hash}:{today.strftime('%Y%m%d')}"

    count = redis_client.incrby(redis_key, cost)
    if count <= cost:  # key created by this call
        redis_client.expire(redis_key, 172800)  # 2-day TTL

    limit = RATE_LIMITS.get(tier, 100)
    remaining = max(0, limit - count)
    reset = _midnight_ts()

    if count > limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded ({limit} requests/day on {tier} tier).",
            headers={
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(reset),
            },
        )

    return {"limit": limit, "remaining": remaining, "reset": reset}


def _midnight_ts() -> int:
    """Unix timestamp of next UTC midnight."""
    from datetime import date, datetime, timedelta, timezone
    tomorrow = datetime.combine(
        date.today() + timedelta(days=1),
        datetime.min.time(),
        tzinfo=timezone.utc,
    )
    return int(tomorrow.timestamp())
