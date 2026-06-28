"""FastAPI dependency injection — shared ClickHouse client, Redis, auth."""

import redis as redis_sync
from fastapi import Depends, Security
from fastapi.security import HTTPAuthorizationCredentials

import clickhouse_connect
from api.auth import bearer_scheme, check_rate_limit, get_key_hash, lookup_key, rate_limit_account
from db.client import get_client, get_settings


def get_ch():
    return get_client()


def get_redis():
    settings = get_settings()
    return redis_sync.from_url(settings.redis_url, decode_responses=True)


def authenticated_key_no_rl(
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
    ch=Depends(get_ch),
) -> tuple[dict, str]:
    """Auth-only dependency — no rate limiting. Used by endpoints with custom cost (e.g. batch)."""
    key_hash = get_key_hash(credentials)
    key_record = lookup_key(ch, key_hash)
    return key_record, key_hash


def authenticated_key(
    auth: tuple = Depends(authenticated_key_no_rl),
    redis=Depends(get_redis),
) -> dict:
    """Dependency that validates the API key and enforces rate limits (cost=1)."""
    key_record, key_hash = auth
    rl = check_rate_limit(redis, rate_limit_account(key_record, key_hash), key_record["tier"])
    key_record["_rl"] = rl  # pass rate limit info to route for response headers
    return key_record
