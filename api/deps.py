"""FastAPI dependency injection — shared ClickHouse client, Redis, auth."""

import redis as redis_sync
from fastapi import Depends, Security
from fastapi.security import HTTPAuthorizationCredentials

import clickhouse_connect
from api.auth import bearer_scheme, check_rate_limit, get_key_hash, lookup_key
from db.client import get_client, get_settings


def get_ch():
    return get_client()


def get_redis():
    settings = get_settings()
    return redis_sync.from_url(settings.redis_url, decode_responses=True)


def authenticated_key(
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
    ch=Depends(get_ch),
    redis=Depends(get_redis),
) -> dict:
    """Dependency that validates the API key and enforces rate limits."""
    key_hash = get_key_hash(credentials)
    key_record = lookup_key(ch, key_hash)
    rl = check_rate_limit(redis, key_hash, key_record["tier"])
    key_record["_rl"] = rl  # pass rate limit info to route for response headers
    return key_record
