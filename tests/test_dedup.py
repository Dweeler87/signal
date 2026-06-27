"""
Tests for ingestion/dedup.py

Uses a real Redis connection (requires Docker Compose to be running).
Marks tests as skipped if Redis is unavailable.
"""

import asyncio
import os

import pytest
import redis.asyncio as aioredis

from ingestion.dedup import DedupFilter

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")


@pytest.fixture
async def redis_client():
    client = aioredis.from_url(REDIS_URL, decode_responses=False)
    try:
        await client.ping()
    except Exception:
        pytest.skip("Redis not available — run: docker compose up -d")
    # Flush dedup keys before each test to avoid cross-test pollution
    keys = await client.keys("signal:dedup:*")
    if keys:
        await client.delete(*keys)
    yield client
    await client.aclose()


@pytest.fixture
async def dedup(redis_client):
    return DedupFilter(redis_client)


async def test_new_hash_is_new(dedup):
    h = b"\x01" * 32
    assert await dedup.is_new(h) is True


async def test_seen_hash_not_new(dedup):
    h = b"\x02" * 32
    await dedup.is_new(h)   # marks as seen
    assert await dedup.is_new(h) is False


async def test_batch_filter(dedup):
    h1 = b"\xaa" * 32
    h2 = b"\xbb" * 32
    h3 = b"\xcc" * 32

    # Mark h1 as seen first
    await dedup.is_new(h1)

    results = await dedup.filter_new([h1, h2, h3])
    assert results == [False, True, True]

    # Now h2 and h3 should also be seen
    results2 = await dedup.filter_new([h1, h2, h3])
    assert results2 == [False, False, False]


async def test_empty_batch(dedup):
    assert await dedup.filter_new([]) == []


async def test_different_hashes_independent(dedup):
    """Each hash is tracked independently."""
    hashes = [bytes([i]) * 32 for i in range(5)]
    r1 = await dedup.filter_new(hashes)
    assert all(r1)

    r2 = await dedup.filter_new(hashes)
    assert not any(r2)


async def test_pre_cert_cert_pair_dedup():
    """
    Critical: if a pre-cert and its final cert share the same TBS hash (as
    they must per RFC 6962), only the first one should pass dedup.

    We simulate this by using the same TBS hash for both "entries".
    """
    # Simulate TBS hash (would be identical for pre-cert + final cert)
    tbs_hash = b"\xde\xad\xbe\xef" * 8  # 32 bytes

    client = aioredis.from_url(REDIS_URL, decode_responses=False)
    try:
        await client.ping()
    except Exception:
        pytest.skip("Redis not available")

    await client.delete("signal:dedup:" + tbs_hash.hex())
    dedup = DedupFilter(client)

    # First encounter (pre-cert) — should be new
    first = await dedup.is_new(tbs_hash)
    # Second encounter (final cert) — should be duplicate
    second = await dedup.is_new(tbs_hash)

    assert first is True
    assert second is False

    await client.aclose()
