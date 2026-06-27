"""
Persist tile-fetch position per log to Redis so we can resume without gaps
or duplicate storms after a crash.

Key: signal:checkpoint:<log_id>
Value: next tile index to fetch (integer string)

Tile granularity means worst-case replay on crash is 256 entries per log —
acceptable. We do NOT checkpoint per-cert because that's too many Redis writes.
"""

import redis.asyncio as aioredis

_KEY_PREFIX = "signal:checkpoint:"


class Checkpoint:
    def __init__(self, redis: aioredis.Redis, log_id: str) -> None:
        self._redis = redis
        self._key = _KEY_PREFIX + log_id

    async def get(self) -> int | None:
        """Return the last saved tile index, or None if no checkpoint exists."""
        val = await self._redis.get(self._key)
        return int(val) if val is not None else None

    async def save(self, tile_index: int) -> None:
        await self._redis.set(self._key, tile_index)

    async def delete(self) -> None:
        await self._redis.delete(self._key)
