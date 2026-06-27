"""
TBS-hash dedup using Redis SET.

Key: signal:dedup:<hex(sha256_tbs)>
TTL: 30 days — long enough that we won't re-insert the same cert after a
     crash/restart, but we don't hold Redis memory forever.

Returns only certs that have NOT been seen before, and marks them as seen
atomically using a pipeline so a crash between check and insert doesn't
cause double-writes.
"""

import redis.asyncio as aioredis

_DEDUP_TTL_SECONDS = 60 * 60 * 24 * 30  # 30 days
_KEY_PREFIX = "signal:dedup:"


class DedupFilter:
    def __init__(self, redis: aioredis.Redis) -> None:
        self._redis = redis

    async def filter_new(self, tbs_hashes: list[bytes]) -> list[bool]:
        """
        Return a list of booleans, True if the corresponding hash is NEW
        (not seen before). Marks all new hashes as seen atomically.
        """
        if not tbs_hashes:
            return []

        keys = [_KEY_PREFIX + h.hex() for h in tbs_hashes]

        # Check existence for all keys in one round-trip
        pipe = self._redis.pipeline()
        for key in keys:
            pipe.exists(key)
        exists_results = await pipe.execute()

        # Mark new ones as seen, also in one pipeline
        pipe = self._redis.pipeline()
        is_new: list[bool] = []
        for key, exists in zip(keys, exists_results):
            new = not bool(exists)
            is_new.append(new)
            if new:
                pipe.setex(key, _DEDUP_TTL_SECONDS, 1)
        await pipe.execute()

        return is_new

    async def is_new(self, tbs_hash: bytes) -> bool:
        """Single-item check — used in tests."""
        results = await self.filter_new([tbs_hash])
        return results[0]
