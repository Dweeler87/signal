"""
Dev CLI — live ingest stats.

Usage:
    python scripts/cli.py stats          # one-shot stats snapshot
    python scripts/cli.py watch          # refresh every 5 seconds
    python scripts/cli.py reset <log_id> # delete checkpoint for a log (triggers re-fetch)
"""

import asyncio
import sys
import time

import redis.asyncio as aioredis

from db.client import get_client, get_settings
from ingestion.checkpoint import Checkpoint


async def stats_snapshot(settings) -> dict:
    redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    ch = get_client()

    result = {}

    # ClickHouse counts
    try:
        rows = ch.query("SELECT count() FROM signal.certificates").result_rows
        result["total_certs"] = rows[0][0]
        rows = ch.query("SELECT count() FROM signal.domains").result_rows
        result["total_domains"] = rows[0][0]
        rows = ch.query("SELECT count() FROM signal.signals").result_rows
        result["total_signals"] = rows[0][0]
    except Exception as e:
        result["clickhouse_error"] = str(e)

    # Checkpoint positions per log
    from ingestion.log_follower import LOG_REGISTRY
    checkpoints = {}
    for log_def in LOG_REGISTRY:
        cp = Checkpoint(redis, log_def["log_id"])
        pos = await cp.get()
        checkpoints[log_def["log_id"]] = {
            "tile": pos,
            "approx_entry": (pos * 256) if pos is not None else None,
            "enabled": log_def["enabled"],
        }
    result["checkpoints"] = checkpoints

    # Redis dedup key count
    try:
        dedup_keys = await redis.dbsize()
        result["redis_keys"] = dedup_keys
    except Exception:
        result["redis_keys"] = "unavailable"

    await redis.aclose()
    return result


def print_stats(s: dict) -> None:
    print("\n=== SIGNAL Ingest Stats ===")
    print(f"  Certificates (ClickHouse): {s.get('total_certs', 'N/A'):,}")
    print(f"  Domains (ClickHouse):      {s.get('total_domains', 'N/A'):,}")
    print(f"  Signals (ClickHouse):      {s.get('total_signals', 'N/A'):,}")
    print(f"  Redis keys (dedup cache):  {s.get('redis_keys', 'N/A'):,}")

    if "clickhouse_error" in s:
        print(f"  ClickHouse error: {s['clickhouse_error']}")

    print("\n  Log checkpoints:")
    for log_id, info in s.get("checkpoints", {}).items():
        status = "ON " if info["enabled"] else "off"
        tile = info["tile"]
        entry = info["approx_entry"]
        if tile is None:
            print(f"    [{status}] {log_id}: not started")
        else:
            print(f"    [{status}] {log_id}: tile {tile:,} (~entry {entry:,})")
    print()


async def reset_checkpoint(log_id: str, settings) -> None:
    redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    cp = Checkpoint(redis, log_id)
    await cp.delete()
    print(f"Checkpoint deleted for {log_id}. It will re-fetch from near-head on next run.")
    await redis.aclose()


def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "stats"
    settings = get_settings()

    if cmd == "stats":
        s = asyncio.run(stats_snapshot(settings))
        print_stats(s)

    elif cmd == "watch":
        while True:
            s = asyncio.run(stats_snapshot(settings))
            print_stats(s)
            try:
                time.sleep(5)
            except KeyboardInterrupt:
                break

    elif cmd == "reset":
        if len(sys.argv) < 3:
            print("Usage: python scripts/cli.py reset <log_id>")
            sys.exit(1)
        asyncio.run(reset_checkpoint(sys.argv[2], settings))

    else:
        print(f"Unknown command: {cmd}. Use: stats | watch | reset <log_id>")
        sys.exit(1)


if __name__ == "__main__":
    main()
