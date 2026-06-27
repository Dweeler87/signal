"""
SIGNAL health monitor — runs as a supervisord-managed process.

Checks every INTERVAL seconds:
  1. Log follower lag per active log (CT tree size - our checkpoint)
  2. Enrichment backlog (unenriched domain count)
  3. Signal throughput (signals generated in last hour)
  4. Redis reachability
  5. ClickHouse reachability

Writes structured JSON alert lines to stderr when thresholds are crossed.
On recovery, writes a recovery event.

Run:
  python scripts/monitor.py
"""

import asyncio
import json
import logging
import sys
import time
from datetime import datetime, timezone

import httpx
import redis.asyncio as aioredis

from db.client import get_client, get_settings
from ingestion.checkpoint import Checkpoint

INTERVAL = 300  # check every 5 minutes

# Alert thresholds
LAG_WARN = 50_000       # entries behind CT head before warning
LAG_CRIT = 500_000      # entries behind before critical
ENRICH_WARN = 10_000    # unenriched domains before warning
ENRICH_CRIT = 50_000    # unenriched domains before critical
SIGNAL_STALE_HOURS = 2  # no signals for this many hours → alert

# Active log URLs to check lag for (must match log_follower.LOG_REGISTRY)
ACTIVE_LOGS = [
    ("nimbus2025", "https://ct.cloudflare.com/logs/nimbus2025/"),
]


def _emit(level: str, check: str, message: str, **extra):
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "check": check,
        "message": message,
        **extra,
    }
    print(json.dumps(record), file=sys.stderr, flush=True)


async def check_log_lag(redis_client, http: httpx.AsyncClient) -> None:
    for log_id, log_url in ACTIVE_LOGS:
        try:
            r = await http.get(log_url.rstrip("/") + "/ct/v1/get-sth", timeout=10)
            r.raise_for_status()
            tree_size = r.json()["tree_size"]

            cp = Checkpoint(redis_client, log_id)
            checkpoint = await cp.get()
            if checkpoint is None:
                _emit("warn", "log_lag", "no checkpoint found — follower may not have started", log_id=log_id)
                continue

            lag = tree_size - checkpoint
            level = "ok"
            if lag >= LAG_CRIT:
                level = "crit"
            elif lag >= LAG_WARN:
                level = "warn"

            _emit(level, "log_lag", f"{log_id} lag {lag:,} entries",
                  log_id=log_id, tree_size=tree_size, checkpoint=checkpoint, lag=lag)

        except Exception as exc:
            _emit("crit", "log_lag", f"could not reach {log_id}: {exc}", log_id=log_id)


async def check_enrichment_backlog(ch) -> None:
    try:
        row = ch.query(
            "SELECT count() FROM signal.domains FINAL WHERE enrichment_at IS NULL"
        ).result_rows
        backlog = row[0][0] if row else 0

        level = "ok"
        if backlog >= ENRICH_CRIT:
            level = "crit"
        elif backlog >= ENRICH_WARN:
            level = "warn"

        _emit(level, "enrich_backlog", f"{backlog:,} domains awaiting enrichment", backlog=backlog)
    except Exception as exc:
        _emit("crit", "enrich_backlog", f"query failed: {exc}")


async def check_signal_throughput(ch) -> None:
    try:
        row = ch.query(
            f"SELECT count() FROM signal.signals WHERE detected_at >= now() - INTERVAL {SIGNAL_STALE_HOURS} HOUR"
        ).result_rows
        count = row[0][0] if row else 0

        if count == 0:
            _emit("warn", "signal_throughput",
                  f"no signals in last {SIGNAL_STALE_HOURS}h — enrichment worker may be stalled",
                  signals_recent=count, window_hours=SIGNAL_STALE_HOURS)
        else:
            _emit("ok", "signal_throughput",
                  f"{count} signals in last {SIGNAL_STALE_HOURS}h",
                  signals_recent=count, window_hours=SIGNAL_STALE_HOURS)
    except Exception as exc:
        _emit("crit", "signal_throughput", f"query failed: {exc}")


async def check_clickhouse(ch) -> None:
    try:
        ch.query("SELECT 1")
        _emit("ok", "clickhouse", "reachable")
    except Exception as exc:
        _emit("crit", "clickhouse", f"unreachable: {exc}")


async def check_redis(redis_client) -> None:
    try:
        await redis_client.ping()
        _emit("ok", "redis", "reachable")
    except Exception as exc:
        _emit("crit", "redis", f"unreachable: {exc}")


async def run_checks() -> None:
    settings = get_settings()
    redis_client = aioredis.from_url(settings.redis_url, decode_responses=False)
    ch = get_client()

    async with httpx.AsyncClient(
        headers={"User-Agent": "signal-monitor/0.1"},
        follow_redirects=True,
    ) as http:
        await asyncio.gather(
            check_clickhouse(ch),
            check_redis(redis_client),
            check_log_lag(redis_client, http),
            check_enrichment_backlog(ch),
            check_signal_throughput(ch),
            return_exceptions=True,
        )


async def main() -> None:
    _emit("ok", "startup", f"monitor started, check interval {INTERVAL}s")
    while True:
        try:
            await run_checks()
        except Exception as exc:
            _emit("crit", "monitor", f"check loop error: {exc}")
        await asyncio.sleep(INTERVAL)


if __name__ == "__main__":
    asyncio.run(main())
