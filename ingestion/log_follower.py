"""
CT log follower — RFC 6962 get-entries API.

Fetches entries from CT logs concurrently, parses cert metadata, deduplicates
on TBS hash, and writes new records to ClickHouse.

API used:
  GET <log_url>/ct/v1/get-sth            → current tree size
  GET <log_url>/ct/v1/get-entries?start=N&end=M  → up to (M-N+1) entries

Concurrency model:
  - One asyncio task per enabled log
  - Within each log: fetch FETCH_BATCH_SIZE entries, then next batch
  - Multiple logs run in parallel via asyncio.gather

Backpressure:
  If the write queue depth exceeds BACKPRESSURE_LIMIT, fetching pauses
  until the writer catches up.

Run:
  python -m ingestion.log_follower
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field

import httpx
import redis.asyncio as aioredis
import structlog

from db.client import get_client, get_settings
from ingestion.checkpoint import Checkpoint
from ingestion.dedup import DedupFilter
from ingestion.parser import ParsedCert, extract_domains, parse_entries_response

log = structlog.get_logger()

FETCH_BATCH_SIZE = 1000     # max entries per get-entries call (RFC 6962 cap)
FETCH_CONCURRENCY = 4       # parallel get-entries calls per log
POLL_INTERVAL = 15          # seconds to wait when caught up at log head
BACKPRESSURE_LIMIT = 5000   # max queued-but-unwritten certs before pausing
WRITE_BATCH_SIZE = 500      # certs per ClickHouse INSERT
WRITE_INTERVAL = 2.0        # max seconds between forced flushes

# Active logs — toggle enabled=True to activate additional logs
LOG_REGISTRY: list[dict] = [
    {
        "log_id": "nimbus2025",
        "operator": "cloudflare",
        "url": "https://ct.cloudflare.com/logs/nimbus2025/",
        "enabled": True,
    },
    {
        "log_id": "nimbus2024",
        "operator": "cloudflare",
        "url": "https://ct.cloudflare.com/logs/nimbus2024/",
        "enabled": False,
    },
    {
        "log_id": "oak2025h2",
        "operator": "letsencrypt",
        "url": "https://oak.ct.letsencrypt.org/2025h2/",
        "enabled": False,  # DNS may fail depending on resolver
    },
    {
        "log_id": "oak2026",
        "operator": "letsencrypt",
        "url": "https://oak.ct.letsencrypt.org/2026/",
        "enabled": False,  # DNS may fail depending on resolver
    },
]


@dataclass
class IngestStats:
    fetched: int = 0
    parsed: int = 0
    deduped: int = 0
    skipped: int = 0
    written: int = 0
    errors: int = 0
    start_time: float = field(default_factory=time.monotonic)

    def rate(self) -> float:
        elapsed = time.monotonic() - self.start_time
        return self.written / elapsed if elapsed > 0 else 0.0

    def dedup_ratio(self) -> float:
        total = self.deduped + self.skipped
        return self.skipped / total if total > 0 else 0.0


async def get_tree_size(client: httpx.AsyncClient, log_url: str) -> int:
    url = log_url.rstrip("/") + "/ct/v1/get-sth"
    r = await client.get(url, timeout=10)
    r.raise_for_status()
    return r.json()["tree_size"]


async def fetch_entries(
    client: httpx.AsyncClient, log_url: str, start: int, end: int
) -> list[dict]:
    url = log_url.rstrip("/") + f"/ct/v1/get-entries?start={start}&end={end}"
    r = await client.get(url, timeout=30)
    r.raise_for_status()
    return r.json().get("entries", [])


async def follow_log(
    log_def: dict,
    dedup: DedupFilter,
    write_queue: asyncio.Queue,
    stats: IngestStats,
    settings,
) -> None:
    log_id = log_def["log_id"]
    log_url = log_def["url"]
    logger = log.bind(log_id=log_id)

    redis_client = aioredis.from_url(settings.redis_url, decode_responses=False)
    checkpoint = Checkpoint(redis_client, log_id)

    async with httpx.AsyncClient(
        headers={"User-Agent": "signal-ct-follower/0.1 (contact: signal@example.com)"},
        follow_redirects=True,
        limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
    ) as http:
        saved = await checkpoint.get()
        if saved is not None:
            next_index = saved
            logger.info("resuming", entry_index=next_index)
        else:
            tree_size = await get_tree_size(http, log_url)
            lookback = min(settings.initial_lookback, tree_size)
            next_index = max(0, tree_size - lookback)
            logger.info("starting_fresh", tree_size=tree_size, start_index=next_index)

        while True:
            try:
                tree_size = await get_tree_size(http, log_url)

                if next_index >= tree_size:
                    logger.debug("caught_up", tree_size=tree_size)
                    await asyncio.sleep(POLL_INTERVAL)
                    continue

                # Build concurrent fetch tasks (up to FETCH_CONCURRENCY batches)
                batches: list[tuple[int, int]] = []
                idx = next_index
                while idx < tree_size and len(batches) < FETCH_CONCURRENCY:
                    end = min(idx + FETCH_BATCH_SIZE - 1, tree_size - 1)
                    batches.append((idx, end))
                    idx = end + 1

                results = await asyncio.gather(
                    *[fetch_entries(http, log_url, s, e) for s, e in batches],
                    return_exceptions=True,
                )

                for (start, end), result in zip(batches, results):
                    if isinstance(result, Exception):
                        logger.warning("fetch_error", start=start, error=str(result))
                        stats.errors += 1
                        break  # don't advance checkpoint past the failed batch

                    entries: list[dict] = result
                    certs = parse_entries_response(entries, log_id, start)
                    stats.fetched += len(entries)
                    stats.parsed += len(certs)

                    if certs:
                        is_new_flags = await dedup.filter_new([c.sha256_tbs for c in certs])
                        new_certs = [c for c, new in zip(certs, is_new_flags) if new]
                        stats.deduped += len(new_certs)
                        stats.skipped += len(certs) - len(new_certs)

                        for cert in new_certs:
                            while write_queue.qsize() >= BACKPRESSURE_LIMIT:
                                logger.warning("backpressure", queue_depth=write_queue.qsize())
                                await asyncio.sleep(1)
                            await write_queue.put(cert)

                    next_index = end + 1
                    await checkpoint.save(next_index)

                logger.info(
                    "progress",
                    next_index=next_index,
                    tree_size=tree_size,
                    lag=tree_size - next_index,
                    write_rate=f"{stats.rate():.0f}/s",
                    dedup_ratio=f"{stats.dedup_ratio():.1%}",
                )

            except httpx.HTTPError as exc:
                logger.warning("http_error", error=str(exc))
                stats.errors += 1
                await asyncio.sleep(30)
            except Exception as exc:
                logger.error("unexpected_error", error=str(exc), exc_info=True)
                stats.errors += 1
                await asyncio.sleep(30)


async def writer(write_queue: asyncio.Queue, stats: IngestStats) -> None:
    ch = get_client()
    buffer: list[ParsedCert] = []
    last_flush = time.monotonic()

    while True:
        try:
            cert = await asyncio.wait_for(write_queue.get(), timeout=WRITE_INTERVAL)
            buffer.append(cert)
        except asyncio.TimeoutError:
            pass

        should_flush = (
            len(buffer) >= WRITE_BATCH_SIZE
            or (buffer and time.monotonic() - last_flush >= WRITE_INTERVAL)
        )
        if should_flush and buffer:
            await _flush(ch, buffer, stats)
            buffer.clear()
            last_flush = time.monotonic()


async def _flush(ch, certs: list[ParsedCert], stats: IngestStats) -> None:
    cert_rows = []
    domain_rows = []

    for c in certs:
        cert_rows.append([
            c.sha256_tbs,
            c.sha256_leaf,
            c.log_id,
            c.leaf_index,
            c.not_before,
            c.not_after,
            c.issuer_cn,
            c.issuer_org,
            c.subject_cn,
            c.is_precert,
            c.sans,
        ])
        for pd in extract_domains(c.sans):
            domain_rows.append([
                pd.domain,
                pd.apex_domain,
                pd.is_wildcard,
                pd.is_apex,
                c.sha256_tbs,
                c.not_before,
                c.not_before,  # last_seen_at = first_seen_at on initial insert
            ])

    try:
        ch.insert(
            "certificates",
            cert_rows,
            column_names=[
                "sha256_tbs", "sha256_leaf", "log_id", "leaf_index",
                "not_before", "not_after", "issuer_cn", "issuer_org",
                "subject_cn", "is_precert", "sans",
            ],
        )
        if domain_rows:
            ch.insert(
                "domains",
                domain_rows,
                column_names=[
                    "domain", "apex_domain", "is_wildcard", "is_apex",
                    "first_seen_cert", "first_seen_at", "last_seen_at",
                ],
            )
        stats.written += len(certs)
        log.info("batch_written", certs=len(certs), domains=len(domain_rows))
    except Exception as exc:
        log.error("write_error", error=str(exc), exc_info=True)
        stats.errors += len(certs)


async def main() -> None:
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
    )

    settings = get_settings()
    redis_client = aioredis.from_url(settings.redis_url, decode_responses=False)
    dedup = DedupFilter(redis_client)
    write_queue: asyncio.Queue = asyncio.Queue()
    stats = IngestStats()

    active_logs = [l for l in LOG_REGISTRY if l["enabled"]]
    log.info("starting", logs=[l["log_id"] for l in active_logs])

    tasks = [
        asyncio.create_task(follow_log(l, dedup, write_queue, stats, settings))
        for l in active_logs
    ]
    tasks.append(asyncio.create_task(writer(write_queue, stats)))
    await asyncio.gather(*tasks)


if __name__ == "__main__":
    asyncio.run(main())
