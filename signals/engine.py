"""
Signal engine — converts enriched domain records into typed signal events.

Signal types generated:
  new_apex_domain          — first time we see an apex domain (new company/product)
  new_subdomain            — new subdomain under a known apex domain
  saas_adoption_detected   — cert pattern reveals SaaS vendor adoption
  infrastructure_expansion — apex domain added 5+ new subdomains in 24 hours

Dedup: before inserting, checks if a signal already exists for (signal_type, domain).
Uses FINAL on ClickHouse reads to get the deduplicated domain view.

Run as a module (called by the enrichment worker after each batch):
  from signals.engine import generate_signals
  await generate_signals(ch, domains)
"""

import asyncio
from datetime import datetime, timedelta, timezone

import structlog

from signals.types import Signal, SignalType

log = structlog.get_logger()

EXPANSION_THRESHOLD = 5      # new subdomains in 24h to trigger infrastructure_expansion
EXPANSION_WINDOW_HOURS = 24


async def generate_signals(ch, domain_names: list[str]) -> list[Signal]:
    """
    Generate signals for a batch of newly-enriched domain names.
    Inserts new signals to ClickHouse. Returns the list of signals generated.
    """
    if not domain_names:
        return []

    generated: list[Signal] = []

    # Fetch enriched domain data for this batch
    placeholders = ", ".join(f"'{d}'" for d in domain_names)
    rows = ch.query(f"""
        SELECT
            domain, apex_domain, is_apex, is_wildcard,
            first_seen_cert, first_seen_at,
            company_name, company_industry, hosting_provider,
            saas_vendor
        FROM signal.domains FINAL
        WHERE domain IN ({placeholders})
    """).result_rows

    for row in rows:
        (domain, apex_domain, is_apex, is_wildcard,
         first_seen_cert, first_seen_at,
         company_name, company_industry, hosting_provider, saas_vendor) = row

        # Skip wildcards for signal generation — too noisy
        if is_wildcard:
            continue

        candidates: list[Signal] = []

        if is_apex:
            candidates.append(Signal(
                signal_type=SignalType.NEW_APEX_DOMAIN,
                domain=domain,
                apex_domain=apex_domain,
                cert_sha256_tbs=first_seen_cert,
                company_name=company_name,
                company_industry=company_industry,
                hosting_provider=hosting_provider,
                saas_vendor=saas_vendor,
            ))
        else:
            candidates.append(Signal(
                signal_type=SignalType.NEW_SUBDOMAIN,
                domain=domain,
                apex_domain=apex_domain,
                cert_sha256_tbs=first_seen_cert,
                company_name=company_name,
                company_industry=company_industry,
                hosting_provider=hosting_provider,
            ))

        if saas_vendor:
            candidates.append(Signal(
                signal_type=SignalType.SAAS_ADOPTION_DETECTED,
                domain=domain,
                apex_domain=apex_domain,
                cert_sha256_tbs=first_seen_cert,
                company_name=company_name,
                company_industry=company_industry,
                saas_vendor=saas_vendor,
            ))

        # Dedup check: skip if signal already exists for this (type, domain) pair
        for signal in candidates:
            if not await _signal_exists(ch, signal.signal_type, domain):
                generated.append(signal)

    # Check infrastructure_expansion separately (requires aggregation)
    expansion_signals = await _check_infrastructure_expansion(ch, domain_names)
    for signal in expansion_signals:
        if not await _signal_exists(ch, SignalType.INFRASTRUCTURE_EXPANSION, signal.apex_domain):
            generated.append(signal)

    # Bulk insert all new signals
    if generated:
        rows_to_insert = [s.to_row() for s in generated]
        ch.insert("signals", rows_to_insert, column_names=Signal.COLUMN_NAMES)
        log.info("signals_generated", count=len(generated), types=_type_counts(generated))

    return generated


async def _signal_exists(ch, signal_type: SignalType, domain: str) -> bool:
    """Check if a signal already exists for this (type, domain) pair."""
    result = ch.query(
        "SELECT count() FROM signal.signals WHERE signal_type = %(t)s AND domain = %(d)s",
        parameters={"t": signal_type.value, "d": domain},
    ).result_rows
    return result[0][0] > 0


async def _check_infrastructure_expansion(ch, domain_names: list[str]) -> list[Signal]:
    """
    For each unique apex domain in this batch, check if it has added
    EXPANSION_THRESHOLD+ new subdomains in the last EXPANSION_WINDOW_HOURS hours.
    """
    # Get unique apex domains from the batch
    placeholders = ", ".join(f"'{d}'" for d in domain_names)
    apex_rows = ch.query(f"""
        SELECT DISTINCT apex_domain
        FROM signal.domains FINAL
        WHERE domain IN ({placeholders}) AND is_apex = false
    """).result_rows

    signals: list[Signal] = []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=EXPANSION_WINDOW_HOURS)

    for (apex,) in apex_rows:
        count_row = ch.query(
            """
            SELECT count() FROM signal.domains FINAL
            WHERE apex_domain = %(apex)s
              AND is_apex = false
              AND is_wildcard = false
              AND first_seen_at >= %(cutoff)s
            """,
            parameters={"apex": apex, "cutoff": cutoff},
        ).result_rows

        new_sub_count = count_row[0][0]
        if new_sub_count >= EXPANSION_THRESHOLD:
            # Get cert hash from the apex domain row
            apex_row = ch.query(
                "SELECT first_seen_cert, company_name, company_industry, hosting_provider FROM signal.domains FINAL WHERE domain = %(d)s",
                parameters={"d": apex},
            ).result_rows
            if apex_row:
                cert_hash, company_name, company_industry, hosting_provider = apex_row[0]
            else:
                cert_hash = b"\x00" * 32
                company_name = company_industry = hosting_provider = None

            signals.append(Signal(
                signal_type=SignalType.INFRASTRUCTURE_EXPANSION,
                domain=apex,
                apex_domain=apex,
                cert_sha256_tbs=cert_hash,
                company_name=company_name,
                company_industry=company_industry,
                hosting_provider=hosting_provider,
            ))

    return signals


def _type_counts(signals: list[Signal]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for s in signals:
        counts[s.signal_type.value] = counts.get(s.signal_type.value, 0) + 1
    return counts
