"""
Enrichment worker — polls ClickHouse for unenriched domains, runs enrichers,
upserts results, then calls the signal engine.

Run:
  python -m enrichment.worker

Architecture:
  1. Poll domains FINAL WHERE enrichment_at IS NULL (batch of N)
  2. For each domain, fetch its cert SANs + issuer from certificates table
  3. Run DNS → ASN → technographic enrichers concurrently
  4. For apex domains only: run PDL firmographic enricher
  5. Upsert enriched row back to domains table
  6. Call signal engine on newly-enriched domains
"""

import asyncio
import logging
import time
from datetime import datetime, timezone

import httpx
import structlog

from db.client import get_client, get_settings
from enrichment.asn_lookup import AsnLookup
from enrichment.base import EnrichmentResult
from enrichment.dns_resolver import DnsResolver
from enrichment.dns_txt import DnsTxt
from enrichment.firmographic_pdl import FirmographicPDL
from enrichment.http_probe import HttpProbe
from enrichment.technographic import Technographic
from enrichment.whois_lookup import WhoisLookup
from signals.engine import generate_signals

log = structlog.get_logger()


async def enrich_domain(
    domain: str,
    apex_domain: str,
    is_apex: bool,
    sans: list[str],
    issuer_org: str,
    dns: DnsResolver,
    asn: AsnLookup,
    tech: Technographic,
    pdl: FirmographicPDL,
) -> EnrichmentResult:
    """Run all enrichers for a single domain and merge results."""
    result = EnrichmentResult()

    # DNS + ASN + technographic run concurrently
    dns_result, tech_result = await asyncio.gather(
        dns.enrich(domain, apex_domain, sans, issuer_org),
        tech.enrich(domain, apex_domain, sans, issuer_org),
        return_exceptions=True,
    )

    if isinstance(dns_result, EnrichmentResult):
        result.merge(dns_result)
    if isinstance(tech_result, EnrichmentResult):
        result.merge(tech_result)

    # ASN lookup needs the resolved IP — run after DNS
    if result.ip:
        try:
            asn_result = await asn.enrich(domain, apex_domain, sans, issuer_org)
            result.merge(asn_result)
        except Exception:
            pass

    # PDL: only for apex domains, only if key is set
    if is_apex:
        try:
            pdl_result = await pdl.enrich(domain, apex_domain, sans, issuer_org)
            result.merge(pdl_result)
        except Exception:
            pass

    return result


async def run_batch(ch, settings, enrichers: dict) -> int:
    """
    Poll and enrich one batch of unenriched domains.
    Returns number of domains processed.

    saas_vendor is already populated by the log follower at ingest time
    (from cert SAN pattern matching). We only run DNS/ASN/PDL here.
    """
    dns = enrichers["dns"]
    asn = enrichers["asn"]
    pdl = enrichers["pdl"]
    dns_txt = enrichers["dns_txt"]
    whois = enrichers["whois"]
    http_probe = enrichers["http_probe"]

    # Poll for unenriched domains (FINAL gives deduplicated view)
    rows = ch.query(f"""
        SELECT domain, apex_domain, is_apex, is_wildcard,
               first_seen_cert, first_seen_at, saas_vendor
        FROM signal.domains FINAL
        WHERE enrichment_at IS NULL
        LIMIT {settings.enrichment_batch_size}
    """).result_rows

    if not rows:
        return 0

    log.info("enrichment_batch_start", count=len(rows))

    sem = asyncio.Semaphore(20)
    # PDL free tier: ~1 req/sec. Pro tier: ~10 req/sec.
    pdl_sem = asyncio.Semaphore(1)
    enriched_domains: list[str] = []
    insert_rows = []

    async def _enrich_one(row):
        domain, apex_domain, is_apex, is_wildcard, first_seen_cert, first_seen_at, saas_vendor = row

        async with sem:
            # DNS resolution
            dns_result = await dns.enrich(domain, apex_domain, [], "")
            result = dns_result

            # ASN/CDN lookup (needs the IP from DNS)
            if result.ip:
                try:
                    asn_result = await asn.enrich(domain, apex_domain, [], "")
                    result.merge(asn_result)
                except Exception:
                    pass

            # PDL firmographic: apex domains only, rate-limited separately
            if is_apex:
                try:
                    async with pdl_sem:
                        pdl_result = await pdl.enrich(domain, apex_domain, [], "")
                    result.merge(pdl_result)
                    if pdl_result.company_name:
                        log.info("pdl_hit", domain=apex_domain, company=pdl_result.company_name)
                except Exception as exc:
                    log.warning("pdl_error", domain=apex_domain, error=str(exc))

            # DNS TXT, WHOIS, HTTP probe: apex domains only
            if is_apex:
                try:
                    txt_result = await dns_txt.enrich(domain, apex_domain, [], "")
                    result.merge(txt_result)
                except Exception:
                    pass

                try:
                    whois_result = await whois.enrich(domain, apex_domain, [], "")
                    result.merge(whois_result)
                except Exception:
                    pass

                try:
                    http_result = await http_probe.enrich(domain, apex_domain, [], "")
                    result.merge(http_result)
                    if http_result.http_tech:
                        log.info("http_tech_detected", domain=domain, tech=http_result.http_tech)
                except Exception:
                    pass

        enriched_at = datetime.now(timezone.utc)

        # Ensure first_seen_cert is exactly 32 bytes (FixedString(32) requirement)
        cert_bytes = first_seen_cert
        if isinstance(cert_bytes, (bytes, bytearray)):
            cert_bytes = bytes(cert_bytes)[:32].ljust(32, b'\x00')
        else:
            cert_bytes = b'\x00' * 32

        insert_rows.append([
            domain, apex_domain, is_wildcard, is_apex,
            cert_bytes, first_seen_at,
            first_seen_at,              # last_seen_at
            saas_vendor,                # already set by log follower
            result.ip,
            result.asn,
            result.asn_org,
            result.hosting_provider,
            result.cdn_provider,
            result.country_code,
            result.company_name,
            result.company_industry,
            result.company_size,
            result.company_country,
            result.txt_vendor,
            result.http_tech,
            result.is_live,
            result.domain_registered_at,
            enriched_at,
        ])
        enriched_domains.append(domain)

    await asyncio.gather(*[_enrich_one(row) for row in rows])

    if insert_rows:
        ch.insert(
            "domains",
            insert_rows,
            column_names=[
                "domain", "apex_domain", "is_wildcard", "is_apex",
                "first_seen_cert", "first_seen_at", "last_seen_at",
                "saas_vendor",
                "ip", "asn", "asn_org", "hosting_provider", "cdn_provider",
                "country_code", "company_name", "company_industry",
                "company_size", "company_country",
                "txt_vendor", "http_tech", "is_live", "domain_registered_at",
                "enrichment_at",
            ],
        )

    await generate_signals(ch, enriched_domains)

    log.info("enrichment_batch_done", count=len(enriched_domains))
    return len(enriched_domains)


async def main() -> None:
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
    )

    settings = get_settings()
    ch = get_client()

    async with httpx.AsyncClient(timeout=10) as http:
        enrichers = {
            "dns": DnsResolver(),
            "asn": AsnLookup(http_client=http),
            "tech": Technographic(),
            "pdl": FirmographicPDL(api_key=settings.pdl_api_key, http_client=http),
            "dns_txt": DnsTxt(),
            "whois": WhoisLookup(),
            "http_probe": HttpProbe(http_client=http),
        }

        log.info("enrichment_worker_started", pdl_enabled=bool(settings.pdl_api_key))

        while True:
            try:
                processed = await run_batch(ch, settings, enrichers)
                if processed == 0:
                    log.debug("no_domains_to_enrich")
                    await asyncio.sleep(settings.enrichment_poll_interval)
            except Exception as exc:
                log.error("enrichment_error", error=str(exc), exc_info=True)
                await asyncio.sleep(30)


if __name__ == "__main__":
    asyncio.run(main())
