"""
WHOIS domain age enricher — fetches domain registration date.

Domain age relative to first cert issuance is a strong signal multiplier:
  - Domain registered < 30 days before first cert = brand new company launching infra
  - Domain 5 years old + new cert = expansion move on existing business

Only stores creation_date — no registrant name, email, or address is read or persisted.
Uses python-whois (sync) wrapped in asyncio.to_thread to avoid blocking the event loop.
"""

import asyncio
from datetime import datetime

from enrichment.base import BaseEnricher, EnrichmentResult

_WHOIS_TIMEOUT = 10.0  # seconds — some WHOIS servers are slow


async def get_registration_date(apex_domain: str) -> datetime | None:
    """Return domain creation date from WHOIS, or None on failure / WHOIS privacy."""
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(_whois_query, apex_domain),
            timeout=_WHOIS_TIMEOUT,
        )
        if result is None:
            return None
        creation = result.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(creation, datetime):
            return creation.replace(tzinfo=None)  # store as naive UTC-equivalent
    except Exception:
        pass
    return None


def _whois_query(domain: str):
    try:
        import whois  # deferred import — only needed here
        return whois.whois(domain)
    except Exception:
        return None


class WhoisLookup(BaseEnricher):
    async def enrich(self, domain: str, apex_domain: str, sans: list[str], issuer_org: str) -> EnrichmentResult:
        reg_date = await get_registration_date(apex_domain)
        return EnrichmentResult(domain_registered_at=reg_date)
