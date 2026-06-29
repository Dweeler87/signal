"""
WHOIS enricher — fetches domain registration date and registered organization name.

Domain age relative to first cert issuance is a strong signal multiplier:
  - Domain registered < 30 days before first cert = brand new company launching infra
  - Domain 5 years old + new cert = expansion move on existing business

The WHOIS `org` field is the registered organization name (company-level data, not PII).
It serves as a zero-cost fallback for company_name when PDL is disabled.
No registrant names, emails, or physical addresses are read or persisted.

Uses python-whois (sync) wrapped in asyncio.to_thread to avoid blocking the event loop.
"""

import asyncio
from datetime import datetime

from enrichment.base import BaseEnricher, EnrichmentResult

_WHOIS_TIMEOUT = 10.0  # seconds — some WHOIS servers are slow


async def get_whois_data(apex_domain: str) -> tuple[datetime | None, str | None]:
    """Return (creation_date, org_name) from WHOIS, or (None, None) on failure."""
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(_whois_query, apex_domain),
            timeout=_WHOIS_TIMEOUT,
        )
        if result is None:
            return None, None

        creation = result.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        reg_date = creation.replace(tzinfo=None) if isinstance(creation, datetime) else None

        org = result.org
        if isinstance(org, list):
            org = org[0]
        company_name = _clean_org(org)

        return reg_date, company_name
    except Exception:
        pass
    return None, None


def _clean_org(org: str | None) -> str | None:
    """Strip WHOIS privacy/proxy noise. Returns None if the org is a privacy service."""
    if not org or not isinstance(org, str):
        return None
    org = org.strip()
    if not org:
        return None
    # Common WHOIS privacy/proxy strings, error states, and placeholder values to discard
    noise = ("privacy", "proxy", "redacted", "whoisguard", "perfect privacy",
             "domains by proxy", "contact privacy", "withheld", "data protected",
             "domain expired", "data expunged", "not disclosed", "data masked",
             "registration private", "identity protection", "n/a", "none",
             "see registrar", "domain administrator")
    lower = org.lower()
    if any(n in lower for n in noise):
        return None
    if lower in ("n/a", "none", "na", "-", ".", "null"):
        return None
    # Trim legal suffixes that add noise without meaning
    return org[:128]  # cap length


def _whois_query(domain: str):
    try:
        import whois  # deferred import — only needed here
        return whois.whois(domain)
    except Exception:
        return None


class WhoisLookup(BaseEnricher):
    async def enrich(self, domain: str, apex_domain: str, sans: list[str], issuer_org: str) -> EnrichmentResult:
        reg_date, company_name = await get_whois_data(apex_domain)
        return EnrichmentResult(domain_registered_at=reg_date, company_name=company_name)
