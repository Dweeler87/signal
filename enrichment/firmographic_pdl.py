"""
PDL (People Data Labs) Company Enrichment API adapter.

Enriches apex domains with company-level firmographic data:
  company_name, industry, size_range, country

Only called for apex domains to conserve API credits.
Gracefully skips if PDL_API_KEY is not configured.

PDL Company Enrich API:
  GET https://api.peopledatalabs.com/v5/company/enrich?website=<domain>
  Headers: X-Api-Key: <key>
  Response: { name, industry, size, location.country, ... }

Sign up at https://www.peopledatalabs.com/ to get an API key.
Free tier: 100 lookups/month. Pro: $98/month for 1,000 lookups.
"""

import httpx

from enrichment.base import BaseEnricher, EnrichmentResult

PDL_BASE = "https://api.peopledatalabs.com/v5/company/enrich"


class FirmographicPDL(BaseEnricher):
    def __init__(self, api_key: str, http_client: httpx.AsyncClient | None = None):
        self._api_key = api_key
        self._http = http_client

    async def enrich(self, domain: str, apex_domain: str, sans: list[str], issuer_org: str) -> EnrichmentResult:
        if not self._api_key:
            return EnrichmentResult()
        # Only enrich at the apex domain level to save credits
        target = apex_domain or domain
        return await enrich_domain(target, self._api_key, self._http)


async def enrich_domain(
    apex_domain: str, api_key: str, http: httpx.AsyncClient | None = None
) -> EnrichmentResult:
    """Call PDL Company API for an apex domain. Returns empty result on any failure."""
    if not api_key:
        return EnrichmentResult()

    close_after = False
    if http is None:
        http = httpx.AsyncClient(timeout=10)
        close_after = True

    try:
        r = await http.get(
            PDL_BASE,
            params={"website": apex_domain, "pretty": "false"},
            headers={"X-Api-Key": api_key},
        )
        if r.status_code == 404:
            return EnrichmentResult()  # company not found — normal
        r.raise_for_status()
        data = r.json()
    except Exception:
        return EnrichmentResult()
    finally:
        if close_after:
            await http.aclose()

    return EnrichmentResult(
        company_name=data.get("name"),
        company_industry=data.get("industry"),
        company_size=_normalize_size(data.get("size")),
        company_country=_nested(data, "location", "country"),
    )


def _normalize_size(size: str | None) -> str | None:
    """PDL returns sizes like '1-10', '11-50', '51-200', etc. Keep as-is."""
    return size if isinstance(size, str) else None


def _nested(data: dict, *keys: str) -> str | None:
    cur = data
    for key in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur if isinstance(cur, str) else None
