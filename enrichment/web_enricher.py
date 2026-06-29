"""
Web enricher — fetches apex domain homepage metadata and uses Claude Haiku
to extract company_name and company_industry.

Pipeline:
  1. GET https://<apex_domain> (first 8 KB of body)
  2. Extract <title>, og:site_name, og:description, meta[description]
  3. Call Claude Haiku with extracted text
  4. Parse structured JSON response: {company_name, company_industry}

Only runs on apex domains that have a live website. Falls back gracefully
on network errors, timeouts, or unparseable LLM responses.

Cost: ~$0.0003 per domain (claude-haiku-4-5, 200 input + 40 output tokens).
"""

import json
import re
from html.parser import HTMLParser

import anthropic
import httpx

from enrichment.base import BaseEnricher, EnrichmentResult

INDUSTRY_TAXONOMY = [
    "software", "fintech", "healthcare", "ecommerce", "education",
    "legal", "real_estate", "marketing", "logistics", "manufacturing",
    "media", "gaming", "crypto", "consulting", "other",
]

_BODY_READ_CHARS = 32_768   # 32 KB — meta tags are always in <head>
_GET_TIMEOUT = httpx.Timeout(connect=5.0, read=8.0, write=5.0, pool=5.0)
_UA = "Mozilla/5.0 (compatible; forelight-probe/1.0)"
_MODEL = "claude-haiku-4-5-20251001"

_SYSTEM_PROMPT = (
    "You extract structured company data from website metadata. "
    "Return only valid JSON with keys company_name and company_industry. "
    "No markdown, no explanation."
)


# ---------------------------------------------------------------------------
# HTML metadata extraction
# ---------------------------------------------------------------------------

class _MetaExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.og_site_name: str | None = None
        self.og_description: str | None = None
        self.meta_description: str | None = None
        self.title: str | None = None
        self._in_title = False
        self._past_head = False

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if self._past_head:
            return
        d = dict(attrs)
        if tag == "title":
            self._in_title = True
        elif tag == "meta":
            prop = (d.get("property") or "").lower()
            name = (d.get("name") or "").lower()
            content = d.get("content") or ""
            if prop == "og:site_name" and content:
                self.og_site_name = content[:200]
            elif prop == "og:description" and content:
                self.og_description = content[:400]
            elif name == "description" and content:
                self.meta_description = content[:400]
        elif tag == "body":
            self._past_head = True

    def handle_data(self, data: str) -> None:
        if self._in_title and not self._past_head:
            self.title = data.strip()[:200]
            self._in_title = False

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False


def _extract_metadata(html: str) -> dict[str, str]:
    p = _MetaExtractor()
    try:
        p.feed(html[:_BODY_READ_CHARS])
    except Exception:
        pass
    return {
        "name": p.og_site_name or p.title or "",
        "description": p.og_description or p.meta_description or "",
    }


async def _fetch_metadata(domain: str, http: httpx.AsyncClient) -> dict[str, str] | None:
    """GET the apex domain homepage and extract page metadata. Returns None if unreachable."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            r = await http.get(
                url,
                follow_redirects=True,
                timeout=_GET_TIMEOUT,
                headers={"User-Agent": _UA},
            )
            if r.status_code >= 500:
                continue
            meta = _extract_metadata(r.text)
            if meta["name"] or meta["description"]:
                return meta
        except Exception:
            continue
    return None


# ---------------------------------------------------------------------------
# LLM extraction
# ---------------------------------------------------------------------------

async def _call_llm(
    domain: str,
    meta: dict[str, str],
    api_key: str,
) -> tuple[str | None, str | None]:
    """Return (company_name, company_industry) via Claude Haiku. Both may be None."""
    industries = ", ".join(INDUSTRY_TAXONOMY)
    user_msg = (
        f"Domain: {domain}\n"
        f"Page title / site name: {meta['name']}\n"
        f"Description: {meta['description']}\n\n"
        f"Extract the company name and industry.\n"
        f"Industry must be exactly one of: {industries}\n"
        f"If you cannot determine a field with confidence, use null.\n"
        f'Return JSON only: {{"company_name": "...", "company_industry": "..."}}'
    )

    try:
        client = anthropic.AsyncAnthropic(api_key=api_key)
        msg = await client.messages.create(
            model=_MODEL,
            max_tokens=64,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_msg}],
        )
        raw = msg.content[0].text.strip()
        # Strip accidental markdown code fences
        raw = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw, flags=re.MULTILINE).strip()
        data = json.loads(raw)
        name = data.get("company_name") or None
        industry = data.get("company_industry") or None
        if name:
            name = str(name)[:256]
        if industry and industry not in INDUSTRY_TAXONOMY:
            industry = None
        return name, industry
    except Exception:
        return None, None


# ---------------------------------------------------------------------------
# Enricher
# ---------------------------------------------------------------------------

class WebEnricher(BaseEnricher):
    """
    Apex-domain enricher: fetches homepage metadata, calls Claude Haiku
    to extract company_name and company_industry.
    """

    def __init__(self, api_key: str, http_client: httpx.AsyncClient | None = None):
        self._api_key = api_key
        self._http = http_client

    async def enrich(
        self,
        domain: str,
        apex_domain: str,
        sans: list[str],
        issuer_org: str,
    ) -> EnrichmentResult:
        if not self._api_key:
            return EnrichmentResult()

        close_after = self._http is None
        http = self._http or httpx.AsyncClient(timeout=_GET_TIMEOUT)

        try:
            meta = await _fetch_metadata(apex_domain, http)
            if not meta:
                return EnrichmentResult()

            company_name, company_industry = await _call_llm(apex_domain, meta, self._api_key)
            return EnrichmentResult(
                company_name=company_name,
                company_industry=company_industry,
            )
        except Exception:
            return EnrichmentResult()
        finally:
            if close_after:
                await http.aclose()
