"""
HTTP liveness probe — checks if a domain is reachable and identifies tech stack
from response headers and redirect targets.

Catches SaaS adoptions that SAN patterns and TXT records miss:
  - Shopify: x-shopify-stage header or redirect to *.myshopify.com
  - Vercel: x-vercel-id header or redirect to *.vercel.app
  - Wix: x-wix-request-id header
  - Squarespace: server: squarespace header
  - HubSpot CMS: x-hs-cf-cache-status header
  - Next.js: x-powered-by: Next.js header

Strategy: HEAD with follow_redirects=True on https:// then http://.
Falls back from HEAD to GET if the server returns 405.
Uses the shared httpx.AsyncClient for connection pooling.
"""

import httpx

from enrichment.base import BaseEnricher, EnrichmentResult

_UA = "Mozilla/5.0 (compatible; forelight-probe/1.0)"

# (header_name, value_substring_or_empty, vendor)
# empty value_substring = matches any non-empty header value
_HEADER_PATTERNS: list[tuple[str, str, str]] = [
    ("x-shopify-stage",        "",             "Shopify"),
    ("x-shopify-request-id",   "",             "Shopify"),
    ("x-vercel-id",            "",             "Vercel"),
    ("x-vercel-cache",         "",             "Vercel"),
    ("x-wix-request-id",       "",             "Wix"),
    ("x-ghost-cache-status",   "",             "Ghost"),
    ("x-hs-cf-cache-status",   "",             "HubSpot"),
    ("x-hubspot-correlation",  "",             "HubSpot"),
    ("x-squarespace-template", "",             "Squarespace"),
    ("x-powered-by",           "next.js",      "Next.js"),
    ("x-powered-by",           "wix",          "Wix"),
    ("x-powered-by",           "ghost",        "Ghost"),
    ("server",                 "squarespace",  "Squarespace"),
    ("server",                 "webflow",      "Webflow"),
]

# Substrings in the final URL (after redirect) → vendor
_REDIRECT_PATTERNS: list[tuple[str, str]] = [
    (".myshopify.com",   "Shopify"),
    (".hubspot.com",     "HubSpot"),
    (".hs-sites.com",    "HubSpot"),
    (".squarespace.com", "Squarespace"),
    (".webflow.io",      "Webflow"),
    (".netlify.app",     "Netlify"),
    (".vercel.app",      "Vercel"),
    (".github.io",       "GitHub Pages"),
    (".wixsite.com",     "Wix"),
    (".wpengine.com",    "WP Engine"),
]

_PROBE_TIMEOUT = httpx.Timeout(connect=3.0, read=5.0, write=5.0, pool=5.0)


def _detect_vendor(headers: httpx.Headers, final_url: str) -> str | None:
    h = {k.lower(): v.lower() for k, v in headers.items()}

    for hdr, value_sub, vendor in _HEADER_PATTERNS:
        if hdr in h:
            if not value_sub or value_sub in h[hdr]:
                return vendor

    for pattern, vendor in _REDIRECT_PATTERNS:
        if pattern in final_url.lower():
            return vendor

    return None


async def probe_domain(http_client: httpx.AsyncClient, domain: str) -> tuple[bool, str | None]:
    """Return (is_live, http_tech). Tries HTTPS→HTTP, HEAD→GET."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        for method in ("HEAD", "GET"):
            try:
                r = await http_client.request(
                    method, url,
                    follow_redirects=True,
                    timeout=_PROBE_TIMEOUT,
                    headers={"User-Agent": _UA},
                )
                if r.status_code == 405 and method == "HEAD":
                    continue  # server doesn't support HEAD, try GET
                if r.status_code < 500:
                    return True, _detect_vendor(r.headers, str(r.url))
                break  # 5xx — not live
            except Exception:
                if method == "HEAD":
                    continue  # try GET before giving up on this scheme
                break  # both methods failed on this scheme
    return False, None


class HttpProbe(BaseEnricher):
    def __init__(self, http_client: httpx.AsyncClient):
        self._http = http_client

    async def enrich(self, domain: str, apex_domain: str, sans: list[str], issuer_org: str) -> EnrichmentResult:
        is_live, http_tech = await probe_domain(self._http, domain)
        return EnrichmentResult(is_live=is_live, http_tech=http_tech)
