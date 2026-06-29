"""
ASN / hosting / CDN lookup via ip-api.com batch endpoint.
Free tier: 45 requests/minute, 100 IPs per request → 4,500 IPs/min.
No API key required.

Returns per-IP: ASN number, ASN org, hosting provider, CDN provider, country code.
CDN detection is based on ASN name pattern matching.
"""

import httpx

from enrichment.base import BaseEnricher, EnrichmentResult
from enrichment.dns_resolver import resolve_ipv4

IP_API_BATCH_URL = "http://ip-api.com/batch"
IP_API_FIELDS = "status,country,countryCode,isp,org,as,asname,query"

# Known CDN ASN names (partial matches — normalized to uppercase)
_CDN_ASN_PATTERNS: dict[str, str] = {
    "CLOUDFLARENET": "Cloudflare",
    "FASTLY": "Fastly",
    "AKAMAI": "Akamai",
    "EDGECAST": "Edgecast/Verizon",
    "AMAZON": "AWS",
    "AMAZON-02": "AWS",
    "GOOGLE": "Google Cloud",
    "MICROSOFT-CORP": "Azure",
    "MICROSOFT": "Azure",
    "DIGITALOCEAN": "DigitalOcean",
    "LINODE": "Linode",
    "HETZNER": "Hetzner",
    "OVH": "OVH",
}

# Hosting provider name normalization (isp/org field substrings)
_HOSTING_PATTERNS: dict[str, str] = {
    "Amazon": "AWS",
    "Google": "Google Cloud",
    "Microsoft": "Azure",
    "Cloudflare": "Cloudflare",
    "DigitalOcean": "DigitalOcean",
    "Linode": "Linode",
    "Hetzner": "Hetzner",
    "OVH": "OVH",
    "Fastly": "Fastly",
    "Akamai": "Akamai",
    "Vultr": "Vultr",
    "Rackspace": "Rackspace",
}


class AsnLookup(BaseEnricher):
    def __init__(self, http_client: httpx.AsyncClient | None = None):
        self._http = http_client

    async def enrich(self, domain: str, apex_domain: str, sans: list[str], issuer_org: str) -> EnrichmentResult:
        ip = await resolve_ipv4(domain)
        if not ip:
            return EnrichmentResult()
        results = await lookup_batch([ip], self._http)
        return results.get(ip, EnrichmentResult())


async def lookup_batch(
    ips: list[str], http: httpx.AsyncClient | None = None
) -> dict[str, EnrichmentResult]:
    """
    Look up ASN/hosting/CDN for up to 100 IPs.
    Returns a dict mapping ip → EnrichmentResult.
    """
    if not ips:
        return {}

    payload = [{"query": ip, "fields": IP_API_FIELDS} for ip in ips[:100]]

    close_after = False
    if http is None:
        http = httpx.AsyncClient(timeout=10)
        close_after = True

    try:
        r = await http.post(IP_API_BATCH_URL, json=payload)
        r.raise_for_status()
        items = r.json()
    except Exception:
        return {}
    finally:
        if close_after:
            await http.aclose()

    out: dict[str, EnrichmentResult] = {}
    for item in items:
        if item.get("status") != "success":
            continue
        ip = item.get("query", "")
        asn_str = item.get("as", "")  # e.g. "AS13335 Cloudflare, Inc."
        asn_num = _parse_asn_number(asn_str)
        asn_name = item.get("asname", "").upper()

        cdn = _detect_cdn(asn_name, asn_str)
        hosting = _detect_hosting(item.get("org", ""), item.get("isp", ""))

        raw_org = item.get("org") or item.get("isp") or ""
        out[ip] = EnrichmentResult(
            ip=ip,
            asn=asn_num,
            asn_org=raw_org,
            hosting_provider=hosting or _normalize_org(raw_org),
            cdn_provider=cdn,
            country_code=item.get("countryCode"),
        )

    return out


def _parse_asn_number(as_str: str) -> int | None:
    """Parse 'AS13335 Cloudflare, Inc.' → 13335."""
    try:
        token = as_str.split()[0]
        if token.upper().startswith("AS"):
            return int(token[2:])
    except (IndexError, ValueError):
        pass
    return None


def _detect_cdn(asn_name: str, as_str: str) -> str | None:
    for pattern, name in _CDN_ASN_PATTERNS.items():
        if pattern in asn_name:
            return name
    return None


def _detect_hosting(org: str, isp: str) -> str | None:
    combined = f"{org} {isp}"
    for pattern, name in _HOSTING_PATTERNS.items():
        if pattern.lower() in combined.lower():
            return name
    return None


_ORG_NOISE = (" inc.", ", inc", " llc", ", llc", " ltd", ", ltd", " corp.",
              ", corp", " co.", " limited", " s.a.", " b.v.", " gmbh")


def _normalize_org(org: str) -> str | None:
    """Return a readable org name for unknown providers, stripping legal suffixes."""
    if not org:
        return None
    cleaned = org.strip()
    lower = cleaned.lower()
    for suffix in _ORG_NOISE:
        if lower.endswith(suffix):
            cleaned = cleaned[:len(cleaned) - len(suffix)].strip().rstrip(",")
            break
    return cleaned[:80] if cleaned else None
