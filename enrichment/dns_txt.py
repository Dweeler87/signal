"""
DNS TXT record enricher — detects SaaS vendor adoption from DNS TXT records.

SAN pattern matching only catches platforms that appear in the cert's SANs.
TXT record verification catches the rest: HubSpot, Salesforce, Google Workspace,
Microsoft 365, Marketo, Atlassian, Zendesk, etc. all require a DNS TXT record
for domain ownership verification before they'll activate on a domain.

Uses aiodns (already a project dependency) for async TXT lookups.
All lookups are against the apex domain — TXT records live there.
"""

import asyncio

import aiodns

from enrichment.base import BaseEnricher, EnrichmentResult

# TXT record substring → vendor (first match wins, most specific first)
_TXT_PATTERNS: list[tuple[str, str]] = [
    # HubSpot — developer domain verification
    ("hubspot-developer-verification=",             "HubSpot"),
    # Salesforce — domain verification
    ("salesforce-domain-verification=",             "Salesforce"),
    # Microsoft 365 — domain verification token
    ("ms=ms",                                       "Microsoft 365"),
    # Microsoft 365 — SPF record
    ("spf.protection.outlook.com",                  "Microsoft 365"),
    # Google Workspace — SPF record (site-verification is too broad; SPF is reliable)
    ("include:_spf.google.com",                     "Google Workspace"),
    # Marketo
    ("marketo-domain-verification=",               "Adobe Marketo"),
    # Atlassian (Jira / Confluence Cloud)
    ("atlassian-domain-verification=",              "Atlassian"),
    # Zendesk
    ("include:mail.zendesk.com",                   "Zendesk"),
    # Segment
    ("segment-site-verification=",                  "Segment"),
    # Intercom
    ("intercom-verification=",                      "Intercom"),
    # SendGrid — SPF
    ("include:sendgrid.net",                        "SendGrid"),
    # Mailchimp — SPF
    ("include:servers.mcsv.net",                    "Mailchimp"),
    # Stripe — domain verification
    ("stripe-verification=",                        "Stripe"),
    # Shopify — domain verification (alternative to SAN detection)
    ("shopify-verification=",                       "Shopify"),
]


async def lookup_txt_vendor(apex_domain: str) -> str | None:
    """Return the first recognised SaaS vendor in the apex domain's TXT records."""
    try:
        resolver = aiodns.DNSResolver()
        result = await asyncio.wait_for(resolver.query(apex_domain, "TXT"), timeout=5.0)
        for record in result:
            txt = record.text.decode("utf-8", errors="ignore").lower()
            for pattern, vendor in _TXT_PATTERNS:
                if pattern.lower() in txt:
                    return vendor
    except Exception:
        pass
    return None


class DnsTxt(BaseEnricher):
    async def enrich(self, domain: str, apex_domain: str, sans: list[str], issuer_org: str) -> EnrichmentResult:
        vendor = await lookup_txt_vendor(apex_domain)
        return EnrichmentResult(txt_vendor=vendor)
