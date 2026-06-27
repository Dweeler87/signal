"""
Technographic inference — detect SaaS vendor adoption from cert SAN patterns.

Core signal: if a cert covers a custom apex domain AND includes a known SaaS
platform's domain as a SAN, the custom domain has adopted that SaaS vendor.

Example: cert SANs = ["acme.com", "acme.myshopify.com"] → acme.com is on Shopify.
"""

from enrichment.base import BaseEnricher, EnrichmentResult

# SAN suffix → SaaS vendor (ordered by specificity, most specific first)
_SAN_PATTERNS: list[tuple[str, str]] = [
    # E-commerce
    (".myshopify.com", "Shopify"),
    (".shopify.com", "Shopify"),
    (".myshopify.dev", "Shopify"),
    (".bigcommerce.com", "BigCommerce"),
    (".squarespace.com", "Squarespace"),
    (".wixsite.com", "Wix"),
    (".weebly.com", "Weebly"),
    # Hosting / deploy platforms
    (".vercel.app", "Vercel"),
    (".netlify.app", "Netlify"),
    (".netlify.com", "Netlify"),
    (".pages.dev", "Cloudflare Pages"),
    (".workers.dev", "Cloudflare Workers"),
    (".onrender.com", "Render"),
    (".railway.app", "Railway"),
    (".fly.dev", "Fly.io"),
    (".github.io", "GitHub Pages"),
    (".gitlab.io", "GitLab Pages"),
    (".azurewebsites.net", "Azure App Service"),
    (".azurestaticapps.net", "Azure Static Web Apps"),
    (".cloudfront.net", "AWS CloudFront"),
    (".elasticbeanstalk.com", "AWS Elastic Beanstalk"),
    (".s3-website", "AWS S3"),
    (".herokuapp.com", "Heroku"),
    (".heroku.com", "Heroku"),
    (".firebaseapp.com", "Firebase"),
    # CMS / website builders
    (".wpengine.com", "WP Engine"),
    (".pantheonsite.io", "Pantheon"),
    (".kinsta.cloud", "Kinsta"),
    (".webflow.io", "Webflow"),
    (".ghost.io", "Ghost"),
    # Marketing / CRM
    (".hubspot.com", "HubSpot"),
    (".hs-sites.com", "HubSpot"),
    (".salesforce.com", "Salesforce"),
    (".force.com", "Salesforce"),
    (".marketo.com", "Adobe Marketo"),
    (".pardot.com", "Salesforce Pardot"),
    # Customer support
    (".zendesk.com", "Zendesk"),
    (".zendeskservices.com", "Zendesk"),
    (".intercom.io", "Intercom"),
    (".freshdesk.com", "Freshdesk"),
    # Email / communication
    (".sendgrid.net", "SendGrid"),
    (".mailchimp.com", "Mailchimp"),
    # Payments
    (".stripe.com", "Stripe"),
]

# Issuer org substrings → SaaS vendor (lower confidence — only when no SAN match)
_ISSUER_PATTERNS: list[tuple[str, str]] = [
    ("Cloudflare", "Cloudflare"),   # Cloudflare Access / Tunnel certs
]

# Known SaaS root domains — SANs that ARE one of these are the platform domain,
# not the custom domain. We skip these when looking for the customer domain.
_SAAS_DOMAINS: frozenset[str] = frozenset(
    suffix.lstrip(".") for suffix, _ in _SAN_PATTERNS
)


class Technographic(BaseEnricher):
    async def enrich(self, domain: str, apex_domain: str, sans: list[str], issuer_org: str) -> EnrichmentResult:
        vendor = detect_saas_vendor(sans, issuer_org)
        return EnrichmentResult(saas_vendor=vendor)


def detect_saas_vendor(sans: list[str], issuer_org: str) -> str | None:
    """
    Return the name of a detected SaaS vendor, or None.
    Checks SAN patterns first, then issuer org patterns.
    """
    # Check if any SAN matches a known SaaS platform suffix
    for san in sans:
        san_lower = san.lower().lstrip("*.")
        for suffix, vendor in _SAN_PATTERNS:
            if san_lower.endswith(suffix.lstrip(".")):
                return vendor

    # Fallback: issuer org match
    for pattern, vendor in _ISSUER_PATTERNS:
        if pattern.lower() in issuer_org.lower():
            return vendor

    return None


def is_saas_domain(domain: str) -> bool:
    """True if this domain is itself a SaaS platform domain (not a customer domain)."""
    d = domain.lower()
    return any(d.endswith(suffix.lstrip(".")) for suffix, _ in _SAN_PATTERNS)
