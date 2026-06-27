"""
Tests for enrichment modules.

DNS test uses real network (google.com). ASN test mocks ip-api.com.
PDL test verifies it skips gracefully without an API key.
"""

import json

import pytest
import httpx
from pytest_httpx import HTTPXMock

from enrichment.asn_lookup import AsnLookup, lookup_batch, _parse_asn_number, _detect_cdn
from enrichment.dns_resolver import resolve_ipv4, DnsResolver
from enrichment.firmographic_pdl import FirmographicPDL, enrich_domain
from enrichment.technographic import Technographic, detect_saas_vendor, is_saas_domain


# ---------------------------------------------------------------------------
# DNS resolver
# ---------------------------------------------------------------------------

async def test_dns_resolves_known_domain():
    ip = await resolve_ipv4("google.com")
    assert ip is not None
    parts = ip.split(".")
    assert len(parts) == 4
    assert all(p.isdigit() for p in parts)


async def test_dns_returns_none_for_invalid():
    ip = await resolve_ipv4("this-domain-definitely-does-not-exist-signal.invalid")
    assert ip is None


async def test_dns_enricher_returns_result():
    resolver = DnsResolver()
    result = await resolver.enrich("google.com", "google.com", [], "")
    assert result.ip is not None


# ---------------------------------------------------------------------------
# ASN lookup (mocked)
# ---------------------------------------------------------------------------

async def test_asn_lookup_batch(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        method="POST",
        url="http://ip-api.com/batch",
        json=[
            {
                "status": "success",
                "query": "1.1.1.1",
                "as": "AS13335 Cloudflare, Inc.",
                "asname": "CLOUDFLARENET",
                "org": "Cloudflare, Inc.",
                "isp": "Cloudflare, Inc.",
                "country": "United States",
                "countryCode": "US",
            }
        ],
    )
    async with httpx.AsyncClient() as http:
        results = await lookup_batch(["1.1.1.1"], http)

    assert "1.1.1.1" in results
    r = results["1.1.1.1"]
    assert r.asn == 13335
    assert r.asn_org == "Cloudflare, Inc."
    assert r.cdn_provider == "Cloudflare"
    assert r.country_code == "US"


async def test_asn_lookup_batch_failure_returns_empty(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        method="POST", url="http://ip-api.com/batch", status_code=429
    )
    async with httpx.AsyncClient() as http:
        results = await lookup_batch(["1.2.3.4"], http)
    assert results == {}


async def test_asn_lookup_empty_list():
    results = await lookup_batch([])
    assert results == {}


def test_parse_asn_number():
    assert _parse_asn_number("AS13335 Cloudflare, Inc.") == 13335
    assert _parse_asn_number("AS16509 Amazon.com, Inc.") == 16509
    assert _parse_asn_number("") is None
    assert _parse_asn_number("invalid") is None


def test_detect_cdn():
    assert _detect_cdn("CLOUDFLARENET", "") == "Cloudflare"
    assert _detect_cdn("FASTLY", "") == "Fastly"
    assert _detect_cdn("AMAZON-02", "") == "AWS"
    assert _detect_cdn("COMCAST", "") is None


# ---------------------------------------------------------------------------
# Technographic
# ---------------------------------------------------------------------------

def test_shopify_san_detected():
    vendor = detect_saas_vendor(["acme.com", "acme.myshopify.com"], "")
    assert vendor == "Shopify"


def test_vercel_san_detected():
    vendor = detect_saas_vendor(["myapp.com", "myapp.vercel.app"], "")
    assert vendor == "Vercel"


def test_netlify_san_detected():
    vendor = detect_saas_vendor(["site.com", "site.netlify.app"], "")
    assert vendor == "Netlify"


def test_hubspot_san_detected():
    vendor = detect_saas_vendor(["company.com", "company.hs-sites.com"], "")
    assert vendor == "HubSpot"


def test_no_saas_match_returns_none():
    vendor = detect_saas_vendor(["example.com", "api.example.com"], "Let's Encrypt")
    assert vendor is None


def test_cloudflare_issuer_fallback():
    vendor = detect_saas_vendor(["example.com"], "Cloudflare, Inc.")
    assert vendor == "Cloudflare"


def test_is_saas_domain():
    assert is_saas_domain("mystore.myshopify.com") is True
    assert is_saas_domain("myapp.vercel.app") is True
    assert is_saas_domain("mycompany.com") is False


async def test_technographic_enricher():
    tech = Technographic()
    result = await tech.enrich("acme.com", "acme.com", ["acme.com", "acme.myshopify.com"], "")
    assert result.saas_vendor == "Shopify"


# ---------------------------------------------------------------------------
# PDL firmographic
# ---------------------------------------------------------------------------

async def test_pdl_skips_without_api_key():
    pdl = FirmographicPDL(api_key="")
    result = await pdl.enrich("example.com", "example.com", [], "")
    assert result.company_name is None
    assert result.company_industry is None


async def test_pdl_enriches_with_api_key(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="https://api.peopledatalabs.com/v5/company/enrich?website=acme.com&pretty=false",
        json={
            "name": "Acme Corp",
            "industry": "technology",
            "size": "51-200",
            "location": {"country": "United States"},
        },
    )
    async with httpx.AsyncClient() as http:
        result = await enrich_domain("acme.com", "fake-api-key", http)

    assert result.company_name == "Acme Corp"
    assert result.company_industry == "technology"
    assert result.company_size == "51-200"
    assert result.company_country == "United States"


async def test_pdl_returns_empty_on_404(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="https://api.peopledatalabs.com/v5/company/enrich?website=unknown-corp.com&pretty=false",
        status_code=404,
    )
    async with httpx.AsyncClient() as http:
        result = await enrich_domain("unknown-corp.com", "fake-key", http)
    assert result.company_name is None
