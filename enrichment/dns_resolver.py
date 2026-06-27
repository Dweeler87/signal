"""
Async DNS resolver — returns the first IPv4 address for a domain.
Uses asyncio.to_thread + socket.getaddrinfo for cross-platform compatibility.
"""

import asyncio
import ipaddress
import socket

from enrichment.base import BaseEnricher, EnrichmentResult


class DnsResolver(BaseEnricher):
    async def enrich(self, domain: str, apex_domain: str, sans: list[str], issuer_org: str) -> EnrichmentResult:
        ip = await resolve_ipv4(domain)
        return EnrichmentResult(ip=ip)


async def resolve_ipv4(domain: str) -> str | None:
    """Return the first IPv4 address for domain, or None on failure."""
    try:
        loop = asyncio.get_event_loop()
        results = await asyncio.wait_for(
            loop.run_in_executor(None, _getaddrinfo, domain),
            timeout=5.0,
        )
        for _family, _type, _proto, _canonname, sockaddr in results:
            ip_str = sockaddr[0]
            try:
                addr = ipaddress.ip_address(ip_str)
                if isinstance(addr, ipaddress.IPv4Address):
                    return ip_str
            except ValueError:
                continue
        return None
    except Exception:
        return None


def _getaddrinfo(domain: str) -> list:
    return socket.getaddrinfo(domain, None, socket.AF_INET)
