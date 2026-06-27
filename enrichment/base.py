"""Abstract enricher interface. All enrichers implement enrich()."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class EnrichmentResult:
    ip: str | None = None
    asn: int | None = None
    asn_org: str | None = None
    hosting_provider: str | None = None
    cdn_provider: str | None = None
    country_code: str | None = None
    company_name: str | None = None
    company_industry: str | None = None
    company_size: str | None = None
    company_country: str | None = None
    saas_vendor: str | None = None

    def merge(self, other: "EnrichmentResult") -> "EnrichmentResult":
        """Merge another result into this one, other wins on non-None fields."""
        for field in self.__dataclass_fields__:
            val = getattr(other, field)
            if val is not None:
                setattr(self, field, val)
        return self


class BaseEnricher(ABC):
    @abstractmethod
    async def enrich(self, domain: str, apex_domain: str, sans: list[str], issuer_org: str) -> EnrichmentResult:
        """Enrich a domain. Return partial results — None fields are skipped."""
        ...
