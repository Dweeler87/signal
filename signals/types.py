"""Signal type definitions and the typed signal dataclass."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class SignalType(str, Enum):
    NEW_APEX_DOMAIN = "new_apex_domain"
    NEW_SUBDOMAIN = "new_subdomain"
    SAAS_ADOPTION_DETECTED = "saas_adoption_detected"
    INFRASTRUCTURE_EXPANSION = "infrastructure_expansion"


SIGNAL_COLUMN_NAMES: list[str] = [
    "signal_type", "domain", "apex_domain", "detected_at",
    "cert_sha256_tbs", "company_name", "company_industry",
    "hosting_provider", "saas_vendor", "delivered", "delivered_at",
]


@dataclass
class Signal:
    signal_type: SignalType
    domain: str
    apex_domain: str
    cert_sha256_tbs: bytes
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    company_name: str | None = None
    company_industry: str | None = None
    hosting_provider: str | None = None
    saas_vendor: str | None = None

    # Class-level constant (not a dataclass field)
    COLUMN_NAMES = SIGNAL_COLUMN_NAMES

    def to_row(self) -> list:
        return [
            self.signal_type.value,
            self.domain,
            self.apex_domain,
            self.detected_at,
            self.cert_sha256_tbs,
            self.company_name,
            self.company_industry,
            self.hosting_provider,
            self.saas_vendor,
            False,   # delivered
            None,    # delivered_at
        ]
