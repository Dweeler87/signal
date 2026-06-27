"""Pydantic request/response models for the SIGNAL API."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, Field, HttpUrl


# ---------------------------------------------------------------------------
# Signal
# ---------------------------------------------------------------------------

class SignalOut(BaseModel):
    signal_id: UUID
    signal_type: str
    domain: str
    apex_domain: str
    detected_at: datetime
    hosting_provider: str | None = None
    cdn_provider: str | None = None
    saas_vendor: str | None = None
    company_name: str | None = None
    company_industry: str | None = None
    company_size: str | None = None
    company_country: str | None = None

    model_config = {"from_attributes": True}


class SignalListResponse(BaseModel):
    data: list[SignalOut]
    next_cursor: str | None = None     # base64(detected_at ISO) — pass as ?cursor=
    total: int


# ---------------------------------------------------------------------------
# Watchlist
# ---------------------------------------------------------------------------

VALID_PATTERN_TYPES = {"apex_domain", "keyword", "industry", "saas_vendor"}


class WatchlistCreate(BaseModel):
    pattern_type: str = Field(..., description="One of: apex_domain, keyword, industry, saas_vendor")
    pattern: str = Field(..., min_length=1, max_length=256)


class WatchlistOut(BaseModel):
    watchlist_id: UUID
    pattern_type: str
    pattern: str
    created_at: datetime
    active: bool


class WatchlistListResponse(BaseModel):
    data: list[WatchlistOut]


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------

class KeyCreate(BaseModel):
    tier: str = Field(default="free", description="free | starter | pro")
    label: str | None = None
    buyer_verified: bool = False


class KeyOut(BaseModel):
    key: str = Field(..., description="Raw API key — shown once, store securely")
    key_hash: str
    tier: str
    created_at: datetime


# ---------------------------------------------------------------------------
# Webhooks
# ---------------------------------------------------------------------------

class WebhookCreate(BaseModel):
    url: str = Field(..., description="HTTPS URL to receive signal payloads")
    secret: str | None = Field(default=None, description="Optional secret for HMAC-SHA256 signature")


class WebhookOut(BaseModel):
    url: str
    has_secret: bool


# ---------------------------------------------------------------------------
# Health / metrics
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    status: str
    clickhouse: str
    redis: str


class MetricsResponse(BaseModel):
    total_certificates: int
    total_domains: int
    total_signals: int
    signals_last_24h: int
