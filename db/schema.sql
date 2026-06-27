-- SIGNAL ClickHouse Schema
-- Apply with: python scripts/apply_schema.py
-- PII-free by construction: no registrant fields exist.
-- Dedup key is sha256_tbs (TBS hash), not leaf hash — handles pre-cert/cert pairs.

CREATE DATABASE IF NOT EXISTS signal;

USE signal;

-- ---------------------------------------------------------------------------
-- CT log registry
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ct_logs (
    log_id      String,
    operator    LowCardinality(String),
    url         String,
    description String,
    state       Enum8('active'=1, 'paused'=2, 'retired'=3),
    api_type    Enum8('tile'=1, 'rfc6962'=2),
    added_at    DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY log_id;

-- Seed known logs
INSERT INTO ct_logs (log_id, operator, url, description, state, api_type) VALUES
('xenon2025h2',  'google',      'https://ct.googleapis.com/logs/us1/xenon2025h2/', 'Google Xenon 2025 H2',       'active', 'tile'),
('xenon2026h1',  'google',      'https://ct.googleapis.com/logs/us1/xenon2026h1/', 'Google Xenon 2026 H1',       'active', 'tile'),
('argon2026h1',  'google',      'https://ct.googleapis.com/logs/eu1/argon2026h1/', 'Google Argon 2026 H1',       'active', 'tile'),
('nimbus2025',   'cloudflare',  'https://ct.cloudflare.com/logs/nimbus2025/',       'Cloudflare Nimbus 2025',     'active', 'tile'),
('oak2025h2',    'letsencrypt', 'https://oak.ct.letsencrypt.org/2025h2/',           'Let''s Encrypt Oak 2025 H2', 'active', 'tile'),
('oak2026',      'letsencrypt', 'https://oak.ct.letsencrypt.org/2026/',             'Let''s Encrypt Oak 2026',    'active', 'tile');

-- ---------------------------------------------------------------------------
-- Certificate metadata (no raw blobs, no PII)
-- One row per unique certificate issuance (deduped on TBS hash).
-- Pre-cert and final cert for the same issuance share sha256_tbs.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS certificates (
    sha256_tbs  FixedString(32),       -- dedup key: hash of TBS certificate structure
    sha256_leaf FixedString(32),       -- hash of the leaf entry (different per log)
    log_id      String,
    leaf_index  UInt64,
    not_before  DateTime,
    not_after   DateTime,
    issuer_cn   String,
    issuer_org  LowCardinality(String),
    subject_cn  String,
    is_precert  Bool,
    sans        Array(String),         -- all Subject Alternative Names
    seen_at     DateTime DEFAULT now()
) ENGINE = ReplacingMergeTree(seen_at)
ORDER BY sha256_tbs
PARTITION BY toYYYYMM(not_before)
SETTINGS index_granularity = 8192;

-- ---------------------------------------------------------------------------
-- Domain-level deduplicated records
-- One row per unique domain name. Updated on each new observation.
-- Enrichment fields populated async after initial insert.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS domains (
    domain            String,
    apex_domain       String,
    is_wildcard       Bool,
    is_apex           Bool,
    first_seen_cert   FixedString(32),      -- FK → certificates.sha256_tbs
    first_seen_at     DateTime,
    last_seen_at      DateTime,
    -- DNS / network enrichment (populated async)
    ip                Nullable(IPv4),
    asn               Nullable(UInt32),
    asn_org           Nullable(String),
    hosting_provider  LowCardinality(Nullable(String)),
    cdn_provider      LowCardinality(Nullable(String)),
    country_code      LowCardinality(Nullable(String)),
    -- Firmographic enrichment via PDL Company API (company-level only, no person data)
    -- Technographic (from cert SAN patterns — detected at ingest time)
    saas_vendor       Nullable(String),
    -- Firmographic enrichment via PDL Company API (company-level only, no person data)
    company_name      Nullable(String),
    company_industry  LowCardinality(Nullable(String)),
    company_size      LowCardinality(Nullable(String)),  -- e.g. "1-10", "11-50", "51-200"
    company_country   LowCardinality(Nullable(String)),
    enrichment_at     Nullable(DateTime)
) ENGINE = ReplacingMergeTree(last_seen_at)
ORDER BY domain
SETTINGS index_granularity = 8192;

-- ---------------------------------------------------------------------------
-- Typed signals
-- One row per signal event. Immutable after creation.
-- signal_type values: new_apex_domain | new_subdomain | saas_adoption_detected | infrastructure_expansion
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS signals (
    signal_id         UUID DEFAULT generateUUIDv4(),
    signal_type       LowCardinality(String),
    domain            String,
    apex_domain       String,
    detected_at       DateTime DEFAULT now(),
    cert_sha256_tbs   FixedString(32),
    -- Enrichment snapshot at signal time (denormalized for fast API reads)
    company_name      Nullable(String),
    company_industry  LowCardinality(Nullable(String)),
    hosting_provider  LowCardinality(Nullable(String)),
    saas_vendor       Nullable(String),      -- set for saas_adoption_detected type
    -- Delivery tracking
    delivered         Bool DEFAULT false,
    delivered_at      Nullable(DateTime)
) ENGINE = MergeTree()
ORDER BY (signal_type, detected_at)
PARTITION BY toYYYYMM(detected_at)
SETTINGS index_granularity = 8192;

-- ---------------------------------------------------------------------------
-- Watchlists (per API key — used to filter which signals to deliver)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS watchlists (
    watchlist_id  UUID DEFAULT generateUUIDv4(),
    key_hash      String,
    pattern_type  Enum8('apex_domain'=1, 'keyword'=2, 'industry'=3, 'saas_vendor'=4),
    pattern       String,
    created_at    DateTime DEFAULT now(),
    active        Bool DEFAULT true
) ENGINE = MergeTree()
ORDER BY key_hash;

-- ---------------------------------------------------------------------------
-- API keys
-- Raw key is never stored. key_hash = SHA-256(raw_key).
-- buyer_verified gates phishing-adjacent signal types.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api_keys (
    key_hash       String,
    tier           LowCardinality(String),  -- free | starter | pro
    buyer_verified Bool DEFAULT false,
    created_at     DateTime DEFAULT now(),
    revoked        Bool DEFAULT false,
    label          Nullable(String)
) ENGINE = MergeTree()
ORDER BY key_hash;

-- ---------------------------------------------------------------------------
-- Usage metering (13-month TTL — enough for annual billing audits)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS usage_events (
    key_hash     String,
    endpoint     String,
    ts           DateTime DEFAULT now(),
    credits_used UInt16 DEFAULT 1
) ENGINE = MergeTree()
ORDER BY (key_hash, ts)
PARTITION BY toYYYYMM(ts)
TTL ts + INTERVAL 13 MONTH
SETTINGS index_granularity = 8192;
