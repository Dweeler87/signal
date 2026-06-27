# SIGNAL — Architecture & Runbook

## What This Is

A real-time Certificate Transparency (CT) log harvester that converts the raw cert stream into go-to-market sales signals. Alerts GTM teams the moment a target company stands up new infrastructure.

**Legal basis:** CT logs are public by mandate (RFC 6962 / RFC 9162). We run our own log follower against public CT log APIs — no scraping, no ToS violations.

---

## Architecture

```
CT Logs (public tile API)
        │
        ▼
  [ingestion/]          ← async tile follower, cert parser, TBS-hash dedup
        │ Redis Stream
        ▼
  [enrichment/]         ← DNS, ASN, technographic, firmographic (PDL)
        │ Redis Stream
        ▼
  [signals/]            ← typed event generator, watchlist matching
        │
        ▼
  ClickHouse Cloud      ← certificate metadata + domains + signals
        │
        ▼
  [api/]                ← FastAPI, API keys, rate limiting, webhook delivery
```

### Key design decisions

- **No raw cert blobs.** Store parsed metadata + TBS hash + leaf index. Re-fetch raw cert on demand via log URL + leaf index.
- **Dedup on TBS hash, not leaf hash.** Pre-cert and final cert for the same issuance share the same TBS hash but have different leaf hashes. Deduping on leaf hash double-counts every cert.
- **PII-free by schema.** No WHOIS registrant fields exist in the schema. Firmographic enrichment targets company-level data only (via PDL Company API).
- **No raw person data.** `buyer_verified` flag on API keys gates phishing-adjacent signal types (lookalike domains, brand-protection feeds) to verified defensive buyers only.
- **Redis Streams for queuing.** One service per stage, backpressure via consumer group lag monitoring. No Kafka, no NATS.
- **ClickHouse ReplacingMergeTree** for certificates and domains — handles dedup/upsert patterns efficiently at this volume.

---

## CT Logs (active)

| Log | Operator | API Type |
|-----|----------|----------|
| xenon2025h2 | Google | Static tile |
| xenon2026h1 | Google | Static tile |
| nimbus2025 | Cloudflare | Static tile |
| oak2025h2 | Let's Encrypt | Static tile |
| oak2026 | Let's Encrypt | Static tile |
| argon2026h1 | Google | Static tile |

Add new logs in `db/schema.sql` ct_logs table and `ingestion/log_follower.py` LOG_REGISTRY.

---

## Stack

| Layer | Tech |
|-------|------|
| Language | Python 3.12 |
| HTTP client | httpx (async) |
| Cert parsing | cryptography lib |
| Queue | Redis Streams |
| Database | ClickHouse Cloud (free tier → self-hosted fallback) |
| API | FastAPI |
| DNS resolution | aiodns |
| Firmographics | PDL Company API |
| Local dev | Docker Compose (Redis only) |
| Process mgmt (prod) | supervisord |

---

## Environment Variables

See `.env.example` for all required vars. Never commit `.env`.

| Var | Description |
|-----|-------------|
| `CLICKHOUSE_HOST` | ClickHouse Cloud hostname |
| `CLICKHOUSE_PORT` | Usually 8443 |
| `CLICKHOUSE_USER` | ClickHouse user |
| `CLICKHOUSE_PASSWORD` | ClickHouse password |
| `CLICKHOUSE_DATABASE` | Database name (default: signal) |
| `REDIS_URL` | Redis connection string |
| `PDL_API_KEY` | People Data Labs API key (Phase 2+) |
| `API_SECRET_KEY` | FastAPI signing secret |
| `LOG_LEVEL` | debug / info / warning |

---

## Commands

### Local dev setup
```bash
# Start Redis
docker compose up -d

# Install deps
pip install -e ".[dev]"

# Apply ClickHouse schema (run once against Cloud instance)
python scripts/apply_schema.py

# Run ingestion (Phase 1+)
python -m ingestion.log_follower

# Run enrichment worker (Phase 2+)
python -m enrichment.worker

# Run signal engine (Phase 2+)
python -m signals.engine

# Run API server (Phase 3+)
uvicorn api.main:app --reload

# Dev CLI — live stats
python scripts/cli.py stats
```

### Tests
```bash
pytest tests/ -v
```

### ClickHouse schema apply
```bash
python scripts/apply_schema.py
```

---

## Infrastructure

- **Hosting:** Hetzner CX32 (4 vCPU / 8 GB RAM, ~$15/mo)
- **Database:** ClickHouse Cloud free tier (1 TB storage, ~10M rows/day ingest cap)
- **ClickHouse free tier limit:** If ingest exceeds ~10M rows/day, upgrade path is self-hosted ClickHouse on a second Hetzner VM ($35/mo). Schema is identical — change connection string only.

### Monthly cost estimate

| Phase | Cost |
|-------|------|
| Phase 0–1 (scaffold + ingest) | ~$15/mo |
| Phase 2+ (enrichment enabled) | ~$114/mo |

---

## Changelog

### 2026-06-27
- Phase 0: Repo scaffolded. Schema, docker-compose, pyproject.toml, PLAN.md created.
