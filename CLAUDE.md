# SIGNAL — Architecture & Runbook

## What This Is

A real-time Certificate Transparency (CT) log harvester that converts the raw cert stream into go-to-market sales signals. Alerts GTM teams the moment a target company stands up new infrastructure.

**Legal basis:** CT logs are public by mandate (RFC 6962 / RFC 9162). We run our own log follower against public CT log APIs — no scraping, no ToS violations.

---

## Architecture

```
CT Logs (public RFC 6962 API)
        │
        ▼
  [ingestion/]       ← async log follower, cert parser, TBS-hash dedup
        │
        ▼
  ClickHouse Cloud   ← certificates + domains tables
        │
        ▼
  [enrichment/]      ← DNS, ASN/hosting/CDN, technographic (SaaS vendor), firmographic (PDL)
        │
        ▼
  [signals/]         ← typed event generator, watchlist matching
        │
        ▼
  ClickHouse Cloud   ← signals table
        │
        ▼
  [api/]             ← FastAPI, API keys, rate limiting, cursor pagination, webhooks
```

### Key design decisions

- **No raw cert blobs.** Store parsed metadata + TBS hash + leaf index only.
- **Dedup on TBS hash, not leaf hash.** Pre-cert and final cert for the same issuance share TBS hash but differ on leaf hash. Leaf-hash dedup double-counts every cert issuance.
- **PII-free by schema.** No WHOIS registrant fields. Firmographic enrichment is company-level only (PDL Company API).
- **`buyer_verified` flag gates phishing-adjacent signals.** Lookalike/typosquat feeds require this flag on the API key.
- **SaaS vendor detected at ingest time.** Log follower has SANs in hand; no cert cross-reference needed in enrichment worker.
- **ClickHouse ReplacingMergeTree** on sha256_tbs — handles upsert/dedup at volume. Always query with `FINAL`.

---

## CT Logs (15 active as of 2026-06-28)

| Log ID | Operator | Status |
|--------|----------|--------|
| nimbus2025 | Cloudflare | **enabled** |
| nimbus2026 | Cloudflare | **enabled** |
| argon2026h1 | Google | **enabled** |
| argon2026h2 | Google | **enabled** |
| xenon2026h1 | Google | **enabled** |
| xenon2026h2 | Google | **enabled** |
| wyvern2026h1 | DigiCert | **enabled** |
| wyvern2026h2 | DigiCert | **enabled** |
| sphinx2026h1 | DigiCert | **enabled** |
| sphinx2026h2 | DigiCert | **enabled** |
| elephant2026h1 | Sectigo | **enabled** |
| elephant2026h2 | Sectigo | **enabled** |
| tiger2026h1 | Sectigo | **enabled** |
| tiger2026h2 | Sectigo | **enabled** |
| trustasia2026a | TrustAsia | **enabled** |
| trustasia2026b | TrustAsia | **enabled** |
| oak2026h1 | Let's Encrypt | disabled (retired) |

To enable a log: set `"enabled": True` in `ingestion/log_follower.py` LOG_REGISTRY and restart the `log_follower` process. Each new log starts from its current tree head (not from the beginning).

---

## Stack

| Layer | Tech |
|-------|------|
| Language | Python 3.12 |
| HTTP client | httpx (async) |
| Cert parsing | cryptography lib |
| Dedup | Redis (TBS hash, 30-day TTL) |
| Database | ClickHouse Cloud (free tier → self-hosted fallback) |
| API | FastAPI + uvicorn |
| DNS resolution | stdlib socket (asyncio.to_thread) |
| ASN/hosting | ip-api.com batch (free, 45 req/min) |
| Firmographics | PDL Company API (disabled — 0.016% hit rate, clear PDL_API_KEY to keep off) |
| LLM enrichment | Claude Haiku 4.5 — extracts company_name + industry from domain homepage metadata (~$0.0003/domain) |
| Local dev | Redis standalone (winget on Windows) |
| Process mgmt (prod) | supervisord |
| Reverse proxy (prod) | nginx |

---

## Environment Variables

| Var | Description |
|-----|-------------|
| `CLICKHOUSE_HOST` | ClickHouse Cloud hostname |
| `CLICKHOUSE_PORT` | Usually 8443 |
| `CLICKHOUSE_USER` | ClickHouse user |
| `CLICKHOUSE_PASSWORD` | ClickHouse password |
| `CLICKHOUSE_DATABASE` | Database name (default: signal) |
| `REDIS_URL` | Redis connection string (default: redis://localhost:6379) |
| `PDL_API_KEY` | People Data Labs API key (optional; enrichment skips firmographic without it) |
| `API_ADMIN_SECRET` | Protects POST /v1/keys — generate with `python -c "import secrets; print(secrets.token_hex(32))"` |
| `RESEND_API_KEY` | Resend.com key for transactional email (signup, reissue) |
| `STRIPE_SECRET_KEY` | Stripe secret key for billing |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook signing secret |
| `STRIPE_STARTER_PRICE_ID` | Stripe price ID for Starter tier ($99/mo) |
| `STRIPE_GROWTH_PRICE_ID` | Stripe price ID for Growth tier ($299/mo) |
| `STRIPE_PRO_PRICE_ID` | Stripe price ID for Pro tier ($999/mo) |
| `ANTHROPIC_API_KEY` | Claude Haiku API key for LLM web enrichment (company_name + industry from homepage) |
| `LOG_LEVEL` | debug / info / warning (default: info) |
| `INITIAL_LOOKBACK` | Entries to process on first start (default: 2000) |

---

## Local Dev Commands

```bash
# Install deps
pip install -e ".[dev]"

# Apply ClickHouse schema (once, against Cloud)
python scripts/apply_schema.py

# Start Redis (Windows — run in separate terminal)
redis-server

# Run ingestion
python -m ingestion.log_follower

# Run enrichment worker
python -m enrichment.worker

# Run API server
uvicorn api.main:app --reload --port 8000

# Run monitor (optional locally)
python scripts/monitor.py

# Dev CLI — live stats
python scripts/cli.py stats

# Tests
pytest tests/ -v
```

---

## Production Deploy (Hetzner CX32)

### First-time setup

```bash
# On the Hetzner server (Ubuntu 22.04), as root:
git clone https://github.com/Dweeler87/signal.git /opt/signal
bash /opt/signal/deploy/setup.sh
```

The script installs Python 3.12, Redis, supervisord, nginx, creates a `signal` system user, and configures the firewall.

### After setup

```bash
# Copy .env (do not commit this file)
scp .env root@<server-ip>:/opt/signal/.env
chown signal:signal /opt/signal/.env && chmod 600 /opt/signal/.env

# Start all processes
supervisorctl reload
supervisorctl status   # should show all RUNNING

# Tail logs
tail -f /var/log/signal/log_follower.log
tail -f /var/log/signal/enrichment.log
tail -f /var/log/signal/api.log
tail -f /var/log/signal/monitor.log   # JSON alert stream
```

### Deploying updates

```bash
cd /opt/signal
git pull
sudo -u signal .venv/bin/pip install -e . -q
supervisorctl restart all
supervisorctl status
```

### Provision your first API key

```bash
curl -s -X POST http://localhost:8000/v1/keys \
  -H "X-Admin-Secret: <API_ADMIN_SECRET>" \
  -H "Content-Type: application/json" \
  -d '{"tier": "pro", "label": "founder-key"}' | python -m json.tool
# → key field is shown ONCE. Save it securely.
```

---

## Monitoring

`scripts/monitor.py` runs as a supervisord process and emits JSON lines to `monitor.log`:

```json
{"ts": "2026-06-27T20:00:00Z", "level": "ok",   "check": "log_lag",          "lag": 1234}
{"ts": "2026-06-27T20:00:00Z", "level": "warn",  "check": "enrich_backlog",   "backlog": 12000}
{"ts": "2026-06-27T20:00:00Z", "level": "crit",  "check": "signal_throughput","message": "no signals in last 2h"}
```

**Alert thresholds:**

| Check | Warn | Crit |
|-------|------|------|
| Log follower lag | 50,000 entries | 500,000 entries |
| Enrichment backlog | 10,000 domains | 50,000 domains |
| Signal throughput | — | 0 signals in 2h |

To watch alerts in real time:
```bash
tail -f /var/log/signal/monitor.log | grep -v '"level":"ok"'
```

---

## Infrastructure

| Component | Spec | Cost |
|-----------|------|------|
| Hetzner CX32 | 4 vCPU / 8 GB RAM | ~$15/mo |
| ClickHouse Cloud | Free tier (1 TB storage) | $0 |
| ip-api.com | 45 req/min free | $0 |
| Resend.com | Transactional email | ~$0 (free tier) |
| Stripe | Subscription billing | 2.9% + 30¢ per transaction |
| PDL Company API | **disabled** — 0.016% hit rate | $0 (was $98/mo) |

**ClickHouse upgrade path:** If ingest exceeds ~10M rows/day, self-host on a second Hetzner VM ($35/mo). Schema is identical — change connection string only.

---

## Guardrails (non-negotiable)

- **No natural-person PII.** Schema has no WHOIS, no registrant name, no email.
- **No phishing enablement.** Lookalike/typosquat signal types gated to `buyer_verified=true` keys.
- **Store metadata, not raw cert blobs.** TBS hash + leaf index only. Re-fetch raw cert on demand via log URL + leaf index.
- **Dedup on TBS hash.** Pre-cert and final cert for the same issuance must not count twice.

---

## Changelog

### 2026-06-27
- Phase 0: Repo scaffolded. Schema, docker-compose, pyproject.toml, PLAN.md, CLAUDE.md.
- Phase 1: RFC 6962 log follower (Cloudflare nimbus2025), cert parser, TBS dedup, checkpointing.
- Phase 2: DNS/ASN/technographic/PDL enrichment, signal engine (4 signal types), watchlist matching.
- Phase 3: FastAPI self-serve API — auth, rate limits, signals/watchlists/keys/webhooks endpoints, 81 tests.
- Phase 4: supervisord + nginx + Hetzner deploy script, monitor, CT log registry expanded to 15 active logs.

### 2026-06-28
- Stripe billing: /v1/billing/checkout + webhook handler; tier upgrades on payment; Growth tier ($299/mo, 40K/day, 60d lookback).
- Self-serve signup with tier picker; /v1/signup/reissue for lost keys; rate limits keyed to email (not key hash).
- score_min query param on GET /v1/signals and POST /v1/signals/batch.
- /v1/account endpoint: tier, quota used/remaining, reset timestamp.
- Webhook delivery wired to enrichment worker with per-key watchlist filtering.
- SEO: OG tags, Twitter Cards, JSON-LD, sitemap.xml, robots.txt, og-image.jpg (1200×630).
- PDL disabled (0.016% hit rate). H2 2026 logs enabled (16 active logs total).
- Plausible analytics added to all landing pages.
- Security: X-Admin-Secret hidden from public OpenAPI spec; /metrics gated behind admin secret.
- Bug fix: /v1/account quota reads same Redis bucket as rate limiter (was always showing 0 for non-signup keys).
- Bug fix: cursor pagination now encodes signal_id alongside timestamp to prevent signal drops at second boundaries.
- Company name: WHOIS org field used as zero-cost fallback for company_name when PDL is disabled.
