# SIGNAL — Build Plan

## Phase 0 — Plan & Scaffold ✅
- [x] Propose repo structure, stack, schema, CT log list, cost estimate, risks
- [x] Get founder approval
- [x] `git init` and create repo skeleton
- [x] Write `CLAUDE.md`
- [x] Write `PLAN.md`
- [x] Write `.env.example` and `.gitignore`
- [x] Write `db/schema.sql` (ClickHouse DDL, PII-free)
- [x] Write `docker-compose.yml` (Redis for local dev)
- [x] Write `pyproject.toml` with pinned deps
- [x] Create package `__init__.py` stubs
- [ ] **CHECKPOINT:** founder reviews scaffold → approve Phase 1

---

## Phase 1 — Ingestion MVP ✅
- [x] Implement RFC 6962 get-entries log follower (`ingestion/log_follower.py`)
- [x] Implement cert parser: leaf_input → parsed metadata + SAN array (`ingestion/parser.py`)
- [x] Implement TBS-hash dedup (`ingestion/dedup.py`)
- [x] Implement entry-index checkpointing (`ingestion/checkpoint.py`)
- [x] Write ClickHouse client wrapper (`db/client.py`)
- [x] Push parsed + deduped records to ClickHouse `certificates` and `domains` tables
- [x] Write tests: parser (16), dedup (6) — 22/22 passing with real CT fixtures
- [x] Dev CLI: stats/watch/reset commands (`scripts/cli.py`)
- [x] Verify: 474 certs / 946 domains written to ClickHouse in 60s smoke test
- [x] **CHECKPOINT:** live ingest confirmed, no raw blobs stored

---

## Phase 2 — Enrichment + Signal Engine
- [ ] DNS/IP resolver enricher (`enrichment/dns_resolver.py`)
- [ ] ASN / hosting / CDN fingerprinter (`enrichment/asn_lookup.py`)
- [ ] Technographic inferencer: SaaS vendor from issuer + SAN patterns (`enrichment/technographic.py`)
- [ ] PDL Company API adapter (`enrichment/firmographic_pdl.py`)
- [ ] Enrichment worker: consume from Redis, enrich, upsert `domains` table
- [ ] Signal engine: enriched domain → typed signal (`signals/engine.py`)
- [ ] Watchlist matching (`signals/watchlist.py`)
- [ ] Tests for each enricher (DNS, ASN, technographic, PDL)
- [ ] Show 20 real example signals from live data
- [ ] **CHECKPOINT:** 20 real signals reviewed by founder

---

## Phase 3 — Self-Serve API
- [ ] API key generation + SHA-256 hashing (never store raw keys)
- [ ] `buyer_verified` flag enforcement for phishing-adjacent signals
- [ ] Tiered rate limiting (free / starter / pro)
- [ ] Usage metering → `usage_events` table
- [ ] `/v1/signals` endpoint (filterable, paginated, Clay-friendly flat JSON)
- [ ] `/v1/watchlists` CRUD endpoints
- [ ] Webhook delivery (per-key endpoint config + retry logic)
- [ ] `/healthz` and `/metrics` endpoints
- [ ] Basic API docs (auto-generated from FastAPI + hand-written quickstart)
- [ ] **CHECKPOINT:** end-to-end test with a real API key → Clay import

---

## Phase 4 — Orchestration & Ops
- [ ] `supervisord` config for all three workers + API
- [ ] Ingest stall detection + alert (if log follower falls behind > N tiles)
- [ ] Unreachable log detection + alert
- [ ] Daily data-quality checks (row counts, dedup ratio, enrichment coverage)
- [ ] Backpressure handling: Redis queue depth → throttle fetch rate
- [ ] Expand CT logs: add Sectigo, DigiCert, TrustAsia
- [ ] One-command Hetzner deploy script
- [ ] Full runbook in `CLAUDE.md`
- [ ] **CHECKPOINT:** run unattended for 48 hours, review ops metrics

---

## Phase 5 — Go-to-Market Surface
- [ ] Landing page (explains signals, free-tier signup)
- [ ] Free-tier API key self-serve signup flow
- [ ] Clay-ready example / "bring your own key" walkthrough
- [ ] Buyer-verification gate stub for phishing-adjacent data
- [ ] **CHECKPOINT:** founder reviews GTM surface, ready to acquire first customers
