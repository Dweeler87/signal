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

## Phase 2 — Enrichment + Signal Engine ✅
- [x] DNS/IP resolver enricher (`enrichment/dns_resolver.py`)
- [x] ASN / hosting / CDN fingerprinter via ip-api.com (`enrichment/asn_lookup.py`)
- [x] Technographic inferencer: SaaS vendor from SAN patterns (40+ vendors) (`enrichment/technographic.py`)
- [x] PDL Company API adapter — graceful no-op without key (`enrichment/firmographic_pdl.py`)
- [x] Enrichment worker: polls ClickHouse FINAL, enriches, upserts (`enrichment/worker.py`)
- [x] Signal engine: new_apex_domain, new_subdomain, saas_adoption_detected, infrastructure_expansion
- [x] Watchlist matching: apex_domain/keyword/industry/saas_vendor patterns
- [x] 56/56 tests passing (enrichment + signals + parser + dedup)
- [x] 90 real signals generated from first 100 enriched domains
- [x] **CHECKPOINT:** live signals confirmed — ready for Phase 3

---

## Phase 3 — Self-Serve API ✅
- [x] API key generation + SHA-256 hashing (never store raw keys)
- [x] `buyer_verified` flag enforcement (gated on key record)
- [x] Tiered rate limiting (free/starter/pro) via Redis daily counter
- [x] `/v1/signals` with 7 filters, cursor pagination, Clay-friendly flat JSON
- [x] `/v1/watchlists` CRUD per key
- [x] POST `/v1/keys` (admin-protected via `X-Admin-Secret`)
- [x] GET/PUT/DELETE `/v1/webhooks` per key (HTTPS-only, HMAC-SHA256 signing)
- [x] `/healthz` and `/metrics` endpoints
- [x] Fire-and-forget webhook delivery (`api/webhook_delivery.py`)
- [x] 81/81 tests passing; smoke test: 90 signals returned with real key
- [x] **CHECKPOINT:** end-to-end test with real API key confirmed

---

## Phase 4 — Orchestration & Ops ✅
- [x] `supervisord` config for all four processes (`deploy/supervisord.conf`)
- [x] One-command Hetzner deploy script (`deploy/setup.sh`)
- [x] Stall/lag/backlog/throughput monitor (`scripts/monitor.py`)
- [x] CT log expansion: Google (xenon, argon), DigiCert (yeti, nessie), Sectigo (sabre, mammoth)
- [x] Full runbook in `CLAUDE.md`
- [ ] **CHECKPOINT:** server provisioned, run unattended 48h, review monitor log

---

## Phase 5 — Go-to-Market Surface ✅
- [x] Landing page (explains signals, free-tier signup) — forelight.net
- [x] Free-tier API key self-serve signup flow (POST /v1/signup + Resend email)
- [x] Clay-ready example / "bring your own key" walkthrough — forelight.net/clay
- [x] Buyer-verification gate stub (RESTRICTED_SIGNAL_TYPES wired, currently empty)
- [x] X-RateLimit-* response headers on all authenticated routes
- [x] Custom domain — forelight.net with SSL via certbot
- [x] **CHECKPOINT:** GTM surface live at forelight.net, ready to acquire first customers
