"""
API integration tests using httpx AsyncClient + ASGI transport.
All ClickHouse and Redis calls are mocked — no live services required.

Uses app.dependency_overrides (the correct FastAPI test pattern) rather than
unittest.mock.patch, which does not intercept FastAPI's DI function references.
"""

import base64
import uuid

from stripe._error import SignatureVerificationError as StripeSignatureError
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from api.auth import generate_key
from api.deps import authenticated_key, authenticated_key_no_rl, get_ch, get_redis
from api.main import app

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RAW_KEY, KEY_HASH = generate_key()
AUTH_HEADERS = {"Authorization": f"Bearer {RAW_KEY}"}

FAKE_KEY_RECORD = {
    "key_hash": KEY_HASH,
    "tier": "free",
    "buyer_verified": False,
    "webhook_url": None,
    "webhook_secret": None,
}

FAKE_KEY_WITH_WEBHOOK = {
    **FAKE_KEY_RECORD,
    "webhook_url": "https://example.com/existing",
    "webhook_secret": "secret",
}


def _make_ch():
    ch = MagicMock()
    ch.query.return_value = MagicMock(result_rows=[])
    return ch


def _make_redis(rate_count: int = 1):
    r = MagicMock()
    r.ping.return_value = True
    r.incr.return_value = rate_count
    return r


def _key_row(tier="free", buyer_verified=False, revoked=False,
             webhook_url=None, webhook_secret=None, label=None):
    return (tier, int(buyer_verified), int(revoked), webhook_url, webhook_secret, label)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clear_overrides():
    """Reset all dependency overrides after each test."""
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def ch():
    return _make_ch()


@pytest.fixture
def redis():
    return _make_redis()


@pytest.fixture
def authed(ch, redis):
    """Override auth + inject ch/redis so non-auth tests can focus on logic."""
    app.dependency_overrides[authenticated_key] = lambda: FAKE_KEY_RECORD
    app.dependency_overrides[get_ch] = lambda: ch
    app.dependency_overrides[get_redis] = lambda: redis


@pytest.fixture
def authed_webhook(ch, redis):
    """Like authed but the key has a webhook configured."""
    app.dependency_overrides[authenticated_key] = lambda: FAKE_KEY_WITH_WEBHOOK
    app.dependency_overrides[get_ch] = lambda: ch
    app.dependency_overrides[get_redis] = lambda: redis


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_healthz_ok(ch, redis):
    ch.query.return_value = MagicMock(result_rows=[(1,)])
    app.dependency_overrides[get_ch] = lambda: ch
    app.dependency_overrides[get_redis] = lambda: redis

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/healthz")

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"


@pytest.mark.asyncio
async def test_healthz_ch_down(ch, redis):
    ch.query.side_effect = Exception("connection refused")
    app.dependency_overrides[get_ch] = lambda: ch
    app.dependency_overrides[get_redis] = lambda: redis

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/healthz")

    assert resp.status_code == 200
    assert resp.json()["status"] == "degraded"


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_missing_auth(ch):
    app.dependency_overrides[get_ch] = lambda: ch
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/signals")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_wrong_key_prefix(ch, redis):
    """Key without sig_ prefix is rejected before DB lookup."""
    app.dependency_overrides[get_ch] = lambda: ch
    app.dependency_overrides[get_redis] = lambda: redis

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/signals", headers={"Authorization": "Bearer badkey"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_revoked_key(ch, redis):
    ch.query.return_value = MagicMock(result_rows=[_key_row(revoked=True)])
    app.dependency_overrides[get_ch] = lambda: ch
    app.dependency_overrides[get_redis] = lambda: redis

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/signals", headers=AUTH_HEADERS)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_rate_limit_exceeded(ch, redis):
    ch.query.return_value = MagicMock(result_rows=[_key_row()])
    redis.incrby.return_value = 101  # free tier limit = 100
    app.dependency_overrides[get_ch] = lambda: ch
    app.dependency_overrides[get_redis] = lambda: redis

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/signals", headers=AUTH_HEADERS)
    assert resp.status_code == 429


# ---------------------------------------------------------------------------
# Signals
# ---------------------------------------------------------------------------

def _signal_rows(n: int = 1):
    return [
        (
            uuid.uuid4(),
            "new_apex_domain",
            "acme.com",
            "acme.com",
            datetime(2026, 6, 1, 12, 0, 0),
            "AWS",
            None,
            "Acme Corp",
            "technology",
        )
        for _ in range(n)
    ]


@pytest.mark.asyncio
async def test_list_signals_empty(ch, authed):
    def _query(sql, parameters=None):
        r = MagicMock()
        if "count()" in sql.lower():
            r.result_rows = [(0,)]
        else:
            r.result_rows = []
        return r

    ch.query.side_effect = _query

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/signals", headers=AUTH_HEADERS)

    assert resp.status_code == 200
    body = resp.json()
    assert body["data"] == []
    assert body["total"] == 0
    assert body["next_cursor"] is None


@pytest.mark.asyncio
async def test_list_signals_returns_data(ch, authed):
    rows = _signal_rows(1)

    call_count = [0]
    def _query(sql, parameters=None):
        r = MagicMock()
        call_count[0] += 1
        sql_up = sql.upper()
        if "COUNT()" in sql_up and "WATCHLIST" not in sql_up:
            r.result_rows = [(1,)]
        elif "WATCHLIST" in sql_up:
            r.result_rows = []
        else:
            r.result_rows = rows
        return r

    ch.query.side_effect = _query

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/signals", headers=AUTH_HEADERS)

    assert resp.status_code == 200
    data = resp.json()["data"]
    assert len(data) == 1
    assert data[0]["domain"] == "acme.com"
    assert data[0]["signal_type"] == "new_apex_domain"
    assert data[0]["company_name"] == "Acme Corp"


@pytest.mark.asyncio
async def test_list_signals_cursor_pagination(ch, authed):
    """Fetching limit+1 rows should return a next_cursor."""
    rows = _signal_rows(3)  # limit=2 → 3 fetched → has_more

    def _query(sql, parameters=None):
        r = MagicMock()
        sql_up = sql.upper()
        if "COUNT()" in sql_up and "WATCHLIST" not in sql_up:
            r.result_rows = [(10,)]
        elif "WATCHLIST" in sql_up:
            r.result_rows = []
        else:
            r.result_rows = rows
        return r

    ch.query.side_effect = _query

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/signals?limit=2", headers=AUTH_HEADERS)

    assert resp.status_code == 200
    body = resp.json()
    assert len(body["data"]) == 2
    assert body["next_cursor"] is not None
    decoded = base64.b64decode(body["next_cursor"].encode()).decode()
    assert "2026" in decoded


# ---------------------------------------------------------------------------
# Watchlists
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_list_watchlists_empty(ch, authed):
    ch.query.return_value = MagicMock(result_rows=[])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/watchlists", headers=AUTH_HEADERS)

    assert resp.status_code == 200
    assert resp.json()["data"] == []


@pytest.mark.asyncio
async def test_list_watchlists_returns_items(ch, authed):
    wid = uuid.uuid4()
    ch.query.return_value = MagicMock(result_rows=[(
        wid, "apex_domain", "acme.com", datetime(2026, 6, 1), True
    )])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/watchlists", headers=AUTH_HEADERS)

    assert resp.status_code == 200
    items = resp.json()["data"]
    assert len(items) == 1
    assert items[0]["pattern"] == "acme.com"
    assert items[0]["active"] is True


@pytest.mark.asyncio
async def test_create_watchlist(ch, authed):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/watchlists",
            headers=AUTH_HEADERS,
            json={"pattern_type": "apex_domain", "pattern": "acme.com"},
        )

    assert resp.status_code == 201
    body = resp.json()
    assert body["pattern_type"] == "apex_domain"
    assert body["pattern"] == "acme.com"
    assert body["active"] is True
    ch.insert.assert_called_once()


@pytest.mark.asyncio
async def test_create_watchlist_invalid_type(ch, authed):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/watchlists",
            headers=AUTH_HEADERS,
            json={"pattern_type": "not_valid", "pattern": "acme.com"},
        )

    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_delete_watchlist_not_found(ch, authed):
    ch.query.return_value = MagicMock(result_rows=[])  # ownership check fails

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.delete(f"/v1/watchlists/{uuid.uuid4()}", headers=AUTH_HEADERS)

    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_watchlist_success(ch, authed):
    wid = str(uuid.uuid4())
    ch.query.return_value = MagicMock(result_rows=[(wid,)])  # ownership check passes

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.delete(f"/v1/watchlists/{wid}", headers=AUTH_HEADERS)

    assert resp.status_code == 204
    ch.command.assert_called_once()


# ---------------------------------------------------------------------------
# Keys (admin)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_create_key_no_admin_header(ch):
    app.dependency_overrides[get_ch] = lambda: ch

    with patch("api.routes.keys.get_settings") as mock_settings:
        mock_settings.return_value.api_admin_secret = "test-admin-secret"
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/v1/keys", json={"tier": "free"})

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_create_key_wrong_secret(ch):
    app.dependency_overrides[get_ch] = lambda: ch

    with patch("api.routes.keys.get_settings") as mock_settings:
        mock_settings.return_value.api_admin_secret = "test-admin-secret"
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/v1/keys",
                headers={"X-Admin-Secret": "wrong"},
                json={"tier": "free"},
            )

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_create_key_success(ch):
    app.dependency_overrides[get_ch] = lambda: ch

    with patch("api.routes.keys.get_settings") as mock_settings:
        mock_settings.return_value.api_admin_secret = "test-admin-secret"
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/v1/keys",
                headers={"X-Admin-Secret": "test-admin-secret"},
                json={"tier": "starter"},
            )

    assert resp.status_code == 201
    body = resp.json()
    assert body["key"].startswith("sig_")
    assert body["tier"] == "starter"
    assert len(body["key_hash"]) == 64  # SHA-256 hexdigest
    ch.insert.assert_called_once()


@pytest.mark.asyncio
async def test_create_key_invalid_tier(ch):
    app.dependency_overrides[get_ch] = lambda: ch

    with patch("api.routes.keys.get_settings") as mock_settings:
        mock_settings.return_value.api_admin_secret = "secret"
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/v1/keys",
                headers={"X-Admin-Secret": "secret"},
                json={"tier": "enterprise"},
            )

    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Webhooks
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_webhook_not_configured(ch, authed):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/webhooks", headers=AUTH_HEADERS)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_webhook_configured(ch, authed_webhook):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/webhooks", headers=AUTH_HEADERS)
    assert resp.status_code == 200
    body = resp.json()
    assert body["url"] == "https://example.com/existing"
    assert body["has_secret"] is True


@pytest.mark.asyncio
async def test_set_webhook(ch, authed):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.put(
            "/v1/webhooks",
            headers=AUTH_HEADERS,
            json={"url": "https://hooks.example.com/signal", "secret": "mysecret"},
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["url"] == "https://hooks.example.com/signal"
    assert body["has_secret"] is True
    ch.command.assert_called_once()


@pytest.mark.asyncio
async def test_set_webhook_requires_https(ch, authed):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.put(
            "/v1/webhooks",
            headers=AUTH_HEADERS,
            json={"url": "http://insecure.example.com/webhook"},
        )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_delete_webhook(ch, authed_webhook):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.delete("/v1/webhooks", headers=AUTH_HEADERS)
    assert resp.status_code == 204
    ch.command.assert_called_once()


@pytest.mark.asyncio
async def test_delete_webhook_not_configured(ch, authed):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.delete("/v1/webhooks", headers=AUTH_HEADERS)
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Account
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_account_returns_quota(ch, redis):
    redis.get.return_value = "42"
    key_record = {**FAKE_KEY_RECORD, "label": "signup:test@example.com"}
    app.dependency_overrides[authenticated_key_no_rl] = lambda: (key_record, KEY_HASH)
    app.dependency_overrides[get_ch] = lambda: ch
    app.dependency_overrides[get_redis] = lambda: redis

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/account", headers=AUTH_HEADERS)

    assert resp.status_code == 200
    body = resp.json()
    assert body["tier"] == "free"
    assert body["quota_used"] == 42
    assert body["quota_limit"] == 100
    assert body["quota_remaining"] == 58
    assert body["label"] == "signup:test@example.com"


@pytest.mark.asyncio
async def test_account_no_usage(ch, redis):
    redis.get.return_value = None
    app.dependency_overrides[authenticated_key_no_rl] = lambda: (FAKE_KEY_RECORD, KEY_HASH)
    app.dependency_overrides[get_ch] = lambda: ch
    app.dependency_overrides[get_redis] = lambda: redis

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/account", headers=AUTH_HEADERS)

    assert resp.status_code == 200
    body = resp.json()
    assert body["quota_used"] == 0
    assert body["quota_remaining"] == 100


# ---------------------------------------------------------------------------
# Billing
# ---------------------------------------------------------------------------

_FAKE_TIER_MAP = {"starter": "price_s", "growth": "price_g", "pro": "price_p"}


@pytest.mark.asyncio
async def test_checkout_no_stripe_config(ch, authed):
    with patch("api.routes.billing.get_settings") as mock_settings:
        mock_settings.return_value.stripe_secret_key = ""
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/v1/billing/checkout",
                headers=AUTH_HEADERS,
                json={"tier": "starter"},
            )
    assert resp.status_code == 503


@pytest.mark.asyncio
async def test_checkout_unknown_tier(ch, authed):
    with patch("api.routes.billing.get_settings") as mock_settings, \
         patch("api.routes.billing._tier_price_map", return_value=_FAKE_TIER_MAP):
        mock_settings.return_value.stripe_secret_key = "sk_test_xxx"
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/v1/billing/checkout",
                headers=AUTH_HEADERS,
                json={"tier": "enterprise"},
            )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_checkout_returns_url(ch, authed):
    mock_session = MagicMock()
    mock_session.url = "https://checkout.stripe.com/pay/cs_test_abc"

    with patch("api.routes.billing.get_settings") as mock_settings, \
         patch("api.routes.billing._tier_price_map", return_value=_FAKE_TIER_MAP), \
         patch("stripe.checkout.Session.create", return_value=mock_session):
        mock_settings.return_value.stripe_secret_key = "sk_test_xxx"
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/v1/billing/checkout",
                headers=AUTH_HEADERS,
                json={"tier": "starter"},
            )

    assert resp.status_code == 200
    assert resp.json()["checkout_url"] == "https://checkout.stripe.com/pay/cs_test_abc"


@pytest.mark.asyncio
async def test_webhook_no_config(ch):
    app.dependency_overrides[get_ch] = lambda: ch

    with patch("api.routes.billing.get_settings") as mock_settings:
        mock_settings.return_value.stripe_webhook_secret = ""
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/v1/billing/webhook", content=b"{}")
    assert resp.status_code == 503


@pytest.mark.asyncio
async def test_webhook_invalid_signature(ch):
    app.dependency_overrides[get_ch] = lambda: ch

    with patch("api.routes.billing.get_settings") as mock_settings, \
         patch("stripe.Webhook.construct_event",
               side_effect=StripeSignatureError("bad", "hdr")):
        mock_settings.return_value.stripe_webhook_secret = "whsec_test"
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/v1/billing/webhook",
                content=b"payload",
                headers={"stripe-signature": "bad"},
            )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_webhook_subscription_created_upgrades_tier(ch):
    app.dependency_overrides[get_ch] = lambda: ch

    fake_event = {
        "type": "customer.subscription.created",
        "data": {
            "object": {
                "id": "sub_123",
                "customer": "cus_456",
                "metadata": {"key_hash": KEY_HASH},
                "items": {"data": [{"price": {"id": "price_s"}}]},
            }
        },
    }

    with patch("api.routes.billing.get_settings") as mock_settings, \
         patch("api.routes.billing._tier_price_map", return_value=_FAKE_TIER_MAP), \
         patch("stripe.Webhook.construct_event", return_value=fake_event):
        mock_settings.return_value.stripe_webhook_secret = "whsec_test"
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/v1/billing/webhook",
                content=b"payload",
                headers={"stripe-signature": "t=123,v1=abc"},
            )

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "updated"
    assert body["tier"] == "starter"
    ch.command.assert_called_once()


@pytest.mark.asyncio
async def test_webhook_subscription_deleted_downgrades_to_free(ch):
    app.dependency_overrides[get_ch] = lambda: ch

    fake_event = {
        "type": "customer.subscription.deleted",
        "data": {"object": {"metadata": {"key_hash": KEY_HASH}}},
    }

    with patch("api.routes.billing.get_settings") as mock_settings, \
         patch("stripe.Webhook.construct_event", return_value=fake_event):
        mock_settings.return_value.stripe_webhook_secret = "whsec_test"
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/v1/billing/webhook",
                content=b"payload",
                headers={"stripe-signature": "t=123,v1=abc"},
            )

    assert resp.status_code == 200
    assert resp.json()["status"] == "downgraded"
    ch.command.assert_called_once()


@pytest.mark.asyncio
async def test_webhook_ignored_event_type(ch):
    app.dependency_overrides[get_ch] = lambda: ch

    fake_event = {"type": "payment_intent.created", "data": {"object": {}}}

    with patch("api.routes.billing.get_settings") as mock_settings, \
         patch("stripe.Webhook.construct_event", return_value=fake_event):
        mock_settings.return_value.stripe_webhook_secret = "whsec_test"
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/v1/billing/webhook",
                content=b"payload",
                headers={"stripe-signature": "t=123,v1=abc"},
            )

    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"
