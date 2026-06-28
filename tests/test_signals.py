"""
Tests for signal engine and watchlist matching.
Uses in-memory mocks for ClickHouse — no live DB required.
"""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

from signals.engine import generate_signals, _type_counts
from signals.types import Signal, SignalType
from signals.watchlist import matches_watchlist, filter_signals_for_key


# ---------------------------------------------------------------------------
# Watchlist matching
# ---------------------------------------------------------------------------

def _make_signal(**kwargs) -> Signal:
    defaults = dict(
        signal_type=SignalType.NEW_APEX_DOMAIN,
        domain="acme.com",
        apex_domain="acme.com",
        cert_sha256_tbs=b"\x00" * 32,
        company_name="Acme Corp",
        company_industry="technology",
        hosting_provider="AWS",
        saas_vendor=None,
    )
    defaults.update(kwargs)
    return Signal(**defaults)


def test_watchlist_apex_domain_match():
    s = _make_signal(apex_domain="acme.com")
    assert matches_watchlist(s, "apex_domain", "acme.com") is True
    assert matches_watchlist(s, "apex_domain", "other.com") is False


def test_watchlist_keyword_match():
    s = _make_signal(domain="shop.acme.com")
    assert matches_watchlist(s, "keyword", "acme") is True
    assert matches_watchlist(s, "keyword", "ACME") is True  # case-insensitive
    assert matches_watchlist(s, "keyword", "xyz") is False


def test_watchlist_industry_match():
    s = _make_signal(company_industry="technology")
    assert matches_watchlist(s, "industry", "technology") is True
    assert matches_watchlist(s, "industry", "TECHNOLOGY") is True
    assert matches_watchlist(s, "industry", "finance") is False


def test_watchlist_saas_vendor_match():
    s = _make_signal(saas_vendor="Shopify")
    assert matches_watchlist(s, "saas_vendor", "shopify") is True
    assert matches_watchlist(s, "saas_vendor", "Vercel") is False


def test_watchlist_no_saas_vendor():
    s = _make_signal(saas_vendor=None)
    assert matches_watchlist(s, "saas_vendor", "Shopify") is False


def test_filter_signals_empty_watchlist_returns_all():
    signals = [_make_signal(domain=f"domain{i}.com") for i in range(3)]
    result = filter_signals_for_key(signals, [])
    assert result == signals


def test_filter_signals_with_watchlist():
    s1 = _make_signal(domain="acme.com", apex_domain="acme.com")
    s2 = _make_signal(domain="other.com", apex_domain="other.com")
    result = filter_signals_for_key([s1, s2], [("apex_domain", "acme.com")])
    assert result == [s1]


def test_filter_signals_multi_pattern():
    s1 = _make_signal(domain="acme.com", apex_domain="acme.com", company_industry="technology", saas_vendor=None)
    s2 = _make_signal(domain="shop.com", apex_domain="shop.com", company_industry="retail", saas_vendor="Shopify")
    s3 = _make_signal(domain="random.com", apex_domain="random.com", company_industry="healthcare", saas_vendor=None)

    watchlist = [("industry", "technology"), ("saas_vendor", "shopify")]
    result = filter_signals_for_key([s1, s2, s3], watchlist)
    assert s1 in result
    assert s2 in result
    assert s3 not in result


# ---------------------------------------------------------------------------
# Signal type counts helper
# ---------------------------------------------------------------------------

def test_type_counts():
    signals = [
        _make_signal(signal_type=SignalType.NEW_APEX_DOMAIN),
        _make_signal(signal_type=SignalType.NEW_APEX_DOMAIN),
        _make_signal(signal_type=SignalType.SAAS_ADOPTION_DETECTED),
    ]
    counts = _type_counts(signals)
    assert counts["new_apex_domain"] == 2
    assert counts["saas_adoption_detected"] == 1


# ---------------------------------------------------------------------------
# Signal.to_row() shape
# ---------------------------------------------------------------------------

def test_signal_to_row_shape():
    s = _make_signal()
    row = s.to_row()
    assert len(row) == len(Signal.COLUMN_NAMES)
    assert row[0] == SignalType.NEW_APEX_DOMAIN.value
    assert row[1] == "acme.com"
    assert row[-2] is False   # delivered
    assert row[-1] is None    # delivered_at


# ---------------------------------------------------------------------------
# Signal engine (mocked ClickHouse)
# ---------------------------------------------------------------------------

def _mock_ch(domain_rows=None, signal_exists=False, cert_rows=None):
    ch = MagicMock()

    def query_side_effect(sql, parameters=None):
        result = MagicMock()
        sql_upper = sql.upper()
        # Order matters: more specific checks first
        if "DISTINCT APEX_DOMAIN" in sql_upper:
            result.result_rows = []
        elif "COUNT()" in sql_upper and "SIGNAL.SIGNALS" in sql_upper:
            result.result_rows = [(1 if signal_exists else 0,)]
        elif "COMPANY_NAME IS NOT NULL" in sql_upper and "FROM SIGNAL.DOMAINS" in sql_upper:
            # Velocity domain query — return 6-column rows only for rows with company_name
            # domain_row format: 14 cols — see _domain_row() helper
            vel_rows = []
            for r in (domain_rows or []):
                if len(r) >= 10 and r[6] is not None:
                    vel_rows.append((r[0], r[1], r[4], r[6], r[7], r[8]))
            result.result_rows = vel_rows
        elif "FROM SIGNAL.DOMAINS" in sql_upper:
            result.result_rows = domain_rows or []
        else:
            result.result_rows = []
        return result

    ch.query.side_effect = query_side_effect
    return ch


def _domain_row(
    domain="acme.com", apex="acme.com", is_apex=True, is_wildcard=False,
    cert=b"\x01" * 32, first_seen=None,
    company_name=None, company_industry=None, hosting_provider=None, saas_vendor=None,
    txt_vendor=None, http_tech=None, is_live=None, domain_registered_at=None,
):
    """Build a 14-column domain row matching the engine's SELECT."""
    if first_seen is None:
        first_seen = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return (
        domain, apex, is_apex, is_wildcard,
        cert, first_seen,
        company_name, company_industry, hosting_provider, saas_vendor,
        txt_vendor, http_tech, is_live, domain_registered_at,
    )


async def test_generate_signals_new_apex():
    ch = _mock_ch(domain_rows=[_domain_row()], signal_exists=False)
    signals = await generate_signals(ch, ["acme.com"])
    assert any(s.signal_type == SignalType.NEW_APEX_DOMAIN for s in signals)
    ch.insert.assert_called_once()


async def test_generate_signals_dedup():
    """If signal already exists, don't insert a duplicate."""
    ch = _mock_ch(domain_rows=[_domain_row()], signal_exists=True)
    signals = await generate_signals(ch, ["acme.com"])
    assert signals == []
    ch.insert.assert_not_called()


async def test_generate_signals_saas_adoption():
    ch = _mock_ch(
        domain_rows=[_domain_row(company_name="Acme Corp", company_industry="technology",
                                 hosting_provider="AWS", saas_vendor="Shopify")],
        signal_exists=False,
    )
    signals = await generate_signals(ch, ["acme.com"])
    types = {s.signal_type for s in signals}
    assert SignalType.NEW_APEX_DOMAIN in types
    assert SignalType.SAAS_ADOPTION_DETECTED in types


async def test_generate_signals_saas_adoption_from_txt():
    """saas_adoption_detected should fire when txt_vendor is set (no SAN match needed)."""
    ch = _mock_ch(
        domain_rows=[_domain_row(txt_vendor="HubSpot")],
        signal_exists=False,
    )
    signals = await generate_signals(ch, ["acme.com"])
    types = {s.signal_type for s in signals}
    assert SignalType.SAAS_ADOPTION_DETECTED in types
    adoption = next(s for s in signals if s.signal_type == SignalType.SAAS_ADOPTION_DETECTED)
    assert adoption.saas_vendor == "HubSpot"


async def test_generate_signals_saas_adoption_from_http():
    """saas_adoption_detected should fire when http_tech is set."""
    ch = _mock_ch(
        domain_rows=[_domain_row(http_tech="Shopify")],
        signal_exists=False,
    )
    signals = await generate_signals(ch, ["acme.com"])
    types = {s.signal_type for s in signals}
    assert SignalType.SAAS_ADOPTION_DETECTED in types


async def test_generate_signals_fresh_domain():
    """fresh_domain fires when domain was registered ≤30 days before first cert."""
    from datetime import timedelta
    reg_date = datetime(2025, 12, 20)  # 12 days before cert
    first_seen = datetime(2026, 1, 1, tzinfo=timezone.utc)
    ch = _mock_ch(
        domain_rows=[_domain_row(first_seen=first_seen, domain_registered_at=reg_date)],
        signal_exists=False,
    )
    signals = await generate_signals(ch, ["acme.com"])
    assert any(s.signal_type == SignalType.FRESH_DOMAIN for s in signals)


async def test_generate_signals_no_fresh_domain_old_registration():
    """fresh_domain does NOT fire for domains registered >30 days before cert."""
    reg_date = datetime(2025, 1, 1)  # 365 days before cert
    first_seen = datetime(2026, 1, 1, tzinfo=timezone.utc)
    ch = _mock_ch(
        domain_rows=[_domain_row(first_seen=first_seen, domain_registered_at=reg_date)],
        signal_exists=False,
    )
    signals = await generate_signals(ch, ["acme.com"])
    assert not any(s.signal_type == SignalType.FRESH_DOMAIN for s in signals)


async def test_generate_signals_wildcard_cert_issued():
    """Wildcard domains should generate a wildcard_cert_issued signal."""
    ch = _mock_ch(
        domain_rows=[_domain_row(domain="example.com", is_apex=False, is_wildcard=True, cert=b"\x03" * 32)],
        signal_exists=False,
    )
    signals = await generate_signals(ch, ["example.com"])
    assert any(s.signal_type == SignalType.WILDCARD_CERT_ISSUED for s in signals)


async def test_generate_signals_empty_input():
    ch = MagicMock()
    signals = await generate_signals(ch, [])
    assert signals == []
    ch.query.assert_not_called()
