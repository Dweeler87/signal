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
        elif "FROM SIGNAL.DOMAINS" in sql_upper:
            result.result_rows = domain_rows or []
        else:
            result.result_rows = []
        return result

    ch.query.side_effect = query_side_effect
    return ch


async def test_generate_signals_new_apex():
    domain_rows = [(
        "acme.com", "acme.com", True, False,
        b"\x01" * 32, datetime(2026, 1, 1, tzinfo=timezone.utc),
        None, None, None, None,
    )]
    ch = _mock_ch(domain_rows=domain_rows, signal_exists=False)

    signals = await generate_signals(ch, ["acme.com"])

    assert any(s.signal_type == SignalType.NEW_APEX_DOMAIN for s in signals)
    ch.insert.assert_called_once()


async def test_generate_signals_dedup():
    """If signal already exists, don't insert a duplicate."""
    domain_rows = [(
        "acme.com", "acme.com", True, False,
        b"\x01" * 32, datetime(2026, 1, 1, tzinfo=timezone.utc),
        None, None, None, None,
    )]
    ch = _mock_ch(domain_rows=domain_rows, signal_exists=True)

    signals = await generate_signals(ch, ["acme.com"])

    assert signals == []
    ch.insert.assert_not_called()


async def test_generate_signals_saas_adoption():
    domain_rows = [(
        "acme.com", "acme.com", True, False,
        b"\x02" * 32, datetime(2026, 1, 1, tzinfo=timezone.utc),
        "Acme Corp", "technology", "AWS", "Shopify",
    )]
    ch = _mock_ch(domain_rows=domain_rows, signal_exists=False)

    signals = await generate_signals(ch, ["acme.com"])

    types = {s.signal_type for s in signals}
    assert SignalType.NEW_APEX_DOMAIN in types
    assert SignalType.SAAS_ADOPTION_DETECTED in types


async def test_generate_signals_wildcard_skipped():
    """Wildcard domains should not generate signals."""
    domain_rows = [(
        "example.com", "example.com", False, True,  # is_wildcard=True
        b"\x03" * 32, datetime(2026, 1, 1, tzinfo=timezone.utc),
        None, None, None, None,
    )]
    ch = _mock_ch(domain_rows=domain_rows, signal_exists=False)

    signals = await generate_signals(ch, ["example.com"])
    assert signals == []


async def test_generate_signals_empty_input():
    ch = MagicMock()
    signals = await generate_signals(ch, [])
    assert signals == []
    ch.query.assert_not_called()
