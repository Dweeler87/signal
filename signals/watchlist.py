"""
Watchlist matching — check whether a signal matches any active watchlist for an API key.

Pattern types:
  apex_domain  — exact match on signal.apex_domain
  keyword      — substring match on signal.domain
  industry     — exact match on signal.company_industry (case-insensitive)
  saas_vendor  — exact match on signal.saas_vendor (case-insensitive)

Used by the API layer in Phase 3 to filter signals per-key.
Also used to drive webhook delivery.
"""

from signals.types import Signal, SignalType


def matches_watchlist(signal: Signal, pattern_type: str, pattern: str) -> bool:
    """Return True if this signal matches the given watchlist pattern."""
    p = pattern.lower().strip()

    if pattern_type == "apex_domain":
        return signal.apex_domain.lower() == p

    elif pattern_type == "keyword":
        return p in signal.domain.lower()

    elif pattern_type == "industry":
        return (signal.company_industry or "").lower() == p

    elif pattern_type == "saas_vendor":
        return (signal.saas_vendor or "").lower() == p

    return False


def filter_signals_for_key(
    signals: list[Signal],
    watchlist_rows: list[tuple],  # (pattern_type, pattern)
) -> list[Signal]:
    """
    Given a list of signals and a key's watchlist rows,
    return only signals that match at least one watchlist entry.
    If the watchlist is empty, return all signals (no filter).
    """
    if not watchlist_rows:
        return signals

    result: list[Signal] = []
    for signal in signals:
        for pattern_type, pattern in watchlist_rows:
            if matches_watchlist(signal, pattern_type, pattern):
                result.append(signal)
                break
    return result
