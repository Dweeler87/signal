"""
Fire-and-forget webhook delivery.

Called by the signal engine after new signals are generated.  For each
api_keys row that has a webhook_url, we POST matching signals as JSON,
filtered through that key's watchlist (empty watchlist = all signals).

Payload shape (one POST per batch, not per signal):
  {
    "event": "signals.new",
    "data": [{ ...signal fields... }]
  }

Signing: if webhook_secret is set, we include an HMAC-SHA256 signature in
  X-Signal-Signature: sha256=<hexdigest>
computed over the raw request body bytes.
"""

import asyncio
import hashlib
import hmac
import json
import logging

import httpx

from signals.watchlist import filter_signals_for_key

log = logging.getLogger(__name__)

_TIMEOUT = 10.0  # seconds


def _sign(body_bytes: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(secret.encode(), body_bytes, hashlib.sha256).hexdigest()


async def deliver_to_key(url: str, secret: str | None, signals: list[dict]) -> None:
    """POST signals to a single webhook URL. Errors are logged, not raised."""
    payload = {"event": "signals.new", "data": signals}
    body = json.dumps(payload, default=str).encode()

    headers = {"Content-Type": "application/json"}
    if secret:
        headers["X-Signal-Signature"] = _sign(body, secret)

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as http:
            resp = await http.post(url, content=body, headers=headers)
            if resp.status_code >= 400:
                log.warning("webhook %s returned %s", url, resp.status_code)
    except Exception as exc:
        log.warning("webhook delivery to %s failed: %s", url, exc)


async def dispatch_signals(ch, signals) -> None:
    """
    For each api_key with a webhook_url, filter signals through that key's
    watchlist and POST any matches.

    signals: list of Signal objects (signals.types.Signal) or dicts.
    """
    if not signals:
        return

    rows = ch.query(
        """
        SELECT k.key_hash, k.webhook_url, k.webhook_secret
        FROM signal.api_keys k
        WHERE k.webhook_url != '' AND k.webhook_url IS NOT NULL AND k.revoked = false
        """
    ).result_rows

    if not rows:
        return

    tasks = []
    for key_hash, url, secret in rows:
        if not url:
            continue

        # Load this key's watchlist patterns
        watchlist_rows = ch.query(
            "SELECT pattern_type, pattern FROM signal.watchlists WHERE key_hash = %(h)s",
            parameters={"h": key_hash},
        ).result_rows  # list of (pattern_type, pattern)

        # Filter signals using the watchlist (empty = all signals pass)
        matched = filter_signals_for_key(signals, watchlist_rows)
        if not matched:
            continue

        signal_dicts = [
            s.to_webhook_dict() if hasattr(s, "to_webhook_dict") else s
            for s in matched
        ]
        tasks.append(deliver_to_key(url, secret or None, signal_dicts))

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
