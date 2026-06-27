"""
Fire-and-forget webhook delivery.

Called by the signal engine after new signals are generated.  For each
api_keys row that has a webhook_url, we POST matching signals as JSON.

Payload shape (one POST per batch, not per signal):
  {
    "event": "signals.new",
    "data": [{ ...SignalOut fields... }]
  }

Signing: if webhook_secret is set, we include an HMAC-SHA256 signature in
  X-Signal-Signature: sha256=<hexdigest>
computed over the raw request body bytes.
"""

import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone

import httpx

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


async def dispatch_signals(ch, signals: list[dict]) -> None:
    """
    Query all api_keys with a webhook_url and deliver matching signals.
    signals is a list of dicts matching SignalOut field names.
    """
    if not signals:
        return

    rows = ch.query(
        "SELECT key_hash, webhook_url, webhook_secret FROM signal.api_keys WHERE webhook_url != '' AND revoked = false"
    ).result_rows

    if not rows:
        return

    import asyncio
    tasks = []
    for key_hash, url, secret in rows:
        if url:
            tasks.append(deliver_to_key(url, secret or None, signals))

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
