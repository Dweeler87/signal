"""
POST /v1/signup — self-serve free-tier API key provisioning.

Flow:
  1. Validate email
  2. Check for existing key for this email (prevent duplicate provisioning)
  3. Provision a free-tier key
  4. Send key via email (Resend)
  5. Return 200 (key is in the email — not shown in response for security)
"""

import hashlib
import re
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr

from api.auth import generate_key
from api.deps import get_ch
from db.client import get_settings

router = APIRouter(prefix="/v1/signup", tags=["signup"])

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
RESEND_SEND_URL = "https://api.resend.com/emails"


class SignupRequest(BaseModel):
    email: str


async def send_key_email(email: str, raw_key: str, resend_api_key: str) -> None:
    """Send the API key to the user via Resend."""
    body_text = f"""Welcome to Forelight.

Your free API key:

  {raw_key}

This key gives you 100 API requests per day. Keep it secret — it cannot be retrieved again.

Quick start:

  curl -s "https://forelight.net/v1/signals?limit=5" \\
    -H "Authorization: Bearer {raw_key}"

Full docs: https://forelight.net/docs
Clay walkthrough: https://forelight.net/clay

---
Forelight — The earliest buying signal. Infrastructure, not intent.
Unsubscribe: reply with "unsubscribe"
"""

    payload = {
        "from": "Forelight <onboarding@resend.dev>",
        "to": [email],
        "subject": "Your Forelight API key",
        "text": body_text,
    }

    async with httpx.AsyncClient(timeout=10) as http:
        r = await http.post(
            RESEND_SEND_URL,
            json=payload,
            headers={"Authorization": f"Bearer {resend_api_key}"},
        )
        r.raise_for_status()


@router.post("", status_code=status.HTTP_200_OK)
async def signup(body: SignupRequest, ch=Depends(get_ch)):
    settings = get_settings()

    if not EMAIL_RE.match(body.email):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid email address.",
        )

    email_lower = body.email.strip().lower()

    # Prevent duplicate keys for the same email
    existing = ch.query(
        "SELECT key_hash FROM signal.api_keys WHERE label = %(label)s AND revoked = false LIMIT 1",
        parameters={"label": f"signup:{email_lower}"},
    ).result_rows
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An API key has already been issued to this email address. Check your inbox.",
        )

    raw_key, key_hash = generate_key()
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    ch.insert(
        "signal.api_keys",
        [[
            key_hash,
            "free",
            False,              # buyer_verified
            f"signup:{email_lower}",
            now,
            False,              # revoked
            None,               # webhook_url
            None,               # webhook_secret
        ]],
        column_names=[
            "key_hash", "tier", "buyer_verified", "label",
            "created_at", "revoked", "webhook_url", "webhook_secret",
        ],
    )

    if settings.resend_api_key:
        try:
            await send_key_email(email_lower, raw_key, settings.resend_api_key)
        except Exception:
            # Key is already provisioned — don't fail the request, but log
            # The user can contact support to retrieve their key
            pass

    return {
        "message": "Check your email for your API key.",
        "docs": "https://forelight.net/docs",
    }
