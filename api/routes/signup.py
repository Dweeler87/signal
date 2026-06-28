"""
POST /v1/signup        — self-serve API key provisioning (free or paid tier)
POST /v1/signup/reissue — revoke lost key and issue a replacement to the same email
"""

import re
from datetime import datetime, timezone

import httpx
import stripe
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from api.auth import generate_key
from api.deps import get_ch
from db.client import get_settings

router = APIRouter(prefix="/v1/signup", tags=["signup"])

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
RESEND_SEND_URL = "https://api.resend.com/emails"
VALID_TIERS = {"free", "starter", "growth", "pro"}


class SignupRequest(BaseModel):
    email: str
    tier: str = "free"


async def send_key_email(email: str, raw_key: str, tier: str, resend_api_key: str) -> None:
    tier_lines = {
        "free":    "This key gives you 100 API requests per day.",
        "starter": "Your key starts on the free tier and will be upgraded to Starter once your payment completes.",
        "growth":  "Your key starts on the free tier and will be upgraded to Growth once your payment completes.",
        "pro":     "Your key starts on the free tier and will be upgraded to Pro once your payment completes.",
    }
    body_text = f"""Welcome to Forelight.

Your API key:

  {raw_key}

{tier_lines.get(tier, "")} Keep it secret — it cannot be retrieved again.

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
        "from": "Forelight <hello@forelight.net>",
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

    tier = body.tier.lower() if body.tier else "free"
    if tier not in VALID_TIERS:
        tier = "free"

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

    # Always provision as free — webhook upgrades tier after payment succeeds
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
            await send_key_email(email_lower, raw_key, tier, settings.resend_api_key)
        except Exception:
            pass

    # For paid tiers, create a Stripe Checkout session and return the URL
    checkout_url: str | None = None
    if tier != "free" and settings.stripe_secret_key:
        tier_prices = {
            "starter": settings.stripe_starter_price_id,
            "growth":  settings.stripe_growth_price_id,
            "pro":     settings.stripe_pro_price_id,
        }
        price_id = tier_prices.get(tier)
        if price_id:
            try:
                stripe.api_key = settings.stripe_secret_key
                session = stripe.checkout.Session.create(
                    mode="subscription",
                    line_items=[{"price": price_id, "quantity": 1}],
                    success_url="https://forelight.net/upgrade?success=1",
                    cancel_url="https://forelight.net/",
                    subscription_data={"metadata": {"key_hash": key_hash}},
                    metadata={"key_hash": key_hash},
                )
                checkout_url = session.url
            except Exception:
                pass  # key is provisioned; user can upgrade later via /upgrade

    response: dict = {"message": "Check your email for your API key.", "docs": "https://forelight.net/docs"}
    if checkout_url:
        response["checkout_url"] = checkout_url
    return response


# ---------------------------------------------------------------------------
# POST /v1/signup/reissue — replace a lost key
# ---------------------------------------------------------------------------

class ReissueRequest(BaseModel):
    email: str


async def send_reissue_email(email: str, raw_key: str, tier: str, resend_api_key: str) -> None:
    body_text = f"""Your Forelight API key has been re-issued.

Your new API key:

  {raw_key}

Tier: {tier}

Your previous key has been revoked. Keep this key secret — it cannot be retrieved again.

  curl -s "https://forelight.net/v1/signals?limit=5" \\
    -H "Authorization: Bearer {raw_key}"

Full docs: https://forelight.net/docs

---
Forelight — The earliest buying signal. Infrastructure, not intent.
"""
    payload = {
        "from": "Forelight <hello@forelight.net>",
        "to": [email],
        "subject": "Your new Forelight API key",
        "text": body_text,
    }
    async with httpx.AsyncClient(timeout=10) as http:
        r = await http.post(
            RESEND_SEND_URL,
            json=payload,
            headers={"Authorization": f"Bearer {resend_api_key}"},
        )
        r.raise_for_status()


@router.post("/reissue", status_code=status.HTTP_200_OK)
async def reissue(body: ReissueRequest, ch=Depends(get_ch)):
    """Revoke the existing key for this email and issue a fresh one."""
    settings = get_settings()

    if not EMAIL_RE.match(body.email):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid email address.",
        )

    email_lower = body.email.strip().lower()
    label = f"signup:{email_lower}"

    existing = ch.query(
        "SELECT key_hash, tier FROM signal.api_keys WHERE label = %(label)s AND revoked = false LIMIT 1",
        parameters={"label": label},
    ).result_rows

    if not existing:
        # Return the same message whether email exists or not — prevents enumeration
        return {"message": "If that email has a key, a replacement is on its way."}

    old_key_hash, tier = existing[0]

    # Revoke old key
    ch.command(
        "ALTER TABLE signal.api_keys UPDATE revoked = true WHERE key_hash = %(h)s",
        parameters={"h": old_key_hash},
    )

    # Issue new key with same tier and label
    raw_key, new_key_hash = generate_key()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    ch.insert(
        "signal.api_keys",
        [[new_key_hash, tier, False, label, now, False, None, None]],
        column_names=["key_hash", "tier", "buyer_verified", "label", "created_at", "revoked", "webhook_url", "webhook_secret"],
    )

    if settings.resend_api_key:
        try:
            await send_reissue_email(email_lower, raw_key, tier, settings.resend_api_key)
        except Exception:
            pass

    return {"message": "If that email has a key, a replacement is on its way."}
