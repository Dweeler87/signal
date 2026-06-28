"""
Stripe billing endpoints.

POST /v1/billing/checkout  — create a Stripe Checkout session for tier upgrade
POST /v1/billing/webhook   — receive Stripe subscription lifecycle events

Checkout flow:
  1. Customer POSTs {"tier": "starter"} with their API key
  2. We create a Stripe Checkout Session (hosted payment page)
  3. Return {"checkout_url": "..."} — client redirects there
  4. On successful payment, Stripe fires customer.subscription.created
  5. Webhook updates the key's tier in ClickHouse

The key_hash is embedded in subscription metadata at checkout creation so
every subscription lifecycle event can be mapped back to an API key without
a separate customer lookup.
"""

import stripe
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from api.deps import authenticated_key, get_ch
from db.client import get_settings

router = APIRouter(prefix="/v1/billing", tags=["billing"])

_TIER_TO_PRICE: dict[str, str] = {}  # populated lazily from settings


def _tier_price_map() -> dict[str, str]:
    if not _TIER_TO_PRICE:
        s = get_settings()
        _TIER_TO_PRICE.update({
            "starter": s.stripe_starter_price_id,
            "growth":  s.stripe_growth_price_id,
            "pro":     s.stripe_pro_price_id,
        })
    return _TIER_TO_PRICE


def _price_to_tier(price_id: str) -> str | None:
    return {v: k for k, v in _tier_price_map().items()}.get(price_id)


# ---------------------------------------------------------------------------
# POST /v1/billing/checkout
# ---------------------------------------------------------------------------

class CheckoutRequest(BaseModel):
    tier: str  # starter | growth | pro


class CheckoutResponse(BaseModel):
    checkout_url: str


@router.post("/checkout", response_model=CheckoutResponse)
def create_checkout(
    body: CheckoutRequest,
    key: dict = Depends(authenticated_key),
    ch=Depends(get_ch),
):
    s = get_settings()
    if not s.stripe_secret_key:
        raise HTTPException(status_code=503, detail="Billing not configured.")

    tier_map = _tier_price_map()
    price_id = tier_map.get(body.tier)
    if not price_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown tier '{body.tier}'. Valid: {', '.join(tier_map)}",
        )

    stripe.api_key = s.stripe_secret_key
    session = stripe.checkout.Session.create(
        mode="subscription",
        line_items=[{"price": price_id, "quantity": 1}],
        success_url="https://forelight.net/upgrade?success=1",
        cancel_url="https://forelight.net/upgrade?canceled=1",
        subscription_data={"metadata": {"key_hash": key["key_hash"]}},
        metadata={"key_hash": key["key_hash"]},
    )
    return CheckoutResponse(checkout_url=session.url)


# ---------------------------------------------------------------------------
# POST /v1/billing/webhook  (no API key auth — verified by Stripe signature)
# ---------------------------------------------------------------------------

@router.post("/webhook", status_code=200)
async def stripe_webhook(request: Request, ch=Depends(get_ch)):
    s = get_settings()
    if not s.stripe_webhook_secret:
        raise HTTPException(status_code=503, detail="Billing not configured.")

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, s.stripe_webhook_secret
        )
    except stripe.errors.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid Stripe signature.")

    obj = event["data"]["object"]
    event_type = event["type"]

    if event_type in ("customer.subscription.created", "customer.subscription.updated"):
        key_hash = (obj.get("metadata") or {}).get("key_hash")
        if not key_hash:
            return {"status": "ignored", "reason": "no key_hash in metadata"}

        # Determine tier from the first subscription item's price
        try:
            price_id = obj["items"]["data"][0]["price"]["id"]
        except (KeyError, IndexError):
            return {"status": "ignored", "reason": "no price on subscription"}

        new_tier = _price_to_tier(price_id)
        if not new_tier:
            return {"status": "ignored", "reason": f"unknown price_id {price_id}"}

        sub_id = obj.get("id", "")
        customer_id = obj.get("customer", "")

        ch.command(
            f"""
            ALTER TABLE signal.api_keys
            UPDATE
                tier = %(tier)s,
                stripe_subscription_id = %(sub_id)s,
                stripe_customer_id = %(customer_id)s
            WHERE key_hash = %(key_hash)s
            """,
            parameters={
                "tier": new_tier,
                "sub_id": sub_id,
                "customer_id": customer_id,
                "key_hash": key_hash,
            },
        )
        return {"status": "updated", "tier": new_tier, "key_hash": key_hash[:8] + "..."}

    if event_type == "customer.subscription.deleted":
        key_hash = (obj.get("metadata") or {}).get("key_hash")
        if not key_hash:
            return {"status": "ignored", "reason": "no key_hash in metadata"}

        ch.command(
            "ALTER TABLE signal.api_keys UPDATE tier = 'free' WHERE key_hash = %(key_hash)s",
            parameters={"key_hash": key_hash},
        )
        return {"status": "downgraded", "key_hash": key_hash[:8] + "..."}

    return {"status": "ignored", "event_type": event_type}
