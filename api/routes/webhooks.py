"""
GET /v1/webhooks   — show current webhook config for the authenticated key
PUT /v1/webhooks   — set or update webhook URL (and optional secret)
DELETE /v1/webhooks — remove webhook config
"""

from fastapi import APIRouter, Depends, HTTPException, status

from api.deps import authenticated_key, get_ch
from api.schemas import WebhookCreate, WebhookOut

router = APIRouter(prefix="/v1/webhooks", tags=["webhooks"])


@router.get("", response_model=WebhookOut)
def get_webhook(key: dict = Depends(authenticated_key)):
    url = key.get("webhook_url")
    if not url:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No webhook configured.")
    return WebhookOut(url=url, has_secret=bool(key.get("webhook_secret")))


@router.put("", response_model=WebhookOut)
def set_webhook(
    body: WebhookCreate,
    key: dict = Depends(authenticated_key),
    ch=Depends(get_ch),
):
    if not body.url.startswith("https://"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Webhook URL must use HTTPS.",
        )

    ch.command(
        """
        ALTER TABLE signal.api_keys
        UPDATE webhook_url = %(url)s, webhook_secret = %(secret)s
        WHERE key_hash = %(h)s
        """,
        parameters={
            "url": body.url,
            "secret": body.secret or "",
            "h": key["key_hash"],
        },
    )

    return WebhookOut(url=body.url, has_secret=bool(body.secret))


@router.delete("", status_code=status.HTTP_204_NO_CONTENT)
def delete_webhook(key: dict = Depends(authenticated_key), ch=Depends(get_ch)):
    if not key.get("webhook_url"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No webhook configured.")

    ch.command(
        "ALTER TABLE signal.api_keys UPDATE webhook_url = NULL, webhook_secret = NULL WHERE key_hash = %(h)s",
        parameters={"h": key["key_hash"]},
    )
