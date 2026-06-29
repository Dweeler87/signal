"""
POST /v1/keys — provision a new API key (admin-only).

Protected by API_ADMIN_SECRET in the X-Admin-Secret header.
Returns the raw key once — it is never stored and cannot be retrieved later.
"""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, status

from api.auth import generate_key
from api.deps import get_ch
from api.schemas import KeyCreate, KeyOut
from db.client import get_settings

router = APIRouter(prefix="/v1/keys", tags=["keys"], include_in_schema=False)

VALID_TIERS = {"free", "starter", "pro"}


def require_admin(x_admin_secret: str | None = Header(default=None, alias="X-Admin-Secret", include_in_schema=False)) -> None:
    settings = get_settings()
    if not settings.api_admin_secret:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="API_ADMIN_SECRET not configured on server.",
        )
    if x_admin_secret != settings.api_admin_secret:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid admin secret.",
        )


@router.post("", response_model=KeyOut, status_code=status.HTTP_201_CREATED)
def create_key(
    body: KeyCreate,
    _: None = Depends(require_admin),
    ch=Depends(get_ch),
):
    if body.tier not in VALID_TIERS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"tier must be one of: {', '.join(sorted(VALID_TIERS))}",
        )

    raw_key, key_hash = generate_key()
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    ch.insert(
        "signal.api_keys",
        [[
            key_hash,
            body.tier,
            bool(body.buyer_verified),
            body.label or "",
            now,
            False,       # revoked
            None,        # webhook_url
            None,        # webhook_secret
        ]],
        column_names=[
            "key_hash", "tier", "buyer_verified", "label",
            "created_at", "revoked", "webhook_url", "webhook_secret",
        ],
    )

    return KeyOut(key=raw_key, key_hash=key_hash, tier=body.tier, created_at=now)
