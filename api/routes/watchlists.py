"""
GET/POST/DELETE /v1/watchlists — per-key signal filters.

Watchlists let callers pre-filter the signal stream server-side so they only
receive signals that match their criteria.  Each API key has its own set.

Pattern types:
  apex_domain  — exact match on apex_domain field
  keyword      — substring match on domain field
  industry     — case-insensitive exact match on company_industry
  saas_vendor  — case-insensitive exact match on saas_vendor
"""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Path, status

from api.deps import authenticated_key, get_ch
from api.schemas import VALID_PATTERN_TYPES, WatchlistCreate, WatchlistListResponse, WatchlistOut

router = APIRouter(prefix="/v1/watchlists", tags=["watchlists"])


@router.get("", response_model=WatchlistListResponse)
def list_watchlists(key: dict = Depends(authenticated_key), ch=Depends(get_ch)):
    rows = ch.query(
        """
        SELECT watchlist_id, pattern_type, pattern, created_at, active
        FROM signal.watchlists
        WHERE key_hash = %(h)s
        ORDER BY created_at DESC
        """,
        parameters={"h": key["key_hash"]},
    ).result_rows

    items = [
        WatchlistOut(
            watchlist_id=row[0],
            pattern_type=row[1],
            pattern=row[2],
            created_at=row[3],
            active=bool(row[4]),
        )
        for row in rows
    ]
    return WatchlistListResponse(data=items)


@router.post("", response_model=WatchlistOut, status_code=status.HTTP_201_CREATED)
def create_watchlist(
    body: WatchlistCreate,
    key: dict = Depends(authenticated_key),
    ch=Depends(get_ch),
):
    if body.pattern_type not in VALID_PATTERN_TYPES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"pattern_type must be one of: {', '.join(sorted(VALID_PATTERN_TYPES))}",
        )

    wid = uuid.uuid4()
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    ch.insert(
        "signal.watchlists",
        [[str(wid), key["key_hash"], body.pattern_type, body.pattern, now, True]],
        column_names=["watchlist_id", "key_hash", "pattern_type", "pattern", "created_at", "active"],
    )

    return WatchlistOut(
        watchlist_id=wid,
        pattern_type=body.pattern_type,
        pattern=body.pattern,
        created_at=now,
        active=True,
    )


@router.delete("/{watchlist_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_watchlist(
    watchlist_id: str = Path(...),
    key: dict = Depends(authenticated_key),
    ch=Depends(get_ch),
):
    # Verify ownership before deactivating
    rows = ch.query(
        "SELECT watchlist_id FROM signal.watchlists WHERE watchlist_id = %(wid)s AND key_hash = %(h)s LIMIT 1",
        parameters={"wid": watchlist_id, "h": key["key_hash"]},
    ).result_rows

    if not rows:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Watchlist not found.")

    # ClickHouse: insert a replacement row with active=false (ReplacingMergeTree deduplication)
    ch.command(
        "ALTER TABLE signal.watchlists UPDATE active = false WHERE watchlist_id = %(wid)s",
        parameters={"wid": watchlist_id},
    )
