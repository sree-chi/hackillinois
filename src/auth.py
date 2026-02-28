from __future__ import annotations

import hashlib
import hmac
import os
import secrets

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session

from src.database import get_db
from src.store import DatabaseStore

api_key_header = APIKeyHeader(name="Authorization", auto_error=False)
x_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

ADMIN_API_KEY = os.getenv("API_KEY", "default-dev-key")


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def generate_api_key() -> str:
    return f"ska_live_{secrets.token_urlsafe(24)}"


def api_key_prefix(api_key: str) -> str:
    return api_key[:18]


def extract_api_key(authorization_header: str | None, x_api_key: str | None) -> str | None:
    if authorization_header:
        return authorization_header.replace("Bearer ", "", 1).strip()
    if x_api_key:
        return x_api_key.strip()
    return None

def _is_admin_key(candidate: str) -> bool:
    return hmac.compare_digest(candidate.encode("utf-8"), ADMIN_API_KEY.encode("utf-8"))


async def verify_api_key(
    authorization_header: str | None = Security(api_key_header),
    x_api_key: str | None = Security(x_api_key_header),
    db: Session = Depends(get_db),
):
    candidate = extract_api_key(authorization_header, x_api_key)
    if not candidate:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API Key",
        )

    if candidate == ADMIN_API_KEY:
        return candidate

    store = DatabaseStore(db)
    client = store.get_api_client_by_hash(hash_api_key(candidate))
    if client and client.revoked_at is None:
        store.mark_api_client_used(client.client_id)
        return candidate

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API Key",
    )

async def verify_admin_key(
        authorization_header: str | None = Security(api_key_header), 
        x_api_key: str | None = Security(x_api_key_header), 
) -> str:
    candidate = extract_api_key(authorization_header, x_api_key)
    if not candidate or not _is_admin_key(candidate):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This endpoint requires admin credentials",
        )
    return candidate