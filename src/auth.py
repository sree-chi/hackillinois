from __future__ import annotations

import base64
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
x_session_token_header = APIKeyHeader(name="X-Session-Token", auto_error=False)

ADMIN_API_KEY = os.getenv("API_KEY", "default-dev-key")


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def generate_api_key() -> str:
    return f"ska_live_{secrets.token_urlsafe(24)}"


def api_key_prefix(api_key: str) -> str:
    return api_key[:18]


def normalize_email(email: str) -> str:
    return email.strip().lower()


def generate_session_token() -> str:
    return f"ssa_live_{secrets.token_urlsafe(32)}"


def hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120000)
    return f"{base64.b64encode(salt).decode('ascii')}:{base64.b64encode(digest).decode('ascii')}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        encoded_salt, encoded_digest = password_hash.split(":", 1)
        salt = base64.b64decode(encoded_salt.encode("ascii"))
        expected = base64.b64decode(encoded_digest.encode("ascii"))
    except Exception:
        return False

    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120000)
    return hmac.compare_digest(candidate, expected)


def extract_api_key(authorization_header: str | None, x_api_key: str | None) -> str | None:
    if authorization_header and authorization_header.startswith("Bearer "):
        return authorization_header.replace("Bearer ", "", 1).strip()
    if x_api_key:
        return x_api_key.strip()
    return None


def extract_session_token(authorization_header: str | None, x_session_token: str | None) -> str | None:
    if x_session_token:
        return x_session_token.strip()
    if authorization_header and authorization_header.startswith("Bearer "):
        return authorization_header.replace("Bearer ", "", 1).strip()
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
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing API Key")

    if _is_admin_key(candidate):
        return candidate

    store = DatabaseStore(db)
    client = store.get_api_client_by_hash(hash_api_key(candidate))
    if client and client.revoked_at is None:
        store.mark_api_client_used(client.client_id)
        return candidate

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing API Key")


async def verify_admin_key(
    authorization_header: str | None = Security(api_key_header),
    x_api_key: str | None = Security(x_api_key_header),
):
    candidate = extract_api_key(authorization_header, x_api_key)
    if not candidate or not _is_admin_key(candidate):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This endpoint requires admin credentials",
        )
    return candidate


async def verify_account_session(
    authorization_header: str | None = Security(api_key_header),
    x_session_token: str | None = Security(x_session_token_header),
    db: Session = Depends(get_db),
):
    token = extract_session_token(authorization_header, x_session_token)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing session token")

    store = DatabaseStore(db)
    session = store.get_account_session_by_hash(hash_session_token(token))
    if not session or session.revoked_at is not None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing session token")

    from datetime import datetime, timezone

    expires_at = session.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session token expired")

    account = store.get_account_by_id(session.account_id)
    if not account:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account not found for session")

    return account
