"""Authentication helpers and dependencies for Sentinel Auth API.

This file provides:
- API key extraction and verification (admin key + per-client API keys stored in DB)
- Session token handling and verification
- Password hashing and verification utilities
- A simple in-process rate limiter for authentication endpoints

The user requested the file be replaced with this improved version which adds
stricter startup checks (refuse to run in production with a default key),
email validation helpers, and an auth attempt rate limiter.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone as _tz

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session

from src.database import get_db
from src.store import DatabaseStore

api_key_header = APIKeyHeader(name="Authorization", auto_error=False)
x_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
x_session_token_header = APIKeyHeader(name="X-Session-Token", auto_error=False)

_DEFAULT_DEV_KEY = "default-dev-key"
_ENV_NAME = os.getenv("APP_ENV", "production").lower()
ADMIN_API_KEY = os.getenv("API_KEY", _DEFAULT_DEV_KEY)

# Refuse to start in production with the default insecure key
if ADMIN_API_KEY == _DEFAULT_DEV_KEY and _ENV_NAME not in ("development", "dev", "test", "testing"):
    raise RuntimeError(
        "FATAL: API_KEY environment variable is not set (or uses the insecure default). "
        "Set a strong API_KEY before starting in a non-development environment."
    )

# Basic RFC-5322-inspired email regex — rejects obviously malformed addresses
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def generate_api_key() -> str:
    return f"ska_live_{secrets.token_urlsafe(24)}"


def api_key_prefix(api_key: str) -> str:
    return api_key[:18]


def normalize_email(email: str) -> str:
    return email.strip().lower()


def normalize_phone_number(phone_number: str) -> str:
    """Normalize and validate a phone number to E.164-like format.

    Strips whitespace, dashes, and parentheses then verifies the result
    starts with '+' and contains only digits afterwards.
    Raises ValueError if the number looks invalid.
    """
    cleaned = phone_number.strip().replace("-", "").replace(" ", "").replace("(", "").replace(")", "")
    if not cleaned.startswith("+"):
        raise ValueError(f"Phone number must start with '+' country code, got: {phone_number!r}")
    digits = cleaned[1:]
    if not digits.isdigit() or len(digits) < 7 or len(digits) > 15:
        raise ValueError(f"Invalid phone number: {phone_number!r}")
    return cleaned


def validate_email(email: str) -> bool:
    """Return True if email looks structurally valid."""
    return bool(_EMAIL_RE.match(email))


# ── In-process rate limiter for auth endpoints ────────────────────────────────
_auth_rate_lock = threading.Lock()
# Maps IP -> deque of attempt timestamps
_auth_rate_store: dict[str, deque] = defaultdict(deque)
_AUTH_RATE_WINDOW_SECONDS = int(os.getenv("AUTH_RATE_WINDOW_SECONDS", "60"))
_AUTH_RATE_MAX_ATTEMPTS = int(os.getenv("AUTH_RATE_MAX_ATTEMPTS", "10"))


def check_auth_rate_limit(ip: str) -> None:
    """Raise HTTP 429 if the IP has exceeded the auth attempt rate limit."""
    now = datetime.now(_tz.utc)
    cutoff = now - timedelta(seconds=_AUTH_RATE_WINDOW_SECONDS)
    with _auth_rate_lock:
        dq = _auth_rate_store[ip]
        # Evict old entries
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= _AUTH_RATE_MAX_ATTEMPTS:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many authentication attempts. Please try again later.",
                headers={"Retry-After": str(_AUTH_RATE_WINDOW_SECONDS)},
            )
        dq.append(now)


def validate_email(email: str) -> bool:
    """Return True if email looks structurally valid."""
    return bool(_EMAIL_RE.match(email))


def generate_session_token() -> str:
    return f"ssa_live_{secrets.token_urlsafe(32)}"


def hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_phone_verification_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_phone_verification_code(phone_number: str, code: str) -> str:
    secret = os.getenv("PHONE_CODE_SECRET", "sentinel-phone-code-secret")
    payload = f"{phone_number}:{code}:{secret}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


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
    if client and client.revoked_at is None and client.suspended_at is None:
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
