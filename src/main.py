from __future__ import annotations

# Load .env.local BEFORE any src.* imports so that modules like auth.py
# can read env vars (API_KEY, APP_ENV, etc.) at import time.
from dotenv import load_dotenv
load_dotenv(dotenv_path=".env.local", override=True)

import logging
import os
import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session
from src.auth import (
    api_key_prefix,
    extract_api_key,
    generate_api_key,
    generate_phone_verification_code,
    generate_session_token,
    hash_api_key,
    hash_phone_verification_code,
    hash_password,
    hash_session_token,
    normalize_email,
    normalize_phone_number,
    verify_account_session,
    verify_admin_key,
    verify_api_key,
    verify_password,
)
from src.database import Base, engine, get_db
from src.models import (
    AccountApiPricingRecord,
    AccountDashboardResponse,
    AccountSessionResponse,
    AgentIntentRequest,
    AgentRecord,
    AuditRecord,
    AuditStatus,
    AuditStatsResponse,
    AccountRecord,
    AuthorizationProof,
    AuthorizationDecision,
    AuthorizeRequest,
    BudgetExceptionRecord,
    CreateAgentRequest,
    LinkedWalletRecord,
    LoginAccountRequest,
    PhoneCodeChallengeResponse,
    PublicApiOverview,
    CreatePolicyRequest,
    ErrorEnvelope,
    IssueApiKeyRequest,
    IssueApiKeyResponse,
    RegisterAccountRequest,
    ReceiptStatus,
    RequestPhoneCodeRequest,
    SafetyViolation,
    UpdateApiPricingRequest,
    VerifyPhoneCodeRequest,
    VerifyProofRequest,
    VerifyProofResult,
    UpdatePolicyRequest,
    WalletLinkChallengeRequest,
    WalletLinkChallengeResponse,
    WalletLinkRequest,
    WalletOverviewResponse,
    expires_at,
    new_id,
)
from src.solana import SolanaVerificationError, receipt_service
from src.sms import SmsDeliveryError, SmsSender
from src.store import DatabaseStore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("SentinelAuth")

HIGH_RISK_AMOUNT_USD = float(os.getenv("HIGH_RISK_AMOUNT_USD", "1000"))
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
ACCOUNT_SESSION_TTL_SECONDS = int(os.getenv("ACCOUNT_SESSION_TTL_SECONDS", "86400"))
PHONE_VERIFICATION_TTL_SECONDS = int(os.getenv("PHONE_VERIFICATION_TTL_SECONDS", "600"))
ALLOWED_ORIGINS = [
    origin.strip().rstrip("/")
    for origin in os.getenv(
        "CORS_ALLOW_ORIGINS",
        "http://localhost:8000,http://127.0.0.1:8000,http://localhost:3000,http://127.0.0.1:3000"
    ).split(",")
    if origin.strip()
]
sms_sender = SmsSender()


def ensure_runtime_schema_compatibility() -> None:
    inspector = inspect(engine)
    table_names = set(inspector.get_table_names())
    if "policies" not in table_names:
        return

    policy_columns = {column["name"] for column in inspector.get_columns("policies")}
    dialect = engine.dialect.name

    statements: list[str] = []
    if "version" not in policy_columns:
        if dialect == "postgresql":
            statements.append("ALTER TABLE policies ADD COLUMN IF NOT EXISTS version INTEGER NOT NULL DEFAULT 1")
        else:
            statements.append("ALTER TABLE policies ADD COLUMN version INTEGER NOT NULL DEFAULT 1")
    if "root_policy_id" not in policy_columns:
        if dialect == "postgresql":
            statements.append("ALTER TABLE policies ADD COLUMN IF NOT EXISTS root_policy_id VARCHAR")
        else:
            statements.append("ALTER TABLE policies ADD COLUMN root_policy_id VARCHAR")
    if "idempotency_key" not in policy_columns:
        if dialect == "postgresql":
            statements.append("ALTER TABLE policies ADD COLUMN IF NOT EXISTS idempotency_key VARCHAR")
            statements.append("CREATE UNIQUE INDEX IF NOT EXISTS ix_policies_idempotency_key ON policies (idempotency_key)")
        else:
            statements.append("ALTER TABLE policies ADD COLUMN idempotency_key VARCHAR")
    if "policy_schema_version" not in policy_columns:
        if dialect == "postgresql":
            statements.append(
                "ALTER TABLE policies ADD COLUMN IF NOT EXISTS policy_schema_version VARCHAR(50) NOT NULL DEFAULT 'sentinel-policy/v1'"
            )
        else:
            statements.append(
                "ALTER TABLE policies ADD COLUMN policy_schema_version VARCHAR(50) NOT NULL DEFAULT 'sentinel-policy/v1'"
            )
    if "risk_categories" not in policy_columns:
        if dialect == "postgresql":
            statements.append("ALTER TABLE policies ADD COLUMN IF NOT EXISTS risk_categories JSONB NOT NULL DEFAULT '[]'::jsonb")
        else:
            statements.append("ALTER TABLE policies ADD COLUMN risk_categories JSON NOT NULL DEFAULT '[]'")
    if "budget_config" not in policy_columns:
        if dialect == "postgresql":
            statements.append("ALTER TABLE policies ADD COLUMN IF NOT EXISTS budget_config JSONB NOT NULL DEFAULT '{}'::jsonb")
        else:
            statements.append("ALTER TABLE policies ADD COLUMN budget_config JSON NOT NULL DEFAULT '{}'")
    if "required_approvers" not in policy_columns:
        if dialect == "postgresql":
            statements.append("ALTER TABLE policies ADD COLUMN IF NOT EXISTS required_approvers JSONB NOT NULL DEFAULT '[]'::jsonb")
        else:
            statements.append("ALTER TABLE policies ADD COLUMN required_approvers JSON NOT NULL DEFAULT '[]'")

    if not statements:
        pass

    if "audit_records" in table_names:
        audit_columns = {column["name"] for column in inspector.get_columns("audit_records")}
        if "reasoning_trace" not in audit_columns:
            if dialect == "postgresql":
                statements.append("ALTER TABLE audit_records ADD COLUMN IF NOT EXISTS reasoning_trace TEXT")
            else:
                statements.append("ALTER TABLE audit_records ADD COLUMN reasoning_trace TEXT")

    if "api_clients" in table_names:
        api_client_columns = {column["name"] for column in inspector.get_columns("api_clients")}
        if "suspended_at" not in api_client_columns:
            if dialect == "postgresql":
                statements.append("ALTER TABLE api_clients ADD COLUMN IF NOT EXISTS suspended_at TIMESTAMP WITH TIME ZONE")
            else:
                statements.append("ALTER TABLE api_clients ADD COLUMN suspended_at DATETIME")
        if "wallet_address" not in api_client_columns:
            if dialect == "postgresql":
                statements.append("ALTER TABLE api_clients ADD COLUMN IF NOT EXISTS wallet_address VARCHAR(120)")
            else:
                statements.append("ALTER TABLE api_clients ADD COLUMN wallet_address VARCHAR(120)")
        if "wallet_label" not in api_client_columns:
            if dialect == "postgresql":
                statements.append("ALTER TABLE api_clients ADD COLUMN IF NOT EXISTS wallet_label VARCHAR(100)")
            else:
                statements.append("ALTER TABLE api_clients ADD COLUMN wallet_label VARCHAR(100)")

    if "accounts" in table_names:
        account_columns = {column["name"] for column in inspector.get_columns("accounts")}
        if "phone_number" not in account_columns:
            if dialect == "postgresql":
                statements.append("ALTER TABLE accounts ADD COLUMN IF NOT EXISTS phone_number VARCHAR(20)")
            else:
                statements.append("ALTER TABLE accounts ADD COLUMN phone_number VARCHAR(20)")

    if "account_phone_verifications" in table_names:
        verification_columns = {column["name"] for column in inspector.get_columns("account_phone_verifications")}
        if "account_id" not in verification_columns:
            if dialect == "postgresql":
                statements.append("ALTER TABLE account_phone_verifications ADD COLUMN IF NOT EXISTS account_id VARCHAR")
            else:
                statements.append("ALTER TABLE account_phone_verifications ADD COLUMN account_id VARCHAR")

    if not statements:
        return

    with engine.begin() as connection:
        for statement in statements:
            logger.warning("Applying runtime schema compatibility patch: %s", statement)
            connection.execute(text(statement))


@asynccontextmanager
async def lifespan(app: FastAPI):
    if str(engine.url) != "sqlite:///:memory:":
        Base.metadata.create_all(bind=engine)
        ensure_runtime_schema_compatibility()
    yield


app = FastAPI(
    title="Sentinel Auth API",
    version="0.1.0",
    description="Policy-based AI action authorization with Solana-backed safety receipts.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["x-mock-payment-token", "X-Request-ID"],
)


@app.get("/")
def read_root():
    return {
        "name": "Sentinel Auth API",
        "status": "online",
        "docs_url": "/docs",
        "message": "Public API for issuing agent keys, creating policies, and authorizing AI actions.",
    }


@app.get("/health")
def health_check():
    return {"status": "healthy"}


def resolve_public_base_url(request: Request) -> str:
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL
    return str(request.base_url).rstrip("/")


def request_domain(request: Request) -> str:
    origin = request.headers.get("origin")
    if origin:
        return origin.rstrip("/")
    return resolve_public_base_url(request)


def error_response(
    status_code: int,
    code: str,
    message: str,
    request_id: str | None = None,
    policy_id: str | None = None,
    details: dict | None = None,
) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail=ErrorEnvelope(
            error={
                "type": "policy_error" if status_code < 500 else "server_error",
                "code": code,
                "message": message,
                "request_id": request_id,
                "policy_id": policy_id,
                "status": status_code,
                "details": details or {},
            }
        ).model_dump()
    )


@app.get("/v1/public/overview", response_model=PublicApiOverview)
def public_overview(request: Request):
    base_url = resolve_public_base_url(request)
    return PublicApiOverview(
        name="Sentinel Auth API",
        status="online",
        docs_url=f"{base_url}/docs",
        key_endpoint=f"{base_url}/v1/accounts/register",
        quickstart=[
            "Create a developer key from the public portal or POST /v1/developer/keys.",
            "Send the key as Authorization: Bearer <key> or X-API-Key.",
            "Create a policy: POST /v1/policies",
            "Route each agent action through: POST /v1/authorize",
            "Update a policy (creates new version): PUT /v1/policies/{id}",
        ],
        sample_policy_rules={
            "allowed_http_methods": ["GET", "POST"],
            "max_spend_usd": 5000,
            "max_requests_per_minute": 60,
        },
    )


def build_session_response(account: AccountRecord, request: Request, store: DatabaseStore) -> AccountSessionResponse:
    session_token = generate_session_token()
    session = store.create_account_session(
        account_id=account.account_id,
        token_hash=hash_session_token(session_token),
        expires_at=expires_at(ACCOUNT_SESSION_TTL_SECONDS),
    )
    return AccountSessionResponse(
        account=account,
        session_token=session_token,
        expires_at=session.expires_at,
    )


@app.post("/v1/accounts/register", response_model=AccountSessionResponse, status_code=status.HTTP_201_CREATED)
def register_account(payload: RegisterAccountRequest, request: Request, db: Session = Depends(get_db)):
    store = DatabaseStore(db)
    email = normalize_email(payload.email)
    if store.get_account_by_email(email):
        raise error_response(
            status_code=status.HTTP_409_CONFLICT,
            code="ACCOUNT_ALREADY_EXISTS",
            message="An account with this email already exists.",
        )
    account = store.create_account(email=email, password_hash=hash_password(payload.password), full_name=payload.full_name)
    return build_session_response(account, request, store)


@app.post("/v1/accounts/login", response_model=AccountSessionResponse)
def login_account(payload: LoginAccountRequest, request: Request, db: Session = Depends(get_db)):
    store = DatabaseStore(db)
    email = normalize_email(payload.email)
    account_row = store.get_account_by_email(email)
    if not account_row or not verify_password(payload.password, account_row.password_hash):
        raise error_response(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="INVALID_LOGIN",
            message="Invalid email or password.",
        )
    account = AccountRecord.model_validate(account_row)
    return build_session_response(account, request, store)


@app.post("/v1/accounts/me/phone-2fa/request-code", response_model=PhoneCodeChallengeResponse, status_code=status.HTTP_201_CREATED)
def request_phone_code(
    payload: RequestPhoneCodeRequest,
    account: AccountRecord = Depends(verify_account_session),
    db: Session = Depends(get_db),
):
    store = DatabaseStore(db)
    try:
        phone_number = normalize_phone_number(payload.phone_number)
    except ValueError as exc:
        raise error_response(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_PHONE_NUMBER",
            message=str(exc),
        ) from exc

    existing_account = store.get_account_by_phone(phone_number)
    if existing_account and existing_account.account_id != account.account_id:
        raise error_response(
            status_code=status.HTTP_409_CONFLICT,
            code="PHONE_ALREADY_IN_USE",
            message="This phone number is already verified on another account.",
        )

    code = generate_phone_verification_code()
    try:
        delivery = sms_sender.send_verification_code(phone_number, code)
    except SmsDeliveryError as exc:
        raise error_response(
            status_code=status.HTTP_502_BAD_GATEWAY,
            code="SMS_DELIVERY_FAILED",
            message=str(exc),
        ) from exc

    verification = store.create_phone_verification(
        account_id=account.account_id,
        phone_number=phone_number,
        code_hash=hash_phone_verification_code(phone_number, code),
        full_name=account.full_name,
        delivery_channel=str(delivery["delivery_channel"]),
        expires_at=expires_at(PHONE_VERIFICATION_TTL_SECONDS),
    )
    return PhoneCodeChallengeResponse(
        phone_number=phone_number,
        expires_at=verification.expires_at,
        delivery_channel=str(delivery["delivery_channel"]),
        dev_code=delivery["dev_code"],
    )


@app.post("/v1/accounts/me/phone-2fa/verify-code", response_model=AccountRecord)
def verify_phone_code(
    payload: VerifyPhoneCodeRequest,
    account: AccountRecord = Depends(verify_account_session),
    db: Session = Depends(get_db),
):
    store = DatabaseStore(db)
    try:
        phone_number = normalize_phone_number(payload.phone_number)
    except ValueError as exc:
        raise error_response(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_PHONE_NUMBER",
            message=str(exc),
        ) from exc

    verification = store.get_latest_phone_verification(phone_number, account.account_id)
    if not verification or verification.consumed_at is not None:
        raise error_response(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="INVALID_CODE",
            message="No active verification code was found for this phone number.",
        )

    verification_expires_at = verification.expires_at
    if verification_expires_at.tzinfo is None:
        verification_expires_at = verification_expires_at.replace(tzinfo=timezone.utc)
    if verification_expires_at <= datetime.now(timezone.utc):
        raise error_response(
            status_code=status.HTTP_410_GONE,
            code="CODE_EXPIRED",
            message="The verification code has expired.",
        )
    if verification.code_hash != hash_phone_verification_code(phone_number, payload.code.strip()):
        raise error_response(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="INVALID_CODE",
            message="The verification code is invalid.",
        )

    store.consume_phone_verification(verification.verification_id)
    updated_account = store.update_account_phone_number(account.account_id, phone_number)
    if not updated_account:
        raise error_response(
            status_code=status.HTTP_404_NOT_FOUND,
            code="ACCOUNT_NOT_FOUND",
            message="Account was not found.",
        )
    return updated_account


@app.get("/v1/accounts/me", response_model=AccountRecord)
def get_current_account(account: AccountRecord = Depends(verify_account_session)):
    return account


@app.get("/v1/accounts/me/dashboard", response_model=AccountDashboardResponse)
def account_dashboard(
    account: AccountRecord = Depends(verify_account_session),
    db: Session = Depends(get_db),
):
    store = DatabaseStore(db)
    return AccountDashboardResponse(
        account=account,
        api_keys=store.list_api_clients_for_account(account.account_id),
        linked_wallets=store.list_wallets_for_account(account.account_id),
    )


@app.get("/v1/accounts/me/keys/{client_id}/pricing", response_model=AccountApiPricingRecord)
def get_account_api_key_pricing(
    client_id: str,
    account: AccountRecord = Depends(verify_account_session),
    db: Session = Depends(get_db),
):
    store = DatabaseStore(db)
    pricing = store.get_api_pricing_for_account(account.account_id, client_id)
    if not pricing:
        raise error_response(
            status_code=status.HTTP_404_NOT_FOUND,
            code="API_PRICING_NOT_FOUND",
            message="No pricing profile exists for this API key.",
        )
    return pricing


@app.put("/v1/accounts/me/keys/{client_id}/pricing", response_model=AccountApiPricingRecord)
def upsert_account_api_key_pricing(
    client_id: str,
    payload: UpdateApiPricingRequest,
    account: AccountRecord = Depends(verify_account_session),
    db: Session = Depends(get_db),
):
    store = DatabaseStore(db)
    pricing = store.upsert_api_pricing_for_account(account.account_id, client_id, payload)
    if not pricing:
        raise error_response(
            status_code=status.HTTP_404_NOT_FOUND,
            code="API_KEY_NOT_FOUND",
            message="The requested API key does not exist for this account.",
        )
    return pricing


@app.post(
    "/v1/accounts/me/solana/challenge",
    response_model=WalletLinkChallengeResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_wallet_link_challenge(
    payload: WalletLinkChallengeRequest,
    request: Request,
    account: AccountRecord = Depends(verify_account_session),
    db: Session = Depends(get_db),
):
    store = DatabaseStore(db)
    try:
        wallet_address = receipt_service.validate_wallet_address(payload.wallet_address)
    except SolanaVerificationError as exc:
        raise error_response(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_WALLET_ADDRESS",
            message=str(exc),
        ) from exc

    nonce = receipt_service.new_wallet_link_nonce()
    message = receipt_service.build_wallet_link_message(
        domain=request_domain(request),
        wallet_address=wallet_address,
        account_email=account.email,
        nonce=nonce,
    )
    challenge = store.create_wallet_link_challenge(
        account_id=account.account_id,
        wallet_address=wallet_address,
        provider=payload.provider.lower(),
        nonce=nonce,
        message=message,
        ttl_seconds=receipt_service.wallet_link_ttl_seconds,
    )
    return WalletLinkChallengeResponse(
        wallet_address=challenge.wallet_address,
        provider=challenge.provider,
        nonce=challenge.nonce,
        message=challenge.message,
        expires_at=challenge.expires_at,
    )


@app.post("/v1/accounts/me/solana/link", response_model=LinkedWalletRecord, status_code=status.HTTP_201_CREATED)
def link_solana_wallet(
    payload: WalletLinkRequest,
    account: AccountRecord = Depends(verify_account_session),
    db: Session = Depends(get_db),
):
    store = DatabaseStore(db)
    try:
        wallet_address = receipt_service.validate_wallet_address(payload.wallet_address)
    except SolanaVerificationError as exc:
        raise error_response(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_WALLET_ADDRESS",
            message=str(exc),
        ) from exc

    challenge = store.get_wallet_link_challenge(account.account_id, wallet_address, payload.nonce)
    if not challenge or challenge.provider != payload.provider.lower():
        raise error_response(
            status_code=status.HTTP_404_NOT_FOUND,
            code="WALLET_CHALLENGE_NOT_FOUND",
            message="Wallet link challenge was not found.",
        )
    if challenge.used_at is not None:
        raise error_response(
            status_code=status.HTTP_409_CONFLICT,
            code="WALLET_CHALLENGE_USED",
            message="Wallet link challenge has already been used.",
        )
    challenge_expires_at = challenge.expires_at
    if challenge_expires_at.tzinfo is None:
        challenge_expires_at = challenge_expires_at.replace(tzinfo=timezone.utc)
    if challenge_expires_at <= datetime.now(timezone.utc):
        raise error_response(
            status_code=status.HTTP_410_GONE,
            code="WALLET_CHALLENGE_EXPIRED",
            message="Wallet link challenge has expired.",
        )
    if payload.signed_message != challenge.message:
        raise error_response(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="WALLET_MESSAGE_MISMATCH",
            message="Signed wallet message does not match the challenge.",
        )
    if not receipt_service.verify_wallet_link_signature(wallet_address, payload.signed_message, payload.signature):
        raise error_response(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="INVALID_WALLET_SIGNATURE",
            message="Wallet signature verification failed.",
        )

    existing_wallet = store.get_account_wallet_by_address(wallet_address)
    if existing_wallet and existing_wallet.account_id != account.account_id:
        raise error_response(
            status_code=status.HTTP_409_CONFLICT,
            code="WALLET_ALREADY_LINKED",
            message="This wallet is already linked to another account.",
        )

    store.mark_wallet_link_challenge_used(challenge.challenge_id)
    try:
        return store.link_account_wallet(
            account_id=account.account_id,
            wallet_address=wallet_address,
            provider=payload.provider.lower(),
        )
    except ValueError as exc:
        raise error_response(
            status_code=status.HTTP_409_CONFLICT,
            code="WALLET_ALREADY_LINKED",
            message=str(exc),
        ) from exc


@app.get("/v1/accounts/me/solana/wallets", response_model=list[LinkedWalletRecord])
def list_linked_wallets(
    account: AccountRecord = Depends(verify_account_session),
    db: Session = Depends(get_db),
):
    store = DatabaseStore(db)
    return store.list_wallets_for_account(account.account_id)


@app.get("/v1/accounts/me/solana/wallets/{wallet_address}", response_model=WalletOverviewResponse)
def get_linked_wallet_overview(
    wallet_address: str,
    account: AccountRecord = Depends(verify_account_session),
    db: Session = Depends(get_db),
):
    store = DatabaseStore(db)
    wallet = store.get_wallet_for_account(account.account_id, wallet_address)
    if not wallet:
        raise error_response(
            status_code=status.HTTP_404_NOT_FOUND,
            code="WALLET_NOT_FOUND",
            message="Wallet is not linked to this account.",
        )
    try:
        overview = receipt_service.get_wallet_overview(wallet.wallet_address)
    except SolanaVerificationError as exc:
        raise error_response(
            status_code=status.HTTP_502_BAD_GATEWAY,
            code="SOLANA_RPC_UNAVAILABLE",
            message=str(exc),
        ) from exc
    return WalletOverviewResponse(wallet=wallet, **overview)


@app.delete("/v1/accounts/me/solana/wallets/{wallet_address}", status_code=status.HTTP_200_OK)
def unlink_solana_wallet(
    wallet_address: str,
    account: AccountRecord = Depends(verify_account_session),
    db: Session = Depends(get_db),
):
    store = DatabaseStore(db)
    deleted = store.unlink_wallet_for_account(account.account_id, wallet_address)
    if not deleted:
        raise error_response(
            status_code=status.HTTP_404_NOT_FOUND,
            code="WALLET_NOT_FOUND",
            message="Wallet is not linked to this account.",
        )
    return {"status": "success", "wallet_address": wallet_address}


@app.post("/v1/developer/keys", response_model=IssueApiKeyResponse, status_code=status.HTTP_201_CREATED)
def issue_developer_key(
    payload: IssueApiKeyRequest,
    request: Request,
    account: AccountRecord = Depends(verify_account_session),
    db: Session = Depends(get_db),
):
    key = generate_api_key()
    prefix = api_key_prefix(key)
    store = DatabaseStore(db)
    client = store.create_api_client(
        payload,
        api_key_hash=hash_api_key(key),
        api_key_prefix=prefix,
        account_id=account.account_id,
        owner_email=account.email,
    )
    base_url = resolve_public_base_url(request)
    return IssueApiKeyResponse(
        client_id=client.client_id,
        app_name=client.app_name,
        owner_email=account.email,
        api_key=key,
        api_key_prefix=client.api_key_prefix,
        wallet_address=payload.wallet_address,
        wallet_label=payload.wallet_label,
        created_at=client.created_at,
        base_url=base_url,
        docs_url=f"{base_url}/docs",
        authorization_header=f"Bearer {key}",
        example_policy_name=f"{client.app_name} default policy",
    )


@app.delete("/v1/accounts/me/keys/{client_id}", status_code=status.HTTP_200_OK)
def delete_account_api_key(
    client_id: str,
    account: AccountRecord = Depends(verify_account_session),
    db: Session = Depends(get_db),
):
    store = DatabaseStore(db)
    client = store.revoke_api_client_for_account(account.account_id, client_id)
    if not client:
        raise error_response(
            status_code=status.HTTP_404_NOT_FOUND,
            code="API_KEY_NOT_FOUND",
            message="The requested API key does not exist for this account.",
        )
    return {
        "status": "success",
        "client_id": client.client_id,
        "revoked_at": client.revoked_at,
    }


@app.post("/v1/accounts/me/keys/{client_id}/suspend", status_code=status.HTTP_200_OK)
def suspend_account_api_key(
    client_id: str,
    account: AccountRecord = Depends(verify_account_session),
    db: Session = Depends(get_db),
):
    store = DatabaseStore(db)
    client = store.suspend_api_client_for_account(account.account_id, client_id)
    if not client:
        raise error_response(
            status_code=status.HTTP_404_NOT_FOUND,
            code="API_KEY_NOT_FOUND",
            message="The requested active API key does not exist for this account.",
        )
    return {
        "status": "success",
        "client_id": client.client_id,
        "suspended_at": client.suspended_at,
    }


@app.post("/v1/accounts/me/keys/{client_id}/restore", status_code=status.HTTP_200_OK)
def restore_account_api_key(
    client_id: str,
    account: AccountRecord = Depends(verify_account_session),
    db: Session = Depends(get_db),
):
    store = DatabaseStore(db)
    client = store.restore_api_client_for_account(account.account_id, client_id)
    if not client:
        raise error_response(
            status_code=status.HTTP_404_NOT_FOUND,
            code="API_KEY_NOT_FOUND",
            message="The requested restorable API key does not exist for this account.",
        )
    return {
        "status": "success",
        "client_id": client.client_id,
        "suspended_at": client.suspended_at,
    }


@app.post(
    "/v1/developer/keys/{client_id}/rotate",
    response_model=IssueApiKeyResponse,
    dependencies=[Depends(verify_api_key)],
)
def rotate_developer_key(
    client_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    raise error_response(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        code="KEY_ROTATION_UNAVAILABLE",
        message="API key rotation is temporarily unavailable in this build.",
    )


@app.delete(
    "/v1/developer/keys/{client_id}",
    status_code=status.HTTP_200_OK,
)
def revoke_developer_key(
    client_id: str,
    account: AccountRecord = Depends(verify_account_session),
    db: Session = Depends(get_db),
):
    store = DatabaseStore(db)
    client = store.revoke_api_client_for_account(account.account_id, client_id)
    if not client:
        raise error_response(
            status_code=status.HTTP_404_NOT_FOUND,
            code="API_KEY_NOT_FOUND",
            message="The requested API key does not exist for this account.",
        )
    return {
        "status": "success",
        "client_id": client.client_id,
        "revoked_at": client.revoked_at,
    }


# ─────────────────────────────────────────────────────────────
# Admin-only
# ─────────────────────────────────────────────────────────────

@app.post("/v1/dev/reset-db", dependencies=[Depends(verify_admin_key)])
def reset_database():
    """Wipe and recreate the entire DB schema. Requires the admin API key."""
    logger.warning("Admin triggered full database reset.")
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    return {"status": "success", "message": "Database wiped and recreated."}


# ─────────────────────────────────────────────────────────────
# Policies
# ─────────────────────────────────────────────────────────────

@app.post(
    "/v1/policies",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(verify_api_key)],
)
def create_policy(
    payload: CreatePolicyRequest,
    response: Response,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    db: Session = Depends(get_db),
):
    store = DatabaseStore(db)
    policy = store.create_policy(payload, idempotency_key=idempotency_key)
    if idempotency_key:
        response.headers["Idempotency-Key"] = idempotency_key
    return policy


@app.put(
    "/v1/policies/{policy_id}",
    dependencies=[Depends(verify_api_key)],
)
def update_policy(
    policy_id: str,
    payload: UpdatePolicyRequest,
    db: Session = Depends(get_db),
):
    """Create a new immutable version of an existing policy.

    The previous version is permanently stamped as superseded (its
    `superseded_by` field is set to the new version's ID).  Old audit
    records and proofs that reference the previous policy_id remain
    fully valid — only new authorization requests should use the latest ID.

    Returns the newly created policy version.
    """
    raise error_response(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        code="POLICY_UPDATE_UNAVAILABLE",
        message="Policy versioning is temporarily unavailable in this build.",
        policy_id=policy_id,
    )


@app.get("/v1/policies", dependencies=[Depends(verify_api_key)])
def list_policies(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    store = DatabaseStore(db)
    policies = store.list_all_policies(limit=limit, offset=offset)
    return {"data": [p.model_dump(mode="json") for p in policies]}


@app.get("/v1/policies/{policy_id}", dependencies=[Depends(verify_api_key)])
def get_policy(policy_id: str, db: Session = Depends(get_db)):
    store = DatabaseStore(db)
    policy = store.get_policy(policy_id)
    if not policy:
        raise error_response(
            status_code=status.HTTP_404_NOT_FOUND,
            code="POLICY_NOT_FOUND",
            message="The requested policy does not exist.",
            policy_id=policy_id,
        )
    return policy


@app.get("/v1/policies/{policy_id}/versions", dependencies=[Depends(verify_api_key)])
def list_policy_versions(policy_id: str, db: Session = Depends(get_db)):
    """Return the full version history for a policy lineage.

    Pass any version's ID — the endpoint resolves to the lineage root automatically.
    """
    raise error_response(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        code="POLICY_VERSION_HISTORY_UNAVAILABLE",
        message="Policy version history is temporarily unavailable in this build.",
        policy_id=policy_id,
    )


# Authorization


@app.post("/v1/authorize", dependencies=[Depends(verify_api_key)])
def authorize(
    payload: AuthorizeRequest,
    request: Request,
    response: Response,
    x_solana_tx_signature: str | None = Header(default=None, alias="x-solana-tx-signature"),
    db: Session = Depends(get_db),
):
    logger.info(
        f"Authorization request — policy: {payload.policy_id}, action: {payload.action.type}"
    )
    store = DatabaseStore(db)

    # ── Auto-fill agent_wallet from the API key's linked wallet ──────
    if not payload.agent_wallet:
        raw_key = extract_api_key(
            request.headers.get("authorization"),
            request.headers.get("x-api-key"),
        )
        if raw_key:
            client = store.get_api_client_by_hash(hash_api_key(raw_key))
            if client and client.wallet_address:
                payload.agent_wallet = client.wallet_address

    # Resolve: accept either a specific version id or a root id
    policy = store.get_policy(payload.policy_id)
    if not policy:
        raise error_response(
            status_code=status.HTTP_404_NOT_FOUND,
            code="POLICY_NOT_FOUND",
            message="The requested policy does not exist.",
            policy_id=payload.policy_id,
        )
    # Warn callers who submit against a superseded version
    if hasattr(policy, "superseded_by") and policy.superseded_by is not None:
        logger.warning(
            f"Authorization request uses superseded policy {payload.policy_id}. "
            f"Latest is {policy.superseded_by}."
        )
        response.headers["X-Policy-Superseded-By"] = policy.superseded_by

    rules = policy.rules

    # ── Rate limiting ────────────────────────────────────────────────
    if rules.max_requests_per_minute is not None:
        recent = store.get_requests_in_last_minute(payload.policy_id)
        logger.info(f"Rate limit: {recent}/{rules.max_requests_per_minute} rpm")
        if recent >= rules.max_requests_per_minute:
            logger.warning(f"Rate limit exceeded for policy {payload.policy_id}.")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=ErrorEnvelope(
                    error={
                        "type": "policy_error",
                        "code": "RATE_LIMIT_EXCEEDED",
                        "message": "The maximum number of requests per minute for this policy has been exceeded.",
                        "policy_id": payload.policy_id,
                        "status": 429,
                        "details": {"limit": rules.max_requests_per_minute},
                    }
                ).model_dump(),
                headers={
                    "Retry-After": "60",
                    "X-RateLimit-Limit": str(rules.max_requests_per_minute),
                    "X-RateLimit-Remaining": "0",
                },
            )

    method = payload.action.http_method.upper()
    violation: SafetyViolation | None = None
    action_payload = payload.action.model_dump()
    payment_verification_payload = payload.model_dump()
    verification_payload = {
        "policy_id": payload.policy_id,
        "policy_hash": policy.policy_hash,
        "requester": payload.requester,
        "origin_service": payload.origin_service,
        "agent_wallet": payload.agent_wallet,
        "action": action_payload,
        "reasoning_trace": payload.reasoning_trace,
    }
    action_hash = receipt_service.action_hash({
        "policy_id": payload.policy_id,
        "policy_hash": policy.policy_hash,
        "origin_service": payload.origin_service,
        "agent_wallet": payload.agent_wallet,
        "action": action_payload,
    })

    # ── High-risk x402 payment verification ─────────────────────────
    is_high_risk = (payload.action.amount_usd or 0) >= HIGH_RISK_AMOUNT_USD
    if is_high_risk:
        logger.info(
            f"High-risk action (${payload.action.amount_usd}). Verifying x402 payment..."
        )
        try:
            verified = receipt_service.verify_high_risk_signature(
                x_solana_tx_signature, payment_verification_payload
            )
        except SolanaVerificationError as exc:
            logger.exception("x402 verification failed")
            raise error_response(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                code="SOLANA_VERIFICATION_UNAVAILABLE",
                message="Unable to verify the Solana payment proof for this request.",
                policy_id=payload.policy_id,
                details={"reason": str(exc)},
            )

        if not verified:
            logger.warning("x402 verification failed for high-risk action.")
            error_detail = (
                "High-risk actions require a verified payment token via x-solana-tx-signature."
            )
            headers: dict[str, str] = {}
            if receipt_service.mode == "mock":
                mock_token = receipt_service.build_mock_payment_token(verification_payload)
                error_detail += f" Use this demo token: {mock_token}"
                headers["x-mock-payment-token"] = mock_token
            raise HTTPException(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                detail=error_detail,
                headers=headers,
            )
        logger.info(f"x402 verified: {x_solana_tx_signature[:15]}...")

    # ── Policy rule checks ───────────────────────────────────────────
    if rules.allowed_http_methods and method not in [
        m.upper() for m in rules.allowed_http_methods
    ]:
        violation = SafetyViolation(
            category="method_not_allowed",
            severity="medium",
            explanation=f"HTTP method {method} is not allowed by this policy.",
        )
    elif rules.trusted_origins and payload.origin_service not in rules.trusted_origins:
        violation = SafetyViolation(
            category="origin_not_trusted",
            severity="high",
            explanation="This origin service is not trusted to request cross-agent execution under the policy.",
        )
    elif not payload.action.target_service and (
        rules.requires_proof_for_external_execution or rules.trusted_executors
    ):
        violation = SafetyViolation(
            category="proof_target_missing",
            severity="medium",
            explanation="A target service is required when the policy issues external execution proofs.",
        )
    elif rules.trusted_executors and payload.action.target_service not in rules.trusted_executors:
        violation = SafetyViolation(
            category="executor_not_trusted",
            severity="high",
            explanation="This target service is not trusted to execute actions under the policy.",
        )
    elif rules.max_spend_usd is not None:
        total_spend = store.get_total_spend_usd(payload.policy_id)
        projected_spend = total_spend + (payload.action.amount_usd or 0)
        
        budget_waived = False
        if payload.agent_wallet and payload.action.amount_usd is not None:
            if store.consume_approved_exception(payload.policy_id, payload.agent_wallet, payload.action.amount_usd):
                budget_waived = True
                logger.info(f"Budget exception consumed for wallet {payload.agent_wallet}; waiving limit.")

        if not budget_waived and projected_spend > rules.max_spend_usd:
            if payload.agent_wallet and payload.action.amount_usd is not None:
                store.create_budget_exception(payload.policy_id, payload.agent_wallet, payload.action.amount_usd)
            
            violation = SafetyViolation(
                category="spend_limit_exceeded",
                severity="high",
                explanation=f"The proposed action (${payload.action.amount_usd or 0:.2f}) would exceed the policy's remaining budget of ${max(0, rules.max_spend_usd - total_spend):.2f}.",
            )
    elif (
        rules.requires_human_approval_for_delete
        and method == "DELETE"
        and not payload.action.requires_human_approval
    ):
        violation = SafetyViolation(
            category="human_approval_required",
            severity="high",
            explanation="This delete action requires explicit human approval.",
        )

    allowed = violation is None

    if allowed:
        logger.info(f"Action '{payload.action.type}' allowed. Anchoring to Solana...")
    else:
        logger.warning(f"Action blocked: {violation.explanation}")

    receipt = receipt_service.anchor({**verification_payload, "allowed": allowed})
    receipt_status = ReceiptStatus(receipt.status)

    proof: AuthorizationProof | None = None
    if allowed and (rules.requires_proof_for_external_execution or payload.action.target_service):
        proof_id = new_id("prf")
        proof_claims = receipt_service.build_authorization_proof({
            "proof_id": proof_id,
            "schema_version": "sentinel-proof/v1",
            "policy_id": payload.policy_id,
            "policy_hash": policy.policy_hash,
            "action_hash": action_hash,
            "requester": payload.requester,
            "agent_wallet": payload.agent_wallet,
            "origin_service": payload.origin_service,
            "target_service": payload.action.target_service,
            "receipt_signature": receipt.signature,
            "issued_at": datetime.now(timezone.utc),
            "expires_at": expires_at(rules.proof_ttl_seconds),
        })
        proof = AuthorizationProof.model_validate(proof_claims)
        store.create_proof(proof)

    decision = AuthorizationDecision(
        policy_id=payload.policy_id,
        policy_hash=policy.policy_hash,
        action_hash=action_hash,
        allowed=allowed,
        decision="allow" if allowed else "deny",
        receipt_status=receipt_status,
        receipt_signature=receipt.signature,
        proof=proof,
        violation=violation,
    )

    store.append_audit(AuditRecord(
        policy_id=payload.policy_id,
        request_id=decision.request_id,
        status=AuditStatus.allowed if allowed else AuditStatus.blocked,
        requester=payload.requester,
        origin_service=payload.origin_service,
        target_service=payload.action.target_service,
        agent_wallet=payload.agent_wallet,
        action_type=payload.action.type,
        http_method=method,
        resource=payload.action.resource,
        amount_usd=payload.action.amount_usd,
        reasoning_trace=payload.reasoning_trace,
        action_hash=action_hash,
        policy_hash=policy.policy_hash,
        proof_id=proof.proof_id if proof else None,
        receipt_status=decision.receipt_status,
        receipt_signature=decision.receipt_signature,
        violation=violation,
    ))

    if not allowed:
        raise error_response(
            status_code=status.HTTP_403_FORBIDDEN,
            code={
                "method_not_allowed": "POLICY_ACTION_NOT_ALLOWED",
                "spend_limit_exceeded": "POLICY_LIMIT_EXCEEDED",
                "human_approval_required": "POLICY_REQUIRES_HUMAN_APPROVAL",
                "origin_not_trusted": "POLICY_ORIGIN_NOT_TRUSTED",
                "executor_not_trusted": "POLICY_EXECUTOR_NOT_TRUSTED",
                "proof_target_missing": "POLICY_PROOF_TARGET_REQUIRED",
            }[violation.category],
            message=violation.explanation,
            request_id=decision.request_id,
            policy_id=payload.policy_id,
            details={
                "action_type": payload.action.type,
                "resource": payload.action.resource,
                "action_hash": action_hash,
                "receipt_status": decision.receipt_status.value,
                "receipt_signature": decision.receipt_signature,
                "safety_violation": violation.model_dump(),
            },
        )

    return decision


@app.post("/v1/agent/intent", dependencies=[Depends(verify_api_key)])
def generate_agent_intent(payload: AgentIntentRequest):
    try:
        import google.generativeai as genai
        from dotenv import dotenv_values
    except ImportError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Gemini dependencies are not installed on this server.",
        ) from exc

    env_path = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")), ".env.local")
    logger.info(f"Loading dot env from {env_path}")
    env = dotenv_values(env_path)
    logger.info(f"Loaded config: {env}") # this is unsafe to log in production if the .env contains secrets, but it's useful for debugging missing config issues in this demo

    gemini_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("Gemini_API_Key") or env.get("GEMINI_API_KEY") or env.get("Gemini_API_Key")
    
    if not gemini_key:
        raise HTTPException(status_code=500, detail=f"Gemini API Key is missing. Path: {env_path}. Loaded: {env}. OS env: {os.environ.get('GEMINI_API_KEY')}")
        
    genai.configure(api_key=gemini_key)
    
    system_prompt = """
You are an autonomous financial AI agent. 
Before you act, you MUST request authorization from the Sentinel-Auth API. 
Return ONLY a valid JSON object matching this schema, with no markdown formatting:
{
  "policy_id": "The active policy ID provided in the prompt",
  "requester": "agent://gemini_financial_bot",
  "action": {
    "type": "wire_transfer",
    "http_method": "POST",
    "resource": "/wallets/treasury",
    "amount_usd": <estimated cost as a number>
  },
  "reasoning_trace": "A detailed explanation of WHY you are doing this."
}
"""
    
    try:
        model = genai.GenerativeModel("gemini-2.5-flash", system_instruction=system_prompt)
        response = model.generate_content(
            f"Active Policy: {payload.policy_id}\nCommand: {payload.human_command}",
            generation_config=genai.GenerationConfig(response_mime_type="application/json")
        )
        return json.loads(response.text)
    except Exception as e:
        logger.exception("Failed to generate Agent Intent via Gemini")
        raise HTTPException(status_code=500, detail=f"Gemini generation failed: {str(e)}")


@app.post("/v1/proofs/verify", dependencies=[Depends(verify_api_key)])
def verify_proof(payload: VerifyProofRequest, db: Session = Depends(get_db)):
    store = DatabaseStore(db)
    stored_proof = store.get_proof(payload.proof.proof_id)
    if not stored_proof:
        raise error_response(
            status_code=status.HTTP_404_NOT_FOUND,
            code="PROOF_NOT_FOUND",
            message="The requested authorization proof does not exist.",
            policy_id=payload.proof.policy_id,
        )

    def _stable(p) -> dict:
        return {
            "proof_id": p.proof_id,
            "schema_version": p.schema_version,
            "policy_id": p.policy_id,
            "policy_hash": p.policy_hash,
            "action_hash": p.action_hash,
            "requester": p.requester,
            "agent_wallet": p.agent_wallet,
            "origin_service": p.origin_service,
            "target_service": p.target_service,
            "issuer": p.issuer,
            "receipt_signature": p.receipt_signature,
            "signature": p.signature,
        }

    if _stable(stored_proof) != _stable(payload.proof):
        raise error_response(
            status_code=status.HTTP_409_CONFLICT,
            code="PROOF_MISMATCH",
            message="The provided authorization proof does not match the stored record.",
            policy_id=payload.proof.policy_id,
        )

    action_hash = receipt_service.action_hash({
        "policy_id": payload.proof.policy_id,
        "policy_hash": payload.proof.policy_hash,
        "origin_service": payload.proof.origin_service,
        "agent_wallet": payload.proof.agent_wallet,
        "action": payload.action.model_dump(),
    })

    if payload.verifier != payload.proof.target_service:
        return VerifyProofResult(
            valid=False, reason="verifier_not_authorized",
            policy_id=payload.proof.policy_id, policy_hash=payload.proof.policy_hash,
            action_hash=action_hash, verifier=payload.verifier,
            proof_id=payload.proof.proof_id, expires_at=payload.proof.expires_at,
            receipt_signature=payload.proof.receipt_signature,
        )

    if action_hash != payload.proof.action_hash:
        return VerifyProofResult(
            valid=False, reason="action_mismatch",
            policy_id=payload.proof.policy_id, policy_hash=payload.proof.policy_hash,
            action_hash=action_hash, verifier=payload.verifier,
            proof_id=payload.proof.proof_id, expires_at=payload.proof.expires_at,
            receipt_signature=payload.proof.receipt_signature,
        )

    proof_expires_at = payload.proof.expires_at
    if proof_expires_at.tzinfo is None:
        proof_expires_at = proof_expires_at.replace(tzinfo=timezone.utc)

    if proof_expires_at <= datetime.now(timezone.utc):
        return VerifyProofResult(
            valid=False, reason="proof_expired",
            policy_id=payload.proof.policy_id, policy_hash=payload.proof.policy_hash,
            action_hash=action_hash, verifier=payload.verifier,
            proof_id=payload.proof.proof_id, expires_at=proof_expires_at,
            receipt_signature=payload.proof.receipt_signature,
        )

    # Explicitly strip `signature` before re-deriving it for verification
    unsigned = {k: v for k, v in payload.proof.model_dump().items() if k != "signature"}
    if not receipt_service.verify_authorization_proof(unsigned, payload.proof.signature):
        return VerifyProofResult(
            valid=False, reason="invalid_signature",
            policy_id=payload.proof.policy_id, policy_hash=payload.proof.policy_hash,
            action_hash=action_hash, verifier=payload.verifier,
            proof_id=payload.proof.proof_id, expires_at=proof_expires_at,
            receipt_signature=payload.proof.receipt_signature,
        )

    return VerifyProofResult(
        valid=True, reason="verified",
        policy_id=payload.proof.policy_id, policy_hash=payload.proof.policy_hash,
        action_hash=action_hash, verifier=payload.verifier,
        proof_id=payload.proof.proof_id, expires_at=proof_expires_at,
        receipt_signature=payload.proof.receipt_signature,
    )


@app.get("/v1/audits/{policy_id}", dependencies=[Depends(verify_api_key)])
def list_audits(
    policy_id: str,
    status_filter: str | None = Query(default=None, alias="status"),
    created_after: datetime | None = Query(default=None),
    db: Session = Depends(get_db),
):
    store = DatabaseStore(db)
    if not store.get_policy(policy_id):
        raise error_response(
            status_code=status.HTTP_404_NOT_FOUND,
            code="POLICY_NOT_FOUND",
            message="The requested policy does not exist.",
            policy_id=policy_id,
        )
    audits = store.list_audits(policy_id, status_filter, created_after)
    # Enrich each audit with a Solana Explorer URL derived from receipt_signature
    audit_dicts = []
    for audit in audits:
        d = audit.model_dump()
        if audit.receipt_signature and not audit.receipt_signature.startswith("mock_"):
            d["explorer_url"] = receipt_service.explorer_url_for_signature(audit.receipt_signature)
        else:
            d["explorer_url"] = None
        audit_dicts.append(d)
    return {
        "policy_id": policy_id,
        "data": audit_dicts,
    }


@app.get("/v1/audits/{policy_id}/stats", dependencies=[Depends(verify_api_key)], response_model=AuditStatsResponse)
def get_audit_stats(
    policy_id: str,
    db: Session = Depends(get_db),
):
    store = DatabaseStore(db)
    policy = store.get_policy(policy_id)
    if not policy:
        raise error_response(
            status_code=status.HTTP_404_NOT_FOUND,
            code="POLICY_NOT_FOUND",
            message="The requested policy does not exist.",
            policy_id=policy_id,
        )
    return store.get_audit_stats(policy_id, policy)


# ────────────────────────────────────────────────────────────────
# Agent Identity
# ────────────────────────────────────────────────────────────────

@app.post("/v1/agents", response_model=AgentRecord, status_code=status.HTTP_201_CREATED)
def create_agent(
    payload: CreateAgentRequest,
    account: AccountRecord = Depends(verify_account_session),
    db: Session = Depends(get_db),
):
    store = DatabaseStore(db)
    return store.create_agent(payload, account_id=account.account_id)


@app.get("/v1/agents", response_model=list[AgentRecord])
def list_agents(
    account: AccountRecord = Depends(verify_account_session),
    db: Session = Depends(get_db),
):
    store = DatabaseStore(db)
    return store.list_agents_for_account(account.account_id)


@app.delete("/v1/agents/{agent_id}", status_code=status.HTTP_200_OK)
def delete_agent(
    agent_id: str,
    account: AccountRecord = Depends(verify_account_session),
    db: Session = Depends(get_db),
):
    store = DatabaseStore(db)
    deleted = store.delete_agent(agent_id, account.account_id)
    if not deleted:
        raise error_response(
            status_code=status.HTTP_404_NOT_FOUND,
            code="AGENT_NOT_FOUND",
            message="The requested agent does not exist.",
        )
    return {"status": "success", "agent_id": agent_id}


# ── Budget Exceptions ────────────────────────────────────────────────────────

@app.get("/v1/policies/{policy_id}/exceptions", response_model=list[BudgetExceptionRecord])
def list_budget_exceptions(
    policy_id: str,
    account: AccountRecord = Depends(verify_account_session),
    db: Session = Depends(get_db),
):
    store = DatabaseStore(db)
    return store.list_exceptions(policy_id)

@app.post("/v1/exceptions/{exception_id}/approve", response_model=BudgetExceptionRecord)
def approve_budget_exception(
    exception_id: str,
    account: AccountRecord = Depends(verify_account_session),
    db: Session = Depends(get_db),
):
    from src.db_models import BudgetExceptionStatus as DBBudgetExceptionStatus
    store = DatabaseStore(db)
    record = store.update_exception_status(exception_id, DBBudgetExceptionStatus.approved)
    if not record:
        raise HTTPException(status_code=404, detail="Exception request not found")
    return record

@app.post("/v1/exceptions/{exception_id}/deny", response_model=BudgetExceptionRecord)
def deny_budget_exception(
    exception_id: str,
    account: AccountRecord = Depends(verify_account_session),
    db: Session = Depends(get_db),
):
    from src.db_models import BudgetExceptionStatus as DBBudgetExceptionStatus
    store = DatabaseStore(db)
    record = store.update_exception_status(exception_id, DBBudgetExceptionStatus.denied)
    if not record:
        raise HTTPException(status_code=404, detail="Exception request not found")
    return record
