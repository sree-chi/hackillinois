from __future__ import annotations

import logging
import os
import json
import math
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import google.generativeai as genai
from dotenv import load_dotenv

env_path = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")), ".env.local")
load_dotenv(env_path)

from src.auth import api_key_prefix, generate_api_key, hash_api_key, verify_admin_key, verify_api_key
from src.database import Base, engine, get_db
from src.models import (
    AgentIntentRequest,
    AuditRecord,
    AuditStatus,
    AuthorizationProof,
    AuthorizationDecision,
    AuthorizeRequest,
    PublicApiOverview,
    CreatePolicyRequest,
    ErrorEnvelope,
    IssueApiKeyRequest,
    IssueApiKeyResponse,
    ReceiptStatus,
    SafetyViolation,
    VerifyProofRequest,
    VerifyProofResult,
    UpdatePolicyRequest,
    expires_at,
    new_id,
)
from src.solana import SolanaVerificationError, receipt_service
from src.store import DatabaseStore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("SentinelAuth")

HIGH_RISK_AMOUNT_USD = float(os.getenv("HIGH_RISK_AMOUNT_USD", "1000"))
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
ALLOWED_ORIGINS = [
    origin.strip().rstrip("/")
    for origin in os.getenv(
        "CORS_ALLOW_ORIGINS",
        "http://localhost:8000,http://127.0.0.1:8000,http://localhost:3000,http://127.0.0.1:3000"
    ).split(",")
    if origin.strip()
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    if str(engine.url) != "sqlite:///:memory:":
        Base.metadata.create_all(bind=engine)
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

@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


def resolve_public_base_url(request: Request) -> str:
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL
    return str(request.base_url).rstrip("/")


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
        ).model_dump(),
    )


def _paginate(data: list, total: int, limit: int, offset: int) -> dict:
    return {
        "data": data,
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": offset + len(data) < total,
    }


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


@app.get("/v1/public/overview", response_model=PublicApiOverview)
def public_overview(request: Request):
    base_url = resolve_public_base_url(request)
    return PublicApiOverview(
        name="Sentinel Auth API",
        status="online",
        docs_url=f"{base_url}/docs",
        key_endpoint=f"{base_url}/v1/developer/keys",
        quickstart=[
            "Create a developer key: POST /v1/developer/keys",
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


# ─────────────────────────────────────────────────────────────
# Developer key management
# ─────────────────────────────────────────────────────────────

@app.post(
    "/v1/developer/keys",
    response_model=IssueApiKeyResponse,
    status_code=status.HTTP_201_CREATED,
)
def issue_developer_key(
    payload: IssueApiKeyRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    key = generate_api_key()
    prefix = api_key_prefix(key)
    store = DatabaseStore(db)
    client = store.create_api_client(payload, api_key_hash=hash_api_key(key), api_key_prefix=prefix)
    base_url = resolve_public_base_url(request)
    return IssueApiKeyResponse(
        client_id=client.client_id,
        app_name=client.app_name,
        owner_email=client.owner_email,
        api_key=key,
        api_key_prefix=client.api_key_prefix,
        created_at=client.created_at,
        base_url=base_url,
        docs_url=f"{base_url}/docs",
        authorization_header=f"Bearer {key}",
        example_policy_name=f"{client.app_name} default policy",
    )


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
    """Issue a brand-new API key for an existing client, invalidating the old one immediately."""
    store = DatabaseStore(db)
    existing = store.get_api_client_by_id(client_id)
    if not existing:
        raise error_response(
            status_code=status.HTTP_404_NOT_FOUND,
            code="CLIENT_NOT_FOUND",
            message="The requested API client does not exist.",
        )
    if existing.revoked_at is not None:
        raise error_response(
            status_code=status.HTTP_409_CONFLICT,
            code="CLIENT_REVOKED",
            message="Cannot rotate the key of a revoked API client.",
        )

    new_key = generate_api_key()
    new_prefix = api_key_prefix(new_key)
    updated = store.rotate_api_client_key(
        client_id,
        new_api_key_hash=hash_api_key(new_key),
        new_api_key_prefix=new_prefix,
    )
    if not updated:
        raise error_response(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            code="ROTATION_FAILED",
            message="Key rotation failed unexpectedly.",
        )

    base_url = resolve_public_base_url(request)
    return IssueApiKeyResponse(
        client_id=updated.client_id,
        app_name=updated.app_name,
        owner_email=updated.owner_email,
        api_key=new_key,
        api_key_prefix=updated.api_key_prefix,
        created_at=updated.created_at,
        base_url=base_url,
        docs_url=f"{base_url}/docs",
        authorization_header=f"Bearer {new_key}",
        example_policy_name=f"{updated.app_name} default policy",
    )


@app.delete(
    "/v1/developer/keys/{client_id}",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(verify_api_key)],
)
def revoke_developer_key(client_id: str, db: Session = Depends(get_db)):
    """Soft-revoke an API key so it can no longer authenticate."""
    store = DatabaseStore(db)
    revoked = store.revoke_api_client(client_id)
    if not revoked:
        raise error_response(
            status_code=status.HTTP_404_NOT_FOUND,
            code="CLIENT_NOT_FOUND",
            message="The requested API client does not exist.",
        )
    return {
        "client_id": revoked.client_id,
        "revoked_at": revoked.revoked_at,
        "message": "API key has been revoked.",
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
    store = DatabaseStore(db)
    # Resolve to the current live version first (caller may pass root_id or any version id)
    current = store.get_policy(policy_id)
    if not current:
        raise error_response(
            status_code=status.HTTP_404_NOT_FOUND,
            code="POLICY_NOT_FOUND",
            message="The requested policy does not exist.",
            policy_id=policy_id,
        )
    if current.superseded_by is not None:
        raise error_response(
            status_code=status.HTTP_409_CONFLICT,
            code="POLICY_ALREADY_SUPERSEDED",
            message=(
                "This policy version has already been superseded. "
                f"Use the latest version: {current.superseded_by}"
            ),
            policy_id=policy_id,
            details={"latest_policy_id": current.superseded_by},
        )

    new_policy = store.update_policy(policy_id, payload)
    if not new_policy:
        raise error_response(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            code="POLICY_UPDATE_FAILED",
            message="Policy update failed unexpectedly.",
            policy_id=policy_id,
        )
    return new_policy


@app.get("/v1/policies", dependencies=[Depends(verify_api_key)])
def list_policies(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    """List the current (latest) version of every policy lineage, paginated."""
    store = DatabaseStore(db)
    policies, total = store.list_policies(limit=limit, offset=offset)
    return _paginate([p.model_dump() for p in policies], total, limit, offset)


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
    store = DatabaseStore(db)
    policy = store.get_policy(policy_id)
    if not policy:
        raise error_response(
            status_code=status.HTTP_404_NOT_FOUND,
            code="POLICY_NOT_FOUND",
            message="The requested policy does not exist.",
            policy_id=policy_id,
        )
    versions = store.list_policy_versions(policy.root_policy_id)
    return {
        "root_policy_id": policy.root_policy_id,
        "total_versions": len(versions),
        "versions": [v.model_dump() for v in versions],
    }


# Authorization


@app.post("/v1/authorize", dependencies=[Depends(verify_api_key)])
def authorize(
    payload: AuthorizeRequest,
    response: Response,
    x_solana_tx_signature: str | None = Header(default=None, alias="x-solana-tx-signature"),
    db: Session = Depends(get_db),
):
    logger.info(
        f"Authorization request — policy: {payload.policy_id}, action: {payload.action.type}"
    )
    store = DatabaseStore(db)

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
    if policy.superseded_by is not None:
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
    elif rules.max_spend_usd is not None and (payload.action.amount_usd or 0) > rules.max_spend_usd:
        violation = SafetyViolation(
            category="spend_limit_exceeded",
            severity="high",
            explanation="The proposed action exceeds the policy maximum spend limit.",
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
    action_type: str | None = Query(default=None),
    created_after: datetime | None = Query(default=None),
    sort: str = Query(default="desc", pattern="^(asc|desc)$"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
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
    audits, total = store.list_audits(
        policy_id,
        status=status_filter,
        created_after=created_after,
        action_type=action_type,
        sort=sort,  # type: ignore[arg-type]
        limit=limit,
        offset=offset,
    )
    result = _paginate([a.model_dump() for a in audits], total, limit, offset)
    result["policy_id"] = policy_id
    return result