from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from src.auth import verify_api_key
from src.database import Base, engine, get_db
from src.models import (
    AuditRecord,
    AuditStatus,
    AuthorizationDecision,
    AuthorizeRequest,
    CreatePolicyRequest,
    ErrorEnvelope,
    ReceiptStatus,
    SafetyViolation,
)
from src.solana import SolanaVerificationError, receipt_service
from src.store import DatabaseStore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("SentinelAuth")

HIGH_RISK_AMOUNT_USD = float(os.getenv("HIGH_RISK_AMOUNT_USD", "1000"))
ALLOWED_ORIGINS = [
    origin.strip()
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
)


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


@app.post("/v1/policies", status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_api_key)])
def create_policy(
    payload: CreatePolicyRequest,
    response: Response,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    db: Session = Depends(get_db)
):
    store = DatabaseStore(db)
    policy = store.create_policy(payload, idempotency_key=idempotency_key)
    if idempotency_key:
        response.headers["Idempotency-Key"] = idempotency_key
    return policy


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


@app.post("/v1/authorize", dependencies=[Depends(verify_api_key)])
def authorize(
    payload: AuthorizeRequest,
    x_solana_tx_signature: str | None = Header(default=None, alias="x-solana-tx-signature"),
    db: Session = Depends(get_db)
):
    logger.info(f"Received authorization request for policy: {payload.policy_id}, action: {payload.action.type}")
    store = DatabaseStore(db)
    policy = store.get_policy(payload.policy_id)
    if not policy:
        logger.warning(f"Authorization denied: Policy {payload.policy_id} not found.")
        raise error_response(
            status_code=status.HTTP_404_NOT_FOUND,
            code="POLICY_NOT_FOUND",
            message="The requested policy does not exist.",
            policy_id=payload.policy_id,
        )

    if policy.rules.max_requests_per_minute is not None:
        recent_requests = store.get_requests_in_last_minute(payload.policy_id)
        logger.info(f"Rate limit check: {recent_requests}/{policy.rules.max_requests_per_minute} requests in last minute.")
        if recent_requests >= policy.rules.max_requests_per_minute:
            logger.warning(f"Authorization denied: Rate limit exceeded for {payload.policy_id}.")
            raise error_response(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                code="RATE_LIMIT_EXCEEDED",
                message="The maximum number of requests per minute for this policy has been exceeded.",
                policy_id=payload.policy_id,
            )

    method = payload.action.http_method.upper()
    rules = policy.rules
    violation: SafetyViolation | None = None
    verification_payload = {
        "policy_id": payload.policy_id,
        "requester": payload.requester,
        "action": payload.action.model_dump(),
        "reasoning_trace": payload.reasoning_trace,
    }

    is_high_risk = (payload.action.amount_usd or 0) >= HIGH_RISK_AMOUNT_USD
    if is_high_risk:
        logger.info(
            f"High-risk action detected (amount: ${payload.action.amount_usd}). Verifying x402 payment signature..."
        )
        try:
            verified = receipt_service.verify_high_risk_signature(x_solana_tx_signature, verification_payload)
        except SolanaVerificationError as exc:
            logger.exception("x402 verification failed due to Solana verification error")
            raise error_response(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                code="SOLANA_VERIFICATION_UNAVAILABLE",
                message="Unable to verify the Solana payment proof for this request.",
                policy_id=payload.policy_id,
                details={"reason": str(exc)},
            )

        if not verified:
            logger.warning("x402 verification failed for high-risk action.")
            raise HTTPException(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                detail=(
                    "High-risk actions require a verified payment token via x-solana-tx-signature. "
                    "In mock mode, use the deterministic demo token returned by the frontend."
                ),
            )

        logger.info(f"x402 verified for signature: {x_solana_tx_signature[:15]}...")

    if rules.allowed_http_methods and method not in [item.upper() for item in rules.allowed_http_methods]:
        violation = SafetyViolation(
            category="method_not_allowed",
            severity="medium",
            explanation=f"HTTP method {method} is not allowed by this policy.",
        )
    elif rules.max_spend_usd is not None and (payload.action.amount_usd or 0) > rules.max_spend_usd:
        violation = SafetyViolation(
            category="spend_limit_exceeded",
            severity="high",
            explanation="The proposed action exceeds the policy maximum spend limit.",
        )
    elif rules.requires_human_approval_for_delete and method == "DELETE" and not payload.action.requires_human_approval:
        violation = SafetyViolation(
            category="human_approval_required",
            severity="high",
            explanation="This delete action requires explicit human approval.",
        )

    allowed = violation is None

    if allowed:
        logger.info(f"Action '{payload.action.type}' complies with policy rules. Submitting intent hash to Solana receipt service...")
    else:
        logger.warning(f"Action blocked by policy rules: {violation.explanation}")

    receipt = receipt_service.anchor({**verification_payload, "allowed": allowed})

    receipt_status = ReceiptStatus(receipt.status)
    decision = AuthorizationDecision(
        policy_id=payload.policy_id,
        allowed=allowed,
        decision="allow" if allowed else "deny",
        receipt_status=receipt_status,
        receipt_signature=receipt.signature,
        violation=violation,
    )

    audit = AuditRecord(
        policy_id=payload.policy_id,
        request_id=decision.request_id,
        status=AuditStatus.allowed if allowed else AuditStatus.blocked,
        requester=payload.requester,
        action_type=payload.action.type,
        http_method=method,
        resource=payload.action.resource,
        amount_usd=payload.action.amount_usd,
        receipt_status=decision.receipt_status,
        receipt_signature=decision.receipt_signature,
        violation=violation,
    )
    store.append_audit(audit)

    if not allowed:
        raise error_response(
            status_code=status.HTTP_403_FORBIDDEN,
            code={
                "method_not_allowed": "POLICY_ACTION_NOT_ALLOWED",
                "spend_limit_exceeded": "POLICY_LIMIT_EXCEEDED",
                "human_approval_required": "POLICY_REQUIRES_HUMAN_APPROVAL",
            }[violation.category],
            message=violation.explanation,
            request_id=decision.request_id,
            policy_id=payload.policy_id,
            details={
                "action_type": payload.action.type,
                "resource": payload.action.resource,
                "receipt_status": decision.receipt_status.value,
                "receipt_signature": decision.receipt_signature,
                "safety_violation": violation.model_dump(),
            },
        )

    return decision


@app.get("/v1/audits/{policy_id}", dependencies=[Depends(verify_api_key)])
def list_audits(
    policy_id: str,
    status_filter: str | None = Query(default=None, alias="status"),
    created_after: datetime | None = Query(default=None),
    db: Session = Depends(get_db)
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
    return {
        "policy_id": policy_id,
        "data": [audit.model_dump() for audit in store.list_audits(policy_id, status_filter, created_after)],
    }
