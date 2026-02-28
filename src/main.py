from __future__ import annotations

from fastapi import FastAPI, Header, HTTPException, Query, Response, status, Depends

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

from src.solana import receipt_service
from sqlalchemy.orm import Session
from src.database import get_db, engine, Base
from src.store import DatabaseStore
from src.auth import verify_api_key

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Only create tables if the engine URL doesn't look like an in-memory test DB
    # Tests will handle their own setup.
    if str(engine.url) != "sqlite:///:memory:":
        Base.metadata.create_all(bind=engine)
    yield

app = FastAPI(
    title="Sentinel Auth API",
    version="0.1.0",
    description="Policy-based AI action authorization with Solana-backed safety receipts.",
    lifespan=lifespan,
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
    # The new DatabaseStore implementation currently doesn't track idempotency_keys
    # in an attribute like the in-memory one did. In a real system you would check the DB.
    # For now we'll just return it directly.
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
def authorize(payload: AuthorizeRequest, db: Session = Depends(get_db)):
    store = DatabaseStore(db)
    policy = store.get_policy(payload.policy_id)
    if not policy:
        raise error_response(
            status_code=status.HTTP_404_NOT_FOUND,
            code="POLICY_NOT_FOUND",
            message="The requested policy does not exist.",
            policy_id=payload.policy_id,
        )

    method = payload.action.http_method.upper()
    rules = policy.rules
    violation: SafetyViolation | None = None

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
    receipt = receipt_service.anchor(
        {
            "policy_id": payload.policy_id,
            "requester": payload.requester,
            "action": payload.action.model_dump(),
            "reasoning_trace": payload.reasoning_trace,
            "allowed": allowed,
        }
    )

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
    created_after: str | None = Query(default=None),
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
