from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, ConfigDict


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:24]}"


def canonical_hash(payload: dict[str, Any]) -> str:
    canonical_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()


def expires_at(seconds: int) -> datetime:
    return utc_now() + timedelta(seconds=seconds)


class AuditStatus(str, Enum):
    allowed = "allowed"
    blocked = "blocked"


class ReceiptStatus(str, Enum):
    pending = "pending"
    anchored = "anchored"
    skipped = "skipped"
    failed = "failed"


class PolicyRule(BaseModel):
    allowed_http_methods: list[str] = Field(default_factory=list)
    max_spend_usd: float | None = None
    requires_human_approval_for_delete: bool = False
    max_requests_per_minute: int | None = Field(default=None, ge=1)
    trusted_origins: list[str] = Field(default_factory=list)
    trusted_executors: list[str] = Field(default_factory=list)
    requires_proof_for_external_execution: bool = False
    proof_ttl_seconds: int = Field(default=300, ge=60, le=86400)


class CreatePolicyRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=500)
    rules: PolicyRule


class Policy(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str = Field(default_factory=lambda: new_id("pol"))
    name: str
    description: str | None = None
    rules: PolicyRule
    policy_hash: str
    created_at: datetime = Field(default_factory=utc_now)


class ActionRequest(BaseModel):
    type: str = Field(min_length=1, max_length=100)
    http_method: str = Field(min_length=1, max_length=20)
    resource: str = Field(min_length=1, max_length=200)
    amount_usd: float | None = Field(default=None, ge=0)
    requires_human_approval: bool = False
    target_service: str | None = Field(default=None, max_length=200)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuthorizeRequest(BaseModel):
    policy_id: str
    requester: str = Field(min_length=1, max_length=200)
    origin_service: str | None = Field(default=None, max_length=200)
    agent_wallet: str | None = Field(default=None, max_length=120)
    action: ActionRequest
    reasoning_trace: str = Field(min_length=1, max_length=5000)


class SafetyViolation(BaseModel):
    category: Literal[
        "method_not_allowed",
        "spend_limit_exceeded",
        "human_approval_required",
        "origin_not_trusted",
        "executor_not_trusted",
        "proof_target_missing",
    ]
    severity: Literal["low", "medium", "high"]
    explanation: str


class ErrorEnvelope(BaseModel):
    error: dict[str, Any]


class AuthorizationProof(BaseModel):
    proof_id: str = Field(default_factory=lambda: new_id("prf"))
    schema_version: str = "sentinel-proof/v1"
    policy_id: str
    policy_hash: str
    action_hash: str
    requester: str
    agent_wallet: str | None = None
    origin_service: str | None = None
    target_service: str
    issuer: str
    receipt_signature: str | None = None
    signature: str
    issued_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime


class AuthorizationDecision(BaseModel):
    request_id: str = Field(default_factory=lambda: new_id("req"))
    policy_id: str
    policy_hash: str
    action_hash: str
    allowed: bool
    decision: Literal["allow", "deny"]
    receipt_status: ReceiptStatus
    receipt_signature: str | None = None
    proof: AuthorizationProof | None = None
    violation: SafetyViolation | None = None
    created_at: datetime = Field(default_factory=utc_now)


class AuditRecord(BaseModel):
    id: str = Field(default_factory=lambda: new_id("aud"))
    policy_id: str
    request_id: str
    status: AuditStatus
    requester: str
    origin_service: str | None = None
    target_service: str | None = None
    agent_wallet: str | None = None
    action_type: str
    http_method: str
    resource: str
    amount_usd: float | None = None
    action_hash: str | None = None
    policy_hash: str | None = None
    proof_id: str | None = None
    receipt_status: ReceiptStatus
    receipt_signature: str | None = None
    violation: SafetyViolation | None = None
    created_at: datetime = Field(default_factory=utc_now)


class VerifyProofRequest(BaseModel):
    verifier: str = Field(min_length=1, max_length=200)
    action: ActionRequest
    proof: AuthorizationProof


class VerifyProofResult(BaseModel):
    valid: bool
    reason: str
    policy_id: str
    policy_hash: str
    action_hash: str
    verifier: str
    proof_id: str
    expires_at: datetime
    receipt_signature: str | None = None
