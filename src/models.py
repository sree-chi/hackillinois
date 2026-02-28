from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, ConfigDict


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:24]}"


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
    created_at: datetime = Field(default_factory=utc_now)


class ActionRequest(BaseModel):
    type: str = Field(min_length=1, max_length=100)
    http_method: str = Field(min_length=1, max_length=20)
    resource: str = Field(min_length=1, max_length=200)
    amount_usd: float | None = Field(default=None, ge=0)
    requires_human_approval: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuthorizeRequest(BaseModel):
    policy_id: str
    requester: str = Field(min_length=1, max_length=200)
    action: ActionRequest
    reasoning_trace: str = Field(min_length=1, max_length=5000)


class SafetyViolation(BaseModel):
    category: Literal["method_not_allowed", "spend_limit_exceeded", "human_approval_required"]
    severity: Literal["low", "medium", "high"]
    explanation: str


class ErrorEnvelope(BaseModel):
    error: dict[str, Any]


class AuthorizationDecision(BaseModel):
    request_id: str = Field(default_factory=lambda: new_id("req"))
    policy_id: str
    allowed: bool
    decision: Literal["allow", "deny"]
    receipt_status: ReceiptStatus
    receipt_signature: str | None = None
    violation: SafetyViolation | None = None
    created_at: datetime = Field(default_factory=utc_now)


class AuditRecord(BaseModel):
    id: str = Field(default_factory=lambda: new_id("aud"))
    policy_id: str
    request_id: str
    status: AuditStatus
    requester: str
    action_type: str
    http_method: str
    resource: str
    amount_usd: float | None = None
    receipt_status: ReceiptStatus
    receipt_signature: str | None = None
    violation: SafetyViolation | None = None
    created_at: datetime = Field(default_factory=utc_now)
