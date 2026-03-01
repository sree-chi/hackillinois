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

class UpdatePolicyRequest(BaseModel):
    name: str | None = Field(min_length=1, max_length=100)
    description : str | None = Field(default=None, max_length=500)
    rules: PolicyRule | None = None


class IssueApiKeyRequest(BaseModel):
    app_name: str = Field(min_length=1, max_length=100)
    owner_name: str | None = Field(default=None, max_length=100)
    use_case: str | None = Field(default=None, max_length=500)


class RegisterAccountRequest(BaseModel):
    email: str = Field(min_length=3, max_length=200)
    password: str = Field(min_length=8, max_length=200)
    full_name: str | None = Field(default=None, max_length=100)


class LoginAccountRequest(BaseModel):
    email: str = Field(min_length=3, max_length=200)
    password: str = Field(min_length=8, max_length=200)


class WalletLinkChallengeRequest(BaseModel):
    wallet_address: str = Field(min_length=32, max_length=80)
    provider: str = Field(default="phantom", min_length=2, max_length=30)


class WalletLinkRequest(BaseModel):
    wallet_address: str = Field(min_length=32, max_length=80)
    provider: str = Field(default="phantom", min_length=2, max_length=30)
    nonce: str = Field(min_length=8, max_length=120)
    signed_message: str = Field(min_length=20, max_length=4000)
    signature: str = Field(min_length=20, max_length=4000)


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


class AgentIntentRequest(BaseModel):
    policy_id: str
    human_command: str = Field(min_length=1, max_length=5000)


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
    reasoning_trace: str | None = None
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


class ApiClientRecord(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    client_id: str = Field(default_factory=lambda: new_id("cli"))
    app_name: str
    owner_name: str | None = None
    owner_email: str
    use_case: str | None = None
    api_key_prefix: str
    created_at: datetime = Field(default_factory=utc_now)
    last_used_at: datetime | None = None
    suspended_at: datetime | None = None
    revoked_at: datetime | None = None


class IssueApiKeyResponse(BaseModel):
    client_id: str
    app_name: str
    owner_email: str
    api_key: str
    api_key_prefix: str
    created_at: datetime
    base_url: str
    docs_url: str
    authorization_header: str
    example_policy_name: str


class PublicApiOverview(BaseModel):
    name: str
    status: str
    docs_url: str
    key_endpoint: str
    quickstart: list[str]
    sample_policy_rules: dict[str, Any]


class AccountRecord(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    account_id: str = Field(default_factory=lambda: new_id("acct"))
    email: str
    full_name: str | None = None
    created_at: datetime = Field(default_factory=utc_now)


class LinkedWalletRecord(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    wallet_id: str = Field(default_factory=lambda: new_id("wal"))
    account_id: str
    wallet_address: str
    provider: str = "phantom"
    connected_at: datetime = Field(default_factory=utc_now)


class WalletLinkChallengeRecord(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    challenge_id: str = Field(default_factory=lambda: new_id("wch"))
    account_id: str
    wallet_address: str
    provider: str = "phantom"
    nonce: str
    message: str
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime
    used_at: datetime | None = None


class WalletLinkChallengeResponse(BaseModel):
    wallet_address: str
    provider: str
    nonce: str
    message: str
    expires_at: datetime


class WalletTransactionSummary(BaseModel):
    signature: str
    slot: int | None = None
    block_time: datetime | None = None
    confirmation_status: str | None = None
    success: bool = True
    memo: str | None = None
    native_change_lamports: int | None = None
    explorer_url: str | None = None


class WalletOverviewResponse(BaseModel):
    wallet: LinkedWalletRecord
    rpc_url: str
    network: str
    balance_lamports: int
    balance_sol: float
    fetched_at: datetime = Field(default_factory=utc_now)
    transactions: list[WalletTransactionSummary] = Field(default_factory=list)


class AccountSessionRecord(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    session_id: str = Field(default_factory=lambda: new_id("sess"))
    account_id: str
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime
    revoked_at: datetime | None = None


class AccountSessionResponse(BaseModel):
    account: AccountRecord
    session_token: str
    expires_at: datetime


class AccountApiKeySummary(BaseModel):
    client_id: str
    app_name: str
    owner_email: str
    api_key_prefix: str
    created_at: datetime
    last_used_at: datetime | None = None
    suspended_at: datetime | None = None
    revoked_at: datetime | None = None


class AccountDashboardResponse(BaseModel):
    account: AccountRecord
    api_keys: list[AccountApiKeySummary]
    linked_wallets: list[LinkedWalletRecord] = Field(default_factory=list)


class CreateAgentRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    wallet_address: str | None = Field(default=None, max_length=120)
    description: str | None = Field(default=None, max_length=500)


class AgentRecord(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    agent_id: str = Field(default_factory=lambda: new_id("agt"))
    account_id: str
    name: str
    wallet_address: str | None = None
    description: str | None = None
    created_at: datetime = Field(default_factory=utc_now)


class AuditStatsResponse(BaseModel):
    policy_id: str
    total_requests: int
    allowed_requests: int
    blocked_requests: int
    anchored_receipts: int
    total_spend_usd: float
    remaining_credit_usd: float | None = None
    policy_max_spend_usd: float | None = None
