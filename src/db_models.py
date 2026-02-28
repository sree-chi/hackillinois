
from sqlalchemy import Column, String, Float, Boolean, DateTime, Enum, JSON, Integer, Index
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func
from src.database import Base
import enum

# Define Enum types for Postgres
class AuditStatusEnum(enum.Enum):
    allowed = "allowed"
    blocked = "blocked"

class ReceiptStatusEnum(enum.Enum):
    pending = "pending"
    anchored = "anchored"
    skipped = "skipped"
    failed = "failed"

class PolicyModel(Base):
    __tablename__ = "policies"

    id = Column(String, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(String(500), nullable=True)
    policy_hash = Column(String(64), nullable=False, index=True)
    # Using JSONB if on postgres, otherwise JSON for sqlite fallback if needed, but JSON is safer cross-db
    rules = Column(JSON, nullable=False)
    version = Column(Integer, nullable=False, default=1, server_default="1")
    root_policy_id = Column(String, nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    idempotency_key = Column(String, unique=True, index=True, nullable=True)

    __table_args__ = (
        Index("ix_policies_root_version", "root_policy_id", "version"),
        Index("ix_policies_created_at", "created_at"), 
    )

class AuditRecordModel(Base):
    __tablename__ = "audit_records"

    id = Column(String, primary_key=True, index=True)
    policy_id = Column(String, index=True, nullable=False)
    request_id = Column(String, index=True, nullable=False)
    status = Column(Enum(AuditStatusEnum), nullable=False)
    requester = Column(String, nullable=False)
    origin_service = Column(String, nullable=True)
    target_service = Column(String, nullable=True)
    agent_wallet = Column(String, nullable=True)
    action_type = Column(String, nullable=False)
    http_method = Column(String, nullable=False)
    resource = Column(String, nullable=False)
    amount_usd = Column(Float, nullable=True)
    action_hash = Column(String(64), nullable=True, index=True)
    policy_hash = Column(String(64), nullable=True, index=True)
    proof_id = Column(String, nullable=True, index=True)
    receipt_status = Column(Enum(ReceiptStatusEnum), nullable=False)
    receipt_signature = Column(String, nullable=True)
    violation = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_audit_policy_created", "policy_id", "created_at"), 
        Index("ix_audit_request_created", "policy_id", "status", "created_at")
        
    )


class AuthorizationProofModel(Base):
    __tablename__ = "authorization_proofs"

    proof_id = Column(String, primary_key=True, index=True)
    policy_id = Column(String, nullable=False, index=True)
    policy_hash = Column(String(64), nullable=False, index=True)
    action_hash = Column(String(64), nullable=False, index=True)
    requester = Column(String, nullable=False)
    agent_wallet = Column(String, nullable=True)
    origin_service = Column(String, nullable=True)
    target_service = Column(String, nullable=False, index=True)
    issuer = Column(String, nullable=False)
    receipt_signature = Column(String, nullable=True)
    signature = Column(String, nullable=False)
    schema_version = Column(String, nullable=False)
    issued_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)


class ApiClientModel(Base):
    __tablename__ = "api_clients"

    client_id = Column(String, primary_key=True, index=True)
    app_name = Column(String(100), nullable=False)
    owner_name = Column(String(100), nullable=True)
    owner_email = Column(String(200), nullable=False, index=True)
    use_case = Column(String(500), nullable=True)
    api_key_hash = Column(String(64), nullable=False, unique=True, index=True)
    api_key_prefix = Column(String(24), nullable=False, unique=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    suspended_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)


class AccountModel(Base):
    __tablename__ = "accounts"

    account_id = Column(String, primary_key=True, index=True)
    email = Column(String(200), nullable=False, unique=True, index=True)
    full_name = Column(String(100), nullable=True)
    password_hash = Column(String(200), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class AccountSessionModel(Base):
    __tablename__ = "account_sessions"

    session_id = Column(String, primary_key=True, index=True)
    account_id = Column(String, nullable=False, index=True)
    token_hash = Column(String(64), nullable=False, unique=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)


class AccountWalletModel(Base):
    __tablename__ = "account_wallets"

    wallet_id = Column(String, primary_key=True, index=True)
    account_id = Column(String, nullable=False, index=True)
    wallet_address = Column(String(80), nullable=False, unique=True, index=True)
    provider = Column(String(30), nullable=False, default="phantom", server_default="phantom")
    connected_at = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_account_wallets_account_connected", "account_id", "connected_at"),
    )


class AccountWalletLinkChallengeModel(Base):
    __tablename__ = "account_wallet_link_challenges"

    challenge_id = Column(String, primary_key=True, index=True)
    account_id = Column(String, nullable=False, index=True)
    wallet_address = Column(String(80), nullable=False, index=True)
    provider = Column(String(30), nullable=False, default="phantom", server_default="phantom")
    nonce = Column(String(120), nullable=False, unique=True, index=True)
    message = Column(String(4000), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    used_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_wallet_challenges_account_wallet", "account_id", "wallet_address"),
    )


class AccountApiClientModel(Base):
    __tablename__ = "account_api_clients"

    id = Column(String, primary_key=True, index=True)
    account_id = Column(String, nullable=False, index=True)
    client_id = Column(String, nullable=False, unique=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
