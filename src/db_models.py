from sqlalchemy import Column, String, Float, Boolean, DateTime, Enum, JSON
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
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    idempotency_key = Column(String, unique=True, index=True, nullable=True)

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
