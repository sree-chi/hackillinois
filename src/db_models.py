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
    # Using JSONB if on postgres, otherwise JSON for sqlite fallback if needed, but JSON is safer cross-db
    rules = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class AuditRecordModel(Base):
    __tablename__ = "audit_records"

    id = Column(String, primary_key=True, index=True)
    policy_id = Column(String, index=True, nullable=False)
    request_id = Column(String, index=True, nullable=False)
    status = Column(Enum(AuditStatusEnum), nullable=False)
    requester = Column(String, nullable=False)
    action_type = Column(String, nullable=False)
    http_method = Column(String, nullable=False)
    resource = Column(String, nullable=False)
    amount_usd = Column(Float, nullable=True)
    receipt_status = Column(Enum(ReceiptStatusEnum), nullable=False)
    receipt_signature = Column(String, nullable=True)
    violation = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
