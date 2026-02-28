from __future__ import annotations
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from sqlalchemy import or_

from src.models import AuditRecord, CreatePolicyRequest, Policy
from src.db_models import PolicyModel, AuditRecordModel, AuditStatusEnum, ReceiptStatusEnum


class DatabaseStore:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create_policy(self, payload: CreatePolicyRequest, idempotency_key: str | None) -> Policy:
        if idempotency_key:
            existing = self.db.query(PolicyModel).filter(PolicyModel.idempotency_key == idempotency_key).first()
            if existing:
                return Policy.model_validate({
                    "id": existing.id,
                    "name": existing.name,
                    "description": existing.description,
                    "rules": existing.rules,
                    "created_at": existing.created_at
                })

        policy_data = Policy(**payload.model_dump())
        
        db_policy = PolicyModel(
            id=policy_data.id,
            name=policy_data.name,
            description=policy_data.description,
            rules=policy_data.rules.model_dump(),
            created_at=policy_data.created_at,
            idempotency_key=idempotency_key
        )
        self.db.add(db_policy)
        self.db.commit()
        self.db.refresh(db_policy)
        
        return policy_data

    def get_policy(self, policy_id: str) -> Policy | None:
        db_policy = self.db.query(PolicyModel).filter(PolicyModel.id == policy_id).first()
        if not db_policy:
            return None
            
        return Policy.model_validate({
            "id": db_policy.id,
            "name": db_policy.name,
            "description": db_policy.description,
            "rules": db_policy.rules,
            "created_at": db_policy.created_at
        })

    def append_audit(self, audit: AuditRecord) -> None:
        db_audit = AuditRecordModel(
            id=audit.id,
            policy_id=audit.policy_id,
            request_id=audit.request_id,
            status=AuditStatusEnum(audit.status.value),
            requester=audit.requester,
            action_type=audit.action_type,
            http_method=audit.http_method,
            resource=audit.resource,
            amount_usd=audit.amount_usd,
            receipt_status=ReceiptStatusEnum(audit.receipt_status.value),
            receipt_signature=audit.receipt_signature,
            violation=audit.violation.model_dump() if audit.violation else None,
            created_at=audit.created_at
        )
        self.db.add(db_audit)
        self.db.commit()

    def list_audits(
        self,
        policy_id: str,
        status: str | None = None,
        created_after: str | None = None,
    ) -> list[AuditRecord]:
        query = self.db.query(AuditRecordModel).filter(AuditRecordModel.policy_id == policy_id)
        
        if status:
            query = query.filter(AuditRecordModel.status == AuditStatusEnum(status))
        if created_after:
            query = query.filter(AuditRecordModel.created_at >= created_after)
            
        db_audits = query.all()
        
        results = []
        for db_audit in db_audits:
            results.append(AuditRecord.model_validate({
                "id": db_audit.id,
                "policy_id": db_audit.policy_id,
                "request_id": db_audit.request_id,
                "status": db_audit.status.value,
                "requester": db_audit.requester,
                "action_type": db_audit.action_type,
                "http_method": db_audit.http_method,
                "resource": db_audit.resource,
                "amount_usd": db_audit.amount_usd,
                "receipt_status": db_audit.receipt_status.value,
                "receipt_signature": db_audit.receipt_signature,
                "violation": db_audit.violation,
                "created_at": db_audit.created_at
            }))
            
        return results

# Note: The global `store = InMemoryStore()` in main.py will need to be replaced 
# with dependency injection of DatabaseStore(db) into the route handlers.

    def get_requests_in_last_minute(self, policy_id: str) -> int:
        one_min_ago = datetime.now(timezone.utc) - timedelta(minutes=1)
        return self.db.query(AuditRecordModel).filter(
            AuditRecordModel.policy_id == policy_id,
            AuditRecordModel.created_at >= one_min_ago
        ).count()
