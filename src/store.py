from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Literal

from sqlakchemy import asc, desc
from sqlalchemy.orm import Session

from src.db_models import (
    ApiClientModel,
    AuditRecordModel,
    AuditStatusEnum,
    AuthorizationProofModel,
    PolicyModel,
    ReceiptStatusEnum,
)
from src.models import (
    ApiClientRecord,
    AuditRecord,
    AuthorizationProof,
    CreatePolicyRequest,
    IssueApiKeyRequest,
    Policy,
    PolicyVersionSummary,
    UpdatePolicyRequest,
    canonical_hash,
    new_id,
)

def _policy_from_row(row: PolicyModel) -> Policy: 
    return Policy.model_validate({
        "id": row.id,
        "name": row.name,
        "description": row.description,
        "policy_hash": row.policy_hash,
        "rules": row.rules,
        "version": row.version,
        "root_policy_id": row.root_policy_id,
        "superseded_by": row.superseded_by,
        "created_at": row.created_at,
    })


class DatabaseStore:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create_api_client(
        self,
        payload: IssueApiKeyRequest,
        api_key_hash: str,
        api_key_prefix: str,
    ) -> ApiClientRecord:
        client = ApiClientRecord(
            app_name=payload.app_name,
            owner_name=payload.owner_name,
            owner_email=payload.owner_email,
            use_case=payload.use_case,
            api_key_prefix=api_key_prefix,
        )

        db_client = ApiClientModel(
            client_id=client.client_id,
            app_name=client.app_name,
            owner_name=client.owner_name,
            owner_email=client.owner_email,
            use_case=client.use_case,
            api_key_hash=api_key_hash,
            api_key_prefix=client.api_key_prefix,
            created_at=client.created_at,
        )
        self.db.add(db_client)
        self.db.commit()
        self.db.refresh(db_client)
        return client

    def get_api_client_by_hash(self, api_key_hash: str) -> ApiClientRecord | None:
        row = (
            self.db.query(ApiClientModel)
            .filter(ApiClientModel.api_key_hash == api_key_hash)
            .first()
        )
        return ApiClientRecord.model_validate(row) if row else None
    
    def get_api_client_by_id(self, client_id: str) -> ApiClientRecord | None:
        row = (
            self.db.query(ApiClientModel)
            .filter(ApiClientModel.client_id == client_id)
            .first()
        )
        return ApiClientRecord.model_validate(row) if row else None

    def mark_api_client_used(self, client_id: str) -> None:
        row = (
            self.db.query(ApiClientModel)
            .filter(ApiClientModel.client_id == client_id)
            .first()
        )
        if row:
            row.last_used_at = datetime.now(timezone.utc)
            self.db.commit()

    def rotate_api_client_key(self, 
                              client_id: str, 
                              new_api_key_hash: str,
                              new_api_key_prefix: str) -> ApiClientRecord | None:
        row = (
            self.db.query(ApiClientModel)
            .filter(ApiClientModel.client_id == client_id)
            .first()
        )

        if not row or row.revoked_at is not None:
            return None
        row.api_key_hash = new_api_key_hash
        row.api_key_prefix = new_api_key_prefix
        row.last_used_at = None
        self.db.commit()
        self.db.refresh(row)
        return ApiClientRecord.model_validate(row)
    
    def revoke_api_client(self, client_id: str) -> ApiClientRecord | None:
        row = (
            self.db.query(ApiClientModel)
            .filter(ApiClientModel.client_id == client_id)
            .first()

        )
        if not row:
            return None
        row.revoked_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(row)
        return ApiClientRecord.model_validate(row)


    def create_policy(self, payload: CreatePolicyRequest, idempotency_key: str | None) -> Policy:
        if idempotency_key:
            existing = (
                self.db.query(PolicyModel)
                .filter(PolicyModel.idempotency_key == idempotency_key)
                .first()
            )
            if existing:
                return _policy_from_row(existing)

        payload_data = payload.model_dump()
        policy_hash = canonical_hash(payload_data)
        policy_id = new_id("pol")
        policy = Policy(
            id=policy_id,
            **payload_data,
            policy_hash=policy_hash,
            version=1,
            root_policy_id=policy_id,   # first version: root == self
        )
        db_policy = PolicyModel(
            id=policy.id,
            name=policy.name,
            description=policy.description,
            policy_hash=policy.policy_hash,
            rules=policy.rules.model_dump(),
            version=policy.version,
            root_policy_id=policy.root_policy_id,
            superseded_by=None,
            created_at=policy.created_at,
            idempotency_key=idempotency_key,
        )
        self.db.add(db_policy)
        self.db.commit()
        self.db.refresh(db_policy)
        return policy
    

    def update_policy(self, policy_id: str, payload: UpdatePolicyRequest) -> Policy | None:
        
        old_row = (
            self.db.query(PolicyModel)
            .filter(PolicyModel.id == policy_id)
            .first()
        )
        if not old_row or old_row.superseded_by is not None:
            return None

        # Merge: use existing values for any field not supplied in the request
        new_name = payload.name if payload.name is not None else old_row.name
        new_description = payload.description if payload.description is not None else old_row.description
        new_rules = payload.rules.model_dump() if payload.rules is not None else old_row.rules

        new_version = old_row.version + 1
        new_id_val = new_id("pol")
        new_hash = canonical_hash({"name": new_name, "description": new_description, "rules": new_rules})

        new_row = PolicyModel(
            id=new_id_val,
            name=new_name,
            description=new_description,
            policy_hash=new_hash,
            rules=new_rules,
            version=new_version,
            root_policy_id=old_row.root_policy_id,
            superseded_by=None,
            idempotency_key=None,
        )
        self.db.add(new_row)

        # Stamp the old version as superseded
        old_row.superseded_by = new_id_val
        self.db.commit()
        self.db.refresh(new_row)
        return _policy_from_row(new_row)
    
    def get_policy(self, policy_id: str) -> Policy | None:
        db_policy = self.db.query(PolicyModel).filter(PolicyModel.id == policy_id).first()
        if not db_policy:
            return None

        return Policy.model_validate({
            "id": db_policy.id,
            "name": db_policy.name,
            "description": db_policy.description,
            "policy_hash": db_policy.policy_hash,
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
            origin_service=audit.origin_service,
            target_service=audit.target_service,
            agent_wallet=audit.agent_wallet,
            action_type=audit.action_type,
            http_method=audit.http_method,
            resource=audit.resource,
            amount_usd=audit.amount_usd,
            action_hash=audit.action_hash,
            policy_hash=audit.policy_hash,
            proof_id=audit.proof_id,
            receipt_status=ReceiptStatusEnum(audit.receipt_status.value),
            receipt_signature=audit.receipt_signature,
            violation=audit.violation.model_dump() if audit.violation else None,
            created_at=audit.created_at
        )
        self.db.add(db_audit)
        self.db.commit()

    def create_proof(self, proof: AuthorizationProof) -> None:
        db_proof = AuthorizationProofModel(
            proof_id=proof.proof_id,
            policy_id=proof.policy_id,
            policy_hash=proof.policy_hash,
            action_hash=proof.action_hash,
            requester=proof.requester,
            agent_wallet=proof.agent_wallet,
            origin_service=proof.origin_service,
            target_service=proof.target_service,
            issuer=proof.issuer,
            receipt_signature=proof.receipt_signature,
            signature=proof.signature,
            schema_version=proof.schema_version,
            issued_at=proof.issued_at,
            expires_at=proof.expires_at,
        )
        self.db.add(db_proof)
        self.db.commit()

    def get_proof(self, proof_id: str) -> AuthorizationProof | None:
        db_proof = self.db.query(AuthorizationProofModel).filter(AuthorizationProofModel.proof_id == proof_id).first()
        if not db_proof:
            return None

        return AuthorizationProof.model_validate({
            "proof_id": db_proof.proof_id,
            "policy_id": db_proof.policy_id,
            "policy_hash": db_proof.policy_hash,
            "action_hash": db_proof.action_hash,
            "requester": db_proof.requester,
            "agent_wallet": db_proof.agent_wallet,
            "origin_service": db_proof.origin_service,
            "target_service": db_proof.target_service,
            "issuer": db_proof.issuer,
            "receipt_signature": db_proof.receipt_signature,
            "signature": db_proof.signature,
            "schema_version": db_proof.schema_version,
            "issued_at": db_proof.issued_at,
            "expires_at": db_proof.expires_at,
        })

    def list_audits(
        self,
        policy_id: str,
        status: str | None = None,
        created_after: datetime | None = None,
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
                "origin_service": db_audit.origin_service,
                "target_service": db_audit.target_service,
                "agent_wallet": db_audit.agent_wallet,
                "action_type": db_audit.action_type,
                "http_method": db_audit.http_method,
                "resource": db_audit.resource,
                "amount_usd": db_audit.amount_usd,
                "action_hash": db_audit.action_hash,
                "policy_hash": db_audit.policy_hash,
                "proof_id": db_audit.proof_id,
                "receipt_status": db_audit.receipt_status.value,
                "receipt_signature": db_audit.receipt_signature,
                "violation": db_audit.violation,
                "created_at": db_audit.created_at
            }))

        return results

    def get_requests_in_last_minute(self, policy_id: str) -> int:
        one_min_ago = datetime.now(timezone.utc) - timedelta(minutes=1)
        return self.db.query(AuditRecordModel).filter(
            AuditRecordModel.policy_id == policy_id,
            AuditRecordModel.created_at >= one_min_ago
        ).count()
