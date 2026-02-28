from __future__ import annotations

from collections import defaultdict

from src.models import AuditRecord, CreatePolicyRequest, Policy


class InMemoryStore:
    def __init__(self) -> None:
        self.policies: dict[str, Policy] = {}
        self.policy_idempotency_keys: dict[str, str] = {}
        self.audits_by_policy: dict[str, list[AuditRecord]] = defaultdict(list)

    def create_policy(self, payload: CreatePolicyRequest, idempotency_key: str | None) -> Policy:
        if idempotency_key and idempotency_key in self.policy_idempotency_keys:
            return self.policies[self.policy_idempotency_keys[idempotency_key]]

        policy = Policy(**payload.model_dump())
        self.policies[policy.id] = policy
        if idempotency_key:
            self.policy_idempotency_keys[idempotency_key] = policy.id
        return policy

    def get_policy(self, policy_id: str) -> Policy | None:
        return self.policies.get(policy_id)

    def append_audit(self, audit: AuditRecord) -> None:
        self.audits_by_policy[audit.policy_id].append(audit)

    def list_audits(
        self,
        policy_id: str,
        status: str | None = None,
        created_after: str | None = None,
    ) -> list[AuditRecord]:
        audits = self.audits_by_policy.get(policy_id, [])
        filtered = audits
        if status:
            filtered = [audit for audit in filtered if audit.status.value == status]
        if created_after:
            filtered = [audit for audit in filtered if audit.created_at.isoformat() >= created_after]
        return filtered


store = InMemoryStore()
