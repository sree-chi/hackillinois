from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func as sql_func
from sqlalchemy.orm import Session

from src.db_models import (
    AccountApiClientModel,
    AccountApiPricingModel,
    AccountModel,
    AccountPhoneVerificationModel,
    AccountSessionModel,
    AccountWalletLinkChallengeModel,
    AccountWalletModel,
    ApiClientModel,
    AuditRecordModel,
    AuditStatusEnum,
    AuthorizationProofModel,
    BudgetExceptionModel,
    BudgetExceptionStatus,
    PolicyModel,
    ReceiptStatusEnum,
    AgentModel,
)
from src.models import (
    AccountApiCostSummary,
    AccountApiKeySummary,
    AccountApiPricingRecord,
    AccountRecord,
    AccountSessionRecord,
    ApiClientRecord,
    AuditRecord,
    AuthorizationProof,
    BudgetExceptionRecord,
    CreateAgentRequest,
    CreatePolicyRequest,
    IssueApiKeyRequest,
    LinkedWalletRecord,
    POLICY_SCHEMA_VERSION,
    Policy,
    UpdateApiPricingRequest,
    WalletLinkChallengeRecord,
    canonical_hash,
    expires_at,
    new_id,
    CreateAgentRequest,
    AgentRecord,
)


class DatabaseStore:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create_account(
        self,
        email: str,
        password_hash: str,
        full_name: str | None,
        phone_number: str | None = None,
    ) -> AccountRecord:
        account = AccountRecord(email=email, phone_number=phone_number, full_name=full_name)
        row = AccountModel(
            account_id=account.account_id,
            email=account.email,
            phone_number=account.phone_number,
            full_name=account.full_name,
            password_hash=password_hash,
            created_at=account.created_at,
        )
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return AccountRecord.model_validate(row)

    def get_account_by_email(self, email: str) -> AccountModel | None:
        return self.db.query(AccountModel).filter(AccountModel.email == email).first()

    def get_account_by_phone(self, phone_number: str) -> AccountModel | None:
        return self.db.query(AccountModel).filter(AccountModel.phone_number == phone_number).first()

    def get_account_by_id(self, account_id: str) -> AccountRecord | None:
        row = self.db.query(AccountModel).filter(AccountModel.account_id == account_id).first()
        return AccountRecord.model_validate(row) if row else None

    def create_account_session(self, account_id: str, token_hash: str, expires_at: datetime) -> AccountSessionRecord:
        session = AccountSessionRecord(account_id=account_id, expires_at=expires_at)
        row = AccountSessionModel(
            session_id=session.session_id,
            account_id=session.account_id,
            token_hash=token_hash,
            created_at=session.created_at,
            expires_at=session.expires_at,
        )
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return AccountSessionRecord.model_validate(row)

    def get_account_session_by_hash(self, token_hash: str) -> AccountSessionModel | None:
        return self.db.query(AccountSessionModel).filter(AccountSessionModel.token_hash == token_hash).first()

    def create_phone_verification(
        self,
        account_id: str | None,
        phone_number: str,
        code_hash: str,
        full_name: str | None,
        delivery_channel: str,
        expires_at: datetime,
    ) -> AccountPhoneVerificationModel:
        row = AccountPhoneVerificationModel(
            verification_id=new_id("pvc"),
            account_id=account_id,
            phone_number=phone_number,
            code_hash=code_hash,
            full_name=full_name,
            delivery_channel=delivery_channel,
            expires_at=expires_at,
        )
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return row

    def get_latest_phone_verification(
        self,
        phone_number: str,
        account_id: str | None = None,
    ) -> AccountPhoneVerificationModel | None:
        query = self.db.query(AccountPhoneVerificationModel).filter(AccountPhoneVerificationModel.phone_number == phone_number)
        if account_id is not None:
            query = query.filter(AccountPhoneVerificationModel.account_id == account_id)
        return query.order_by(AccountPhoneVerificationModel.created_at.desc()).first()

    def consume_phone_verification(self, verification_id: str) -> None:
        row = (
            self.db.query(AccountPhoneVerificationModel)
            .filter(AccountPhoneVerificationModel.verification_id == verification_id)
            .first()
        )
        if not row:
            return
        row.consumed_at = datetime.now(timezone.utc)
        self.db.commit()

    def update_account_phone_number(self, account_id: str, phone_number: str | None) -> AccountRecord | None:
        row = self.db.query(AccountModel).filter(AccountModel.account_id == account_id).first()
        if not row:
            return None
        row.phone_number = phone_number
        self.db.commit()
        self.db.refresh(row)
        return AccountRecord.model_validate(row)

    def create_wallet_link_challenge(
        self,
        account_id: str,
        wallet_address: str,
        provider: str,
        nonce: str,
        message: str,
        ttl_seconds: int,
    ) -> WalletLinkChallengeRecord:
        challenge = WalletLinkChallengeRecord(
            account_id=account_id,
            wallet_address=wallet_address,
            provider=provider,
            nonce=nonce,
            message=message,
            expires_at=expires_at(ttl_seconds),
        )
        row = AccountWalletLinkChallengeModel(
            challenge_id=challenge.challenge_id,
            account_id=challenge.account_id,
            wallet_address=challenge.wallet_address,
            provider=challenge.provider,
            nonce=challenge.nonce,
            message=challenge.message,
            created_at=challenge.created_at,
            expires_at=challenge.expires_at,
            used_at=challenge.used_at,
        )
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return WalletLinkChallengeRecord.model_validate(row)

    def get_wallet_link_challenge(self, account_id: str, wallet_address: str, nonce: str) -> WalletLinkChallengeRecord | None:
        row = (
            self.db.query(AccountWalletLinkChallengeModel)
            .filter(
                AccountWalletLinkChallengeModel.account_id == account_id,
                AccountWalletLinkChallengeModel.wallet_address == wallet_address,
                AccountWalletLinkChallengeModel.nonce == nonce,
            )
            .first()
        )
        return WalletLinkChallengeRecord.model_validate(row) if row else None

    def mark_wallet_link_challenge_used(self, challenge_id: str) -> None:
        row = (
            self.db.query(AccountWalletLinkChallengeModel)
            .filter(AccountWalletLinkChallengeModel.challenge_id == challenge_id)
            .first()
        )
        if not row:
            return
        row.used_at = datetime.now(timezone.utc)
        self.db.commit()

    def get_account_wallet_by_address(self, wallet_address: str) -> LinkedWalletRecord | None:
        row = (
            self.db.query(AccountWalletModel)
            .filter(AccountWalletModel.wallet_address == wallet_address)
            .first()
        )
        return LinkedWalletRecord.model_validate(row) if row else None

    def link_account_wallet(self, account_id: str, wallet_address: str, provider: str) -> LinkedWalletRecord:
        row = (
            self.db.query(AccountWalletModel)
            .filter(AccountWalletModel.wallet_address == wallet_address)
            .first()
        )
        if row:
            if row.account_id != account_id:
                raise ValueError("Wallet already linked to another account.")
            return LinkedWalletRecord.model_validate(row)

        wallet = LinkedWalletRecord(
            account_id=account_id,
            wallet_address=wallet_address,
            provider=provider,
        )
        row = AccountWalletModel(
            wallet_id=wallet.wallet_id,
            account_id=wallet.account_id,
            wallet_address=wallet.wallet_address,
            provider=wallet.provider,
            connected_at=wallet.connected_at,
        )
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return LinkedWalletRecord.model_validate(row)

    def list_wallets_for_account(self, account_id: str) -> list[LinkedWalletRecord]:
        rows = (
            self.db.query(AccountWalletModel)
            .filter(AccountWalletModel.account_id == account_id)
            .order_by(AccountWalletModel.connected_at.desc())
            .all()
        )
        return [LinkedWalletRecord.model_validate(row) for row in rows]

    def get_wallet_for_account(self, account_id: str, wallet_address: str) -> LinkedWalletRecord | None:
        row = (
            self.db.query(AccountWalletModel)
            .filter(
                AccountWalletModel.account_id == account_id,
                AccountWalletModel.wallet_address == wallet_address,
            )
            .first()
        )
        return LinkedWalletRecord.model_validate(row) if row else None

    def unlink_wallet_for_account(self, account_id: str, wallet_address: str) -> bool:
        row = (
            self.db.query(AccountWalletModel)
            .filter(
                AccountWalletModel.account_id == account_id,
                AccountWalletModel.wallet_address == wallet_address,
            )
            .first()
        )
        if not row:
            return False
        self.db.delete(row)
        self.db.commit()
        return True

    def create_api_client(
        self,
        payload: IssueApiKeyRequest,
        api_key_hash: str,
        api_key_prefix: str,
        account_id: str | None = None,
        owner_email: str | None = None,
    ) -> ApiClientRecord:
        client = ApiClientRecord(
            app_name=payload.app_name,
            owner_name=payload.owner_name,
            owner_email=owner_email or "",
            use_case=payload.use_case,
            api_key_prefix=api_key_prefix,
        )

        row = ApiClientModel(
            client_id=client.client_id,
            app_name=client.app_name,
            owner_name=client.owner_name,
            owner_email=client.owner_email,
            use_case=client.use_case,
            api_key_hash=api_key_hash,
            api_key_prefix=client.api_key_prefix,
            wallet_address=payload.wallet_address,
            wallet_label=payload.wallet_label,
            created_at=client.created_at,
        )
        self.db.add(row)

        if account_id:
            link = AccountApiClientModel(
                id=new_id("acl"),
                account_id=account_id,
                client_id=client.client_id,
                created_at=client.created_at,
            )
            self.db.add(link)

        self.db.commit()
        self.db.refresh(row)
        return ApiClientRecord.model_validate(row)

    def get_api_client_for_account(self, account_id: str, client_id: str) -> ApiClientModel | None:
        return (
            self.db.query(ApiClientModel)
            .join(AccountApiClientModel, AccountApiClientModel.client_id == ApiClientModel.client_id)
            .filter(
                AccountApiClientModel.account_id == account_id,
                ApiClientModel.client_id == client_id,
            )
            .first()
        )

    def get_api_pricing_for_account(self, account_id: str, client_id: str) -> AccountApiPricingRecord | None:
        row = (
            self.db.query(AccountApiPricingModel)
            .filter(
                AccountApiPricingModel.account_id == account_id,
                AccountApiPricingModel.client_id == client_id,
            )
            .first()
        )
        return AccountApiPricingRecord.model_validate(row) if row else None

    def upsert_api_pricing_for_account(
        self,
        account_id: str,
        client_id: str,
        payload: UpdateApiPricingRequest,
    ) -> AccountApiPricingRecord | None:
        client = self.get_api_client_for_account(account_id, client_id)
        if not client:
            return None

        row = (
            self.db.query(AccountApiPricingModel)
            .filter(
                AccountApiPricingModel.account_id == account_id,
                AccountApiPricingModel.client_id == client_id,
            )
            .first()
        )
        if not row:
            row = AccountApiPricingModel(
                pricing_id=new_id("prc"),
                account_id=account_id,
                client_id=client_id,
            )
            self.db.add(row)

        row.provider_name = payload.provider_name.strip()
        row.api_name = payload.api_name.strip()
        row.price_per_call_usd = payload.price_per_call_usd
        row.monthly_budget_usd = payload.monthly_budget_usd
        row.sol_usd_rate = payload.sol_usd_rate
        row.billing_notes = payload.billing_notes.strip() if payload.billing_notes else None

        self.db.commit()
        self.db.refresh(row)
        return AccountApiPricingRecord.model_validate(row)

    def _build_api_cost_summary(
        self,
        client: ApiClientModel,
        pricing: AccountApiPricingRecord | None,
        usage_by_wallet: dict[str, dict[str, float]],
    ) -> AccountApiCostSummary:
        usage = usage_by_wallet.get(client.wallet_address or "", {})
        total_allowed_requests = int(usage.get("total_allowed_requests", 0))
        actual_tracked_spend_usd = round(float(usage.get("actual_tracked_spend_usd", 0.0)), 4)
        estimated_running_cost_usd = 0.0
        estimated_running_cost_sol = None
        monthly_budget_usd = None
        remaining_budget_usd = None
        over_budget = False

        if pricing:
            estimated_running_cost_usd = round(total_allowed_requests * pricing.price_per_call_usd, 4)
            monthly_budget_usd = pricing.monthly_budget_usd
            if monthly_budget_usd is not None:
                remaining_budget_usd = round(monthly_budget_usd - estimated_running_cost_usd, 4)
                over_budget = estimated_running_cost_usd > monthly_budget_usd
            if pricing.sol_usd_rate:
                estimated_running_cost_sol = round(estimated_running_cost_usd / pricing.sol_usd_rate, 8)

        return AccountApiCostSummary(
            client_id=client.client_id,
            attributed_wallet=client.wallet_address,
            total_allowed_requests=total_allowed_requests,
            actual_tracked_spend_usd=actual_tracked_spend_usd,
            estimated_running_cost_usd=estimated_running_cost_usd,
            estimated_running_cost_sol=estimated_running_cost_sol,
            monthly_budget_usd=monthly_budget_usd,
            remaining_budget_usd=remaining_budget_usd,
            over_budget=over_budget,
        )

    def list_api_clients_for_account(self, account_id: str) -> list[AccountApiKeySummary]:
        rows = (
            self.db.query(ApiClientModel)
            .join(AccountApiClientModel, AccountApiClientModel.client_id == ApiClientModel.client_id)
            .filter(AccountApiClientModel.account_id == account_id)
            .order_by(ApiClientModel.created_at.desc())
            .all()
        )
        pricing_rows = (
            self.db.query(AccountApiPricingModel)
            .filter(AccountApiPricingModel.account_id == account_id)
            .all()
        )
        pricing_by_client = {
            row.client_id: AccountApiPricingRecord.model_validate(row)
            for row in pricing_rows
        }
        usage_rows = (
            self.db.query(
                AuditRecordModel.agent_wallet,
                sql_func.count(AuditRecordModel.id),
                sql_func.sum(AuditRecordModel.amount_usd),
            )
            .filter(
                AuditRecordModel.status == AuditStatusEnum.allowed,
                AuditRecordModel.agent_wallet.isnot(None),
            )
            .group_by(AuditRecordModel.agent_wallet)
            .all()
        )
        usage_by_wallet = {
            (wallet or ""): {
                "total_allowed_requests": count or 0,
                "actual_tracked_spend_usd": float(total_spend) if total_spend else 0.0,
            }
            for wallet, count, total_spend in usage_rows
        }
        return [
            AccountApiKeySummary(
                client_id=row.client_id,
                app_name=row.app_name,
                owner_email=row.owner_email,
                api_key_prefix=row.api_key_prefix,
                wallet_address=row.wallet_address,
                wallet_label=row.wallet_label,
                created_at=row.created_at,
                last_used_at=row.last_used_at,
                suspended_at=row.suspended_at,
                revoked_at=row.revoked_at,
                pricing=pricing_by_client.get(row.client_id),
                cost_summary=self._build_api_cost_summary(
                    row,
                    pricing_by_client.get(row.client_id),
                    usage_by_wallet,
                ),
            )
            for row in rows
        ]

    def get_api_client_by_hash(self, api_key_hash: str) -> ApiClientRecord | None:
        row = self.db.query(ApiClientModel).filter(ApiClientModel.api_key_hash == api_key_hash).first()
        return ApiClientRecord.model_validate(row) if row else None

    def get_api_client_by_id(self, client_id: str) -> ApiClientRecord | None:
        row = self.db.query(ApiClientModel).filter(ApiClientModel.client_id == client_id).first()
        return ApiClientRecord.model_validate(row) if row else None

    def mark_api_client_used(self, client_id: str) -> None:
        row = self.db.query(ApiClientModel).filter(ApiClientModel.client_id == client_id).first()
        if not row:
            return
        row.last_used_at = datetime.now(timezone.utc)
        self.db.commit()

    def rotate_api_client_key(
        self,
        account_id: str,
        client_id: str,
        new_api_key_hash: str,
        new_api_key_prefix: str,
    ) -> ApiClientRecord | None:
        """Replace the key hash/prefix for an active, non-revoked client owned by account_id."""
        row = (
            self.db.query(ApiClientModel)
            .join(AccountApiClientModel, AccountApiClientModel.client_id == ApiClientModel.client_id)
            .filter(
                AccountApiClientModel.account_id == account_id,
                ApiClientModel.client_id == client_id,
                ApiClientModel.revoked_at.is_(None),
            )
            .first()
        )
        if not row:
            return None
        row.api_key_hash = new_api_key_hash
        row.api_key_prefix = new_api_key_prefix
        row.suspended_at = None  # restore if previously suspended
        self.db.commit()
        self.db.refresh(row)
        return ApiClientRecord.model_validate(row)

    def revoke_api_client_for_account(self, account_id: str, client_id: str) -> ApiClientRecord | None:
        row = (
            self.db.query(ApiClientModel)
            .join(AccountApiClientModel, AccountApiClientModel.client_id == ApiClientModel.client_id)
            .filter(
                AccountApiClientModel.account_id == account_id,
                ApiClientModel.client_id == client_id,
            )
            .first()
        )
        if not row:
            return None
        if row.revoked_at is None:
            row.revoked_at = datetime.now(timezone.utc)
            row.suspended_at = row.suspended_at or row.revoked_at
            self.db.commit()
            self.db.refresh(row)
        return ApiClientRecord.model_validate(row)

    def suspend_api_client_for_account(self, account_id: str, client_id: str) -> ApiClientRecord | None:
        row = (
            self.db.query(ApiClientModel)
            .join(AccountApiClientModel, AccountApiClientModel.client_id == ApiClientModel.client_id)
            .filter(
                AccountApiClientModel.account_id == account_id,
                ApiClientModel.client_id == client_id,
            )
            .first()
        )
        if not row or row.revoked_at is not None:
            return None
        if row.suspended_at is None:
            row.suspended_at = datetime.now(timezone.utc)
            self.db.commit()
            self.db.refresh(row)
        return ApiClientRecord.model_validate(row)

    def restore_api_client_for_account(self, account_id: str, client_id: str) -> ApiClientRecord | None:
        row = (
            self.db.query(ApiClientModel)
            .join(AccountApiClientModel, AccountApiClientModel.client_id == ApiClientModel.client_id)
            .filter(
                AccountApiClientModel.account_id == account_id,
                ApiClientModel.client_id == client_id,
            )
            .first()
        )
        if not row or row.revoked_at is not None:
            return None
        if row.suspended_at is not None:
            row.suspended_at = None
            self.db.commit()
            self.db.refresh(row)
        return ApiClientRecord.model_validate(row)

    def create_policy(self, payload: CreatePolicyRequest, idempotency_key: str | None) -> Policy:
        if idempotency_key:
            existing = self.db.query(PolicyModel).filter(PolicyModel.idempotency_key == idempotency_key).first()
            if existing:
                return Policy.model_validate({
                    "id": existing.id,
                    "name": existing.name,
                    "description": existing.description,
                    "policy_schema_version": getattr(existing, "policy_schema_version", POLICY_SCHEMA_VERSION),
                    "policy_hash": existing.policy_hash,
                    "rules": existing.rules,
                    "risk_categories": getattr(existing, "risk_categories", []) or [],
                    "budget_config": getattr(existing, "budget_config", {}) or {},
                    "required_approvers": getattr(existing, "required_approvers", []) or [],
                    "created_at": existing.created_at,
                })

        payload_data = payload.model_dump()
        policy_hash = canonical_hash(payload.canonical_hash_payload())
        policy = Policy(**payload_data, policy_hash=policy_hash)

        row = PolicyModel(
            id=policy.id,
            name=policy.name,
            description=policy.description,
            policy_schema_version=policy.policy_schema_version,
            policy_hash=policy.policy_hash,
            rules=policy.rules.model_dump(),
            risk_categories=policy.risk_categories,
            budget_config=policy.budget_config.model_dump(exclude_none=False),
            required_approvers=policy.required_approvers,
            created_at=policy.created_at,
            idempotency_key=idempotency_key,
        )
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return policy

    def update_policy(self, policy_id: str, payload) -> Policy | None:
        current_row = self.db.query(PolicyModel).filter(PolicyModel.id == policy_id).first()
        if not current_row:
            return None

        new_name = payload.name if payload.name is not None else current_row.name
        new_description = payload.description if payload.description is not None else current_row.description
        new_rules = payload.rules.model_dump() if payload.rules is not None else current_row.rules
        new_risk_categories = payload.risk_categories if payload.risk_categories is not None else (getattr(current_row, "risk_categories", []) or [])
        new_budget_config = (
            payload.budget_config.model_dump(exclude_none=False)
            if payload.budget_config is not None
            else (getattr(current_row, "budget_config", {}) or {})
        )
        new_required_approvers = (
            payload.required_approvers
            if payload.required_approvers is not None
            else (getattr(current_row, "required_approvers", []) or [])
        )

        from src.models import BudgetConfig, PolicyRule

        rules_obj = PolicyRule.model_validate(new_rules)
        policy_payload = CreatePolicyRequest(
            name=new_name,
            description=new_description,
            rules=rules_obj,
            risk_categories=new_risk_categories,
            budget_config=BudgetConfig.model_validate(new_budget_config),
            required_approvers=new_required_approvers,
        )
        policy_hash = canonical_hash(policy_payload.canonical_hash_payload())
        policy = Policy(**policy_payload.model_dump(), policy_hash=policy_hash)

        row = PolicyModel(
            id=policy.id,
            name=policy.name,
            description=policy.description,
            policy_schema_version=policy.policy_schema_version,
            policy_hash=policy.policy_hash,
            rules=policy.rules.model_dump(),
            risk_categories=policy.risk_categories,
            budget_config=policy.budget_config.model_dump(exclude_none=False),
            required_approvers=policy.required_approvers,
            created_at=policy.created_at,
        )
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return policy

    def list_policies(self, limit: int = 50, offset: int = 0) -> list[Policy]:
        """Return only the latest version of each policy lineage."""
        from sqlalchemy import func
        # Subquery: for each root (or standalone) policy, find max version
        subq = (
            self.db.query(
                func.coalesce(PolicyModel.root_policy_id, PolicyModel.id).label("root"),
                func.max(PolicyModel.version).label("max_version"),
            )
            .group_by(func.coalesce(PolicyModel.root_policy_id, PolicyModel.id))
            .subquery()
        )
        rows = (
            self.db.query(PolicyModel)
            .join(
                subq,
                (func.coalesce(PolicyModel.root_policy_id, PolicyModel.id) == subq.c.root)
                & (PolicyModel.version == subq.c.max_version),
            )
            .order_by(PolicyModel.created_at.desc())
            .limit(limit)
            .offset(offset)
            .all()
        )
        return [
            Policy.model_validate({
                "id": row.id,
                "name": row.name,
                "description": row.description,
                "policy_hash": row.policy_hash,
                "rules": row.rules,
                "version": row.version,
                "root_policy_id": row.root_policy_id,
                "created_at": row.created_at,
            })
            for row in rows
        ]

    def list_policy_versions(self, policy_id: str) -> list[Policy]:
        """Return all versions for the lineage containing policy_id."""
        row = self.db.query(PolicyModel).filter(PolicyModel.id == policy_id).first()
        if not row:
            return []
        root_id = row.root_policy_id or row.id
        rows = (
            self.db.query(PolicyModel)
            .filter(
                (PolicyModel.root_policy_id == root_id) | (PolicyModel.id == root_id)
            )
            .order_by(PolicyModel.version.asc())
            .all()
        )
        return [
            Policy.model_validate({
                "id": r.id,
                "name": r.name,
                "description": r.description,
                "policy_hash": r.policy_hash,
                "rules": r.rules,
                "version": r.version,
                "root_policy_id": r.root_policy_id,
                "created_at": r.created_at,
            })
            for r in rows
        ]

    def get_policy(self, policy_id: str) -> Policy | None:
        row = self.db.query(PolicyModel).filter(PolicyModel.id == policy_id).first()
        if not row:
            return None
        return Policy.model_validate({
            "id": row.id,
            "name": row.name,
            "description": row.description,
            "policy_hash": row.policy_hash,
            "rules": row.rules,
            "created_at": row.created_at,
        })

    def append_audit(self, audit: AuditRecord) -> None:
        row = AuditRecordModel(
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
            created_at=audit.created_at,
        )
        self.db.add(row)
        self.db.commit()

    def create_proof(self, proof: AuthorizationProof) -> None:
        row = AuthorizationProofModel(
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
        self.db.add(row)
        self.db.commit()

    def get_proof(self, proof_id: str) -> AuthorizationProof | None:
        row = self.db.query(AuthorizationProofModel).filter(AuthorizationProofModel.proof_id == proof_id).first()
        if not row:
            return None
        return AuthorizationProof.model_validate({
            "proof_id": row.proof_id,
            "policy_id": row.policy_id,
            "policy_hash": row.policy_hash,
            "action_hash": row.action_hash,
            "requester": row.requester,
            "agent_wallet": row.agent_wallet,
            "origin_service": row.origin_service,
            "target_service": row.target_service,
            "issuer": row.issuer,
            "receipt_signature": row.receipt_signature,
            "signature": row.signature,
            "schema_version": row.schema_version,
            "issued_at": row.issued_at,
            "expires_at": row.expires_at,
        })

    def list_audits(
        self,
        policy_id: str,
        status: str | None = None,
        created_after: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditRecord]:
        query = self.db.query(AuditRecordModel).filter(AuditRecordModel.policy_id == policy_id)
        if status:
            query = query.filter(AuditRecordModel.status == AuditStatusEnum(status))
        if created_after:
            query = query.filter(AuditRecordModel.created_at >= created_after)

        rows = (
            query
            .order_by(AuditRecordModel.created_at.desc())
            .limit(limit)
            .offset(offset)
            .all()
        )
        return [
            AuditRecord.model_validate({
                "id": row.id,
                "policy_id": row.policy_id,
                "request_id": row.request_id,
                "status": row.status.value,
                "requester": row.requester,
                "origin_service": row.origin_service,
                "target_service": row.target_service,
                "agent_wallet": row.agent_wallet,
                "action_type": row.action_type,
                "http_method": row.http_method,
                "resource": row.resource,
                "amount_usd": row.amount_usd,
                "action_hash": row.action_hash,
                "policy_hash": row.policy_hash,
                "proof_id": row.proof_id,
                "receipt_status": row.receipt_status.value,
                "receipt_signature": row.receipt_signature,
                "violation": row.violation,
                "created_at": row.created_at,
            })
            for row in rows
        ]

    def count_audits(
        self,
        policy_id: str,
        status: str | None = None,
        created_after: datetime | None = None,
    ) -> int:
        query = self.db.query(AuditRecordModel).filter(AuditRecordModel.policy_id == policy_id)
        if status:
            query = query.filter(AuditRecordModel.status == AuditStatusEnum(status))
        if created_after:
            query = query.filter(AuditRecordModel.created_at >= created_after)
        return query.count()

    def get_requests_in_last_minute(self, policy_id: str) -> int:
        """Count only *allowed* requests in the last minute to avoid blocking
        legitimate callers due to prior policy-blocked attempts."""
        one_minute_ago = datetime.now(timezone.utc) - timedelta(minutes=1)
        return self.db.query(AuditRecordModel).filter(
            AuditRecordModel.policy_id == policy_id,
            AuditRecordModel.status == AuditStatusEnum.allowed,
            AuditRecordModel.created_at >= one_minute_ago,
        ).count()

    def revoke_account_session(self, session_id: str) -> bool:
        """Mark a session as revoked. Returns True if found and revoked."""
        row = (
            self.db.query(AccountSessionModel)
            .filter(AccountSessionModel.session_id == session_id)
            .first()
        )
        if not row or row.revoked_at is not None:
            return False
        row.revoked_at = datetime.now(timezone.utc)
        self.db.commit()
        return True
    def get_total_spend_usd(self, policy_id: str) -> float:
        result = self.db.query(sql_func.sum(AuditRecordModel.amount_usd)).filter(
            AuditRecordModel.policy_id == policy_id,
            AuditRecordModel.status == AuditStatusEnum.allowed,
        ).scalar()
        return float(result) if result else 0.0

    # ── Agent Identity ─────────────────────────────────────────────────────

    def create_agent(self, payload: CreateAgentRequest, account_id: str) -> AgentRecord:
        agent = AgentRecord(
            account_id=account_id,
            name=payload.name,
            wallet_address=payload.wallet_address,
            description=payload.description,
        )
        row = AgentModel(
            agent_id=agent.agent_id,
            account_id=agent.account_id,
            name=agent.name,
            wallet_address=agent.wallet_address,
            description=agent.description,
            created_at=agent.created_at,
        )
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return AgentRecord.model_validate(row)

    def list_agents_for_account(self, account_id: str) -> list[AgentRecord]:
        rows = (
            self.db.query(AgentModel)
            .filter(AgentModel.account_id == account_id)
            .order_by(AgentModel.created_at.desc())
            .all()
        )
        return [AgentRecord.model_validate(row) for row in rows]

    def get_agent_by_id(self, agent_id: str, account_id: str) -> AgentRecord | None:
        row = (
            self.db.query(AgentModel)
            .filter(AgentModel.agent_id == agent_id, AgentModel.account_id == account_id)
            .first()
        )
        return AgentRecord.model_validate(row) if row else None

    def delete_agent(self, agent_id: str, account_id: str) -> bool:
        row = (
            self.db.query(AgentModel)
            .filter(AgentModel.agent_id == agent_id, AgentModel.account_id == account_id)
            .first()
        )
        if not row:
            return False
        self.db.delete(row)
        self.db.commit()
        return True

    # ── Budget Exceptions ────────────────────────────────────────────────────

    def create_budget_exception(self, policy_id: str, agent_wallet: str, amount_usd: float) -> BudgetExceptionRecord:
        # Check if a pending or approved one already exists for this wallet & amount exactly
        existing = (
            self.db.query(BudgetExceptionModel)
            .filter(
                BudgetExceptionModel.policy_id == policy_id,
                BudgetExceptionModel.agent_wallet == agent_wallet,
                BudgetExceptionModel.amount_usd == amount_usd,
                BudgetExceptionModel.status.in_([BudgetExceptionStatus.pending, BudgetExceptionStatus.approved])
            )
            .first()
        )
        if existing:
            return BudgetExceptionRecord.model_validate(existing)

        exception_id = new_id("exc")
        model = BudgetExceptionModel(
            id=exception_id,
            policy_id=policy_id,
            agent_wallet=agent_wallet,
            amount_usd=amount_usd,
            status=BudgetExceptionStatus.pending,
        )
        self.db.add(model)
        self.db.commit()
        return BudgetExceptionRecord.model_validate(model)

    def list_exceptions(self, policy_id: str) -> list[BudgetExceptionRecord]:
        rows = (
            self.db.query(BudgetExceptionModel)
            .filter(BudgetExceptionModel.policy_id == policy_id)
            .order_by(BudgetExceptionModel.created_at.desc())
            .all()
        )
        return [BudgetExceptionRecord.model_validate(row) for row in rows]

    def update_exception_status(self, exception_id: str, status: BudgetExceptionStatus) -> BudgetExceptionRecord | None:
        row = self.db.query(BudgetExceptionModel).filter(BudgetExceptionModel.id == exception_id).first()
        if not row:
            return None
        row.status = status
        self.db.commit()
        self.db.refresh(row)
        return BudgetExceptionRecord.model_validate(row)

    def consume_approved_exception(self, policy_id: str, agent_wallet: str, amount_usd: float) -> bool:
        row = (
            self.db.query(BudgetExceptionModel)
            .filter(
                BudgetExceptionModel.policy_id == policy_id,
                BudgetExceptionModel.agent_wallet == agent_wallet,
                BudgetExceptionModel.amount_usd == amount_usd,
                BudgetExceptionModel.status == BudgetExceptionStatus.approved
            )
            .order_by(BudgetExceptionModel.created_at.asc())
            .first()
        )
        if not row:
            return False
        row.status = BudgetExceptionStatus.used
        self.db.commit()
        return True

