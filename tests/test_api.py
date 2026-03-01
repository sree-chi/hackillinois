import os
import base64

import pytest
from fastapi.testclient import TestClient
from solders.keypair import Keypair
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src.database import Base, get_db
from src.main import app
from src.solana import receipt_service

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db

os.environ["SOLANA_RECEIPT_MODE"] = "mock"
receipt_service.mode = "mock"

client = TestClient(app)
Base.metadata.create_all(bind=engine)


@pytest.fixture(autouse=True)
def setup_and_teardown():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


def create_default_policy() -> str:
    response = client.post(
        "/v1/policies",
        headers={
            "Idempotency-Key": "policy-key-1",
            "Authorization": "Bearer default-dev-key"
        },
        json={
            "name": "Safe GET policy",
            "description": "Allows reads only and caps spend",
            "rules": {
                "allowed_http_methods": ["GET"],
                "max_spend_usd": 5.0,
                "requires_human_approval_for_delete": True,
            },
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


def create_account_session() -> str:
    response = client.post(
        "/v1/accounts/register",
        json={
            "email": "owner@example.com",
            "password": "strong-password-123",
            "full_name": "Portal Owner",
        },
    )
    assert response.status_code == 201
    return response.json()["session_token"]


def issue_public_key() -> str:
    session_token = create_account_session()
    response = client.post(
        "/v1/developer/keys",
        headers={"Authorization": f"Bearer {session_token}"},
        json={
            "app_name": "Portal Test App",
            "owner_name": "Portal Owner",
            "use_case": "Testing public onboarding",
        },
    )
    assert response.status_code == 201
    return response.json()["api_key"]


def test_register_account_returns_session():
    response = client.post(
        "/v1/accounts/register",
        json={
            "email": "founder@example.com",
            "password": "strong-password-123",
            "full_name": "Founder",
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert body["session_token"].startswith("ssa_live_")
    assert body["account"]["email"] == "founder@example.com"


def test_account_dashboard_lists_issued_keys():
    session_token = create_account_session()
    issue = client.post(
        "/v1/developer/keys",
        headers={"Authorization": f"Bearer {session_token}"},
        json={
            "app_name": "Public Portal App",
            "owner_name": "Portal Owner",
        },
    )
    assert issue.status_code == 201

    response = client.get(
        "/v1/accounts/me/dashboard",
        headers={"Authorization": f"Bearer {session_token}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["account"]["email"] == "owner@example.com"
    assert body["api_keys"][0]["app_name"] == "Public Portal App"
    assert body["linked_wallets"] == []


def test_account_can_revoke_its_api_key():
    session_token = create_account_session()
    issue = client.post(
        "/v1/developer/keys",
        headers={"Authorization": f"Bearer {session_token}"},
        json={
            "app_name": "Revocable App",
            "owner_name": "Portal Owner",
        },
    )
    assert issue.status_code == 201
    issued = issue.json()

    revoke = client.delete(
        f"/v1/accounts/me/keys/{issued['client_id']}",
        headers={"Authorization": f"Bearer {session_token}"},
    )
    assert revoke.status_code == 200
    assert revoke.json()["client_id"] == issued["client_id"]
    assert revoke.json()["revoked_at"] is not None

    dashboard = client.get(
        "/v1/accounts/me/dashboard",
        headers={"Authorization": f"Bearer {session_token}"},
    )
    assert dashboard.status_code == 200
    assert dashboard.json()["api_keys"][0]["revoked_at"] is not None

    denied = client.post(
        "/v1/policies",
        headers={"Authorization": f"Bearer {issued['api_key']}"},
        json={
            "name": "Should fail",
            "rules": {"allowed_http_methods": ["GET"]},
        },
    )
    assert denied.status_code == 401


def test_account_can_suspend_and_restore_api_key():
    session_token = create_account_session()
    issue = client.post(
        "/v1/developer/keys",
        headers={"Authorization": f"Bearer {session_token}"},
        json={
            "app_name": "Suspendable App",
            "owner_name": "Portal Owner",
        },
    )
    assert issue.status_code == 201
    issued = issue.json()

    suspend = client.post(
        f"/v1/accounts/me/keys/{issued['client_id']}/suspend",
        headers={"Authorization": f"Bearer {session_token}"},
    )
    assert suspend.status_code == 200
    assert suspend.json()["client_id"] == issued["client_id"]
    assert suspend.json()["suspended_at"] is not None

    dashboard_after_suspend = client.get(
        "/v1/accounts/me/dashboard",
        headers={"Authorization": f"Bearer {session_token}"},
    )
    assert dashboard_after_suspend.status_code == 200
    assert dashboard_after_suspend.json()["api_keys"][0]["suspended_at"] is not None
    assert dashboard_after_suspend.json()["api_keys"][0]["revoked_at"] is None

    denied_while_suspended = client.post(
        "/v1/policies",
        headers={"Authorization": f"Bearer {issued['api_key']}"},
        json={
            "name": "Should fail while suspended",
            "rules": {"allowed_http_methods": ["GET"]},
        },
    )
    assert denied_while_suspended.status_code == 401

    restore = client.post(
        f"/v1/accounts/me/keys/{issued['client_id']}/restore",
        headers={"Authorization": f"Bearer {session_token}"},
    )
    assert restore.status_code == 200
    assert restore.json()["client_id"] == issued["client_id"]
    assert restore.json()["suspended_at"] is None

    allowed_again = client.post(
        "/v1/policies",
        headers={"Authorization": f"Bearer {issued['api_key']}"},
        json={
            "name": "Works again",
            "rules": {"allowed_http_methods": ["GET"]},
        },
    )
    assert allowed_again.status_code == 201


def test_can_link_wallet_to_account_and_fetch_overview():
    session_token = create_account_session()
    keypair = Keypair()
    wallet_address = str(keypair.pubkey())

    challenge = client.post(
        "/v1/accounts/me/solana/challenge",
        headers={"Authorization": f"Bearer {session_token}"},
        json={
            "wallet_address": wallet_address,
            "provider": "phantom",
        },
    )
    assert challenge.status_code == 201
    challenge_body = challenge.json()
    assert challenge_body["wallet_address"] == wallet_address

    signature = keypair.sign_message(challenge_body["message"].encode("utf-8"))
    encoded_signature = base64.b64encode(bytes(signature)).decode("ascii")

    linked = client.post(
        "/v1/accounts/me/solana/link",
        headers={"Authorization": f"Bearer {session_token}"},
        json={
            "wallet_address": wallet_address,
            "provider": "phantom",
            "nonce": challenge_body["nonce"],
            "signed_message": challenge_body["message"],
            "signature": encoded_signature,
        },
    )
    assert linked.status_code == 201
    assert linked.json()["wallet_address"] == wallet_address

    original_get_wallet_overview = receipt_service.get_wallet_overview
    receipt_service.get_wallet_overview = lambda address, limit=8: {
        "rpc_url": "https://api.devnet.solana.com",
        "network": "devnet",
        "balance_lamports": 2_500_000_000,
        "balance_sol": 2.5,
        "transactions": [
            {
                "signature": "txsig123",
                "slot": 12345,
                "block_time": "2026-02-28T18:00:00Z",
                "confirmation_status": "confirmed",
                "success": True,
                "memo": "wallet linked",
                "native_change_lamports": 5000,
                "explorer_url": "https://explorer.solana.com/tx/txsig123?cluster=devnet",
            }
        ],
        "fetched_at": "2026-02-28T18:05:00Z",
    }
    try:
        dashboard = client.get(
            "/v1/accounts/me/dashboard",
            headers={"Authorization": f"Bearer {session_token}"},
        )
        assert dashboard.status_code == 200
        assert dashboard.json()["linked_wallets"][0]["wallet_address"] == wallet_address

        overview = client.get(
            f"/v1/accounts/me/solana/wallets/{wallet_address}",
            headers={"Authorization": f"Bearer {session_token}"},
        )
        assert overview.status_code == 200
        body = overview.json()
        assert body["wallet"]["wallet_address"] == wallet_address
        assert body["balance_sol"] == 2.5
        assert body["transactions"][0]["signature"] == "txsig123"
    finally:
        receipt_service.get_wallet_overview = original_get_wallet_overview


def test_issued_public_key_can_access_protected_endpoints():
    api_key = issue_public_key()

    response = client.post(
        "/v1/policies",
        headers={"Authorization": f"Bearer {api_key}"},
        json={
            "name": "Public key policy",
            "rules": {"allowed_http_methods": ["GET"]},
        },
    )

    assert response.status_code == 201
    assert response.json()["name"] == "Public key policy"


def test_create_policy_is_idempotent():
    first = client.post(
        "/v1/policies",
        headers={
            "Idempotency-Key": "policy-key-2",
            "Authorization": "Bearer default-dev-key"
        },
        json={
            "name": "Idempotent policy",
            "rules": {"allowed_http_methods": ["GET"]},
        },
    )
    second = client.post(
        "/v1/policies",
        headers={
            "Idempotency-Key": "policy-key-2",
            "Authorization": "Bearer default-dev-key"
        },
        json={
            "name": "Idempotent policy",
            "rules": {"allowed_http_methods": ["GET"]},
        },
    )

    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json()["id"] == second.json()["id"]


def test_policy_hash_is_deterministic_for_canonical_equivalents():
    first = client.post(
        "/v1/policies",
        headers={"Authorization": "Bearer default-dev-key"},
        json={
            "name": "Treasury control policy",
            "description": "First render",
            "rules": {
                "allowed_http_methods": ["POST", "GET"],
                "max_spend_usd": 5000,
                "trusted_executors": ["billing-api", "settlement-worker"],
                "trusted_origins": ["agent-router", "risk-engine"],
                "requires_human_approval_for_delete": True,
            },
            "risk_categories": ["payments", "treasury", "payments"],
            "budget_config": {
                "period": "monthly",
                "warning_threshold_usd": 3500,
                "max_total_spend_usd": 5000,
                "currency": "USD",
            },
            "required_approvers": ["finance-lead", "ops-manager"],
        },
    )
    second = client.post(
        "/v1/policies",
        headers={"Authorization": "Bearer default-dev-key"},
        json={
            "name": "Treasury control policy v2",
            "description": "Same semantics, different ordering",
            "rules": {
                "trusted_origins": ["risk-engine", "agent-router"],
                "requires_human_approval_for_delete": True,
                "trusted_executors": ["settlement-worker", "billing-api"],
                "max_spend_usd": 5000,
                "allowed_http_methods": ["GET", "POST"],
            },
            "risk_categories": ["treasury", "payments"],
            "budget_config": {
                "currency": "USD",
                "max_total_spend_usd": 5000,
                "warning_threshold_usd": 3500,
                "period": "monthly",
            },
            "required_approvers": ["ops-manager", "finance-lead"],
        },
    )

    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json()["policy_hash"] == second.json()["policy_hash"]
    assert first.json()["policy_schema_version"] == "sentinel-policy/v1"


def test_policy_hash_changes_when_budget_or_approvers_change():
    baseline = client.post(
        "/v1/policies",
        headers={"Authorization": "Bearer default-dev-key"},
        json={
            "name": "Baseline policy",
            "rules": {"allowed_http_methods": ["GET", "POST"]},
            "risk_categories": ["payments"],
            "budget_config": {
                "currency": "USD",
                "max_total_spend_usd": 1000,
                "period": "monthly",
            },
            "required_approvers": ["finance-lead"],
        },
    )
    changed = client.post(
        "/v1/policies",
        headers={"Authorization": "Bearer default-dev-key"},
        json={
            "name": "Changed policy",
            "rules": {"allowed_http_methods": ["GET", "POST"]},
            "risk_categories": ["payments", "vendor-risk"],
            "budget_config": {
                "currency": "USD",
                "max_total_spend_usd": 2000,
                "period": "monthly",
            },
            "required_approvers": ["finance-lead", "cfo"],
        },
    )

    assert baseline.status_code == 201
    assert changed.status_code == 201
    assert baseline.json()["policy_hash"] != changed.json()["policy_hash"]


def test_authorize_allows_valid_request():
    policy_id = create_default_policy()

    response = client.post(
        "/v1/authorize",
        headers={"Authorization": "Bearer default-dev-key"},
        json={
            "policy_id": policy_id,
            "requester": "agent://planner",
            "action": {
                "type": "fetch_balance",
                "http_method": "GET",
                "resource": "/wallets/primary",
                "amount_usd": 1.25,
            },
            "reasoning_trace": "Need current balance before computing settlement path.",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["allowed"] is True
    assert body["receipt_status"] == "anchored"
    assert body["receipt_signature"].startswith("mock_")


def test_cross_agent_proof_can_be_verified_by_target_service():
    response = client.post(
        "/v1/policies",
        headers={"Authorization": "Bearer default-dev-key"},
        json={
            "name": "Cross agent trust policy",
            "rules": {
                "allowed_http_methods": ["POST"],
                "trusted_origins": ["agent-router"],
                "trusted_executors": ["billing-api"],
                "requires_proof_for_external_execution": True,
                "proof_ttl_seconds": 600,
            },
        },
    )
    policy_id = response.json()["id"]

    authorize_payload = {
        "policy_id": policy_id,
        "requester": "agent://planner",
        "origin_service": "agent-router",
        "agent_wallet": "wallet_agent_123",
        "action": {
            "type": "submit_payment",
            "http_method": "POST",
            "resource": "/payments",
            "target_service": "billing-api",
            "amount_usd": 100,
        },
        "reasoning_trace": "Delegate payment execution to billing-api with a verifiable proof.",
    }

    authorize = client.post(
        "/v1/authorize",
        headers={"Authorization": "Bearer default-dev-key"},
        json=authorize_payload,
    )

    assert authorize.status_code == 200
    proof = authorize.json()["proof"]
    assert proof["target_service"] == "billing-api"
    assert proof["signature"].startswith("mockproof_")

    verify = client.post(
        "/v1/proofs/verify",
        headers={"Authorization": "Bearer default-dev-key"},
        json={
            "verifier": "billing-api",
            "action": authorize_payload["action"],
            "proof": proof,
        },
    )

    assert verify.status_code == 200
    assert verify.json()["valid"] is True
    assert verify.json()["reason"] == "verified"


def test_cross_agent_proof_rejects_wrong_verifier():
    response = client.post(
        "/v1/policies",
        headers={"Authorization": "Bearer default-dev-key"},
        json={
            "name": "Cross agent verifier policy",
            "rules": {
                "allowed_http_methods": ["POST"],
                "trusted_origins": ["agent-router"],
                "trusted_executors": ["billing-api"],
                "requires_proof_for_external_execution": True,
            },
        },
    )
    policy_id = response.json()["id"]

    authorize = client.post(
        "/v1/authorize",
        headers={"Authorization": "Bearer default-dev-key"},
        json={
            "policy_id": policy_id,
            "requester": "agent://planner",
            "origin_service": "agent-router",
            "action": {
                "type": "submit_payment",
                "http_method": "POST",
                "resource": "/payments",
                "target_service": "billing-api",
            },
            "reasoning_trace": "Delegate payment execution to billing-api with a verifiable proof.",
        },
    )

    proof = authorize.json()["proof"]
    verify = client.post(
        "/v1/proofs/verify",
        headers={"Authorization": "Bearer default-dev-key"},
        json={
            "verifier": "inventory-api",
            "action": {
                "type": "submit_payment",
                "http_method": "POST",
                "resource": "/payments",
                "target_service": "billing-api",
            },
            "proof": proof,
        },
    )

    assert verify.status_code == 200
    assert verify.json()["valid"] is False
    assert verify.json()["reason"] == "verifier_not_authorized"


def test_high_risk_action_requires_verified_signature():
    policy_id = client.post(
        "/v1/policies",
        headers={"Authorization": "Bearer default-dev-key"},
        json={
            "name": "High Risk policy",
            "rules": {"allowed_http_methods": ["POST"], "max_spend_usd": 5000},
        },
    ).json()["id"]

    request_body = {
        "policy_id": policy_id,
        "requester": "agent://trader",
        "action": {
            "type": "wire_transfer",
            "http_method": "POST",
            "resource": "/wallets/primary/send",
            "amount_usd": 2000,
        },
        "reasoning_trace": "Transfer inventory budget to settlement wallet.",
    }

    denied = client.post(
        "/v1/authorize",
        headers={"Authorization": "Bearer default-dev-key"},
        json=request_body,
    )
    assert denied.status_code == 402

    verified = client.post(
        "/v1/authorize",
        headers={
            "Authorization": "Bearer default-dev-key",
            "x-solana-tx-signature": receipt_service.build_mock_payment_token(request_body),
        },
        json=request_body,
    )
    assert verified.status_code == 200
    assert verified.json()["allowed"] is True


def test_live_high_risk_verification_accepts_confirmed_tx_with_matching_memo_and_payment(monkeypatch):
    monkeypatch.setattr(receipt_service, "mode", "live")
    monkeypatch.setattr(receipt_service, "required_commitment", "confirmed")
    monkeypatch.setattr(receipt_service, "require_memo", True)
    monkeypatch.setattr(receipt_service, "payment_recipient", "treasury-wallet")
    monkeypatch.setattr(receipt_service, "payment_min_lamports", 1000)
    monkeypatch.setattr(
        receipt_service,
        "_get_signature_status",
        lambda signature: {"err": None, "confirmationStatus": "finalized"},
    )
    monkeypatch.setattr(
        receipt_service,
        "_get_transaction",
        lambda signature: {
            "meta": {"err": None, "innerInstructions": []},
            "transaction": {
                "message": {
                    "instructions": [
                        {
                            "program": "system",
                            "parsed": {
                                "info": {
                                    "destination": "treasury-wallet",
                                    "lamports": 1500,
                                }
                            },
                        },
                        {
                            "program": "spl-memo",
                            "parsed": "action_hash_123",
                        },
                    ]
                }
            },
        },
    )

    assert receipt_service.verify_high_risk_signature(
        "1111111111111111111111111111111111111111111111111111111111111111",
        {"policy_id": "pol_live"},
        action_hash="action_hash_123",
    ) is True


def test_live_high_risk_verification_rejects_missing_required_memo(monkeypatch):
    monkeypatch.setattr(receipt_service, "mode", "live")
    monkeypatch.setattr(receipt_service, "required_commitment", "confirmed")
    monkeypatch.setattr(receipt_service, "require_memo", True)
    monkeypatch.setattr(receipt_service, "payment_recipient", "treasury-wallet")
    monkeypatch.setattr(receipt_service, "payment_min_lamports", 1000)
    monkeypatch.setattr(
        receipt_service,
        "_get_signature_status",
        lambda signature: {"err": None, "confirmationStatus": "finalized"},
    )
    monkeypatch.setattr(
        receipt_service,
        "_get_transaction",
        lambda signature: {
            "meta": {"err": None, "innerInstructions": []},
            "transaction": {
                "message": {
                    "instructions": [
                        {
                            "program": "system",
                            "parsed": {
                                "info": {
                                    "destination": "treasury-wallet",
                                    "lamports": 1500,
                                }
                            },
                        }
                    ]
                }
            },
        },
    )

    assert receipt_service.verify_high_risk_signature(
        "1111111111111111111111111111111111111111111111111111111111111111",
        {"policy_id": "pol_live"},
        action_hash="action_hash_123",
    ) is False


def test_authorize_blocks_excessive_spend():
    policy_id = create_default_policy()

    response = client.post(
        "/v1/authorize",
        headers={"Authorization": "Bearer default-dev-key"},
        json={
            "policy_id": policy_id,
            "requester": "agent://trader",
            "action": {
                "type": "transfer_funds",
                "http_method": "GET",
                "resource": "/wallets/primary/send",
                "amount_usd": 12.5,
            },
            "reasoning_trace": "Transfer inventory budget to settlement wallet.",
        },
    )

    assert response.status_code == 403
    body = response.json()["detail"]["error"]
    assert body["code"] == "POLICY_LIMIT_EXCEEDED"


def test_list_audits_returns_history():
    policy_id = create_default_policy()
    client.post(
        "/v1/authorize",
        headers={"Authorization": "Bearer default-dev-key"},
        json={
            "policy_id": policy_id,
            "requester": "agent://reader",
            "action": {
                "type": "fetch_weather",
                "http_method": "GET",
                "resource": "/weather/chicago",
            },
            "reasoning_trace": "Need forecast for downstream travel quote.",
        },
    )

    response = client.get(
        f"/v1/audits/{policy_id}",
        headers={"Authorization": "Bearer default-dev-key"}
    )

    assert response.status_code == 200
    assert response.json()["data"]
