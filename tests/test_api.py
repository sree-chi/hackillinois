import os

import pytest
from fastapi.testclient import TestClient
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


def issue_public_key() -> str:
    response = client.post(
        "/v1/developer/keys",
        json={
            "app_name": "Portal Test App",
            "owner_name": "Portal Owner",
            "owner_email": "owner@example.com",
            "use_case": "Testing public onboarding",
        },
    )
    assert response.status_code == 201
    return response.json()["api_key"]


def test_public_key_issuance_returns_live_key_material():
    response = client.post(
        "/v1/developer/keys",
        json={
            "app_name": "Public Portal App",
            "owner_email": "founder@example.com",
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert body["api_key"].startswith("ska_live_")
    assert body["authorization_header"].startswith("Bearer ska_live_")
    assert body["docs_url"].endswith("/docs")


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
