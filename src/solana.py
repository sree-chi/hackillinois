from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from solana.rpc.api import Client
from solders.instruction import Instruction
from solders.keypair import Keypair
from solders.message import MessageV0
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

logger = logging.getLogger("SolanaPlugin")


@dataclass
class SolanaReceipt:
    status: str
    signature: str | None
    intent_hash: str
    provider: str


class SolanaVerificationError(RuntimeError):
    pass


class SolanaReceiptService:
    def __init__(self) -> None:
        self.mode = os.getenv("SOLANA_RECEIPT_MODE", "mock").lower()
        self.rpc_url = os.getenv("SOLANA_RPC_URL", "https://api.devnet.solana.com")
        self.client = Client(self.rpc_url)
        self.mock_signing_secret = os.getenv("SOLANA_PROOF_SECRET", "sentinel-proof-secret")
        self.mock_issuer = os.getenv("SOLANA_PROOF_ISSUER", "sentinel-mock-issuer")

        pk_env = os.getenv("SOLANA_PRIVATE_KEY")
        if pk_env:
            try:
                secret = json.loads(pk_env)
                self.keypair = Keypair.from_bytes(bytes(secret))
            except Exception:
                self.keypair = None
        else:
            self.keypair = None

    def issuer(self) -> str:
        if self.keypair:
            return str(self.keypair.pubkey())
        return self.mock_issuer

    def _intent_hash(self, payload: dict[str, Any]) -> str:
        normalized = self._normalize_payload(payload)
        canonical_payload = json.dumps(
            normalized, 
            sort_keys=True, 
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()

    def _normalize_payload(self, payload: Any) -> Any:
        if isinstance(payload, dict):
            return {key: self._normalize_payload(payload[key]) for key in sorted(payload)}
        if isinstance(payload, list):
            return [self._normalize_payload(item) for item in payload]
        if isinstance(payload, datetime):
            value = payload
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        return payload

    def _proof_signature(self, payload: dict[str, Any]) -> str:
        canonical_payload = json.dumps(
            self._normalize_payload(payload),
            sort_keys=True,
            separators=(",", ":"),
        )
        if self.mode == "live" and self.keypair:
            return str(self.keypair.sign_message(canonical_payload.encode("utf-8")))
        digest = hashlib.sha256(f"{self.mock_signing_secret}:{canonical_payload}".encode("utf-8")).hexdigest()
        return f"mockproof_{digest}"

    def build_mock_payment_token(self, payload: dict[str, Any]) -> str:
        serialized_payload = json.dumps(payload, separators=(",", ":"))
        encoded = base64.b64encode(serialized_payload.encode("utf-8")).decode("ascii")
        token_body = "".join(ch for ch in encoded if ch.isalnum())[:24]
        return f"mock_x402_{token_body}"

    def action_hash(self, payload: dict[str, Any]) -> str:
        return self._intent_hash(payload)

    def build_authorization_proof(self, claims: dict[str, Any]) -> dict[str, Any]:
        proof_claims = {**claims, "issuer": self.issuer()}
        proof_claims["signature"] = self._proof_signature(proof_claims)
        return proof_claims

    def verify_authorization_proof(self, claims: dict[str, Any], signature: str) -> bool:
        unsigned_claims = {key: value for key, value in claims.items() if key != "signature"}
        expected = self._proof_signature(unsigned_claims)
        return expected == signature

    def verify_high_risk_signature(self, signature: str | None, payload: dict[str, Any]) -> bool:
        if not signature:
            return False

        if self.mode == "off":
            return False

        if self.mode == "mock":
            return signature == self.build_mock_payment_token(payload)

        if self.mode != "live":
            raise SolanaVerificationError(f"Unknown Solana verification mode: {self.mode}")

        try:
            parsed_signature = Signature.from_string(signature)
        except Exception:
            return False

        try:
            response = self.client.get_signature_statuses([parsed_signature])
        except Exception as exc:
            raise SolanaVerificationError("Unable to verify the Solana transaction signature") from exc

        status = response.value[0] if response.value else None
        return status is not None and status.err is None

    def anchor(self, payload: dict[str, Any]) -> SolanaReceipt:
        intent_hash = self._intent_hash(payload)

        if self.mode == "off":
            return SolanaReceipt(status="skipped", signature=None, intent_hash=intent_hash, provider="disabled")

        if self.mode == "mock":
            signature = f"mock_{intent_hash[:32]}"
            logger.info(
                f"[Mock Mode] Successfully simulated Solana anchoring. Intent Hash: {intent_hash[:10]}... "
                f"Signature: {signature[:10]}..."
            )
            return SolanaReceipt(status="anchored", signature=signature, intent_hash=intent_hash, provider="mock")

        if self.mode == "live":
            logger.info(f"[Live Mode] Attempting to anchor Intent Hash: {intent_hash} to {self.rpc_url}")
            if not self.keypair:
                logger.error("Live Solana anchoring is configured but SOLANA_PRIVATE_KEY is missing or invalid")
                return SolanaReceipt(status="failed", signature=None, intent_hash=intent_hash, provider=self.rpc_url)

            try:
                memo_program_id = Pubkey.from_string("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
                instruction = Instruction(
                    program_id=memo_program_id,
                    accounts=[],
                    data=intent_hash.encode("utf-8"),
                )

                recent_blockhash_resp = self.client.get_latest_blockhash()
                recent_blockhash = recent_blockhash_resp.value.blockhash

                message = MessageV0.try_compile(
                    payer=self.keypair.pubkey(),
                    instructions=[instruction],
                    address_lookup_table_accounts=[],
                    recent_blockhash=recent_blockhash,
                )

                tx = VersionedTransaction(message, [self.keypair])
                logger.info(f"Sending standard transaction with {len(message.instructions)} instructions to network...")
                response = self.client.send_transaction(tx)
                signature = str(response.value)
                logger.info(f"Success! Live Solana receipt anchored: {signature}")
                return SolanaReceipt(
                    status="anchored",
                    signature=signature,
                    intent_hash=intent_hash,
                    provider=self.rpc_url,
                )
            except Exception:
                logger.exception("Live Solana anchoring failed")
                return SolanaReceipt(status="failed", signature=None, intent_hash=intent_hash, provider=self.rpc_url)

        logger.error(f"Unknown Solana anchoring mode: {self.mode}")
        return SolanaReceipt(status="failed", signature=None, intent_hash=intent_hash, provider=self.rpc_url)


receipt_service = SolanaReceiptService()
