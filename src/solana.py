from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
from urllib import error as urllib_error
from urllib import request as urllib_request
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
        self.wallet_link_ttl_seconds = int(os.getenv("SOLANA_WALLET_LINK_TTL_SECONDS", "600"))
        self.mock_signing_secret = os.getenv("SOLANA_PROOF_SECRET", "sentinel-proof-secret")
        self.mock_issuer = os.getenv("SOLANA_PROOF_ISSUER", "sentinel-mock-issuer")
        self.required_commitment = os.getenv("SOLANA_REQUIRED_COMMITMENT", "confirmed").lower()
        self.payment_recipient = os.getenv("SOLANA_PAYMENT_RECIPIENT")
        self.payment_min_lamports = int(os.getenv("SOLANA_PAYMENT_MIN_LAMPORTS", "0"))
        self.require_memo = os.getenv("SOLANA_PAYMENT_REQUIRE_MEMO", "false").lower() == "true"

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

    def wallet_network(self) -> str:
        lower = self.rpc_url.lower()
        if "mainnet" in lower:
            return "mainnet-beta"
        if "testnet" in lower:
            return "testnet"
        return "devnet"

    def explorer_url_for_signature(self, signature: str) -> str:
        network = self.wallet_network()
        suffix = "" if network == "mainnet-beta" else f"?cluster={network}"
        return f"https://explorer.solana.com/tx/{signature}{suffix}"

    def validate_wallet_address(self, wallet_address: str) -> str:
        try:
            return str(Pubkey.from_string(wallet_address))
        except Exception as exc:
            raise SolanaVerificationError("Invalid Solana wallet address.") from exc

    def new_wallet_link_nonce(self) -> str:
        return secrets.token_urlsafe(24)

    def build_wallet_link_message(self, domain: str, wallet_address: str, account_email: str, nonce: str) -> str:
        normalized_wallet = self.validate_wallet_address(wallet_address)
        return "\n".join([
            f"{domain} wants you to link your Solana wallet.",
            "",
            "Sign this message with Phantom to connect your wallet to your Sentinel account.",
            f"Wallet: {normalized_wallet}",
            f"Account: {account_email}",
            f"Nonce: {nonce}",
            f"RPC: {self.rpc_url}",
        ])

    def verify_wallet_link_signature(self, wallet_address: str, message: str, signature: str) -> bool:
        try:
            pubkey = Pubkey.from_string(wallet_address)
            signature_bytes = base64.b64decode(signature, validate=True)
            signed = Signature.from_bytes(signature_bytes)
        except Exception:
            return False
        try:
            return bool(signed.verify(pubkey, message.encode("utf-8")))
        except Exception:
            return False

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
        if isinstance(payload, float) and payload.is_integer():
            return int(payload)
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
        canonical = json.dumps(self._normalize_payload(payload), sort_keys=True, separators=(",", ":"))
        digest = hmac.new(
            self.mock_signing_secret.encode("utf-8"),
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return f"mock_x402_{digest[:32]}"

    def action_hash(self, payload: dict[str, Any]) -> str:
        return self._intent_hash(payload)

    def _commitment_rank(self, commitment: str | None) -> int:
        order = {"processed": 0, "confirmed": 1, "finalized": 2}
        return order.get((commitment or "").lower(), -1)

    def _rpc_json(self, method: str, params: list[Any]) -> dict[str, Any]:
        payload = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }).encode("utf-8")
        req = urllib_request.Request(
            self.rpc_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib_request.urlopen(req, timeout=15) as response:
                data = json.loads(response.read().decode("utf-8"))
        except (urllib_error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise SolanaVerificationError(f"Unable to call Solana RPC method {method}") from exc

        if "error" in data:
            raise SolanaVerificationError(f"Solana RPC {method} failed: {data['error']}")

        return data

    def _get_signature_status(self, signature: str) -> dict[str, Any] | None:
        response = self._rpc_json("getSignatureStatuses", [[signature], {"searchTransactionHistory": True}])
        values = response.get("result", {}).get("value", [])
        return values[0] if values else None

    def _get_transaction(self, signature: str) -> dict[str, Any] | None:
        response = self._rpc_json(
            "getTransaction",
            [
                signature,
                {
                    "encoding": "jsonParsed",
                    "commitment": self.required_commitment,
                    "maxSupportedTransactionVersion": 0,
                },
            ],
        )
        return response.get("result")

    def _get_balance(self, wallet_address: str) -> int:
        response = self._rpc_json(
            "getBalance",
            [
                wallet_address,
                {"commitment": self.required_commitment},
            ],
        )
        value = response.get("result", {}).get("value")
        try:
            return int(value)
        except (TypeError, ValueError):
            raise SolanaVerificationError("Unable to read wallet balance from Solana RPC.")

    def _get_signatures_for_address(self, wallet_address: str, limit: int) -> list[dict[str, Any]]:
        response = self._rpc_json(
            "getSignaturesForAddress",
            [
                wallet_address,
                {"limit": limit},
            ],
        )
        result = response.get("result", [])
        return result if isinstance(result, list) else []

    def _wallet_native_change_lamports(self, tx: dict[str, Any], wallet_address: str) -> int | None:
        try:
            message = tx.get("transaction", {}).get("message", {})
            account_keys = message.get("accountKeys", [])
            addresses = []
            for entry in account_keys:
                if isinstance(entry, dict):
                    addresses.append(entry.get("pubkey"))
                else:
                    addresses.append(entry)
            index = addresses.index(wallet_address)
            meta = tx.get("meta", {})
            pre_balances = meta.get("preBalances", [])
            post_balances = meta.get("postBalances", [])
            return int(post_balances[index]) - int(pre_balances[index])
        except Exception:
            return None

    def get_wallet_overview(self, wallet_address: str, limit: int = 8) -> dict[str, Any]:
        normalized_wallet = self.validate_wallet_address(wallet_address)
        balance_lamports = self._get_balance(normalized_wallet)
        signatures = self._get_signatures_for_address(normalized_wallet, limit)
        transactions: list[dict[str, Any]] = []

        for entry in signatures:
            signature = entry.get("signature")
            if not signature:
                continue
            tx = self._get_transaction(signature)
            native_change_lamports = self._wallet_native_change_lamports(tx or {}, normalized_wallet) if tx else None
            block_time = entry.get("blockTime")
            transactions.append({
                "signature": signature,
                "slot": entry.get("slot"),
                "block_time": datetime.fromtimestamp(block_time, tz=timezone.utc) if block_time else None,
                "confirmation_status": entry.get("confirmationStatus"),
                "success": entry.get("err") is None,
                "memo": entry.get("memo"),
                "native_change_lamports": native_change_lamports,
                "explorer_url": self.explorer_url_for_signature(signature),
            })

        return {
            "rpc_url": self.rpc_url,
            "network": self.wallet_network(),
            "balance_lamports": balance_lamports,
            "balance_sol": balance_lamports / 1_000_000_000,
            "transactions": transactions,
            "fetched_at": datetime.now(timezone.utc),
        }

    def _iter_transaction_instructions(self, tx: dict[str, Any]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        message = tx.get("transaction", {}).get("message", {})
        for instruction in message.get("instructions", []):
            if isinstance(instruction, dict):
                result.append(instruction)

        for group in tx.get("meta", {}).get("innerInstructions", []):
            for instruction in group.get("instructions", []):
                if isinstance(instruction, dict):
                    result.append(instruction)
        return result

    def _memo_matches_action_hash(self, tx: dict[str, Any], action_hash: str) -> bool:
        for instruction in self._iter_transaction_instructions(tx):
            rendered = json.dumps(instruction, sort_keys=True)
            if action_hash in rendered:
                return True
        return False

    def _lamports_sent_to_recipient(self, tx: dict[str, Any], recipient: str) -> int:
        lamports = 0
        for instruction in self._iter_transaction_instructions(tx):
            parsed = instruction.get("parsed")
            if not isinstance(parsed, dict):
                continue

            info = parsed.get("info")
            if not isinstance(info, dict):
                continue

            destination = info.get("destination")
            amount = info.get("lamports")
            if destination != recipient or amount is None:
                continue

            try:
                lamports += int(amount)
            except (TypeError, ValueError):
                continue
        return lamports

    def build_authorization_proof(self, claims: dict[str, Any]) -> dict[str, Any]:
        proof_claims = {**claims, "issuer": self.issuer()}
        proof_claims["signature"] = self._proof_signature(proof_claims)
        return proof_claims

    def verify_authorization_proof(self, claims: dict[str, Any], signature: str) -> bool:
        unsigned_claims = {key: value for key, value in claims.items() if key != "signature"}
        expected = self._proof_signature(unsigned_claims)
        return hmac.compare_digest(expected, signature)

    def verify_high_risk_signature(self, signature: str | None, payload: dict[str, Any], action_hash: str | None = None) -> bool:
        if not signature:
            return False

        if self.mode == "off":
            return False

        if self.mode == "mock":
            return signature == self.build_mock_payment_token(payload)

        if self.mode != "live":
            raise SolanaVerificationError(f"Unknown Solana verification mode: {self.mode}")

        try:
            Signature.from_string(signature)
        except Exception:
            return False

        try:
            status = self._get_signature_status(signature)
            tx = self._get_transaction(signature)
        except Exception as exc:
            raise SolanaVerificationError("Unable to verify the Solana transaction signature") from exc

        if not status or status.get("err") is not None:
            return False

        if self._commitment_rank(status.get("confirmationStatus")) < self._commitment_rank(self.required_commitment):
            return False

        if not tx:
            return False

        if tx.get("meta", {}).get("err") is not None:
            return False

        if action_hash:
            memo_matches = self._memo_matches_action_hash(tx, action_hash)
            if self.require_memo and not memo_matches:
                return False

        if self.payment_recipient:
            lamports_sent = self._lamports_sent_to_recipient(tx, self.payment_recipient)
            if lamports_sent <= 0:
                return False
            if self.payment_min_lamports and lamports_sent < self.payment_min_lamports:
                return False

        return True

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
