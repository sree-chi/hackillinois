from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Any


@dataclass
class SolanaReceipt:
    status: str
    signature: str | None
    intent_hash: str
    provider: str


class SolanaReceiptService:
    def __init__(self) -> None:
        self.mode = os.getenv("SOLANA_RECEIPT_MODE", "mock").lower()

    def anchor(self, payload: dict[str, Any]) -> SolanaReceipt:
        intent_hash = hashlib.sha256(str(payload).encode("utf-8")).hexdigest()
        if self.mode == "off":
            return SolanaReceipt(status="skipped", signature=None, intent_hash=intent_hash, provider="disabled")
        if self.mode == "mock":
            signature = f"mock_{intent_hash[:32]}"
            return SolanaReceipt(status="anchored", signature=signature, intent_hash=intent_hash, provider="mock")

        # Real RPC/program submission belongs here. Keeping the contract narrow
        # lets the API work locally without a funded wallet or deployed program.
        raise RuntimeError("Live Solana anchoring is not configured")


receipt_service = SolanaReceiptService()
