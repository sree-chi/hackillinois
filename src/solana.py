from __future__ import annotations

import hashlib
import os
import json
from dataclasses import dataclass
from typing import Any

from solana.rpc.api import Client
from solders.pubkey import Pubkey
from solders.instruction import Instruction
from solders.transaction import VersionedTransaction
from solders.message import MessageV0
from solders.keypair import Keypair

@dataclass
class SolanaReceipt:
    status: str
    signature: str | None
    intent_hash: str
    provider: str


class SolanaReceiptService:
    def __init__(self) -> None:
        self.mode = os.getenv("SOLANA_RECEIPT_MODE", "mock").lower()
        self.rpc_url = os.getenv("SOLANA_RPC_URL", "https://api.devnet.solana.com")
        self.client = Client(self.rpc_url)
        
        # Load keypair from env var if provided, otherwise generate a dummy one (will fail if used)
        pk_env = os.getenv("SOLANA_PRIVATE_KEY")
        if pk_env:
            try:
                # Assuming JSON array format like [1,2,3...255]
                secret = json.loads(pk_env)
                self.keypair = Keypair.from_bytes(bytes(secret))
            except Exception:
                self.keypair = None
        else:
            self.keypair = None

    def anchor(self, payload: dict[str, Any]) -> SolanaReceipt:
        intent_hash = hashlib.sha256(str(payload).encode("utf-8")).hexdigest()
        
        if self.mode == "off":
            return SolanaReceipt(status="skipped", signature=None, intent_hash=intent_hash, provider="disabled")
        if self.mode == "mock":
            signature = f"mock_{intent_hash[:32]}"
            return SolanaReceipt(status="anchored", signature=signature, intent_hash=intent_hash, provider="mock")

        if self.mode == "live":
            if not self.keypair:
                raise RuntimeError("Live Solana anchoring is configured but SOLANA_PRIVATE_KEY is missing or invalid")
                
            # Create a memo instruction with the intent hash
            # Memo program ID: MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr
            memo_program_id = Pubkey.from_string("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
            instruction = Instruction(
                program_id=memo_program_id,
                accounts=[], # Memo program doesn't require accounts
                data=intent_hash.encode("utf-8")
            )
            
            # Fetch latest blockhash
            recent_blockhash_resp = self.client.get_latest_blockhash()
            recent_blockhash = recent_blockhash_resp.value.blockhash
            
            # Create the transaction message
            message = MessageV0.try_compile(
                payer=self.keypair.pubkey(),
                instructions=[instruction],
                address_lookup_table_accounts=[],
                recent_blockhash=recent_blockhash,
            )
            
            # Build and sign the transaction
            tx = VersionedTransaction(message, [self.keypair])
            
            # Send the transaction
            try:
                response = self.client.send_transaction(tx)
                signature = str(response.value)
                return SolanaReceipt(
                    status="anchored", 
                    signature=signature, 
                    intent_hash=intent_hash, 
                    provider=self.rpc_url
                )
            except Exception as e:
                # In a real app we might retry, or save `failed` to the DB and retry asynchronously
                return SolanaReceipt(
                    status="failed", 
                    signature=None, 
                    intent_hash=intent_hash, 
                    provider=self.rpc_url
                )

        raise RuntimeError(f"Unknown Solana anchoring mode: {self.mode}")

receipt_service = SolanaReceiptService()
