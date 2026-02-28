# Sentinel Auth API

Minimal FastAPI implementation of a policy-based authorization service with Solana-backed safety receipts.

## What it does

- `POST /v1/policies` creates a safety policy and supports `Idempotency-Key`.
- `POST /v1/authorize` evaluates an agent action against a policy.
- `GET /v1/policies/{id}` returns policy details.
- `GET /v1/audits/{policy_id}` returns allow/deny history.
- Solana anchoring is abstracted behind `SolanaReceiptService`.

## Local run

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn src.main:app --reload
```

Open `http://127.0.0.1:8000/docs` for the OpenAPI UI.

## Receipt modes

- `SOLANA_RECEIPT_MODE=mock` (default): returns a deterministic fake signature.
- `SOLANA_RECEIPT_MODE=off`: skips anchoring and marks the receipt as `skipped`.
- Any other value: reserved for a real Solana RPC/program integration.

## Example request

```bash
curl -X POST http://127.0.0.1:8000/v1/authorize ^
  -H "Content-Type: application/json" ^
  -d "{\"policy_id\":\"pol_123\",\"requester\":\"agent://planner\",\"action\":{\"type\":\"fetch_balance\",\"http_method\":\"GET\",\"resource\":\"/wallets/primary\"},\"reasoning_trace\":\"Need balance before planning transfer.\"}"
```

## Notes

- The full reasoning trace stays off-chain.
- The current Solana module anchors a hash and returns a receipt abstraction.
- For production, replace `src/solana.py` with real RPC/program submission and durable storage.
