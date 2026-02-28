# Sentinel Auth

Sentinel Auth is a policy gateway for AI agents. It issues developer API keys, lets teams define action policies, and evaluates each agent request against those rules before the action reaches downstream infrastructure.

## What changed

- Public developer onboarding via `POST /v1/developer/keys`
- Per-client API keys stored as hashes instead of one shared hardcoded secret
- Developer portal UI for issuing a key, copying quickstart snippets, and testing `/v1/authorize`
- Existing policy, proof verification, audit, and high-risk Solana receipt flows remain available

## Public onboarding flow

1. Open the frontend developer portal.
2. Create a key from the form or call `POST /v1/developer/keys`.
3. Use the returned key as `Authorization: Bearer <key>` or `X-API-Key: <key>`.
4. Create a policy with `POST /v1/policies`.
5. Send every agent action through `POST /v1/authorize`.

## Example: issue a key

```bash
curl -X POST http://localhost:8000/v1/developer/keys \
  -H "Content-Type: application/json" \
  -d '{
    "app_name": "Atlas Agent Ops",
    "owner_email": "team@example.com",
    "owner_name": "Atlas Team",
    "use_case": "Managing support and treasury agents."
  }'
```

## Example: create a policy with an issued key

```bash
curl -X POST http://localhost:8000/v1/policies \
  -H "Authorization: Bearer ska_live_your_key_here" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Agent spending policy",
    "rules": {
      "allowed_http_methods": ["GET", "POST"],
      "max_spend_usd": 5000,
      "max_requests_per_minute": 60
    }
  }'
```

## Core endpoints

- `GET /v1/public/overview`
- `POST /v1/developer/keys`
- `POST /v1/policies`
- `GET /v1/policies/{policy_id}`
- `POST /v1/authorize`
- `POST /v1/proofs/verify`
- `GET /v1/audits/{policy_id}`

## Local development

Backend:

```bash
uvicorn src.main:app --reload
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

## Notes

- The legacy admin key from `API_KEY` still works for internal/dev access.
- Issued developer keys are only returned in plaintext once at creation time.
- Public response URLs can be pinned with `PUBLIC_BASE_URL`.
