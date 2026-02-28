# Sentinel-Auth: The Policy-Gated API Proxy 🛡️

**Sentinel-Auth** is a next-generation middleware API designed for the agentic web (2026+). It acts as a "Safety Buffer" between autonomous AI agents and critical backend infrastructure, preventing "Prompt Injection" and "Agent Drift" from executing catastrophic API calls (e.g., `DELETE /account`).

Instead of simply verifying if an API key is valid, Sentinel-Auth inspects the **intent** of the request against strict, pre-defined safety policies, utilizing **Solana's Alpenglow 150ms finality** for real-time cryptographic verification and x402 micro-payments for high-risk actions.

---

## 🌟 Key Features (Built for Stripe's Best Web API Metrics)

1. **Stateful Policy Engine & Safety Limits**
   Enforce rate limits, maximum spend thresholds, and HTTP method restrictions per AI agent. State is managed gracefully to ensure predictable AI behavior without silent failures.

2. **Solana-Backed Immutable Audit Trails ("Safety Receipts")**
   Every allowed intent is hashed (SHA-256) and anchored to the Solana blockchain as a micro-transaction, providing a cryptographically verifiable history of what an agent intended to do at any millisecond in time.

3. **x402 "Pay-per-Safety" Protocol**
   High-risk actions (e.g., moving >$1000) trigger an `HTTP 402 Payment Required` response. The AI agent (via its integrated Phantom/Solana wallet) must autonomously sign a micro-transaction fee (`x-solana-tx-signature`) to unlock the audit verification before the API proceeds.

4. **World-Class Developer Experience (DX)**
   Built on FastAPI, delivering strict OpenAPI specifications and highly informative, standardized Error Envelope schemas (e.g., `POLICY_LIMIT_EXCEEDED`) so developers can debug agent behavior immediately.

---

## ⚡ Quick Start: 7 Lines to Safety

Integrating Sentinel-Auth is as simple as routing your agent's proposed HTTP action through the `/v1/authorize` decision engine:

```bash
curl -X POST https://hackillinois-tbrqg.ondigitalocean.app/v1/authorize \
  -H "Authorization: Bearer hackillinois_2026_super_secret" \
  -H "Content-Type: application/json" \
  -d '{
    "policy_id": "pol_70bf5edaa66241e4a6c65a89",
    "requester": "agent://trading_bot_alpha",
    "reasoning_trace": "Market conditions optimal. Initiating $500 stablecoin purchase.",
    "action": {
      "type": "wire_transfer",
      "http_method": "POST",
      "resource": "/api/exchange/buy",
      "amount_usd": 500
    }
  }'
```

**Success Response (200 OK):**
```json
{
  "request_id": "req_c29ab09b456f488d8a509605",
  "policy_id": "pol_70bf5edaa66241e4a6c65a89",
  "allowed": true,
  "decision": "allow",
  "receipt_status": "anchored",
  "receipt_signature": "5Hq2... (Solana TX Hash)",
  "violation": null
}
```

---

## 🏛️ Architecture & Tech Stack

- **Backend:** Python + FastAPI (Strict Pydantic Type Validation)
- **Database:** PostgreSQL (DigitalOcean Managed) + SQLAlchemy
- **Blockchain:** `@solana/web3.js` + Devnet for real-time x402 intent verification.
- **Frontend / Demo UI:** React/Vite + Vanilla CSS (Live simulated environment)
- **Deployment:** DigitalOcean App Platform (Dockerized)

---

## 📖 API Reference

Complete interactive Swagger UI Documentation is available at:
👉 **[https://hackillinois-tbrqg.ondigitalocean.app/docs](https://hackillinois-tbrqg.ondigitalocean.app/docs)**

### Core Endpoints
- `POST /v1/policies`: Create a new Safety Profile for an agent (supports `Idempotency-Key`).
- `GET /v1/policies/{id}`: Retrieve policy details.
- `POST /v1/authorize`: The core decision engine. Submits an intent for approval.
- `GET /v1/audits/{policy_id}`: Retrieve the immutable history of blocked and allowed actions.

---

## 🚀 Running the Demo Locally

1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/hackillinois.git
   cd hackillinois/frontend
   ```

2. Install dependencies & run the Vite UI:
   ```bash
   npm install
   npm run dev
   ```

3. Open your browser to `http://localhost:5173`. Make sure you have the **Phantom Wallet** browser extension installed and set to Solana Devnet to handle x402 high-risk verifications!
