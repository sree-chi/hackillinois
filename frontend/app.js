const API_BASE = 'http://127.0.0.1:8000';
const AUTH_HEADER = 'Bearer default-dev-key';
const btnExpensiveApi = document.getElementById('btn-expensive-api');
const NGROK_URL = 'https://nonobservant-patrick-catchingly.ngrok-free.dev/';
const HIGH_RISK_THRESHOLD = 1000;
let currentPolicyId = null;

const consoleEl = document.getElementById('console-output');
const btnCreate = document.getElementById('btn-create-policy');
const btnSafe = document.getElementById('btn-safe-action');
const btnHighRisk = document.getElementById('btn-high-risk');
const btnUnlock = document.getElementById('btn-unlock');

function log(msg, type = 'info') {
    const time = new Date().toLocaleTimeString();
    const div = document.createElement('div');
    div.className = `log-entry log-${type}`;
    div.innerHTML = `<span class="log-time">[${time}]</span> ${msg}`;
    consoleEl.appendChild(div);
    consoleEl.scrollTop = consoleEl.scrollHeight;
}

function buildMockPaymentToken(requestBody) {
    return `mock_x402_${btoa(JSON.stringify(requestBody)).replace(/[^a-zA-Z0-9]/g, '').slice(0, 24)}`;
}

btnCreate.addEventListener('click', async () => {
    log('Setting up Sentinel API connection...', 'info');
    log('POST /v1/policies [Idempotency-Key: UI-Demo-Token]', 'info');

    try {
        const res = await fetch(`${API_BASE}/v1/policies`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': AUTH_HEADER,
                'Idempotency-Key': 'ui-demo-' + Math.random().toString(36).substr(2, 9)
            },
            body: JSON.stringify({
                name: "Agent UI Policy",
                description: "Approve actions under $5000, with x402 verification above $1000",
                rules: {
                    allowed_http_methods: ["GET", "POST"],
                    max_spend_usd: 5000,
                    max_requests_per_minute: 10
                }
            })
        });

        const data = await res.json();
        if (res.ok) {
            currentPolicyId = data.id;
            log(`Success! Created Policy ID: <strong>${currentPolicyId}</strong>`, 'success');
            btnSafe.disabled = false;
            btnHighRisk.disabled = false;

            // Enable our new demo button
            btnExpensiveApi.disabled = false;

            btnCreate.disabled = true;
            btnCreate.textContent = "Policy Active";
        } else {
            log(`Error: ${JSON.stringify(data)}`, 'error');
        }
    } catch (e) {
        log(`Failed to connect to API: ${e.message}`, 'error');
    }
});

btnSafe.addEventListener('click', async () => {
    log(`Executing Safe Action ($500) for agent...`, 'info');

    try {
        const res = await fetch(`${API_BASE}/v1/authorize`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': AUTH_HEADER
            },
            body: JSON.stringify({
                policy_id: currentPolicyId,
                requester: "agent://ui_demo",
                action: {
                    type: "wire_transfer",
                    http_method: "POST",
                    resource: "/wallets/primary",
                    amount_usd: 500
                },
                reasoning_trace: "Standard operational transfer of $500."
            })
        });

        const data = await res.json();
        if (res.ok) {
            log(`Action Approved! Receipt: ${data.receipt_signature}`, 'success');
        } else {
            log(`Denied: ${data.detail || JSON.stringify(data)}`, 'error');
        }
    } catch (e) {
        log(`Error: ${e.message}`, 'error');
    }
});

btnHighRisk.addEventListener('click', async () => {
    log(`Executing High-Risk Action ($2000)...`, 'info');
    log(`Actions at or above $${HIGH_RISK_THRESHOLD} require x402 verification.`, 'info');

    try {
        const res = await fetch(`${API_BASE}/v1/authorize`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': AUTH_HEADER
            },
            body: JSON.stringify({
                policy_id: currentPolicyId,
                requester: "agent://ui_demo",
                action: {
                    type: "wire_transfer",
                    http_method: "POST",
                    resource: "/wallets/primary",
                    amount_usd: 2000
                },
                reasoning_trace: "High value wire transfer of $2000."
            })
        });

        if (res.status === 402) {
            log(`402 Payment Required! Action blocked by Sentinel.`, 'error');
            log(`Solana x402 verification required for amounts >= $${HIGH_RISK_THRESHOLD}.`, 'info');
            btnUnlock.disabled = false;
            btnHighRisk.disabled = true;
        } else {
            const data = await res.json();
            log(`Result: ${JSON.stringify(data)}`, 'info');
        }
    } catch (e) {
        log(`Error: ${e.message}`, 'error');
    }
});

btnUnlock.addEventListener('click', async () => {
    log(`Agent signing micro-payment on Solana...`, 'solana');
    log(`Resubmitting intent with x-solana-tx-signature header...`, 'info');

    btnUnlock.textContent = "Verifying on Chain...";

    setTimeout(async () => {
        try {
            const requestBody = {
                policy_id: currentPolicyId,
                requester: "agent://ui_demo",
                action: {
                    type: "wire_transfer",
                    http_method: "POST",
                    resource: "/wallets/primary",
                    amount_usd: 2000
                },
                reasoning_trace: "High value wire transfer of $2000."
            };

            const res = await fetch(`${API_BASE}/v1/authorize`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': AUTH_HEADER,
                    'x-solana-tx-signature': buildMockPaymentToken(requestBody)
                },
                body: JSON.stringify(requestBody)
            });

            const data = await res.json();
            if (res.ok) {
                log(`x402 Payment Verified! Action Unlocked.`, 'success');
                log(`Immutable Audit Anchor: <a href="https://explorer.solana.com/tx/${data.receipt_signature}?cluster=devnet" target="_blank" style="color:var(--solana-green)">${data.receipt_signature.substring(0, 25)}...</a>`, 'solana');
                btnUnlock.textContent = "Verified";
                btnUnlock.disabled = true;
                btnHighRisk.disabled = false;
            } else {
                log(`Failed: ${JSON.stringify(data)}`, 'error');
                btnUnlock.textContent = "Sign & Execute Transfer";
            }
        } catch (e) {
            log(`Error: ${e.message}`, 'error');
            btnUnlock.textContent = "Sign & Execute Transfer";
        }
    }, 800);
});

// NEW EXPENSIVE API DEMO FLOW
const geminiTaskInput = document.getElementById('gemini-task-input');

btnExpensiveApi.addEventListener('click', async () => {
    const taskText = geminiTaskInput.value.trim();
    if (!taskText) {
        log(`Error: Please enter a task for the agent.`, 'error');
        return;
    }

    log(`[Agent] Generating intent for task via Gemini...`, 'info');

    try {
        // STEP 1: Generate Intent via Gemini
        const intentRes = await fetch(`${API_BASE}/v1/agent/intent`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': AUTH_HEADER
            },
            body: JSON.stringify({
                policy_id: currentPolicyId,
                task: taskText
            })
        });

        if (!intentRes.ok) {
            const data = await intentRes.json();
            log(`Gemini Intent Generation Failed: ${JSON.stringify(data)}`, 'error');
            return;
        }

        const agentIntent = await intentRes.json();
        log(`[Agent] Intent generated: ${agentIntent.action.type} for $${agentIntent.action.amount_usd}`, 'info');
        log(`[Agent] Reasoning: ${agentIntent.reasoning_trace}`, 'info');

        // STEP 2: Ask Sentinel-Auth for authorization
        log(`[Agent] Requesting permission from Sentinel-Auth...`, 'info');
        const sentinelRes = await fetch(`${API_BASE}/v1/authorize`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': AUTH_HEADER
            },
            body: JSON.stringify(agentIntent)
        });

        // STEP 3: Evaluate Sentinel's Decision
        if (sentinelRes.status === 403) {
            const data = await sentinelRes.json();
            log(`🚨 FLAG TRIPPED: Sentinel-Auth blocked the request!`, 'error');
            log(`Reason: ${data.detail.error.message}`, 'error');
            log(`The expensive ngrok API was NOT called.`, 'success');
        } else if (sentinelRes.status === 402) {
            const data = await sentinelRes.json();
            log(`🚨 FLAG TRIPPED: 402 Payment Required!`, 'error');
            log(`Action exceeds risk threshold. Solana x402 verification required before calling ngrok.`, 'warning');
        } else if (sentinelRes.ok) {
            const data = await sentinelRes.json();
            log(`Sentinel Approved. Receipt: <a href="https://explorer.solana.com/tx/${data.receipt_signature}?cluster=devnet" target="_blank" style="color:var(--solana-green)">${data.receipt_signature.substring(0, 25)}...</a>`, 'success');

            // STEP 4: Actually execute the expensive API call since it was approved
            log(`Executing request to ${NGROK_URL}...`, 'info');
            try {
                const targetRes = await fetch(NGROK_URL, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ authorized_by: "Sentinel-Auth", receipt: data.receipt_signature })
                });
                log(`ngrok API responded with status: ${targetRes.status}`, 'success');
            } catch (err) {
                log(`ngrok API call failed: ${err.message}`, 'error');
            }
        }
    } catch (e) {
        log(`Error: ${e.message}`, 'error');
    }
});

log('Frontend initialized. Ready.', 'info');