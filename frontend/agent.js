const STORAGE_KEYS = {
    apiBase: "sentinel.apiBase",
    apiKey: "sentinel.apiKey",
    policyId: "sentinel.policyId",
};

const form = document.getElementById("agent-form");
const apiBaseInput = document.getElementById("agent-api-base");
const apiKeyInput = document.getElementById("agent-api-key");
const policyIdInput = document.getElementById("agent-policy-id");
const humanCommandInput = document.getElementById("human-command");
const runButton = document.getElementById("run-agent-button");

const intentOutput = document.getElementById("agent-intent-output");
const decisionHeader = document.getElementById("agent-decision-header");
const decisionOutput = document.getElementById("agent-decision-output");

function resolveDefaultApiBase() {
    const { hostname, origin } = window.location;
    const isLocalhost = hostname === "localhost" || hostname === "127.0.0.1";
    return isLocalhost ? "http://localhost:8000" : `${origin}/server`;
}

function loadSavedContext() {
    apiBaseInput.value = localStorage.getItem(STORAGE_KEYS.apiBase) || resolveDefaultApiBase();
    apiKeyInput.value = localStorage.getItem(STORAGE_KEYS.apiKey) || "";
    policyIdInput.value = localStorage.getItem(STORAGE_KEYS.policyId) || "";
}

function saveContext() {
    localStorage.setItem(STORAGE_KEYS.apiBase, apiBaseInput.value.trim());
    localStorage.setItem(STORAGE_KEYS.apiKey, apiKeyInput.value.trim());
    localStorage.setItem(STORAGE_KEYS.policyId, policyIdInput.value.trim());
}

async function readJson(response) {
    const text = await response.text();
    try {
        return JSON.parse(text);
    } catch {
        return { message: text };
    }
}

async function runAgent() {
    const baseUrl = apiBaseInput.value.trim().replace(/\/$/, "");
    const apiKey = apiKeyInput.value.trim();
    const policyId = policyIdInput.value.trim();
    const humanCommand = humanCommandInput.value.trim();

    if (!baseUrl || !apiKey || !policyId || !humanCommand) {
        alert("API base URL, API key, policy ID, and human command are all required.");
        return;
    }

    saveContext();
    runButton.disabled = true;
    runButton.textContent = "Agent is thinking...";

    intentOutput.textContent = "Waiting for Gemini...";
    decisionHeader.className = "alert-card alert-neutral";
    decisionHeader.innerHTML = "<strong>Evaluating...</strong>";
    decisionOutput.textContent = "Waiting for intent...";

    try {
        // Step 1: Generate Intent from Gemini
        const intentResponse = await fetch(`${baseUrl}/v1/agent/intent`, {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${apiKey}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                policy_id: policyId,
                human_command: humanCommand
            })
        });

        const intentData = await readJson(intentResponse);

        if (!intentResponse.ok) {
            throw new Error(`Gemini Error: ${intentData.detail || intentData.message || JSON.stringify(intentData)}`);
        }

        // Display Gemini Intent
        intentOutput.textContent = JSON.stringify(intentData, null, 2);

        // Step 2: Send Intent to Sentinel Auth
        runButton.textContent = "Evaluating intent...";

        const proxyResponse = await fetch(`${baseUrl}/v1/authorize`, {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${apiKey}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify(intentData)
        });

        const decisionData = await readJson(proxyResponse);

        // Display Sentinel Decision
        decisionOutput.textContent = JSON.stringify(decisionData, null, 2);

        if (proxyResponse.ok) {
            decisionHeader.className = "alert-card alert-success";
            decisionHeader.innerHTML = `<strong>APPROVED! Solana Receipt anchored: ${decisionData.receipt_signature || "N/A"}</strong>`;
        } else {
            decisionHeader.className = "alert-card alert-danger";
            const errstr = typeof decisionData.detail === 'string'
                ? decisionData.detail
                : (decisionData.detail?.error?.message || "Unknown error");

            decisionHeader.innerHTML = `<strong>BLOCKED BY SENTINEL: ${errstr}</strong>`;
        }

    } catch (error) {
        intentOutput.textContent = "Failed to run agent.";
        decisionHeader.className = "alert-card alert-danger";
        decisionHeader.innerHTML = `<strong>ERROR</strong>`;
        decisionOutput.textContent = error.message;
    } finally {
        runButton.disabled = false;
        runButton.textContent = "Run Agent Process";
    }
}

form.addEventListener("submit", async (event) => {
    event.preventDefault();
    await runAgent();
});

loadSavedContext();
