const API_BASE = resolveApiBase();
const STORAGE_KEYS = {
    apiBase: "sentinel.apiBase",
    apiKey: "sentinel.apiKey",
    policyId: "sentinel.policyId",
    sessionToken: "sentinel.sessionToken",
};

let currentApiKey = localStorage.getItem(STORAGE_KEYS.apiKey) || "";
let currentPolicyId = localStorage.getItem(STORAGE_KEYS.policyId) || "";
let currentSessionToken = localStorage.getItem(STORAGE_KEYS.sessionToken) || "";
let currentAccount = null;

const docsLink = document.getElementById("docs-link");
const apiBaseLabel = document.getElementById("api-base-label");
const apiStatus = document.getElementById("api-status");
const authView = document.getElementById("auth-view");
const dashboardView = document.getElementById("dashboard-view");
const registerForm = document.getElementById("register-form");
const loginForm = document.getElementById("login-form");
const logoutButton = document.getElementById("logout-button");
const issueKeyForm = document.getElementById("issue-key-form");
const issueKeyButton = document.getElementById("issue-key-button");
const issuedKey = document.getElementById("issued-key");
const issuedKeyMeta = document.getElementById("issued-key-meta");
const copyKeyButton = document.getElementById("copy-key-button");
const copyCurlButton = document.getElementById("copy-curl-button");
const copyJsButton = document.getElementById("copy-js-button");
const curlSnippet = document.getElementById("curl-snippet");
const jsSnippet = document.getElementById("js-snippet");
const createPolicyButton = document.getElementById("create-policy-button");
const runAuthorizeButton = document.getElementById("run-authorize-button");
const policyIdLabel = document.getElementById("policy-id-label");
const consoleEl = document.getElementById("console-output");
const accountSummary = document.getElementById("account-summary");
const sessionMeta = document.getElementById("session-meta");
const apiKeyList = document.getElementById("api-key-list");

function resolveApiBase() {
    const { hostname, origin } = window.location;
    const isLocalhost = hostname === "localhost" || hostname === "127.0.0.1";
    return isLocalhost ? "http://localhost:8000" : `${origin}/server`;
}

function log(message, type = "info") {
    const time = new Date().toLocaleTimeString();
    const row = document.createElement("div");
    row.className = `log-entry log-${type}`;
    row.innerHTML = `<span class="log-time">[${time}]</span>${message}`;
    consoleEl.appendChild(row);
    consoleEl.scrollTop = consoleEl.scrollHeight;
}

function saveLocalState() {
    localStorage.setItem(STORAGE_KEYS.apiBase, API_BASE);
    if (currentApiKey) {
        localStorage.setItem(STORAGE_KEYS.apiKey, currentApiKey);
    }
    if (currentPolicyId) {
        localStorage.setItem(STORAGE_KEYS.policyId, currentPolicyId);
    }
    if (currentSessionToken) {
        localStorage.setItem(STORAGE_KEYS.sessionToken, currentSessionToken);
    }
}

function clearSession() {
    currentSessionToken = "";
    currentAccount = null;
    localStorage.removeItem(STORAGE_KEYS.sessionToken);
}

async function readApiResponse(response) {
    const contentType = response.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
        return response.json();
    }
    return { message: await response.text() };
}

function sessionHeaders() {
    return {
        Authorization: `Bearer ${currentSessionToken}`,
        "Content-Type": "application/json",
    };
}

function apiHeaders() {
    return {
        Authorization: `Bearer ${currentApiKey}`,
        "Content-Type": "application/json",
    };
}

function updateSnippets() {
    if (!currentApiKey) {
        curlSnippet.textContent = "Sign in and issue a key to generate a ready-to-run cURL example.";
        jsSnippet.textContent = "Sign in and issue a key to generate a browser/server example.";
        return;
    }

    curlSnippet.textContent = [
        `curl -X POST ${API_BASE}/v1/policies \\`,
        `  -H "Authorization: Bearer ${currentApiKey}" \\`,
        `  -H "Content-Type: application/json" \\`,
        "  -d '{",
        '    "name": "Agent spending policy",',
        '    "rules": {',
        '      "allowed_http_methods": ["GET", "POST"],',
        '      "max_spend_usd": 5000,',
        '      "max_requests_per_minute": 60',
        "    }",
        "  }'",
    ].join("\n");

    jsSnippet.textContent = [
        `const BASE_URL = "${API_BASE}";`,
        "const res = await fetch(`${BASE_URL}/v1/authorize`, {",
        '  method: "POST",',
        "  headers: {",
        `    Authorization: "Bearer ${currentApiKey}",`,
        '    "Content-Type": "application/json"',
        "  },",
        "  body: JSON.stringify({",
        `    policy_id: "${currentPolicyId || "pol_your_policy_id"}",`,
        '    requester: "agent://ops-bot",',
        "    action: {",
        '      type: "wire_transfer",',
        '      http_method: "POST",',
        '      resource: "/wallets/treasury",',
        "      amount_usd: 250",
        "    },",
        '    reasoning_trace: "Routine treasury movement requested by the orchestration agent."',
        "  })",
        "});",
    ].join("\n");
}

function renderApiKeys(apiKeys) {
    if (!apiKeys.length) {
        apiKeyList.innerHTML = '<div class="empty-state">No keys issued yet.</div>';
        return;
    }

    apiKeyList.innerHTML = apiKeys.map((entry) => `
        <article class="activity-card activity-success">
            <div class="activity-header">
                <div>
                    <p class="activity-title">${entry.app_name}</p>
                    <p class="activity-meta">${entry.owner_email} | Created ${new Date(entry.created_at).toLocaleString()}</p>
                </div>
                <span class="status-pill status-success">${entry.revoked_at ? "revoked" : "active"}</span>
            </div>
            <p class="activity-message">Prefix ${entry.api_key_prefix}${entry.last_used_at ? ` | Last used ${new Date(entry.last_used_at).toLocaleString()}` : " | Not used yet"}</p>
        </article>
    `).join("");
}

function updateDashboardState() {
    const signedIn = Boolean(currentSessionToken && currentAccount);
    authView.classList.toggle("is-hidden", signedIn);
    dashboardView.classList.toggle("is-hidden", !signedIn);
    issueKeyButton.disabled = !signedIn;
    logoutButton.disabled = !signedIn;
    registerForm.querySelector("button").disabled = false;
    loginForm.querySelector("button").disabled = false;

    if (signedIn) {
        accountSummary.textContent = `${currentAccount.email}${currentAccount.full_name ? ` | ${currentAccount.full_name}` : ""}`;
        sessionMeta.textContent = "Account session active. You can issue and manage API keys from this dashboard.";
    } else {
        accountSummary.textContent = "Not signed in.";
        sessionMeta.textContent = "Create an account or sign in to issue keys.";
        renderApiKeys([]);
    }

    createPolicyButton.disabled = !(signedIn && currentApiKey);
    copyKeyButton.disabled = !(signedIn && currentApiKey);
    copyCurlButton.disabled = !(signedIn && currentApiKey);
    copyJsButton.disabled = !(signedIn && currentApiKey);
    runAuthorizeButton.disabled = !(signedIn && currentApiKey && currentPolicyId);
}

async function fetchDashboard() {
    if (!currentSessionToken) {
        updateDashboardState();
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/v1/accounts/me/dashboard`, {
            headers: {
                Authorization: `Bearer ${currentSessionToken}`,
            },
        });
        const data = await readApiResponse(response);
        if (!response.ok) {
            throw new Error(JSON.stringify(data));
        }

        currentAccount = data.account;
        renderApiKeys(data.api_keys || []);
        updateDashboardState();
    } catch (error) {
        clearSession();
        updateDashboardState();
        log(`Account session invalid: ${error.message}`, "error");
    }
}

async function authenticate(path, payload, successMessage) {
    const response = await fetch(`${API_BASE}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
    });
    const data = await readApiResponse(response);
    if (!response.ok) {
        throw new Error(JSON.stringify(data));
    }

    currentSessionToken = data.session_token;
    currentAccount = data.account;
    saveLocalState();
    await fetchDashboard();
    registerForm.reset();
    loginForm.reset();
    log(successMessage, "success");
}

async function loadOverview() {
    apiBaseLabel.textContent = API_BASE;
    try {
        const response = await fetch(`${API_BASE}/v1/public/overview`);
        const data = await readApiResponse(response);
        if (!response.ok) {
            throw new Error(data.message || "Failed to load overview");
        }

        apiStatus.textContent = data.status;
        docsLink.href = data.docs_url;
        docsLink.textContent = data.docs_url;
    } catch (error) {
        apiStatus.textContent = "offline";
        log(`Portal bootstrap failed: ${error.message}`, "error");
    }
}

registerForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
        await authenticate("/v1/accounts/register", {
            email: document.getElementById("register-email").value.trim(),
            password: document.getElementById("register-password").value,
            full_name: document.getElementById("register-full-name").value.trim() || null,
        }, "Account created and signed in.");
    } catch (error) {
        log(`Registration failed: ${error.message}`, "error");
    }
});

loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
        await authenticate("/v1/accounts/login", {
            email: document.getElementById("login-email").value.trim(),
            password: document.getElementById("login-password").value,
        }, "Signed in successfully.");
    } catch (error) {
        log(`Login failed: ${error.message}`, "error");
    }
});

logoutButton.addEventListener("click", () => {
    clearSession();
    updateDashboardState();
    log("Signed out of the dashboard.");
});

issueKeyForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!currentSessionToken) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/v1/developer/keys`, {
            method: "POST",
            headers: sessionHeaders(),
            body: JSON.stringify({
                app_name: document.getElementById("app-name").value.trim(),
                owner_name: document.getElementById("owner-name").value.trim() || null,
                use_case: document.getElementById("use-case").value.trim() || null,
            }),
        });
        const data = await readApiResponse(response);
        if (!response.ok) {
            throw new Error(JSON.stringify(data));
        }

        currentApiKey = data.api_key;
        saveLocalState();
        issuedKey.textContent = data.api_key;
        issuedKeyMeta.textContent = `Prefix ${data.api_key_prefix} issued for ${data.owner_email}.`;
        updateSnippets();
        updateDashboardState();
        await fetchDashboard();
        log(`Issued key ${data.api_key_prefix} for ${data.owner_email}`, "success");
    } catch (error) {
        log(`Key issuance failed: ${error.message}`, "error");
    }
});

createPolicyButton.addEventListener("click", async () => {
    if (!currentApiKey) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/v1/policies`, {
            method: "POST",
            headers: {
                ...apiHeaders(),
                "Idempotency-Key": `portal-${Date.now()}`,
            },
            body: JSON.stringify({
                name: document.getElementById("custom-policy-name").value.trim(),
                description: "Custom policy issued from the account dashboard.",
                rules: {
                    allowed_http_methods: ["GET", "POST"],
                    max_spend_usd: Number(document.getElementById("custom-spend-limit").value),
                    max_requests_per_minute: Number(document.getElementById("custom-rate-limit").value),
                },
            }),
        });
        const data = await readApiResponse(response);
        if (!response.ok) {
            throw new Error(JSON.stringify(data));
        }

        currentPolicyId = data.id;
        saveLocalState();
        policyIdLabel.textContent = currentPolicyId;
        updateSnippets();
        updateDashboardState();
        log(`Policy created: ${currentPolicyId}`, "success");
    } catch (error) {
        log(`Policy creation failed: ${error.message}`, "error");
    }
});

runAuthorizeButton.addEventListener("click", async () => {
    if (!currentApiKey || !currentPolicyId) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/v1/authorize`, {
            method: "POST",
            headers: apiHeaders(),
            body: JSON.stringify({
                policy_id: currentPolicyId,
                requester: "agent://account-dashboard-demo",
                action: {
                    type: "knowledge_sync",
                    http_method: "POST",
                    resource: "/agents/sync",
                    amount_usd: 250,
                },
                reasoning_trace: "Sync managed agent memory after a successful dashboard test workflow.",
            }),
        });
        const data = await readApiResponse(response);
        if (!response.ok) {
            throw new Error(JSON.stringify(data));
        }
        log(`Authorization allowed. Receipt: ${data.receipt_signature}`, "success");
    } catch (error) {
        log(`Authorization request failed: ${error.message}`, "error");
    }
});

async function copyText(value, button) {
    await navigator.clipboard.writeText(value);
    const previous = button.textContent;
    button.textContent = "Copied";
    window.setTimeout(() => {
        button.textContent = previous;
    }, 1200);
}

copyKeyButton.addEventListener("click", () => copyText(currentApiKey, copyKeyButton));
copyCurlButton.addEventListener("click", () => copyText(curlSnippet.textContent, copyCurlButton));
copyJsButton.addEventListener("click", () => copyText(jsSnippet.textContent, copyJsButton));

loadOverview();
updateSnippets();
if (currentApiKey) {
    issuedKey.textContent = currentApiKey;
    issuedKeyMeta.textContent = "Loaded latest API key from local browser storage.";
}
if (currentPolicyId) {
    policyIdLabel.textContent = currentPolicyId;
}
fetchDashboard();
updateDashboardState();
log("Account dashboard ready.");
