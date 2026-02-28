const API_BASE = resolveApiBase();
const STORAGE_KEYS = {
    apiBase: "sentinel.apiBase",
    apiKey: "sentinel.apiKey",
    policyId: "sentinel.policyId",
};

let currentApiKey = localStorage.getItem(STORAGE_KEYS.apiKey) || "";
let currentPolicyId = localStorage.getItem(STORAGE_KEYS.policyId) || "";

const docsLink = document.getElementById("docs-link");
const apiBaseLabel = document.getElementById("api-base-label");
const apiStatus = document.getElementById("api-status");
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

function persistSession() {
    localStorage.setItem(STORAGE_KEYS.apiBase, API_BASE);
    if (currentApiKey) {
        localStorage.setItem(STORAGE_KEYS.apiKey, currentApiKey);
    }
    if (currentPolicyId) {
        localStorage.setItem(STORAGE_KEYS.policyId, currentPolicyId);
    }
}

async function readApiResponse(response) {
    const contentType = response.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
        return response.json();
    }

    return { message: await response.text() };
}

function updateSnippets() {
    if (!currentApiKey) {
        curlSnippet.textContent = "Issue a key to generate a ready-to-run cURL example.";
        jsSnippet.textContent = "Issue a key to generate a browser/server example.";
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
        "const res = await fetch(`${API_BASE}/v1/authorize`, {",
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

async function copyText(value, button) {
    await navigator.clipboard.writeText(value);
    const previous = button.textContent;
    button.textContent = "Copied";
    window.setTimeout(() => {
        button.textContent = previous;
    }, 1200);
}

function authHeaders() {
    return {
        Authorization: `Bearer ${currentApiKey}`,
        "Content-Type": "application/json",
    };
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
        log(`Connected to ${data.name}. Key endpoint: ${data.key_endpoint}`, "success");
    } catch (error) {
        apiStatus.textContent = "offline";
        log(`Portal bootstrap failed: ${error.message}`, "error");
    }
}

issueKeyForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    issueKeyButton.disabled = true;
    log("Requesting a new developer key from /v1/developer/keys ...");

    const payload = {
        app_name: document.getElementById("app-name").value.trim(),
        owner_email: document.getElementById("owner-email").value.trim(),
        owner_name: document.getElementById("owner-name").value.trim() || null,
        use_case: document.getElementById("use-case").value.trim() || null,
    };

    try {
        const response = await fetch(`${API_BASE}/v1/developer/keys`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });
        const data = await readApiResponse(response);

        if (!response.ok) {
            throw new Error(JSON.stringify(data));
        }

        currentApiKey = data.api_key;
        persistSession();
        issuedKey.textContent = data.api_key;
        issuedKeyMeta.textContent = `Prefix ${data.api_key_prefix} issued for ${data.app_name}. Docs: ${data.docs_url}`;
        createPolicyButton.disabled = false;
        copyKeyButton.disabled = false;
        copyCurlButton.disabled = false;
        copyJsButton.disabled = false;
        updateSnippets();
        log(`Issued key ${data.api_key_prefix} for ${data.owner_email}`, "success");
    } catch (error) {
        log(`Key issuance failed: ${error.message}`, "error");
    } finally {
        issueKeyButton.disabled = false;
    }
});

createPolicyButton.addEventListener("click", async () => {
    if (!currentApiKey) {
        return;
    }

    createPolicyButton.disabled = true;
    log("Creating starter policy with the issued key ...");

    try {
        const response = await fetch(`${API_BASE}/v1/policies`, {
            method: "POST",
            headers: {
                ...authHeaders(),
                "Idempotency-Key": `portal-${Date.now()}`,
            },
            body: JSON.stringify({
                name: "Public portal starter policy",
                description: "Default policy issued from the public developer portal.",
                rules: {
                    allowed_http_methods: ["GET", "POST"],
                    max_spend_usd: 5000,
                    max_requests_per_minute: 60,
                },
            }),
        });
        const data = await readApiResponse(response);

        if (!response.ok) {
            throw new Error(JSON.stringify(data));
        }

        currentPolicyId = data.id;
        persistSession();
        policyIdLabel.textContent = currentPolicyId;
        runAuthorizeButton.disabled = false;
        updateSnippets();
        log(`Starter policy created: ${currentPolicyId}`, "success");
    } catch (error) {
        log(`Starter policy creation failed: ${error.message}`, "error");
        createPolicyButton.disabled = false;
    }
});

runAuthorizeButton.addEventListener("click", async () => {
    if (!currentApiKey || !currentPolicyId) {
        return;
    }

    runAuthorizeButton.disabled = true;
    log("Submitting sample agent action to /v1/authorize ...");

    try {
        const response = await fetch(`${API_BASE}/v1/authorize`, {
            method: "POST",
            headers: authHeaders(),
            body: JSON.stringify({
                policy_id: currentPolicyId,
                requester: "agent://public-portal-demo",
                action: {
                    type: "knowledge_sync",
                    http_method: "POST",
                    resource: "/agents/sync",
                    amount_usd: 250,
                },
                reasoning_trace: "Sync the managed agent memory after a successful customer support workflow.",
            }),
        });
        const data = await readApiResponse(response);

        if (!response.ok) {
            throw new Error(JSON.stringify(data));
        }

        log(`Authorization allowed. Receipt: ${data.receipt_signature}`, "success");
    } catch (error) {
        log(`Authorization request failed: ${error.message}`, "error");
    } finally {
        runAuthorizeButton.disabled = false;
    }
});

copyKeyButton.addEventListener("click", () => copyText(currentApiKey, copyKeyButton));
copyCurlButton.addEventListener("click", () => copyText(curlSnippet.textContent, copyCurlButton));
copyJsButton.addEventListener("click", () => copyText(jsSnippet.textContent, copyJsButton));

loadOverview();
updateSnippets();
if (currentApiKey) {
    issuedKey.textContent = currentApiKey;
    issuedKeyMeta.textContent = "Loaded from local browser storage.";
    createPolicyButton.disabled = false;
    copyKeyButton.disabled = false;
    copyCurlButton.disabled = false;
    copyJsButton.disabled = false;
}
if (currentPolicyId) {
    policyIdLabel.textContent = currentPolicyId;
    runAuthorizeButton.disabled = false;
}
log("Developer portal ready.");
