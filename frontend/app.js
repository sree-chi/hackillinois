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
let currentIssuedClientId = "";
let currentAccount = null;
let currentLinkedWallets = [];
let selectedWalletAddress = "";
let phantomProviderReady = false;

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
const connectWalletButton = document.getElementById("connect-wallet-button");
const refreshWalletButton = document.getElementById("refresh-wallet-button");
const unlinkWalletButton = document.getElementById("unlink-wallet-button");
const walletStatus = document.getElementById("wallet-status");
const walletList = document.getElementById("wallet-list");
const walletAddressLabel = document.getElementById("wallet-address-label");
const walletBalanceLabel = document.getElementById("wallet-balance-label");
const walletNetworkLabel = document.getElementById("wallet-network-label");
const walletLastSync = document.getElementById("wallet-last-sync");
const walletTransactionList = document.getElementById("wallet-transaction-list");

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

function formatDate(value) {
    if (!value) {
        return "Not available";
    }
    return new Date(value).toLocaleString();
}

function bytesToBase64(bytes) {
    const chars = Array.from(bytes, (byte) => String.fromCharCode(byte)).join("");
    return window.btoa(chars);
}

function setWalletStatus(message, type = "info") {
    walletStatus.textContent = message;
    walletStatus.dataset.state = type;
}

function resetWalletOverview(message = "Link a wallet to load recent transactions.") {
    walletAddressLabel.textContent = "No wallet selected.";
    walletBalanceLabel.textContent = "0 SOL";
    walletNetworkLabel.textContent = "Not loaded";
    walletLastSync.textContent = "Not synced";
    walletTransactionList.innerHTML = `<div class="empty-state">${message}</div>`;
}

function renderLinkedWallets(wallets) {
    currentLinkedWallets = wallets;
    if (!wallets.length) {
        walletList.innerHTML = '<div class="empty-state">No wallets linked to this account.</div>';
        setWalletStatus(phantomProviderReady ? "No wallet linked yet." : "Phantom wallet not detected yet.");
        return;
    }

    setWalletStatus(`${wallets.length} wallet${wallets.length === 1 ? "" : "s"} linked to this account.`, "success");
    walletList.innerHTML = wallets.map((wallet) => `
        <article class="activity-card ${wallet.wallet_address === selectedWalletAddress ? "activity-success" : ""}">
            <div class="activity-header">
                <div>
                    <p class="activity-title">${wallet.provider} <span>${wallet.wallet_address}</span></p>
                    <p class="activity-meta">Linked ${formatDate(wallet.connected_at)}</p>
                </div>
                <button class="btn btn-ghost" type="button" data-wallet-select="${wallet.wallet_address}">View wallet</button>
            </div>
        </article>
    `).join("");
}

function renderWalletOverview(overview) {
    const { wallet, network, balance_sol: balanceSol, fetched_at: fetchedAt, transactions } = overview;
    walletAddressLabel.textContent = wallet.wallet_address;
    walletBalanceLabel.textContent = `${Number(balanceSol).toFixed(4)} SOL`;
    walletNetworkLabel.textContent = network;
    walletLastSync.textContent = formatDate(fetchedAt);

    if (!transactions.length) {
        walletTransactionList.innerHTML = '<div class="empty-state">No recent transactions found for this wallet.</div>';
        return;
    }

    walletTransactionList.innerHTML = transactions.map((entry) => `
        <article class="activity-card ${entry.success ? "activity-success" : "activity-danger"}">
            <div class="activity-header">
                <div>
                    <p class="activity-title">${entry.success ? "Confirmed" : "Failed"} <span>${entry.signature}</span></p>
                    <p class="activity-meta">${formatDate(entry.block_time)} | Slot ${entry.slot ?? "unknown"} | ${entry.confirmation_status || "unknown"}</p>
                </div>
                <span class="status-pill ${entry.success ? "status-success" : "status-danger"}">
                    ${entry.native_change_lamports == null ? "n/a" : `${(entry.native_change_lamports / 1_000_000_000).toFixed(4)} SOL`}
                </span>
            </div>
            <p class="activity-message">${entry.memo || "No memo attached to this transaction."}</p>
            <a href="${entry.explorer_url}" target="_blank" rel="noreferrer">Open in Solana Explorer</a>
        </article>
    `).join("");
}

function getPhantomProvider() {
    const provider = window.phantom?.solana || window.solana;
    return provider?.isPhantom ? provider : null;
}

function updateWalletProviderState() {
    phantomProviderReady = Boolean(getPhantomProvider());
    if (!currentSessionToken) {
        setWalletStatus("Sign in to connect a Phantom wallet.");
        return;
    }
    if (!currentLinkedWallets.length) {
        setWalletStatus(
            phantomProviderReady
                ? "Phantom detected. Connect your wallet to link it to this account."
                : "Phantom wallet was not detected. Open this site on HTTPS or localhost with the extension enabled.",
            phantomProviderReady ? "success" : "error",
        );
    }
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
                <div class="action-row">
                    <span class="status-pill ${entry.revoked_at ? "status-danger" : entry.suspended_at ? "status-warning" : "status-success"}">
                        ${entry.revoked_at ? "revoked" : entry.suspended_at ? "suspended" : "active"}
                    </span>
                    <button
                        class="btn btn-ghost"
                        type="button"
                        data-suspend-key="${entry.client_id}"
                        ${entry.revoked_at || entry.suspended_at ? "disabled" : ""}
                    >
                        Temp remove
                    </button>
                    <button
                        class="btn btn-ghost"
                        type="button"
                        data-restore-key="${entry.client_id}"
                        ${entry.revoked_at || !entry.suspended_at ? "disabled" : ""}
                    >
                        Restore
                    </button>
                    <button
                        class="btn btn-ghost"
                        type="button"
                        data-revoke-key="${entry.client_id}"
                        ${entry.revoked_at ? "disabled" : ""}
                    >
                        Permanent
                    </button>
                </div>
            </div>
            <p class="activity-message">
                Prefix ${entry.api_key_prefix}
                ${entry.last_used_at ? ` | Last used ${new Date(entry.last_used_at).toLocaleString()}` : " | Not used yet"}
                ${entry.suspended_at ? ` | Suspended ${new Date(entry.suspended_at).toLocaleString()}` : ""}
                ${entry.revoked_at ? ` | Revoked ${new Date(entry.revoked_at).toLocaleString()}` : ""}
            </p>
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
        currentLinkedWallets = [];
        selectedWalletAddress = "";
        renderLinkedWallets([]);
        resetWalletOverview();
    }

    createPolicyButton.disabled = !(signedIn && currentApiKey);
    copyKeyButton.disabled = !(signedIn && currentApiKey);
    copyCurlButton.disabled = !(signedIn && currentApiKey);
    copyJsButton.disabled = !(signedIn && currentApiKey);
    runAuthorizeButton.disabled = !(signedIn && currentApiKey && currentPolicyId);
    connectWalletButton.disabled = !signedIn;
    refreshWalletButton.disabled = !(signedIn && selectedWalletAddress);
    unlinkWalletButton.disabled = !(signedIn && selectedWalletAddress);
    updateWalletProviderState();
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
        renderLinkedWallets(data.linked_wallets || []);
        if (currentLinkedWallets.length) {
            selectedWalletAddress = currentLinkedWallets.some((wallet) => wallet.wallet_address === selectedWalletAddress)
                ? selectedWalletAddress
                : currentLinkedWallets[0].wallet_address;
            renderLinkedWallets(currentLinkedWallets);
            await fetchWalletOverview(selectedWalletAddress, false);
        } else {
            selectedWalletAddress = "";
            resetWalletOverview();
        }
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

async function fetchWalletOverview(walletAddress, shouldLog = true) {
    if (!walletAddress || !currentSessionToken) {
        return;
    }

    const response = await fetch(`${API_BASE}/v1/accounts/me/solana/wallets/${walletAddress}`, {
        headers: {
            Authorization: `Bearer ${currentSessionToken}`,
        },
    });
    const data = await readApiResponse(response);
    if (!response.ok) {
        throw new Error(JSON.stringify(data));
    }

    selectedWalletAddress = walletAddress;
    renderLinkedWallets(currentLinkedWallets);
    renderWalletOverview(data);
    updateDashboardState();
    if (shouldLog) {
        log(`Loaded Solana wallet overview for ${walletAddress}`, "success");
    }
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

walletList.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-wallet-select]");
    if (!button) {
        return;
    }
    try {
        await fetchWalletOverview(button.dataset.walletSelect);
    } catch (error) {
        log(`Wallet overview failed: ${error.message}`, "error");
    }
});

apiKeyList.addEventListener("click", async (event) => {
    const suspendButton = event.target.closest("[data-suspend-key]");
    const restoreButton = event.target.closest("[data-restore-key]");
    const revokeButton = event.target.closest("[data-revoke-key]");
    const button = suspendButton || restoreButton || revokeButton;
    if (!button || !currentSessionToken) {
        return;
    }

    const clientId = button.dataset.suspendKey || button.dataset.restoreKey || button.dataset.revokeKey;
    const path = button.dataset.suspendKey
        ? `/v1/accounts/me/keys/${clientId}/suspend`
        : button.dataset.restoreKey
            ? `/v1/accounts/me/keys/${clientId}/restore`
            : `/v1/accounts/me/keys/${clientId}`;
    const method = button.dataset.revokeKey ? "DELETE" : "POST";
    button.disabled = true;
    try {
        const response = await fetch(`${API_BASE}${path}`, {
            method,
            headers: {
                Authorization: `Bearer ${currentSessionToken}`,
            },
        });
        const data = await readApiResponse(response);
        if (!response.ok) {
            throw new Error(JSON.stringify(data));
        }

        if (currentApiKey && currentIssuedClientId === clientId) {
            if (button.dataset.revokeKey) {
                currentApiKey = "";
                currentIssuedClientId = "";
                localStorage.removeItem(STORAGE_KEYS.apiKey);
                issuedKey.textContent = "Key deleted.";
                issuedKeyMeta.textContent = "The selected API key was permanently revoked.";
            } else if (button.dataset.suspendKey) {
                issuedKeyMeta.textContent = "The selected API key is temporarily disabled.";
            } else if (button.dataset.restoreKey) {
                issuedKeyMeta.textContent = "The selected API key is active again.";
            }
        }
        updateSnippets();
        updateDashboardState();
        await fetchDashboard();
        log(
            button.dataset.suspendKey
                ? `Temporarily disabled API key ${clientId}`
                : button.dataset.restoreKey
                    ? `Restored API key ${clientId}`
                    : `Permanently revoked API key ${clientId}`,
            "success"
        );
    } catch (error) {
        button.disabled = false;
        log(`API key update failed: ${error.message}`, "error");
    }
});

connectWalletButton.addEventListener("click", async () => {
    if (!currentSessionToken) {
        log("Sign in before linking a wallet.", "error");
        return;
    }

    const provider = getPhantomProvider();
    if (!provider) {
        setWalletStatus("Phantom wallet was not detected. Open this site on HTTPS or localhost with the extension enabled.", "error");
        log("Phantom wallet was not detected. Install Phantom and open this site on HTTPS or localhost.", "error");
        return;
    }

    try {
        setWalletStatus("Connecting to Phantom...", "info");
        const connection = await provider.connect({ onlyIfTrusted: false });
        const walletAddress = connection.publicKey?.toString() || provider.publicKey?.toString();
        if (!walletAddress) {
            throw new Error("Phantom did not return a wallet address.");
        }

        const challengeResponse = await fetch(`${API_BASE}/v1/accounts/me/solana/challenge`, {
            method: "POST",
            headers: sessionHeaders(),
            body: JSON.stringify({
                wallet_address: walletAddress,
                provider: "phantom",
            }),
        });
        const challenge = await readApiResponse(challengeResponse);
        if (!challengeResponse.ok) {
            throw new Error(JSON.stringify(challenge));
        }

        const encodedMessage = new TextEncoder().encode(challenge.message);
        const signed = await provider.signMessage(encodedMessage, "utf8");
        const signature = bytesToBase64(signed.signature || signed);

        const linkResponse = await fetch(`${API_BASE}/v1/accounts/me/solana/link`, {
            method: "POST",
            headers: sessionHeaders(),
            body: JSON.stringify({
                wallet_address: walletAddress,
                provider: "phantom",
                nonce: challenge.nonce,
                signed_message: challenge.message,
                signature,
            }),
        });
        const linkedWallet = await readApiResponse(linkResponse);
        if (!linkResponse.ok) {
            throw new Error(JSON.stringify(linkedWallet));
        }

        selectedWalletAddress = linkedWallet.wallet_address;
        await fetchDashboard();
        setWalletStatus(`Linked wallet ${linkedWallet.wallet_address}`, "success");
        log(`Linked Phantom wallet ${linkedWallet.wallet_address}`, "success");
    } catch (error) {
        setWalletStatus(`Wallet link failed: ${error.message}`, "error");
        log(`Wallet link failed: ${error.message}`, "error");
    }
});

refreshWalletButton.addEventListener("click", async () => {
    if (!selectedWalletAddress) {
        log("Select a linked wallet before refreshing.", "error");
        return;
    }
    try {
        await fetchWalletOverview(selectedWalletAddress);
    } catch (error) {
        log(`Wallet refresh failed: ${error.message}`, "error");
    }
});

unlinkWalletButton.addEventListener("click", async () => {
    if (!selectedWalletAddress) {
        log("Select a linked wallet before unlinking.", "error");
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/v1/accounts/me/solana/wallets/${selectedWalletAddress}`, {
            method: "DELETE",
            headers: {
                Authorization: `Bearer ${currentSessionToken}`,
            },
        });
        const data = await readApiResponse(response);
        if (!response.ok) {
            throw new Error(JSON.stringify(data));
        }
        const removedWallet = selectedWalletAddress;
        selectedWalletAddress = "";
        await fetchDashboard();
        setWalletStatus(`Unlinked wallet ${removedWallet}`, "info");
        log(`Unlinked wallet ${removedWallet}`, "success");
    } catch (error) {
        setWalletStatus(`Wallet unlink failed: ${error.message}`, "error");
        log(`Wallet unlink failed: ${error.message}`, "error");
    }
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
        currentIssuedClientId = data.client_id;
        saveLocalState();
        issuedKey.textContent = data.api_key;
        issuedKeyMeta.textContent = `Prefix ${data.api_key_prefix} issued for ${data.owner_email}. Client ${data.client_id}.`;
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
updateWalletProviderState();
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

window.addEventListener("focus", updateWalletProviderState);
window.addEventListener("load", updateWalletProviderState);
