// ── State ─────────────────────────────────────────────────────────────────
const STORAGE_KEYS = {
    apiBase: "sentinel.apiBase",
    apiKey: "sentinel.apiKey",
    policyId: "sentinel.policyId",
    sessionToken: "sentinel.sessionToken",
};

let STATE = {
    apiBase: resolveApiBase(),
    apiKey: localStorage.getItem(STORAGE_KEYS.apiKey) || "",
    policyId: localStorage.getItem(STORAGE_KEYS.policyId) || "",
    sessionToken: localStorage.getItem(STORAGE_KEYS.sessionToken) || "",
    allAudits: [],
    agents: [],
    apiKeys: [],
    account: null,
    currentFilter: "all",
};

function resolveApiBase() {
    const { hostname, origin } = window.location;
    const isLocalhost = hostname === "localhost" || hostname === "127.0.0.1";
    return isLocalhost ? "http://localhost:8000" : `${origin}/server`;
}

// ── DOM refs ──────────────────────────────────────────────────────────────
const cfgApiKey = document.getElementById("cfg-api-key");
const cfgPolicyId = document.getElementById("cfg-policy-id");
const loadBtn = document.getElementById("load-btn");
const killSwitchBtn = document.getElementById("kill-switch-btn");
const ksOverlay = document.getElementById("ks-confirm-overlay");
const ksCancelBtn = document.getElementById("ks-cancel-btn");
const ksConfirmBtn = document.getElementById("ks-confirm-btn");
const accountChip = document.getElementById("account-chip");
const toastStack = document.getElementById("toast-stack");

// Stats
const statTotal = document.getElementById("stat-total");
const statAllowed = document.getElementById("stat-allowed");
const statBlocked = document.getElementById("stat-blocked");
const statAnchored = document.getElementById("stat-anchored");
const statSpend = document.getElementById("stat-spend");

// Budget
const budgetBar = document.getElementById("budget-bar");
const budgetSpent = document.getElementById("budget-spent");
const budgetLimit = document.getElementById("budget-limit");
const budgetSub = document.getElementById("budget-sub");
const budgetRemLabel = document.getElementById("budget-remaining-label");

// Agents
const agentList = document.getElementById("agent-list");
const agentCount = document.getElementById("agent-count");
const newAgentName = document.getElementById("new-agent-name");
const newAgentWallet = document.getElementById("new-agent-wallet");
const addAgentBtn = document.getElementById("add-agent-btn");

// Audit
const auditFeed = document.getElementById("audit-feed");
const auditCount = document.getElementById("audit-count");

// ── Utilities ─────────────────────────────────────────────────────────────
function esc(val) {
    return String(val ?? "")
        .replace(/&/g, "&amp;").replace(/</g, "&lt;")
        .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

async function apiFetch(path, opts = {}) {
    const url = `${STATE.apiBase}${path}`;
    const res = await fetch(url, opts);
    const ct = res.headers.get("content-type") || "";
    const body = ct.includes("application/json") ? await res.json() : { message: await res.text() };
    if (!res.ok) throw Object.assign(new Error(body?.detail?.error?.message || body?.message || JSON.stringify(body)), { status: res.status });
    return body;
}

function apiHeaders() {
    return { Authorization: `Bearer ${STATE.apiKey}`, "Content-Type": "application/json" };
}
function sessionHeaders() {
    return { Authorization: `Bearer ${STATE.sessionToken}`, "Content-Type": "application/json" };
}
function accountIdentity(account) { return account.email || account.phone_number; }

function toast(msg, type = "info") {
    const el = document.createElement("div");
    el.className = `toast toast-${type}`;
    el.textContent = msg;
    toastStack.appendChild(el);
    setTimeout(() => el.remove(), 3800);
}

function fmt(val, decimals = 2) {
    if (val === null || val === undefined) return "—";
    return Number(val).toLocaleString("en-US", { maximumFractionDigits: decimals });
}

function fmtUSD(val) {
    if (val === null || val === undefined) return "—";
    return `$${Number(val).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
}

function timeAgo(isoStr) {
    if (!isoStr) return "—";
    const diff = Date.now() - new Date(isoStr).getTime();
    const s = Math.floor(diff / 1000);
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    return new Date(isoStr).toLocaleDateString();
}

// ── Load session / account ─────────────────────────────────────────────────
async function loadAccountInfo() {
    if (!STATE.sessionToken) return;
    try {
        const data = await apiFetch("/v1/accounts/me/dashboard", { headers: { Authorization: `Bearer ${STATE.sessionToken}` } });
        STATE.account = data.account;
        STATE.apiKeys = data.api_keys || [];
        accountChip.textContent = accountIdentity(STATE.account);
        killSwitchBtn.disabled = STATE.apiKeys.filter(k => !k.revoked_at && !k.suspended_at).length === 0;
    } catch { /* session may have expired */ }
}

// ── Stats ─────────────────────────────────────────────────────────────────
async function loadStats() {
    const data = await apiFetch(`/v1/audits/${STATE.policyId}/stats`, { headers: apiHeaders() });
    statTotal.textContent = fmt(data.total_requests, 0);
    statAllowed.textContent = fmt(data.allowed_requests, 0);
    statBlocked.textContent = fmt(data.blocked_requests, 0);
    statAnchored.textContent = fmt(data.anchored_receipts, 0);
    statSpend.textContent = fmtUSD(data.total_spend_usd);

    // Budget bar
    const spent = data.total_spend_usd || 0;
    const max = data.policy_max_spend_usd;
    const remaining = data.remaining_credit_usd;
    budgetSpent.textContent = fmtUSD(spent);
    if (max !== null && max !== undefined) {
        const pct = Math.min(100, (spent / max) * 100);
        budgetLimit.textContent = `/ ${fmtUSD(max)} limit`;
        budgetBar.style.width = `${pct}%`;
        budgetBar.className = "progress-fill" + (pct >= 90 ? " danger" : pct >= 70 ? " warning" : "");
        budgetSub.textContent = `${fmt(pct, 1)}% of policy budget consumed`;
        budgetRemLabel.textContent = `${fmtUSD(remaining)} remaining`;
    } else {
        budgetLimit.textContent = "/ No spend limit set";
        budgetBar.style.width = "0%";
        budgetSub.textContent = "This policy has no maximum spend limit configured.";
        budgetRemLabel.textContent = "Unlimited";
    }
}

// ── Agents ─────────────────────────────────────────────────────────────────
async function loadAgents() {
    if (!STATE.sessionToken) return;
    STATE.agents = await apiFetch("/v1/agents", { headers: { Authorization: `Bearer ${STATE.sessionToken}` } });
    renderAgents();
}

function agentIsActive(agent) {
    // An agent is "active" if it made a request in the last 5 minutes
    const fiveMinAgo = Date.now() - 5 * 60 * 1000;
    return STATE.allAudits.some(a => {
        const matchWallet = agent.wallet_address && a.agent_wallet === agent.wallet_address;
        const matchName = a.requester && a.requester.includes(agent.name.toLowerCase().replace(/\s+/g, "_"));
        return (matchWallet || matchName) && new Date(a.created_at).getTime() > fiveMinAgo;
    });
}

function renderAgents() {
    agentCount.textContent = `${STATE.agents.length} registered`;
    if (!STATE.agents.length) {
        agentList.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">🤖</div>
                No agents registered. Add one above to link a wallet address to a named identity.
            </div>`;
        return;
    }

    agentList.innerHTML = STATE.agents.map(agent => {
        const active = agentIsActive(agent);
        return `
        <div class="agent-row">
            <div class="agent-status-dot ${active ? "dot-active" : "dot-idle"}"></div>
            <div class="agent-info">
                <div class="agent-name">${esc(agent.name)}</div>
                <div class="agent-wallet">${agent.wallet_address ? esc(agent.wallet_address) : "No wallet linked"}</div>
            </div>
            <button class="btn-sm btn-sm-danger" data-delete-agent="${esc(agent.agent_id)}">Remove</button>
        </div>`;
    }).join("");
}

addAgentBtn.addEventListener("click", async () => {
    const name = newAgentName.value.trim();
    const wallet = newAgentWallet.value.trim() || null;
    if (!name) { toast("Agent name is required.", "error"); return; }
    if (!STATE.sessionToken) { toast("Sign in to register agents.", "error"); return; }
    addAgentBtn.disabled = true;
    try {
        await apiFetch("/v1/agents", {
            method: "POST",
            headers: sessionHeaders(),
            body: JSON.stringify({ name, wallet_address: wallet }),
        });
        newAgentName.value = "";
        newAgentWallet.value = "";
        await loadAgents();
        toast(`Agent "${name}" registered.`, "success");
    } catch (err) { toast(`Failed: ${err.message}`, "error"); }
    finally { addAgentBtn.disabled = false; }
});

agentList.addEventListener("click", async (e) => {
    const btn = e.target.closest("[data-delete-agent]");
    if (!btn) return;
    const id = btn.dataset.deleteAgent;
    btn.disabled = true;
    try {
        await apiFetch(`/v1/agents/${id}`, { method: "DELETE", headers: sessionHeaders() });
        await loadAgents();
        toast("Agent removed.", "info");
    } catch (err) {
        btn.disabled = false;
        toast(`Failed: ${err.message}`, "error");
    }
});

// ── Audit Feed ─────────────────────────────────────────────────────────────
async function loadAudits() {
    const data = await apiFetch(`/v1/audits/${STATE.policyId}`, { headers: apiHeaders() });
    STATE.allAudits = Array.isArray(data.data) ? data.data : [];
    auditCount.textContent = `${STATE.allAudits.length} events`;
    renderAuditFeed();
}

function verifyBadge(audit) {
    if (!audit.receipt_signature) return `<span class="verify-check fail">✗ No receipt</span>`;
    if (audit.receipt_signature.startsWith("mock_")) return `<span class="verify-check mock">⬡ Mock</span>`;
    return `<span class="verify-check ok">✓ Verified</span>`;
}

function renderAuditCard(audit) {
    const statusClass = audit.status === "allowed" ? "allowed" : "blocked";
    const badgeClass = audit.status === "allowed" ? "badge-allowed" : "badge-blocked";
    const receiptBadge = audit.receipt_status === "anchored" ? "badge-anchored" : "badge-pending";

    const traceHtml = audit.reasoning_trace
        ? `<div class="audit-trace">💬 ${esc(audit.reasoning_trace)}</div>`
        : "";

    const violationHtml = audit.violation?.explanation
        ? `<div class="audit-trace" style="border-left-color: var(--ent-red); background: rgba(239,68,68,0.06);">
               ⛔ ${esc(audit.violation.explanation)}
           </div>`
        : "";

    const solanaLink = audit.explorer_url
        ? `<a class="solana-link" href="${esc(audit.explorer_url)}" target="_blank" rel="noreferrer">
               🔗 View on Solana Explorer ↗
           </a>`
        : "";

    const sigShort = audit.receipt_signature
        ? audit.receipt_signature.substring(0, 20) + "…"
        : "None";
    const hashShort = audit.action_hash
        ? audit.action_hash.substring(0, 16) + "…"
        : "None";

    return `
    <div class="audit-card ${statusClass}">
        <div class="audit-top">
            <div class="audit-action">
                ${esc(audit.action_type)}
                <span>${esc(audit.http_method)} ${esc(audit.resource)}</span>
            </div>
            <div style="display:flex; gap:0.4rem; align-items:center; flex-shrink:0;">
                ${verifyBadge(audit)}
                <span class="status-badge ${badgeClass}">${esc(audit.status)}</span>
            </div>
        </div>
        <div class="audit-meta">
            <span>${esc(audit.requester)}</span>
            <span class="sep">·</span>
            <span>${timeAgo(audit.created_at)}</span>
            ${audit.amount_usd != null ? `<span class="sep">·</span><span>${fmtUSD(audit.amount_usd)}</span>` : ""}
            <span class="sep">·</span>
            <span class="status-badge ${receiptBadge}">${esc(audit.receipt_status)}</span>
        </div>
        ${traceHtml}
        ${violationHtml}
        <div class="audit-grid">
            <div class="audit-kv">
                <span class="audit-kv-label">Action Hash</span>
                <span class="audit-kv-value" title="${esc(audit.action_hash || "")}">${esc(hashShort)}</span>
            </div>
            <div class="audit-kv">
                <span class="audit-kv-label">Solana Signature</span>
                <span class="audit-kv-value" title="${esc(audit.receipt_signature || "")}">${esc(sigShort)}</span>
            </div>
            ${audit.agent_wallet ? `
            <div class="audit-kv">
                <span class="audit-kv-label">Agent Wallet</span>
                <span class="audit-kv-value">${esc(audit.agent_wallet.substring(0, 16))}…</span>
            </div>` : ""}
            ${audit.proof_id ? `
            <div class="audit-kv">
                <span class="audit-kv-label">Proof ID</span>
                <span class="audit-kv-value">${esc(audit.proof_id)}</span>
            </div>` : ""}
        </div>
        ${solanaLink}
    </div>`;
}

function renderAuditFeed() {
    let audits = [...STATE.allAudits].sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    const filter = STATE.currentFilter;
    if (filter === "allowed") audits = audits.filter(a => a.status === "allowed");
    if (filter === "blocked") audits = audits.filter(a => a.status === "blocked");
    if (filter === "anchored") audits = audits.filter(a => a.receipt_status === "anchored");

    if (!audits.length) {
        auditFeed.innerHTML = `<div class="empty-state"><div class="empty-icon">🔍</div>No events match this filter.</div>`;
        return;
    }
    auditFeed.innerHTML = audits.map(renderAuditCard).join("");
}

// Filter chips
document.querySelectorAll(".filter-chip").forEach(chip => {
    chip.addEventListener("click", () => {
        document.querySelectorAll(".filter-chip").forEach(c => c.classList.remove("active-chip"));
        chip.classList.add("active-chip");
        STATE.currentFilter = chip.dataset.filter;
        renderAuditFeed();
    });
});

// ── Kill Switch ─────────────────────────────────────────────────────────────
killSwitchBtn.addEventListener("click", () => {
    ksOverlay.classList.add("open");
});
ksCancelBtn.addEventListener("click", () => ksOverlay.classList.remove("open"));
ksOverlay.addEventListener("click", (e) => { if (e.target === ksOverlay) ksOverlay.classList.remove("open"); });

ksConfirmBtn.addEventListener("click", async () => {
    ksOverlay.classList.remove("open");
    ksConfirmBtn.disabled = true;
    const activeKeys = STATE.apiKeys.filter(k => !k.revoked_at && !k.suspended_at);
    let suspended = 0;
    let failed = 0;
    for (const key of activeKeys) {
        try {
            await apiFetch(`/v1/accounts/me/keys/${key.client_id}/suspend`, {
                method: "POST",
                headers: { Authorization: `Bearer ${STATE.sessionToken}` },
            });
            suspended++;
        } catch { failed++; }
    }
    toast(
        `Kill switch: ${suspended} key${suspended !== 1 ? "s" : ""} suspended${failed ? `, ${failed} failed` : ""}.`,
        failed ? "error" : "success"
    );
    killSwitchBtn.disabled = true;
    ksConfirmBtn.disabled = false;
    await loadAccountInfo();
});

// ── Load All ──────────────────────────────────────────────────────────────
async function loadDashboard() {
    const apiKey = cfgApiKey.value.trim();
    const policyId = cfgPolicyId.value.trim();
    if (!apiKey || !policyId) {
        toast("Both API key and Policy ID are required.", "error");
        return;
    }
    STATE.apiKey = apiKey;
    STATE.policyId = policyId;
    localStorage.setItem(STORAGE_KEYS.apiKey, apiKey);
    localStorage.setItem(STORAGE_KEYS.policyId, policyId);

    loadBtn.disabled = true;
    loadBtn.textContent = "Loading…";

    try {
        await Promise.all([
            loadStats(),
            loadAudits(),
        ]);
        await loadAgents();
        toast("Dashboard loaded successfully.", "success");
    } catch (err) {
        toast(`Load failed: ${err.message}`, "error");
    } finally {
        loadBtn.disabled = false;
        loadBtn.textContent = "Load Dashboard";
    }
}

loadBtn.addEventListener("click", loadDashboard);

// ── Restore + init ────────────────────────────────────────────────────────
(async function init() {
    cfgApiKey.value = STATE.apiKey;
    cfgPolicyId.value = STATE.policyId;

    await loadAccountInfo();

    // Auto-load if we have credentials
    if (STATE.apiKey && STATE.policyId) {
        loadDashboard();
    }
})();
