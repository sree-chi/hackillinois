// ── State ──────────────────────────────────────────────────────────────────
const STORAGE_KEYS = {
    apiKey: "sentinel.apiKey",
    policyId: "sentinel.policyId",
    sessionToken: "sentinel.sessionToken",
};

const WALLET_COLORS = [
    "var(--primary)", "var(--secondary-dark)", "#5d9c3e", "#bf573f",
    "#6366f1", "#d97706", "#8b5cf6", "#0891b2",
];

let STATE = {
    apiBase: resolveApiBase(),
    apiKey: localStorage.getItem(STORAGE_KEYS.apiKey) || "",
    policyId: localStorage.getItem(STORAGE_KEYS.policyId) || "",
    sessionToken: localStorage.getItem(STORAGE_KEYS.sessionToken) || "",
    allAudits: [],
    agents: [],
    apiKeys: [],
    policies: [],
    account: null,
    currentFilter: "all",
};

function resolveApiBase() {
    const { hostname, origin } = window.location;
    return (hostname === "localhost" || hostname === "127.0.0.1")
        ? "http://localhost:8000"
        : `${origin}/server`;
}

// ── DOM ────────────────────────────────────────────────────────────────────
const apiKeySelect = document.getElementById("cfg-api-key-select");
const policySelect = document.getElementById("cfg-policy-select");
const loadBtn = document.getElementById("load-btn");
const notSignedHint = document.getElementById("not-signed-in-hint");
const killSwitchBtn = document.getElementById("kill-switch-btn");
const ksOverlay = document.getElementById("ks-confirm-overlay");
const ksCancelBtn = document.getElementById("ks-cancel-btn");
const ksConfirmBtn = document.getElementById("ks-confirm-btn");
const accountChip = document.getElementById("account-chip");
const toastStack = document.getElementById("toast-stack");

const statTotal = document.getElementById("stat-total");
const statAllowed = document.getElementById("stat-allowed");
const statBlocked = document.getElementById("stat-blocked");
const statAnchored = document.getElementById("stat-anchored");
const statSpend = document.getElementById("stat-spend");

const budgetBar = document.getElementById("budget-bar");
const budgetSpent = document.getElementById("budget-spent");
const budgetLimit = document.getElementById("budget-limit");
const budgetSub = document.getElementById("budget-sub");
const budgetRemLabel = document.getElementById("budget-remaining-label");
const walletBreakdown = document.getElementById("wallet-breakdown");

const agentList = document.getElementById("agent-list");
const agentCount = document.getElementById("agent-count");
const newAgentName = document.getElementById("new-agent-name");
const newAgentWallet = document.getElementById("new-agent-wallet");
const addAgentBtn = document.getElementById("add-agent-btn");

const auditFeed = document.getElementById("audit-feed");
const auditCount = document.getElementById("audit-count");

// ── Utilities ──────────────────────────────────────────────────────────────
function esc(v) {
    return String(v ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

async function apiFetch(path, opts = {}) {
    const res = await fetch(`${STATE.apiBase}${path}`, opts);
    const ct = res.headers.get("content-type") || "";
    const body = ct.includes("application/json") ? await res.json() : { message: await res.text() };
    if (!res.ok) {
        const msg = body?.detail?.error?.message || body?.detail || body?.message || JSON.stringify(body);
        throw Object.assign(new Error(msg), { status: res.status });
    }
    return body;
}

function apiHeaders() { return { Authorization: `Bearer ${STATE.apiKey}`, "Content-Type": "application/json" }; }
function sessionHeaders() { return { Authorization: `Bearer ${STATE.sessionToken}`, "Content-Type": "application/json" }; }

function toast(msg, type = "info") {
    const el = document.createElement("div");
    el.className = `toast toast-${type}`;
    el.textContent = msg;
    toastStack.appendChild(el);
    setTimeout(() => el.remove(), 3800);
}

function fmt(v, d = 0) {
    if (v == null) return "—";
    return Number(v).toLocaleString("en-US", { maximumFractionDigits: d });
}

function fmtUSD(v) {
    if (v == null) return "—";
    return `$${Number(v).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
}

function timeAgo(iso) {
    if (!iso) return "—";
    const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    return new Date(iso).toLocaleDateString();
}

// ── Wallet name resolution ─────────────────────────────────────────────────
function walletDisplayName(walletAddr) {
    if (!walletAddr) return null;
    // Check agents first
    const agent = STATE.agents.find(a => a.wallet_address === walletAddr);
    if (agent) return agent.name;
    // Shorten address
    return walletAddr.substring(0, 6) + "…" + walletAddr.substring(walletAddr.length - 4);
}

function walletColor(walletAddr) {
    if (!walletAddr) return WALLET_COLORS[0];
    // Deterministic color based on wallet hash
    let hash = 0;
    for (let i = 0; i < walletAddr.length; i++) hash = ((hash << 5) - hash + walletAddr.charCodeAt(i)) | 0;
    return WALLET_COLORS[Math.abs(hash) % WALLET_COLORS.length];
}

// ── Account / Session ──────────────────────────────────────────────────────
async function loadAccountInfo() {
    if (!STATE.sessionToken) {
        notSignedHint.classList.remove("is-hidden");
        return;
    }
    notSignedHint.classList.add("is-hidden");
    try {
        const data = await apiFetch("/v1/accounts/me/dashboard", {
            headers: { Authorization: `Bearer ${STATE.sessionToken}` },
        });
        STATE.account = data.account;
        STATE.apiKeys = (data.api_keys || []).filter(k => !k.revoked_at);
        accountChip.textContent = `${STATE.account.email}${STATE.account.full_name ? ' | ' + STATE.account.full_name : ''}`;
        killSwitchBtn.disabled = !STATE.apiKeys.some(k => !k.suspended_at);

        // Populate API key dropdown
        populateApiKeyDropdown();
    } catch {
        notSignedHint.classList.remove("is-hidden");
    }
}

function populateApiKeyDropdown() {
    const activeKeys = STATE.apiKeys.filter(k => !k.suspended_at);
    if (!activeKeys.length) {
        apiKeySelect.innerHTML = `<option value="">No active keys found</option>`;
        return;
    }
    apiKeySelect.innerHTML = `<option value="">Choose an API key…</option>` +
        activeKeys.map(k =>
            `<option value="${esc(k.api_key_prefix)}" ${STATE.apiKey.startsWith(k.api_key_prefix.replace('…', '')) ? 'selected' : ''}>
                ${esc(k.app_name)} — ${esc(k.api_key_prefix)}
            </option>`
        ).join("");

    // If user already has a key stored and it matches a prefix, auto-select
    if (STATE.apiKey) {
        const match = activeKeys.find(k => STATE.apiKey.startsWith(k.api_key_prefix.replace('…', '')));
        if (match) {
            // The full key is stored in localStorage; set it as selected
            for (const opt of apiKeySelect.options) {
                if (opt.value === match.api_key_prefix) { opt.selected = true; break; }
            }
        }
    }
}

// When API key is selected, fetch policies for that key
apiKeySelect.addEventListener("change", async () => {
    const prefix = apiKeySelect.value;
    if (!prefix) {
        policySelect.innerHTML = `<option value="">Select an API key first…</option>`;
        return;
    }

    // We need the FULL api key. If user has it stored and prefix matches, use it.
    // Otherwise, the prefix alone won't work — we need the full key.
    if (STATE.apiKey && STATE.apiKey.startsWith(prefix.replace('…', ''))) {
        // Great, stored key matches this prefix
    } else {
        // User doesn't have the full key stored for this selection.
        // Show a notice asking them to paste the full key.
        policySelect.innerHTML = `<option value="">Paste full API key on Keys page first</option>`;
        toast("The full API key must be stored. Copy it from the Keys page.", "info");
        return;
    }

    await loadPolicies();
});

async function loadPolicies() {
    policySelect.innerHTML = `<option value="">Loading policies…</option>`;
    try {
        const data = await apiFetch("/v1/policies", { headers: apiHeaders() });
        STATE.policies = data.data || [];
        if (!STATE.policies.length) {
            policySelect.innerHTML = `<option value="">No policies found. Create one on the Keys page.</option>`;
            return;
        }
        policySelect.innerHTML = `<option value="">Choose a policy…</option>` +
            STATE.policies.map(p =>
                `<option value="${esc(p.id)}" ${p.id === STATE.policyId ? 'selected' : ''}>
                    ${esc(p.name)} — ${esc(p.id)}
                </option>`
            ).join("");
    } catch (err) {
        policySelect.innerHTML = `<option value="">Failed to load policies</option>`;
        toast(`Policies: ${err.message}`, "error");
    }
}

// ── Stats ──────────────────────────────────────────────────────────────────
async function loadStats() {
    const data = await apiFetch(`/v1/audits/${STATE.policyId}/stats`, { headers: apiHeaders() });
    statTotal.textContent = fmt(data.total_requests);
    statAllowed.textContent = fmt(data.allowed_requests);
    statBlocked.textContent = fmt(data.blocked_requests);
    statAnchored.textContent = fmt(data.anchored_receipts);
    statSpend.textContent = fmtUSD(data.total_spend_usd);

    const spent = data.total_spend_usd || 0;
    const max = data.policy_max_spend_usd;
    budgetSpent.textContent = fmtUSD(spent);

    if (max != null) {
        const pct = Math.min(100, (spent / max) * 100);
        budgetLimit.textContent = `/ ${fmtUSD(max)} limit`;
        budgetBar.style.width = `${pct}%`;
        budgetBar.className = "progress-fill" + (pct >= 90 ? " danger" : pct >= 70 ? " warning" : "");
        budgetSub.textContent = `${fmt(pct, 1)}% of policy budget consumed`;
        budgetRemLabel.textContent = `${fmtUSD(data.remaining_credit_usd)} remaining`;
    } else {
        budgetLimit.textContent = "/ No spend limit";
        budgetBar.style.width = "0%";
        budgetSub.textContent = "This policy has no maximum spend limit configured.";
        budgetRemLabel.textContent = "Unlimited";
    }
}

// ── Wallet Breakdown ───────────────────────────────────────────────────────
function renderWalletBreakdown() {
    // Group spend by agent_wallet from allowed audits
    const walletSpend = {};
    for (const a of STATE.allAudits) {
        if (a.status !== "allowed" || a.amount_usd == null) continue;
        const w = a.agent_wallet || "Unknown Wallet";
        walletSpend[w] = (walletSpend[w] || 0) + a.amount_usd;
    }

    const entries = Object.entries(walletSpend).sort((a, b) => b[1] - a[1]);
    if (!entries.length) {
        walletBreakdown.innerHTML = "";
        return;
    }

    walletBreakdown.innerHTML = `
        <div class="section-heading" style="margin-bottom:4px;margin-top:6px;">
            <p class="eyebrow" style="margin-bottom:0;">Spend by Wallet</p>
        </div>` +
        entries.map(([wallet, total]) => {
            const name = walletDisplayName(wallet) || wallet;
            const color = walletColor(wallet);
            const isUnknown = wallet === "Unknown Wallet";
            return `
            <div class="wallet-spend-row">
                <div class="wallet-dot" style="background:${color}"></div>
                <div class="wallet-spend-info">
                    <div class="wallet-spend-name">${esc(name)}</div>
                    ${!isUnknown ? `<div class="wallet-spend-addr">${esc(wallet)}</div>` : ""}
                </div>
                <div class="wallet-spend-amount">${fmtUSD(total)}</div>
            </div>`;
        }).join("");
}

// ── Agents ─────────────────────────────────────────────────────────────────
async function loadAgents() {
    if (!STATE.sessionToken) return;
    try {
        STATE.agents = await apiFetch("/v1/agents", {
            headers: { Authorization: `Bearer ${STATE.sessionToken}` },
        });
    } catch { STATE.agents = []; }
    renderAgents();
}

function agentIsActive(agent) {
    const fiveMinAgo = Date.now() - 5 * 60 * 1000;
    return STATE.allAudits.some(a => {
        const m1 = agent.wallet_address && a.agent_wallet === agent.wallet_address;
        const m2 = a.requester?.toLowerCase().includes(agent.name.toLowerCase().replace(/\s+/g, "_"));
        return (m1 || m2) && new Date(a.created_at).getTime() > fiveMinAgo;
    });
}

function renderAgents() {
    agentCount.textContent = `${STATE.agents.length} registered`;
    if (!STATE.agents.length) {
        agentList.innerHTML = `<div class="empty-state">No agents registered yet. Add one above.</div>`;
        return;
    }
    agentList.innerHTML = STATE.agents.map(a => {
        const active = agentIsActive(a);
        return `
        <div class="agent-row">
            <div class="agent-status-dot ${active ? "dot-active" : "dot-idle"}"></div>
            <div class="agent-info">
                <div class="agent-name">${esc(a.name)}</div>
                <div class="agent-wallet-addr">${a.wallet_address ? esc(a.wallet_address) : "No wallet linked"}</div>
            </div>
            <button class="btn-remove" data-delete-agent="${esc(a.agent_id)}">Remove</button>
        </div>`;
    }).join("");
}

addAgentBtn.addEventListener("click", async () => {
    const name = newAgentName.value.trim();
    const wallet = newAgentWallet.value.trim() || null;
    if (!name) { toast("Agent name is required.", "error"); return; }
    if (!wallet) { toast("Wallet address is required to track spending.", "error"); return; }
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
        renderWalletBreakdown(); // Re-render with new names
        renderAuditFeed();       // Re-render wallet tags
        toast(`Agent "${name}" registered.`, "success");
    } catch (err) { toast(`Failed: ${err.message}`, "error"); }
    finally { addAgentBtn.disabled = false; }
});

agentList.addEventListener("click", async (e) => {
    const btn = e.target.closest("[data-delete-agent]");
    if (!btn) return;
    btn.disabled = true;
    try {
        await apiFetch(`/v1/agents/${btn.dataset.deleteAgent}`, { method: "DELETE", headers: sessionHeaders() });
        await loadAgents();
        toast("Agent removed.", "info");
    } catch (err) { btn.disabled = false; toast(`Failed: ${err.message}`, "error"); }
});

// ── Audit Feed ─────────────────────────────────────────────────────────────
async function loadAudits() {
    const data = await apiFetch(`/v1/audits/${STATE.policyId}`, { headers: apiHeaders() });
    STATE.allAudits = Array.isArray(data.data) ? data.data : [];
    auditCount.textContent = `${STATE.allAudits.length} events`;
    renderAuditFeed();
}

function verifyBadge(a) {
    if (!a.receipt_signature) return `<span class="verify-check fail">✗ No receipt</span>`;
    if (a.receipt_signature.startsWith("mock_")) return `<span class="verify-check mock">⬡ Mock</span>`;
    return `<span class="verify-check ok">✓ Verified</span>`;
}

function renderAuditCard(a) {
    const ok = a.status === "allowed";
    const rcptClass = a.receipt_status === "anchored" ? "status-success" : "status-warning";
    const walletName = walletDisplayName(a.agent_wallet);
    const walletTag = a.agent_wallet
        ? `<span class="audit-wallet-tag" style="border-color:${walletColor(a.agent_wallet)}33;background:${walletColor(a.agent_wallet)}18;">
               <span style="display:inline-block;width:6px;height:6px;border-radius:50%;background:${walletColor(a.agent_wallet)}"></span>
               ${esc(walletName || a.agent_wallet.substring(0, 8) + '…')}
           </span>`
        : "";

    const traceHtml = a.reasoning_trace
        ? `<div class="audit-trace-block">💬 ${esc(a.reasoning_trace)}</div>` : "";
    const violationHtml = a.violation?.explanation
        ? `<div class="audit-violation-block">⛔ ${esc(a.violation.explanation)}</div>` : "";
    const solanaLink = a.explorer_url
        ? `<a class="solana-link" href="${esc(a.explorer_url)}" target="_blank" rel="noreferrer">🔗 View on Solana Explorer ↗</a>` : "";

    const sigShort = a.receipt_signature ? a.receipt_signature.substring(0, 22) + "…" : "None";
    const hashShort = a.action_hash ? a.action_hash.substring(0, 16) + "…" : "None";

    return `
    <div class="audit-card ${ok ? "allowed" : "blocked"}">
        <div class="audit-top">
            <div class="audit-action-label">
                ${esc(a.action_type)}<span>${esc(a.http_method)} ${esc(a.resource)}</span>
            </div>
            <div style="display:flex;gap:6px;align-items:center;flex-shrink:0;">
                ${verifyBadge(a)}
                <span class="status-pill ${ok ? "status-success" : "status-danger"}">${esc(a.status)}</span>
            </div>
        </div>
        <div class="audit-meta-row">
            ${walletTag}
            <span>${esc(a.requester)}</span>
            <span class="sep">·</span>
            <span>${timeAgo(a.created_at)}</span>
            ${a.amount_usd != null ? `<span class="sep">·</span><span>${fmtUSD(a.amount_usd)}</span>` : ""}
            <span class="sep">·</span>
            <span class="status-pill ${rcptClass}" style="padding:4px 10px;font-size:0.72rem">${esc(a.receipt_status)}</span>
        </div>
        ${traceHtml}${violationHtml}
        <div class="audit-detail-grid">
            <div class="audit-kv"><span class="audit-kv-label">Action Hash</span><span class="audit-kv-value" title="${esc(a.action_hash || "")}">${esc(hashShort)}</span></div>
            <div class="audit-kv"><span class="audit-kv-label">Solana Sig</span><span class="audit-kv-value" title="${esc(a.receipt_signature || "")}">${esc(sigShort)}</span></div>
            ${a.agent_wallet ? `<div class="audit-kv"><span class="audit-kv-label">Agent Wallet</span><span class="audit-kv-value">${esc(a.agent_wallet)}</span></div>` : ""}
            ${a.proof_id ? `<div class="audit-kv"><span class="audit-kv-label">Proof ID</span><span class="audit-kv-value">${esc(a.proof_id)}</span></div>` : ""}
        </div>
        ${solanaLink}
    </div>`;
}

function renderAuditFeed() {
    let audits = [...STATE.allAudits].sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    const f = STATE.currentFilter;
    if (f === "allowed") audits = audits.filter(a => a.status === "allowed");
    if (f === "blocked") audits = audits.filter(a => a.status === "blocked");
    if (f === "anchored") audits = audits.filter(a => a.receipt_status === "anchored");

    auditFeed.innerHTML = audits.length
        ? audits.map(renderAuditCard).join("")
        : `<div class="empty-state">No events match this filter.</div>`;
}

document.querySelectorAll(".filter-chip").forEach(chip => {
    chip.addEventListener("click", () => {
        document.querySelectorAll(".filter-chip").forEach(c => c.classList.remove("active-chip"));
        chip.classList.add("active-chip");
        STATE.currentFilter = chip.dataset.filter;
        renderAuditFeed();
    });
});

// ── Kill Switch ────────────────────────────────────────────────────────────
killSwitchBtn.addEventListener("click", () => ksOverlay.classList.add("open"));
ksCancelBtn.addEventListener("click", () => ksOverlay.classList.remove("open"));
ksOverlay.addEventListener("click", e => { if (e.target === ksOverlay) ksOverlay.classList.remove("open"); });

ksConfirmBtn.addEventListener("click", async () => {
    ksOverlay.classList.remove("open");
    ksConfirmBtn.disabled = true;
    const active = STATE.apiKeys.filter(k => !k.revoked_at && !k.suspended_at);
    let ok = 0, fail = 0;
    for (const k of active) {
        try {
            await apiFetch(`/v1/accounts/me/keys/${k.client_id}/suspend`, {
                method: "POST", headers: { Authorization: `Bearer ${STATE.sessionToken}` },
            });
            ok++;
        } catch { fail++; }
    }
    toast(`Kill switch: ${ok} key${ok !== 1 ? "s" : ""} suspended${fail ? `, ${fail} failed` : ""}.`, fail ? "error" : "success");
    killSwitchBtn.disabled = true;
    ksConfirmBtn.disabled = false;
    await loadAccountInfo();
});

// ── Load All ───────────────────────────────────────────────────────────────
async function loadDashboard() {
    const policyId = policySelect.value;
    if (!STATE.apiKey) { toast("Select an API key.", "error"); return; }
    if (!policyId) { toast("Select a policy.", "error"); return; }

    STATE.policyId = policyId;
    localStorage.setItem(STORAGE_KEYS.policyId, policyId);

    loadBtn.disabled = true;
    loadBtn.textContent = "Loading…";
    try {
        await Promise.all([loadStats(), loadAudits()]);
        await loadAgents();
        renderWalletBreakdown();
        toast("Dashboard loaded.", "success");
    } catch (err) {
        toast(`Load failed: ${err.message}`, "error");
    } finally {
        loadBtn.disabled = false;
        loadBtn.textContent = "Load Dashboard";
    }
}

loadBtn.addEventListener("click", loadDashboard);

// ── Init ───────────────────────────────────────────────────────────────────
(async function init() {
    await loadAccountInfo();

    // If we have a stored key, auto-trigger policy load
    if (STATE.apiKey && STATE.apiKeys.length) {
        await loadPolicies();
        // If policy is also stored, auto-load
        if (STATE.policyId && policySelect.querySelector(`option[value="${STATE.policyId}"]`)) {
            policySelect.value = STATE.policyId;
            loadDashboard();
        }
    }
})();
