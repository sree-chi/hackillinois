const STORAGE_KEYS = {
    apiBase: "sentinel.apiBase",
    apiKey: "sentinel.apiKey",
    policyId: "sentinel.policyId",
};

const form = document.getElementById("activity-form");
const apiBaseInput = document.getElementById("activity-api-base");
const apiKeyInput = document.getElementById("activity-api-key");
const policyIdInput = document.getElementById("activity-policy-id");
const loadButton = document.getElementById("load-activity-button");
const clearButton = document.getElementById("clear-activity-button");
const summaryTotal = document.getElementById("summary-total");
const summaryAllowed = document.getElementById("summary-allowed");
const summaryBlocked = document.getElementById("summary-blocked");
const summaryAnchored = document.getElementById("summary-anchored");
const alertsEl = document.getElementById("activity-alerts");
const activityList = document.getElementById("activity-list");
const activityEmpty = document.getElementById("activity-empty");

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

function clearContext() {
    localStorage.removeItem(STORAGE_KEYS.apiBase);
    localStorage.removeItem(STORAGE_KEYS.apiKey);
    localStorage.removeItem(STORAGE_KEYS.policyId);
    loadSavedContext();
    resetView();
}

function resetView() {
    summaryTotal.textContent = "0";
    summaryAllowed.textContent = "0";
    summaryBlocked.textContent = "0";
    summaryAnchored.textContent = "0";
    alertsEl.innerHTML = "";
    activityList.innerHTML = "";
    activityEmpty.style.display = "block";
}

function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}

async function readJson(response) {
    const text = await response.text();
    try {
        return JSON.parse(text);
    } catch {
        return { raw: text };
    }
}

function summarizeAudits(audits) {
    const allowed = audits.filter((audit) => audit.status === "allowed").length;
    const blocked = audits.filter((audit) => audit.status === "blocked").length;
    const anchored = audits.filter((audit) => audit.receipt_status === "anchored").length;
    const alerts = [];

    if (!audits.length) {
        alerts.push({ tone: "neutral", message: "No audit events found for this policy yet." });
    }
    if (blocked > 0) {
        alerts.push({ tone: "danger", message: `${blocked} request${blocked === 1 ? "" : "s"} blocked by policy or verification checks.` });
    }
    if (anchored > 0) {
        alerts.push({ tone: "success", message: `${anchored} receipt${anchored === 1 ? "" : "s"} anchored successfully.` });
    }
    const proofCount = audits.filter((audit) => audit.proof_id).length;
    if (proofCount > 0) {
        alerts.push({ tone: "info", message: `${proofCount} verification proof${proofCount === 1 ? "" : "s"} issued for external execution.` });
    }
    const failedReceipts = audits.filter((audit) => audit.receipt_status === "failed").length;
    if (failedReceipts > 0) {
        alerts.push({ tone: "danger", message: `${failedReceipts} receipt anchor${failedReceipts === 1 ? "" : "s"} failed and should be reviewed.` });
    }

    return { allowed, blocked, anchored, alerts };
}

function importantMessageForAudit(audit) {
    if (audit.violation?.explanation) {
        return audit.violation.explanation;
    }
    if (audit.proof_id) {
        return `Verification proof issued: ${audit.proof_id}`;
    }
    if (audit.receipt_status === "anchored" && audit.receipt_signature) {
        return `Receipt anchored on Solana: ${audit.receipt_signature}`;
    }
    if (audit.receipt_status === "failed") {
        return "Receipt verification failed or could not be anchored.";
    }
    return "Authorization processed without additional proof details.";
}

function renderAlerts(alerts) {
    alertsEl.innerHTML = alerts.map((alert) => `
        <article class="alert-card alert-${alert.tone}">
            <strong>${escapeHtml(alert.message)}</strong>
        </article>
    `).join("");
}

function renderAudits(audits) {
    if (!audits.length) {
        activityList.innerHTML = "";
        activityEmpty.style.display = "block";
        return;
    }

    activityEmpty.style.display = "none";
    activityList.innerHTML = audits
        .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
        .map((audit) => {
            const tone = audit.status === "allowed" ? "success" : "danger";
            return `
                <article class="activity-card activity-${tone}">
                    <div class="activity-header">
                        <div>
                            <p class="activity-title">${escapeHtml(audit.action_type)} <span>${escapeHtml(audit.http_method)} ${escapeHtml(audit.resource)}</span></p>
                            <p class="activity-meta">${escapeHtml(audit.requester)} | ${new Date(audit.created_at).toLocaleString()}</p>
                        </div>
                        <span class="status-pill status-${tone}">${escapeHtml(audit.status)}</span>
                    </div>
                    <p class="activity-message">${escapeHtml(importantMessageForAudit(audit))}</p>
                    <div class="activity-grid">
                        <div>
                            <span class="meta-label">Receipt status</span>
                            <code>${escapeHtml(audit.receipt_status)}</code>
                        </div>
                        <div>
                            <span class="meta-label">Receipt signature</span>
                            <code>${escapeHtml(audit.receipt_signature || "None")}</code>
                        </div>
                        <div>
                            <span class="meta-label">Action hash</span>
                            <code>${escapeHtml(audit.action_hash || "None")}</code>
                        </div>
                        <div>
                            <span class="meta-label">Proof ID</span>
                            <code>${escapeHtml(audit.proof_id || "None")}</code>
                        </div>
                    </div>
                </article>
            `;
        })
        .join("");
}

async function loadActivity() {
    const baseUrl = apiBaseInput.value.trim().replace(/\/$/, "");
    const apiKey = apiKeyInput.value.trim();
    const policyId = policyIdInput.value.trim();

    if (!baseUrl || !apiKey || !policyId) {
        renderAlerts([{ tone: "danger", message: "API base URL, API key, and policy ID are all required." }]);
        return;
    }

    saveContext();
    loadButton.disabled = true;
    alertsEl.innerHTML = "";

    try {
        const response = await fetch(`${baseUrl}/v1/audits/${policyId}`, {
            headers: {
                Authorization: `Bearer ${apiKey}`,
            },
        });
        const data = await readJson(response);
        if (!response.ok) {
            throw new Error(JSON.stringify(data));
        }

        const audits = Array.isArray(data.data) ? data.data : [];
        const summary = summarizeAudits(audits);
        summaryTotal.textContent = String(audits.length);
        summaryAllowed.textContent = String(summary.allowed);
        summaryBlocked.textContent = String(summary.blocked);
        summaryAnchored.textContent = String(summary.anchored);
        renderAlerts(summary.alerts);
        renderAudits(audits);
    } catch (error) {
        resetView();
        renderAlerts([{ tone: "danger", message: `Failed to load activity: ${error.message}` }]);
    } finally {
        loadButton.disabled = false;
    }
}

form.addEventListener("submit", async (event) => {
    event.preventDefault();
    await loadActivity();
});

clearButton.addEventListener("click", clearContext);

loadSavedContext();
resetView();
if (apiKeyInput.value && policyIdInput.value) {
    loadActivity();
}
