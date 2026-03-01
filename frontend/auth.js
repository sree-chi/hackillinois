/**
 * auth.js - Shared Authentication Utility
 */

const SentinelAuth = {
    STORAGE_KEYS: {
        sessionToken: "sentinel.sessionToken",
        apiKey: "sentinel.apiKey",
        policyId: "sentinel.policyId"
    },

    logout() {
        console.log("Logging out...");
        // Clear all session-related storage
        localStorage.removeItem(this.STORAGE_KEYS.sessionToken);
        localStorage.removeItem(this.STORAGE_KEYS.apiKey);
        localStorage.removeItem(this.STORAGE_KEYS.policyId);

        // Redirect to landing page
        window.location.href = "/index.html";
    },

    initLogoutButton(buttonId) {
        const btn = document.getElementById(buttonId);
        if (btn) {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                this.logout();
            });
        }
    }
};

// Auto-initialize if the script is loaded and a logout button exists
document.addEventListener('DOMContentLoaded', () => {
    SentinelAuth.initLogoutButton('logout-btn');
});

window.SentinelAuth = SentinelAuth;
