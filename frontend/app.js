const STORAGE_KEYS = {
    apiBase: "sentinel.apiBase",
    apiKey: "sentinel.apiKey",
    policyId: "sentinel.policyId",
    sessionToken: "sentinel.sessionToken",
};

const PARTICLE_COUNT = 170;
const canvas = document.getElementById("gravity-canvas");
const ctx = canvas.getContext("2d");
const launchLoginButton = document.getElementById("launch-login-button");
const authOverlay = document.getElementById("auth-overlay");
const authStatus = document.getElementById("auth-status");
const closeAuthButton = document.getElementById("close-auth-button");
const showLoginTab = document.getElementById("show-login-tab");
const showRegisterTab = document.getElementById("show-register-tab");
const loginPanel = document.getElementById("login-panel");
const registerPanel = document.getElementById("register-panel");
const loginForm = document.getElementById("login-form");
const registerForm = document.getElementById("register-form");

const pointer = { x: window.innerWidth / 2, y: window.innerHeight / 2, active: false };
const particles = [];
let canvasWidth = 0;
let canvasHeight = 0;
let rushMode = false;
let rushTarget = null;

function resolveApiBase() {
    const { hostname, origin } = window.location;
    const isLocalhost = hostname === "localhost" || hostname === "127.0.0.1";
    return isLocalhost ? "http://localhost:8000" : `${origin}/server`;
}

function saveSession(sessionToken) {
    localStorage.setItem(STORAGE_KEYS.apiBase, resolveApiBase());
    localStorage.setItem(STORAGE_KEYS.sessionToken, sessionToken);
}

function restoreSession() {
    const sessionToken = localStorage.getItem(STORAGE_KEYS.sessionToken);
    if (sessionToken) {
        window.location.href = "/dashboard.html";
    }
}

function resizeCanvas() {
    canvasWidth = window.innerWidth;
    canvasHeight = window.innerHeight;
    canvas.width = canvasWidth * window.devicePixelRatio;
    canvas.height = canvasHeight * window.devicePixelRatio;
    canvas.style.width = `${canvasWidth}px`;
    canvas.style.height = `${canvasHeight}px`;
    ctx.setTransform(window.devicePixelRatio, 0, 0, window.devicePixelRatio, 0, 0);
}

function seedParticles() {
    particles.length = 0;
    for (let index = 0; index < PARTICLE_COUNT; index += 1) {
        particles.push({
            x: Math.random() * canvasWidth,
            y: Math.random() * canvasHeight,
            vx: (Math.random() - 0.5) * 0.6,
            vy: (Math.random() - 0.5) * 0.6,
            size: 1.2 + Math.random() * 2.3,
            hue: 24 + Math.random() * 150,
        });
    }
}

function animateParticles() {
    ctx.clearRect(0, 0, canvasWidth, canvasHeight);

    for (const particle of particles) {
        if (rushMode && rushTarget) {
            const dx = rushTarget.x - particle.x;
            const dy = rushTarget.y - particle.y;
            particle.vx += dx * 0.0105;
            particle.vy += dy * 0.0105;
            particle.vx *= 0.86;
            particle.vy *= 0.86;
        } else {
            const driftX = Math.sin((particle.y + performance.now() * 0.02) * 0.003) * 0.015;
            const driftY = Math.cos((particle.x + performance.now() * 0.02) * 0.003) * 0.015;
            particle.vx += driftX;
            particle.vy += driftY;

            if (pointer.active) {
                const dx = pointer.x - particle.x;
                const dy = pointer.y - particle.y;
                const distance = Math.max(32, Math.hypot(dx, dy));
                const force = Math.min(120 / distance, 2.2);
                particle.vx += (dx / distance) * force * 0.04;
                particle.vy += (dy / distance) * force * 0.04;
            }

            particle.vx *= 0.985;
            particle.vy *= 0.985;
        }

        particle.x += particle.vx;
        particle.y += particle.vy;

        if (!rushMode) {
            if (particle.x < -40) particle.x = canvasWidth + 40;
            if (particle.x > canvasWidth + 40) particle.x = -40;
            if (particle.y < -40) particle.y = canvasHeight + 40;
            if (particle.y > canvasHeight + 40) particle.y = -40;
        }

        ctx.beginPath();
        ctx.fillStyle = `hsla(${particle.hue}, 86%, 72%, 0.82)`;
        ctx.arc(particle.x, particle.y, particle.size, 0, Math.PI * 2);
        ctx.fill();
    }

    requestAnimationFrame(animateParticles);
}

function openAuthOverlay(defaultTab = "login") {
    authOverlay.classList.remove("auth-overlay-hidden");
    authOverlay.setAttribute("aria-hidden", "false");
    setActiveTab(defaultTab);
}

function closeAuthOverlay() {
    authOverlay.classList.add("auth-overlay-hidden");
    authOverlay.setAttribute("aria-hidden", "true");
    rushMode = false;
    rushTarget = null;
}

function setActiveTab(mode) {
    const loginActive = mode === "login";
    showLoginTab.classList.toggle("auth-tab-active", loginActive);
    showRegisterTab.classList.toggle("auth-tab-active", !loginActive);
    loginPanel.classList.toggle("auth-panel-hidden", !loginActive);
    registerPanel.classList.toggle("auth-panel-hidden", loginActive);
    authStatus.textContent = loginActive
        ? "Enter your account credentials to continue to the dashboard."
        : "Create an account to generate keys and manage policies.";
}

async function readApiResponse(response) {
    const contentType = response.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
        return response.json();
    }
    return { message: await response.text() };
}

async function authenticate(path, payload, successMessage) {
    const response = await fetch(`${resolveApiBase()}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
    });
    const data = await readApiResponse(response);
    if (!response.ok) {
        throw new Error(data.detail?.error?.message || data.message || JSON.stringify(data));
    }

    saveSession(data.session_token);
    authStatus.textContent = successMessage;
    window.setTimeout(() => {
        window.location.href = "/dashboard.html";
    }, 420);
}

launchLoginButton.addEventListener("click", () => {
    const rect = launchLoginButton.getBoundingClientRect();
    rushTarget = {
        x: rect.left + rect.width / 2,
        y: rect.top + rect.height / 2,
    };
    rushMode = true;
    launchLoginButton.disabled = true;
    launchLoginButton.textContent = "Pulling particles in...";
    window.setTimeout(() => {
        openAuthOverlay("login");
        launchLoginButton.disabled = false;
        launchLoginButton.textContent = "Login to Sentinel";
    }, 640);
});

closeAuthButton.addEventListener("click", closeAuthOverlay);
showLoginTab.addEventListener("click", () => setActiveTab("login"));
showRegisterTab.addEventListener("click", () => setActiveTab("register"));

loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    authStatus.textContent = "Signing in...";
    try {
        await authenticate("/v1/accounts/login", {
            email: document.getElementById("login-email").value.trim(),
            password: document.getElementById("login-password").value,
        }, "Login successful. Redirecting to the dashboard...");
    } catch (error) {
        authStatus.textContent = `Login failed: ${error.message}`;
    }
});

registerForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    authStatus.textContent = "Creating account...";
    try {
        await authenticate("/v1/accounts/register", {
            email: document.getElementById("register-email").value.trim(),
            password: document.getElementById("register-password").value,
            full_name: document.getElementById("register-full-name").value.trim() || null,
        }, "Account created. Redirecting to the dashboard...");
    } catch (error) {
        authStatus.textContent = `Account creation failed: ${error.message}`;
    }
});

window.addEventListener("mousemove", (event) => {
    pointer.x = event.clientX;
    pointer.y = event.clientY;
    pointer.active = true;
});

window.addEventListener("mouseleave", () => {
    pointer.active = false;
});

window.addEventListener("resize", () => {
    resizeCanvas();
    seedParticles();
});

restoreSession();
resizeCanvas();
seedParticles();
animateParticles();
