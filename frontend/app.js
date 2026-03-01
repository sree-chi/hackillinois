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
const launchRegisterButton = document.getElementById("launch-register-button");
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
let activeLaunchButton = null;

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
            anchorX: Math.random() * canvasWidth,
            anchorY: Math.random() * canvasHeight,
            x: Math.random() * canvasWidth,
            y: Math.random() * canvasHeight,
            vx: 0,
            vy: 0,
            size: 3 + Math.random() * 8,
            depth: 0.35 + Math.random() * 1.4,
            alpha: 0.2 + Math.random() * 0.35,
        });
    }
}

function animateParticles() {
    ctx.clearRect(0, 0, canvasWidth, canvasHeight);

    for (const particle of particles) {
        if (rushMode && rushTarget) {
            const dx = rushTarget.x - particle.x;
            const dy = rushTarget.y - particle.y;
            particle.vx += dx * 0.016;
            particle.vy += dy * 0.016;
            particle.vx *= 0.84;
            particle.vy *= 0.84;
        } else {
            const offsetX = pointer.active ? (pointer.x - canvasWidth / 2) * 0.055 * particle.depth : 0;
            const offsetY = pointer.active ? (pointer.y - canvasHeight / 2) * 0.055 * particle.depth : 0;
            const targetX = particle.anchorX + offsetX;
            const targetY = particle.anchorY + offsetY;

            particle.vx += (targetX - particle.x) * 0.075;
            particle.vy += (targetY - particle.y) * 0.075;
            particle.vx *= 0.8;
            particle.vy *= 0.8;
        }

        particle.x += particle.vx;
        particle.y += particle.vy;

        const radius = particle.size * (0.55 + particle.depth * 0.42);
        const highlightX = particle.x - radius * 0.32;
        const highlightY = particle.y - radius * 0.32;

        const bubbleFill = ctx.createRadialGradient(
            highlightX,
            highlightY,
            radius * 0.18,
            particle.x,
            particle.y,
            radius * 1.15,
        );
        bubbleFill.addColorStop(0, `rgba(255, 251, 243, ${particle.alpha + 0.26})`);
        bubbleFill.addColorStop(0.42, `rgba(231, 210, 179, ${particle.alpha + 0.16})`);
        bubbleFill.addColorStop(1, `rgba(168, 128, 78, ${particle.alpha})`);

        ctx.beginPath();
        ctx.fillStyle = bubbleFill;
        ctx.arc(particle.x, particle.y, radius, 0, Math.PI * 2);
        ctx.fill();

        ctx.beginPath();
        ctx.fillStyle = `rgba(255, 255, 255, ${particle.alpha + 0.18})`;
        ctx.arc(highlightX, highlightY, Math.max(1.2, radius * 0.24), 0, Math.PI * 2);
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
    activeLaunchButton = null;
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

function launchAuth(button, mode) {
    const rect = button.getBoundingClientRect();
    rushTarget = {
        x: rect.left + rect.width / 2,
        y: rect.top + rect.height / 2,
    };
    rushMode = true;
    activeLaunchButton = button;
    button.disabled = true;
    button.textContent = mode === "login" ? "Opening..." : "Preparing...";
    window.setTimeout(() => {
        rushMode = false;
        openAuthOverlay(mode);
        if (activeLaunchButton === button) {
            button.disabled = false;
            button.textContent = mode === "login" ? "Login" : "Sign Up";
        }
    }, 640);
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

launchLoginButton.addEventListener("click", () => launchAuth(launchLoginButton, "login"));
launchRegisterButton.addEventListener("click", () => launchAuth(launchRegisterButton, "register"));

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
