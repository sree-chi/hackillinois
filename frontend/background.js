const canvas = document.getElementById("ambient-canvas");
const backdropTitle = document.querySelector("[data-background-title]");

if (canvas) {
    const ctx = canvas.getContext("2d");
    const PARTICLE_COUNT = 280;
    const pointer = { x: window.innerWidth / 2, y: window.innerHeight / 2, active: false };
    const particles = [];
    let canvasWidth = 0;
    let canvasHeight = 0;

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
            const angle = Math.random() * Math.PI * 2;
            const spread = Math.pow(Math.random(), 0.72);
            const radius = Math.max(canvasWidth, canvasHeight) * (0.12 + spread * 0.68);
            const depth = 0.35 + Math.random() * 1.4;
            particles.push({
                angle,
                radius,
                depth,
                length: 1.5 + depth * 3.4,
                width: 0.7 + Math.random() * 1.6,
                x: canvasWidth / 2,
                y: canvasHeight / 2,
                vx: 0,
                vy: 0,
                alpha: 0.12 + Math.random() * 0.22,
                hue: 220 + Math.sin(angle * 1.7) * 40 + Math.cos(angle * 2.3) * 18,
            });
        }
    }

    function updateBackdropTitle() {
        if (!backdropTitle) return;
        const centerX = canvasWidth / 2;
        const centerY = canvasHeight / 2;
        const normalizedX = pointer.active ? (pointer.x - centerX) / centerX : 0;
        const normalizedY = pointer.active ? (pointer.y - centerY) / centerY : 0;
        backdropTitle.style.transform = `
            translate3d(${(normalizedX * 28).toFixed(2)}px, ${(normalizedY * 18).toFixed(2)}px, 0)
            rotateX(${(-normalizedY * 4).toFixed(2)}deg)
            rotateY(${(normalizedX * 5).toFixed(2)}deg)
        `;
    }

    function animateParticles() {
        ctx.clearRect(0, 0, canvasWidth, canvasHeight);

        const centerX = canvasWidth / 2;
        const centerY = canvasHeight / 2;
        const normalizedX = pointer.active ? (pointer.x - centerX) / centerX : 0;
        const normalizedY = pointer.active ? (pointer.y - centerY) / centerY : 0;
        const tiltX = normalizedX * 36;
        const tiltY = normalizedY * 26;

        for (const particle of particles) {
            const baseX = Math.cos(particle.angle) * particle.radius;
            const baseY = Math.sin(particle.angle) * particle.radius;
            const projectedX = baseX + tiltX * particle.depth;
            const projectedY = baseY + tiltY * particle.depth + baseX * normalizedY * 0.04;
            const perspective = 1 + ((Math.cos(particle.angle) * normalizedX) + (Math.sin(particle.angle) * normalizedY)) * 0.12 * particle.depth;
            const targetX = centerX + projectedX * perspective;
            const targetY = centerY + projectedY * perspective;

            particle.vx += (targetX - particle.x) * 0.07;
            particle.vy += (targetY - particle.y) * 0.07;
            particle.vx *= 0.78;
            particle.vy *= 0.78;
            particle.x += particle.vx;
            particle.y += particle.vy;

            const streakAngle = particle.angle + normalizedX * 0.16 - normalizedY * 0.1;
            const length = particle.length * (0.82 + particle.depth * 0.22);
            const width = particle.width * (0.9 + particle.depth * 0.12);

            ctx.save();
            ctx.translate(particle.x, particle.y);
            ctx.rotate(streakAngle);
            ctx.fillStyle = `hsla(${particle.hue}, 78%, 56%, ${particle.alpha})`;
            ctx.beginPath();
            ctx.roundRect(-length / 2, -width / 2, length, width, width);
            ctx.fill();
            ctx.restore();
        }

        updateBackdropTitle();
        requestAnimationFrame(animateParticles);
    }

    window.addEventListener("mousemove", (event) => {
        pointer.x = event.clientX;
        pointer.y = event.clientY;
        pointer.active = true;
    });

    window.addEventListener("mouseleave", () => {
        pointer.active = false;
        updateBackdropTitle();
    });

    window.addEventListener("resize", () => {
        resizeCanvas();
        seedParticles();
        updateBackdropTitle();
    });

    resizeCanvas();
    seedParticles();
    updateBackdropTitle();
    animateParticles();
}
