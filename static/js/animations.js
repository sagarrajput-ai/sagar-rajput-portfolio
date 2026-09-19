/* ============================================
   Sagar Rajput Portfolio — Animation Engine v2
   Additive only. Does not touch main.js logic.
   ============================================ */

document.addEventListener("DOMContentLoaded", () => {
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ---------- 1. Scroll reveal (now also covers toolkit cards) ---------- */
  const revealEls = [...document.querySelectorAll("[data-reveal]")];
  const toolkitCards = [...document.querySelectorAll(".toolkit-card")];
  toolkitCards.forEach((card, i) => {
    card.setAttribute("data-reveal-delay", Math.min(i * 70, 420));
  });
  const allReveal = [...revealEls, ...toolkitCards];

  if (allReveal.length && !reduceMotion) {
    const io = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          const delay = entry.target.getAttribute("data-reveal-delay");
          if (delay) entry.target.style.transitionDelay = `${delay}ms`;
          entry.target.classList.add("is-visible");
          io.unobserve(entry.target);
        }
      });
    }, { threshold: 0.15 });
    allReveal.forEach((el) => io.observe(el));
  } else {
    allReveal.forEach((el) => el.classList.add("is-visible"));
  }

  /* ---------- 2. Network topology canvas — works for any
                   #network-canvas or .network-canvas element ---------- */
  function initNetworkCanvas(canvas) {
    const ctx = canvas.getContext("2d");
    const host = canvas.closest("section") || canvas.parentElement;
    let width, height, nodes, dpr, animId = null, running = false;
    let mouseX = null, mouseY = null;

    function resize() {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      width = host.clientWidth;
      height = host.clientHeight;
      canvas.width = width * dpr;
      canvas.height = height * dpr;
      canvas.style.width = width + "px";
      canvas.style.height = height + "px";
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      const count = window.innerWidth < 700 ? 16 : 34;
      nodes = Array.from({ length: count }, () => ({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.3,
        vy: (Math.random() - 0.5) * 0.3,
        r: Math.random() * 1.6 + 1,
        pulse: Math.random() * Math.PI * 2,
      }));
    }

    function step() {
      ctx.clearRect(0, 0, width, height);
      const linkDist = 150;

      nodes.forEach((n) => {
        n.x += n.vx;
        n.y += n.vy;
        if (mouseX !== null) {
          n.x += (mouseX - width / 2) * 0.00004;
          n.y += (mouseY - height / 2) * 0.00004;
        }
        if (n.x < 0 || n.x > width) n.vx *= -1;
        if (n.y < 0 || n.y > height) n.vy *= -1;
        n.pulse += 0.02;
      });

      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i], b = nodes[j];
          const dx = a.x - b.x, dy = a.y - b.y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < linkDist) {
            ctx.strokeStyle = `rgba(40,215,197,${(1 - dist / linkDist) * 0.35})`;
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.stroke();

            if (Math.random() < 0.0025) {
              ctx.fillStyle = "rgba(124,140,255,0.9)";
              ctx.beginPath();
              ctx.arc(a.x, a.y, 2, 0, Math.PI * 2);
              ctx.fill();
            }
          }
        }
      }

      nodes.forEach((n) => {
        const glow = 0.6 + Math.sin(n.pulse) * 0.4;
        ctx.fillStyle = `rgba(124,140,255,${glow})`;
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
        ctx.fill();
      });

      if (running) animId = requestAnimationFrame(step);
    }

    function start() { if (!running) { running = true; animId = requestAnimationFrame(step); } }
    function stop() { running = false; if (animId) cancelAnimationFrame(animId); }

    resize();
    start();
    window.addEventListener("resize", resize);
    host.addEventListener("mousemove", (e) => {
      const rect = host.getBoundingClientRect();
      mouseX = e.clientX - rect.left;
      mouseY = e.clientY - rect.top;
    });
    host.addEventListener("mouseleave", () => { mouseX = null; mouseY = null; });

    document.addEventListener("visibilitychange", () => { document.hidden ? stop() : start(); });
    const hostObserver = new IntersectionObserver((entries) => {
      entries.forEach((e) => (e.isIntersecting ? start() : stop()));
    }, { threshold: 0 });
    hostObserver.observe(host);
  }

  if (!reduceMotion) {
    document.querySelectorAll("#network-canvas, .network-canvas").forEach(initNetworkCanvas);
  }

  /* ---------- 3. Hero card tilt ---------- */
  const tiltCard = document.querySelector(".hero-card");
  if (tiltCard && !reduceMotion && window.matchMedia("(pointer: fine)").matches) {
    const strength = 10;
    tiltCard.addEventListener("mousemove", (e) => {
      const rect = tiltCard.getBoundingClientRect();
      const x = (e.clientX - rect.left) / rect.width - 0.5;
      const y = (e.clientY - rect.top) / rect.height - 0.5;
      tiltCard.style.transform = `perspective(800px) rotateY(${x * strength}deg) rotateX(${-y * strength}deg)`;
    });
    tiltCard.addEventListener("mouseleave", () => {
      tiltCard.style.transform = "perspective(800px) rotateY(0deg) rotateX(0deg)";
    });
  }

  /* ---------- 4. Toolkit terminal typewriter ---------- */
  const typeEl = document.querySelector(".type-text");
  if (typeEl && !reduceMotion) {
    const phrases = [
      "ping 8.8.8.8",
      "nslookup sagarrajput.com",
      "calculate 192.168.1.0/24",
      "traceroute to destination",
      "scan authorized host",
    ];
    let pIndex = 0, charIndex = 0, deleting = false;

    function tick() {
      const current = phrases[pIndex];
      if (!deleting) {
        charIndex++;
        typeEl.textContent = current.slice(0, charIndex);
        if (charIndex === current.length) { deleting = true; setTimeout(tick, 1400); return; }
      } else {
        charIndex--;
        typeEl.textContent = current.slice(0, charIndex);
        if (charIndex === 0) { deleting = false; pIndex = (pIndex + 1) % phrases.length; }
      }
      setTimeout(tick, deleting ? 35 : 55);
    }
    tick();
  }
});