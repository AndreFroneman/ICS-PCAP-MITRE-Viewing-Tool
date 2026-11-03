import { useEffect, useRef } from "react";

export function HorizonField() {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const cv = ref.current;
    if (!cv) return;
    const ctx = cv.getContext("2d");
    if (!ctx) return;
    const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
    let frame = 0;
    const mouse = { x: -9999, y: -9999 };
    type P = { x: number; y: number; vx: number; vy: number; r: number };
    let parts: P[] = [];
    let w = 0;
    let h = 0;
    const dpr = Math.min(devicePixelRatio || 1, 2);
    const resize = () => {
      w = cv.width = innerWidth * dpr;
      h = cv.height = innerHeight * dpr;
      cv.style.width = `${innerWidth}px`;
      cv.style.height = `${innerHeight}px`;
      const n = Math.min(110, Math.floor((innerWidth * innerHeight) / 16000));
      parts = Array.from({ length: n }, () => ({
        x: Math.random() * w,
        y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.25 * dpr,
        vy: (Math.random() - 0.5) * 0.25 * dpr,
        r: (Math.random() * 1.4 + 0.4) * dpr,
      }));
    };
    const onMove = (event: MouseEvent) => {
      mouse.x = event.clientX * dpr;
      mouse.y = event.clientY * dpr;
    };
    resize();
    addEventListener("resize", resize);
    addEventListener("mousemove", onMove);
    const loop = () => {
      ctx.clearRect(0, 0, w, h);
      const reach = 130 * dpr;
      for (const p of parts) {
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < 0 || p.x > w) p.vx *= -1;
        if (p.y < 0 || p.y > h) p.vy *= -1;
        const dx = p.x - mouse.x;
        const dy = p.y - mouse.y;
        const dist = Math.hypot(dx, dy);
        if (dist < 160 * dpr && dist > 0) {
          p.x += (dx / dist) * 1.1;
          p.y += (dy / dist) * 1.1;
        }
        ctx.fillStyle = "rgba(34,230,255,.55)";
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fill();
      }
      for (let i = 0; i < parts.length; i++) {
        for (let j = i + 1; j < parts.length; j++) {
          const a = parts[i];
          const b = parts[j];
          const dist = Math.hypot(a.x - b.x, a.y - b.y);
          if (dist < reach) {
            ctx.strokeStyle = `rgba(34,230,255,${(1 - dist / reach) * 0.18})`;
            ctx.lineWidth = dpr * 0.7;
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.stroke();
          }
        }
      }
      if (!reduce) frame = requestAnimationFrame(loop);
    };
    loop();
    return () => {
      cancelAnimationFrame(frame);
      removeEventListener("resize", resize);
      removeEventListener("mousemove", onMove);
    };
  }, []);
  return (
    <>
      <canvas id="bgfx" ref={ref} aria-hidden="true" />
      <div className="scan" />
      <div className="vignette" />
    </>
  );
}

export function CursorFollower() {
  const ring = useRef<HTMLDivElement>(null);
  const dot = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!matchMedia("(hover: hover)").matches) return;
    const c = ring.current;
    const d = dot.current;
    if (!c || !d) return;
    let tx = 0;
    let ty = 0;
    let cx = 0;
    let cy = 0;
    let frame = 0;
    const move = (event: MouseEvent) => {
      tx = event.clientX;
      ty = event.clientY;
      d.style.left = `${tx}px`;
      d.style.top = `${ty}px`;
    };
    const over = (event: MouseEvent) => {
      const target = event.target instanceof Element ? event.target : null;
      c.classList.toggle("big", Boolean(target?.closest("a, button, .card, .hz-btn")));
    };
    const tick = () => {
      cx += (tx - cx) * 0.18;
      cy += (ty - cy) * 0.18;
      c.style.left = `${cx}px`;
      c.style.top = `${cy}px`;
      frame = requestAnimationFrame(tick);
    };
    addEventListener("mousemove", move);
    addEventListener("mouseover", over);
    tick();
    return () => {
      cancelAnimationFrame(frame);
      removeEventListener("mousemove", move);
      removeEventListener("mouseover", over);
    };
  }, []);
  return (
    <>
      <div className="cur" ref={ring} />
      <div className="cur-dot" ref={dot} />
    </>
  );
}

export function Mark({ className = "mark" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 40 40" fill="none" aria-hidden="true">
      <polygon points="20,2 37,11 37,29 20,38 3,29 3,11" stroke="currentColor" strokeWidth="1.6" />
      <path d="M8 24h24" stroke="#22e6ff" strokeWidth="2" />
      <circle cx="20" cy="24" r="6" stroke="#fff" strokeWidth="1.4" />
      <path d="M20 8v6" stroke="#fff" strokeWidth="1.4" />
    </svg>
  );
}
