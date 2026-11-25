// The animated view: packets fly from the internet (and the LAN) to the
// firewall; allowed ones continue to the server, dropped ones burst on the wall.

import type { Level } from "./levels";
import type { Verdict } from "./sim";

const COLORS = {
  legit: "#4cc9f0",
  attack: "#f72585",
  wall: "#ff9f1c",
  miss: "#ffd166",
  breach: "#ff4d6d",
  text: "rgba(226,232,255,.72)",
  faint: "rgba(226,232,255,.08)",
};

const TO_WALL = 900;     // ms from the left edge to the firewall
const TO_SERVER = 650;   // ms from the firewall to the server

interface Shot {
  v: Verdict;
  at: number;            // ms after the start when the packet appears
  y0: number;            // 0..1, height where it starts
  y1: number;            // 0..1, height where it hits the server
  counted: boolean;
}

interface Effect {
  x: number;
  y: number;
  born: number;
  kind: "spark" | "miss";
}

export interface Progress {
  done: number;
  total: number;
  legitIn: number;
  legitSeen: number;
  blocked: number;
  attacksSeen: number;
}

function hash01(n: number): number {
  let x = n >>> 0;
  x = Math.imul(x ^ (x >>> 16), 0x45d9f3b);
  x = Math.imul(x ^ (x >>> 16), 0x45d9f3b);
  return ((x ^ (x >>> 16)) >>> 0) / 4294967296;
}

export class Stage {
  private ctx: CanvasRenderingContext2D;
  private w = 0;
  private h = 0;
  private shots: Shot[] = [];
  private effects: Effect[] = [];
  private start = 0;
  private end = 0;
  private level: Level | null = null;
  private serverHit = -1e9;
  private raf = 0;
  private progress: Progress = { done: 0, total: 0, legitIn: 0, legitSeen: 0, blocked: 0, attacksSeen: 0 };
  private onProgress: (p: Progress) => void = () => {};
  private onDone: () => void = () => {};
  speed = 1;

  constructor(private canvas: HTMLCanvasElement) {
    this.ctx = canvas.getContext("2d")!;
    new ResizeObserver(() => this.resize()).observe(canvas);
    this.resize();
  }

  setLevel(level: Level): void {
    this.level = level;
    this.stop();
    this.shots = [];
    this.effects = [];
    this.draw(performance.now());
  }

  get running(): boolean {
    return this.raf !== 0;
  }

  play(verdicts: Verdict[], duration: number, onProgress: (p: Progress) => void, onDone: () => void): void {
    this.stop();
    const span = 9000;  // the whole wave plays in about nine seconds, whatever its simulated length
    this.shots = verdicts.map((v) => {
      const lan = v.packet.iface === "lan";
      const r = hash01(v.packet.src);
      return {
        v, at: (v.packet.t / duration) * span, counted: false,
        y0: lan ? 0.86 + r * 0.08 : 0.1 + r * 0.66,
        y1: 0.3 + hash01(v.packet.dport * 7919 + 1) * 0.4,
      };
    });
    this.effects = [];
    this.progress = { done: 0, total: verdicts.length, legitIn: 0, legitSeen: 0, blocked: 0, attacksSeen: 0 };
    this.onProgress = onProgress;
    this.onDone = onDone;
    this.start = performance.now();
    this.end = span + TO_WALL + TO_SERVER + 600;
    this.clock = 0;
    this.last = this.start;
    this.raf = requestAnimationFrame((t) => this.frame(t));
  }

  /** Jump to the end of the wave. */
  finish(): void {
    if (!this.running) return;
    this.clock = this.end;
  }

  stop(): void {
    if (this.raf) cancelAnimationFrame(this.raf);
    this.raf = 0;
  }

  // -- animation ----------------------------------------------------------------
  private clock = 0;   // ms of wave time, advanced by real time × speed
  private last = 0;

  private frame(now: number): void {
    this.clock += (now - this.last) * this.speed;
    this.last = now;
    for (const s of this.shots) {
      if (!s.counted && this.clock >= s.at + TO_WALL) this.count(s, now);
    }
    this.draw(now);
    if (this.clock >= this.end) {
      this.raf = 0;
      this.onDone();
      this.settle(now + 1700);
      return;
    }
    this.raf = requestAnimationFrame((t) => this.frame(t));
  }

  /** Keep drawing for a moment after the wave so sparks and flashes fade out. */
  private settle(until: number): void {
    const step = (now: number) => {
      if (this.running) return;  // a new wave took over
      this.draw(now);
      if (now < until) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  private count(s: Shot, now: number): void {
    s.counted = true;
    const p = this.progress;
    const allowed = s.v.action === "allow";
    p.done++;
    if (s.v.packet.legit) {
      p.legitSeen++;
      if (allowed) p.legitIn++;
      else this.effects.push({ x: 0.52, y: s.y0, born: now, kind: "miss" });
    } else {
      p.attacksSeen++;
      if (!allowed) p.blocked++;
    }
    if (!allowed) this.effects.push({ x: 0.52, y: s.y0, born: now, kind: "spark" });
    this.onProgress({ ...p });
  }

  private resize(): void {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const rect = this.canvas.getBoundingClientRect();
    this.w = rect.width;
    this.h = rect.height;
    this.canvas.width = Math.round(rect.width * dpr);
    this.canvas.height = Math.round(rect.height * dpr);
    this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    if (!this.running) this.draw(performance.now());
  }

  // -- drawing ------------------------------------------------------------------
  /** Where the server box sits; wider on narrow screens so its labels fit. */
  private server(): { x: number; y: number; w: number; h: number } {
    const sw = Math.max(Math.min(0.17 * this.w, 170), 118);
    return { x: Math.min(0.8 * this.w, this.w - sw - 10), y: 0.16 * this.h, w: sw, h: 0.68 * this.h };
  }

  private draw(now: number): void {
    const { ctx, w, h } = this;
    if (!w || !h) return;
    ctx.clearRect(0, 0, w, h);
    this.scenery(now);

    const wallX = 0.52 * w;
    const srvX = this.server().x;
    for (const s of this.shots) {
      const age = this.clock - s.at;
      if (age < 0) continue;
      const legit = s.v.packet.legit;
      const color = legit ? COLORS.legit : COLORS.attack;
      let x: number;
      let y: number;
      if (age < TO_WALL) {
        const k = age / TO_WALL;
        x = 0.03 * w + (wallX - 0.03 * w) * k;
        y = s.y0 * h;
      } else if (s.v.action === "allow" && age < TO_WALL + TO_SERVER) {
        const k = (age - TO_WALL) / TO_SERVER;
        const e = k * k * (3 - 2 * k);
        x = wallX + (srvX - wallX) * k;
        y = (s.y0 + (s.y1 - s.y0) * e) * h;
        if (!legit && k > 0.95 && now - this.serverHit > 120) this.serverHit = now;
      } else {
        continue;
      }
      ctx.fillStyle = color;
      ctx.shadowColor = color;
      ctx.shadowBlur = 10;
      ctx.beginPath();
      ctx.arc(x, y, legit ? 3.2 : 3.6, 0, Math.PI * 2);
      ctx.fill();
      ctx.shadowBlur = 0;
      ctx.globalAlpha = 0.25;
      ctx.fillRect(x - 18, y - 1, 16, 2);
      ctx.globalAlpha = 1;
    }

    this.effects = this.effects.filter((e) => now - e.born < (e.kind === "spark" ? 450 : 1600));
    for (const e of this.effects) {
      const age = now - e.born;
      const x = e.x * w;
      const y = e.y * h;
      if (e.kind === "spark") {
        const k = age / 450;
        ctx.strokeStyle = COLORS.wall;
        ctx.globalAlpha = 1 - k;
        for (let i = 0; i < 6; i++) {
          const a = (i / 6) * Math.PI * 2 + e.y * 10;
          ctx.beginPath();
          ctx.moveTo(x + Math.cos(a) * 3, y + Math.sin(a) * 3);
          ctx.lineTo(x + Math.cos(a) * (4 + k * 12), y + Math.sin(a) * (4 + k * 12));
          ctx.stroke();
        }
        ctx.globalAlpha = 1;
      } else if (e.kind === "miss") {
        // A real user was blocked: leave a visible mark on the wall.
        ctx.globalAlpha = 1 - age / 1600;
        ctx.strokeStyle = COLORS.miss;
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.arc(x, y, 9, 0, Math.PI * 2);
        ctx.moveTo(x - 4, y - 4);
        ctx.lineTo(x + 4, y + 4);
        ctx.moveTo(x + 4, y - 4);
        ctx.lineTo(x - 4, y + 4);
        ctx.stroke();
        ctx.lineWidth = 1;
        ctx.globalAlpha = 1;
      }
    }
  }

  private scenery(now: number): void {
    const { ctx, w, h } = this;
    // grid
    ctx.strokeStyle = COLORS.faint;
    ctx.lineWidth = 1;
    for (let x = 0; x < w; x += 32) {
      ctx.beginPath();
      ctx.moveTo(x + 0.5, 0);
      ctx.lineTo(x + 0.5, h);
      ctx.stroke();
    }
    for (let y = 0; y < h; y += 32) {
      ctx.beginPath();
      ctx.moveTo(0, y + 0.5);
      ctx.lineTo(w, y + 0.5);
      ctx.stroke();
    }

    ctx.font = "600 11px ui-monospace, SFMono-Regular, Menlo, monospace";
    ctx.fillStyle = COLORS.text;
    ctx.fillText("INTERNET · wan", 12, 20);
    ctx.fillText("LAN · 10.0.1.0/24", 12, h * 0.84);
    ctx.strokeStyle = "rgba(226,232,255,.14)";
    ctx.setLineDash([4, 6]);
    ctx.beginPath();
    ctx.moveTo(0, h * 0.81);
    ctx.lineTo(0.5 * w, h * 0.81);
    ctx.stroke();
    ctx.setLineDash([]);

    // firewall
    const wallX = 0.52 * w;
    const glow = ctx.createLinearGradient(wallX - 26, 0, wallX + 26, 0);
    glow.addColorStop(0, "rgba(255,159,28,0)");
    glow.addColorStop(0.5, "rgba(255,159,28,.22)");
    glow.addColorStop(1, "rgba(255,159,28,0)");
    ctx.fillStyle = glow;
    ctx.fillRect(wallX - 26, 0, 52, h);
    const brickH = 14;
    for (let y = 0, row = 0; y < h; y += brickH, row++) {
      ctx.fillStyle = row % 2 ? "#c46d0c" : "#e0820f";
      ctx.fillRect(wallX - 5, y + 1, 10, brickH - 2);
    }
    ctx.fillStyle = COLORS.wall;
    ctx.fillText("FIREWALL", wallX + 12, h - 12);

    // server
    const { x: sx, y: sy, w: sw, h: sh } = this.server();
    const hit = Math.max(0, 1 - (now - this.serverHit) / 400);
    ctx.fillStyle = "#121a38";
    ctx.strokeStyle = hit > 0 ? `rgba(255,77,109,${0.4 + hit * 0.6})` : "rgba(226,232,255,.25)";
    ctx.lineWidth = hit > 0 ? 2 + hit * 2 : 1;
    roundRect(ctx, sx, sy, sw, sh, 10);
    ctx.fill();
    ctx.stroke();
    ctx.lineWidth = 1;
    ctx.fillStyle = COLORS.text;
    ctx.fillText("SERVER", sx + 12, sy + 22);
    const services = this.level?.services ?? [];
    services.forEach((s, i) => {
      const y = sy + 48 + i * 30;
      if (y > sy + sh - 10) return;
      ctx.fillStyle = "#4ade80";
      ctx.beginPath();
      ctx.arc(sx + 16, y - 4, 3, 0, Math.PI * 2);
      ctx.fill();
      ctx.fillStyle = "rgba(226,232,255,.9)";
      const max = Math.floor((sw - 34) / 7);
      ctx.fillText(s.name.length > max ? s.name.slice(0, max - 1) + "…" : s.name, sx + 26, y);
      ctx.fillStyle = COLORS.text;
      ctx.fillText(s.port, sx + 26, y + 13);
    });
    if (hit > 0) {
      ctx.fillStyle = `rgba(255,77,109,${hit})`;
      ctx.fillText("ATTACK GOT IN", sx + 12, sy + sh - 14);
    }

    if (!this.shots.length) {
      ctx.fillStyle = COLORS.text;
      ctx.font = "500 13px ui-sans-serif, system-ui, sans-serif";
      ctx.fillText("Write your rules,", 0.05 * w, h * 0.42);
      ctx.fillText("then press Run.", 0.05 * w, h * 0.42 + 18);
    }
  }
}

function roundRect(ctx: CanvasRenderingContext2D, x: number, y: number, w: number, h: number, r: number): void {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.arcTo(x + w, y, x + w, y + h, r);
  ctx.arcTo(x + w, y + h, x, y + h, r);
  ctx.arcTo(x, y + h, x, y, r);
  ctx.arcTo(x, y, x + w, y, r);
  ctx.closePath();
}
