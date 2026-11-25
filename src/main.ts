// Screens, editor and results. The game logic lives in rules.ts, sim.ts and levels.ts.

import { formatIp } from "./ip";
import { LEVELS, type Level, seeded } from "./levels";
import { parseRules, RuleError, type Ruleset } from "./rules";
import { type Packet, pct, simulate, stats, type Verdict } from "./sim";
import { Stage } from "./stage";

const $ = <T extends HTMLElement>(sel: string) => document.querySelector(sel) as T;
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

// Storage can be missing or throw (private mode, blocked cookies): the game still works without it.
const store = {
  get(key: string): string | null {
    try { return localStorage.getItem(`fwd:${key}`); } catch { return null; }
  },
  set(key: string, value: string): void {
    try { localStorage.setItem(`fwd:${key}`, value); } catch { /* not saved, not fatal */ }
  },
};

const editor = $<HTMLTextAreaElement>("#rules");
const gutter = $<HTMLElement>("#gutter");
const status = $<HTMLElement>("#status");
const runBtn = $<HTMLButtonElement>("#run");
const stage = new Stage($<HTMLCanvasElement>("#stage"));

let level: Level = LEVELS[0];
let parsed: Ruleset | null = null;

// -- level select ---------------------------------------------------------------------
const stars = (id: number) => Number(store.get(`stars:${id}`) ?? 0);

function renderLevels(): void {
  $("#levels").innerHTML = LEVELS.map((l) => {
    const s = stars(l.id);
    return `<button class="chip${l.id === level.id ? " on" : ""}" data-level="${l.id}" aria-label="Level ${l.id}: ${esc(l.title)}">
      <b>${l.id}</b><i>${"★".repeat(s)}<s>${"★".repeat(3 - s)}</s></i></button>`;
  }).join("");
}

$("#levels").addEventListener("click", (e) => {
  const btn = (e.target as HTMLElement).closest<HTMLButtonElement>("[data-level]");
  if (btn) openLevel(Number(btn.dataset.level));
});

function openLevel(id: number): void {
  level = LEVELS[id - 1];
  store.set("last", String(id));
  renderLevels();
  $("#level-no").textContent = `Level ${level.id} of ${LEVELS.length}`;
  $("#level-title").textContent = level.title;
  $("#story").innerHTML = level.story.split("\n\n").map((p) => `<p>${esc(p)}</p>`).join("");
  $("#services").innerHTML = level.services.map((s) =>
    `<tr><td><code>${esc(s.port)}</code></td><td>${esc(s.name)}</td><td>${esc(s.who)}</td></tr>`).join("");
  $("#goals").innerHTML = `To pass: let in <b>${level.goals.legit}%</b> of real traffic and block
    <b>${level.goals.blocked}%</b> of attacks. Third star: ${level.par} rule${level.par === 1 ? "" : "s"} or fewer
    (the policy line does not count).`;
  $("#hint").hidden = true;
  $("#hint").textContent = level.hint;
  editor.value = store.get(`rules:${level.id}`) ?? level.starter;
  $("#results").innerHTML = "";
  $("#live").textContent = "";
  stage.setLevel(level);
  onEdit();
}

// -- editor -------------------------------------------------------------------------------
function onEdit(): void {
  store.set(`rules:${level.id}`, editor.value);
  const lines = editor.value.split("\n").length;
  let errorLine = 0;
  try {
    parsed = parseRules(editor.value);
    const n = parsed.rules.length;
    status.className = "status";
    status.textContent = `${n} rule${n === 1 ? "" : "s"} · policy ${parsed.policy}`;
  } catch (err) {
    parsed = null;
    if (!(err instanceof RuleError)) throw err;
    errorLine = err.line;
    status.className = "status error";
    status.textContent = err.message;
  }
  gutter.innerHTML = Array.from({ length: lines }, (_, i) =>
    `<span${i + 1 === errorLine ? ' class="bad"' : ""}>${i + 1}</span>`).join("");
  gutter.scrollTop = editor.scrollTop;
  runBtn.disabled = parsed === null || stage.running;
}

editor.addEventListener("input", onEdit);
editor.addEventListener("scroll", () => { gutter.scrollTop = editor.scrollTop; });
editor.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
    e.preventDefault();
    run();
  }
});

$("#hint-btn").addEventListener("click", () => { $("#hint").hidden = !$("#hint").hidden; });
$("#reset").addEventListener("click", () => {
  editor.value = level.starter;
  onEdit();
  editor.focus();
});

// -- running a wave ------------------------------------------------------------------------
let seedCounter = Number(store.get("seed") ?? Date.now() % 100000);

function run(): void {
  if (!parsed || stage.running) return;
  const rules = parsed;
  seedCounter = (seedCounter + 1) % 1_000_000;
  store.set("seed", String(seedCounter));
  const packets = level.traffic(seeded(seedCounter * 2654435761));
  const verdicts = simulate(rules, packets);
  runBtn.disabled = true;
  $("#skip").hidden = false;
  $("#results").innerHTML = "";
  const live = $("#live");
  stage.play(verdicts, level.duration, (p) => {
    live.innerHTML = `<span class="legit">● real traffic in ${p.legitIn}/${p.legitSeen}</span>
      <span class="attack">● attacks blocked ${p.blocked}/${p.attacksSeen}</span>
      <span class="mute">${p.done}/${p.total} packets</span>`;
  }, () => {
    $("#skip").hidden = true;
    runBtn.disabled = parsed === null;
    showResults(rules, verdicts);
  });
}

runBtn.addEventListener("click", run);
$("#skip").addEventListener("click", () => stage.finish());
$<HTMLInputElement>("#speed").addEventListener("change", (e) => {
  stage.speed = (e.target as HTMLInputElement).checked ? 3 : 1;
});

// -- results -----------------------------------------------------------------------------------
function describe(p: Packet): string {
  const ports = p.proto === "icmp" ? "" : `:${p.sport} → :${p.dport}`;
  return `${p.proto} ${formatIp(p.src)}${ports} · ${p.iface} · ${p.state}`;
}

function decidedBy(v: Verdict, rules: Ruleset): string {
  return v.rule
    ? `line ${v.rule.line}: <code>${esc(v.rule.text)}</code>`
    : `the policy, because no rule matched: <code>policy ${rules.policy}</code>`;
}

function showResults(rules: Ruleset, verdicts: Verdict[]): void {
  const s = stats(verdicts);
  const legit = pct(s.legitAllowed, s.legit);
  const blocked = pct(s.attacksBlocked, s.attacks);
  const passed = legit >= level.goals.legit && blocked >= level.goals.blocked;
  const n = rules.rules.length;
  const earned = passed ? (n <= level.par ? 3 : n <= level.par + 2 ? 2 : 1) : 0;
  if (earned > stars(level.id)) store.set(`stars:${level.id}`, String(earned));
  renderLevels();

  // Group packets by what they are, so the player sees which traffic went wrong.
  const groups = new Map<string, Verdict[]>();
  for (const v of verdicts) groups.set(v.packet.kind, [...(groups.get(v.packet.kind) ?? []), v]);
  const rows = [...groups.entries()]
    .sort(([, a], [, b]) => Number(a[0].packet.legit) - Number(b[0].packet.legit))
    .map(([kind, vs]) => {
      const legitKind = vs[0].packet.legit;
      const wrong = vs.filter((v) => (v.action === "allow") !== legitKind);
      const example = wrong[0] ?? vs[0];
      const allowed = vs.filter((v) => v.action === "allow").length;
      return `<details class="row ${wrong.length ? "bad" : "good"}"${wrong.length ? " open" : ""}>
        <summary><i class="${legitKind ? "legit" : "attack"}">●</i><span>${esc(kind)}</span>
          <em>${allowed} in · ${vs.length - allowed} dropped</em>
          <b>${wrong.length ? `✕ ${wrong.length} wrong` : "✓"}</b></summary>
        <p><code>${esc(describe(example.packet))}</code></p>
        <p>${wrong.length ? (legitKind ? "Dropped by " : "Let in by ") : "Decided by "}${decidedBy(example, rules)}</p>
      </details>`;
    }).join("");

  const meter = (label: string, value: number, goal: number, cls: string) => `
    <div class="meter ${value >= goal ? "ok" : "low"}">
      <div class="meter-top"><span>${label}</span><b>${value.toFixed(value % 1 ? 1 : 0)}%</b></div>
      <div class="bar"><i class="${cls}" style="width:${value}%"></i><u style="left:${goal}%"></u></div>
      <small>goal ${goal}%</small>
    </div>`;

  const next = LEVELS[level.id];
  $("#results").innerHTML = `
    <div class="verdict ${passed ? "pass" : "fail"}">
      ${passed
        ? `<h3>Level passed <span class="stars">${"★".repeat(earned)}${"☆".repeat(3 - earned)}</span></h3>
           <p>${esc(level.lesson)}</p>
           ${earned < 3 ? `<p class="mute">Third star: solve it with ${level.par} rule${level.par === 1 ? "" : "s"} or fewer (you used ${n}).</p>` : ""}
           ${next ? `<button class="go" id="next">Next: ${esc(next.title)} →</button>` : `<p><b>That was the last level.</b> You just wrote a production firewall.</p>`}`
        : `<h3>Not yet</h3><p>${failReason(s.legit - s.legitAllowed, s.attacks - s.attacksBlocked, blocked)}</p>`}
    </div>
    <div class="meters">
      ${meter("Real traffic let in", legit, level.goals.legit, "legit")}
      ${meter("Attacks blocked", blocked, level.goals.blocked, "attack")}
    </div>
    <h4>What arrived <span class="mute">(new traffic is generated on every run)</span></h4>
    <div class="rows">${rows}</div>`;
  $("#next")?.addEventListener("click", () => openLevel(next!.id));
  $("#results").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function failReason(legitLost: number, attacksIn: number, blocked: number): string {
  const parts: string[] = [];
  if (legitLost) parts.push(`${legitLost} real packet${legitLost === 1 ? " was" : "s were"} dropped`);
  if (blocked < level.goals.blocked) parts.push(`${attacksIn} attack${attacksIn === 1 ? "" : "s"} got through`);
  return `${parts.join(" and ")}. The rows marked ✕ below show which traffic and which rule decided.`;
}

// -- start -----------------------------------------------------------------------------------
const fromUrl = Number(new URLSearchParams(location.search).get("level"));
const lastLevel = Number(store.get("last"));
openLevel(fromUrl >= 1 && fromUrl <= LEVELS.length ? fromUrl : lastLevel >= 1 && lastLevel <= LEVELS.length ? lastLevel : 1);
