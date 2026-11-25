// The rule language: a small, readable cousin of iptables.
//
//   policy drop
//   allow state established
//   allow tcp port 80,443
//   allow tcp port 22 from 198.51.100.0/24
//   allow tcp port 22 limit 3/m per-src
//   drop in wan from 10.0.0.0/8
//
// Rules are checked from the top; the first one that matches decides.
// Packets that no rule matches follow the policy (allow, unless changed).

import { type Cidr, parseCidr } from "./ip";

export type Action = "allow" | "drop";
export type Proto = "tcp" | "udp" | "icmp";
export type Iface = "wan" | "lan";
export type State = "new" | "established";

export interface PortRange {
  lo: number;
  hi: number;
}

export interface Limit {
  count: number;
  perSeconds: number;
  perSrc: boolean;
}

export interface Rule {
  line: number;          // 1-based line in the editor
  text: string;
  action: Action;
  proto?: Proto;
  from?: Cidr;
  ports?: PortRange[];   // destination ports
  sports?: PortRange[];  // source ports
  iface?: Iface;
  state?: State;
  limit?: Limit;
}

export interface Ruleset {
  rules: Rule[];
  policy: Action;
}

export class RuleError extends Error {
  constructor(public line: number, message: string) {
    super(`line ${line}: ${message}`);
  }
}

const WORDS = ["allow", "drop", "policy", "tcp", "udp", "icmp", "from", "port", "sport", "in", "state", "limit",
  "per-src", "wan", "lan", "new", "established"];

export function parseRules(source: string): Ruleset {
  const rules: Rule[] = [];
  let policy: Action = "allow";
  let policySeen = 0;
  source.split("\n").forEach((raw, i) => {
    const line = i + 1;
    const text = raw.replace(/#.*/, "").trim();
    if (!text) return;
    const words = text.toLowerCase().split(/\s+/);
    if (words[0] === "policy") {
      if (words.length !== 2 || (words[1] !== "allow" && words[1] !== "drop")) {
        throw new RuleError(line, "write 'policy allow' or 'policy drop'");
      }
      if (policySeen) throw new RuleError(line, `the policy is already set on line ${policySeen}`);
      policy = words[1];
      policySeen = line;
      return;
    }
    rules.push(parseRule(words, line, raw.trim()));
  });
  return { rules, policy };
}

function parseRule(words: string[], line: number, text: string): Rule {
  const [first, ...rest] = words;
  if (first !== "allow" && first !== "drop") {
    throw new RuleError(line, `a rule starts with 'allow' or 'drop'${suggest(first)}`);
  }
  const rule: Rule = { line, text, action: first };
  const seen = new Set<string>();
  const once = (key: string) => {
    if (seen.has(key)) throw new RuleError(line, `'${key}' appears twice`);
    seen.add(key);
  };
  const need = (i: number, what: string) => {
    if (i >= rest.length) throw new RuleError(line, `'${rest[i - 1]}' needs ${what}`);
    return rest[i];
  };

  for (let i = 0; i < rest.length; i++) {
    const w = rest[i];
    if (w === "tcp" || w === "udp" || w === "icmp") {
      once("protocol");
      rule.proto = w;
    } else if (w === "from") {
      once("from");
      const value = need(++i, "an address like 203.0.113.0/24");
      const cidr = parseCidr(value);
      if (!cidr) throw new RuleError(line, `'${value}' is not an address or network (example: 10.0.0.0/8)`);
      rule.from = cidr;
    } else if (w === "port" || w === "sport") {
      once(w);
      const value = need(++i, "a port, a list or a range: 22, 80,443 or 1024-65535");
      const ports = parsePorts(value);
      if (!ports) throw new RuleError(line, `'${value}' is not a port list (examples: 22, 80,443, 1024-65535)`);
      if (w === "port") rule.ports = ports;
      else rule.sports = ports;
    } else if (w === "in") {
      once("in");
      const value = need(++i, "'wan' or 'lan'");
      if (value !== "wan" && value !== "lan") throw new RuleError(line, "'in' must be followed by 'wan' or 'lan'");
      rule.iface = value;
    } else if (w === "state") {
      once("state");
      const value = need(++i, "'new' or 'established'");
      if (value !== "new" && value !== "established") {
        throw new RuleError(line, "'state' must be followed by 'new' or 'established'");
      }
      rule.state = value;
    } else if (w === "limit") {
      once("limit");
      const value = need(++i, "a rate like 3/m or 10/s");
      const m = /^([1-9][0-9]{0,4})\/(s|m)$/.exec(value);
      if (!m) throw new RuleError(line, `'${value}' is not a rate (examples: 3/m, 10/s)`);
      rule.limit = { count: Number(m[1]), perSeconds: m[2] === "s" ? 1 : 60, perSrc: false };
      if (rest[i + 1] === "per-src") {
        rule.limit.perSrc = true;
        i++;
      }
    } else if (w === "per-src") {
      throw new RuleError(line, "'per-src' goes right after a limit, as in 'limit 3/m per-src'");
    } else {
      throw new RuleError(line, `unknown word '${w}'${suggest(w)}`);
    }
  }
  if ((rule.ports || rule.sports) && rule.proto !== "tcp" && rule.proto !== "udp") {
    // Same as iptables: only TCP and UDP have ports.
    throw new RuleError(line, "ports need a protocol: add 'tcp' or 'udp'");
  }
  return rule;
}

export function parsePorts(text: string): PortRange[] | null {
  const out: PortRange[] = [];
  for (const part of text.split(",")) {
    const m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(part);
    if (!m) return null;
    const lo = Number(m[1]);
    const hi = m[2] === undefined ? lo : Number(m[2]);
    if (lo < 1 || hi > 65535 || lo > hi) return null;
    out.push({ lo, hi });
  }
  return out;
}

function suggest(word: string): string {
  let best = "";
  let bestD = 3;
  for (const w of WORDS) {
    const d = distance(word, w);
    if (d < bestD) {
      best = w;
      bestD = d;
    }
  }
  return best ? ` (did you mean '${best}'?)` : "";
}

/** Edit distance where swapping two neighbouring letters counts as one typo ("prot" -> "port"). */
function distance(a: string, b: string): number {
  const d = Array.from({ length: a.length + 1 }, (_, i) =>
    Array.from({ length: b.length + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0)));
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
    }
  }
  return d[a.length][b.length];
}
