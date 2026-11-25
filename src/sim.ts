// Runs a wave of packets through a ruleset.

import { inCidr } from "./ip";
import type { Action, Iface, PortRange, Proto, Rule, Ruleset, State } from "./rules";

export interface Packet {
  t: number;             // arrival time in seconds since the wave started
  proto: Proto;
  src: number;           // source IPv4 as uint32
  sport: number;         // 0 for icmp
  dport: number;         // 0 for icmp
  iface: Iface;          // wan = from the internet, lan = from the internal network
  state: State;          // established = reply to a connection the server opened
  legit: boolean;
  kind: string;          // short label shown to the player, e.g. "SSH brute force"
}

export interface Verdict {
  packet: Packet;
  action: Action;
  rule: Rule | null;     // null when the policy decided
}

export interface Stats {
  legit: number;
  legitAllowed: number;
  attacks: number;
  attacksBlocked: number;
}

const inPorts = (port: number, ranges: PortRange[]) => ranges.some((r) => port >= r.lo && port <= r.hi);

/** Everything except the rate limit. */
export function matches(rule: Rule, p: Packet): boolean {
  if (rule.proto && rule.proto !== p.proto) return false;
  if (rule.from && !inCidr(p.src, rule.from)) return false;
  if (rule.ports && !inPorts(p.dport, rule.ports)) return false;
  if (rule.sports && !inPorts(p.sport, rule.sports)) return false;
  if (rule.iface && rule.iface !== p.iface) return false;
  if (rule.state && rule.state !== p.state) return false;
  return true;
}

/**
 * Token bucket, like iptables' limit/hashlimit: the bucket holds up to
 * `count` tokens and refills at `count` per period. A packet that finds the
 * bucket empty does not match the rule and moves on to the next one.
 */
class Buckets {
  private state = new Map<string, { tokens: number; at: number }>();

  take(key: string, count: number, perSeconds: number, now: number): boolean {
    const rate = count / perSeconds;
    let b = this.state.get(key);
    if (!b) {
      b = { tokens: count, at: now };
      this.state.set(key, b);
    }
    b.tokens = Math.min(count, b.tokens + (now - b.at) * rate);
    b.at = now;
    if (b.tokens >= 1) {
      b.tokens -= 1;
      return true;
    }
    return false;
  }
}

export function simulate(rs: Ruleset, packets: Packet[]): Verdict[] {
  const buckets = new Buckets();
  const ordered = [...packets].sort((a, b) => a.t - b.t);
  return ordered.map((packet) => {
    for (const rule of rs.rules) {
      if (!matches(rule, packet)) continue;
      if (rule.limit) {
        const key = rule.limit.perSrc ? `${rule.line}:${packet.src}` : `${rule.line}`;
        if (!buckets.take(key, rule.limit.count, rule.limit.perSeconds, packet.t)) continue;
      }
      return { packet, action: rule.action, rule };
    }
    return { packet, action: rs.policy, rule: null };
  });
}

export function stats(verdicts: Verdict[]): Stats {
  const s: Stats = { legit: 0, legitAllowed: 0, attacks: 0, attacksBlocked: 0 };
  for (const v of verdicts) {
    if (v.packet.legit) {
      s.legit++;
      if (v.action === "allow") s.legitAllowed++;
    } else {
      s.attacks++;
      if (v.action === "drop") s.attacksBlocked++;
    }
  }
  return s;
}

export const pct = (part: number, whole: number) => (whole === 0 ? 100 : (100 * part) / whole);
