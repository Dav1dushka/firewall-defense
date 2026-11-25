import assert from "node:assert/strict";
import { test } from "node:test";

import { formatCidr, inCidr, parseCidr, parseIp } from "../src/ip";
import { parseRules, RuleError } from "../src/rules";
import { type Packet, simulate } from "../src/sim";

const pkt = (over: Partial<Packet> = {}): Packet => ({
  t: 0, proto: "tcp", src: parseIp("192.0.2.10")!, sport: 50000, dport: 443, iface: "wan", state: "new",
  legit: true, kind: "test", ...over,
});

const verdict = (rules: string, p: Packet) => simulate(parseRules(rules), [p])[0];

test("addresses and networks", () => {
  assert.equal(parseIp("203.0.113.50"), 0xcb007132);
  for (const bad of ["1.2.3", "256.1.1.1", "01.2.3.4", "1.2.3.4.5", "a.b.c.d"]) assert.equal(parseIp(bad), null);
  const net = parseCidr("10.0.1.0/24")!;
  assert.ok(inCidr(parseIp("10.0.1.200")!, net));
  assert.ok(!inCidr(parseIp("10.0.2.1")!, net));
  assert.equal(parseCidr("10.0.1.5/24"), null, "host bits must be zero");
  assert.equal(formatCidr(parseCidr("192.0.2.7")!), "192.0.2.7");
  assert.ok(inCidr(parseIp("8.8.8.8")!, parseCidr("0.0.0.0/0")!));
});

test("parses a full ruleset with comments and a policy", () => {
  const rs = parseRules(`
    # web
    policy drop
    allow tcp port 80,443           # everyone
    allow tcp port 22 from 198.51.100.0/24
    allow tcp port 1024-65535 state established
    drop in wan from 10.0.0.0/8
    allow tcp port 22 limit 3/m per-src
  `);
  assert.equal(rs.policy, "drop");
  assert.equal(rs.rules.length, 5);
  assert.deepEqual(rs.rules[0].ports, [{ lo: 80, hi: 80 }, { lo: 443, hi: 443 }]);
  assert.deepEqual(rs.rules[4].limit, { count: 3, perSeconds: 60, perSrc: true });
  assert.equal(rs.rules[1].line, 5);
});

test("helpful errors with line numbers", () => {
  const cases: [string, RegExp][] = [
    ["allow tcp prot 22", /line 1: unknown word 'prot' \(did you mean 'port'\?\)/],
    ["\nalow tcp port 22", /line 2: a rule starts with 'allow' or 'drop' \(did you mean 'allow'\?\)/],
    ["allow port 22", /ports need a protocol/],
    ["allow icmp port 22", /ports need a protocol/],
    ["allow tcp port 70000", /not a port list/],
    ["allow from 10.0.0.1/8", /not an address or network/],
    ["allow tcp tcp", /'protocol' appears twice/],
    ["allow tcp port", /'port' needs/],
    ["allow tcp port 22 limit fast", /not a rate/],
    ["allow per-src", /'per-src' goes right after a limit/],
    ["policy maybe", /policy allow' or 'policy drop'/],
    ["policy drop\npolicy allow", /line 2: the policy is already set on line 1/],
  ];
  for (const [src, msg] of cases) {
    assert.throws(() => parseRules(src), (e: unknown) => e instanceof RuleError && msg.test(e.message), src);
  }
});

test("first match wins, then the policy", () => {
  const rules = "allow tcp port 443 from 203.0.113.50\ndrop from 203.0.113.0/24\nallow tcp port 443\npolicy drop";
  assert.equal(verdict(rules, pkt({ src: parseIp("203.0.113.50")! })).rule?.line, 1);
  assert.equal(verdict(rules, pkt({ src: parseIp("203.0.113.9")! })).action, "drop");
  assert.equal(verdict(rules, pkt()).rule?.line, 3);
  const v = verdict(rules, pkt({ dport: 22 }));
  assert.equal(v.action, "drop");
  assert.equal(v.rule, null, "decided by the policy");
});

test("the default policy is allow, like iptables", () => {
  assert.equal(verdict("", pkt({ dport: 3389 })).action, "allow");
});

test("each condition narrows the match", () => {
  assert.equal(verdict("drop udp", pkt()).action, "allow");
  assert.equal(verdict("drop tcp sport 53", pkt()).action, "allow");
  assert.equal(verdict("drop tcp sport 50000", pkt()).action, "drop");
  assert.equal(verdict("drop in lan", pkt()).action, "allow");
  assert.equal(verdict("drop state established", pkt()).action, "allow");
  assert.equal(verdict("drop state new", pkt()).action, "drop");
  assert.equal(verdict("drop tcp port 400-500", pkt()).action, "drop");
});

test("rate limits let a burst through, then refill over time", () => {
  // 3 tokens, refilled at 3 per minute (one every 20 s), one bucket per source.
  const rs = parseRules("allow tcp port 22 limit 3/m per-src\npolicy drop");
  const src = parseIp("192.0.2.66")!;
  const packets = [
    ...[0, 1, 2, 3, 4, 5].map((t) => pkt({ t, dport: 22, src })),  // a burst of 6
    pkt({ t: 6, dport: 22, src: parseIp("192.0.2.67")! }),         // someone else: own bucket
    pkt({ t: 30, dport: 22, src }),                                // tokens have refilled
  ];
  assert.deepEqual(simulate(rs, packets).map((v) => v.action),
    ["allow", "allow", "allow", "drop", "drop", "drop", "allow", "allow"]);
});

test("a global limit is shared by every source", () => {
  const rs = parseRules("allow tcp port 22 limit 2/m\npolicy drop");
  const packets = [1, 2, 3].map((n) => pkt({ t: n, dport: 22, src: parseIp(`192.0.2.${n}`)! }));
  assert.deepEqual(simulate(rs, packets).map((v) => v.action), ["allow", "allow", "drop"]);
});
