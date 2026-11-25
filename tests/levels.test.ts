// Every level must be solvable, and the tempting wrong answers must fail.
// Each check runs on many seeds, because the game generates fresh traffic
// on every run.
import assert from "node:assert/strict";
import { test } from "node:test";

import { LEVELS, internetIp, seeded } from "../src/levels";
import { inCidr, parseCidr } from "../src/ip";
import { parseRules } from "../src/rules";
import { pct, simulate, stats } from "../src/sim";

const SEEDS = Array.from({ length: 30 }, (_, i) => 1000 + i * 7919);

const SOLUTIONS: Record<number, string> = {
  1: "allow tcp port 80,443\npolicy drop",
  2: "allow tcp port 80,443\nallow tcp port 22 from 198.51.100.0/24\npolicy drop",
  3: "allow tcp port 443 from 203.0.113.50\ndrop from 203.0.113.0/24\nallow tcp port 80,443\npolicy drop",
  4: "allow state established\nallow tcp port 80,443\npolicy drop",
  5: "allow tcp port 80,443\nallow tcp port 3306,6379 from 10.0.1.0/24\npolicy drop",
  6: "allow tcp port 80,443\nallow tcp port 3306,6379 in lan from 10.0.1.0/24\npolicy drop",
  7: "allow tcp port 80,443\nallow tcp port 22 limit 3/m per-src\npolicy drop",
  8: `allow state established
allow tcp port 443 from 203.0.113.50
drop from 203.0.113.0/24
allow tcp port 80,443
allow tcp port 22 from 198.51.100.0/24
allow tcp port 22 limit 3/m per-src
allow tcp port 3306,6379 in lan from 10.0.1.0/24
policy drop`,
};

// Plausible answers that a player might try first. Each must fail on every seed.
const WRONG: Record<number, string[]> = {
  1: ["policy allow", "drop tcp port 22,23,3306,3389\npolicy allow"],
  2: ["allow tcp port 80,443\nallow tcp port 22\npolicy drop", "allow tcp port 80,443\npolicy drop"],
  3: ["drop from 203.0.113.0/24\nallow tcp port 80,443\npolicy drop",
    "allow tcp port 80,443\ndrop from 203.0.113.0/24\npolicy drop"],
  4: ["allow tcp sport 443,80\nallow udp sport 53\nallow tcp port 80,443\npolicy drop",
    "allow tcp port 80,443\nallow tcp port 32768-60999\nallow udp port 32768-60999\npolicy drop"],
  5: ["allow tcp port 80,443,3306,6379\npolicy drop"],
  6: [SOLUTIONS[5]],     // the level 5 answer trusts spoofed addresses
  7: ["allow tcp port 80,443\nallow tcp port 22\npolicy drop",
    "allow tcp port 80,443\nallow tcp port 22 limit 3/m\npolicy drop"],
  8: [`allow state established
allow tcp port 443 from 203.0.113.50
drop from 203.0.113.0/24
allow tcp port 80,443
allow tcp port 22 limit 3/m per-src
allow tcp port 3306,6379 in lan from 10.0.1.0/24
policy drop`],
};

function run(levelId: number, rules: string, seed: number) {
  const level = LEVELS[levelId - 1];
  const s = stats(simulate(parseRules(rules), level.traffic(seeded(seed))));
  const legit = pct(s.legitAllowed, s.legit);
  const blocked = pct(s.attacksBlocked, s.attacks);
  return { legit, blocked, passed: legit >= level.goals.legit && blocked >= level.goals.blocked };
}

for (const level of LEVELS) {
  test(`level ${level.id} (${level.title}): the reference solution passes on every seed`, () => {
    const rules = SOLUTIONS[level.id];
    assert.ok(parseRules(rules).rules.length <= level.par, "solution fits the par");
    for (const seed of SEEDS) {
      const r = run(level.id, rules, seed);
      assert.ok(r.passed, `seed ${seed}: legit ${r.legit.toFixed(1)}%, blocked ${r.blocked.toFixed(1)}%`);
    }
  });

  test(`level ${level.id}: tempting wrong answers fail on every seed`, () => {
    for (const rules of WRONG[level.id]) {
      for (const seed of SEEDS) {
        assert.ok(!run(level.id, rules, seed).passed, `seed ${seed} passed with:\n${rules}`);
      }
    }
  });

  test(`level ${level.id}: the starter rules do not already pass`, () => {
    assert.ok(!run(level.id, level.starter, SEEDS[0]).passed);
  });

  test(`level ${level.id}: traffic is deterministic for a seed and has both kinds`, () => {
    const a = level.traffic(seeded(42));
    const b = level.traffic(seeded(42));
    assert.deepEqual(a, b);
    assert.ok(a.some((p) => p.legit) && a.some((p) => !p.legit));
    assert.ok(a.every((p) => p.t >= 0 && p.t <= level.duration));
  });
}

test("random internet addresses avoid private and documentation ranges", () => {
  const rng = seeded(7);
  const reserved = ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "203.0.113.0/24", "198.51.100.0/24",
    "127.0.0.0/8"].map((c) => parseCidr(c)!);
  for (let i = 0; i < 20000; i++) {
    const ip = internetIp(rng);
    assert.ok(!reserved.some((c) => inCidr(ip, c)));
  }
});
