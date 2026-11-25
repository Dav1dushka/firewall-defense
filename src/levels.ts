// Level definitions. Each level describes a server, the traffic it should
// accept and the attacks it receives, and generates a fresh wave of packets
// from a seed, so a ruleset cannot pass by listing the attackers' addresses.

import { parseIp } from "./ip";
import type { Iface, Proto, State } from "./rules";
import type { Packet } from "./sim";

export type Rng = () => number;

/** mulberry32: tiny, fast, good enough for games, and repeatable from a seed. */
export function seeded(seed: number): Rng {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export interface Service {
  port: string;
  name: string;
  who: string;
}

export interface Level {
  id: number;
  title: string;
  story: string;
  services: Service[];
  goals: { legit: number; blocked: number };   // percentages needed to pass
  par: number;                                  // rules needed for the third star
  hint: string;
  lesson: string;                               // shown after passing
  starter: string;
  duration: number;                             // seconds of simulated traffic
  traffic(rng: Rng): Packet[];
}

// -- traffic helpers --------------------------------------------------------------------
const ip = (s: string) => parseIp(s) as number;
const int = (rng: Rng, lo: number, hi: number) => lo + Math.floor(rng() * (hi - lo + 1));
const pick = <T>(rng: Rng, items: readonly T[]): T => items[Math.floor(rng() * items.length)];
const ephemeral = (rng: Rng) => int(rng, 32768, 60999);

// Ranges a random "internet" address must avoid: private, loopback, multicast,
// and the documentation ranges the levels use for specific actors.
const RESERVED: [number, number][] = ([
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
  ["172.16.0.0", 12], ["192.0.2.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24],
  ["203.0.113.0", 24], ["224.0.0.0", 3],
] as [string, number][]).map(([a, prefix]) => [ip(a), prefix]);

export function internetIp(rng: Rng): number {
  for (;;) {
    const n = Math.floor(rng() * 2 ** 32) >>> 0;
    if (!RESERVED.some(([base, prefix]) => n >>> (32 - prefix) === base >>> (32 - prefix))) return n;
  }
}

interface Spec {
  proto?: Proto;
  src: number;
  sport?: number;
  dport: number;
  iface?: Iface;
  state?: State;
  legit: boolean;
  kind: string;
}

const packet = (t: number, s: Spec): Packet => ({
  t, proto: s.proto ?? "tcp", src: s.src, sport: s.sport ?? 0, dport: s.dport, iface: s.iface ?? "wan",
  state: s.state ?? "new", legit: s.legit, kind: s.kind,
});

/** n packets spread randomly over the wave, each made by `make`. */
function spread(rng: Rng, n: number, duration: number, make: () => Spec): Packet[] {
  return Array.from({ length: n }, () => packet(rng() * duration, make()));
}

// Traffic every level reuses.
const KIND = {
  web: "Website visitor",
  office: "Admin SSH from the office",
  partner: "Partner API at 203.0.113.50",
  reply: "Reply to the server's own request",
  app: "App server → database",
  team: "Team member SSH",
  deploy: "Deploy script from the office",
  scan: "Port scan",
  sshWorld: "SSH login from the internet",
  botnet: "Botnet flooding the website",
  fakeReply: "Fake reply (source port trick)",
  dbScan: "Database scan from the internet",
  spoof: "Spoofed internal address",
  brute: "SSH brute force",
};

const SCAN_PORTS = [21, 22, 23, 25, 110, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200,
  11211, 27017];

const web = (rng: Rng, n: number, d: number) => spread(rng, n, d, () => ({
  src: internetIp(rng), sport: ephemeral(rng), dport: rng() < 0.8 ? 443 : 80, legit: true, kind: KIND.web,
}));

function portScan(rng: Rng, scanners: number, probes: number, d: number, skip: number[] = []): Packet[] {
  const out: Packet[] = [];
  const ports = SCAN_PORTS.filter((p) => !skip.includes(p));
  for (let s = 0; s < scanners; s++) {
    const src = internetIp(rng);
    let t = rng() * d * 0.5;
    for (let i = 0; i < probes; i++) {
      t += 0.05 + rng() * 0.3;   // scanners are fast
      out.push(packet(Math.min(t, d), { src, sport: ephemeral(rng), dport: pick(rng, ports), legit: false, kind: KIND.scan }));
    }
  }
  return out;
}

const office = (rng: Rng, n: number, d: number) => spread(rng, n, d, () => ({
  src: ip("198.51.100.0") + int(rng, 10, 60), sport: ephemeral(rng), dport: 22, legit: true, kind: KIND.office,
}));

/** A deploy script: one office machine opening many SSH connections in a burst. */
function deploy(rng: Rng, d: number): Packet[] {
  const src = ip("198.51.100.20");
  let t = rng() * (d - 30);
  return Array.from({ length: 15 }, () => {
    t += 0.5 + rng() * 1.5;
    return packet(t, { src, sport: ephemeral(rng), dport: 22, legit: true, kind: KIND.deploy });
  });
}

const replies = (rng: Rng, n: number, d: number) => spread(rng, n, d, () => {
  const dns = rng() < 0.2;
  return {
    proto: dns ? "udp" : "tcp", src: dns ? pick(rng, [ip("1.1.1.1"), ip("8.8.8.8")]) : internetIp(rng),
    sport: dns ? 53 : pick(rng, [443, 443, 80]), dport: ephemeral(rng), state: "established", legit: true,
    kind: KIND.reply,
  } satisfies Spec;
});

const fakeReplies = (rng: Rng, n: number, d: number) => spread(rng, n, d, () => {
  const dns = rng() < 0.25;
  return {
    proto: dns ? "udp" : "tcp", src: internetIp(rng), sport: dns ? 53 : pick(rng, [443, 80]),
    dport: dns ? ephemeral(rng) : pick(rng, [ephemeral(rng), 3306, 6379, 5432, 8080]), legit: false,
    kind: KIND.fakeReply,
  } satisfies Spec;
});

const appToDb = (rng: Rng, n: number, d: number) => spread(rng, n, d, () => ({
  src: ip("10.0.1.0") + int(rng, 11, 20), sport: ephemeral(rng), dport: pick(rng, [3306, 3306, 6379]),
  iface: "lan", legit: true, kind: KIND.app,
} satisfies Spec));

const dbScan = (rng: Rng, n: number, d: number) => spread(rng, n, d, () => ({
  src: internetIp(rng), sport: ephemeral(rng), dport: pick(rng, [3306, 6379, 6379, 5432, 27017, 9200]),
  legit: false, kind: KIND.dbScan,
}));

const spoofed = (rng: Rng, n: number, d: number) => spread(rng, n, d, () => ({
  src: ip("10.0.1.0") + int(rng, 2, 250), sport: ephemeral(rng), dport: pick(rng, [3306, 6379]),
  iface: "wan", legit: false, kind: KIND.spoof,
} satisfies Spec));

/** People connecting a few times each, at random moments. */
function team(rng: Rng, people: number, d: number): Packet[] {
  const out: Packet[] = [];
  for (let i = 0; i < people; i++) {
    const src = internetIp(rng);
    const tries = int(rng, 1, 3);
    let t = rng() * (d - 60);         // up to 3 tries, at most 25 s apart, fit before the end
    for (let k = 0; k < tries; k++) {
      out.push(packet(t, { src, sport: ephemeral(rng), dport: 22, legit: true, kind: KIND.team }));
      t += 5 + rng() * 20;      // a typo in the password, then another try
    }
  }
  return out;
}

/** Bots guessing passwords: a few addresses, many attempts each, at a steady pace. */
function bruteForce(rng: Rng, bots: number, perMinute: number, d: number): Packet[] {
  const out: Packet[] = [];
  for (let b = 0; b < bots; b++) {
    const src = internetIp(rng);
    let t = rng() * 10;
    while (t < d) {
      out.push(packet(t, { src, sport: ephemeral(rng), dport: 22, legit: false, kind: KIND.brute }));
      t += (60 / perMinute) * (0.6 + rng() * 0.8);
    }
  }
  return out;
}

const botnet = (rng: Rng, n: number, d: number) => spread(rng, n, d, () => ({
  src: ip("203.0.113.0") + pick(rng, [int(rng, 1, 49), int(rng, 51, 254)]), sport: ephemeral(rng),
  dport: rng() < 0.85 ? 443 : 80, legit: false, kind: KIND.botnet,
}));

const partner = (rng: Rng, n: number, d: number) => spread(rng, n, d, () => ({
  src: ip("203.0.113.50"), sport: ephemeral(rng), dport: 443, legit: true, kind: KIND.partner,
}));

const WEB: Service = { port: "tcp 80, 443", name: "Website", who: "everyone" };

// -- the levels ----------------------------------------------------------------------------
export const LEVELS: Level[] = [
  {
    id: 1,
    title: "Default deny",
    story: "Your first server only hosts a website. Within minutes of going online, scanners start knocking on every port to see what else answers.\n\nThe firewall currently lets everything in. Press Run to watch what happens, then fix it.",
    services: [WEB],
    goals: { legit: 100, blocked: 100 },
    par: 1,
    hint: "Allow exactly what the server offers (allow tcp port 80,443), then turn the policy around: policy drop.",
    lesson: "Default deny: list what is allowed and drop everything else. Listing what is forbidden never ends, because attackers can always try something you did not think of.",
    starter: "# Rules are checked from the top. The first rule that matches wins.\n# Packets that match no rule follow the policy.\npolicy allow\n",
    duration: 60,
    traffic: (rng) => [...web(rng, 60, 60), ...portScan(rng, 2, 20, 60, [80, 443])],
  },
  {
    id: 2,
    title: "Office only",
    story: "The admins need SSH to manage the server, but only from the office network 198.51.100.0/24. Bots from all over the internet try SSH too.",
    services: [WEB, { port: "tcp 22", name: "SSH", who: "office 198.51.100.0/24" }],
    goals: { legit: 100, blocked: 100 },
    par: 2,
    hint: "A rule can check where a packet comes from: allow tcp port 22 from 198.51.100.0/24",
    lesson: "Restricting management ports to known networks removes most of the attack surface. Most SSH break-ins hit servers whose port 22 is open to the whole internet.",
    starter: "policy drop\nallow tcp port 80,443\n",
    duration: 60,
    traffic: (rng) => [...web(rng, 50, 60), ...office(rng, 15, 60),
      ...spread(rng, 40, 60, () => ({ src: internetIp(rng), sport: ephemeral(rng), dport: 22, legit: false, kind: KIND.sshWorld })),
      ...portScan(rng, 1, 15, 60, [80, 443])],
  },
  {
    id: 3,
    title: "Order matters",
    story: "A botnet in 203.0.113.0/24 is flooding the website. Block the whole network, but one address in it, 203.0.113.50, belongs to a partner whose system calls your API on port 443.",
    services: [WEB, { port: "tcp 443", name: "API", who: "partner 203.0.113.50" }],
    goals: { legit: 100, blocked: 100 },
    par: 3,
    hint: "The first matching rule wins. Put the exception for 203.0.113.50 above the rule that drops 203.0.113.0/24.",
    lesson: "Rule order is part of the logic: put narrow exceptions before broad rules. When a firewall misbehaves, the cause is very often a rule that is correct but in the wrong place.",
    starter: "policy drop\nallow tcp port 80,443\n",
    duration: 60,
    traffic: (rng) => [...web(rng, 50, 60), ...partner(rng, 12, 60), ...botnet(rng, 50, 60)],
  },
  {
    id: 4,
    title: "Replies welcome",
    story: "The server now downloads updates and calls other APIs. The answers come back to random high ports, and your policy drops them, which breaks updates.\n\nAttackers know that admins open 'source port 443' to fix this, and send packets from port 443 that answer nothing.",
    services: [WEB, { port: "replies", name: "Answers to the server's own requests", who: "anyone it talked to" }],
    goals: { legit: 100, blocked: 100 },
    par: 2,
    hint: "The firewall remembers connections the server opened. 'allow state established' accepts their replies and nothing else.",
    lesson: "A stateful firewall tracks connections, so replies are allowed because the server asked for them, not because of a port number an attacker can choose freely.",
    starter: "policy drop\nallow tcp port 80,443\n",
    duration: 60,
    traffic: (rng) => [...web(rng, 40, 60), ...replies(rng, 45, 60), ...fakeReplies(rng, 40, 60)],
  },
  {
    id: 5,
    title: "Keep the database inside",
    story: "MySQL (3306) and Redis (6379) now run on this server. Only the app servers in 10.0.1.0/24 should reach them. Scanners look for open databases all day: an unprotected Redis on the internet is usually taken over within hours.",
    services: [WEB, { port: "tcp 3306, 6379", name: "MySQL, Redis", who: "app servers 10.0.1.0/24" }],
    goals: { legit: 100, blocked: 100 },
    par: 2,
    hint: "allow tcp port 3306,6379 from 10.0.1.0/24",
    lesson: "Databases belong on the internal network only. Thousands of breaches started with MongoDB, Elasticsearch or Redis reachable from the internet without a password.",
    starter: "policy drop\nallow tcp port 80,443\n",
    duration: 60,
    traffic: (rng) => [...web(rng, 40, 60), ...appToDb(rng, 30, 60), ...dbScan(rng, 40, 60)],
  },
  {
    id: 6,
    title: "Spoofed insiders",
    story: "Your level 5 rule trusts any packet whose source address is in 10.0.1.0/24. An attacker noticed and is sending packets from the internet with a forged internal source address.\n\nReal internal traffic arrives on the internal interface, lan. Packets from the internet arrive on wan.",
    services: [WEB, { port: "tcp 3306, 6379", name: "MySQL, Redis", who: "app servers 10.0.1.0/24, on lan" }],
    goals: { legit: 100, blocked: 100 },
    par: 2,
    hint: "Check the interface too: allow tcp port 3306,6379 in lan from 10.0.1.0/24",
    lesson: "A source address is just a number the sender writes into the packet. Anti-spoofing rules (no private addresses arriving from the internet, BCP 38) tie addresses to where they can really come from.",
    starter: "policy drop\nallow tcp port 80,443\nallow tcp port 3306,6379 from 10.0.1.0/24\n",
    duration: 60,
    traffic: (rng) => [...web(rng, 40, 60), ...appToDb(rng, 30, 60), ...spoofed(rng, 40, 60), ...dbScan(rng, 15, 60)],
  },
  {
    id: 7,
    title: "Brute force",
    story: "The team works from anywhere, so SSH has to stay open to the internet. People connect a few times a day; bots guess passwords many times a minute from a handful of addresses.\n\nYou cannot block every guess without locking people out, so the goal is to slow the bots down.",
    services: [WEB, { port: "tcp 22", name: "SSH", who: "the team, from anywhere" }],
    goals: { legit: 100, blocked: 70 },
    par: 2,
    hint: "A rate limit lets a rule match only a few times per period. Packets over the limit fall through to the next rule: allow tcp port 22 limit 3/m per-src",
    lesson: "Rate limiting does not stop an attack, it makes it slow. This is what fail2ban does, usually together with key-only SSH logins so that guessing passwords is useless anyway.",
    starter: "policy drop\nallow tcp port 80,443\n",
    duration: 120,
    traffic: (rng) => [...web(rng, 30, 120), ...team(rng, 18, 120), ...bruteForce(rng, 4, 20, 120)],
  },
  {
    id: 8,
    title: "Production",
    story: "Everything at once. Website for everyone; the partner at 203.0.113.50 but not the rest of its botnet-infested network; SSH for the office without limits (a deploy script connects in bursts) and for the travelling team with a limit; databases for the app servers on lan only; replies to the server's own requests.",
    services: [
      WEB,
      { port: "tcp 443", name: "API", who: "partner 203.0.113.50" },
      { port: "tcp 22", name: "SSH", who: "office 198.51.100.0/24; team from anywhere" },
      { port: "tcp 3306, 6379", name: "MySQL, Redis", who: "app servers 10.0.1.0/24, on lan" },
      { port: "replies", name: "Answers to the server's own requests", who: "anyone it talked to" },
    ],
    goals: { legit: 100, blocked: 85 },
    par: 7,
    hint: "Combine what you learned. Exceptions before broad rules; the office SSH rule before the rate-limited one.",
    lesson: "A real ruleset is short, ordered and commented. Keep it in version control and test it the way you just did: with real and malicious traffic side by side.",
    starter: "policy drop\n",
    duration: 120,
    traffic: (rng) => [
      ...web(rng, 40, 120), ...partner(rng, 10, 120), ...office(rng, 8, 120), ...deploy(rng, 120),
      ...team(rng, 10, 120),
      ...appToDb(rng, 20, 120), ...replies(rng, 25, 120),
      ...botnet(rng, 30, 120), ...bruteForce(rng, 3, 15, 120), ...dbScan(rng, 20, 120), ...spoofed(rng, 20, 120),
      ...fakeReplies(rng, 20, 120), ...portScan(rng, 1, 20, 120, [80, 443, 22]),
    ],
  },
];
