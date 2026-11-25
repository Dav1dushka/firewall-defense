// IPv4 addresses as unsigned 32-bit numbers, and CIDR blocks.

export function parseIp(text: string): number | null {
  const parts = text.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(p) || Number(p) > 255) return null;
    n = n * 256 + Number(p);
  }
  return n >>> 0;
}

export function formatIp(n: number): string {
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

export interface Cidr {
  base: number;
  prefix: number;
}

/** "10.0.0.0/8" or a single address "192.0.2.7" (= /32). Host bits must be zero. */
export function parseCidr(text: string): Cidr | null {
  const [ip, len, extra] = text.split("/");
  if (extra !== undefined) return null;
  const base = parseIp(ip);
  if (base === null) return null;
  const prefix = len === undefined ? 32 : /^\d{1,2}$/.test(len) ? Number(len) : NaN;
  if (!(prefix >= 0 && prefix <= 32)) return null;
  if ((base & ~maskOf(prefix)) >>> 0 !== 0) return null;
  return { base, prefix };
}

export function maskOf(prefix: number): number {
  // A shift by 32 is a shift by 0 in JavaScript, so /0 needs its own case.
  return prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
}

export function inCidr(ip: number, c: Cidr): boolean {
  return ((ip & maskOf(c.prefix)) >>> 0) === c.base;
}

export function formatCidr(c: Cidr): string {
  return c.prefix === 32 ? formatIp(c.base) : `${formatIp(c.base)}/${c.prefix}`;
}
