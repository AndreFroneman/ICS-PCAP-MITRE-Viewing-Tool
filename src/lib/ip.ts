export function parseMac(mac: string): Uint8Array {
  const parts = mac.split(/[:-]/).map((p) => Number.parseInt(p, 16));
  if (parts.length !== 6 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    throw new Error(`Bad MAC ${mac}`);
  }
  return Uint8Array.from(parts);
}

export function formatMac(u: Uint8Array, o = 0): string {
  const parts = new Array<string>(6);
  for (let i = 0; i < 6; i++) parts[i] = u[o + i].toString(16).padStart(2, "0");
  return parts.join(":");
}

export function parseIpv4(ip: string): Uint8Array {
  const p = ip.split(".").map((n) => Number(n));
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    throw new Error(`Bad IPv4 ${ip}`);
  }
  return Uint8Array.from(p);
}

export function formatIpv4(u: Uint8Array, o = 0): string {
  return `${u[o]}.${u[o + 1]}.${u[o + 2]}.${u[o + 3]}`;
}

export function parseIpv6(ip: string): Uint8Array {
  const lower = ip.toLowerCase();
  const halves = lower.split("::");
  if (halves.length > 2) throw new Error(`Bad IPv6 ${ip}`);
  const parseSide = (s: string) => (s ? s.split(":").map((h) => Number.parseInt(h || "0", 16)) : []);
  const left = parseSide(halves[0]);
  const right = halves.length === 2 ? parseSide(halves[1]) : [];
  if ([...left, ...right].some((n) => Number.isNaN(n) || n < 0 || n > 0xffff)) {
    throw new Error(`Bad IPv6 ${ip}`);
  }
  const missing = 8 - (left.length + right.length);
  if (halves.length === 1 && missing !== 0) throw new Error(`Bad IPv6 ${ip}`);
  if (missing < 0) throw new Error(`Bad IPv6 ${ip}`);
  const groups = [...left, ...new Array<number>(missing).fill(0), ...right];
  const out = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    out[i * 2] = (groups[i] >> 8) & 0xff;
    out[i * 2 + 1] = groups[i] & 0xff;
  }
  return out;
}

export function formatIpv6(u: Uint8Array, o = 0): string {
  const groups = new Array<number>(8);
  for (let i = 0; i < 8; i++) groups[i] = (u[o + i * 2] << 8) | u[o + i * 2 + 1];
  let bestStart = -1;
  let bestLen = 0;
  let i = 0;
  while (i < 8) {
    if (groups[i] === 0) {
      let j = i;
      while (j < 8 && groups[j] === 0) j++;
      if (j - i > bestLen) {
        bestStart = i;
        bestLen = j - i;
      }
      i = j;
    } else i++;
  }
  if (bestLen < 2) bestStart = -1;
  const parts: string[] = [];
  for (let g = 0; g < 8; ) {
    if (g === bestStart) {
      parts.push("");
      g += bestLen;
      if (g >= 8) parts.push("");
      continue;
    }
    parts.push(groups[g].toString(16));
    g++;
  }
  return parts.join(":") || "::";
}

export function isInternal(ip: string): boolean {
  if (!ip || ip === "0.0.0.0" || ip === "255.255.255.255") return false;
  if (ip.includes(":")) {
    const x = ip.toLowerCase();
    if (x === "::1") return true;
    if (x.startsWith("fe80")) return true;
    if (x.startsWith("fc") || x.startsWith("fd")) return true;
    return false;
  }
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n))) return false;
  if (p[0] === 10) return true;
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
  if (p[0] === 192 && p[1] === 168) return true;
  if (p[0] === 127) return true;
  if (p[0] === 169 && p[1] === 254) return true;
  return false;
}

export function isPublicUnicast(ip: string): boolean {
  if (!ip) return false;
  if (ip.includes(":")) {
    const x = ip.toLowerCase();
    if (isInternal(ip) || x === "::" || x.startsWith("ff")) return false;
    return true;
  }
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n))) return false;
  if (p[0] === 0 || p[0] === 127 || p[0] >= 224) return false;
  return !isInternal(ip);
}

export function isDeviceIp(ip: string): boolean {
  if (!isInternal(ip)) return false;
  if (ip.endsWith(".255")) return false;
  return true;
}
