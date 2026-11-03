export function concat(...parts: Array<Uint8Array | number[]>): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function be16(n: number): Uint8Array {
  return Uint8Array.of((n >>> 8) & 0xff, n & 0xff);
}

export function be24(n: number): Uint8Array {
  return Uint8Array.of((n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
}

export function le16(n: number): Uint8Array {
  return Uint8Array.of(n & 0xff, (n >>> 8) & 0xff);
}

export function le32(n: number): Uint8Array {
  return Uint8Array.of(n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff);
}

export function viewOf(u: Uint8Array): DataView {
  return new DataView(u.buffer, u.byteOffset, u.byteLength);
}

export function readBe16(u: Uint8Array, o: number): number {
  return (u[o] << 8) | u[o + 1];
}

export function readBe32(u: Uint8Array, o: number): number {
  return ((u[o] << 24) | (u[o + 1] << 16) | (u[o + 2] << 8) | u[o + 3]) >>> 0;
}

export function readLe16(u: Uint8Array, o: number): number {
  return u[o] | (u[o + 1] << 8);
}

export function readLe32(u: Uint8Array, o: number): number {
  return (u[o] | (u[o + 1] << 8) | (u[o + 2] << 16) | (u[o + 3] << 24)) >>> 0;
}

export function latin1(u: Uint8Array): string {
  let s = "";
  const step = 0x8000;
  for (let i = 0; i < u.length; i += step) {
    const slice = u.subarray(i, Math.min(u.length, i + step));
    s += String.fromCharCode(...slice);
  }
  return s;
}

export function asciiPreview(u: Uint8Array, max = 80): string {
  let s = "";
  const n = Math.min(u.length, max);
  for (let i = 0; i < n; i++) {
    const b = u[i];
    s += b >= 32 && b < 127 ? String.fromCharCode(b) : ".";
  }
  return s;
}

export function encodeUtf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function encodeUtf16LE(s: string): Uint8Array {
  const out = new Uint8Array(s.length * 2);
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    out[i * 2] = c & 0xff;
    out[i * 2 + 1] = (c >>> 8) & 0xff;
  }
  return out;
}

export function decodeUtf16LE(u: Uint8Array): string {
  let s = "";
  for (let i = 0; i + 1 < u.length; i += 2) {
    s += String.fromCharCode(u[i] | (u[i + 1] << 8));
  }
  return s;
}

export function hexByte(n: number): string {
  return n.toString(16).padStart(2, "0");
}

export function bytesToHex(u: Uint8Array, sep = " "): string {
  const parts = new Array<string>(u.length);
  for (let i = 0; i < u.length; i++) parts[i] = hexByte(u[i]);
  return parts.join(sep);
}

/** Internet checksum over a sequence of byte strings. Odd trailing byte is padded. */
export function inetChecksum(parts: Uint8Array[]): number {
  let sum = 0;
  let pending = -1;
  const push = (b: number) => {
    if (pending < 0) pending = b;
    else {
      sum += (pending << 8) | b;
      pending = -1;
    }
  };
  for (const p of parts) {
    for (let i = 0; i < p.length; i++) push(p[i]);
  }
  if (pending >= 0) sum += pending << 8;
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  return (~sum) & 0xffff;
}

export function printableStrings(u: Uint8Array, min = 4): string[] {
  const out: string[] = [];
  let cur = "";
  for (let i = 0; i < u.length; i++) {
    const b = u[i];
    if (b >= 32 && b < 127) cur += String.fromCharCode(b);
    else {
      if (cur.length >= min) out.push(cur);
      cur = "";
    }
  }
  if (cur.length >= min) out.push(cur);
  return out;
}

export function shannon(s: string): number {
  if (!s) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of freq.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}
