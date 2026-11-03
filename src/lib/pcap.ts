import { viewOf } from "./bytes.ts";
import type { CaptureFile, RawPacket } from "./model.ts";

/**
 * Classic pcap and pcapng reader.
 *
 * Real captures disagree about endianness, timestamp resolution, and the
 * version field. Primer identifies the file from its magic number, accepts
 * any version (2.4 is only the usual one), and skips blocks it does not
 * know. A surprising version is a warning, not a reason to refuse the file.
 * Gzip wrappers are removed first by {@link gunzipIfNeeded}; the format is
 * never decided from the filename.
 */

const PCAP_MAGIC_US = 0xa1b2c3d4;
const PCAP_MAGIC_NS = 0xa1b23c4d;
const PCAP_MAGIC_MODIFIED = 0xa1b2cd34;
const PCAP_MAGIC_NAVTEL = 0xa12b3c4d;
const PCAP_MAGIC_FMESQUITA = 0xa1b234cd;
const PCAPNG_SHB = 0x0a0d0d0a;
const PCAPNG_BOM = 0x1a2b3c4d;

type PcapKind = "microseconds" | "nanoseconds" | "modified" | "navtel" | "fmesquita";

const PCAP_MAGICS: { kind: PcapKind; magic: number }[] = [
  { kind: "microseconds", magic: PCAP_MAGIC_US },
  { kind: "nanoseconds", magic: PCAP_MAGIC_NS },
  { kind: "modified", magic: PCAP_MAGIC_MODIFIED },
  { kind: "navtel", magic: PCAP_MAGIC_NAVTEL },
  { kind: "fmesquita", magic: PCAP_MAGIC_FMESQUITA },
];

export class CaptureError extends Error {
  readonly detected: string;
  constructor(detected: string, reason: string) {
    super(`${detected}. ${reason}`);
    this.name = "CaptureError";
    this.detected = detected;
  }
}

export async function gunzipIfNeeded(bytes: Uint8Array): Promise<{ bytes: Uint8Array; compressed: boolean }> {
  if (bytes.length < 2 || bytes[0] !== 0x1f || bytes[1] !== 0x8b) return { bytes, compressed: false };
  try {
    const copy = new Uint8Array(bytes.byteLength);
    copy.set(bytes);
    const stream = new Blob([copy]).stream().pipeThrough(new DecompressionStream("gzip"));
    const inflated = new Uint8Array(await new Response(stream).arrayBuffer());
    if (inflated.length > 512 * 1024 * 1024) {
      throw new CaptureError("gzip-compressed capture", "The file expands past 512 MB, so Primer stopped rather than using all of the memory.");
    }
    return { bytes: inflated, compressed: true };
  } catch (error) {
    if (error instanceof CaptureError) throw error;
    throw new CaptureError("gzip-compressed file", "The gzip wrapper could not be opened. Primer reads .pcap.gz and .pcapng.gz itself and does not need Wireshark.");
  }
}

export function parseCapture(input: ArrayBuffer | SharedArrayBuffer | Uint8Array): CaptureFile {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) {
    throw new CaptureError("gzip-compressed capture", "Uncompress it with gunzipIfNeeded before parsing. Primer does this automatically when you open a file.");
  }
  if (bytes.length >= 4 && readU32(bytes, 0, true) === PCAPNG_SHB) return parsePcapng(bytes);
  const classic = matchPcapMagic(bytes);
  if (classic) return parsePcap(bytes, classic.little, classic.kind);
  throw new CaptureError(
    `Unrecognised capture (first bytes ${hexPrefix(bytes)})`,
    "Primer looked for classic pcap (a1b2c3d4), nanosecond pcap (a1b23c4d), modified pcap (a1b2cd34), Navtel (a12b3c4d), and pcapng (0a0d0d0a). None of those headers are here. The filename is ignored; only these bytes matter.",
  );
}

function matchPcapMagic(bytes: Uint8Array): { little: boolean; kind: PcapKind } | null {
  if (bytes.length < 4) return null;
  const le = readU32(bytes, 0, true);
  const be = readU32(bytes, 0, false);
  for (const item of PCAP_MAGICS) {
    if (le === item.magic) return { little: true, kind: item.kind };
    if (be === item.magic) return { little: false, kind: item.kind };
  }
  return null;
}

function readU32(bytes: Uint8Array, offset: number, little: boolean): number {
  return viewOf(bytes).getUint32(offset, little);
}

function hexPrefix(bytes: Uint8Array): string {
  return [...bytes.subarray(0, 8)].map((b) => b.toString(16).padStart(2, "0")).join(" ") || "(empty)";
}

function parsePcap(bytes: Uint8Array, little: boolean, kind: PcapKind): CaptureFile {
  if (bytes.length < 24) {
    throw new CaptureError(
      `classic pcap (${kind}, ${little ? "little" : "big"}-endian)`,
      `The header is only ${bytes.length} bytes. A pcap global header is 24 bytes, so this file is cut off.`,
    );
  }
  const view = viewOf(bytes);
  const warnings: string[] = [];
  const major = view.getUint16(4, little);
  const minor = view.getUint16(6, little);
  if (major !== 2 || minor !== 4) {
    warnings.push(`This classic pcap says version ${major}.${minor}. Primer is written for 2.4 and will still read the packets.`);
  }
  let linkType = view.getUint32(20, little);
  if (kind === "modified") linkType &= 0xffff;
  const header = kind === "modified" ? 24 : 16;
  const nano = kind === "nanoseconds";
  if (kind === "modified") warnings.push("Modified (Kuznetsov) pcap: each record has an extra 8-byte Linux header before the frame.");
  if (kind === "navtel" || kind === "fmesquita") warnings.push(`${kind} pcap is an uncommon variant. Packets are read with microsecond timestamps.`);
  const packets: RawPacket[] = [];
  let o = 24;
  let n = 0;
  while (o + header <= bytes.length) {
    const sec = view.getUint32(o, little);
    const frac = view.getUint32(o + 4, little);
    const incl = view.getUint32(o + 8, little);
    const orig = view.getUint32(o + 12, little);
    const dataAt = o + header;
    if (incl > bytes.length - dataAt || incl > 1_000_000_000) {
      warnings.push(`Packet ${n + 1} is truncated or has an impossible length (${incl} bytes) and was skipped.`);
      break;
    }
    n += 1;
    const scale = nano ? 1e9 : 1e6;
    packets.push({
      n,
      ts: sec + frac / scale,
      origLen: orig,
      data: bytes.subarray(dataAt, dataAt + incl),
      linkType,
    });
    o = dataAt + incl;
  }
  if (o < bytes.length && o + header > bytes.length) {
    warnings.push("The file ends in the middle of a packet header. Earlier packets were kept.");
  }
  return { format: "pcap", packets, warnings, linkType };
}

interface Iface {
  linkType: number;
  tsResol: number;
  tsOffset: number;
  name: string;
  snapLen: number;
  fcs: number;
}

function parsePcapng(bytes: Uint8Array): CaptureFile {
  const warnings: string[] = [];
  const packets: RawPacket[] = [];
  let little = sectionEndian(bytes, 0, warnings);
  let interfaces: Iface[] = [];
  let o = 0;
  let n = 0;
  let linkType = 1;
  let unknownNoted = false;

  while (o + 12 <= bytes.length) {
    const view = viewOf(bytes);
    if (readU32(bytes, o, true) === PCAPNG_SHB || readU32(bytes, o, false) === PCAPNG_SHB) {
      little = sectionEndian(bytes, o, warnings);
      interfaces = [];
    }
    const type = view.getUint32(o, little);
    let total = view.getUint32(o + 4, little);
    if (total < 12) {
      warnings.push(`A pcapng block at offset ${o} has length ${total}, which is too small. Packets after it were skipped.`);
      break;
    }
    if (total % 4 !== 0) {
      warnings.push("A pcapng block length was not a multiple of 4. Primer aligned it and kept going.");
      total += 4 - (total % 4);
    }
    if (o + total > bytes.length) {
      warnings.push("A pcapng block was cut off at the end of the file. Packets already read were kept.");
      break;
    }
    if (type === 0x00000001 && o + 16 <= bytes.length) {
      const lt = view.getUint16(o + 8, little);
      const snap = view.getUint32(o + 12, little);
      const iface: Iface = { linkType: lt, tsResol: 1e-6, tsOffset: 0, name: "", snapLen: snap || 0xffffffff, fcs: 0 };
      readOptions(bytes, o + 16, o + total - 4, little, (code, val) => {
        if (code === 9 && val.length >= 1) {
          const v = val[0];
          iface.tsResol = v & 0x80 ? 2 ** -(v & 0x7f) : 10 ** -(v & 0x7f);
        } else if (code === 2) iface.name = new TextDecoder().decode(val);
        else if (code === 13 && val.length >= 1) iface.fcs = val[0];
        else if (code === 14 && val.length >= 8) iface.tsOffset = Number(new DataView(val.buffer, val.byteOffset, val.byteLength).getBigInt64(0, little));
      });
      interfaces.push(iface);
      linkType = lt;
    } else if (type === 0x00000006) {
      n = pushEnhanced(bytes, o, total, little, interfaces, packets, n, warnings);
      linkType = packets[packets.length - 1]?.linkType ?? linkType;
    } else if (type === 0x00000002) {
      n = pushLegacyPacket(bytes, o, total, little, interfaces, packets, n);
      linkType = packets[packets.length - 1]?.linkType ?? linkType;
    } else if (type === 0x00000003) {
      n = pushSimple(bytes, o, total, little, interfaces, packets, n);
      linkType = packets[packets.length - 1]?.linkType ?? linkType;
    } else if (type !== PCAPNG_SHB) {
      if (!unknownNoted) {
        warnings.push("Some pcapng blocks were not packet data (statistics, names, or a private block). They were skipped.");
        unknownNoted = true;
      }
    } else if (o + 16 <= bytes.length) {
      const major = view.getUint16(o + 12, little);
      const minor = view.getUint16(o + 14, little);
      if (major !== 1 || minor !== 0) {
        warnings.push(`pcapng section version is ${major}.${minor}. Primer expects 1.0 and will still read the packets in this section.`);
      }
    }
    o += total;
  }
  if (o < bytes.length && o + 12 > bytes.length) warnings.push("The pcapng file ends in the middle of a block header. Earlier packets were kept.");
  if (packets.length === 0) warnings.push("The pcapng file had no packet blocks Primer could read.");
  return { format: "pcapng", packets, warnings, linkType };
}

function sectionEndian(bytes: Uint8Array, offset: number, warnings: string[]): boolean {
  if (offset + 12 > bytes.length) return true;
  const le = readU32(bytes, offset + 8, true);
  const be = readU32(bytes, offset + 8, false);
  if (le === PCAPNG_BOM) return true;
  if (be === PCAPNG_BOM) return false;
  warnings.push("A pcapng section header has no byte-order magic (1A2B3C4D). Primer assumed little-endian, which is what Windows captures use.");
  return true;
}

function ifaceAt(interfaces: Iface[], id: number): Iface {
  return interfaces[id] ?? { linkType: 1, tsResol: 1e-6, tsOffset: 0, name: "", snapLen: 0xffffffff, fcs: 0 };
}

function trimFcs(data: Uint8Array, fcs: number): Uint8Array {
  if (fcs > 0 && data.length > fcs) return data.subarray(0, data.length - fcs);
  return data;
}

function pushEnhanced(bytes: Uint8Array, o: number, total: number, little: boolean, interfaces: Iface[], packets: RawPacket[], n: number, warnings: string[]): number {
  if (o + 28 > bytes.length) return n;
  const view = viewOf(bytes);
  const ifId = view.getUint32(o + 8, little);
  const high = view.getUint32(o + 12, little);
  const low = view.getUint32(o + 16, little);
  const incl = view.getUint32(o + 20, little);
  const orig = view.getUint32(o + 24, little);
  if (ifId >= interfaces.length) warnings.push(`Packet ${n + 1} names interface ${ifId}, which this section has not described. It is shown as Ethernet.`);
  const iface = ifaceAt(interfaces, ifId);
  const dataEnd = Math.min(o + 28 + incl, o + total - 4);
  const ticks = high * 0x100000000 + low;
  packets.push({
    n: n + 1,
    ts: ticks * iface.tsResol + iface.tsOffset,
    origLen: orig,
    data: trimFcs(bytes.subarray(o + 28, Math.max(o + 28, dataEnd)), iface.fcs),
    linkType: iface.linkType,
  });
  return n + 1;
}

function pushLegacyPacket(bytes: Uint8Array, o: number, total: number, little: boolean, interfaces: Iface[], packets: RawPacket[], n: number): number {
  if (o + 28 > bytes.length) return n;
  const view = viewOf(bytes);
  const ifId = view.getUint16(o + 8, little);
  const high = view.getUint32(o + 12, little);
  const low = view.getUint32(o + 16, little);
  const incl = view.getUint32(o + 20, little);
  const orig = view.getUint32(o + 24, little);
  const iface = ifaceAt(interfaces, ifId);
  const dataEnd = Math.min(o + 28 + incl, o + total - 4);
  const ticks = high * 0x100000000 + low;
  packets.push({
    n: n + 1,
    ts: ticks * iface.tsResol + iface.tsOffset,
    origLen: orig,
    data: trimFcs(bytes.subarray(o + 28, Math.max(o + 28, dataEnd)), iface.fcs),
    linkType: iface.linkType,
  });
  return n + 1;
}

function pushSimple(bytes: Uint8Array, o: number, total: number, little: boolean, interfaces: Iface[], packets: RawPacket[], n: number): number {
  if (o + 12 > bytes.length) return n;
  const orig = viewOf(bytes).getUint32(o + 8, little);
  const iface = ifaceAt(interfaces, 0);
  const cap = Math.min(orig, iface.snapLen || orig);
  const data = bytes.subarray(o + 12, Math.min(o + 12 + cap, o + total - 4));
  packets.push({ n: n + 1, ts: 0, origLen: orig, data: trimFcs(data, iface.fcs), linkType: iface.linkType });
  return n + 1;
}

function readOptions(
  bytes: Uint8Array,
  start: number,
  end: number,
  little: boolean,
  onOpt: (code: number, val: Uint8Array) => void,
) {
  const view = viewOf(bytes);
  let o = start;
  while (o + 4 <= end) {
    const code = view.getUint16(o, little);
    const len = view.getUint16(o + 2, little);
    if (code === 0) break;
    const val = bytes.subarray(o + 4, Math.min(end, o + 4 + len));
    onOpt(code, val);
    o += 4 + Math.ceil(len / 4) * 4;
  }
}

export interface TimedPacket {
  ts: number;
  data: Uint8Array;
}

export function encodePcap(packets: TimedPacket[], linkType = 1): Uint8Array {
  let size = 24;
  for (const p of packets) size += 16 + p.data.length;
  const out = new Uint8Array(size);
  const view = new DataView(out.buffer);
  view.setUint32(0, PCAP_MAGIC_US, true);
  view.setUint16(4, 2, true);
  view.setUint16(6, 4, true);
  view.setUint32(16, 65535, true);
  view.setUint32(20, linkType, true);
  let o = 24;
  for (const p of packets) {
    const sec = Math.floor(p.ts);
    const usec = Math.max(0, Math.round((p.ts - sec) * 1e6));
    view.setUint32(o, sec, true);
    view.setUint32(o + 4, usec, true);
    view.setUint32(o + 8, p.data.length, true);
    view.setUint32(o + 12, p.data.length, true);
    out.set(p.data, o + 16);
    o += 16 + p.data.length;
  }
  return out;
}

function pad4(n: number): number {
  return (4 - (n % 4)) % 4;
}

export function encodePcapng(packets: TimedPacket[], linkType = 1): Uint8Array {
  const chunks: Uint8Array[] = [];
  chunks.push(sectionHeader());
  chunks.push(interfaceBlock(linkType));
  for (const p of packets) chunks.push(enhancedPacket(p));
  let size = 0;
  for (const c of chunks) size += c.length;
  const out = new Uint8Array(size);
  let o = 0;
  for (const c of chunks) {
    out.set(c, o);
    o += c.length;
  }
  return out;
}

function block(type: number, body: Uint8Array): Uint8Array {
  const total = 12 + body.length;
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  view.setUint32(0, type, true);
  view.setUint32(4, total, true);
  out.set(body, 8);
  view.setUint32(8 + body.length, total, true);
  return out;
}

function sectionHeader(): Uint8Array {
  const body = new Uint8Array(16);
  const view = new DataView(body.buffer);
  view.setUint32(0, 0x1a2b3c4d, true);
  view.setUint16(4, 1, true);
  view.setUint16(6, 0, true);
  view.setBigInt64(8, BigInt(-1), true);
  return block(PCAPNG_SHB, body);
}

function interfaceBlock(linkType: number): Uint8Array {
  const body = new Uint8Array(12);
  const view = new DataView(body.buffer);
  view.setUint16(0, linkType, true);
  view.setUint16(2, 0, true);
  view.setUint32(4, 65535, true);
  view.setUint16(8, 9, true);
  view.setUint16(10, 1, true);
  const opt = new Uint8Array(4);
  opt[0] = 6;
  const full = new Uint8Array(body.length + opt.length);
  full.set(body, 0);
  full.set(opt, body.length);
  const end = new Uint8Array(full.length + 4);
  end.set(full, 0);
  return block(1, end);
}

function enhancedPacket(p: TimedPacket): Uint8Array {
  const pad = pad4(p.data.length);
  const body = new Uint8Array(20 + p.data.length + pad);
  const view = new DataView(body.buffer);
  const usec = Math.round(p.ts * 1e6);
  const high = Math.floor(usec / 0x100000000);
  const low = usec >>> 0;
  view.setUint32(0, 0, true);
  view.setUint32(4, high, true);
  view.setUint32(8, low, true);
  view.setUint32(12, p.data.length, true);
  view.setUint32(16, p.data.length, true);
  body.set(p.data, 20);
  return block(6, body);
}
