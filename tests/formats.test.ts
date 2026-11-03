import { describe, expect, it } from "vitest";
import { tcpIpv4Frame, type Host } from "../src/lib/frame.ts";
import { inspectCapture } from "../src/lib/inspect.ts";
import { CaptureError, encodePcap, encodePcapng, gunzipIfNeeded, parseCapture, type TimedPacket } from "../src/lib/pcap.ts";

const a: Host = { mac: "02:00:00:00:00:0a", ip: "10.1.0.1" };
const b: Host = { mac: "02:00:00:00:00:0b", ip: "10.1.0.2" };

function frame(): Uint8Array {
  return tcpIpv4Frame({ src: a, dst: b, sp: 40000, dp: 80, seq: 1, ack: 0, flags: 0x02 });
}

function packets(): TimedPacket[] {
  return [
    { ts: 1_700_000_000.5, data: frame() },
    { ts: 1_700_000_001, data: frame() },
  ];
}

function view(bytes: Uint8Array): DataView {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

function pcapBigEndian(pkts: TimedPacket[]): Uint8Array {
  let size = 24;
  for (const p of pkts) size += 16 + p.data.length;
  const out = new Uint8Array(size);
  const v = view(out);
  v.setUint32(0, 0xa1b2c3d4, false);
  v.setUint16(4, 2, false);
  v.setUint16(6, 4, false);
  v.setUint32(16, 65535, false);
  v.setUint32(20, 1, false);
  let o = 24;
  for (const p of pkts) {
    const sec = Math.floor(p.ts);
    const usec = Math.round((p.ts - sec) * 1e6);
    v.setUint32(o, sec, false);
    v.setUint32(o + 4, usec, false);
    v.setUint32(o + 8, p.data.length, false);
    v.setUint32(o + 12, p.data.length, false);
    out.set(p.data, o + 16);
    o += 16 + p.data.length;
  }
  return out;
}

function pcapngBigEndian(payload: Uint8Array): Uint8Array {
  const shb = new Uint8Array(28);
  const sv = view(shb);
  sv.setUint32(0, 0x0a0d0d0a, false);
  sv.setUint32(4, 28, false);
  sv.setUint32(8, 0x1a2b3c4d, false);
  sv.setUint16(12, 1, false);
  sv.setUint16(14, 0, false);
  sv.setUint32(16, 0xffffffff, false);
  sv.setUint32(20, 0xffffffff, false);
  sv.setUint32(24, 28, false);
  const idb = new Uint8Array(20);
  const iv = view(idb);
  iv.setUint32(0, 1, false);
  iv.setUint32(4, 20, false);
  iv.setUint16(8, 1, false);
  iv.setUint32(12, 65535, false);
  iv.setUint32(16, 20, false);
  const pad = (4 - (payload.length % 4)) % 4;
  const total = 32 + payload.length + pad;
  const epb = new Uint8Array(total);
  const ev = view(epb);
  ev.setUint32(0, 6, false);
  ev.setUint32(4, total, false);
  ev.setUint32(20, payload.length, false);
  ev.setUint32(24, payload.length, false);
  epb.set(payload, 28);
  ev.setUint32(total - 4, total, false);
  const out = new Uint8Array(shb.length + idb.length + epb.length);
  out.set(shb, 0);
  out.set(idb, shb.length);
  out.set(epb, shb.length + idb.length);
  return out;
}

async function open(bytes: Uint8Array) {
  const copy = bytes.slice();
  return inspectCapture(copy.buffer);
}

describe("classic pcap variants", () => {
  it("reads little-endian microsecond pcap 2.4", async () => {
    const opened = await open(encodePcap(packets()));
    expect(opened.file.packets).toHaveLength(2);
    expect(opened.packets[0].row.proto).toBe("TCP");
    expect(opened.file.warnings.join(" ")).not.toMatch(/version/i);
  });

  it("reads big-endian microsecond pcap", async () => {
    const opened = await open(pcapBigEndian(packets()));
    expect(opened.file.packets).toHaveLength(2);
    expect(opened.packets[0].row.dst).toBe("10.1.0.2");
  });

  it("reads nanosecond pcap and keeps the fraction", () => {
    const file = encodePcap([{ ts: 100.25, data: frame() }]);
    view(file).setUint32(0, 0xa1b23c4d, true);
    view(file).setUint32(28, 250_000_000, true);
    const parsed = parseCapture(file);
    expect(parsed.packets[0].ts).toBeCloseTo(100.25, 6);
  });

  it("accepts version 2.3 with a warning", () => {
    const file = encodePcap(packets());
    view(file).setUint16(6, 3, true);
    const parsed = parseCapture(file);
    expect(parsed.packets).toHaveLength(2);
    expect(parsed.warnings.join(" ")).toMatch(/version 2\.3/);
  });

  it("accepts an odd version instead of refusing the file", () => {
    const file = encodePcap([{ ts: 10, data: frame() }]);
    view(file).setUint16(4, 9, true);
    view(file).setUint16(6, 1, true);
    const parsed = parseCapture(file);
    expect(parsed.packets).toHaveLength(1);
    expect(parsed.warnings.join(" ")).toMatch(/version 9\.1/);
  });

  it("reads modified Kuznetsov pcap", () => {
    const payload = frame();
    const header = 24;
    const file = new Uint8Array(24 + header + payload.length);
    const v = view(file);
    v.setUint32(0, 0xa1b2cd34, true);
    v.setUint16(4, 2, true);
    v.setUint16(6, 4, true);
    v.setUint32(16, 65535, true);
    v.setUint32(20, 1, true);
    v.setUint32(24, 50, true);
    v.setUint32(28, 0, true);
    v.setUint32(32, payload.length, true);
    v.setUint32(36, payload.length, true);
    file.set(payload, 24 + header);
    const parsed = parseCapture(file);
    expect(parsed.packets).toHaveLength(1);
    expect(parsed.packets[0].data).toEqual(payload);
    expect(parsed.warnings.join(" ")).toMatch(/Kuznetsov/);
  });

  it("keeps earlier packets when the last one is truncated", () => {
    const file = encodePcap(packets());
    const cut = file.subarray(0, file.length - 10);
    const parsed = parseCapture(cut);
    expect(parsed.packets.length).toBeGreaterThan(0);
    expect(parsed.packets.length).toBeLessThan(2);
    expect(parsed.warnings.join(" ")).toMatch(/truncated|ends in the middle/i);
  });
});

describe("pcapng variants", () => {
  it("reads a normal pcapng section", async () => {
    const opened = await open(encodePcapng(packets()));
    expect(opened.file.format).toBe("pcapng");
    expect(opened.packets[1].row.proto).toBe("TCP");
  });

  it("reads a big-endian pcapng", async () => {
    const opened = await open(pcapngBigEndian(frame()));
    expect(opened.file.packets).toHaveLength(1);
    expect(opened.packets[0].row.src).toBe("10.1.0.1");
  });

  it("skips unknown blocks and reads a second section", () => {
    const first = encodePcapng([{ ts: 5, data: frame() }]);
    const unknown = new Uint8Array(16);
    const u = view(unknown);
    u.setUint32(0, 0x0badf00d, true);
    u.setUint32(4, 16, true);
    u.setUint32(12, 16, true);
    const second = encodePcapng([{ ts: 9, data: frame() }], 101);
    const file = new Uint8Array(first.length + unknown.length + second.length);
    file.set(first, 0);
    file.set(unknown, first.length);
    file.set(second, first.length + unknown.length);
    const parsed = parseCapture(file);
    expect(parsed.packets).toHaveLength(2);
    expect(parsed.packets[1].linkType).toBe(101);
    expect(parsed.warnings.join(" ")).toMatch(/skipped/);
  });

  it("warns on a pcapng version other than 1.0 and still returns packets", () => {
    const file = encodePcapng(packets());
    view(file).setUint16(14, 2, true);
    const parsed = parseCapture(file);
    expect(parsed.packets).toHaveLength(2);
    expect(parsed.warnings.join(" ")).toMatch(/version is 1\.2/);
  });

  it("reads a legacy packet block and a snaplen of zero", () => {
    const payload = frame();
    const shb = encodePcapng([]).subarray(0, 28);
    const idb = new Uint8Array(20);
    const v = view(idb);
    v.setUint32(0, 1, true);
    v.setUint32(4, 20, true);
    v.setUint16(8, 1, true);
    v.setUint32(12, 0, true);
    v.setUint32(16, 20, true);
    const pad = (4 - (payload.length % 4)) % 4;
    const pbLen = 32 + payload.length + pad;
    const pb = new Uint8Array(pbLen);
    const p = view(pb);
    p.setUint32(0, 2, true);
    p.setUint32(4, pbLen, true);
    p.setUint16(8, 0, true);
    p.setUint32(12, 1, true);
    p.setUint32(20, payload.length, true);
    p.setUint32(24, payload.length, true);
    pb.set(payload, 28);
    p.setUint32(pbLen - 4, pbLen, true);
    const file = new Uint8Array(shb.length + idb.length + pb.length);
    file.set(shb, 0);
    file.set(idb, shb.length);
    file.set(pb, shb.length + idb.length);
    const parsed = parseCapture(file);
    expect(parsed.packets).toHaveLength(1);
    expect(parsed.packets[0].data).toEqual(payload);
  });
});

describe("compression, names, and link types", () => {
  it("opens a gzip-compressed pcap even though the name is irrelevant", async () => {
    const raw = encodePcap(packets());
    const copy = new Uint8Array(raw.byteLength);
    copy.set(raw);
    const stream = new Blob([copy]).stream().pipeThrough(new CompressionStream("gzip"));
    const gz = new Uint8Array(await new Response(stream).arrayBuffer());
    expect(gz[0]).toBe(0x1f);
    const opened = await inspectCapture(gz.buffer);
    expect(opened.file.packets).toHaveLength(2);
    expect(opened.file.warnings.join(" ")).toMatch(/gzip/i);
    const inflated = await gunzipIfNeeded(gz);
    expect(parseCapture(inflated.bytes).format).toBe("pcap");
  });

  it("explains an unrecognised file instead of blaming the version", () => {
    const junk = new Uint8Array([0x4d, 0x5a, 0x90, 0x00, 0, 0, 0, 0]);
    expect(() => parseCapture(junk)).toThrow(CaptureError);
    try {
      parseCapture(junk);
    } catch (error) {
      expect(error).toBeInstanceOf(CaptureError);
      expect((error as Error).message).toMatch(/4d 5a 90 00/);
      expect((error as Error).message).toMatch(/a1b2c3d4/);
    }
  });

  it("decodes Linux cooked, raw IP, loopback, PPP, and radiotap", async () => {
    const ip = frame().subarray(14);
    const sll = new Uint8Array(16 + ip.length);
    sll[14] = 0x08;
    sll.set(ip, 16);
    const sll2 = new Uint8Array(20 + ip.length);
    sll2[0] = 0x08;
    sll2.set(ip, 20);
    const loop = new Uint8Array(4 + ip.length);
    loop[0] = 2;
    loop.set(ip, 4);
    const ppp = new Uint8Array(4 + ip.length);
    ppp.set([0xff, 0x03, 0x00, 0x21], 0);
    ppp.set(ip, 4);
    const radio = new Uint8Array(8 + 24 + 8 + ip.length);
    radio[2] = 8;
    radio[8] = 0x08;
    radio[32] = 0xaa;
    radio[33] = 0xaa;
    radio[34] = 0x03;
    radio[38] = 0x08;
    radio[39] = 0x00;
    radio.set(ip, 40);
    const cases: { link: number; data: Uint8Array; proto: string }[] = [
      { link: 113, data: sll, proto: "TCP" },
      { link: 276, data: sll2, proto: "TCP" },
      { link: 0, data: loop, proto: "TCP" },
      { link: 101, data: ip, proto: "TCP" },
      { link: 9, data: ppp, proto: "TCP" },
      { link: 127, data: radio, proto: "TCP" },
    ];
    for (const item of cases) {
      const parsed = parseCapture(encodePcap([{ ts: 1, data: item.data }], item.link));
      expect(parsed.packets[0].linkType).toBe(item.link);
      const opened = await open(encodePcap([{ ts: 1, data: item.data }], item.link));
      expect(opened.packets[0].row.proto, `link ${item.link}`).toBe(item.proto);
    }
  });
});
