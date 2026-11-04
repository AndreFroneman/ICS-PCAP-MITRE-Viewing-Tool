import { latin1 } from "./bytes.ts";
import { detect } from "./detect.ts";
import { isDeviceIp } from "./ip.ts";
import {
  Bit,
  worse,
  type Analysis,
  type Conversation,
  type Endpoint,
  type FileObject,
  type HierNode,
  type PacketRec,
  type Row,
  type Severity,
  type TimelineBucket,
} from "./model.ts";

const LAYER_ORDER: { bit: number; name: string; parent: string }[] = [
  { bit: Bit.eth, name: "Ethernet", parent: "" },
  { bit: Bit.arp, name: "ARP", parent: "Ethernet" },
  { bit: Bit.ip, name: "IPv4", parent: "Ethernet" },
  { bit: Bit.ipv6, name: "IPv6", parent: "Ethernet" },
  { bit: Bit.icmp, name: "ICMP", parent: "IPv4" },
  { bit: Bit.tcp, name: "TCP", parent: "IPv4" },
  { bit: Bit.udp, name: "UDP", parent: "IPv4" },
  { bit: Bit.dns, name: "DNS", parent: "UDP" },
  { bit: Bit.dhcp, name: "DHCP", parent: "UDP" },
  { bit: Bit.http, name: "HTTP", parent: "TCP" },
  { bit: Bit.tls, name: "TLS", parent: "TCP" },
  { bit: Bit.modbus, name: "Modbus", parent: "TCP" },
  { bit: Bit.s7, name: "S7comm", parent: "TCP" },
  { bit: Bit.dnp3, name: "DNP3", parent: "TCP" },
  { bit: Bit.enip, name: "EtherNet/IP", parent: "TCP" },
  { bit: Bit.bacnet, name: "BACnet", parent: "UDP" },
  { bit: Bit.iec, name: "IEC 104", parent: "TCP" },
  { bit: Bit.opcua, name: "OPC UA", parent: "TCP" },
  { bit: Bit.mqtt, name: "MQTT", parent: "TCP" },
  { bit: Bit.smb, name: "SMB", parent: "TCP" },
  { bit: Bit.ssh, name: "SSH", parent: "TCP" },
  { bit: Bit.ftp, name: "FTP", parent: "TCP" },
  { bit: Bit.smtp, name: "SMTP", parent: "TCP" },
];

export function analyze(packets: PacketRec[]): Analysis {
  const rows = packets.map((p) => p.row);
  const findings = detect(rows);
  const t0 = rows.length ? rows[0].ts : 0;
  const t1 = rows.length ? rows[rows.length - 1].ts : 0;
  const names: Record<string, string> = {};
  for (const r of rows) {
    if (r.dnsQ && r.dnsA && isDeviceIp(r.dnsA) && !names[r.dnsA]) names[r.dnsA] = r.dnsQ;
    if (r.dhcpHost && r.dhcpIp && isDeviceIp(r.dhcpIp) && !names[r.dhcpIp]) names[r.dhcpIp] = r.dhcpHost;
  }
  const devices = new Set<string>();
  for (const r of rows) {
    if (isDeviceIp(r.src)) devices.add(r.src);
    if (isDeviceIp(r.dst)) devices.add(r.dst);
  }
  const marks = new Map<number, Severity>();
  for (const f of findings) {
    if (f.severity === "info") continue;
    for (const e of f.evidence) {
      const prev = marks.get(e.n);
      marks.set(e.n, prev ? worse(prev, f.severity) : f.severity);
    }
  }
  const story = headline(rows, findings, [...devices], t0, t1);
  return {
    findings,
    conversations: conversations(rows),
    endpoints: endpoints(rows),
    hierarchy: hierarchy(rows),
    timeline: timeline(rows, t0, t1),
    dns: rows.filter((r) => r.dnsQ).slice(0, 500).map((r) => ({
      n: r.n, ts: r.ts, src: r.src, dst: r.dst, name: r.dnsQ ?? "", answer: r.dnsA ?? "",
    })),
    http: rows.filter((r) => r.httpMethod || r.httpStatus).slice(0, 500).map((r) => ({
      n: r.n, ts: r.ts, src: r.src, dst: r.dst, method: r.httpMethod ?? "", host: r.httpHost ?? "", path: r.httpPath ?? "", status: r.httpStatus ?? 0, auth: r.httpAuth ?? "",
    })),
    tls: rows.filter((r) => r.tlsSni || r.tlsCn).slice(0, 500).map((r) => ({
      n: r.n, ts: r.ts, src: r.src, dst: r.dst, sni: r.tlsSni ?? "", subject: r.tlsCn ?? "", issuer: r.tlsIssuer ?? "",
    })),
    files: carveFiles(packets),
    names,
    devices: [...devices].sort(),
    headline: story.headline,
    detail: story.detail,
    marks: [...marks.entries()].map(([n, severity]) => ({ n, severity })),
    t0,
    t1,
  };
}

function headline(rows: { proto: string; layers: number }[], findings: { severity: Severity; title: string }[], devices: string[], t0: number, t1: number): { headline: string; detail: string } {
  const counts = new Map<string, number>();
  for (const r of rows) counts.set(r.proto, (counts.get(r.proto) ?? 0) + 1);
  const ranked = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  const boring = new Set(["TCP", "UDP", "IPv4", "IPv6", "Ethernet", "ARP", "ICMP", "ICMPv6", "Raw", "Linux cooked"]);
  const interesting = ranked.filter(([name]) => !boring.has(name));
  const top = (interesting.length ? interesting : ranked).slice(0, 3).map(([name]) => prettyProto(name));
  const mostly = top.length ? `mostly ${humanList(top)}` : "with no recognised application traffic";
  const suspicious = findings.filter((f) => f.severity !== "info");
  const sus = suspicious.length === 0
    ? "Nothing in the automatic checks looks suspicious."
    : suspicious.length === 1
      ? "1 thing looks suspicious."
      : `${suspicious.length} things look suspicious.`;
  const n = devices.length;
  const head = `This capture has ${n} device${n === 1 ? "" : "s"}, ${mostly}. ${sus}`;
  const span = t1 > t0 ? `It covers ${formatSpan(t1 - t0)} and ${rows.length.toLocaleString()} packets.` : `It contains ${rows.length.toLocaleString()} packets.`;
  const lead = suspicious.slice(0, 4).map((f) => f.title.replace(/\.$/, "")).join("; ");
  const detail = suspicious.length
    ? `${span} The leads, highest severity first: ${lead}${suspicious.length > 4 ? ` and ${suspicious.length - 4} more` : ""}. These are heuristics for triage, not proof.`
    : `${span} Primer did not see a scan, a cleartext password, a tunnel, or an industrial write. That is not a guarantee the network is fine.`;
  return { headline: head, detail };
}

function prettyProto(name: string): string {
  if (name === "Modbus") return "Modbus polling";
  if (name === "HTTP") return "web traffic";
  if (name === "TLS") return "encrypted web";
  if (name === "DNS") return "DNS";
  return name;
}

function humanList(items: string[]): string {
  if (items.length === 1) return items[0];
  if (items.length === 2) return `${items[0]} and ${items[1]}`;
  return `${items.slice(0, -1).join(", ")}, and ${items[items.length - 1]}`;
}

export function formatSpan(seconds: number): string {
  if (seconds < 90) return `${seconds.toFixed(0)} seconds`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
  const h = Math.floor(seconds / 3600);
  const m = Math.round((seconds % 3600) / 60);
  return m ? `${h} h ${m} min` : `${h} h`;
}

function conversations(rows: Row[]): Conversation[] {
  const map = new Map<string, Conversation>();
  for (const r of rows) {
    if (!r.src || !r.dst) continue;
    const proto = r.layers & Bit.tcp ? "TCP" : r.layers & Bit.udp ? "UDP" : r.proto;
    const flip = r.src > r.dst || (r.src === r.dst && r.sp > r.dp);
    const a = flip ? r.dst : r.src;
    const b = flip ? r.src : r.dst;
    const aPort = flip ? r.dp : r.sp;
    const bPort = flip ? r.sp : r.dp;
    const key = `${proto}|${a}|${aPort}|${b}|${bPort}`;
    let c = map.get(key);
    if (!c) {
      c = { a, b, proto, aPort, bPort, packets: 0, bytes: 0, aToB: 0, bToA: 0, start: r.ts, end: r.ts };
      map.set(key, c);
    }
    c.packets += 1;
    c.bytes += r.len;
    c.end = Math.max(c.end, r.ts);
    c.start = Math.min(c.start, r.ts);
    if (r.src === a) c.aToB += r.len;
    else c.bToA += r.len;
  }
  return [...map.values()].sort((x, y) => y.bytes - x.bytes).slice(0, 300);
}

function endpoints(rows: Row[]): Endpoint[] {
  const map = new Map<string, Endpoint>();
  const bump = (addr: string, kind: "ip" | "mac", sent: boolean, bytes: number) => {
    if (!addr) return;
    const key = `${kind}|${addr}`;
    let e = map.get(key);
    if (!e) {
      e = { addr, kind, packets: 0, bytesSent: 0, bytesRecv: 0, tx: 0, rx: 0 };
      map.set(key, e);
    }
    e.packets += 1;
    if (sent) {
      e.bytesSent += bytes;
      e.tx += 1;
    } else {
      e.bytesRecv += bytes;
      e.rx += 1;
    }
  };
  for (const r of rows) {
    bump(r.src, "ip", true, r.len);
    bump(r.dst, "ip", false, r.len);
    bump(r.macSrc, "mac", true, r.len);
    bump(r.macDst, "mac", false, r.len);
  }
  return [...map.values()].sort((a, b) => b.bytesSent + b.bytesRecv - (a.bytesSent + a.bytesRecv)).slice(0, 400);
}

function hierarchy(rows: Row[]): HierNode[] {
  const counts = new Map<string, { packets: number; bytes: number }>();
  const add = (name: string, bytes: number) => {
    const c = counts.get(name) ?? { packets: 0, bytes: 0 };
    c.packets += 1;
    c.bytes += bytes;
    counts.set(name, c);
  };
  for (const r of rows) {
    add("Frame", r.len);
    let sawEth = false;
    for (const layer of LAYER_ORDER) {
      if ((r.layers & layer.bit) === 0) continue;
      if (layer.bit === Bit.eth) sawEth = true;
      add(layer.name, r.len);
    }
    if (!sawEth) add("Other link", r.len);
  }
  const frame = counts.get("Frame") ?? { packets: rows.length, bytes: 0 };
  const root: HierNode = { name: "Frame", packets: frame.packets, bytes: frame.bytes, children: [] };
  const nodes = new Map<string, HierNode>([["Frame", root]]);
  for (const layer of LAYER_ORDER) {
    const c = counts.get(layer.name);
    if (!c) continue;
    const node: HierNode = { name: layer.name, packets: c.packets, bytes: c.bytes, children: [] };
    nodes.set(layer.name, node);
    const parentName = layer.parent && nodes.has(layer.parent) ? layer.parent : "Frame";
    nodes.get(parentName)?.children.push(node);
  }
  return [root];
}

function timeline(rows: Row[], t0: number, t1: number): TimelineBucket[] {
  if (!rows.length) return [];
  const span = Math.max(t1 - t0, 0.001);
  const buckets = Math.min(80, Math.max(12, Math.round(span)));
  const width = span / buckets;
  const out: TimelineBucket[] = Array.from({ length: buckets }, (_, i) => ({ t: t0 + i * width, packets: 0, bytes: 0 }));
  for (const r of rows) {
    let i = Math.floor((r.ts - t0) / width);
    if (i >= buckets) i = buckets - 1;
    if (i < 0) i = 0;
    out[i].packets += 1;
    out[i].bytes += r.len;
  }
  return out;
}

function carveFiles(packets: PacketRec[]): FileObject[] {
  const files: FileObject[] = [];
  const seen = new Set<string>();
  for (const p of packets) {
    if (files.length >= 8) break;
    if (p.row.appLen < 6) continue;
    const payload = p.raw.subarray(p.row.appOff, p.row.appOff + p.row.appLen);
    if (p.row.httpStatus || p.row.httpMethod) {
      const head = latin1(payload.subarray(0, Math.min(payload.length, 2000)));
      const idx = head.indexOf("\r\n\r\n");
      if (idx >= 0) {
        const body = payload.subarray(idx + 4);
        const kind = magicKind(body);
        if (kind && body.length > 0 && body.length < 65536) {
          const name = fileName(p.row.httpPath, kind.ext, p.row.n);
          const id = `${p.row.n}:${name}`;
          if (!seen.has(id)) {
            seen.add(id);
            files.push({ id, n: p.row.n, name, type: kind.type, size: body.length, source: "HTTP body", data: body.slice() });
          }
        }
      }
    }
    const kind = magicKind(payload);
    if (kind && payload.length < 65536) {
      const id = `${p.row.n}:carve`;
      if (!seen.has(id) && !files.some((f) => f.n === p.row.n)) {
        seen.add(id);
        files.push({
          id,
          n: p.row.n,
          name: `packet-${p.row.n}.${kind.ext}`,
          type: kind.type,
          size: payload.length,
          source: "Payload signature",
          data: payload.slice(),
        });
      }
    }
  }
  return files;
}

function magicKind(u: Uint8Array): { ext: string; type: string } | null {
  if (u.length >= 6 && latin1(u.subarray(0, 6)) === "GIF89a") return { ext: "gif", type: "GIF image" };
  if (u.length >= 6 && latin1(u.subarray(0, 6)) === "GIF87a") return { ext: "gif", type: "GIF image" };
  if (u.length >= 4 && u[0] === 0x89 && u[1] === 0x50 && u[2] === 0x4e && u[3] === 0x47) return { ext: "png", type: "PNG image" };
  if (u.length >= 4 && latin1(u.subarray(0, 4)) === "%PDF") return { ext: "pdf", type: "PDF" };
  if (u.length >= 4 && u[0] === 0x50 && u[1] === 0x4b && u[2] === 0x03 && u[3] === 0x04) return { ext: "zip", type: "ZIP archive" };
  return null;
}

function fileName(path: string | undefined, ext: string, n: number): string {
  if (!path) return `packet-${n}.${ext}`;
  const base = path.split("?")[0].split("/").filter(Boolean).pop();
  if (!base) return `packet-${n}.${ext}`;
  return base.includes(".") ? base : `${base}.${ext}`;
}
