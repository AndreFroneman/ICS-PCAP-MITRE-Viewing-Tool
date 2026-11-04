import { isPublicUnicast } from "./ip.ts";
import type {
  Analysis,
  ClaimStatus,
  Confidence,
  Evidence,
  Finding,
  Row,
  TriageLevel,
  ValidationStatus,
} from "./model.ts";

/**
 * Forensic labels for Primer 2.
 *
 * A finding has one claim status. "Observed" means the bytes show the fact
 * (a Modbus function, a password, a SYN). "Possible" means an attack reading
 * the bytes are only consistent with. Neither word means the controller was
 * exploited. Technique ids are always a possible reading of those bytes.
 */

export const ATTRIBUTION_NOTE =
  "Observed technical fact. Not evidence of nationality or sponsorship.";

export const CASE_GAPS = [
  "Controller diagnostics, or a program checksum taken from the PLC itself.",
  "Logs from the engineering workstation for the same clock window.",
  "The change ticket or maintenance record, if one was raised.",
];

export interface AssetRecord {
  id: string;
  ip: string;
  mac: string;
  hostname: string;
  role: string;
  confidence: Confidence;
  hypothesis: string;
  alternateHypothesis: string;
  firstSeen: number;
  lastSeen: number;
  evidence: Evidence[];
}

export interface FingerprintRecord {
  id: string;
  ip: string;
  kind: string;
  value: string;
  packetN: number;
  observedFact: string;
  hypothesis: string;
  attributionNote: string;
}

export interface ZeekConn {
  src: string;
  dst: string;
  sp: number;
  dp: number;
  proto: string;
  packets: number;
  bytes: number;
  start: number;
  end: number;
  service: string;
}

export interface ZeekWeird {
  packetN: number;
  name: string;
  detail: string;
}

export interface OtRow {
  n: number;
  ts: number;
  src: string;
  dst: string;
  protocol: string;
  operation: string;
  address: string;
  direction: "read" | "write" | "command" | "other";
}

export interface CaseTriage {
  level: TriageLevel;
  name: string;
  explanation: string;
  families: string[];
}

export interface Dossier {
  findings: Finding[];
  assets: AssetRecord[];
  fingerprints: FingerprintRecord[];
  connections: ZeekConn[];
  weird: ZeekWeird[];
  dns: { n: number; src: string; name: string; answer: string }[];
  http: { n: number; src: string; host: string; method: string; path: string }[];
  tls: { n: number; src: string; dst: string; sni: string }[];
  files: { n: number; name: string; type: string; size: number }[];
  otRows: OtRow[];
  triage: CaseTriage;
  gaps: string[];
}

export interface ActivityEntry {
  at: string;
  actor: string;
  action: string;
  detail: string;
}

export interface AnalystDecision {
  findingId: string;
  validation: ValidationStatus;
  actor: string;
  at: string;
  note: string;
}

const WRITE_FUNCS = new Set([5, 6, 15, 16, 22, 23]);
const READ_FUNCS = new Set([1, 2, 3, 4]);
const OT_SERVER = new Set([102, 502, 2404, 4840, 20000, 2222, 44818, 47808]);

const TRIAGE_NAME: Record<TriageLevel, string> = {
  1: "Anomaly",
  2: "Suspicious activity",
  3: "Credible incident evidence",
};

export function familyOf(id: string): string {
  if (id.startsWith("port-scan") || id === "point-id") return "recon";
  if (id === "cleartext" || id === "brute-force") return "credential";
  if (id.startsWith("beacon") || id === "dns-tunnel" || id.startsWith("exfil") || id.startsWith("external")) return "c2";
  if (id === "smb-lateral") return "lateral";
  if (/^(modbus|s7|iec|dnp3|bacnet|cip|new-writer)/.test(id)) return "ot-command";
  if (id === "benign-polling" || id.startsWith("first-engineering") || id.startsWith("polling-")) return "baseline";
  return "other";
}

export function triageName(level: TriageLevel): string {
  return TRIAGE_NAME[level];
}

function earliest(f: Finding, rows: Row[]): number | undefined {
  const nums = new Set(f.evidence.map((e) => e.n));
  let ts: number | undefined;
  for (const row of rows) {
    if (!nums.has(row.n)) continue;
    if (ts === undefined || row.ts < ts) ts = row.ts;
  }
  return ts;
}

function altFor(id: string): string {
  if (id.startsWith("port-scan")) return "An inventory scanner or a misconfigured laptop can send the same SYNs. Confirm whether a scan was scheduled before treating the host as hostile.";
  if (id === "cleartext") return "A lab script, a legacy historian, or an old backup job can still send these secrets. The secret is on the wire either way; the intent is not in the packet.";
  if (id === "dns-tunnel") return "A long CDN or cloud-storage name can look random. A run of them under one parent is only a lead.";
  if (id.startsWith("beacon")) return "Update agents, time sync, and some vendor tunnels check in on a timer. Regular contact is not, by itself, an implant.";
  if (id.startsWith("exfil")) return "A planned backup or a vendor upload has the same shape as data leaving. Size is not proof of theft.";
  if (id.startsWith("external")) return "A public address may be a vendor, a patch server, or a mistake. It is not automatically a hostile server.";
  if (id === "smb-lateral") return "An administrator copying a tool to ADMIN$ or C$ looks the same as lateral movement. Ask who owns the account.";
  if (id === "brute-force") return "A script with the wrong saved password retries the same way an attack does.";
  if (id.startsWith("modbus") || id.startsWith("s7") || id.startsWith("iec") || id.startsWith("dnp3") || id.startsWith("bacnet") || id.startsWith("cip")) {
    return "Consistent with a maintenance download or an operator setpoint change. The capture shows the command, not whether a work order authorised it.";
  }
  if (id === "point-id") return "A commissioning tool mapping registers looks like a point sweep. Check whether engineering was on site.";
  if (id === "benign-polling") return "Steady polling is what a healthy plant looks like. It is recorded so the quiet case is explicit.";
  if (id.startsWith("new-writer")) return "Consistent with a maintenance download. 'New' means new in this file, not new in the life of the plant. This capture has no earlier baseline.";
  if (id.startsWith("first-engineering")) return "This is the first engineering-style session in this capture only. It may be the normal engineering laptop.";
  return "There is more than one ordinary explanation. The bytes are a lead for someone who knows the plant.";
}

function claimFor(id: string): ClaimStatus {
  // Titles that interpret intent stay "possible". Titles that restate a decoded field are "observed".
  if (id === "dns-tunnel" || id.startsWith("exfil") || id.startsWith("external") || id.startsWith("beacon")) return "possible";
  return "observed";
}

function confidenceFor(id: string): Confidence {
  if (id === "cleartext" || id.startsWith("modbus-write") || id === "s7-stop" || id === "smb-lateral") return "high";
  if (id === "dns-tunnel" || id.startsWith("beacon") || id.startsWith("exfil") || id.startsWith("new-writer")) return "medium";
  if (id.startsWith("first-engineering") || id.startsWith("polling-")) return "low";
  return "medium";
}

/** Fill the case fields without changing the wording or technique ids the 1.0.1 checks already use. */
export function decorateFinding(f: Finding, rows: Row[]): Finding {
  if (f.claimStatus && f.alternativeExplanation && f.engine) return f;
  return {
    ...f,
    engine: f.engine ?? "primer",
    ruleId: f.ruleId ?? "",
    confidence: f.confidence ?? confidenceFor(f.id),
    claimStatus: f.claimStatus ?? claimFor(f.id),
    alternativeExplanation: f.alternativeExplanation || altFor(f.id),
    validation: f.validation ?? "pending",
    validatedBy: f.validatedBy ?? "",
    validatedAt: f.validatedAt ?? null,
    techniqueSupport: "possible",
    ts: f.ts ?? earliest(f, rows),
  };
}

/**
 * Level 3 is not a property of one detector. It requires at least two independent
 * families and one high or critical finding. A lone Modbus write stays at 1 or 2.
 */
export function promoteTriage(findings: Finding[]): Finding[] {
  const loud = findings.filter((f) => f.severity !== "info" && familyOf(f.id) !== "baseline" && f.id !== "point-id");
  const families = new Set(loud.map((f) => familyOf(f.id)));
  const level3 = families.size >= 2 && loud.some((f) => f.severity === "high" || f.severity === "critical");
  return findings.map((f) => {
    let triage: TriageLevel = 1;
    if (f.severity !== "info" && familyOf(f.id) !== "baseline") {
      if (level3 && (f.severity === "high" || f.severity === "critical")) triage = 3;
      else if (f.severity === "low") triage = 1;
      else triage = 2;
    }
    return { ...f, triageLevel: triage };
  });
}

export function annotateFindings(findings: Finding[], rows: Row[]): Finding[] {
  return promoteTriage(findings.map((f) => decorateFinding(f, rows)));
}

export function caseTriage(findings: Finding[]): CaseTriage {
  const level = findings.reduce<TriageLevel>((acc, f) => (f.triageLevel && f.triageLevel > acc ? f.triageLevel : acc), 1);
  const families = [...new Set(findings.filter((f) => f.severity !== "info").map((f) => familyOf(f.id)))];
  const explanation =
    level === 3
      ? "Several independent checks line up. Together they are enough to open a formal investigation. They are not proof the controller was exploited."
      : level === 2
        ? "Something here is worth an investigator's time. Preserve the capture. One check on its own stays short of a formal incident."
        : "Something may be unusual, or the capture may simply be ordinary plant traffic. It may be maintenance, a misconfiguration, or a test.";
  return { level, name: TRIAGE_NAME[level], explanation, families };
}

function isWrite(row: Row): boolean {
  if (row.modbusFunc !== undefined && WRITE_FUNCS.has(row.modbusFunc) && row.sp !== 502) return true;
  if (row.s7Func === 0x05 || row.s7Func === 0x1a || row.s7Func === 0x1d || row.s7Func === 0x29 || row.s7Func === 0x28) return true;
  if (row.cipSvc !== undefined && [0x10, 0x4d, 0x53].includes(row.cipSvc)) return true;
  if (row.bacnetConfirmed && row.bacnetSvc === 15) return true;
  if (row.dnp3Func !== undefined && [3, 4, 5, 6].includes(row.dnp3Func)) return true;
  if (row.iecType !== undefined && row.iecType >= 45 && row.iecType <= 64) return true;
  return false;
}

function isRead(row: Row): boolean {
  return row.modbusFunc !== undefined && READ_FUNCS.has(row.modbusFunc) && row.sp !== 502;
}

function relationshipFindings(rows: Row[], assets: AssetRecord[]): Finding[] {
  const extra: Finding[] = [];
  const firstWriteAt = new Map<string, number>();
  const writers = new Map<string, Row[]>();
  for (const row of rows) {
    if (!isWrite(row)) continue;
    const key = `${row.src}|${row.dst}`;
    const list = writers.get(key) ?? [];
    list.push(row);
    writers.set(key, list);
    const prev = firstWriteAt.get(key);
    if (prev === undefined || row.ts < prev) firstWriteAt.set(key, row.ts);
  }
  // A read only counts as "this writer already polled" when it happened before the first write.
  const readBeforeWrite = new Set<string>();
  for (const row of rows) {
    if (!isRead(row)) continue;
    const key = `${row.src}|${row.dst}`;
    const first = firstWriteAt.get(key);
    if (first !== undefined && row.ts < first) readBeforeWrite.add(key);
  }
  for (const [key, list] of writers) {
    if (readBeforeWrite.has(key)) continue;
    const [src, dst] = key.split("|");
    const sample = list.slice(0, 12).map((r) => ({ n: r.n, detail: `${r.proto} ${r.info}` }));
    extra.push(decorateFinding({
      id: `new-writer:${key}`,
      title: `A new writer appeared: ${src} sent commands to ${dst}`,
      severity: "medium",
      summary: `${src} sent ${list.length} command or write packet${list.length === 1 ? "" : "s"} to ${dst} and did not poll that device earlier in this file.`,
      meaning: "The usual plant pattern is a poller that has been talking to the controller all along. A host that only appears when the writes start is worth a look. It can still be a technician who connected for a job.",
      action: "Ask operations who was logged into this address. Keep the capture. Do not call the write malicious until someone who knows the shift says it was not planned.",
      techniques: [],
      evidence: sample,
      evidenceCount: list.length,
    }, rows));
  }

  const ews = new Set(assets.filter((a) => a.role === "engineering_workstation").map((a) => a.ip));
  const plcs = new Set(assets.filter((a) => a.role === "plc").map((a) => a.ip));
  let first: Row | null = null;
  for (const row of rows) {
    if (!ews.has(row.src) || !plcs.has(row.dst)) continue;
    if (!OT_SERVER.has(row.dp) && !isWrite(row)) continue;
    if (!first || row.ts < first.ts) first = row;
  }
  if (first) {
    extra.push(decorateFinding({
      id: `first-engineering:${first.src}|${first.dst}`,
      title: `First engineering-style session in this capture (${first.src} to ${first.dst})`,
      severity: "info",
      summary: `Packet ${first.n} is the earliest industrial session from ${first.src} to ${first.dst} in this file.`,
      meaning: "Primer can only see this capture. 'First' means first here, not first in the plant's life.",
      action: "If you have a longer capture or a historian of sessions, compare it. On its own this is context, not an incident.",
      techniques: [],
      evidence: [{ n: first.n, detail: first.info }],
      evidenceCount: 1,
    }, rows));
  }
  return extra;
}

interface Acc {
  ip: string;
  mac: string;
  hostname: string;
  sent: number;
  got: number;
  serverPorts: Map<number, number>;
  clientPorts: Map<number, number>;
  writes: number;
  reads: number;
  publicTalk: boolean;
  first: number;
  last: number;
  evidence: Evidence[];
}

function touch(map: Map<string, Acc>, ip: string, ts: number): Acc {
  let acc = map.get(ip);
  if (!acc) {
    acc = {
      ip, mac: "", hostname: "", sent: 0, got: 0, serverPorts: new Map(), clientPorts: new Map(),
      writes: 0, reads: 0, publicTalk: false, first: ts, last: ts, evidence: [],
    };
    map.set(ip, acc);
  }
  if (ts < acc.first) acc.first = ts;
  if (ts > acc.last) acc.last = ts;
  return acc;
}

function roleOf(acc: Acc): { role: string; confidence: Confidence; hypothesis: string; alternate: string } {
  const serves = (port: number) => (acc.serverPorts.get(port) ?? 0) > 0;
  const industrialServer = [...OT_SERVER].some((port) => serves(port));
  const name = acc.hostname.toLowerCase();
  if (acc.writes > 0) {
    return {
      role: "engineering_workstation",
      confidence: acc.publicTalk ? "low" : "medium",
      hypothesis: "Likely an engineering workstation because it initiated industrial writes or programming commands.",
      alternate: acc.publicTalk
        ? "Could be a remote-access host. It also talked to a public address."
        : "Could be an HMI or a maintenance laptop rather than a permanent engineering seat.",
    };
  }
  if (industrialServer) {
    const why = serves(502)
      ? "other hosts speak Modbus to port 502 on this address and it does not start those conversations"
      : serves(102)
        ? "other hosts speak S7 to port 102 on this address and it does not start those conversations"
        : "other hosts speak an industrial protocol to a server port on this address and it does not start those conversations";
    const strong = (acc.serverPorts.get(502) ?? 0) + (acc.serverPorts.get(102) ?? 0) >= 3;
    return {
      role: "plc",
      confidence: strong ? "high" : "medium",
      hypothesis: `Likely a PLC because ${why}.`,
      alternate: "Could be a gateway or a protocol converter in front of the controller.",
    };
  }
  if (/scada/.test(name) || (acc.reads > 2 && acc.clientPorts.has(502))) {
    return {
      role: "scada",
      confidence: "medium",
      hypothesis: "Likely a SCADA server because it polls a controller and the name, where present, says scada.",
      alternate: "Could be an HMI doing the same polling.",
    };
  }
  if (/hist/.test(name) || (acc.serverPorts.get(80) ?? 0) > 0) {
    return {
      role: "historian",
      confidence: /hist/.test(name) ? "medium" : "low",
      hypothesis: "Likely a historian or a web server because it served HTTP or the captured name says historian.",
      alternate: "Could be an ordinary IT web server that happens to sit on the plant network.",
    };
  }
  if (/hmi/.test(name)) {
    return {
      role: "hmi",
      confidence: "low",
      hypothesis: "Likely an HMI because a name in the capture says so. A name is a claim the device made.",
      alternate: "Could be any PC that was given an HMI hostname.",
    };
  }
  if (/eng|ews|laptop/.test(name)) {
    return {
      role: "engineering_workstation",
      confidence: "low",
      hypothesis: "Likely an engineering workstation because a DHCP or DNS name looks like one. The name is not proof of the role.",
      alternate: "Could be an ordinary laptop on the same network.",
    };
  }
  if (acc.publicTalk) {
    return {
      role: "it_host",
      confidence: "low",
      hypothesis: "Likely an IT host because it exchanged packets with a public address.",
      alternate: "Could be a remote-access path into the plant.",
    };
  }
  if (acc.sent + acc.got > 0) {
    return {
      role: "unknown",
      confidence: "low",
      hypothesis: "No strong role. The address was seen, but the traffic does not say what the device is for.",
      alternate: "It could be almost any host that only spoke ordinary IT protocols in this window.",
    };
  }
  return {
    role: "unknown",
    confidence: "low",
    hypothesis: "No strong role.",
    alternate: "Not enough packets to say.",
  };
}

export function inferAssets(rows: Row[], names: Record<string, string>): AssetRecord[] {
  const map = new Map<string, Acc>();
  for (const row of rows) {
    if (!row.src || row.src.includes(":")) continue;
    const src = touch(map, row.src, row.ts);
    src.sent += 1;
    if (row.macSrc && !src.mac) src.mac = row.macSrc;
    if (OT_SERVER.has(row.dp)) src.clientPorts.set(row.dp, (src.clientPorts.get(row.dp) ?? 0) + 1);
    // A reply comes back from the service port to an ephemeral port. BACnet often uses 47808 on both sides, so that is not treated as a server.
    if (isWrite(row)) src.writes += 1;
    if (isRead(row)) src.reads += 1;
    if (isPublicUnicast(row.dst) || isPublicUnicast(row.src)) src.publicTalk = true;
    if (row.dhcpHost && row.src === row.dhcpIp) src.hostname = row.dhcpHost;
    if (src.evidence.length < 3) src.evidence.push({ n: row.n, detail: row.info || row.proto });
    if (row.dst && !row.dst.includes(":")) {
      const dst = touch(map, row.dst, row.ts);
      dst.got += 1;
      if (row.macDst && !dst.mac) dst.mac = row.macDst;
      // A host that is addressed on an industrial server port is acting as that service,
      // even when the capture did not include the reply.
      if (OT_SERVER.has(row.dp)) dst.serverPorts.set(row.dp, (dst.serverPorts.get(row.dp) ?? 0) + 1);
      if (OT_SERVER.has(row.sp) && row.dp > 1024 && !OT_SERVER.has(row.dp)) {
        src.serverPorts.set(row.sp, (src.serverPorts.get(row.sp) ?? 0) + 1);
      }
    }
  }
  for (const [ip, name] of Object.entries(names)) {
    const acc = map.get(ip);
    if (acc && name) acc.hostname = acc.hostname || name;
  }
  for (const row of rows) {
    if (row.dhcpHost) {
      const acc = row.dhcpIp ? map.get(row.dhcpIp) : map.get(row.src);
      if (acc && !acc.hostname) acc.hostname = row.dhcpHost;
    }
  }
  const assets: AssetRecord[] = [];
  for (const acc of map.values()) {
    if (!acc.ip || acc.sent + acc.got === 0) continue;
    const role = roleOf(acc);
    assets.push({
      id: `asset:${acc.ip}`,
      ip: acc.ip,
      mac: acc.mac,
      hostname: acc.hostname,
      role: role.role,
      confidence: role.confidence,
      hypothesis: role.hypothesis,
      alternateHypothesis: role.alternate,
      firstSeen: acc.first,
      lastSeen: acc.last,
      evidence: acc.evidence,
    });
  }
  const rank: Record<string, number> = { plc: 0, engineering_workstation: 1, scada: 2, hmi: 3, historian: 4, gateway: 5, remote_access: 6, it_host: 7, unknown: 8 };
  assets.sort((a, b) => (rank[a.role] ?? 9) - (rank[b.role] ?? 9) || a.ip.localeCompare(b.ip));
  return assets;
}

const KIND_FACT: Record<string, string> = {
  ttl: "IP time-to-live seen on the wire.",
  tcp_options: "TCP option list seen on the wire.",
  dhcp_vendor: "DHCP vendor class the device sent.",
  dhcp_hostname: "DHCP hostname the device claimed.",
  http_ua: "HTTP User-Agent the client sent.",
  smb_dialect: "SMB2 dialect named in a negotiate response.",
  tls_ja3: "TLS JA3 fingerprint supplied by TShark.",
  rdp_keyboard: "RDP keyboard-layout id supplied by TShark.",
};

export function inferFingerprints(rows: Row[]): FingerprintRecord[] {
  const out: FingerprintRecord[] = [];
  const seen = new Set<string>();
  const push = (ip: string, kind: string, value: string, packetN: number, hypothesis: string) => {
    if (!ip || !value) return;
    const key = `${ip}|${kind}|${value}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({
      id: `fp:${out.length + 1}`,
      ip,
      kind,
      value,
      packetN,
      observedFact: KIND_FACT[kind] ?? "Observed technical fact.",
      hypothesis,
      attributionNote: ATTRIBUTION_NOTE,
    });
  };
  for (const row of rows) {
    if (row.ttl) push(row.src, "ttl", String(row.ttl), row.n, "A starting TTL of 64, 128, or 255 is a common stack default. It does not identify a person or a country.");
    if (row.tcpOptions) push(row.src, "tcp_options", row.tcpOptions, row.n, "TCP options are a stack habit. They are not a signature of nationality.");
    if (row.dhcpVendor) push(row.src, "dhcp_vendor", row.dhcpVendor, row.n, "The device claimed this vendor class. A claim can be copied.");
    if (row.dhcpHost) push(row.dhcpIp || row.src, "dhcp_hostname", row.dhcpHost, row.n, "The device claimed this hostname. It is a label, not an identity card.");
    if (row.httpUa) push(row.src, "http_ua", row.httpUa, row.n, "The client sent this User-Agent. Software sets that string.");
    if (row.smbDialect) push(row.src, "smb_dialect", row.smbDialect, row.n, "The negotiate response named this SMB dialect.");
    if (row.tlsJa3) push(row.src, "tls_ja3", row.tlsJa3, row.n, "JA3 summarises a TLS client hello. Many unrelated programs share one.");
    if (row.rdpKeyboard) push(row.src, "rdp_keyboard", row.rdpKeyboard, row.n, "A keyboard-layout id is a software setting. It is not evidence of nationality or sponsorship.");
  }
  return out;
}

function serviceName(port: number, proto: string): string {
  const names: Record<number, string> = { 53: "dns", 80: "http", 443: "tls", 502: "modbus", 102: "s7", 445: "smb", 2404: "iec104", 4840: "opcua", 20000: "dnp3", 47808: "bacnet", 44818: "enip", 1883: "mqtt" };
  return names[port] ?? proto.toLowerCase();
}

export function zeekFrom(rows: Row[], analysis: Analysis): { connections: ZeekConn[]; weird: ZeekWeird[]; dns: Dossier["dns"]; http: Dossier["http"]; tls: Dossier["tls"]; files: Dossier["files"] } {
  const groups = new Map<string, ZeekConn>();
  for (const row of rows) {
    if (!row.src || !row.dst) continue;
    const flip = `${row.dst}|${row.src}|${row.dp}|${row.sp}|${row.proto}`;
    const key = `${row.src}|${row.dst}|${row.sp}|${row.dp}|${row.proto}`;
    const existing = groups.get(key) ?? groups.get(flip);
    if (existing) {
      existing.packets += 1;
      existing.bytes += row.len;
      if (row.ts < existing.start) existing.start = row.ts;
      if (row.ts > existing.end) existing.end = row.ts;
      continue;
    }
    groups.set(key, {
      src: row.src, dst: row.dst, sp: row.sp, dp: row.dp, proto: row.proto || "ip",
      packets: 1, bytes: row.len, start: row.ts, end: row.ts,
      service: serviceName(row.dp, row.proto),
    });
  }
  const weird: ZeekWeird[] = [];
  const seqs = new Map<string, number>();
  for (const row of rows) {
    if (/truncat/i.test(row.info)) weird.push({ packetN: row.n, name: "truncated", detail: row.info });
    if (row.tcpSeq && row.appLen > 0) {
      const key = `${row.src}|${row.dst}|${row.sp}|${row.dp}|${row.tcpSeq}|${row.appLen}`;
      const prev = seqs.get(key) ?? 0;
      seqs.set(key, prev + 1);
      if (prev === 1) weird.push({ packetN: row.n, name: "possible_retransmit", detail: `Same TCP sequence ${row.tcpSeq} seen again` });
    }
  }
  return {
    connections: [...groups.values()].sort((a, b) => b.bytes - a.bytes).slice(0, 500),
    weird: weird.slice(0, 100),
    dns: analysis.dns.map((d) => ({ n: d.n, src: d.src, name: d.name, answer: d.answer })),
    http: analysis.http.map((h) => ({ n: h.n, src: h.src, host: h.host, method: h.method, path: h.path })),
    tls: analysis.tls.map((t) => ({ n: t.n, src: t.src, dst: t.dst, sni: t.sni })),
    files: analysis.files.map((f) => ({ n: f.n, name: f.name, type: f.type, size: f.size })),
  };
}

export function otWorksheet(rows: Row[]): OtRow[] {
  const out: OtRow[] = [];
  for (const row of rows) {
    let direction: OtRow["direction"] = "other";
    let operation = "";
    let address = "";
    let protocol = "";
    if (row.modbusFunc !== undefined) {
      protocol = "Modbus";
      operation = `function ${row.modbusFunc}`;
      address = row.modbusAddr !== undefined ? String(row.modbusAddr) : "";
      direction = WRITE_FUNCS.has(row.modbusFunc) ? "write" : READ_FUNCS.has(row.modbusFunc) ? "read" : "other";
    } else if (row.s7Func !== undefined) {
      protocol = "S7comm";
      operation = `function 0x${row.s7Func.toString(16)}${row.s7Pi ? " " + row.s7Pi : ""}`;
      direction = "command";
    } else if (row.iecType !== undefined) {
      protocol = "IEC 104";
      operation = `type ${row.iecType}`;
      direction = row.iecType >= 45 && row.iecType <= 64 ? "command" : "other";
    } else if (row.dnp3Func !== undefined) {
      protocol = "DNP3";
      operation = `function ${row.dnp3Func}`;
      direction = [3, 4, 5, 6].includes(row.dnp3Func) ? "command" : "other";
    } else if (row.bacnetSvc !== undefined) {
      protocol = "BACnet";
      operation = `service ${row.bacnetSvc}`;
      direction = row.bacnetSvc === 15 ? "write" : "other";
    } else if (row.cipSvc !== undefined || row.enipCmd !== undefined) {
      protocol = "EtherNet/IP";
      operation = row.cipSvc !== undefined ? `CIP service 0x${row.cipSvc.toString(16)}` : `command ${row.enipCmd}`;
      direction = row.cipSvc !== undefined && [0x10, 0x4d, 0x53].includes(row.cipSvc) ? "write" : "other";
    } else continue;
    out.push({ n: row.n, ts: row.ts, src: row.src, dst: row.dst, protocol, operation, address, direction });
  }
  return out;
}

export function buildDossier(rows: Row[], analysis: Analysis): Dossier {
  const assets = inferAssets(rows, analysis.names);
  const base = analysis.findings.map((f) => decorateFinding(f, rows));
  const findings = promoteTriage([...base, ...relationshipFindings(rows, assets)]);
  const zeek = zeekFrom(rows, analysis);
  return {
    findings,
    assets,
    fingerprints: inferFingerprints(rows),
    connections: zeek.connections,
    weird: zeek.weird,
    dns: zeek.dns,
    http: zeek.http,
    tls: zeek.tls,
    files: zeek.files,
    otRows: otWorksheet(rows),
    triage: caseTriage(findings),
    gaps: CASE_GAPS,
  };
}

export function applyDecision(findings: Finding[], log: ActivityEntry[], decision: AnalystDecision): { findings: Finding[]; log: ActivityEntry[] } {
  const next = findings.map((f) => f.id === decision.findingId
    ? { ...f, validation: decision.validation, validatedBy: decision.actor, validatedAt: decision.at }
    : f);
  const entry: ActivityEntry = {
    at: decision.at,
    actor: decision.actor,
    action: decision.validation,
    detail: `${decision.findingId}${decision.note ? `: ${decision.note}` : ""}`,
  };
  return { findings: next, log: [...log, entry] };
}

export type FindingFilter = "ot" | "signatures" | "all";

/** OT view hides signature-only hits so a large ruleset cannot bury a Modbus write. */
export function visibleFindings(findings: Finding[], mode: FindingFilter): Finding[] {
  if (mode === "all") return findings;
  if (mode === "signatures") return findings.filter((f) => f.engine === "suricata" || f.engine === "correlation");
  return findings.filter((f) => f.engine !== "suricata");
}

export function roleLabel(role: string): string {
  const labels: Record<string, string> = {
    plc: "PLC",
    hmi: "HMI",
    engineering_workstation: "engineering workstation",
    scada: "SCADA server",
    historian: "historian",
    gateway: "industrial gateway",
    remote_access: "remote access host",
    it_host: "IT host",
    unknown: "unknown",
  };
  return labels[role] ?? role;
}
