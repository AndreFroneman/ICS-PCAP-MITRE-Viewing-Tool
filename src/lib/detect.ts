import { shannon } from "./bytes.ts";
import { annotateFindings } from "./forensic.ts";
import { isInternal, isPublicUnicast } from "./ip.ts";
import type { Finding, LegacyTechnique, Row, Severity } from "./model.ts";
import { Bit } from "./model.ts";

const OT_PORTS = new Set([102, 502, 1883, 2404, 4840, 20000, 2222, 44818, 47808]);
const IEC_COMMANDS = new Set([45, 46, 47, 48, 49, 50, 51, 58, 59, 60, 61, 62, 63, 64]);
const WRITE_FUNCS = new Set([5, 6, 15, 16, 22, 23]);
const READ_FUNCS = new Set([1, 2, 3, 4]);
const OT_BITS = Bit.modbus | Bit.s7 | Bit.dnp3 | Bit.enip | Bit.bacnet | Bit.iec | Bit.opcua | Bit.mqtt;

const LEGACY_COMMAND: LegacyTechnique[] = [{ id: "T0855", replacedBy: "T1692.001" }];

export function detect(rows: Row[]): Finding[] {
  const findings: Finding[] = [];
  findings.push(...portScans(rows));
  const creds = cleartext(rows);
  if (creds) findings.push(creds);
  const tunnel = dnsTunnel(rows);
  if (tunnel) findings.push(tunnel);
  findings.push(...beacons(rows));
  const smb = smbLateral(rows);
  if (smb) findings.push(smb);
  const brute = bruteForce(rows);
  if (brute) findings.push(brute);
  findings.push(...externals(rows));
  findings.push(...exfil(rows));
  const writes = modbusWrites(rows);
  if (writes) findings.push(writes);
  const io = modbusIoBrute(rows);
  if (io) findings.push(io);
  const stop = s7Stop(rows);
  if (stop) findings.push(stop);
  const down = s7Transfer(rows, "down");
  if (down) findings.push(down);
  const up = s7Transfer(rows, "up");
  if (up) findings.push(up);
  const iec = iecCommands(rows);
  if (iec) findings.push(iec);
  const dnp = dnpOperate(rows);
  if (dnp) findings.push(dnp);
  const bac = bacnetWrites(rows);
  if (bac) findings.push(bac);
  const cip = cipWrites(rows);
  if (cip) findings.push(cip);
  const points = pointId(rows);
  if (points) findings.push(points);
  const suspicious = findings.some((f) => f.severity !== "info");
  if (!suspicious) {
    const calm = calmPolling(rows);
    if (calm) findings.push(calm);
  }
  const rank: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  findings.sort((a, b) => rank[b.severity] - rank[a.severity]);
  // Labels (observed / possible, triage, alternative) sit on the same objects the tests already know.
  return annotateFindings(findings, rows);
}

function cap(rows: Row[], detail: (r: Row) => string, limit = 24): { evidence: { n: number; detail: string }[]; count: number } {
  return {
    count: rows.length,
    evidence: rows.slice(0, limit).map((r) => ({ n: r.n, detail: detail(r) })),
  };
}

function has(mask: number, row: Row): boolean {
  return (row.layers & mask) !== 0;
}

function otPeers(rows: Row[]): Set<string> {
  const s = new Set<string>();
  for (const r of rows) {
    if (has(OT_BITS, r) || OT_PORTS.has(r.sp) || OT_PORTS.has(r.dp)) {
      if (r.src) s.add(r.src);
      if (r.dst) s.add(r.dst);
    }
  }
  return s;
}

function portScans(rows: Row[]): Finding[] {
  const syn = new Map<string, Map<string, Set<number>>>();
  const answered = new Map<string, Set<number>>();
  const evidenceRows = new Map<string, Row[]>();
  for (const r of rows) {
    if (!has(Bit.tcp, r)) continue;
    const synOnly = (r.tcpFlags & 0x02) !== 0 && (r.tcpFlags & 0x10) === 0;
    const synAck = (r.tcpFlags & 0x12) === 0x12;
    if (synOnly) {
      const byDst = syn.get(r.src) ?? new Map<string, Set<number>>();
      const ports = byDst.get(r.dst) ?? new Set<number>();
      ports.add(r.dp);
      byDst.set(r.dst, ports);
      syn.set(r.src, byDst);
      const key = `${r.src}|${r.dst}`;
      const list = evidenceRows.get(key) ?? [];
      list.push(r);
      evidenceRows.set(key, list);
    } else if (synAck) {
      const key = `${r.dst}|${r.src}`;
      const set = answered.get(key) ?? new Set<number>();
      set.add(r.sp);
      answered.set(key, set);
    }
  }
  const out: Finding[] = [];
  for (const [src, byDst] of syn) {
    const targets: string[] = [];
    const ev: Row[] = [];
    let ot = false;
    for (const [dst, ports] of byDst) {
      const done = answered.get(`${src}|${dst}`) ?? new Set<number>();
      const open = [...ports].filter((p) => !done.has(p));
      if (open.length >= 12) {
        targets.push(`${dst} (${open.length} ports)`);
        if (open.some((p) => OT_PORTS.has(p))) ot = true;
        ev.push(...(evidenceRows.get(`${src}|${dst}`) ?? []).filter((r) => open.includes(r.dp)));
      }
    }
    if (!targets.length) continue;
    const sliced = cap(ev, (r) => `SYN ${r.src} → ${r.dst}:${r.dp}`);
    out.push({
      id: `port-scan:${src}`,
      title: `Port scan from ${src}`,
      severity: "high",
      summary: `${src} sent SYN packets to many ports that never completed a handshake: ${targets.join("; ")}.`,
      meaning: "A port scan is someone knocking on many doors to see which services answer. Inventory tools do this on purpose. So do intruders, right before they pick a service to try. On a plant network the interesting doors are the industrial ones: 502 Modbus, 102 S7, 44818 EtherNet/IP, 2404 IEC 104, 20000 DNP3, 47808 BACnet, 4840 OPC UA.",
      action: "Confirm whether this host is an approved scanner or engineering laptop. If nobody scheduled a scan, isolate the host from the OT network, keep this capture, and check what it talked to after the scan.",
      techniques: ot ? ["T1046", "T0846.001"] : ["T1046"],
      ...sliced,
      evidence: sliced.evidence,
      evidenceCount: sliced.count,
    });
  }
  return out;
}

function cleartext(rows: Row[]): Finding | null {
  const hits = rows.filter((r) => r.ftpCmd === "PASS" || r.httpAuth || r.smtpAuth || r.mqttPass);
  if (!hits.length) return null;
  const secrets = new Set<string>();
  for (const r of hits) {
    if (r.ftpCmd === "PASS" && r.ftpArg) secrets.add(`FTP ${r.ftpArg} (packet ${r.n})`);
    if (r.httpAuth) secrets.add(`HTTP Basic ${r.httpAuth} (packet ${r.n})`);
    if (r.smtpAuth) secrets.add(`SMTP ${r.smtpAuth} (packet ${r.n})`);
    if (r.mqttPass) secrets.add(`MQTT ${r.mqttUser ?? "user"} / ${r.mqttPass} (packet ${r.n})`);
  }
  const techniques = ["T1040", "T0842"];
  if (hits.some((r) => r.mqttPass)) techniques.push("T0859", "T0869");
  const sliced = cap(hits, (r) => {
    if (r.ftpCmd === "PASS") return `FTP password visible from ${r.src} to ${r.dst}`;
    if (r.httpAuth) return `HTTP Basic credentials ${r.httpAuth}`;
    if (r.smtpAuth) return `SMTP AUTH ${r.smtpAuth}`;
    return `MQTT password for ${r.mqttUser ?? "a user"}`;
  });
  return {
    id: "cleartext",
    title: "Passwords crossed the network in the clear",
    severity: "high",
    summary: `${hits.length} packet${hits.length === 1 ? "" : "s"} carried a password or authentication secret that was not encrypted. Visible secrets: ${[...secrets].join("; ")}.`,
    meaning: "Encoding such as base64 is not encryption. Anyone who can see this traffic — a span port, a compromised switch, a laptop on the same segment — can read these secrets. On an OT network that often includes shared engineering passwords.",
    action: "Treat the exposed secrets as burned: rotate them, then move the service to an encrypted protocol (SSH or SFTP instead of FTP, HTTPS instead of HTTP Basic, TLS-wrapped MQTT, authenticated mail). While you do that, find out whether this login was expected.",
    techniques,
    ...sliced,
    evidence: sliced.evidence,
    evidenceCount: sliced.count,
  };
}

function dnsTunnel(rows: Row[]): Finding | null {
  const suspicious = rows.filter((r) => r.dnsQ && isTunnelName(r.dnsQ));
  if (!suspicious.length) return null;
  const byParent = new Map<string, Row[]>();
  for (const r of suspicious) {
    const parent = parentName(r.dnsQ ?? "");
    const list = byParent.get(parent) ?? [];
    list.push(r);
    byParent.set(parent, list);
  }
  const groups = [...byParent.entries()].filter(([, list]) => list.length >= 3 || list.some((r) => (r.dnsQ ?? "").length >= 90));
  if (!groups.length) return null;
  const ev = groups.flatMap(([, list]) => list);
  const sliced = cap(ev, (r) => r.dnsQ ?? "");
  const names = groups.map(([p, list]) => `${list.length} long queries under ${p}`).join("; ");
  return {
    id: "dns-tunnel",
    title: "DNS queries look like a tunnel",
    severity: "high",
    summary: `${names}. The labels are long and high-entropy, which is what data looks like when it is hidden inside DNS names.`,
    meaning: "DNS is often allowed out even when other traffic is not. A tunnel encodes stolen data, or commands, as the hostname itself. One long CDN name is usually nothing. A run of random-looking names under the same parent is a lead.",
    action: "Look up the parent domain. If it is not a service you use, block it at the resolver and find the internal host that asked (the source of these packets). Keep the queries; they sometimes decode back into the stolen bytes.",
    techniques: ["T1071.004", "T0869.001"],
    ...sliced,
    evidence: sliced.evidence,
    evidenceCount: sliced.count,
  };
}

function isTunnelName(name: string): boolean {
  const labels = name.split(".").filter(Boolean);
  if (labels.length < 3) return false;
  const prefix = labels.slice(0, -2).join("");
  if (prefix.length < 40) return false;
  return shannon(prefix) >= 3.5;
}

function parentName(name: string): string {
  const labels = name.split(".").filter(Boolean);
  return labels.slice(-2).join(".") || name;
}

function beacons(rows: Row[]): Finding[] {
  const groups = new Map<string, number[]>();
  const sample = new Map<string, Row>();
  for (const r of rows) {
    if (!has(Bit.tcp, r)) continue;
    if (!isInternal(r.src) || !isPublicUnicast(r.dst)) continue;
    if (r.dp === 53) continue;
    const key = `${r.src}|${r.dst}|${r.dp}`;
    const list = groups.get(key) ?? [];
    list.push(r.ts);
    groups.set(key, list);
    if (!sample.has(key)) sample.set(key, r);
  }
  const out: Finding[] = [];
  for (const [key, times] of groups) {
    const clusters = cluster(times, 1);
    if (clusters.length < 8) continue;
    const deltas: number[] = [];
    for (let i = 1; i < clusters.length; i++) deltas.push(clusters[i] - clusters[i - 1]);
    const mean = deltas.reduce((a, b) => a + b, 0) / deltas.length;
    if (mean < 5 || mean > 3600) continue;
    const variance = deltas.reduce((a, b) => a + (b - mean) ** 2, 0) / deltas.length;
    const cv = Math.sqrt(variance) / mean;
    if (cv > 0.2) continue;
    const [src, dst, port] = key.split("|");
    const row = sample.get(key);
    out.push({
      id: `beacon:${key}`,
      title: `Regular connections from ${src} to ${dst}`,
      severity: "high",
      summary: `${src} contacted ${dst}:${port} ${clusters.length} times, about every ${mean.toFixed(0)} seconds, with very little jitter.`,
      meaning: "Implants check in on a timer. So do some update agents and NTP. The difference is where it goes and whether anyone installed it. A steady beat to a public address, especially from a host that also touches PLCs, is a command-and-control lead. Ordinary Modbus polling was ignored here because it stays inside the plant.",
      action: "Identify the process on the internal host that owns this connection. If it is not an approved remote service, take the host off the network and look at what else it talked to in this capture.",
      techniques: ["T1071", "T0869", "T0885"],
      evidence: row ? [{ n: row.n, detail: `One of the regular packets to ${dst}:${port}` }] : [],
      evidenceCount: clusters.length,
    });
  }
  return out;
}

function cluster(times: number[], gap: number): number[] {
  const sorted = [...times].sort((a, b) => a - b);
  const out: number[] = [];
  for (const t of sorted) {
    if (!out.length || t - out[out.length - 1] > gap) out.push(t);
  }
  return out;
}

function smbLateral(rows: Row[]): Finding | null {
  const hits = rows.filter((r) => /ADMIN\$|C\$/i.test(r.smbPath ?? ""));
  if (!hits.length) return null;
  const users = [...new Set(rows.map((r) => r.smbUser).filter(Boolean))];
  const sliced = cap(hits, (r) => `${r.src} → ${r.dst} ${r.smbPath}`);
  return {
    id: "smb-lateral",
    title: "SMB connection to an admin share",
    severity: "high",
    summary: `A client opened ${hits.map((r) => r.smbPath).join(", ")}${users.length ? `. NTLM account name visible: ${users.join(", ")}.` : ""}`,
    meaning: "ADMIN$ and C$ are the shares Windows admins use to reach another machine's disk. Attackers use the same shares to run tools and move sideways. IPC$ alone is too common to call out; these shares are not.",
    action: "Confirm the account is an admin doing planned work. If the source is a surprise, reset that account, check the target host for new services or scheduled tasks, and see whether the same source shows up in other findings.",
    techniques: ["T1021.002"],
    ...sliced,
    evidence: sliced.evidence,
    evidenceCount: sliced.count,
  };
}

function bruteForce(rows: Row[]): Finding | null {
  const ftp = new Map<string, Row[]>();
  const ssh = new Map<string, Row[]>();
  const http = new Map<string, Row[]>();
  for (const r of rows) {
    if (r.ftpCmd === "PASS") {
      const k = `${r.src}|${r.dst}`;
      const list = ftp.get(k) ?? [];
      list.push(r);
      ftp.set(k, list);
    }
    if (r.dp === 22 && (r.sshBanner || ((r.tcpFlags & 0x02) !== 0 && (r.tcpFlags & 0x10) === 0))) {
      const k = `${r.src}|${r.dst}`;
      const list = ssh.get(k) ?? [];
      list.push(r);
      ssh.set(k, list);
    }
    if (r.httpStatus === 401) {
      const k = `${r.dst}|${r.src}`;
      const list = http.get(k) ?? [];
      list.push(r);
      http.set(k, list);
    }
  }
  const ev: Row[] = [];
  const bits: string[] = [];
  for (const [k, list] of ftp) if (list.length >= 6) {
    bits.push(`${list.length} FTP password attempts ${k.replace("|", " → ")}`);
    ev.push(...list);
  }
  for (const [k, list] of ssh) if (list.length >= 6) {
    bits.push(`${list.length} SSH connection attempts ${k.replace("|", " → ")}`);
    ev.push(...list);
  }
  for (const [k, list] of http) if (list.length >= 6) {
    bits.push(`${list.length} HTTP 401 replies ${k.replace("|", " → ")}`);
    ev.push(...list);
  }
  if (!bits.length) return null;
  const sliced = cap(ev, (r) => r.info);
  return {
    id: "brute-force",
    title: "Repeated logon attempts",
    severity: "high",
    summary: bits.join(". ") + ".",
    meaning: "A handful of failures is a person typing. A run of them is guessing. The account that eventually works, if any, should be treated as exposed even when a later packet shows a success.",
    action: "Lock or watch the targeted accounts, turn on rate limits, and prefer key or certificate logon for engineering access. Check whether any attempt succeeded later in the capture.",
    techniques: ["T1110"],
    ...sliced,
    evidence: sliced.evidence,
    evidenceCount: sliced.count,
  };
}

function externals(rows: Row[]): Finding[] {
  const peers = otPeers(rows);
  const groups = new Map<string, Row[]>();
  for (const r of rows) {
    if (!isInternal(r.src) || !isPublicUnicast(r.dst)) continue;
    if (has(Bit.dns, r) || r.dp === 53 || r.sp === 53) continue;
    const key = `${r.src}|${r.dst}`;
    const list = groups.get(key) ?? [];
    list.push(r);
    groups.set(key, list);
  }
  const out: Finding[] = [];
  for (const [key, list] of groups) {
    const [src, dst] = key.split("|");
    const ot = peers.has(src) || peers.has(dst);
    const sliced = cap(list, (r) => `${r.proto} ${r.src}:${r.sp || "–"} → ${r.dst}:${r.dp || "–"}`);
    out.push({
      id: `external:${key}`,
      title: ot ? `Plant host ${src} talked to a public address` : `Internal host ${src} talked to a public address`,
      severity: ot ? "high" : "medium",
      summary: `${src} exchanged ${list.length} packet${list.length === 1 ? "" : "s"} with ${dst}, which is not a private address.`,
      meaning: ot
        ? "A host that also speaks an industrial protocol, or was scanned as one, reached a public IP. PLCs, HMIs, and engineering stations usually should not. This can be command and control, a vendor cloud tool, or a misrouted session."
        : "Traffic leaving the plant LAN toward the public internet is worth naming, even when the host is an ordinary PC. DNS lookups are not counted here.",
      action: "Check whether this destination is an approved vendor, update service, or historian mirror. If it is not, block it and inspect the internal host. Compare the time with the other findings.",
      techniques: ot ? ["T1071", "T0869", "T0885"] : ["T1071"],
      ...sliced,
      evidence: sliced.evidence,
      evidenceCount: sliced.count,
    });
  }
  return out.slice(0, 12);
}

function exfil(rows: Row[]): Finding[] {
  const beaconDsts = new Set<string>();
  const times = new Map<string, number[]>();
  for (const r of rows) {
    if (!has(Bit.tcp, r) || !isInternal(r.src) || !isPublicUnicast(r.dst) || r.dp === 53) continue;
    const key = `${r.src}|${r.dst}|${r.dp}`;
    const list = times.get(key) ?? [];
    list.push(r.ts);
    times.set(key, list);
  }
  for (const [key, list] of times) {
    const clusters = cluster(list, 1);
    if (clusters.length >= 8) beaconDsts.add(key.split("|")[1]);
  }
  const volumes = new Map<string, { bytes: number; rows: Row[] }>();
  for (const r of rows) {
    if (!isInternal(r.src) || !isPublicUnicast(r.dst)) continue;
    if (r.appLen <= 0) continue;
    const key = `${r.src}|${r.dst}`;
    const cur = volumes.get(key) ?? { bytes: 0, rows: [] };
    cur.bytes += r.appLen;
    cur.rows.push(r);
    volumes.set(key, cur);
  }
  const out: Finding[] = [];
  for (const [key, vol] of volumes) {
    if (vol.bytes < 40_000) continue;
    const [src, dst] = key.split("|");
    const overC2 = beaconDsts.has(dst);
    const sliced = cap(vol.rows, (r) => `${r.appLen} bytes to ${r.dst}:${r.dp}`);
    out.push({
      id: `exfil:${key}`,
      title: `Large upload from ${src} to ${dst}`,
      severity: "high",
      summary: `${src} sent about ${(vol.bytes / 1024).toFixed(0)} KB of payload to ${dst}.`,
      meaning: overC2
        ? "The same public host also received regular check-ins. A bulky upload to a host you are already beaconing is the shape of data leaving over a command channel."
        : "A large outbound transfer to a public host can be a backup, a vendor upload, or data leaving the plant. Size alone is not proof. Direction and destination are the clues.",
      action: "Find the files or tags that moved. If this was not a planned upload, assume the data is compromised, preserve the capture, and block the destination.",
      techniques: overC2 ? ["T1041", "T1048.003"] : ["T1048.003"],
      ...sliced,
      evidence: sliced.evidence,
      evidenceCount: sliced.count,
    });
  }
  return out;
}

function modbusWrites(rows: Row[]): Finding | null {
  const hits = rows.filter((r) => r.modbusFunc !== undefined && WRITE_FUNCS.has(r.modbusFunc) && r.sp !== 502);
  if (!hits.length) return null;
  const sliced = cap(hits, (r) => `Unit ${r.modbusUnit ?? "?"} function ${r.modbusFunc} address ${r.modbusAddr ?? "?"} from ${r.src} to ${r.dst}`);
  return {
    id: "modbus-write",
    title: "Modbus write to a controller",
    severity: "high",
    summary: `${hits.length} Modbus write${hits.length === 1 ? "" : "s"} asked a device to change coils or holding registers.`,
    meaning: "A read is a question. A write is a change: a setpoint, a forced coil, a block of registers. HMIs do this when an operator acts. So does anyone else who can speak Modbus to the PLC. ATT&CK called this pattern Unauthorized Command Message (T0855) until version 20, when that entry was revoked and replaced by Command Message (T1692.001). Changing the value itself is Modify Parameter (T0836).",
    action: "Ask operations whether someone changed a setpoint at this time. If not, treat the source address as hostile to the process, snapshot the PLC, and stop further writes from that host.",
    techniques: ["T0836", "T1692.001"],
    legacy: LEGACY_COMMAND,
    ...sliced,
    evidence: sliced.evidence,
    evidenceCount: sliced.count,
  };
}

function modbusIoBrute(rows: Row[]): Finding | null {
  const hits = rows.filter((r) => r.modbusFunc !== undefined && WRITE_FUNCS.has(r.modbusFunc) && r.sp !== 502);
  if (hits.length < 10) return null;
  const sliced = cap(hits, (r) => r.info);
  return {
    id: "modbus-io-brute",
    title: "Repeated Modbus writes",
    severity: "high",
    summary: `${hits.length} writes landed in a short capture. That is more like forcing outputs than like an operator tapping a screen.`,
    meaning: "Brute Force I/O is the idea of walking values, or hammering one point, until the process does something. A single setpoint change is a different finding. This one is the repetition.",
    action: "Trend the points that were written. If the process moved and nobody commanded it, you are in an incident. Freeze writes from the source and pull the PLC event log if it has one.",
    techniques: ["T0806", "T0836"],
    ...sliced,
    evidence: sliced.evidence,
    evidenceCount: sliced.count,
  };
}

function s7Stop(rows: Row[]): Finding | null {
  const hits = rows.filter((r) => r.s7Func === 0x29 || (r.s7Func === 0x28 && /stop/i.test(r.s7Pi ?? "")));
  if (!hits.length) return null;
  const sliced = cap(hits, (r) => `${r.src} → ${r.dst} ${r.info}`);
  return {
    id: "s7-stop",
    title: "S7 message asked a PLC to stop",
    severity: "critical",
    summary: "A Siemens S7 job carried a PLC Stop (or a PI-Service naming a stop). The CPU was asked to leave RUN.",
    meaning: "Stopping the CPU stops the process logic. Maintenance does this on purpose, from a known engineering station, in a window. The same message from anywhere else is an incident. Service Stop (T0881) and Device Restart/Shutdown (T0816) are the ATT&CK names for taking a controller's job away.",
    action: "Confirm with the control room immediately. If this was not planned, isolate the sender, keep the PLC offline until its program and mode are verified, and start the site incident process.",
    techniques: ["T0881", "T0816"],
    ...sliced,
    evidence: sliced.evidence,
    evidenceCount: sliced.count,
  };
}

function s7Transfer(rows: Row[], dir: "down" | "up"): Finding | null {
  const funcs = dir === "down" ? new Set([0x1a, 0x1b, 0x1c]) : new Set([0x1d, 0x1e, 0x1f]);
  const hits = rows.filter((r) => r.s7Func !== undefined && funcs.has(r.s7Func));
  if (!hits.length) return null;
  const sliced = cap(hits, (r) => r.info);
  if (dir === "down") {
    return {
      id: "s7-download",
      title: "S7 program download",
      severity: "critical",
      summary: "An engineering session started a program download toward a Siemens PLC.",
      meaning: "Program download replaces or extends the logic the controller runs. That is how a project is commissioned, and how a controller is quietly reprogrammed.",
      action: "Match this to a change request. If there is no change window, pull the current blocks off the PLC with a trusted laptop and compare them to the last known project. Do not keep downloading from the source in this capture.",
      techniques: ["T0843"],
      ...sliced,
      evidence: sliced.evidence,
      evidenceCount: sliced.count,
    };
  }
  return {
    id: "s7-upload",
    title: "S7 program upload",
    severity: "high",
    summary: "An engineering session started uploading program blocks from a Siemens PLC.",
    meaning: "Program upload copies the controller's logic out. Engineers do it to back up a project. An attacker does it to learn the process, or to modify the copy and write it back.",
    action: "Confirm who uploaded, and where the project file went. If the source is unknown, treat the program as exposed and review whether a download followed.",
    techniques: ["T0845"],
    ...sliced,
    evidence: sliced.evidence,
    evidenceCount: sliced.count,
  };
}

function iecCommands(rows: Row[]): Finding | null {
  const hits = rows.filter((r) => r.iecType !== undefined && IEC_COMMANDS.has(r.iecType));
  if (!hits.length) return null;
  const sliced = cap(hits, (r) => r.info);
  return {
    id: "iec-command",
    title: "IEC 104 command or setpoint",
    severity: "high",
    summary: `${hits.length} IEC 60870-5-104 information object${hits.length === 1 ? "" : "s"} carried a command or a setpoint, not a measurement.`,
    meaning: "General interrogation (type 100) only asks for the current picture. Types 45–64 tell the station to switch, step, or adopt a value. That is a command message. The old ATT&CK id T0855 was revoked and replaced by T1692.001.",
    action: "Check the control room log for the same timestamp. If the command was not an operator action, the master that sent it is the thing to isolate.",
    techniques: ["T1692.001", "T0836"],
    legacy: LEGACY_COMMAND,
    ...sliced,
    evidence: sliced.evidence,
    evidenceCount: sliced.count,
  };
}

function dnpOperate(rows: Row[]): Finding | null {
  const hits = rows.filter((r) => r.dnp3Func !== undefined && [3, 4, 5, 6].includes(r.dnp3Func));
  if (!hits.length) return null;
  const sliced = cap(hits, (r) => r.info);
  return {
    id: "dnp3-operate",
    title: "DNP3 select or operate",
    severity: "high",
    summary: "A DNP3 master sent select, operate, or direct operate. That path drives outputs.",
    meaning: "DNP3 separates a polite read from an operate. Operate is the command. Direct operate skips the select step. Either one can move equipment if the outstation accepts it.",
    action: "Confirm the master address is the real SCADA, and that an operator action matches the time. Otherwise block that master and check the outstation's points.",
    techniques: ["T1692.001", "T0836"],
    legacy: LEGACY_COMMAND,
    ...sliced,
    evidence: sliced.evidence,
    evidenceCount: sliced.count,
  };
}

function bacnetWrites(rows: Row[]): Finding | null {
  const hits = rows.filter((r) => r.bacnetConfirmed && r.bacnetSvc === 15);
  if (!hits.length) return null;
  const sliced = cap(hits, (r) => `${r.src} → ${r.dst} WriteProperty`);
  return {
    id: "bacnet-write",
    title: "BACnet WriteProperty",
    severity: "high",
    summary: "A BACnet client wrote a property. That can change a setpoint, schedule, or binary output.",
    meaning: "Who-Is and ReadProperty are how a building system learns and polls. WriteProperty is how it changes something. On a plant or building network, an unexpected writer is a command you did not ask for.",
    action: "See which device was written and whether the building or process moved. If the client is not the BMS, remove it from the BACnet network.",
    techniques: ["T1692.001", "T0836"],
    legacy: LEGACY_COMMAND,
    ...sliced,
    evidence: sliced.evidence,
    evidenceCount: sliced.count,
  };
}

function cipWrites(rows: Row[]): Finding | null {
  const hits = rows.filter((r) => r.cipSvc !== undefined && [0x10, 0x4d, 0x53].includes(r.cipSvc));
  if (!hits.length) return null;
  const sliced = cap(hits, (r) => r.info);
  return {
    id: "cip-write",
    title: "EtherNet/IP CIP write",
    severity: "high",
    summary: "A CIP service wrote a tag or attribute. On a Logix-style controller that changes live data.",
    meaning: "Read Tag is polling. Write Tag and Set Attribute are edits. They sit in the same family as other unauthorized or unexpected command messages.",
    action: "Match the write to an HMI or engineering action. If nothing lines up, block the client and compare the controller's tag values with the last good backup.",
    techniques: ["T1692.001", "T0836"],
    legacy: LEGACY_COMMAND,
    ...sliced,
    evidence: sliced.evidence,
    evidenceCount: sliced.count,
  };
}

function pointId(rows: Row[]): Finding | null {
  const groups = new Map<string, { addrs: Set<number>; units: Set<number>; rows: Row[] }>();
  for (const r of rows) {
    if (r.modbusFunc === undefined || !READ_FUNCS.has(r.modbusFunc) || r.sp === 502) continue;
    if (r.modbusAddr === undefined) continue;
    const key = `${r.src}|${r.dst}`;
    const g = groups.get(key) ?? { addrs: new Set<number>(), units: new Set<number>(), rows: [] };
    g.addrs.add(r.modbusAddr);
    if (r.modbusUnit !== undefined) g.units.add(r.modbusUnit);
    g.rows.push(r);
    groups.set(key, g);
  }
  const hits: Row[] = [];
  const notes: string[] = [];
  for (const [key, g] of groups) {
    if (g.addrs.size >= 12 || g.units.size >= 5) {
      notes.push(`${key.replace("|", " → ")} read ${g.addrs.size} addresses across ${g.units.size} unit${g.units.size === 1 ? "" : "s"}`);
      hits.push(...g.rows);
    }
  }
  if (!notes.length) return null;
  const sliced = cap(hits, (r) => `unit ${r.modbusUnit} address ${r.modbusAddr}`);
  return {
    id: "point-id",
    title: "Modbus register sweep",
    severity: "medium",
    summary: `${notes.join("; ")}. Steady polling repeats the same few addresses. This walked through many.`,
    meaning: "Point and tag identification is how an attacker, or a new integrator, learns which register is the tank level and which coil is the pump. The map of the process is the prize.",
    action: "If this was not a commissioning tool or a historian backfill, the source is mapping your process. Restrict Modbus clients to the known SCADA and HMI addresses.",
    techniques: ["T0861"],
    ...sliced,
    evidence: sliced.evidence,
    evidenceCount: sliced.count,
  };
}

function calmPolling(rows: Row[]): Finding | null {
  const reads = rows.filter((r) => r.modbusFunc !== undefined && READ_FUNCS.has(r.modbusFunc));
  if (reads.length < 4) return null;
  const addrs = new Set(reads.map((r) => r.modbusAddr));
  if (addrs.size > 3) return null;
  return {
    id: "benign-polling",
    title: "Modbus polling looks steady",
    severity: "info",
    summary: `${reads.length} reads, and only ${addrs.size} register address${addrs.size === 1 ? "" : "es"}. Nothing in the automatic checks looks like a scan, a write, or a tunnel.`,
    meaning: "This is the shape of ordinary SCADA polling: the same questions, over and over, to the same controller. It is not a clean bill of health for the plant. It only means this capture did not trip Primer's checks.",
    action: "If you expected an incident in this file, the interesting traffic may be on another segment, or it may be encrypted where Primer can only see the handshake.",
    techniques: [],
    evidence: reads.slice(0, 3).map((r) => ({ n: r.n, detail: r.info })),
    evidenceCount: reads.length,
  };
}
