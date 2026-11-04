import type { Finding } from "./model.ts";
import { decorateFinding } from "./forensic.ts";

/**
 * TShark and Suricata stay separate programs. Primer reads their files.
 * These parsers are the same shape the Rust side stores, so a fixture can be
 * tested here without a Windows binary.
 */

export interface TsharkRow {
  n: number;
  ts: number;
  len: number;
  src: string;
  dst: string;
  sp: number;
  dp: number;
  proto: string;
  info: string;
  ja3: string;
  rdpKeyboard: string;
}

export interface EveAlert {
  packet: number;
  src: string;
  dst: string;
  proto: string;
  signature: string;
  signatureId: number;
  severity: number;
  category: string;
  timestamp: string;
}

function asText(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number") return String(value);
  if (Array.isArray(value) && value.length) return asText(value[0]);
  return "";
}

function layersOf(entry: unknown): Record<string, unknown> {
  if (!entry || typeof entry !== "object") return {};
  const obj = entry as { _source?: { layers?: Record<string, unknown> }; layers?: Record<string, unknown> };
  return obj._source?.layers ?? obj.layers ?? (entry as Record<string, unknown>);
}

/** Accepts `tshark -T json` output, or a flat array used by the tests. */
export function parseTsharkJson(text: string): TsharkRow[] {
  const parsed = JSON.parse(text) as unknown;
  if (!Array.isArray(parsed)) throw new Error("TShark JSON was not a list of packets.");
  const rows: TsharkRow[] = [];
  for (const entry of parsed) {
    const layers = layersOf(entry);
    const n = Number(asText(layers["frame.number"] ?? layers.n));
    if (!Number.isFinite(n) || n <= 0) continue;
    const src = asText(layers["ip.src"] ?? layers["ipv6.src"] ?? layers.src);
    const dst = asText(layers["ip.dst"] ?? layers["ipv6.dst"] ?? layers.dst);
    const sp = Number(asText(layers["tcp.srcport"] ?? layers["udp.srcport"] ?? layers.sp) || 0);
    const dp = Number(asText(layers["tcp.dstport"] ?? layers["udp.dstport"] ?? layers.dp) || 0);
    rows.push({
      n,
      ts: Number(asText(layers["frame.time_epoch"] ?? layers.ts) || 0),
      len: Number(asText(layers["frame.len"] ?? layers.len) || 0),
      src,
      dst,
      sp: Number.isFinite(sp) ? sp : 0,
      dp: Number.isFinite(dp) ? dp : 0,
      proto: asText(layers["_ws.col.Protocol"] ?? layers.proto) || "tshark",
      info: asText(layers["_ws.col.Info"] ?? layers.info),
      ja3: asText(layers["tls.handshake.ja3"] ?? layers.ja3),
      rdpKeyboard: asText(layers["rdp.client.keyboard_layout"] ?? layers.rdpKeyboard),
    });
  }
  return rows;
}

/** Suricata EVE JSON, one object per line or a JSON array. Packet number is pcap_cnt. */
export function parseEve(text: string, ruleDate = ""): Finding[] {
  const lines = text.trim().startsWith("[")
    ? (JSON.parse(text) as unknown[])
    : text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).map((line) => JSON.parse(line) as unknown);
  const findings: Finding[] = [];
  for (const item of lines) {
    if (!item || typeof item !== "object") continue;
    const row = item as {
      event_type?: string;
      pcap_cnt?: number;
      src_ip?: string;
      dest_ip?: string;
      proto?: string;
      timestamp?: string;
      alert?: { signature?: string; signature_id?: number; severity?: number; category?: string };
    };
    if (row.event_type !== "alert" || !row.alert) continue;
    const packet = Number(row.pcap_cnt ?? 0);
    const sid = row.alert.signature_id ?? 0;
    const sev = row.alert.severity ?? 3;
    const severity = sev <= 1 ? "high" : sev === 2 ? "medium" : "low";
    const dateNote = ruleDate ? ` Rule snapshot: ${ruleDate}.` : "";
    findings.push(decorateFinding({
      id: `suricata:${sid}:${packet || findings.length + 1}`,
      engine: "suricata",
      ruleId: sid ? `sid:${sid}` : "",
      title: row.alert.signature || `Suricata alert ${sid}`,
      severity,
      summary: `${row.alert.signature || "Signature hit"} (${row.alert.category || "uncategorised"}).${dateNote} Signature hits are leads. A quiet ruleset is not a quiet plant: OT commands are Primer's job, not ET Open's.`,
      meaning: "Suricata compared the packet to a signature. A match means the bytes looked like that rule. It does not mean an exploit succeeded, and it does not replace the industrial checks.",
      action: "Read the rule, open the packet, and decide whether it belongs in this plant. Reject it if it is noise.",
      techniques: [],
      evidence: packet > 0 ? [{ n: packet, detail: `${row.src_ip ?? ""} → ${row.dest_ip ?? ""} ${row.proto ?? ""}`.trim() }] : [],
      evidenceCount: packet > 0 ? 1 : 0,
      confidence: "medium",
      claimStatus: "possible",
      alternativeExplanation: "A signature can fire on a lab file, a known-bad test, or a lookalike. Check the packet before acting.",
    }, []));
  }
  return findings;
}

function packetSet(f: Finding): Set<number> {
  return new Set(f.evidence.map((e) => e.n));
}

function sharesBehaviour(a: Finding, b: Finding): boolean {
  const blob = `${a.title} ${a.summary} ${b.title} ${b.summary}`.toLowerCase();
  const keys = ["modbus", "s7", "dnp3", "iec", "bacnet", "scan", "smb", "dns", "mqtt", "write", "password"];
  const hit = keys.filter((k) => a.title.toLowerCase().includes(k) || a.summary.toLowerCase().includes(k));
  return hit.some((k) => blob.includes(k) && (b.title + b.summary).toLowerCase().includes(k));
}

/**
 * One card when Primer and Suricata are talking about the same packets and the same behaviour.
 * Signature-only hits stay separate so they can be filtered.
 */
export function correlateFindings(primer: Finding[], suricata: Finding[]): Finding[] {
  const used = new Set<string>();
  const merged: Finding[] = [];
  for (const left of primer) {
    const lp = packetSet(left);
    const partner = suricata.find((right) => {
      if (used.has(right.id)) return false;
      const rp = packetSet(right);
      if (![...rp].some((n) => lp.has(n))) return false;
      return sharesBehaviour(left, right) || [...rp].every((n) => lp.has(n));
    });
    if (!partner) {
      merged.push(left);
      continue;
    }
    used.add(partner.id);
    const evidence = [...left.evidence];
    for (const item of partner.evidence) {
      if (!evidence.some((e) => e.n === item.n)) evidence.push(item);
    }
    merged.push({
      ...left,
      id: `corr:${left.id}`,
      engine: "correlation",
      ruleId: partner.ruleId || left.ruleId,
      summary: `${left.summary} Also raised by Suricata${partner.ruleId ? ` (${partner.ruleId})` : ""}: ${partner.title}.`,
      evidence,
      evidenceCount: Math.max(left.evidenceCount, evidence.length),
      confidence: left.confidence,
      claimStatus: left.claimStatus,
      techniqueSupport: "possible",
    });
  }
  for (const right of suricata) if (!used.has(right.id)) merged.push(right);
  return merged;
}
