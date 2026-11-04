import { getTechnique } from "./attack.ts";
import type { Analysis, Finding, Row } from "./model.ts";

function cell(value: string | number | undefined | null): string {
  const text = value == null ? "" : String(value);
  if (/[",\n]/.test(text)) return `"${text.replaceAll('"', '""')}"`;
  return text;
}

export function toCsv(headers: string[], rows: Array<Array<string | number | undefined | null>>): string {
  return [headers.map(cell).join(","), ...rows.map((row) => row.map(cell).join(","))].join("\n");
}

export function packetsCsv(rows: Row[], t0: number): string {
  return toCsv(
    ["number", "time_relative_s", "timestamp", "src", "dst", "src_port", "dst_port", "protocol", "length", "info", "mac_src", "mac_dst"],
    rows.map((row) => [
      row.n,
      (row.ts - t0).toFixed(6),
      new Date(row.ts * 1000).toISOString(),
      row.src,
      row.dst,
      row.sp || "",
      row.dp || "",
      row.proto,
      row.len,
      row.info,
      row.macSrc,
      row.macDst,
    ]),
  );
}

export function conversationsCsv(analysis: Analysis): string {
  return toCsv(
    ["a", "a_port", "b", "b_port", "protocol", "packets", "bytes", "start", "end"],
    analysis.conversations.map((c) => [
      c.a, c.aPort, c.b, c.bPort, c.proto, c.packets, c.bytes,
      new Date(c.start * 1000).toISOString(),
      new Date(c.end * 1000).toISOString(),
    ]),
  );
}

export function endpointsCsv(analysis: Analysis): string {
  return toCsv(
    ["address", "kind", "name", "packets", "bytes_sent", "bytes_received"],
    analysis.endpoints.map((e) => [e.addr, e.kind, analysis.names[e.addr] ?? "", e.packets, e.bytesSent, e.bytesRecv]),
  );
}

export function dnsCsv(analysis: Analysis): string {
  return toCsv(
    ["packet", "time", "src", "dst", "query", "answer"],
    analysis.dns.map((d) => [d.n, new Date(d.ts * 1000).toISOString(), d.src, d.dst, d.name, d.answer]),
  );
}

export function httpCsv(analysis: Analysis): string {
  return toCsv(
    ["packet", "time", "src", "dst", "method", "host", "path", "status", "auth_visible"],
    analysis.http.map((h) => [h.n, new Date(h.ts * 1000).toISOString(), h.src, h.dst, h.method, h.host, h.path, h.status || "", h.auth ? "yes" : ""]),
  );
}

export function tlsCsv(analysis: Analysis): string {
  return toCsv(
    ["packet", "time", "src", "dst", "sni", "subject", "issuer"],
    analysis.tls.map((t) => [t.n, new Date(t.ts * 1000).toISOString(), t.src, t.dst, t.sni, t.subject, t.issuer]),
  );
}

function techniqueCells(finding: Finding): { ids: string; names: string; tactics: string } {
  const techs = finding.techniques.map((id) => getTechnique(id)).filter((t) => t != null);
  return {
    ids: finding.techniques.join(" "),
    names: techs.map((t) => t.name).join(" | "),
    tactics: [...new Set(techs.flatMap((t) => t.tactics))].join(" "),
  };
}

export function findingsCsv(findings: Finding[]): string {
  return toCsv(
    ["id", "severity", "title", "summary", "technique_ids", "technique_names", "tactics", "legacy", "evidence_packets", "evidence_count"],
    findings.map((f) => {
      const t = techniqueCells(f);
      const legacy = (f.legacy ?? []).map((l) => `${l.id}->${l.replacedBy}`).join(" ");
      return [f.id, f.severity, f.title, f.summary, t.ids, t.names, t.tactics, legacy, f.evidence.map((e) => e.n).join(" "), f.evidenceCount];
    }),
  );
}
