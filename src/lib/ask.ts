import { getTechnique, techniqueLabel } from "./attack.ts";
import { compileFilter } from "./filter.ts";
import type { Analysis, Finding, Row } from "./model.ts";

export interface AskContext {
  fileName: string;
  rows: Row[];
  analysis: Analysis;
}

export interface ToolResult {
  tool: string;
  summary: string;
  packets: number[];
}

export interface AskAnswer {
  text: string;
  packets: number[];
  tools: string[];
  provider: string;
}

const WRITE_FUNCS = new Set([5, 6, 15, 16, 22, 23]);

export function planTools(question: string): string[] {
  const q = question.toLowerCase();
  const tools = new Set<string>();
  if (/writ|wrot|setpoint|forc|coil|register|command/.test(q)) tools.add("writers");
  if (/c2|beacon|command.and.control|exfil|callback|implant/.test(q)) tools.add("c2");
  if (/password|cleartext|credential|login/.test(q)) tools.add("secrets");
  if (/scan|recon|port/.test(q)) tools.add("scans");
  if (/dns|tunnel/.test(q)) tools.add("dns");
  if (/attack|technique|mitre|tactic|mitigation/.test(q)) tools.add("attack");
  if (/device|host|who|talk/.test(q) && tools.size === 0) tools.add("hosts");
  if (tools.size === 0) tools.add("overview");
  return [...tools];
}

export function runTools(question: string, ctx: AskContext): ToolResult[] {
  return planTools(question).map((tool) => {
    if (tool === "writers") return writers(ctx);
    if (tool === "c2") return c2(ctx);
    if (tool === "secrets") return secrets(ctx);
    if (tool === "scans") return scans(ctx);
    if (tool === "dns") return dns(ctx);
    if (tool === "attack") return attack(ctx, question);
    if (tool === "hosts") return hosts(ctx);
    return overview(ctx);
  });
}

export function answerOffline(question: string, ctx: AskContext): AskAnswer {
  const results = runTools(question, ctx);
  const packets = unique(results.flatMap((r) => r.packets));
  const text = results.map((r) => r.summary).join("\n\n");
  const cited = packets.length ? ` Packet numbers used: ${packets.slice(0, 24).join(", ")}.` : "";
  return {
    text: `${text}${cited}`,
    packets: packets.slice(0, 40),
    tools: results.map((r) => r.tool),
    provider: "offline",
  };
}

function writers(ctx: AskContext): ToolResult {
  const hits = ctx.rows.filter((row) =>
    (row.modbusFunc !== undefined && WRITE_FUNCS.has(row.modbusFunc) && row.sp !== 502)
    || row.s7Func === 0x05
    || (row.cipSvc !== undefined && [0x10, 0x4d, 0x53].includes(row.cipSvc))
    || (row.bacnetConfirmed && row.bacnetSvc === 15)
    || (row.dnp3Func !== undefined && [3, 4, 5, 6].includes(row.dnp3Func))
    || (row.iecType !== undefined && row.iecType >= 45 && row.iecType <= 64),
  );
  const bySrc = new Map<string, Row[]>();
  for (const row of hits) {
    const list = bySrc.get(row.src) ?? [];
    list.push(row);
    bySrc.set(row.src, list);
  }
  if (!hits.length) return { tool: "writers", summary: "No write or command packets were decoded in this capture.", packets: [] };
  const lines = [...bySrc.entries()].map(([src, rows]) => {
    const targets = [...new Set(rows.map((r) => r.dst))].join(", ");
    return `${src} sent ${rows.length} write or command packet${rows.length === 1 ? "" : "s"} to ${targets}.`;
  });
  return { tool: "writers", summary: lines.join(" "), packets: hits.map((r) => r.n) };
}

function c2(ctx: AskContext): ToolResult {
  const hits = ctx.analysis.findings.filter((f) => /beacon|exfil|external|dns-tunnel/.test(f.id));
  if (!hits.length) return { tool: "c2", summary: "Nothing in the automatic checks looks like beaconing, a DNS tunnel, or a large upload to a public host.", packets: [] };
  return { tool: "c2", summary: hits.map((f) => `${f.title}. ${f.summary}`).join(" "), packets: evidenceOf(hits) };
}

function secrets(ctx: AskContext): ToolResult {
  const hits = ctx.analysis.findings.filter((f) => f.id === "cleartext" || f.id === "brute-force");
  if (!hits.length) return { tool: "secrets", summary: "No cleartext password or repeated logon was flagged.", packets: [] };
  return { tool: "secrets", summary: hits.map((f) => f.summary).join(" "), packets: evidenceOf(hits) };
}

function scans(ctx: AskContext): ToolResult {
  const hits = ctx.analysis.findings.filter((f) => f.id.startsWith("port-scan") || f.id === "point-id");
  if (!hits.length) return { tool: "scans", summary: "No port scan or register sweep was flagged.", packets: [] };
  return { tool: "scans", summary: hits.map((f) => f.summary).join(" "), packets: evidenceOf(hits) };
}

function dns(ctx: AskContext): ToolResult {
  const tunnel = ctx.analysis.findings.find((f) => f.id === "dns-tunnel");
  const names = ctx.analysis.dns.slice(0, 8).map((d) => d.name).join(", ");
  const summary = tunnel
    ? `${tunnel.summary} Other names in the capture include ${names || "none"}.`
    : `No DNS tunnel was flagged. Queries seen: ${names || "none"}.`;
  return { tool: "dns", summary, packets: tunnel ? tunnel.evidence.map((e) => e.n) : ctx.analysis.dns.slice(0, 8).map((d) => d.n) };
}

function attack(ctx: AskContext, question: string): ToolResult {
  const idMatch = question.toUpperCase().match(/T\d{4}(?:\.\d{3})?/);
  if (idMatch) {
    const tech = getTechnique(idMatch[0]);
    const related = ctx.analysis.findings.filter((f) => f.techniques.includes(idMatch[0]) || f.legacy?.some((l) => l.id === idMatch[0] || l.replacedBy === idMatch[0]));
    const blurb = tech ? `${techniqueLabel(idMatch[0])}. ${tech.description.slice(0, 420)}` : `${idMatch[0]} is not in the bundled catalogue.`;
    const note = idMatch[0] === "T0855" ? " T0855 was revoked and replaced by T1692.001 Command Message." : "";
    return {
      tool: "attack",
      summary: `${blurb}${note} ${related.map((f) => f.summary).join(" ")}`.trim(),
      packets: evidenceOf(related),
    };
  }
  const rows = ctx.analysis.findings.filter((f) => f.severity !== "info").map((f) => `${f.title}: ${f.techniques.map(techniqueLabel).join(", ") || "no technique"}`);
  return { tool: "attack", summary: rows.join(" ") || "No techniques were mapped.", packets: evidenceOf(ctx.analysis.findings) };
}

function hosts(ctx: AskContext): ToolResult {
  const named = ctx.analysis.devices.map((ip) => ctx.analysis.names[ip] ? `${ip} (${ctx.analysis.names[ip]})` : ip);
  return { tool: "hosts", summary: `${named.length} internal addresses: ${named.join(", ")}.`, packets: [] };
}

function overview(ctx: AskContext): ToolResult {
  const loud = ctx.analysis.findings.filter((f) => f.severity !== "info");
  return {
    tool: "overview",
    summary: `${ctx.analysis.headline} ${ctx.analysis.detail} You can ask which devices wrote to the PLC, whether anything looks like C2, or about a technique id.`,
    packets: evidenceOf(loud).slice(0, 12),
  };
}

export function filterPackets(expr: string, ctx: AskContext): ToolResult {
  try {
    const filter = compileFilter(expr);
    const hits = ctx.rows.filter((row) => filter.test(row, ctx.analysis.t0)).slice(0, 30);
    return {
      tool: "filter",
      summary: hits.length ? hits.map((r) => `#${r.n} ${r.src} -> ${r.dst} ${r.proto} ${r.info}`).join("\n") : `No packets matched ${expr}.`,
      packets: hits.map((r) => r.n),
    };
  } catch (error) {
    return { tool: "filter", summary: error instanceof Error ? error.message : "Filter failed.", packets: [] };
  }
}

function evidenceOf(findings: Finding[]): number[] {
  return unique(findings.flatMap((f) => f.evidence.map((e) => e.n)));
}

function unique(nums: number[]): number[] {
  return [...new Set(nums)];
}

const IP = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const MAC = /\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b/gi;

export function redact(value: string): string {
  const ips = new Map<string, string>();
  const macs = new Map<string, string>();
  return value
    .replace(IP, (ip) => {
      if (!ips.has(ip)) ips.set(ip, `host-${ips.size + 1}`);
      return ips.get(ip) ?? ip;
    })
    .replace(MAC, (mac) => {
      const key = mac.toLowerCase();
      if (!macs.has(key)) macs.set(key, `mac-${macs.size + 1}`);
      return macs.get(key) ?? mac;
    });
}

export function briefForModel(question: string, ctx: AskContext, results: ToolResult[], hideAddresses: boolean): string {
  const body = {
    question,
    file: ctx.fileName,
    devices: ctx.analysis.devices.length,
    headline: ctx.analysis.headline,
    tools: results.map((r) => ({ tool: r.tool, summary: r.summary, packets: r.packets.slice(0, 24) })),
  };
  const json = JSON.stringify(body, null, 2);
  return hideAddresses ? redact(json) : json;
}

export const TOOL_GUIDE = `You are Primer, answering questions about one packet capture for an OT analyst.
Use only the tool results you are given. Do not invent packets, hosts, or technique ids.
If a tool result lists packet numbers, cite those numbers. If it does not, say the capture does not show that.
T0855 was revoked and replaced by T1692.001.
Reply in plain sentences. End with a line that starts "Packets:" and lists only packet numbers from the tool results, or "Packets: none".`;

export function packetsFromReply(reply: string, allowed: number[]): number[] {
  const line = reply.split("\n").find((row) => /^packets:/i.test(row.trim())) ?? "";
  const nums = [...line.matchAll(/\d+/g)].map((m) => Number(m[0]));
  const ok = new Set(allowed);
  return unique(nums.filter((n) => ok.has(n)));
}
