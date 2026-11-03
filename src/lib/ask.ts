import { getTechnique, techniqueLabel } from "./attack.ts";
import { compileFilter } from "./filter.ts";
import { buildDossier, caseTriage, roleLabel, triageName, type AssetRecord, type Dossier } from "./forensic.ts";
import { isPublicUnicast } from "./ip.ts";
import type { Analysis, Finding, Row } from "./model.ts";

export interface AskContext {
  fileName: string;
  rows: Row[];
  analysis: Analysis;
  /** Optional. Built from the rows when a question needs assets or triage. */
  dossier?: Dossier;
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
  if (/incident|enough evidence|formal investigation|open an investigation/.test(q)) tools.add("irGate");
  if (/writ|wrot|setpoint|forc|coil|register|command|controller/.test(q)) tools.add("writers");
  if (/c2|beacon|command.and.control|exfil|callback|implant/.test(q)) tools.add("c2");
  if (/password|cleartext|credential|login/.test(q)) tools.add("secrets");
  if (/scan|recon|reconnaiss|port/.test(q)) tools.add("scans");
  if (/dns|tunnel/.test(q) && !/windows/.test(q)) tools.add("dns");
  if (/attack|technique|mitre|tactic|mitigation/.test(q)) tools.add("attack");
  if (/\b(between|from)\b/.test(q) && (/\d/.test(q) || /noon|midnight|morning/.test(q))) tools.add("timeWindow");
  if (/plc|hmi|workstation|asset|traffic to|going to/.test(q)) tools.add("asset");
  if (/connection|involving/.test(q)) tools.add("connections");
  if (/sequence|before the|stopped communicating|timeline of events/.test(q)) tools.add("sequence");
  if (/internet|public host|external host/.test(q)) tools.add("internet");
  if (/device|host|who|talk/.test(q) && tools.size === 0) tools.add("hosts");
  if (tools.size === 0) tools.add("overview");
  return [...tools];
}

export function runTools(question: string, ctx: AskContext): ToolResult[] {
  const dossier = ctx.dossier ?? buildDossier(ctx.rows, ctx.analysis);
  const withCase = { ...ctx, dossier };
  return planTools(question).map((tool) => {
    if (tool === "writers") return writers(withCase);
    if (tool === "c2") return c2(withCase);
    if (tool === "secrets") return secrets(withCase);
    if (tool === "scans") return scans(withCase);
    if (tool === "dns") return dns(withCase);
    if (tool === "attack") return attack(withCase, question);
    if (tool === "hosts") return hosts(withCase);
    if (tool === "timeWindow") return timeWindow(withCase, question);
    if (tool === "asset") return assetTool(withCase, question);
    if (tool === "connections") return connections(withCase, question);
    if (tool === "sequence") return sequence(withCase);
    if (tool === "irGate") return irGate(withCase);
    if (tool === "internet") return internet(withCase);
    return overview(withCase);
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

function dossierOf(ctx: AskContext): Dossier {
  return ctx.dossier ?? buildDossier(ctx.rows, ctx.analysis);
}

function clock(ts: number): string {
  return new Date(ts * 1000).toISOString().replace(".000Z", "Z");
}

/** Times in the question are read on the capture clock (UTC), not as plant local time. */
function windowBounds(question: string, t0: number): { start: number; end: number } | null {
  const q = question.toLowerCase().replace(/noon/g, "12 pm").replace(/midnight/g, "12 am");
  const matches = [...q.matchAll(/\b(\d{1,2})(?::(\d{2}))?\s*(am|pm)?\b/g)];
  if (matches.length < 2) return null;
  const day = new Date(t0 * 1000);
  const toUnix = (hourText: string, minText: string | undefined, ampm: string | undefined) => {
    let hour = Number(hourText);
    const minute = Number(minText ?? "0");
    if (ampm === "pm" && hour < 12) hour += 12;
    if (ampm === "am" && hour === 12) hour = 0;
    return Date.UTC(day.getUTCFullYear(), day.getUTCMonth(), day.getUTCDate(), hour, minute, 0) / 1000;
  };
  const start = toUnix(matches[0][1], matches[0][2], matches[0][3]);
  const end = toUnix(matches[1][1], matches[1][2], matches[1][3]);
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) return null;
  return { start, end };
}

function timeWindow(ctx: AskContext, question: string): ToolResult {
  const bounds = windowBounds(question, ctx.analysis.t0);
  const span = `This capture's clock runs from ${clock(ctx.analysis.t0)} to ${clock(ctx.analysis.t1)} (UTC, the capture clock, not a plant time zone).`;
  if (!bounds) return { tool: "timeWindow", summary: `No clock window was found in the question. ${span}`, packets: [] };
  const suspicious = /suspicious|attack|bad|incident|anomal/.test(question.toLowerCase());
  const inWindow = ctx.rows.filter((row) => row.ts >= bounds.start && row.ts < bounds.end);
  const evidenceNums = new Set(ctx.analysis.findings.filter((f) => f.severity !== "info").flatMap((f) => f.evidence.map((e) => e.n)));
  const hits = suspicious ? inWindow.filter((row) => evidenceNums.has(row.n)) : inWindow;
  if (!hits.length) {
    return {
      tool: "timeWindow",
      summary: `No ${suspicious ? "suspicious " : ""}packets between ${clock(bounds.start)} and ${clock(bounds.end)}. ${span} Primer will not borrow packet numbers from outside that window.`,
      packets: [],
    };
  }
  return {
    tool: "timeWindow",
    summary: `${hits.length} ${suspicious ? "suspicious " : ""}packet${hits.length === 1 ? "" : "s"} fall between ${clock(bounds.start)} and ${clock(bounds.end)}. ${span}`,
    packets: hits.map((r) => r.n),
  };
}

function resolveAsset(question: string, assets: AssetRecord[]): { asset: AssetRecord | null; note: string } {
  const ip = question.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
  if (ip) {
    const asset = assets.find((a) => a.ip === ip[0]) ?? null;
    return { asset, note: asset ? "" : `No asset record for ${ip[0]}.` };
  }
  const q = question.toLowerCase();
  const byHost = assets.find((a) => a.hostname && q.includes(a.hostname.toLowerCase()));
  if (byHost) return { asset: byHost, note: "" };
  const want =
    /engineering workstation|ews|engineering/.test(q) ? "engineering_workstation"
      : /historian/.test(q) ? "historian"
        : /scada/.test(q) ? "scada"
          : /\bhmi\b/.test(q) ? "hmi"
            : /plc|controller/.test(q) ? "plc"
              : "";
  if (!want) return { asset: null, note: "Name a hostname, an IP address, or a role such as PLC." };
  const matches = assets.filter((a) => a.role === want);
  if (matches.length === 1) {
    const only = matches[0];
    const named = /plc1|plc 1/.test(q) && !/plc1/.test(only.hostname.toLowerCase());
    const note = named
      ? `There is no host literally named PLC1. The likely ${roleLabel(only.role)} in this capture is ${only.ip}${only.hostname ? ` (${only.hostname})` : ""}.`
      : "";
    return { asset: only, note };
  }
  if (!matches.length) return { asset: null, note: `No likely ${roleLabel(want)} was inferred from this capture.` };
  const preferred = matches.find((a) => /^plc(\.|$)/i.test(a.hostname));
  if (preferred && want === "plc") {
    return {
      asset: preferred,
      note: `There is no host literally named PLC1. Several addresses look like PLCs (${matches.map((a) => a.ip).join(", ")}). ${preferred.ip}${preferred.hostname ? ` (${preferred.hostname})` : ""} is the one whose captured name says plc. The others are listed so they are not hidden.`,
    };
  }
  return { asset: null, note: `Several likely ${roleLabel(want)} addresses: ${matches.map((a) => a.ip).join(", ")}. Name one.` };
}

function assetTool(ctx: AskContext, question: string): ToolResult {
  const dossier = dossierOf(ctx);
  const { asset, note } = resolveAsset(question, dossier.assets);
  if (!asset) return { tool: "asset", summary: note || "No matching asset.", packets: [] };
  const q = question.toLowerCase();
  const wantEws = /engineering/.test(q) && /plc|controller/.test(q);
  if (wantEws && asset.role === "plc") {
    const ews = dossier.assets.filter((a) => a.role === "engineering_workstation");
    const peers = ews.filter((a) => ctx.rows.some((r) => (r.src === a.ip && r.dst === asset.ip) || (r.dst === a.ip && r.src === asset.ip)));
    const packets = ctx.rows.filter((r) => peers.some((p) => r.src === p.ip && r.dst === asset.ip) || peers.some((p) => r.dst === p.ip && r.src === asset.ip)).map((r) => r.n);
    if (!peers.length) return { tool: "asset", summary: `${note} No engineering-workstation hypothesis talked to ${asset.ip} in this capture.`.trim(), packets: [] };
    return {
      tool: "asset",
      summary: `${note} ${peers.map((p) => `${p.ip} is a likely engineering workstation (${p.hypothesis})`).join(" ")} Traffic with ${asset.ip} is cited below.`.trim(),
      packets,
    };
  }
  const packets = ctx.rows.filter((r) => r.src === asset.ip || r.dst === asset.ip).map((r) => r.n);
  return {
    tool: "asset",
    summary: `${note} ${asset.ip}${asset.hostname ? ` (${asset.hostname})` : ""}: ${asset.hypothesis} Confidence ${asset.confidence}. Also possible: ${asset.alternateHypothesis}`.trim(),
    packets,
  };
}

function connections(ctx: AskContext, question: string): ToolResult {
  const ip = question.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)?.[0];
  if (!ip) {
    return { tool: "connections", summary: "Name the IP address. Primer will not guess which 'this IP' means.", packets: [] };
  }
  const hits = ctx.rows.filter((r) => r.src === ip || r.dst === ip);
  if (!hits.length) return { tool: "connections", summary: `No packets include ${ip}.`, packets: [] };
  const peers = [...new Set(hits.map((r) => (r.src === ip ? r.dst : r.src)).filter(Boolean))];
  return {
    tool: "connections",
    summary: `${ip} appears in ${hits.length} packets, with ${peers.join(", ") || "no named peer"}.`,
    packets: hits.map((r) => r.n),
  };
}

function sequence(ctx: AskContext): ToolResult {
  const stop = ctx.rows.filter((r) => r.s7Func === 0x29 || (r.s7Func === 0x28 && /stop/i.test(r.s7Pi ?? "")));
  const commands = ctx.rows.filter((r) =>
    (r.modbusFunc !== undefined && [5, 6, 15, 16, 22, 23].includes(r.modbusFunc) && r.sp !== 502)
    || r.s7Func !== undefined
    || (r.iecType !== undefined && r.iecType >= 45 && r.iecType <= 64)
    || (r.dnp3Func !== undefined && [3, 4, 5, 6].includes(r.dnp3Func))
    || (r.cipSvc !== undefined && [0x10, 0x4d, 0x53].includes(r.cipSvc)),
  );
  if (!stop.length) {
    return {
      tool: "sequence",
      summary: commands.length
        ? "This capture does not show an S7 stop (or any other decoded PLC stop). The industrial commands that were decoded, in capture-clock order, are cited below. A stop that is not in the file is not implied."
        : "This capture does not show a PLC stop, and no industrial command was decoded.",
      packets: commands.map((r) => r.n),
    };
  }
  const when = Math.min(...stop.map((r) => r.ts));
  const before = commands.filter((r) => r.ts <= when);
  return {
    tool: "sequence",
    summary: `An S7 stop command is at ${before.filter((r) => stop.some((s) => s.n === r.n)).map((r) => `packet ${r.n} (${clock(r.ts)} UTC)`).join(", ") || "the cited packets"}. Commands at or before that time, in capture-clock order, are cited. This is the order in the file, not proof of what the controller did next.`,
    packets: before.map((r) => r.n),
  };
}

function irGate(ctx: AskContext): ToolResult {
  const dossier = dossierOf(ctx);
  const triage = dossier.triage.level ? dossier.triage : caseTriage(dossier.findings);
  const level3 = dossier.findings.filter((f) => f.triageLevel === 3);
  const cited = level3.flatMap((f) => f.evidence.map((e) => e.n));
  const gaps = dossier.gaps.map((g) => `Still required: ${g}`).join(" ");
  const recommendation = triage.level === 3
    ? "There is enough, together, to open a formal investigation. That is a recommendation to open one. It is not a declaration that an exploit succeeded, and Primer will not make that declaration from a capture alone."
    : triage.level === 2
      ? "Preserve the evidence and have someone who knows the plant review the level-2 findings. There is not enough here to call this a formal incident."
      : "Nothing here meets the bar for a formal incident. Keep the capture if the timing still matters to operations, and do not open an incident on this file alone.";
  return {
    tool: "irGate",
    summary: `Case triage is level ${triage.level} (${triageName(triage.level)}). ${triage.explanation} ${level3.length ? `Level-3 findings: ${level3.map((f) => f.title).join("; ")}.` : "No level-3 finding."} ${gaps} ${recommendation}`,
    packets: cited,
  };
}

function internet(ctx: AskContext): ToolResult {
  const hits = ctx.rows.filter((r) => isPublicUnicast(r.src) || isPublicUnicast(r.dst));
  if (!hits.length) return { tool: "internet", summary: "No packet in this capture has a public unicast address.", packets: [] };
  const byInternal = new Map<string, number>();
  for (const row of hits) {
    const internal = isPublicUnicast(row.src) ? row.dst : row.src;
    byInternal.set(internal, (byInternal.get(internal) ?? 0) + 1);
  }
  const lines = [...byInternal.entries()].map(([ip, n]) => `${ip} (${n} packets)`);
  return { tool: "internet", summary: `Public addresses appear with: ${lines.join("; ")}.`, packets: hits.map((r) => r.n) };
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
