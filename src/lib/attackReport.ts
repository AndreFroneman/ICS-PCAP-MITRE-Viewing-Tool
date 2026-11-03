import { ATTACK_SOURCE, getMitigation, getTechnique, tacticsFor } from "./attack.ts";
import type { Analysis, Finding, Row, Severity } from "./model.ts";
import { buildPdf } from "./report.ts";

const CONFIDENCE: Record<Severity, string> = {
  critical: "High — the pattern is specific and uncommon in steady plant traffic.",
  high: "High — several packets agree, and a benign explanation should be ruled out.",
  medium: "Medium — the shape matches, and it can also be maintenance or inventory.",
  low: "Low — a weak or partial match.",
  info: "Informational",
};

export interface TechniqueBlock {
  id: string;
  name: string;
  tactic: string;
  tacticName: string;
  domain: "enterprise" | "ics";
  confidence: string;
  severity: Severity;
  summary: string;
  meaning: string;
  action: string;
  mitigations: { id: string; name: string; description: string }[];
  evidence: { n: number; time: string; hosts: string; detail: string }[];
  legacy?: string;
}

export function techniqueBlocks(rows: Row[], findings: Finding[]): TechniqueBlock[] {
  const byNumber = new Map(rows.map((row) => [row.n, row]));
  const blocks: TechniqueBlock[] = [];
  for (const domain of ["ics", "enterprise"] as const) {
    for (const tactic of tacticsFor(domain)) {
      const seen = new Set<string>();
      for (const finding of findings) {
        if (finding.severity === "info") continue;
        for (const id of finding.techniques) {
          const tech = getTechnique(id);
          if (!tech || tech.domain !== domain || tech.revoked || !tech.tactics.includes(tactic.shortname)) continue;
          const key = `${domain}:${tactic.shortname}:${id}:${finding.id}`;
          if (seen.has(key)) continue;
          seen.add(key);
          const legacy = (finding.legacy ?? []).find((item) => item.replacedBy === id);
          blocks.push({
            id,
            name: tech.name,
            tactic: tactic.shortname,
            tacticName: tactic.name,
            domain,
            confidence: CONFIDENCE[finding.severity],
            severity: finding.severity,
            summary: finding.summary,
            meaning: finding.meaning,
            action: finding.action,
            mitigations: tech.mitigationIds.slice(0, 4).map((mid) => {
              const m = getMitigation(mid);
              return { id: mid, name: m?.name ?? mid, description: tech.mitigationNotes[mid] || m?.description || "" };
            }),
            evidence: finding.evidence.slice(0, 8).map((item) => {
              const row = byNumber.get(item.n);
              return {
                n: item.n,
                time: row ? new Date(row.ts * 1000).toISOString() : "",
                hosts: row ? `${row.src} → ${row.dst}` : "",
                detail: item.detail,
              };
            }),
            legacy: legacy ? `${legacy.id} was revoked and replaced by ${id}.` : undefined,
          });
        }
      }
    }
  }
  return blocks;
}

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] ?? c);
}

export function attackReportHtml(fileName: string, analysis: Analysis, rows: Row[]): string {
  const blocks = techniqueBlocks(rows, analysis.findings);
  const sections = ["ics", "enterprise"].map((domain) => {
    const mine = blocks.filter((b) => b.domain === domain);
    const tactics = [...new Set(mine.map((b) => b.tacticName))];
    const body = tactics.map((tactic) => {
      const items = mine.filter((b) => b.tacticName === tactic).map((b) => `
        <article>
          <h3>${esc(b.id)} ${esc(b.name)} <span class="pill">${esc(b.severity)}</span></h3>
          <p><strong>Confidence.</strong> ${esc(b.confidence)}</p>
          <p>${esc(b.summary)}</p>
          <p>${esc(b.meaning)}</p>
          <p><strong>What to do.</strong> ${esc(b.action)}</p>
          ${b.legacy ? `<p class="note">${esc(b.legacy)} T0855 Unauthorized Command Message is the legacy id. The current technique is T1692.001 Command Message.</p>` : ""}
          <h4>Mitigations from the bundled STIX</h4>
          <ul>${b.mitigations.map((m) => `<li><strong>${esc(m.id)} ${esc(m.name)}.</strong> ${esc(m.description)}</li>`).join("") || "<li>None listed on this technique.</li>"}</ul>
          <h4>Evidence</h4>
          <ul>${b.evidence.map((e) => `<li>Packet ${e.n} · ${esc(e.time)} · ${esc(e.hosts)} · ${esc(e.detail)}</li>`).join("")}</ul>
        </article>`).join("");
      return `<section><h2>${esc(tactic)}</h2>${items}</section>`;
    }).join("");
    return `<h1>${domain === "ics" ? "ATT&CK for ICS" : "Enterprise ATT&CK"}</h1>${body || "<p>No techniques in this domain.</p>"}`;
  }).join("");
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Primer ATT&CK report — ${esc(fileName)}</title>
<style>
  body{margin:0;background:#03060c;color:#e6f1ff;font:17px/1.5 Rajdhani,Segoe UI,sans-serif}
  main{max-width:880px;margin:0 auto;padding:48px 22px 80px}
  h1,h2,h3{font-family:Orbitron,Segoe UI,sans-serif;letter-spacing:.04em;text-transform:uppercase}
  h1{color:#22e6ff;font-size:28px} h2{font-size:18px;border-bottom:1px solid rgba(120,200,255,.2);padding-bottom:6px}
  article{border:1px solid rgba(120,200,255,.18);padding:16px 18px;margin:14px 0;background:rgba(12,22,38,.72)}
  .pill{font:700 11px JetBrains Mono,monospace;letter-spacing:.14em;color:#031018;background:#22e6ff;padding:2px 6px}
  .note{color:#ffb800} a{color:#22e6ff}
</style></head><body><main>
  <p style="letter-spacing:.28em;font:600 12px JetBrains Mono,monospace;color:#22e6ff">HORIZON · PRIMER · ATT&CK ${esc(ATTACK_SOURCE.attackVersion)}</p>
  <h1 style="font-size:40px">CAPTURE REPORT</h1>
  <p>${esc(fileName)} · ${rows.length.toLocaleString()} packets · ${analysis.devices.length} devices</p>
  <p><strong>${esc(analysis.headline)}</strong></p>
  <p>${esc(analysis.detail)}</p>
  <p class="note">Legacy id: T0855 Unauthorized Command Message was revoked in ATT&CK ${esc(ATTACK_SOURCE.attackVersion)} and replaced by T1692.001 Command Message. This report scores the current id and names the old one where a finding still carries it.</p>
  ${sections}
  <p>Heuristics for triage, generated on this computer. The capture file was not uploaded. Full technique text is the bundled STIX from ${esc(ATTACK_SOURCE.generatedFrom)}.</p>
</main></body></html>`;
}

export function attackReportPdf(fileName: string, analysis: Analysis, rows: Row[]): Uint8Array {
  const blocks = techniqueBlocks(rows, analysis.findings);
  const lines: { text: string; bold?: boolean; size?: number }[] = [
    { text: `PRIMER ATT&CK REPORT  ${fileName}`, bold: true, size: 16 },
    { text: analysis.headline, bold: true },
    { text: analysis.detail },
    { text: "T0855 Unauthorized Command Message was revoked and replaced by T1692.001 Command Message." },
  ];
  let last = "";
  for (const block of blocks) {
    const head = `${block.domain.toUpperCase()} / ${block.tacticName}`;
    if (head !== last) {
      lines.push({ text: "" });
      lines.push({ text: head, bold: true, size: 13 });
      last = head;
    }
    lines.push({ text: `${block.severity.toUpperCase()}  ${block.id} ${block.name}`, bold: true });
    lines.push({ text: `Confidence: ${block.confidence}` });
    lines.push({ text: block.summary });
    if (block.legacy) lines.push({ text: block.legacy });
    const mits = block.mitigations.map((m) => `${m.id} ${m.name}`).join("; ");
    if (mits) lines.push({ text: `Mitigations: ${mits}` });
    for (const ev of block.evidence.slice(0, 5)) lines.push({ text: `  Packet ${ev.n}  ${ev.hosts}  ${ev.detail}`.slice(0, 110) });
  }
  return buildPdf(lines);
}
