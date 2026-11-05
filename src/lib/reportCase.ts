import { ATTACK_SOURCE, getTechnique, techniqueLabel } from "./attack.ts";
import type { Dossier } from "./forensic.ts";
import { roleLabel, triageName } from "./forensic.ts";
import type { Finding } from "./model.ts";
import { buildPdf } from "./report.ts";

/**
 * One investigation report. Observed facts and possible readings are separate.
 * A level-3 section is omitted when the case has no level-3 finding, so a quiet
 * plant does not grow a suspected-incident story.
 */

export interface CaseReportMeta {
  caseName: string;
  fileName: string;
  sha256: string;
  packetCount: number;
  generatedAt: string;
  investigator: string;
  captureClock: string;
}

const LIMITATION =
  "A packet capture cannot prove that a controller was successfully exploited. It shows bytes on the wire. Confirming an impact needs controller diagnostics, engineering-workstation logs, and the change ticket. Technique ids are possible readings of observed bytes. A list of techniques is not an attack chain. Signature hits, when present, are an IT ruleset and do not clear or condemn the OT findings. No Suricata alert is not the same as no industrial finding.";

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] ?? c);
}

function findingBlock(f: Finding): string {
  const claim = f.claimStatus ?? "possible";
  const support = f.techniqueSupport ?? "possible";
  const techs = f.techniques.map((id) => techniqueLabel(id)).join(", ");
  return `<article class="${esc(f.severity)} ${esc(claim)}">
    <p class="pill">${esc(claim)} · ${esc(f.severity)} · level ${f.triageLevel ?? 1} · ${esc(f.engine ?? "primer")}${f.ruleId ? ` · ${esc(f.ruleId)}` : ""}</p>
    <h3>${esc(f.title)}</h3>
    <p>${esc(f.summary)}</p>
    <p><strong>Alternative.</strong> ${esc(f.alternativeExplanation || "Not recorded.")}</p>
    <p>Technique support: ${esc(support)}. ${techs ? esc(techs) : "No technique id on this card."}</p>
    <p>Analyst: ${esc(f.validation ?? "pending")}${f.validatedBy ? ` by ${esc(f.validatedBy)}` : ""}.</p>
    <ul>${f.evidence.slice(0, 12).map((e) => `<li>Packet ${e.n}: ${esc(e.detail)}</li>`).join("")}</ul>
  </article>`;
}

export function reportCaseHtml(meta: CaseReportMeta, dossier: Dossier): string {
  const observed = dossier.findings.filter((f) => f.claimStatus === "observed" && f.severity !== "info");
  const possible = dossier.findings.filter((f) => f.claimStatus === "possible");
  const level3 = dossier.findings.filter((f) => f.triageLevel === 3);
  const level2 = dossier.findings.filter((f) => f.triageLevel === 2);
  const incident = level3.length
    ? level3.map(findingBlock).join("\n")
    : `<p class="empty">No level-3 finding. This section is intentionally empty. A quiet or merely suspicious capture is not written up as a suspected incident.</p>`;
  const assets = dossier.assets.map((a) => `<li><strong>${esc(a.ip)}</strong>${a.hostname ? ` (${esc(a.hostname)})` : ""} — hypothesis: likely ${esc(roleLabel(a.role))} (${esc(a.confidence)}). ${esc(a.hypothesis)} Also possible: ${esc(a.alternateHypothesis)}. Packets ${a.evidence.map((e) => e.n).join(", ") || "n/a"}.</li>`).join("");
  const topology = dossier.connections.slice(0, 30).map((c) => `<li>${esc(c.src)}:${c.sp} → ${esc(c.dst)}:${c.dp} ${esc(c.service)} · ${c.packets} packets · ${c.bytes} bytes</li>`).join("");
  const observedTechs = [...new Set(observed.flatMap((f) => f.techniques))];
  const possibleTechs = [...new Set(possible.flatMap((f) => f.techniques))].filter((id) => !observedTechs.includes(id));
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<title>Primer investigation — ${esc(meta.caseName || meta.fileName)}</title>
<style>
  body { font: 15px/1.5 Georgia, serif; color: #1c1915; background: #f7f4ee; margin: 0; }
  main { max-width: 860px; margin: 0 auto; padding: 40px 20px 72px; }
  h1 { font-weight: 500; font-size: 30px; }
  h2 { font-size: 20px; margin-top: 28px; }
  article, .box { background: #fff; border: 1px solid #e4dccf; padding: 12px 14px; margin: 10px 0; }
  .empty { background: #fff; border: 1px dashed #c4b8a6; padding: 12px 14px; }
  .pill { font: 12px/1 ui-sans-serif, sans-serif; letter-spacing: .04em; text-transform: uppercase; }
  .observed { border-left: 6px solid #1d4ed8; }
  .possible { border-left: 6px solid #a16207; }
</style></head><body><main>
  <p>Primer ${esc(meta.generatedAt)} · ATT&CK ${esc(ATTACK_SOURCE.attackVersion)} · capture clock ${esc(meta.captureClock)}</p>
  <h1>${esc(meta.caseName || meta.fileName)}</h1>
  <section id="executive-summary"><h2>Executive summary</h2>
    <div class="box"><p>Triage level ${dossier.triage.level} (${esc(dossier.triage.name)}). ${esc(dossier.triage.explanation)}</p>
    <p>${esc(meta.packetCount.toLocaleString())} packets in ${esc(meta.fileName)}. Investigator: ${esc(meta.investigator || "not named")}.</p></div>
  </section>
  <section id="scope"><h2>Scope</h2>
    <p>One local capture, analysed offline. Times below are the capture clock (${esc(meta.captureClock)}), not a plant time zone, unless an investigator has set one outside this file.</p>
  </section>
  <section id="evidence"><h2>Evidence inventory</h2>
    <p>${esc(meta.fileName)}</p>
    <p>SHA-256: <code>${esc(meta.sha256 || "not hashed in this session")}</code></p>
    <p>${meta.packetCount.toLocaleString()} packets. The stored copy is the evidence. The original path is left untouched.</p>
  </section>
  <section id="assets"><h2>Asset inventory</h2>
    <ul>${assets || "<li>No asset hypothesis.</li>"}</ul>
    <p>Roles are hypotheses. The word on the page is "likely".</p>
  </section>
  <section id="topology"><h2>Communication topology</h2>
    <ul>${topology || "<li>No conversations.</li>"}</ul>
  </section>
  <section id="suspicious"><h2>Suspicious activity</h2>
    ${level2.length ? level2.map(findingBlock).join("\n") : "<p>No level-2 finding.</p>"}
  </section>
  <section id="exploit-assessment"><h2>Exploit assessment</h2>
    ${incident}
  </section>
  <section id="mitre"><h2>MITRE mapping</h2>
    <p>Observed findings carry these technique ids as a possible reading, not as proof: ${esc(observedTechs.map(techniqueLabel).join("; ") || "none")}.</p>
    <p>Possible findings carry: ${esc(possibleTechs.map(techniqueLabel).join("; ") || "none")}.</p>
    <p>A list of techniques is not an attack chain. ${esc(getTechnique("T1692.001") ? "T0855 was revoked and replaced by T1692.001." : "")}</p>
  </section>
  <section id="ot"><h2>OT process and operational risk</h2>
    <p>${dossier.otRows.length ? `${dossier.otRows.length} industrial operations were decoded (reads, writes, and commands). Writes are changes on the wire. They are consistent with maintenance until an investigator says otherwise.` : "No industrial operation was decoded."}</p>
    <ul>${dossier.otRows.filter((r) => r.direction === "write" || r.direction === "command").slice(0, 20).map((r) => `<li>Packet ${r.n}: ${esc(r.src)} → ${esc(r.dst)} ${esc(r.protocol)} ${esc(r.operation)}${r.address ? ` address ${esc(r.address)}` : ""}</li>`).join("")}</ul>
  </section>
  <section id="packets"><h2>Detailed packet evidence</h2>
    ${observed.concat(possible).slice(0, 12).map(findingBlock).join("\n") || "<p>No finding cited a packet.</p>"}
  </section>
  <section id="limitations"><h2>Limitations</h2><p>${esc(LIMITATION)}</p></section>
  <section id="next"><h2>Recommended next actions</h2>
    <ul>
      <li>${dossier.triage.level === 3 ? "Open a formal investigation and preserve the evidence. Do not treat this report as proof of a successful exploit." : "Do not open a formal incident on this file alone."}</li>
      ${dossier.gaps.map((g) => `<li>${esc(g)}</li>`).join("")}
      <li>Have someone who knows the shift accept or reject each finding. The engines do not do that.</li>
    </ul>
  </section>
</main></body></html>`;
}

export function reportCaseJson(meta: CaseReportMeta, dossier: Dossier): string {
  return JSON.stringify({
    generator: "Primer",
    version: "2.0.2",
    attack: ATTACK_SOURCE,
    meta,
    triage: dossier.triage,
    gaps: dossier.gaps,
    limitations: LIMITATION,
    assets: dossier.assets,
    findings: dossier.findings.map((f) => ({
      ...f,
      techniques: f.techniques.map((id) => ({ id, name: getTechnique(id)?.name ?? id, support: f.techniqueSupport ?? "possible" })),
    })),
    topology: dossier.connections.slice(0, 80),
    ot: dossier.otRows.slice(0, 200),
    fingerprints: dossier.fingerprints,
  }, null, 2);
}

export function reportCaseCsv(dossier: Dossier): string {
  const header = ["id", "claim_status", "triage_level", "severity", "engine", "rule_id", "title", "techniques", "packets", "validation"];
  const lines = dossier.findings.map((f) => [
    f.id, f.claimStatus ?? "", String(f.triageLevel ?? ""), f.severity, f.engine ?? "", f.ruleId ?? "",
    f.title, f.techniques.join(" "), f.evidence.map((e) => e.n).join(" "), f.validation ?? "",
  ].map(csvCell).join(","));
  return [header.join(","), ...lines].join("\n");
}

function csvCell(value: string): string {
  return /[",\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}

export function reportCasePdf(meta: CaseReportMeta, dossier: Dossier): Uint8Array {
  const lines: { text: string; bold?: boolean; size?: number }[] = [];
  const push = (text: string, bold = false, size?: number) => lines.push({ text, bold, size });
  push("Primer investigation report", true, 16);
  push(meta.caseName || meta.fileName, true, 13);
  push(`Level ${dossier.triage.level} ${triageName(dossier.triage.level)}`, true);
  wrap(dossier.triage.explanation).forEach((t) => push(t));
  push(`File ${meta.fileName}`);
  push(`SHA-256 ${meta.sha256 || "not hashed in this session"}`);
  push(`Capture clock ${meta.captureClock}`);
  push("Assets", true, 12);
  for (const a of dossier.assets.slice(0, 20)) {
    wrap(`${a.ip} likely ${roleLabel(a.role)} (${a.confidence}). ${a.hypothesis}`).forEach((t) => push(t));
  }
  const level3 = dossier.findings.filter((f) => f.triageLevel === 3);
  push("Exploit assessment", true, 12);
  if (!level3.length) push("No level-3 finding. This section is intentionally empty.");
  for (const f of level3) wrap(`${f.claimStatus ?? "possible"}: ${f.title}. ${f.summary}`).forEach((t) => push(t));
  push("Limitations", true, 12);
  wrap(LIMITATION).forEach((t) => push(t));
  return buildPdf(lines);
}

function wrap(text: string, width = 92): string[] {
  const words = text.replace(/\s+/g, " ").trim().split(" ");
  const out: string[] = [];
  let cur = "";
  for (const w of words) {
    if ((cur + " " + w).trim().length > width) {
      if (cur) out.push(cur);
      cur = w;
    } else cur = (cur + " " + w).trim();
  }
  if (cur) out.push(cur);
  return out.length ? out : [""];
}
