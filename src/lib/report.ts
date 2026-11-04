import { ATTACK_SOURCE, getMitigation, getTechnique, techniqueLabel } from "./attack.ts";
import type { Analysis, Finding } from "./model.ts";

export interface ReportMeta {
  fileName: string;
  packetCount: number;
  generatedAt: string;
}

export function reportJson(meta: ReportMeta, analysis: Analysis): string {
  const findings = analysis.findings.map((f) => ({
    ...f,
    techniques: f.techniques.map((id) => ({
      id,
      name: getTechnique(id)?.name ?? id,
      url: getTechnique(id)?.url ?? "",
      tactics: getTechnique(id)?.tactics ?? [],
      mitigations: (getTechnique(id)?.mitigationIds ?? []).map((mid) => ({
        id: mid,
        name: getMitigation(mid)?.name ?? mid,
      })),
    })),
    legacy: (f.legacy ?? []).map((l) => ({
      ...l,
      name: getTechnique(l.id)?.name ?? l.id,
      replacedByName: getTechnique(l.replacedBy)?.name ?? l.replacedBy,
    })),
  }));
  return JSON.stringify(
    {
      generator: "Primer",
      ...meta,
      attack: ATTACK_SOURCE,
      headline: analysis.headline,
      detail: analysis.detail,
      devices: analysis.devices,
      findings,
      conversations: analysis.conversations.slice(0, 40),
    },
    null,
    2,
  );
}

export function reportHtml(meta: ReportMeta, analysis: Analysis): string {
  const findings = analysis.findings.map((f) => findingHtml(f)).join("\n");
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Primer findings — ${escapeHtml(meta.fileName)}</title>
<style>
  body { font: 15px/1.5 "Iowan Old Style", Palatino, Georgia, serif; color: #1c1915; background: #f7f4ee; margin: 0; }
  main { max-width: 820px; margin: 0 auto; padding: 48px 24px 80px; }
  h1 { font-weight: 500; font-size: 32px; margin: 0 0 8px; }
  h2 { font-size: 20px; margin: 28px 0 8px; }
  .muted { color: #5e584f; }
  .banner { background: #fff; border: 1px solid #e4dccf; padding: 16px 18px; border-radius: 12px; }
  article { background: #fff; border: 1px solid #e4dccf; border-left: 6px solid var(--sev); padding: 16px 18px; border-radius: 12px; margin: 14px 0; }
  .critical { --sev: #9f1239; } .high { --sev: #c2410c; } .medium { --sev: #a16207; } .low { --sev: #3f6212; } .info { --sev: #1d4ed8; }
  .pill { display: inline-block; font: 12px/1 ui-sans-serif, sans-serif; letter-spacing: .04em; text-transform: uppercase; padding: 2px 8px; border-radius: 99px; background: #f3efe6; }
  ul { padding-left: 18px; }
  a { color: #9a3412; }
  code { font-family: ui-monospace, monospace; font-size: 13px; }
</style>
</head>
<body>
<main>
  <p class="muted">Primer · local findings report · ATT&CK ${escapeHtml(ATTACK_SOURCE.attackVersion)}</p>
  <h1>${escapeHtml(meta.fileName)}</h1>
  <p class="muted">${analysis.devices.length} devices · ${meta.packetCount.toLocaleString()} packets · ${escapeHtml(meta.generatedAt)}</p>
  <div class="banner">
    <strong>${escapeHtml(analysis.headline)}</strong>
    <p>${escapeHtml(analysis.detail)}</p>
  </div>
  <h2>Findings</h2>
  ${findings || "<p>No findings.</p>"}
  <h2>How to read this</h2>
  <p>These checks are heuristics. A match is a lead for someone who knows the plant, not a conclusion that a technique was used. Technique text is bundled from MITRE ATT&CK ${escapeHtml(ATTACK_SOURCE.attackVersion)} (spec ${escapeHtml(ATTACK_SOURCE.attackSpecVersion)}) so the report still makes sense offline. Links need a network.</p>
</main>
</body>
</html>`;
}

function findingHtml(f: Finding): string {
  const techs = f.techniques.map((id) => {
    const t = getTechnique(id);
    const mits = (t?.mitigationIds ?? []).slice(0, 4).map((mid) => getMitigation(mid)?.name ?? mid).join(", ");
    return `<li><a href="${escapeHtml(t?.url ?? "#")}">${escapeHtml(techniqueLabel(id))}</a> — ${escapeHtml(t?.description.slice(0, 280) ?? "")}${mits ? ` Mitigations: ${escapeHtml(mits)}.` : ""}</li>`;
  }).join("");
  const legacy = (f.legacy ?? []).map((l) => `<li>Previously ${escapeHtml(l.id)} ${escapeHtml(getTechnique(l.id)?.name ?? "")}, revoked and replaced by ${escapeHtml(techniqueLabel(l.replacedBy))}.</li>`).join("");
  const ev = f.evidence.map((e) => `<li>Packet ${e.n}: ${escapeHtml(e.detail)}</li>`).join("");
  return `<article class="${f.severity}">
    <span class="pill">${f.severity}</span>
    <h2>${escapeHtml(f.title)}</h2>
    <p>${escapeHtml(f.summary)}</p>
    <p><strong>What this means.</strong> ${escapeHtml(f.meaning)}</p>
    <p><strong>What to do.</strong> ${escapeHtml(f.action)}</p>
    <ul>${techs}${legacy}</ul>
    <p class="muted">Evidence (${f.evidenceCount})</p>
    <ul>${ev}</ul>
  </article>`;
}

export function reportPdf(meta: ReportMeta, analysis: Analysis): Uint8Array {
  const lines: { text: string; bold?: boolean; size?: number }[] = [];
  lines.push({ text: "Primer findings report", bold: true, size: 18 });
  lines.push({ text: meta.fileName, bold: true, size: 14 });
  lines.push({ text: `${meta.packetCount} packets · ${analysis.devices.length} devices · ${meta.generatedAt}` });
  lines.push({ text: `ATT&CK ${ATTACK_SOURCE.attackVersion} (spec ${ATTACK_SOURCE.attackSpecVersion})` });
  lines.push({ text: "" });
  lines.push({ text: analysis.headline, bold: true });
  wrap(analysis.detail).forEach((t) => lines.push({ text: t }));
  for (const f of analysis.findings) {
    lines.push({ text: "" });
    lines.push({ text: `${f.severity.toUpperCase()} · ${f.title}`, bold: true, size: 13 });
    wrap(f.summary).forEach((t) => lines.push({ text: t }));
    wrap(`What this means: ${f.meaning}`).forEach((t) => lines.push({ text: t }));
    wrap(`What to do: ${f.action}`).forEach((t) => lines.push({ text: t }));
    const ids = f.techniques.map((id) => techniqueLabel(id)).join("; ");
    if (ids) wrap(`ATT&CK: ${ids}`).forEach((t) => lines.push({ text: t }));
    for (const l of f.legacy ?? []) {
      wrap(`Legacy id ${l.id} was revoked and replaced by ${techniqueLabel(l.replacedBy)}.`).forEach((t) => lines.push({ text: t }));
    }
    for (const e of f.evidence.slice(0, 8)) lines.push({ text: `  Packet ${e.n}: ${e.detail}`.slice(0, 110) });
    if (f.evidenceCount > 8) lines.push({ text: `  … ${f.evidenceCount - 8} more packets` });
  }
  lines.push({ text: "" });
  wrap("These checks are heuristics for triage, not proof. Generated locally by Primer; the capture was not uploaded.").forEach((t) => lines.push({ text: t }));
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

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] ?? c);
}

export function buildPdf(lines: { text: string; bold?: boolean; size?: number }[]): Uint8Array {
  const pages: string[] = [];
  let commands: string[] = [];
  let y = 760;
  const flush = () => {
    pages.push(commands.join("\n"));
    commands = [];
    y = 760;
  };
  for (const line of lines) {
    const size = line.size ?? 10;
    if (y < 48) flush();
    const font = line.bold ? "F2" : "F1";
    const text = pdfEscape(line.text);
    commands.push(`BT /${font} ${size} Tf 48 ${y} Td (${text}) Tj ET`);
    y -= size + 4;
  }
  if (commands.length) pages.push(commands.join("\n"));
  if (!pages.length) pages.push("BT /F1 12 Tf 48 760 Td (Empty report) Tj ET");

  const contentIds: number[] = [];
  const pageIds: number[] = [];
  let next = 3;
  for (let i = 0; i < pages.length; i++) {
    contentIds.push(next++);
    pageIds.push(next++);
  }
  const pagesId = next++;
  const catalogId = next;
  const objects: string[] = [
    `1 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n`,
    `2 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n`,
  ];
  pages.forEach((content, i) => {
    objects.push(`${contentIds[i]} 0 obj\n<< /Length ${content.length} >>\nstream\n${content}\nendstream\nendobj\n`);
    objects.push(
      `${pageIds[i]} 0 obj\n<< /Type /Page /Parent ${pagesId} 0 R /MediaBox [0 0 612 792] /Contents ${contentIds[i]} 0 R /Resources << /Font << /F1 1 0 R /F2 2 0 R >> >> >>\nendobj\n`,
    );
  });
  const kids = pageIds.map((id) => `${id} 0 R`).join(" ");
  objects.push(`${pagesId} 0 obj\n<< /Type /Pages /Count ${pageIds.length} /Kids [${kids}] >>\nendobj\n`);
  objects.push(`${catalogId} 0 obj\n<< /Type /Catalog /Pages ${pagesId} 0 R >>\nendobj\n`);
  const head = `%PDF-1.4\n`;
  let offset = head.length;
  const offsets = [0];
  const chunks = [head];
  for (const part of objects) {
    offsets.push(offset);
    chunks.push(part);
    offset += part.length;
  }
  let xref = `xref\n0 ${offsets.length}\n0000000000 65535 f \n`;
  for (let i = 1; i < offsets.length; i++) xref += `${offsets[i].toString().padStart(10, "0")} 00000 n \n`;
  const trailer = `trailer\n<< /Size ${offsets.length} /Root ${catalogId} 0 R >>\nstartxref\n${offset}\n%%EOF`;
  return new TextEncoder().encode(chunks.join("") + xref + trailer);
}

function pdfEscape(s: string): string {
  return s
    .replace(/→/g, "->")
    .replace(/[—–]/g, "-")
    .replace(/[^\x20-\x7e]/g, "?")
    .replace(/\\/g, "\\\\")
    .replace(/\(/g, "\\(")
    .replace(/\)/g, "\\)");
}
