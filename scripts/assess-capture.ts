import { readFileSync } from "node:fs";
import { inspectCapture } from "../src/lib/inspect.ts";
import { buildDossier } from "../src/lib/forensic.ts";

const path = process.argv[2];
if (!path) {
  console.error("usage: tsx scripts/assess-capture.ts <file.pcap>");
  process.exit(1);
}
const buf = readFileSync(path);
const inspected = await inspectCapture(buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength));
const rows = inspected.packets.map((p) => p.row);
const dossier = buildDossier(rows, inspected.analysis);
const loud = dossier.findings.filter((f) => f.severity !== "info");
console.log(JSON.stringify({
  file: path,
  format: inspected.file.format,
  packets: rows.length,
  warnings: inspected.file.warnings,
  triage: dossier.triage,
  roles: dossier.assets.filter((a) => a.role !== "unknown").map((a) => ({
    ip: a.ip, role: a.role, confidence: a.confidence, hypothesis: a.hypothesis,
  })),
  findings: loud.map((f) => ({
    id: f.id, severity: f.severity, triage: f.triageLevel, claim: f.claimStatus, title: f.title,
  })),
}, null, 2));
