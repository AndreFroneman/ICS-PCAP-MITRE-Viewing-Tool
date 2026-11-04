/**
 * Rebuild src/data/attack.json from the official MITRE ATT&CK STIX bundles.
 *
 *   node scripts/build-attack.mjs
 *
 * Downloads Enterprise and ICS from mitre-attack/attack-stix-data, then writes a
 * compact offline bundle: tactics, techniques, and mitigations. Citations are
 * shortened so the app can show the text without the raw multi-megabyte STIX.
 */
import fs from "node:fs";

const ENTERPRISE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json";
const ICS_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json";

function clean(s, max = 2200) {
  if (!s) return "";
  let t = s
    .replace(/\(Citation:[^)]*\)/g, "")
    .replace(/\[([^\]]+)\]\((https?:\/\/[^)]+)\)/g, "$1")
    .replace(/\r/g, "")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .replace(/[ \t]{2,}/g, " ")
    .trim();
  if (t.length > max) t = `${t.slice(0, max - 1).trimEnd()}…`;
  return t;
}

async function load(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url} returned ${res.status}`);
  return res.json();
}

function extId(o) {
  return o.external_references?.find((r) => r.source_name === "mitre-attack" && r.external_id) ?? null;
}

function absorb(doc, domain, tactics, techniques, mitigations) {
  const byId = new Map(doc.objects.map((o) => [o.id, o]));
  const matrix = doc.objects.find((o) => o.type === "x-mitre-matrix");
  (matrix?.tactic_refs ?? []).forEach((id, index) => {
    const t = byId.get(id);
    const ref = t && extId(t);
    if (!ref || t.x_mitre_deprecated) return;
    tactics.push({
      id: ref.external_id,
      shortname: t.x_mitre_shortname,
      name: t.name,
      description: clean(t.description, 700),
      url: ref.url || `https://attack.mitre.org/tactics/${ref.external_id}`,
      domain,
      order: index,
    });
  });
  const mitStixToId = new Map();
  for (const o of doc.objects) {
    if (o.type !== "course-of-action" || o.revoked || o.x_mitre_deprecated) continue;
    const ref = extId(o);
    if (!ref || !String(ref.external_id).startsWith("M")) continue;
    mitStixToId.set(o.id, ref.external_id);
    if (!mitigations[ref.external_id]) {
      mitigations[ref.external_id] = {
        id: ref.external_id,
        name: o.name,
        description: clean(o.description, 900),
        url: ref.url || `https://attack.mitre.org/mitigations/${ref.external_id}`,
        domain,
      };
    }
  }
  const mitFor = new Map();
  const revokedBy = new Map();
  for (const o of doc.objects) {
    if (o.type !== "relationship") continue;
    if (o.relationship_type === "mitigates") {
      const mid = mitStixToId.get(o.source_ref);
      if (!mid) continue;
      const list = mitFor.get(o.target_ref) ?? [];
      list.push({ id: mid, note: clean(o.description, 360) });
      mitFor.set(o.target_ref, list);
    }
    if (o.relationship_type === "revoked-by") {
      const ref = extId(byId.get(o.target_ref) ?? {});
      if (ref) revokedBy.set(o.source_ref, ref.external_id);
    }
  }
  for (const o of doc.objects) {
    if (o.type !== "attack-pattern") continue;
    const ref = extId(o);
    if (!ref || !/^T\d+/.test(ref.external_id)) continue;
    const id = ref.external_id;
    const parts = id.split(".");
    const url = parts.length === 2
      ? `https://attack.mitre.org/techniques/${parts[0]}/${parts[1]}/`
      : `https://attack.mitre.org/techniques/${id}/`;
    const mids = [];
    const notes = {};
    for (const m of mitFor.get(o.id) ?? []) {
      if (!mids.includes(m.id)) mids.push(m.id);
      if (m.note && !notes[m.id]) notes[m.id] = m.note;
    }
    const entry = {
      id,
      name: o.name,
      description: clean(o.description, 2200),
      url: ref.url || url,
      domain,
      tactics: [...new Set((o.kill_chain_phases ?? []).map((p) => p.phase_name))],
      revoked: Boolean(o.revoked),
      deprecated: Boolean(o.x_mitre_deprecated),
      revokedBy: revokedBy.get(o.id) ?? null,
      parent: parts.length === 2 ? parts[0] : null,
      platforms: o.x_mitre_platforms ?? [],
      mitigationIds: mids,
      mitigationNotes: notes,
    };
    const prev = techniques[id];
    if (!prev || (prev.revoked && !entry.revoked) || (prev.deprecated && !entry.deprecated)) techniques[id] = entry;
  }
}

const [enterprise, ics] = await Promise.all([load(ENTERPRISE_URL), load(ICS_URL)]);
const tactics = [];
const techniques = {};
const mitigations = {};
absorb(enterprise, "enterprise", tactics, techniques, mitigations);
absorb(ics, "ics", tactics, techniques, mitigations);
const collection = enterprise.objects.find((o) => o.type === "x-mitre-collection");
const icsCollection = ics.objects.find((o) => o.type === "x-mitre-collection");
const out = {
  source: {
    name: "MITRE ATT&CK STIX",
    attackSpecVersion: collection?.x_mitre_attack_spec_version ?? "",
    attackVersion: collection?.x_mitre_version ?? "",
    enterpriseModified: collection?.modified ?? null,
    icsModified: icsCollection?.modified ?? null,
    enterpriseUrl: ENTERPRISE_URL,
    icsUrl: ICS_URL,
    generatedFrom: "mitre-attack/attack-stix-data master (Enterprise + ICS). Citation markers removed for reading length.",
  },
  tactics,
  techniques,
  mitigations,
};
fs.mkdirSync(new URL("../src/data/", import.meta.url), { recursive: true });
const target = new URL("../src/data/attack.json", import.meta.url);
fs.writeFileSync(target, JSON.stringify(out));
console.log(`wrote ${Object.keys(techniques).length} techniques to ${target.pathname}`);
