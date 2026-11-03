import raw from "../data/attack.json" with { type: "json" };

export interface AttackTactic {
  id: string;
  shortname: string;
  name: string;
  description: string;
  url: string;
  domain: "enterprise" | "ics";
  order: number;
}

export interface AttackMitigation {
  id: string;
  name: string;
  description: string;
  url: string;
  domain: string;
}

export interface AttackTechnique {
  id: string;
  name: string;
  description: string;
  url: string;
  domain: "enterprise" | "ics";
  tactics: string[];
  revoked: boolean;
  deprecated: boolean;
  revokedBy: string | null;
  parent: string | null;
  platforms: string[];
  mitigationIds: string[];
  mitigationNotes: Record<string, string>;
}

interface Bundle {
  source: {
    name: string;
    attackSpecVersion: string;
    attackVersion: string;
    enterpriseModified: string | null;
    icsModified: string | null;
    enterpriseUrl: string;
    icsUrl: string;
    generatedFrom: string;
  };
  tactics: AttackTactic[];
  techniques: Record<string, AttackTechnique>;
  mitigations: Record<string, AttackMitigation>;
}

const data = raw as Bundle;

export const ATTACK_SOURCE = data.source;

export function getTechnique(id: string): AttackTechnique | undefined {
  return data.techniques[id];
}

export function getMitigation(id: string): AttackMitigation | undefined {
  return data.mitigations[id];
}

export function tacticsFor(domain: "enterprise" | "ics"): AttackTactic[] {
  return data.tactics.filter((t) => t.domain === domain).sort((a, b) => a.order - b.order);
}

export function techniquesIn(domain: "enterprise" | "ics", shortname: string): AttackTechnique[] {
  return Object.values(data.techniques).filter(
    (t) => t.domain === domain && !t.revoked && !t.deprecated && !t.parent && t.tactics.includes(shortname),
  );
}

export function subsOf(id: string): AttackTechnique[] {
  return Object.values(data.techniques).filter((t) => t.parent === id && !t.revoked && !t.deprecated);
}

export function techniqueLabel(id: string): string {
  const t = getTechnique(id);
  return t ? `${id} ${t.name}` : id;
}
