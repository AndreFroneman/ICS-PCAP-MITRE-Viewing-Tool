import { ATTACK_SOURCE, getTechnique } from "./attack.ts";
import type { Finding, Severity } from "./model.ts";

const SCORE: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export function navigatorLayer(name: string, domain: "enterprise" | "ics", findings: Finding[]): string {
  const scores = new Map<string, { score: number; comment: string }>();
  for (const finding of findings) {
    if (finding.severity === "info") continue;
    for (const id of finding.techniques) {
      const tech = getTechnique(id);
      if (!tech || tech.domain !== domain || tech.revoked) continue;
      const prev = scores.get(id);
      const score = SCORE[finding.severity];
      if (!prev || score > prev.score) {
        scores.set(id, {
          score,
          comment: `${finding.title}. Packets ${finding.evidence.map((e) => e.n).slice(0, 12).join(", ")}.`,
        });
      }
    }
  }
  const layer = {
    name: `Primer ${domain} — ${name}`,
    versions: { attack: String(ATTACK_SOURCE.attackVersion), navigator: "5.1.0", layer: "4.5" },
    domain: domain === "ics" ? "ics-attack" : "enterprise-attack",
    description: `Generated locally by Primer from ${name}. Scores: low 1, medium 2, high 3, critical 4. T0855 was revoked and replaced by T1692.001; only current technique ids are scored.`,
    filters: { platforms: [] as string[] },
    sorting: 0,
    layout: { layout: "side", aggregateFunction: "average", showID: true, showName: true, showAggregateScores: false, countUnscored: false },
    hideDisabled: false,
    techniques: [...scores.entries()].map(([techniqueID, item]) => ({ techniqueID, score: item.score, comment: item.comment, enabled: true })),
    gradient: { colors: ["#070d18", "#22e6ff", "#ffb800", "#ff3d5a"], minValue: 0, maxValue: 4 },
    legendItems: [
      { label: "Low", color: "#3dff9a" },
      { label: "Medium", color: "#ffb800" },
      { label: "High", color: "#ff6a00" },
      { label: "Critical", color: "#ff3d5a" },
    ],
    metadata: [],
    showTacticRowBackground: true,
    tacticRowBackground: "#070d18",
    selectTechniquesAcrossTactics: true,
    selectSubtechniquesWithParent: false,
  };
  return JSON.stringify(layer, null, 2);
}
