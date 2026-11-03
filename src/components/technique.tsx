import { getMitigation, getTechnique, techniqueLabel } from "../lib/attack.ts";
import type { Finding } from "../lib/model.ts";

export function TechniqueBody({ id, findings }: { id: string; findings: Finding[] }) {
  const tech = getTechnique(id);
  if (!tech) return <p>No bundled entry for {id}.</p>;
  const related = findings.filter((f) => f.techniques.includes(id) || f.techniques.some((t) => t.startsWith(`${id}.`)) || f.legacy?.some((l) => l.id === id || l.replacedBy === id));
  return (
    <div className="space-y-4 text-sm leading-relaxed">
      <div className="flex flex-wrap items-center gap-2">
        <span className="rounded-full bg-raise px-2 py-0.5 font-mono text-xs">{tech.id}</span>
        <span className="rounded-full bg-raise px-2 py-0.5 text-xs uppercase tracking-wide text-muted">{tech.domain}</span>
        {tech.revoked && <span className="rounded-full bg-raise px-2 py-0.5 text-xs text-accent">Revoked</span>}
      </div>
      <p className="text-lg font-medium">{tech.name}</p>
      {tech.revoked && tech.revokedBy && (
        <p className="rounded-xl bg-raise p-3">
          MITRE revoked this technique. The replacement is {techniqueLabel(tech.revokedBy)}. Primer still shows the old id so older notes match.
        </p>
      )}
      <p className="text-muted">Tactics: {tech.tactics.join(", ") || "—"}{tech.platforms.length ? ` · ${tech.platforms.join(", ")}` : ""}</p>
      <p>{tech.description}</p>
      <p>
        <a className="text-accent underline" href={tech.url} target="_blank" rel="noreferrer">
          {tech.url}
        </a>
      </p>
      {tech.mitigationIds.length > 0 && (
        <div>
          <h3 className="mb-2 font-medium">Mitigations in the bundle</h3>
          <ul className="space-y-2">
            {tech.mitigationIds.map((mid) => {
              const m = getMitigation(mid);
              return (
                <li key={mid} className="rounded-xl border border-line p-3">
                  <a className="font-medium text-accent" href={m?.url} target="_blank" rel="noreferrer">{mid} {m?.name}</a>
                  <p className="mt-1 text-muted">{tech.mitigationNotes[mid] || m?.description}</p>
                </li>
              );
            })}
          </ul>
        </div>
      )}
      {related.length > 0 && (
        <div>
          <h3 className="mb-2 font-medium">In this capture</h3>
          <ul className="space-y-2">
            {related.map((f) => (
              <li key={f.id} className="rounded-xl border border-line p-3">
                <span className={`sev-${f.severity} font-medium`} style={{ color: "var(--mark)" }}>{f.severity}</span> {f.title}
                <p className="text-muted">{f.summary}</p>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
