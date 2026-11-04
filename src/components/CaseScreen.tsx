import type { ActivityEntry, Dossier } from "../lib/forensic.ts";
import type { Finding } from "../lib/model.ts";

export interface CaseFields {
  name: string;
  investigator: string;
  organisation: string;
  sha256: string;
  storedPath: string;
  note: string;
}

/** Name, people, hash, notes, and the activity log. The engines do not decide findings. */
export function CaseScreen({
  fields,
  onChange,
  dossier,
  findings,
  activity,
  onAddNote,
}: {
  fields: CaseFields;
  onChange: (next: CaseFields) => void;
  dossier: Dossier;
  findings: Finding[];
  activity: ActivityEntry[];
  onAddNote: () => void;
}) {
  const decisions = findings.filter((f) => f.validation && f.validation !== "pending");
  return (
    <div className="grid gap-4 overflow-auto p-4 lg:grid-cols-2">
      <section className="card p-4">
        <p className="font-mono text-[11px] tracking-[0.16em] text-muted">CASE</p>
        <label className="mt-3 block text-sm">Name
          <input className="hz-field mt-1 w-full" value={fields.name} onChange={(event) => onChange({ ...fields, name: event.target.value })} />
        </label>
        <label className="mt-3 block text-sm">Investigator
          <input className="hz-field mt-1 w-full" value={fields.investigator} onChange={(event) => onChange({ ...fields, investigator: event.target.value })} />
        </label>
        <label className="mt-3 block text-sm">Organisation
          <input className="hz-field mt-1 w-full" value={fields.organisation} onChange={(event) => onChange({ ...fields, organisation: event.target.value })} />
        </label>
        <p className="mt-4 font-mono text-xs text-muted">SHA-256</p>
        <p className="break-all font-mono text-xs">{fields.sha256 || "Hashed when the desktop app copies the file into Documents\\Primer\\Cases. The browser session keeps the file in memory only."}</p>
        {fields.storedPath && <p className="mt-2 break-all text-xs text-muted">{fields.storedPath}</p>}
        <p className="mt-3 text-sm">Triage level {dossier.triage.level} ({dossier.triage.name}). Families: {dossier.triage.families.join(", ") || "none"}.</p>
      </section>
      <section className="card p-4">
        <p className="font-mono text-[11px] tracking-[0.16em] text-muted">NOTES AND LOG</p>
        <textarea className="hz-field mt-3 min-h-24 w-full" value={fields.note} onChange={(event) => onChange({ ...fields, note: event.target.value })} placeholder="Case note" />
        <button type="button" className="hz-btn hz-sm mt-2" onClick={onAddNote}>Add note to the log</button>
        <ul className="mt-4 space-y-2 text-sm">
          {activity.length === 0 && <li className="text-muted">No decisions yet. Approve, reject, or escalate a finding and it is recorded here with your name and the time.</li>}
          {activity.map((entry, index) => (
            <li key={`${entry.at}-${index}`}><span className="font-mono text-xs text-muted">{entry.at} · {entry.actor || "local"} · {entry.action}</span><br />{entry.detail}</li>
          ))}
        </ul>
        {decisions.length > 0 && <p className="mt-3 text-sm text-muted">{decisions.length} finding{decisions.length === 1 ? "" : "s"} decided.</p>}
      </section>
    </div>
  );
}
