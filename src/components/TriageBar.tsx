import type { CaseTriage } from "../lib/forensic.ts";
import { triageName } from "../lib/forensic.ts";
import type { TriageLevel, ValidationStatus } from "../lib/model.ts";

const LEVELS: { level: TriageLevel; body: string }[] = [
  { level: 1, body: "Anomaly. Something unusual. It may be maintenance, a misconfiguration, or a test." },
  { level: 2, body: "Suspicious activity. Worth an investigator's time. Preserve the evidence." },
  { level: 3, body: "Credible incident evidence. Enough, together, to open a formal investigation. Still not proof the controller was exploited." },
];

export function TriageBar({ triage }: { triage: CaseTriage }) {
  return (
    <section className="card mx-4 mt-3 p-4">
      <p className="font-mono text-[11px] tracking-[0.16em] text-muted">TRIAGE · LEVEL {triage.level} · {triage.name.toUpperCase()}</p>
      <p className="mt-2 text-sm">{triage.explanation}</p>
      <ul className="mt-3 space-y-1 text-sm text-muted">
        {LEVELS.map((item) => (
          <li key={item.level} className={item.level === triage.level ? "text-ink" : ""}>
            <span className="font-mono text-accent">{triageName(item.level)}. </span>{item.body}
          </li>
        ))}
      </ul>
    </section>
  );
}

export function DecisionButtons({ onDecide }: { onDecide: (validation: ValidationStatus) => void }) {
  return (
    <div className="mt-3 flex flex-wrap gap-2">
      <button type="button" className="hz-btn hz-sm" onClick={() => onDecide("approved")}>Approve</button>
      <button type="button" className="hz-btn hz-sm" onClick={() => onDecide("rejected")}>Reject</button>
      <button type="button" className="hz-btn hz-sm" onClick={() => onDecide("escalated")}>Escalate</button>
    </div>
  );
}
