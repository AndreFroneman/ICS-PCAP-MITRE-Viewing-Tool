import { ATTRIBUTION_NOTE, type FingerprintRecord } from "../lib/forensic.ts";

/**
 * The caution is part of the view. There is no control that hides it,
 * and there is no country field and no actor field.
 */
export function AttributionPanel({ fingerprints, onPacket }: { fingerprints: FingerprintRecord[]; onPacket: (n: number) => void }) {
  return (
    <div className="space-y-3 overflow-auto p-4">
      <section className="card border border-amber-400/40 p-4">
        <p className="font-mono text-[11px] tracking-[0.16em] text-amber-300">FIXED CAUTION</p>
        <p className="mt-2 text-sm">{ATTRIBUTION_NOTE}</p>
        <p className="mt-2 text-sm text-muted">Keyboard layout, language, and working hours are software and schedule facts. They are not evidence of nationality or state sponsorship. This panel cannot be switched off.</p>
      </section>
      {!fingerprints.length && <p className="text-sm text-muted">No stack, DHCP, or application fingerprints were decoded.</p>}
      {fingerprints.map((item) => (
        <article key={item.id} className="card p-4 text-sm">
          <p className="font-mono text-[11px] tracking-[0.14em] text-muted">{item.kind.replaceAll("_", " ").toUpperCase()} · {item.ip}</p>
          <h3 className="mt-1 font-mono text-accent">{item.value}</h3>
          <p className="mt-2">Observed: {item.observedFact}</p>
          <p className="mt-1 text-muted">Hypothesis: {item.hypothesis}</p>
          <p className="mt-1 text-muted">{item.attributionNote}</p>
          <button type="button" className="mt-2 text-accent underline" onClick={() => onPacket(item.packetN)}>Packet {item.packetN}</button>
        </article>
      ))}
    </div>
  );
}
