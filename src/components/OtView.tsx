import type { Dossier, OtRow } from "../lib/forensic.ts";

function line(row: OtRow): string {
  const addr = row.address ? ` @ ${row.address}` : "";
  return `${row.protocol} ${row.operation}${addr}`;
}

/** Function codes, who wrote, and who only polled. Every write keeps its alternative explanation. */
export function OtView({ dossier, onPacket }: { dossier: Dossier; onPacket: (n: number) => void }) {
  const writes = dossier.otRows.filter((row) => row.direction === "write" || row.direction === "command");
  const reads = dossier.otRows.filter((row) => row.direction === "read");
  const writers = [...new Set(writes.map((row) => row.src))];
  const pollers = [...new Set(reads.map((row) => row.src))];
  return (
    <div className="space-y-4 overflow-auto p-4">
      <section className="card p-4">
        <p className="font-mono text-[11px] tracking-[0.16em] text-muted">OT WORKSHEET</p>
        <p className="mt-2 text-sm text-muted">A write is a change on the wire. It is consistent with maintenance until you say otherwise. Primer does not know the work order.</p>
        <p className="mt-2 text-sm">Writers: {writers.join(", ") || "none"}. Pollers: {pollers.join(", ") || "none"}.</p>
      </section>
      <section>
        <h3 className="display px-1 text-xl">Commands and writes</h3>
        {!writes.length && <p className="p-3 text-sm text-muted">No write or command was decoded.</p>}
        <ul className="mt-2 space-y-2">
          {writes.slice(0, 80).map((row) => (
            <li key={`${row.n}-${row.operation}`} className="card px-3 py-2 text-sm">
              <button type="button" className="text-accent underline" onClick={() => onPacket(row.n)}>Packet {row.n}</button>
              <span> {row.src} → {row.dst} · {line(row)}</span>
              <p className="text-muted">Alternative: consistent with a maintenance download or an operator change.</p>
            </li>
          ))}
        </ul>
      </section>
      <section>
        <h3 className="display px-1 text-xl">Reads and polls</h3>
        <p className="px-1 text-sm text-muted">{reads.length} read{reads.length === 1 ? "" : "s"} decoded. Steady polling is normal plant traffic.</p>
      </section>
    </div>
  );
}
