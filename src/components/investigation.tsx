import { useEffect, useState } from "react";
import { captureStatus, listInterfaces, startLiveCapture, stopLiveCapture } from "../lib/case.ts";
import type { Dossier } from "../lib/forensic.ts";
import { roleLabel } from "../lib/forensic.ts";
import type { Finding } from "../lib/model.ts";
import { Button } from "./ui.tsx";

export function InvestigationOverview({ dossier, headline, onPacket }: { dossier: Dossier; headline: string; onPacket: (n: number) => void }) {
  const loud = dossier.findings.filter((f) => (f.triageLevel ?? 1) >= 2).slice(0, 6);
  return (
    <div className="space-y-4 overflow-auto p-4">
      <section className="card p-4">
        <p className="font-mono text-[11px] tracking-[0.16em] text-muted">INVESTIGATION OVERVIEW</p>
        <h2 className="display mt-2 text-3xl">{headline}</h2>
        <p className="mt-2 text-sm">{dossier.triage.explanation}</p>
        <p className="mt-2 text-sm text-muted">{dossier.assets.length} role hypotheses · {dossier.findings.length} findings · {dossier.connections.length} conversations kept in the Zeek-style log.</p>
      </section>
      <div className="grid gap-3 md:grid-cols-2">
        {loud.map((f) => (
          <button key={f.id} type="button" className="card p-4 text-left" onClick={() => f.evidence[0] && onPacket(f.evidence[0].n)}>
            <p className="font-mono text-[11px] text-accent">{(f.claimStatus ?? "possible").toUpperCase()} · L{f.triageLevel}</p>
            <p className="mt-1">{f.title}</p>
          </button>
        ))}
      </div>
      <section className="card p-4 text-sm">
        <p className="font-mono text-[11px] tracking-[0.16em] text-muted">LIKELY ROLES</p>
        <ul className="mt-2 space-y-1">
          {dossier.assets.filter((a) => a.role !== "unknown").slice(0, 8).map((a) => (
            <li key={a.id}>{a.ip} — likely {roleLabel(a.role)} ({a.confidence})</li>
          ))}
        </ul>
      </section>
    </div>
  );
}

export function ConversationView({ dossier, onFilter }: { dossier: Dossier; onFilter: (expr: string) => void }) {
  return (
    <div className="overflow-auto p-4">
      <p className="mb-3 text-sm text-muted">Zeek-style connection records built in Primer. There is no Zeek binary. An external Zeek log can be imported later; it is off unless you point at a folder.</p>
      <table className="w-full text-left text-sm">
        <thead className="font-mono text-[11px] tracking-wide text-muted"><tr><th>From</th><th>To</th><th>Service</th><th>Packets</th><th>Bytes</th></tr></thead>
        <tbody>
          {dossier.connections.slice(0, 80).map((row) => (
            <tr key={`${row.src}-${row.dst}-${row.sp}-${row.dp}`} className="border-t border-line">
              <td className="py-1 pr-2">{row.src}:{row.sp}</td>
              <td>{row.dst}:{row.dp}</td>
              <td>{row.service}</td>
              <td>{row.packets}</td>
              <td>{row.bytes}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <button type="button" className="hz-btn hz-sm mt-3" onClick={() => onFilter("")}>Open the packet list</button>
    </div>
  );
}

export function TimelineView({ findings, onPacket }: { findings: Finding[]; onPacket: (n: number) => void }) {
  const ordered = [...findings].filter((f) => f.severity !== "info").sort((a, b) => (a.ts ?? 0) - (b.ts ?? 0) || a.title.localeCompare(b.title));
  return (
    <div className="overflow-auto p-4">
      <p className="mb-3 text-sm text-muted">This is the order of findings and commands on the capture clock. The traffic-volume histogram stays on Overview. A sequence of technique ids is not an attack chain.</p>
      <ol className="space-y-3 border-l border-line pl-4">
        {ordered.map((f) => (
          <li key={f.id}>
            <p className="font-mono text-[11px] text-accent">{f.claimStatus ?? "possible"} · L{f.triageLevel ?? 1} · {f.engine ?? "primer"}</p>
            <p>{f.title}</p>
            {f.evidence[0] && <button type="button" className="text-sm text-accent underline" onClick={() => onPacket(f.evidence[0].n)}>Packet {f.evidence[0].n}</button>}
          </li>
        ))}
        {!ordered.length && <li className="text-sm text-muted">No suspicious finding to put on a timeline.</li>}
      </ol>
    </div>
  );
}

export function ReportView({ onExport }: { onExport: (kind: string) => void }) {
  return (
    <div className="space-y-3 p-4">
      <p className="text-sm text-muted">One investigation report. Observed facts and possible readings stay visually distinct. If there is no level-3 finding, the exploit section is empty on purpose.</p>
      <div className="flex flex-wrap gap-2">
        <Button type="button" variant="solid" onClick={() => onExport("case-html")}>HTML</Button>
        <Button type="button" onClick={() => onExport("case-pdf")}>PDF</Button>
        <Button type="button" onClick={() => onExport("case-json")}>JSON</Button>
        <Button type="button" onClick={() => onExport("case-csv")}>CSV</Button>
      </div>
    </div>
  );
}

/** Optional, and kept off the path that opens a saved capture. */
export function LiveCapture({ onOpenPath }: { onOpenPath: (path: string) => void }) {
  const [message, setMessage] = useState("Checking whether live capture is possible on this computer.");
  const [url, setUrl] = useState("https://npcap.com/#download");
  const [available, setAvailable] = useState(false);
  const [ifaces, setIfaces] = useState<string[]>([]);
  const [iface, setIface] = useState("");
  const [path, setPath] = useState("");
  const [running, setRunning] = useState(false);

  useEffect(() => {
    void captureStatus().then((status) => {
      setMessage(status.message);
      setUrl(status.url);
      setAvailable(status.available);
      if (status.available) {
        void listInterfaces().then((list) => {
          setIfaces(list);
          setIface(list[0]?.split(".")[0]?.trim() ?? "");
        }).catch((error: unknown) => setMessage(error instanceof Error ? error.message : String(error)));
      }
    }).catch(() => setMessage("Live capture is only available in the desktop app. Opening a file does not need it."));
  }, []);

  return (
    <div className="space-y-3 p-1 text-sm">
      <p>{message}</p>
      {!available && <p><a className="text-accent underline" href={url}>Get Npcap</a>. Primer will not download or install it for you.</p>}
      {available && (
        <>
          <label className="block">Interface
            <select className="hz-field mt-1 w-full" value={iface} onChange={(event) => setIface(event.target.value)}>
              {ifaces.map((item) => <option key={item} value={item.split(".")[0]?.trim()}>{item}</option>)}
            </select>
          </label>
          <p className="text-muted">Capturing may ask for an administrator or for this Windows account to be allowed in Npcap. That prompt is Npcap's. Offline analysis never needs it.</p>
          {!running && <Button type="button" variant="solid" onClick={() => {
            void startLiveCapture(iface, 120).then((dest) => { setPath(dest); setRunning(true); }).catch((error: unknown) => setMessage(error instanceof Error ? error.message : String(error)));
          }}>Record 2 minutes</Button>}
          {running && <Button type="button" onClick={() => {
            void stopLiveCapture().then(() => { setRunning(false); if (path) onOpenPath(path); });
          }}>Stop and open as a case</Button>}
        </>
      )}
    </div>
  );
}
