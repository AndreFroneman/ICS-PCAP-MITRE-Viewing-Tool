import { useMemo, useState } from "react";
import { ATTACK_SOURCE, getTechnique, subsOf, tacticsFor, techniqueLabel, techniquesIn } from "../lib/attack.ts";
import { formatSpan } from "../lib/analyze.ts";
import type { Analysis, Finding, Severity } from "../lib/model.ts";
import { SEVERITY_RANK, worse } from "../lib/model.ts";
import { TechniqueBody } from "./technique.tsx";
import { Modal } from "./ui.tsx";

export function SummaryBand({ analysis, onFinding }: { analysis: Analysis; onFinding: () => void }) {
  const loud = analysis.findings.filter((f) => f.severity !== "info");
  return (
    <section className="border-b border-line bg-raise/70 px-4 py-3" data-tour="summary">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div className="max-w-3xl">
          <p className="text-xs uppercase tracking-[0.16em] text-muted">What this capture is saying</p>
          <h2 className="mt-1 text-lg font-medium leading-snug">{analysis.headline}</h2>
          <p className="mt-1 text-sm text-muted">{analysis.detail}</p>
        </div>
        <button type="button" className="rounded-full border border-line bg-surface px-3 py-1 text-sm" onClick={onFinding}>
          {loud.length === 0 ? "No suspicious checks" : `${loud.length} to review`}
        </button>
      </div>
      <div className="mt-3 flex gap-2 overflow-auto text-sm">
        <Stat label="Devices" value={String(analysis.devices.length)} />
        <Stat label="Conversations" value={String(analysis.conversations.length)} />
        <Stat label="Span" value={formatSpan(Math.max(0, analysis.t1 - analysis.t0))} />
        {analysis.findings.slice(0, 4).map((f) => (
          <span key={f.id} className={`sev-${f.severity} shrink-0 rounded-full border border-line bg-surface px-3 py-1`} style={{ color: "var(--mark)" }}>{f.title}</span>
        ))}
      </div>
    </section>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <span className="shrink-0 rounded-full border border-line bg-surface px-3 py-1">
      <span className="text-muted">{label}</span> {value}
    </span>
  );
}

export function FindingsView({ findings, onPacket, onTechnique }: { findings: Finding[]; onPacket: (n: number) => void; onTechnique: (id: string) => void }) {
  if (!findings.length) return <p className="p-6 text-sm text-muted">No findings for this capture.</p>;
  return (
    <div className="space-y-3 overflow-auto p-4" data-tour="findings">
      {findings.map((f) => (
        <article key={f.id} className={`sev-${f.severity} card border-l-4 p-4`} style={{ borderLeftColor: "var(--mark)" }}>
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded-full px-2 py-0.5 text-xs uppercase tracking-wide" style={{ color: "var(--mark)", background: "color-mix(in srgb, var(--mark) 14%, transparent)" }}>{f.severity}</span>
            <h3 className="text-lg font-medium">{f.title}</h3>
          </div>
          <p className="mt-2 text-sm">{f.summary}</p>
          <div className="mt-3 grid gap-3 md:grid-cols-2">
            <div className="rounded-xl bg-raise p-3 text-sm"><p className="font-medium">What this means</p><p className="mt-1 text-muted">{f.meaning}</p></div>
            <div className="rounded-xl bg-raise p-3 text-sm"><p className="font-medium">What to do</p><p className="mt-1 text-muted">{f.action}</p></div>
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            {f.techniques.map((id) => (
              <button key={id} type="button" className="rounded-full border border-line px-2 py-1 font-mono text-xs hover:border-accent" onClick={() => onTechnique(id)}>
                {techniqueLabel(id)}
              </button>
            ))}
          </div>
          {f.legacy?.map((l) => (
            <p key={l.id} className="mt-2 text-xs text-muted">
              Previously <button type="button" className="underline" onClick={() => onTechnique(l.id)}>{l.id}</button>, revoked and replaced by{" "}
              <button type="button" className="underline" onClick={() => onTechnique(l.replacedBy)}>{techniqueLabel(l.replacedBy)}</button>.
            </p>
          ))}
          <div className="mt-3">
            <p className="text-xs uppercase tracking-wide text-muted">Evidence · {f.evidenceCount} packet{f.evidenceCount === 1 ? "" : "s"}</p>
            <ul className="mt-1 space-y-1">
              {f.evidence.map((e) => (
                <li key={`${f.id}-${e.n}-${e.detail}`}>
                  <button type="button" className="text-left text-sm text-accent underline" onClick={() => onPacket(e.n)}>
                    Packet {e.n}
                  </button>
                  <span className="text-sm text-muted"> — {e.detail}</span>
                </li>
              ))}
            </ul>
          </div>
        </article>
      ))}
    </div>
  );
}

export function MatrixView({ findings, onTechnique }: { findings: Finding[]; onTechnique: (id: string) => void }) {
  const [domain, setDomain] = useState<"ics" | "enterprise">("ics");
  const [onlyHit, setOnlyHit] = useState(false);
  const heat = useMemo(() => heatMap(findings), [findings]);
  const tactics = tacticsFor(domain);
  return (
    <div className="flex min-h-0 flex-1 flex-col" data-tour="attack">
      <div className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-2 text-sm">
        <button type="button" className={`rounded-full px-3 py-1 ${domain === "ics" ? "bg-accent text-[var(--accent-ink)]" : "bg-raise"}`} onClick={() => setDomain("ics")}>ICS</button>
        <button type="button" className={`rounded-full px-3 py-1 ${domain === "enterprise" ? "bg-accent text-[var(--accent-ink)]" : "bg-raise"}`} onClick={() => { setDomain("enterprise"); setOnlyHit(true); }}>Enterprise</button>
        <button type="button" className="rounded-full bg-raise px-3 py-1" onClick={() => setOnlyHit((v) => !v)}>{onlyHit ? "Showing triggered" : "Showing full matrix"}</button>
        <span className="text-xs text-muted">ATT&CK {ATTACK_SOURCE.attackVersion} · spec {ATTACK_SOURCE.attackSpecVersion}</span>
      </div>
      <div className="flex gap-2 overflow-auto p-3">
        {tactics.map((tactic) => {
          const techs = techniquesIn(domain, tactic.shortname)
            .map((t) => ({ t, sev: heat.get(t.id) ?? null }))
            .filter((item) => !onlyHit || item.sev)
            .sort((a, b) => (b.sev ? SEVERITY_RANK[b.sev] : -1) - (a.sev ? SEVERITY_RANK[a.sev] : -1));
          return (
            <div key={tactic.id} className="w-52 shrink-0">
              <h3 className="sticky top-0 bg-bg pb-2 text-xs font-medium uppercase tracking-wide" title={tactic.description}>{tactic.name}</h3>
              <div className="space-y-1">
                {techs.length === 0 && <p className="text-xs text-faint">Nothing in this column.</p>}
                {techs.map(({ t, sev }) => (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => onTechnique(t.id)}
                    className={`sev-${sev ?? "info"} block w-full rounded-lg border border-line px-2 py-1 text-left text-xs`}
                    style={sev ? { background: "color-mix(in srgb, var(--mark) 28%, var(--surface))", borderColor: "var(--mark)" } : undefined}
                    data-sev={sev ?? ""}
                  >
                    <span className={`sev-${sev ?? "info"} font-mono`}>{t.id}</span>
                    <span className="mt-0.5 block text-ink">{t.name}</span>
                  </button>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function heatMap(findings: Finding[]): Map<string, Severity> {
  const map = new Map<string, Severity>();
  const paint = (id: string, sev: Severity) => {
    const prev = map.get(id);
    map.set(id, prev ? worse(prev, sev) : sev);
  };
  for (const f of findings) {
    if (f.severity === "info") continue;
    for (const id of f.techniques) {
      paint(id, f.severity);
      const parent = getTechnique(id)?.parent;
      if (parent) paint(parent, f.severity);
      for (const sub of subsOf(id)) if (f.techniques.includes(sub.id)) paint(id, f.severity);
    }
  }
  return map;
}

export function Tables({ analysis, onFilter }: { analysis: Analysis; onFilter: (expr: string) => void }) {
  const [which, setWhich] = useState<"talk" | "ends" | "hier" | "time" | "objects">("talk");
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex gap-2 overflow-auto border-b border-line px-3 py-2 text-sm">
        {([
          ["talk", "Conversations"],
          ["ends", "Endpoints"],
          ["hier", "Protocols"],
          ["time", "Timeline"],
          ["objects", "DNS, web, files"],
        ] as const).map(([id, label]) => (
          <button key={id} type="button" className={`rounded-full px-3 py-1 ${which === id ? "bg-accent text-[var(--accent-ink)]" : "bg-raise"}`} onClick={() => setWhich(id)}>{label}</button>
        ))}
      </div>
      <div className="min-h-0 flex-1 overflow-auto p-3">
        {which === "talk" && (
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase text-muted"><tr><th>A</th><th>B</th><th>Proto</th><th>Packets</th><th>Bytes</th></tr></thead>
            <tbody>
              {analysis.conversations.map((c) => (
                <tr key={`${c.proto}-${c.a}-${c.aPort}-${c.b}-${c.bPort}`} className="border-t border-line">
                  <td className="py-1 font-mono">{c.a}{c.aPort ? `:${c.aPort}` : ""}</td>
                  <td className="font-mono">{c.b}{c.bPort ? `:${c.bPort}` : ""}</td>
                  <td>{c.proto}</td>
                  <td>{c.packets}</td>
                  <td>
                    <button type="button" className="text-accent underline" onClick={() => onFilter(conversationFilter(c))}>{c.bytes.toLocaleString()}</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {which === "ends" && (
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase text-muted"><tr><th>Address</th><th>Kind</th><th>Sent</th><th>Received</th></tr></thead>
            <tbody>
              {analysis.endpoints.filter((e) => e.kind === "ip").map((e) => (
                <tr key={e.addr} className="border-t border-line">
                  <td className="py-1 font-mono">{e.addr}{analysis.names[e.addr] ? ` (${analysis.names[e.addr]})` : ""}</td>
                  <td>{e.kind}</td>
                  <td>{e.bytesSent.toLocaleString()}</td>
                  <td><button type="button" className="text-accent underline" onClick={() => onFilter(`ip.addr == ${e.addr}`)}>{e.bytesRecv.toLocaleString()}</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {which === "hier" && <Hier nodes={analysis.hierarchy} total={analysis.hierarchy[0]?.packets || 1} />}
        {which === "time" && <Timeline analysis={analysis} />}
        {which === "objects" && <Objects analysis={analysis} />}
      </div>
    </div>
  );
}

function conversationFilter(c: { a: string; b: string; proto: string; aPort: number; bPort: number }): string {
  const addr = `ip.addr == ${c.a} && ip.addr == ${c.b}`;
  if (c.proto === "TCP" && (c.aPort || c.bPort)) return `${addr} && (tcp.port == ${c.aPort} || tcp.port == ${c.bPort})`;
  if (c.proto === "UDP" && (c.aPort || c.bPort)) return `${addr} && (udp.port == ${c.aPort} || udp.port == ${c.bPort})`;
  return addr;
}

function Hier({ nodes, total }: { nodes: Analysis["hierarchy"]; total: number }) {
  return (
    <ul className="space-y-1 text-sm">
      {nodes.map((node) => (
        <li key={node.name}>
          <div className="flex items-center gap-2">
            <span className="w-28">{node.name}</span>
            <span className="h-2 rounded-full bg-accent" style={{ width: `${Math.max(4, (node.packets / total) * 180)}px` }} />
            <span className="text-muted">{node.packets.toLocaleString()} pkts · {node.bytes.toLocaleString()} B</span>
          </div>
          {node.children.length > 0 && <div className="ml-4 mt-1"><Hier nodes={node.children} total={total} /></div>}
        </li>
      ))}
    </ul>
  );
}

function Timeline({ analysis }: { analysis: Analysis }) {
  const buckets = analysis.timeline;
  const max = Math.max(...buckets.map((b) => b.packets), 1);
  return (
    <div>
      <p className="mb-2 text-sm text-muted">Packets across the capture. Taller bars are busier moments.</p>
      <div className="flex h-48 items-end gap-px">
        {buckets.map((b, i) => (
          <div key={i} title={`${new Date(b.t * 1000).toISOString()} · ${b.packets} packets`} className="flex-1 rounded-t bg-accent" style={{ height: `${Math.max(2, (b.packets / max) * 100)}%`, opacity: 0.45 + (b.packets / max) * 0.55 }} />
        ))}
      </div>
    </div>
  );
}

function Objects({ analysis }: { analysis: Analysis }) {
  return (
    <div className="space-y-6 text-sm">
      <section>
        <h3 className="font-medium">DNS</h3>
        <ul className="mt-1 space-y-1 font-mono text-xs">
          {analysis.dns.slice(0, 40).map((d) => <li key={`${d.n}-${d.name}`}>{d.name}{d.answer ? ` → ${d.answer}` : ""}</li>)}
          {analysis.dns.length === 0 && <li className="text-muted">No DNS queries.</li>}
        </ul>
      </section>
      <section>
        <h3 className="font-medium">HTTP</h3>
        <ul className="mt-1 space-y-1">
          {analysis.http.slice(0, 40).map((h) => <li key={h.n}>{h.method || h.status} {h.host}{h.path} {h.auth && <em className="text-accent">credentials visible</em>}</li>)}
          {analysis.http.length === 0 && <li className="text-muted">No HTTP.</li>}
        </ul>
      </section>
      <section>
        <h3 className="font-medium">TLS names and certificates</h3>
        <ul className="mt-1 space-y-1">
          {analysis.tls.slice(0, 40).map((t) => <li key={t.n}>{t.sni || "handshake"}{t.subject ? ` · subject ${t.subject}` : ""}{t.issuer ? ` · issuer ${t.issuer}` : ""}</li>)}
          {analysis.tls.length === 0 && <li className="text-muted">No TLS handshakes with a readable name.</li>}
        </ul>
      </section>
      <section>
        <h3 className="font-medium">Files</h3>
        <ul className="mt-1 space-y-1">
          {analysis.files.map((f) => (
            <li key={f.id}>
              <button type="button" className="text-accent underline" onClick={() => downloadFile(f.name, f.data, f.type)}>{f.name}</button>
              <span className="text-muted"> · {f.type} · {f.size} bytes · packet {f.n} · {f.source}</span>
            </li>
          ))}
          {analysis.files.length === 0 && <li className="text-muted">No HTTP bodies or obvious file signatures.</li>}
        </ul>
      </section>
    </div>
  );
}

function downloadFile(name: string, data: Uint8Array, type: string) {
  const copy = new Uint8Array(data.byteLength);
  copy.set(data);
  const url = URL.createObjectURL(new Blob([copy], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

export function TechniqueDialog({ id, findings, onClose }: { id: string | null; findings: Finding[]; onClose: () => void }) {
  return (
    <Modal open={!!id} onOpenChange={(open) => !open && onClose()} title={id ? techniqueLabel(id) : "Technique"} wide>
      {id && <TechniqueBody id={id} findings={findings} />}
    </Modal>
  );
}
