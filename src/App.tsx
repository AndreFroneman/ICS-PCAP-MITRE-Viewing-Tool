import * as Tabs from "@radix-ui/react-tabs";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AskPanel } from "./components/AskPanel.tsx";
import { AssetMap } from "./components/AssetMap.tsx";
import { AttributionPanel } from "./components/AttributionPanel.tsx";
import { CaseScreen, type CaseFields } from "./components/CaseScreen.tsx";
import { FilterBar, PacketDesk } from "./components/desk.tsx";
import { CursorFollower, HorizonField, Mark } from "./components/horizon.tsx";
import { FindingsView, MatrixView, SummaryBand, Tables, TechniqueDialog } from "./components/insights.tsx";
import { ConversationView, InvestigationOverview, LiveCapture, ReportView, TimelineView } from "./components/investigation.tsx";
import { OtView } from "./components/OtView.tsx";
import { SettingsDialog } from "./components/SettingsDialog.tsx";
import { TriageBar } from "./components/TriageBar.tsx";
import { Button, Menu, MenuItem, Modal, TipProvider } from "./components/ui.tsx";
import { attackReportHtml, attackReportPdf } from "./lib/attackReport.ts";
import { ATTACK_SOURCE } from "./lib/attack.ts";
import { SAMPLES } from "./lib/catalog.ts";
import { conversationsCsv, dnsCsv, endpointsCsv, findingsCsv, httpCsv, packetsCsv, tlsCsv } from "./lib/csv.ts";
import { downloadBytes, downloadText } from "./lib/download.ts";
import { compileFilter } from "./lib/filter.ts";
import { applyDecision, buildDossier, visibleFindings, type ActivityEntry, type FindingFilter } from "./lib/forensic.ts";
import { GLOSSARY } from "./lib/glossary.ts";
import { rememberFolder, rememberedFolder } from "./lib/keys.ts";
import type { Analysis, Row, Severity, TreeNode, ValidationStatus } from "./lib/model.ts";
import { navigatorLayer } from "./lib/navigator.ts";
import { reportCaseCsv, reportCaseHtml, reportCaseJson, reportCasePdf } from "./lib/reportCase.ts";
import { reportHtml, reportJson, reportPdf } from "./lib/report.ts";
import type { FollowedStream } from "./lib/stream.ts";

interface Ready {
  name: string;
  format: string;
  linkType: number;
  warnings: string[];
  rows: Row[];
  analysis: Analysis;
}

const NAV = [
  ["overview", "Overview"],
  ["packets", "Packets"],
  ["findings", "Findings"],
  ["attack", "ATT&CK"],
  ["ask", "Ask"],
] as const;

const VIEWS = [
  ["overview", "Overview"],
  ["assets", "Assets"],
  ["packets", "Packets"],
  ["talk", "Talk"],
  ["ot", "OT"],
  ["findings", "Findings"],
  ["attack", "ATT&CK"],
  ["timeline", "Timeline"],
  ["attribution", "Attribution"],
  ["ask", "Ask"],
  ["case", "Case"],
  ["report", "Report"],
] as const;

export default function App() {
  const workerRef = useRef<Worker | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const folderRef = useRef<HTMLInputElement>(null);
  const [menuOpen, setMenuOpen] = useState(false);
  const [phase, setPhase] = useState<"empty" | "loading" | "ready" | "error">("empty");
  const [progress, setProgress] = useState({ done: 0, total: 0, phase: "Starting" });
  const [error, setError] = useState("");
  const [ready, setReady] = useState<Ready | null>(null);
  const [tab, setTab] = useState("packets");
  const [filterText, setFilterText] = useState("");
  const [selected, setSelected] = useState<number | null>(null);
  const [tree, setTree] = useState<TreeNode[]>([]);
  const [bytes, setBytes] = useState<Uint8Array | null>(null);
  const [field, setField] = useState<TreeNode | null>(null);
  const [stream, setStream] = useState<FollowedStream | null>(null);
  const [streamOpen, setStreamOpen] = useState(false);
  const [techId, setTechId] = useState<string | null>(null);
  const [glossary, setGlossary] = useState(false);
  const [settings, setSettings] = useState(false);
  const [glossQuery, setGlossQuery] = useState("");
  const [tour, setTour] = useState<number | null>(null);
  const [drag, setDrag] = useState(false);
  const [folderFiles, setFolderFiles] = useState<File[]>([]);
  const [clock, setClock] = useState("--:--:--");
  const [engineLine, setEngineLine] = useState("");
  const [findingMode, setFindingMode] = useState<FindingFilter>("ot");
  const [activityLog, setActivityLog] = useState<ActivityEntry[]>([]);
  const [liveOpen, setLiveOpen] = useState(false);
  const [caseFields, setCaseFields] = useState<CaseFields>({
    name: "",
    investigator: "",
    organisation: "",
    sha256: "",
    storedPath: "",
    note: "",
  });
  const caseRef = useRef<{ caseId: string; evidenceId: string; storedPath: string; sha256: string } | null>(null);

  useEffect(() => {
    folderRef.current?.setAttribute("webkitdirectory", "");
    folderRef.current?.setAttribute("directory", "");
  }, []);

  useEffect(() => {
    const tick = () => setClock(new Date().toLocaleTimeString("en-ZA", { hour12: false, timeZone: "Africa/Johannesburg" }));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    const worker = new Worker(new URL("./worker/parser.worker.ts", import.meta.url), { type: "module" });
    workerRef.current = worker;
    worker.onmessage = (event: MessageEvent) => {
      const msg = event.data as {
        type: string; done?: number; total?: number; phase?: string; message?: string; name?: string;
        format?: string; linkType?: number; warnings?: string[]; rows?: Row[]; analysis?: Analysis;
        tree?: TreeNode[]; bytes?: Uint8Array; stream?: FollowedStream | null;
        n?: number; offset?: number; len?: number;
        spans?: { n: number; ts: number; fileOffset: number; capLen: number; origLen: number; linkType: number }[];
        engine?: string; state?: string; detail?: string;
      };
      if (msg.type === "progress") setProgress({ done: msg.done ?? 0, total: msg.total ?? 0, phase: msg.phase ?? "" });
      if (msg.type === "error") {
        setPhase("error");
        setError(msg.message ?? "Could not read that file.");
      }
      if (msg.type === "ready" && msg.rows && msg.analysis) {
        setReady({
          name: msg.name ?? "capture",
          format: msg.format ?? "pcap",
          linkType: msg.linkType ?? 1,
          warnings: msg.warnings ?? [],
          rows: msg.rows,
          analysis: msg.analysis,
        });
        setSelected(msg.rows[0]?.n ?? null);
        setTree([]);
        setBytes(null);
        setField(null);
        setFilterText("");
        setTab("packets");
        setPhase("ready");
      }
      if (msg.type === "dissection" && msg.tree && msg.bytes) {
        setTree(msg.tree);
        setBytes(msg.bytes);
        setField(msg.tree[0] ?? null);
      }
      if (msg.type === "stream") {
        setStream(msg.stream ?? null);
        setStreamOpen(true);
      }
      if (msg.type === "need-bytes" && msg.n && caseRef.current) {
        const wanted = msg.n;
        const offset = msg.offset ?? 0;
        const len = msg.len ?? 0;
        const stored = caseRef.current.storedPath;
        void import("./lib/case.ts").then(async ({ readSpan }) => {
          const buffer = await readSpan(stored, offset, len);
          worker.postMessage({ type: "bytes", n: wanted, buffer }, [buffer]);
        });
      }
      if (msg.type === "ready" && msg.spans && caseRef.current) {
        const current = caseRef.current;
        const spans = msg.spans;
        const rows = msg.rows ?? [];
        void import("./lib/case.ts").then(async (api) => {
          await api.savePacketIndex(current.caseId, current.evidenceId, spans.map((span) => ({
            n: span.n, ts: span.ts, fileOffset: span.fileOffset, capLen: span.capLen, origLen: span.origLen, linkType: span.linkType,
          })));
          await api.savePackets(current.caseId, current.evidenceId, "primer", rows.map((row) => ({
            n: row.n, ts: row.ts, len: row.len, macSrc: row.macSrc, macDst: row.macDst, src: row.src, dst: row.dst,
            sp: row.sp, dp: row.dp, ipProto: row.ipProto, proto: row.proto, info: row.info, layers: row.layers, appJson: "{}",
          })));
          setEngineLine("Case saved. Background decoders run without blocking the list.");
          await api.runEngines(current.caseId, current.evidenceId, current.storedPath);
        }).catch((error: unknown) => {
          setEngineLine(error instanceof Error ? error.message : "The case file could not be saved.");
        });
      }
    };
    return () => worker.terminate();
  }, []);

  useEffect(() => {
    if (phase === "ready" && selected != null) workerRef.current?.postMessage({ type: "dissect", n: selected });
  }, [phase, selected, ready?.name]);

  const parseBuffer = useCallback((buffer: ArrayBuffer, name: string, releaseBytes = false) => {
    setPhase("loading");
    setError("");
    setProgress({ done: 0, total: 1, phase: "Reading the file" });
    workerRef.current?.postMessage({ type: "parse", buffer, name, releaseBytes }, [buffer]);
  }, []);

  const onFiles = useCallback((files: FileList | File[]) => {
    const file = [...files].find((item) => /\.(pcap|pcapng|cap|dmp|gz)$/i.test(item.name)) ?? files[0];
    if (!file) return;
    void file.arrayBuffer().then((buffer) => parseBuffer(buffer, file.name));
  }, [parseBuffer]);

  useEffect(() => {
    const onDrag = (event: DragEvent) => { event.preventDefault(); setDrag(true); };
    const onLeave = () => setDrag(false);
    const onDrop = (event: DragEvent) => {
      event.preventDefault();
      setDrag(false);
      if (event.dataTransfer?.files?.length) onFiles(event.dataTransfer.files);
    };
    window.addEventListener("dragover", onDrag);
    window.addEventListener("dragleave", onLeave);
    window.addEventListener("drop", onDrop);
    return () => {
      window.removeEventListener("dragover", onDrag);
      window.removeEventListener("dragleave", onLeave);
      window.removeEventListener("drop", onDrop);
    };
  }, [onFiles]);

  const compiled = useMemo(() => {
    try { return { filter: compileFilter(filterText), error: "" }; }
    catch (err) { return { filter: null, error: err instanceof Error ? err.message : "That filter could not be read." }; }
  }, [filterText]);

  const shown = useMemo(() => {
    if (!ready) return [];
    if (!compiled.filter) return ready.rows;
    return ready.rows.filter((row) => compiled.filter?.test(row, ready.analysis.t0));
  }, [ready, compiled]);

  const dossier = useMemo(() => (ready ? buildDossier(ready.rows, ready.analysis) : null), [ready]);
  const stampedFindings = useMemo(() => {
    if (!dossier) return [];
    return dossier.findings.map((finding) => {
      const decision = activityLog.find((entry) => entry.detail.startsWith(finding.id) && ["approved", "rejected", "escalated"].includes(entry.action));
      if (!decision) return finding;
      return { ...finding, validation: decision.action as ValidationStatus, validatedBy: decision.actor, validatedAt: decision.at };
    });
  }, [dossier, activityLog]);
  const shownFindings = useMemo(() => visibleFindings(stampedFindings, findingMode), [stampedFindings, findingMode]);

  const onDecide = (id: string, validation: ValidationStatus) => {
    const at = new Date().toISOString();
    const actor = caseFields.investigator || "Investigator";
    const next = applyDecision(stampedFindings, activityLog, { findingId: id, validation, actor, at, note: "" });
    setActivityLog(next.log);
    const current = caseRef.current;
    if (current) {
      void import("./lib/case.ts").then((api) => api.setValidation(current.caseId, id, validation, actor, ""));
    }
  };

  const marks = useMemo(() => {
    const map = new Map<number, Severity>();
    for (const mark of ready?.analysis.marks ?? []) map.set(mark.n, mark.severity);
    return map;
  }, [ready]);

  const loadSample = (file: string) => {
    setPhase("loading");
    void fetch(`/samples/${file}`).then((res) => {
      if (!res.ok) throw new Error("Sample missing");
      return res.arrayBuffer();
    }).then((buffer) => parseBuffer(buffer, file)).catch(() => {
      setPhase("error");
      setError("That sample could not be loaded from this app.");
    });
  };

  const jump = (n: number) => { setSelected(n); setTab("packets"); setMenuOpen(false); };

  const exportReport = (kind: string) => {
    if (!ready) return;
    const meta = { fileName: ready.name, packetCount: ready.rows.length, generatedAt: new Date().toISOString() };
    const stem = ready.name.replace(/\.(pcap|pcapng)$/i, "");
    if (kind === "json") downloadText(`${stem}.findings.json`, reportJson(meta, ready.analysis), "application/json");
    if (kind === "html") downloadText(`${stem}.findings.html`, reportHtml(meta, ready.analysis), "text/html");
    if (kind === "pdf") downloadBytes(`${stem}.findings.pdf`, reportPdf(meta, ready.analysis), "application/pdf");
    if (kind === "attack-html") downloadText(`${stem}.attack.html`, attackReportHtml(ready.name, ready.analysis, ready.rows), "text/html");
    if (kind === "attack-pdf") downloadBytes(`${stem}.attack.pdf`, attackReportPdf(ready.name, ready.analysis, ready.rows), "application/pdf");
    if (kind === "nav-ics") downloadText(`${stem}.ics.layer.json`, navigatorLayer(ready.name, "ics", ready.analysis.findings), "application/json");
    if (kind === "nav-ent") downloadText(`${stem}.enterprise.layer.json`, navigatorLayer(ready.name, "enterprise", ready.analysis.findings), "application/json");
    if (kind === "csv-packets") downloadText(`${stem}.packets.csv`, packetsCsv(shown, ready.analysis.t0), "text/csv");
    if (kind === "csv-talk") downloadText(`${stem}.conversations.csv`, conversationsCsv(ready.analysis), "text/csv");
    if (kind === "csv-ends") downloadText(`${stem}.endpoints.csv`, endpointsCsv(ready.analysis), "text/csv");
    if (kind === "csv-dns") downloadText(`${stem}.dns.csv`, dnsCsv(ready.analysis), "text/csv");
    if (kind === "csv-http") downloadText(`${stem}.http.csv`, httpCsv(ready.analysis), "text/csv");
    if (kind === "csv-tls") downloadText(`${stem}.tls.csv`, tlsCsv(ready.analysis), "text/csv");
    if (kind === "csv-findings") downloadText(`${stem}.findings.csv`, findingsCsv(ready.analysis.findings), "text/csv");
    if (dossier && (kind === "case-html" || kind === "case-pdf" || kind === "case-json" || kind === "case-csv")) {
      const reportMeta = {
        caseName: caseFields.name || ready.name,
        fileName: ready.name,
        sha256: caseFields.sha256,
        packetCount: ready.rows.length,
        generatedAt: new Date().toISOString(),
        investigator: caseFields.investigator,
        captureClock: "UTC",
      };
      if (kind === "case-html") downloadText(`${stem}.investigation.html`, reportCaseHtml(reportMeta, dossier), "text/html");
      if (kind === "case-pdf") downloadBytes(`${stem}.investigation.pdf`, reportCasePdf(reportMeta, dossier), "application/pdf");
      if (kind === "case-json") downloadText(`${stem}.investigation.json`, reportCaseJson(reportMeta, dossier), "application/json");
      if (kind === "case-csv") downloadText(`${stem}.investigation.csv`, reportCaseCsv(dossier), "text/csv");
    }
  };

  const openDesktopPath = useCallback(async (path: string) => {
    const api = await import("./lib/case.ts");
    const imported = await api.importEvidence(path, path.split(/[/\\]/).pop() ?? "capture", caseFields.investigator || "Investigator");
    caseRef.current = { caseId: imported.caseId, evidenceId: imported.evidenceId, storedPath: imported.storedPath, sha256: imported.sha256 };
    setCaseFields((fields) => ({
      ...fields,
      name: fields.name || imported.originalName,
      sha256: imported.sha256,
      storedPath: imported.storedPath,
    }));
    setEngineLine("Evidence copied and hashed. Reading the packet list.");
    const buffer = await api.readCapture(imported.storedPath);
    parseBuffer(buffer, imported.originalName, imported.sizeBytes > 32 * 1024 * 1024);
  }, [caseFields.investigator, parseBuffer]);

  const openedStartup = useRef(false);
  useEffect(() => {
    if (openedStartup.current || !("__TAURI_INTERNALS__" in window)) return;
    openedStartup.current = true;
    void import("@tauri-apps/api/core").then(async ({ invoke }) => {
      const path = await invoke<string | null>("startup_capture");
      if (!path) return;
      await openDesktopPath(path);
    });
  }, [openDesktopPath]);

  const openDesktopFolder = async () => {
    if (!("__TAURI_INTERNALS__" in window)) {
      folderRef.current?.click();
      return;
    }
    const dialog = await import("@tauri-apps/plugin-dialog");
    const { invoke } = await import("@tauri-apps/api/core");
    const chosen = await dialog.open({ directory: true, multiple: false, defaultPath: rememberedFolder() });
    if (typeof chosen !== "string") return;
    rememberFolder(chosen);
    const captures = await invoke<string[]>("list_captures", { dir: chosen });
    if (!captures.length) {
      setError(`No captures in ${chosen}`);
      setPhase(ready ? "ready" : "error");
      return;
    }
    const path = captures[0];
    if (!path) return;
    await openDesktopPath(path);
  };

  const gloss = GLOSSARY.filter((entry) => `${entry.term} ${entry.body}`.toLowerCase().includes(glossQuery.toLowerCase()));
  const findingCount = ready?.analysis.findings.filter((f) => f.severity !== "info").length ?? 0;

  return (
    <TipProvider>
      <HorizonField />
      <CursorFollower />
      <div className="app-shell">
        <header className="hz-nav">
          <a className="brand" href="#top" onClick={(event) => { event.preventDefault(); if (!ready) setPhase("empty"); }}>
            <Mark />
            <span>PRIMER<small>HORIZON · OT CYBER</small></span>
          </a>
          <button type="button" className="burger" onClick={() => setMenuOpen((v) => !v)}>MENU</button>
          <ul className={`nav-links ${menuOpen ? "open" : ""}`}>
            {NAV.map(([id, label]) => (
              <li key={id}><button type="button" className={tab === id && phase === "ready" ? "on" : ""} onClick={() => { if (phase === "ready") { setTab(id); setMenuOpen(false); } }}>{label}{id === "findings" && findingCount ? ` ${findingCount}` : ""}</button></li>
            ))}
          </ul>
          <div className="nav-actions" data-tour="open">
            <input ref={fileRef} type="file" accept=".pcap,.pcapng,.cap,.gz,.dmp,.pcap.gz,.pcapng.gz" className="hidden" onChange={(e) => e.target.files && onFiles(e.target.files)} />
            <input ref={folderRef} type="file" className="hidden" multiple onChange={(event) => {
              const files = [...(event.target.files ?? [])].filter((file) => /\.(pcap|pcapng|cap|dmp|gz)$/i.test(file.name));
              const folder = files[0]?.webkitRelativePath.split("/")[0];
              if (folder) rememberFolder(folder);
              setFolderFiles(files);
            }} />
            <Button type="button" variant="solid" onClick={() => fileRef.current?.click()}>Open</Button>
            <Menu label={<Button type="button">Samples</Button>}>
              {SAMPLES.map((sample) => <MenuItem key={sample.file} onSelect={() => loadSample(sample.file)}>{sample.title}</MenuItem>)}
              <MenuItem onSelect={() => { setPhase("loading"); workerRef.current?.postMessage({ type: "large", count: 100_000 }); }}>100,000 synthetic packets</MenuItem>
            </Menu>
            <span data-tour="export">
              <Menu label={<Button type="button" disabled={!ready}>Export</Button>}>
                <MenuItem onSelect={() => exportReport("attack-html")}>ATT&CK report HTML</MenuItem>
                <MenuItem onSelect={() => exportReport("attack-pdf")}>ATT&CK report PDF</MenuItem>
                <MenuItem onSelect={() => exportReport("nav-ics")}>Navigator layer · ICS</MenuItem>
                <MenuItem onSelect={() => exportReport("nav-ent")}>Navigator layer · Enterprise</MenuItem>
                <MenuItem onSelect={() => exportReport("html")}>Findings HTML</MenuItem>
                <MenuItem onSelect={() => exportReport("pdf")}>Findings PDF</MenuItem>
                <MenuItem onSelect={() => exportReport("json")}>Findings JSON</MenuItem>
                <MenuItem onSelect={() => exportReport("csv-packets")}>Packets CSV (current filter)</MenuItem>
                <MenuItem onSelect={() => exportReport("csv-talk")}>Conversations CSV</MenuItem>
                <MenuItem onSelect={() => exportReport("csv-ends")}>Endpoints CSV</MenuItem>
                <MenuItem onSelect={() => exportReport("csv-dns")}>DNS CSV</MenuItem>
                <MenuItem onSelect={() => exportReport("csv-http")}>HTTP CSV</MenuItem>
                <MenuItem onSelect={() => exportReport("csv-tls")}>TLS CSV</MenuItem>
                <MenuItem onSelect={() => exportReport("csv-findings")}>Findings CSV</MenuItem>
              </Menu>
            </span>
            <Button type="button" onClick={() => void openDesktopFolder()}>Folder</Button>
            <Button type="button" onClick={() => setSettings(true)}>Settings</Button>
          </div>
        </header>

        {phase === "empty" && <Empty onOpen={() => fileRef.current?.click()} onSample={loadSample} drag={drag} onTour={() => setTour(0)} onGlossary={() => setGlossary(true)} onLive={() => setLiveOpen(true)} />}
        {phase === "loading" && (
          <div className="grid flex-1 place-items-center p-8">
            <div className="w-full max-w-md">
              <p className="eyebrow">Decoder</p>
              <p className="display mt-3 text-4xl">{progress.phase}</p>
              <p className="mt-2 text-muted">{progress.total ? `${progress.done.toLocaleString()} / ${progress.total.toLocaleString()}` : "Local worker"}</p>
              <div className="mt-4 h-0.5 bg-line"><div className="h-full bg-accent" style={{ width: `${progress.total ? Math.min(100, (progress.done / progress.total) * 100) : 12}%` }} /></div>
            </div>
          </div>
        )}
        {phase === "error" && (
          <div className="grid flex-1 place-items-center p-8 text-center">
            <div>
              <p className="display text-4xl">File not opened</p>
              <p className="mt-3 text-muted">{error}</p>
              <Button className="mt-4" variant="solid" type="button" onClick={() => { setPhase("empty"); setError(""); }}>Back</Button>
            </div>
          </div>
        )}
        {phase === "ready" && ready && (
          <Tabs.Root value={tab} onValueChange={setTab} className="flex min-h-0 flex-1 flex-col">
            <SummaryBand analysis={ready.analysis} onFinding={() => setTab("findings")} />
            {dossier && <TriageBar triage={dossier.triage} />}
            <div className="flex gap-3 overflow-x-auto border-b border-line px-4 py-2 font-mono text-[11px] tracking-[0.14em]">
              {VIEWS.map(([id, label]) => (
                <button key={id} type="button" className={tab === id ? "text-accent" : "text-muted"} onClick={() => setTab(id)}>{label}</button>
              ))}
            </div>
            <div className="hud-line border-b border-line px-4 py-2 text-[11px]">
              <span>FILE <b>{ready.name}</b></span>
              <span>PKTS <b>{ready.rows.length.toLocaleString()}</b></span>
              <span>ATT&CK <b>{ATTACK_SOURCE.attackVersion}</b></span>
              <span>SAST <b>{clock}</b></span>
              <span>MODE <b>LOCAL</b></span>
              {caseFields.sha256 && <span>SHA <b>{caseFields.sha256.slice(0, 12)}</b></span>}
              {engineLine && <span>{engineLine}</span>}
            </div>
            <Tabs.Content value="packets" className="flex min-h-[70vh] flex-1 flex-col outline-none lg:min-h-0">
              <FilterBar value={filterText} error={compiled.error} shown={compiled.filter ? shown.length : ready.rows.length} total={ready.rows.length} onChange={setFilterText} />
              <PacketDesk
                rows={shown}
                active={ready.rows.find((row) => row.n === selected) ?? null}
                names={ready.analysis.names}
                t0={ready.analysis.t0}
                marks={marks}
                selected={selected}
                onSelect={setSelected}
                tree={tree}
                bytes={bytes}
                field={field}
                onField={setField}
                onFilter={(expr, add) => setFilterText((prev) => (add && prev.trim() ? `${prev} && ${expr}` : expr))}
                onFollow={() => selected != null && workerRef.current?.postMessage({ type: "stream", n: selected })}
              />
            </Tabs.Content>
            <Tabs.Content value="findings" className="min-h-0 flex-1 overflow-auto outline-none">
              <div className="flex gap-2 px-4 pt-3">
                <button type="button" className={`hz-btn hz-sm ${findingMode === "ot" ? "hz-solid" : ""}`} onClick={() => setFindingMode("ot")}>Industrial</button>
                <button type="button" className={`hz-btn hz-sm ${findingMode === "signatures" ? "hz-solid" : ""}`} onClick={() => setFindingMode("signatures")}>Signature hits</button>
                <button type="button" className={`hz-btn hz-sm ${findingMode === "all" ? "hz-solid" : ""}`} onClick={() => setFindingMode("all")}>All</button>
              </div>
              <FindingsView findings={shownFindings} onPacket={jump} onTechnique={setTechId} onDecide={onDecide} />
            </Tabs.Content>
            <Tabs.Content value="attack" className="flex min-h-0 flex-1 flex-col outline-none" data-tour="attack">
              <MatrixView findings={ready.analysis.findings} onTechnique={setTechId} />
            </Tabs.Content>
            <Tabs.Content value="overview" className="flex min-h-0 flex-1 flex-col outline-none">
              {dossier && <InvestigationOverview dossier={dossier} headline={ready.analysis.headline} onPacket={jump} />}
              <Tables analysis={ready.analysis} onFilter={(expr) => { setFilterText(expr); setTab("packets"); }} />
            </Tabs.Content>
            <Tabs.Content value="assets" className="min-h-0 flex-1 overflow-auto outline-none">
              {dossier && <AssetMap assets={dossier.assets} onPacket={jump} />}
            </Tabs.Content>
            <Tabs.Content value="talk" className="min-h-0 flex-1 overflow-auto outline-none">
              {dossier && <ConversationView dossier={dossier} onFilter={(expr) => { setFilterText(expr); setTab("packets"); }} />}
            </Tabs.Content>
            <Tabs.Content value="ot" className="min-h-0 flex-1 overflow-auto outline-none">
              {dossier && <OtView dossier={dossier} onPacket={jump} />}
            </Tabs.Content>
            <Tabs.Content value="timeline" className="min-h-0 flex-1 overflow-auto outline-none">
              <TimelineView findings={stampedFindings} onPacket={jump} />
            </Tabs.Content>
            <Tabs.Content value="attribution" className="min-h-0 flex-1 overflow-auto outline-none">
              {dossier && <AttributionPanel fingerprints={dossier.fingerprints} onPacket={jump} />}
            </Tabs.Content>
            <Tabs.Content value="case" className="min-h-0 flex-1 overflow-auto outline-none">
              {dossier && (
                <CaseScreen
                  fields={caseFields}
                  onChange={setCaseFields}
                  dossier={dossier}
                  findings={stampedFindings}
                  activity={activityLog}
                  onAddNote={() => {
                    if (!caseFields.note.trim()) return;
                    const at = new Date().toISOString();
                    setActivityLog((log) => [...log, { at, actor: caseFields.investigator || "Investigator", action: "note", detail: caseFields.note.trim() }]);
                    const current = caseRef.current;
                    if (current) {
                      void import("./lib/case.ts").then((api) => api.addNote(current.caseId, "", caseFields.note.trim(), caseFields.investigator || "Investigator"));
                    }
                    setCaseFields((fields) => ({ ...fields, note: "" }));
                  }}
                />
              )}
            </Tabs.Content>
            <Tabs.Content value="report" className="min-h-0 flex-1 overflow-auto outline-none">
              <ReportView onExport={exportReport} />
            </Tabs.Content>
            <Tabs.Content value="ask" className="flex min-h-0 flex-1 flex-col outline-none">
              <AskPanel ctx={{ fileName: ready.name, rows: ready.rows, analysis: ready.analysis }} onPacket={jump} />
            </Tabs.Content>
          </Tabs.Root>
        )}

        {drag && <div className="pointer-events-none fixed inset-6 z-30 grid place-items-center border border-dashed border-accent bg-black/70 text-xl tracking-[0.2em]">DROP CAPTURE</div>}

        <Modal open={streamOpen} onOpenChange={setStreamOpen} title={stream?.title ?? "Stream"} wide>
          {stream && stream.messages.length === 0 && <p className="text-sm text-muted">This conversation has no payload bytes. The handshake may be all that was saved.</p>}
          <div className="space-y-2">
            {stream?.messages.map((message) => (
              <div key={message.n} className={`max-w-[90%] border border-line px-3 py-2 text-sm ${message.from === stream.a ? "" : "ml-auto"}`}>
                {message.gap && <p className="text-xs text-amber-400">Sequence gap</p>}
                <p className="font-mono text-xs text-muted">{message.from} · packet {message.n} · {message.bytes} bytes</p>
                <pre className="mt-1 whitespace-pre-wrap font-mono text-xs">{message.text}</pre>
              </div>
            ))}
          </div>
        </Modal>
        <Modal open={liveOpen} onOpenChange={setLiveOpen} title="Live capture (optional)" wide>
          <LiveCapture onOpenPath={(path) => { setLiveOpen(false); void openDesktopPath(path); }} />
        </Modal>
        <TechniqueDialog id={techId} findings={stampedFindings} onClose={() => setTechId(null)} />
        <SettingsDialog open={settings} onClose={() => setSettings(false)} onOpenFolder={() => void openDesktopFolder()} />
        <Modal open={glossary} onOpenChange={setGlossary} title="Glossary" wide>
          <input value={glossQuery} onChange={(e) => setGlossQuery(e.target.value)} placeholder="Search" className="hz-field mb-3 w-full" aria-label="Search glossary" />
          <div className="space-y-3">{gloss.map((entry) => <div key={entry.term}><h3 className="display text-lg">{entry.term}</h3><p className="text-sm text-muted">{entry.body}</p></div>)}</div>
        </Modal>
        <Modal open={folderFiles.length > 0} onOpenChange={(open) => !open && setFolderFiles([])} title="Captures in folder">
          <ul className="space-y-2">{folderFiles.map((file) => (
            <li key={file.webkitRelativePath || file.name}><button type="button" className="text-left text-accent" onClick={() => { setFolderFiles([]); onFiles([file]); }}>{file.webkitRelativePath || file.name}</button></li>
          ))}</ul>
        </Modal>
        {tour != null && <TourCard step={tour} onClose={() => setTour(null)} onPrev={() => setTour((n) => Math.max(0, (n ?? 0) - 1))} onNext={() => setTour((n) => (n ?? 0) + 1)} />}
        <div className="ticker" aria-hidden="true"><div className="t"><span>DETECT<em>◆</em>VERIFY<em>◆</em>PROTECT<em>◆</em>SEGMENT<em>◆</em>MONITOR<em>◆</em>RESPOND<em>◆</em>PARSE<em>◆</em>EXPLAIN<em>◆</em>MAP<em>◆</em></span><span>DETECT<em>◆</em>VERIFY<em>◆</em>PROTECT<em>◆</em>SEGMENT<em>◆</em>MONITOR<em>◆</em>RESPOND<em>◆</em>PARSE<em>◆</em>EXPLAIN<em>◆</em>MAP<em>◆</em></span></div></div>
      </div>
    </TipProvider>
  );
}

const TOUR = [
  { id: "open", title: "Open a capture", body: "Drop a pcap, or start with Plant shift. Parsing stays in this browser." },
  { id: "summary", title: "Read the line first", body: "Device count, the main traffic, and how many things look off." },
  { id: "packets", title: "Packet list", body: "A coloured edge means the packet is evidence. The list is virtualised." },
  { id: "filter", title: "Filter", body: "Type modbus.func == 16, or build it from the menus." },
  { id: "ask", title: "Ask the capture", body: "Plain questions are answered from the packet tools, with packet numbers you can open." },
  { id: "attack", title: "ATT&CK", body: "ICS and Enterprise matrices. T0855 is the revoked id; T1692.001 replaced it." },
  { id: "export", title: "Export", body: "HTML, PDF, Navigator layers, and CSV. Built here." },
];

function Empty({ onOpen, onSample, drag, onTour, onGlossary, onLive }: { onOpen: () => void; onSample: (file: string) => void; drag: boolean; onTour: () => void; onGlossary: () => void; onLive: () => void }) {
  return (
    <div className="flex-1 overflow-auto">
      <section className="px-[4vw] pb-10 pt-8">
        <p className="eyebrow">HORIZON · PRIMER · T-HORIZON</p>
        <h1 className="display mt-5 text-[clamp(42px,6vw,84px)]">READ THE<br /><span className="grad">WIRE</span></h1>
        <p className="mt-5 max-w-xl text-xl text-[#b9c9de]">Operational-technology packet analysis for people who are not packet experts. Open a capture locally. Primer explains it, and maps what looks wrong to ATT&CK.</p>
        <div className="mt-8 flex flex-wrap gap-3">
          <Button type="button" variant="solid" onClick={onOpen}>Open capture</Button>
          <Button type="button" onClick={() => onSample("plant-shift.pcap")}>Plant shift</Button>
          <Button type="button" onClick={onLive}>Live capture</Button>
          <Button type="button" onClick={onTour}>Tour</Button>
          <Button type="button" onClick={onGlossary}>Glossary</Button>
        </div>
        <div className="hud-line mt-8"><span>SYS <b>ONLINE</b></span><span>PARSE <b>LOCAL</b></span><span>FOLDER <b>{rememberedFolder()}</b></span></div>
      </section>
      <div className={`mx-[4vw] border border-dashed px-6 py-8 ${drag ? "border-accent" : "border-line"}`}>
        <p className="font-mono text-xs tracking-[0.2em] text-muted">DROP .PCAP OR .PCAPNG · NOTHING IS UPLOADED</p>
      </div>
      <div className="grid gap-4 px-[4vw] py-8 md:grid-cols-2">
        {SAMPLES.map((sample, index) => (
          <button key={sample.file} type="button" onClick={() => onSample(sample.file)} className="card p-5 text-left">
            <span className="corner tl" /><span className="corner br" />
            <span className="font-mono text-[11px] tracking-[0.22em] text-accent">0{index + 1} · {sample.tag}</span>
            <span className="display mt-3 block text-2xl">{sample.title}</span>
            <span className="mt-2 block text-sm text-muted">{sample.blurb}</span>
          </button>
        ))}
      </div>
    </div>
  );
}

function TourCard({ step, onClose, onPrev, onNext }: { step: number; onClose: () => void; onPrev: () => void; onNext: () => void }) {
  const item = TOUR[Math.min(step, TOUR.length - 1)];
  const last = step >= TOUR.length - 1;
  useEffect(() => { document.querySelector(`[data-tour="${item.id}"]`)?.scrollIntoView({ block: "center" }); }, [item.id]);
  return (
    <div className="card fixed bottom-16 right-4 z-40 w-[min(380px,calc(100%-2rem))] p-4">
      <span className="corner tl" /><span className="corner br" />
      <p className="font-mono text-[11px] tracking-[0.18em] text-muted">TOUR {step + 1} / {TOUR.length}</p>
      <h2 className="display mt-2 text-2xl">{item.title}</h2>
      <p className="mt-2 text-sm text-muted">{item.body}</p>
      <div className="mt-4 flex justify-between">
        <Button type="button" variant="ghost" onClick={onClose}>Close</Button>
        <div className="flex gap-2">
          <Button type="button" onClick={onPrev} disabled={step === 0}>Back</Button>
          <Button type="button" variant="solid" onClick={last ? onClose : onNext}>{last ? "Done" : "Next"}</Button>
        </div>
      </div>
    </div>
  );
}
