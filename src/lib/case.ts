import { invoke } from "@tauri-apps/api/core";

/** Desktop-only case calls. The browser build never reaches these. */

export function inDesktop(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export interface ImportedCase {
  caseId: string;
  evidenceId: string;
  sha256: string;
  sourceSha256: string;
  storedPath: string;
  caseDir: string;
  sizeBytes: number;
  format: string;
  originalName: string;
}

export interface EngineProgress {
  engine: string;
  state: string;
  detail?: string;
}

async function bytesOf(value: ArrayBuffer | number[]): Promise<ArrayBuffer> {
  if (value instanceof ArrayBuffer) return value;
  return Uint8Array.from(value).buffer;
}

export async function importEvidence(path: string, name: string, investigator: string): Promise<ImportedCase> {
  return invoke<ImportedCase>("import_evidence", { path, name, investigator });
}

export async function readCapture(path: string): Promise<ArrayBuffer> {
  const raw = await invoke<ArrayBuffer | number[]>("read_capture", { path });
  return bytesOf(raw);
}

export async function readSpan(path: string, offset: number, len: number): Promise<ArrayBuffer> {
  const raw = await invoke<ArrayBuffer | number[]>("read_span", { path, offset, len });
  return bytesOf(raw);
}

export async function savePacketIndex(caseId: string, evidenceId: string, rows: unknown[]): Promise<void> {
  const chunk = 4000;
  for (let i = 0; i < rows.length; i += chunk) {
    await invoke("save_packet_index", { caseId, evidenceId, rows: rows.slice(i, i + chunk) });
  }
}

export async function savePackets(caseId: string, evidenceId: string, engine: string, rows: unknown[]): Promise<void> {
  const chunk = 2000;
  for (let i = 0; i < rows.length; i += chunk) {
    await invoke("save_packets", { caseId, evidenceId, engine, rows: rows.slice(i, i + chunk) });
  }
}

export async function saveFindings(caseId: string, evidenceId: string, findings: unknown[]): Promise<void> {
  await invoke("save_findings", { caseId, evidenceId, findings });
}

export async function saveAssets(caseId: string, evidenceId: string, assets: unknown[]): Promise<void> {
  await invoke("save_assets", { caseId, evidenceId, assets });
}

export async function saveFingerprints(caseId: string, evidenceId: string, rows: unknown[]): Promise<void> {
  await invoke("save_fingerprints", { caseId, evidenceId, rows });
}

export async function runEngines(caseId: string, evidenceId: string, storedPath: string): Promise<void> {
  await invoke("run_engines", { caseId, evidenceId, storedPath });
}

export async function setValidation(caseId: string, findingId: string, validation: string, actor: string, note: string): Promise<void> {
  await invoke("set_validation", { caseId, findingId, validation, actor, note });
}

export async function addNote(caseId: string, findingId: string, body: string, author: string): Promise<void> {
  await invoke("add_note", { caseId, findingId, body, author });
}

export async function captureStatus(): Promise<{ available: boolean; npcap: boolean; message: string; url: string }> {
  return invoke("capture_status");
}

export async function listInterfaces(): Promise<string[]> {
  return invoke("list_interfaces");
}

export async function startLiveCapture(iface: string, seconds: number): Promise<string> {
  return invoke("start_live_capture", { iface, seconds });
}

export async function stopLiveCapture(): Promise<string> {
  return invoke("stop_live_capture");
}

export async function engineStatus(): Promise<Record<string, unknown>> {
  return invoke("engine_status");
}
