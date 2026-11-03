import { analyze } from "./analyze.ts";
import { dissect } from "./dissect.ts";
import type { Analysis, CaptureFile, PacketRec } from "./model.ts";
import { gunzipIfNeeded, parseCapture } from "./pcap.ts";

export interface Inspected {
  file: CaptureFile;
  packets: PacketRec[];
  analysis: Analysis;
}

export async function inspectCapture(
  buffer: ArrayBuffer | SharedArrayBuffer,
  progress?: (done: number, total: number, phase: string) => void,
): Promise<Inspected> {
  progress?.(0, 1, "Reading the file");
  await yieldNow();
  const raw = new Uint8Array(buffer);
  const opened = await gunzipIfNeeded(raw);
  const file = parseCapture(opened.bytes);
  if (opened.compressed) file.warnings.unshift("This file was gzip-compressed. Primer unpacked it locally; Wireshark is not required.");
  const total = file.packets.length;
  const packets: PacketRec[] = new Array(total);
  for (let i = 0; i < total; i++) {
    const pkt = file.packets[i];
    const { row } = dissect(pkt.data, { n: pkt.n, ts: pkt.ts, linkType: pkt.linkType }, false);
    row.linkType = pkt.linkType;
    packets[i] = { row, raw: pkt.data };
    if (i % 4000 === 0) {
      progress?.(i, total, "Decoding packets");
      await yieldNow();
    }
  }
  progress?.(total, total, "Looking for suspicious behaviour");
  await yieldNow();
  const analysis = analyze(packets);
  progress?.(total, total, "Done");
  return { file, packets, analysis };
}

function yieldNow(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}
