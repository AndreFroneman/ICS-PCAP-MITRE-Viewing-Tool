import { dissect } from "../lib/dissect.ts";
import { inspectCapture } from "../lib/inspect.ts";
import type { Analysis, Row } from "../lib/model.ts";
import { encodePcap } from "../lib/pcap.ts";
import { generateLarge } from "../lib/scenarios.ts";
import { followStream, type FollowedStream } from "../lib/stream.ts";
import type { PacketRec } from "../lib/model.ts";

let store: PacketRec[] = [];

interface Ready {
  type: "ready";
  name: string;
  format: string;
  linkType: number;
  warnings: string[];
  rows: Row[];
  analysis: Analysis;
}

self.onmessage = (event: MessageEvent) => {
  const msg = event.data as { type: string; buffer?: ArrayBuffer; name?: string; n?: number; count?: number };
  if (msg.type === "parse" && msg.buffer) {
    void runParse(msg.buffer, msg.name ?? "capture");
  } else if (msg.type === "large") {
    void runLarge(msg.count ?? 100_000);
  } else if (msg.type === "dissect" && msg.n) {
    const packet = store.find((p) => p.row.n === msg.n);
    if (!packet) return;
    const { tree } = dissect(packet.raw, { n: packet.row.n, ts: packet.row.ts, linkType: packet.row.linkType }, true);
    self.postMessage({ type: "dissection", n: msg.n, tree, bytes: packet.raw });
  } else if (msg.type === "stream" && msg.n) {
    const stream: FollowedStream | null = followStream(store, msg.n);
    self.postMessage({ type: "stream", stream });
  }
};

async function runParse(buffer: ArrayBuffer, name: string) {
  try {
    const inspected = await inspectCapture(buffer, (done, total, phase) => {
      self.postMessage({ type: "progress", done, total, phase });
    });
    store = inspected.packets;
    const ready: Ready = {
      type: "ready",
      name,
      format: inspected.file.format,
      linkType: inspected.file.linkType,
      warnings: inspected.file.warnings,
      rows: inspected.packets.map((p) => p.row),
      analysis: inspected.analysis,
    };
    self.postMessage(ready);
  } catch (error) {
    self.postMessage({ type: "error", message: error instanceof Error ? error.message : "Could not read that capture." });
  }
}

async function runLarge(count: number) {
  try {
    self.postMessage({ type: "progress", done: 0, total: count, phase: "Building a synthetic capture" });
    await new Promise((r) => setTimeout(r, 0));
    const packets = generateLarge(count);
    const encoded = encodePcap(packets);
    await runParse(encoded.buffer as ArrayBuffer, `synthetic-${count}.pcap`);
  } catch (error) {
    self.postMessage({ type: "error", message: error instanceof Error ? error.message : "Could not build the large capture." });
  }
}
