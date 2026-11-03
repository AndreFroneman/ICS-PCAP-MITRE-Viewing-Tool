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
  spans: { n: number; ts: number; fileOffset: number; capLen: number; origLen: number; linkType: number }[];
}

const RELEASE_AT = 32 * 1024 * 1024;

self.onmessage = (event: MessageEvent) => {
  const msg = event.data as {
    type: string;
    buffer?: ArrayBuffer;
    name?: string;
    n?: number;
    count?: number;
    releaseBytes?: boolean;
    packets?: { n: number; buffer: ArrayBuffer }[];
  };
  if (msg.type === "parse" && msg.buffer) {
    void runParse(msg.buffer, msg.name ?? "capture", Boolean(msg.releaseBytes));
  } else if (msg.type === "large") {
    void runLarge(msg.count ?? 100_000);
  } else if (msg.type === "dissect" && msg.n) {
    const packet = store.find((p) => p.row.n === msg.n);
    if (!packet) return;
    if (packet.raw.length === 0) {
      self.postMessage({ type: "need-bytes", n: packet.row.n, offset: packet.fileOffset ?? 0, len: packet.capLen ?? 0 });
      return;
    }
    const { tree } = dissect(packet.raw, { n: packet.row.n, ts: packet.row.ts, linkType: packet.row.linkType }, true);
    self.postMessage({ type: "dissection", n: msg.n, tree, bytes: packet.raw });
  } else if (msg.type === "bytes" && msg.n && msg.buffer) {
    const packet = store.find((p) => p.row.n === msg.n);
    if (!packet) return;
    packet.raw = new Uint8Array(msg.buffer);
    const { tree } = dissect(packet.raw, { n: packet.row.n, ts: packet.row.ts, linkType: packet.row.linkType }, true);
    self.postMessage({ type: "dissection", n: msg.n, tree, bytes: packet.raw });
    if ((packet.capLen ?? 0) > 0 && packet.raw.length === packet.capLen) {
      // Drop the copy again so a large evidence file does not stay resident.
      packet.raw = new Uint8Array();
    }
  } else if (msg.type === "stream" && msg.n) {
    const stream: FollowedStream | null = followStream(store, msg.n);
    self.postMessage({ type: "stream", stream });
  }
};

async function runParse(buffer: ArrayBuffer, name: string, releaseBytes: boolean) {
  try {
    const inspected = await inspectCapture(buffer, (done, total, phase) => {
      self.postMessage({ type: "progress", done, total, phase });
    });
    store = inspected.packets;
    const spans = store.map((p) => ({
      n: p.row.n,
      ts: p.row.ts,
      fileOffset: p.fileOffset ?? 0,
      capLen: p.capLen ?? p.raw.length,
      origLen: p.row.len,
      linkType: p.row.linkType ?? 1,
    }));
    const held = store.reduce((sum, packet) => sum + packet.raw.byteLength, 0);
    if (releaseBytes && held > RELEASE_AT) {
      for (const packet of store) packet.raw = new Uint8Array();
      self.postMessage({ type: "progress", done: spans.length, total: spans.length, phase: "Packet bytes released; opening one frame reads it from the case file" });
    }
    const ready: Ready = {
      type: "ready",
      name,
      format: inspected.file.format,
      linkType: inspected.file.linkType,
      warnings: inspected.file.warnings,
      rows: inspected.packets.map((p) => p.row),
      analysis: inspected.analysis,
      spans,
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
    await runParse(encoded.buffer as ArrayBuffer, `synthetic-${count}.pcap`, false);
  } catch (error) {
    self.postMessage({ type: "error", message: error instanceof Error ? error.message : "Could not build the large capture." });
  }
}
