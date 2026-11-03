import { latin1 } from "./bytes.ts";
import { Bit, type PacketRec } from "./model.ts";

export interface StreamMessage {
  n: number;
  ts: number;
  from: string;
  to: string;
  text: string;
  bytes: number;
  gap: boolean;
}

export interface FollowedStream {
  title: string;
  proto: "TCP" | "UDP";
  a: string;
  b: string;
  messages: StreamMessage[];
}

export function followStream(packets: PacketRec[], n: number): FollowedStream | null {
  const hit = packets.find((p) => p.row.n === n);
  if (!hit) return null;
  const row = hit.row;
  const tcp = (row.layers & Bit.tcp) !== 0;
  const udp = (row.layers & Bit.udp) !== 0;
  if (!tcp && !udp) return null;
  const related = packets.filter((p) => {
    const r = p.row;
    if (tcp && (r.layers & Bit.tcp) === 0) return false;
    if (udp && (r.layers & Bit.udp) === 0) return false;
    const same = r.src === row.src && r.dst === row.dst && r.sp === row.sp && r.dp === row.dp;
    const flip = r.src === row.dst && r.dst === row.src && r.sp === row.dp && r.dp === row.sp;
    return same || flip;
  });
  const a = `${row.src}:${row.sp}`;
  const b = `${row.dst}:${row.dp}`;
  const messages: StreamMessage[] = [];
  let expectA = row.tcpSeq;
  let expectB = row.tcpAck;
  const ordered = [...related].sort((x, y) => x.row.ts - y.row.ts || x.row.n - y.row.n);
  for (const p of ordered) {
    if (p.row.appLen <= 0) continue;
    const fromA = p.row.src === row.src && p.row.sp === row.sp;
    const raw = p.raw.subarray(p.row.appOff, p.row.appOff + p.row.appLen);
    let gap = false;
    if (tcp) {
      const expect = fromA ? expectA : expectB;
      if (messages.length && p.row.tcpSeq > expect) gap = true;
      const next = p.row.tcpSeq + p.row.appLen;
      if (fromA) expectA = Math.max(expectA, next);
      else expectB = Math.max(expectB, next);
    }
    messages.push({
      n: p.row.n,
      ts: p.row.ts,
      from: fromA ? a : b,
      to: fromA ? b : a,
      text: toText(raw),
      bytes: raw.length,
      gap,
    });
  }
  return {
    title: `${tcp ? "TCP" : "UDP"} ${a} ↔ ${b}`,
    proto: tcp ? "TCP" : "UDP",
    a,
    b,
    messages,
  };
}

function toText(raw: Uint8Array): string {
  let printable = 0;
  const n = Math.min(raw.length, 4000);
  for (let i = 0; i < n; i++) {
    const b = raw[i];
    if (b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127)) printable++;
  }
  if (n > 0 && printable / n > 0.75) return latin1(raw.subarray(0, Math.min(raw.length, 8000)));
  const hex = [...raw.subarray(0, 64)].map((b) => b.toString(16).padStart(2, "0")).join(" ");
  return `Binary payload, ${raw.length} bytes. First bytes: ${hex}`;
}
