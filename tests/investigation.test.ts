import { describe, expect, it } from "vitest";
import { answerOffline, runTools } from "../src/lib/ask.ts";
import { correlateFindings, parseEve, parseTsharkJson } from "../src/lib/engines.ts";
import { applyDecision, buildDossier, familyOf } from "../src/lib/forensic.ts";
import { PSH, ACK, modbusPdu, tcpIpv4Frame } from "../src/lib/frame.ts";
import { inspectCapture } from "../src/lib/inspect.ts";
import { encodePcap, parseCapture } from "../src/lib/pcap.ts";
import { reportCaseHtml } from "../src/lib/reportCase.ts";
import { buildBenign, buildModbusWrites, buildPlantShift, HOST } from "../src/lib/scenarios.ts";

async function open(packets: { ts: number; data: Uint8Array }[]) {
  const bytes = encodePcap(packets);
  const inspected = await inspectCapture(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
  return inspected;
}

function meta(name: string, count: number) {
  return {
    caseName: name,
    fileName: name,
    sha256: "abc",
    packetCount: count,
    generatedAt: "2026-11-03T00:00:00Z",
    investigator: "Test",
    captureClock: "UTC",
  };
}

describe("packet offsets", () => {
  it("points each classic-pcap offset at that packet's bytes", async () => {
    const built = buildPlantShift();
    const bytes = encodePcap(built);
    const parsed = parseCapture(bytes);
    expect(parsed.packets.length).toBe(built.length);
    for (const packet of parsed.packets) {
      expect(packet.fileOffset).toBeGreaterThan(0);
      expect(bytes.subarray(packet.fileOffset!, packet.fileOffset! + packet.data.length)).toEqual(packet.data);
    }
    const again = parseCapture(bytes);
    expect(again.packets.map((p) => p.n)).toEqual(parsed.packets.map((p) => p.n));
  });
});

describe("case labels", () => {
  it("does not call the quiet plant a level-3 incident", async () => {
    const { packets, analysis } = await open(buildBenign());
    const dossier = buildDossier(packets.map((p) => p.row), analysis);
    expect(dossier.triage.level).toBeLessThan(3);
    expect(dossier.findings.every((f) => (f.triageLevel ?? 1) < 3)).toBe(true);
    const plc = dossier.assets.find((a) => a.ip === HOST.plc.ip);
    expect(plc?.role).toBe("plc");
    expect(plc?.hypothesis.startsWith("Likely")).toBe(true);
    expect(plc?.alternateHypothesis.length).toBeGreaterThan(0);
    expect(plc?.hypothesis.toLowerCase()).not.toContain("this is a plc");
    const html = reportCaseHtml(meta("benign-plant.pcap", packets.length), dossier);
    expect(html).toContain("No level-3 finding");
    expect(html).not.toContain("Port scan from");
    expect(html.toLowerCase()).not.toContain("confirmed exploit");
  });

  it("flags Modbus writes and keeps a single write below level 3", async () => {
    const many = await open(buildModbusWrites());
    const dossier = buildDossier(many.packets.map((p) => p.row), many.analysis);
    const write = dossier.findings.find((f) => f.id === "modbus-write");
    expect(write?.claimStatus).toBe("observed");
    expect(write?.techniqueSupport).toBe("possible");
    expect(write?.alternativeExplanation).toMatch(/maintenance/i);
    expect(write?.triageLevel).toBeLessThanOrEqual(2);
    expect(dossier.triage.level).toBeLessThanOrEqual(2);
    expect(dossier.findings.some((f) => f.id.startsWith("new-writer:"))).toBe(true);

    const one = tcpIpv4Frame({
      src: HOST.atk,
      dst: HOST.plc,
      sp: 41502,
      dp: 502,
      seq: 10,
      ack: 1,
      flags: PSH | ACK,
      payload: modbusPdu(1, Uint8Array.of(16, 0, 100, 0, 2, 4, 0, 50, 0, 60), 1),
    });
    const single = await open([{ ts: 1_700_000_000, data: one }]);
    const alone = buildDossier(single.packets.map((p) => p.row), single.analysis);
    const only = alone.findings.find((f) => f.id === "modbus-write");
    expect(only).toBeTruthy();
    expect(only?.triageLevel).toBeLessThanOrEqual(2);
    expect(alone.triage.level).toBeLessThanOrEqual(2);
    expect(familyOf(only?.id ?? "")).toBe("ot-command");
  });

  it("records an investigator rejecting a finding, and the log survives a reopen", async () => {
    const { packets, analysis } = await open(buildModbusWrites());
    const dossier = buildDossier(packets.map((p) => p.row), analysis);
    const target = dossier.findings[0];
    expect(target).toBeTruthy();
    const decided = applyDecision(dossier.findings, [], {
      findingId: target.id,
      validation: "rejected",
      actor: "A. Froneman",
      at: "2026-11-03T12:00:00Z",
      note: "Scheduled maintenance",
    });
    expect(decided.log.some((entry) => entry.action === "rejected" && entry.detail.includes(target.id))).toBe(true);
    const reopened = JSON.parse(JSON.stringify(decided)) as typeof decided;
    expect(reopened.findings.find((f) => f.id === target.id)?.validation).toBe("rejected");
    expect(reopened.findings.find((f) => f.id === target.id)?.validatedBy).toBe("A. Froneman");
  });
});

describe("engines", () => {
  it("loads a TShark field export without running TShark", () => {
    const rows = parseTsharkJson(JSON.stringify([
      {
        _source: {
          layers: {
            "frame.number": ["4"],
            "frame.time_epoch": ["1700000000.5"],
            "ip.src": ["10.10.1.80"],
            "ip.dst": ["10.10.1.50"],
            "tcp.srcport": ["41502"],
            "tcp.dstport": ["502"],
            "frame.len": ["74"],
            "_ws.col.Protocol": ["Modbus/TCP"],
            "_ws.col.Info": ["Write Multiple Registers"],
            "tls.handshake.ja3": ["deadbeef"],
          },
        },
      },
    ]));
    expect(rows).toEqual([
      expect.objectContaining({ n: 4, src: "10.10.1.80", dst: "10.10.1.50", dp: 502, proto: "Modbus/TCP", ja3: "deadbeef" }),
    ]);
  });

  it("turns an EVE alert into one finding and merges it with the matching Primer card", () => {
    const eve = parseEve([
      JSON.stringify({
        timestamp: "2026-11-02T08:00:00.000000+0000",
        event_type: "alert",
        src_ip: "10.10.1.80",
        dest_ip: "10.10.1.50",
        proto: "TCP",
        pcap_cnt: 12,
        alert: { signature_id: 2024897, signature: "ET POLICY Modbus write", severity: 1, category: "Attempted Information Leak" },
      }),
    ].join("\n"), "2026-10-01");
    expect(eve).toHaveLength(1);
    expect(eve[0].engine).toBe("suricata");
    expect(eve[0].ruleId).toBe("sid:2024897");
    expect(eve[0].evidence.map((e) => e.n)).toEqual([12]);
    expect(eve[0].summary).toContain("2026-10-01");
    const primer = [{
      id: "modbus-write",
      title: "Modbus write to a controller",
      severity: "high" as const,
      summary: "A Modbus write was decoded.",
      meaning: "",
      action: "",
      techniques: ["T0836"],
      evidence: [{ n: 12, detail: "function 16" }],
      evidenceCount: 1,
      engine: "primer",
      claimStatus: "observed" as const,
      techniqueSupport: "possible" as const,
    }];
    const merged = correlateFindings(primer, eve);
    expect(merged).toHaveLength(1);
    expect(merged[0].engine).toBe("correlation");
    expect(merged[0].ruleId).toBe("sid:2024897");
    expect(merged[0].evidence.map((e) => e.n)).toContain(12);
    const noise = parseEve(JSON.stringify({
      event_type: "alert", pcap_cnt: 99,
      alert: { signature_id: 1, signature: "ET MALWARE unrelated", severity: 1 },
    }));
    const both = correlateFindings(primer, noise);
    expect(both.map((f) => f.engine).sort()).toEqual(["primer", "suricata"]);
  });
});

describe("questions on the plant shift", () => {
  it("answers the investigation questions from real packet numbers", async () => {
    const { packets, analysis } = await open(buildPlantShift());
    const rows = packets.map((p) => p.row);
    const ctx = { fileName: "plant-shift.pcap", rows, analysis };
    const writes = rows.filter((r) => r.modbusFunc !== undefined && [5, 6, 15, 16].includes(r.modbusFunc) && r.sp !== 502).map((r) => r.n);
    const asked = runTools("Did anyone write to the controller?", ctx).find((t) => t.tool === "writers");
    expect(asked?.packets.length).toBeGreaterThan(0);
    expect(asked?.packets.every((n) => writes.includes(n) || rows.find((r) => r.n === n && (r.s7Func !== undefined || r.iecType !== undefined || r.dnp3Func !== undefined || r.cipSvc !== undefined || r.bacnetSvc === 15)))).toBe(true);

    const toPlc = runTools("Show me all traffic going to PLC1.", ctx).find((t) => t.tool === "asset");
    expect(toPlc?.summary).toMatch(/PLC1|10\.10\.1\.50/);
    expect(toPlc?.packets.length).toBeGreaterThan(0);
    expect(toPlc?.packets.every((n) => {
      const row = rows.find((r) => r.n === n);
      return row?.src === HOST.plc.ip || row?.dst === HOST.plc.ip;
    })).toBe(true);

    const ews = runTools("Which engineering workstation communicated with this PLC?", ctx).find((t) => t.tool === "asset");
    expect(ews?.summary).toMatch(/10\.10\.1\.80/);
    expect(ews?.packets).toEqual([]);
    const ewsNamed = runTools("Which engineering workstation communicated with 10.10.1.50?", ctx).find((t) => t.tool === "asset");
    expect(ewsNamed?.packets.length).toBeGreaterThan(0);
    expect(ewsNamed?.packets.every((n) => {
      const row = rows.find((r) => r.n === n);
      return row?.src === "10.10.1.80" || row?.dst === "10.10.1.80" || row?.src === "10.10.1.50" || row?.dst === "10.10.1.50";
    })).toBe(true);

    const emptyWindow = runTools("Show me suspicious activity between 10 AM and noon.", ctx).find((t) => t.tool === "timeWindow");
    expect(emptyWindow?.packets).toEqual([]);
    expect(emptyWindow?.summary.toLowerCase()).toContain("capture");

    const covered = runTools("Show me suspicious activity between 6:00 AM and 8:00 AM.", ctx).find((t) => t.tool === "timeWindow");
    expect(covered && covered.packets.length).toBeGreaterThan(0);
    expect(covered?.packets.every((n) => analysis.findings.some((f) => f.severity !== "info" && f.evidence.some((e) => e.n === n)))).toBe(true);

    const net = runTools("Which devices communicated with the Internet?", ctx).find((t) => t.tool === "internet");
    expect(net?.summary).toContain("10.10.1.80");
    expect(net?.packets.every((n) => {
      const row = rows.find((r) => r.n === n);
      return row?.src === "203.0.113.50" || row?.dst === "203.0.113.50";
    })).toBe(true);

    const recon = runTools("Was there evidence of network reconnaissance?", ctx).find((t) => t.tool === "scans");
    expect(recon?.packets.length).toBeGreaterThan(0);
    expect(recon?.summary.toLowerCase()).toMatch(/scan|port/);

    const conn = runTools("Show all connections involving 10.10.1.80.", ctx).find((t) => t.tool === "connections");
    expect(conn?.packets.every((n) => {
      const row = rows.find((r) => r.n === n);
      return row?.src === "10.10.1.80" || row?.dst === "10.10.1.80";
    })).toBe(true);
    expect(runTools("Show all connections involving this IP address.", ctx).find((t) => t.tool === "connections")?.packets).toEqual([]);

    const attack = runTools("Which MITRE ATT&CK techniques are supported by the evidence?", ctx).find((t) => t.tool === "attack");
    expect(attack?.summary).toMatch(/T\d{4}/);
    expect(attack?.packets.every((n) => rows.some((r) => r.n === n))).toBe(true);

    const seq = runTools("Can you reconstruct the sequence of events before the PLC stopped communicating?", ctx).find((t) => t.tool === "sequence");
    expect(seq?.packets.length).toBeGreaterThan(0);
    const stopN = rows.find((r) => r.s7Func === 0x29)?.n;
    expect(stopN).toBeTruthy();
    expect(seq?.packets).toContain(stopN);

    const gate = runTools("Is there enough evidence to open a formal incident investigation?", ctx).find((t) => t.tool === "irGate");
    expect(gate?.summary).toMatch(/level 3/i);
    expect(gate?.summary.toLowerCase()).not.toContain("confirmed exploit");
    expect(gate?.summary).toMatch(/not a declaration|not proof/i);
    expect(gate?.packets.every((n) => rows.some((r) => r.n === n))).toBe(true);

    const offline = answerOffline("which devices wrote to the PLC?", ctx);
    expect(offline.text).toContain("10.10.1.80");
    expect(offline.provider).toBe("offline");
  });
});
