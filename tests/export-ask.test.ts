import { describe, expect, it } from "vitest";
import { answerOffline, redact } from "../src/lib/ask.ts";
import { techniqueBlocks } from "../src/lib/attackReport.ts";
import { findingsCsv, packetsCsv } from "../src/lib/csv.ts";
import { inspectCapture } from "../src/lib/inspect.ts";
import { navigatorLayer } from "../src/lib/navigator.ts";
import { encodePcap } from "../src/lib/pcap.ts";
import { buildPlantShift } from "../src/lib/scenarios.ts";

async function plant() {
  const bytes = encodePcap(buildPlantShift());
  return inspectCapture(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
}

describe("csv and attack report", () => {
  it("exports the filtered packet list and findings with technique names", async () => {
    const { packets, analysis } = await plant();
    const csv = packetsCsv(packets.map((p) => p.row).slice(0, 3), analysis.t0);
    expect(csv.split("\n")[0]).toContain("protocol");
    expect(csv.split("\n")).toHaveLength(4);
    const findings = findingsCsv(analysis.findings);
    expect(findings).toContain("T0836");
    expect(findings).toContain("Modify Parameter");
    expect(findings).toContain("T1692.001");
  });

  it("groups the report by tactic and emits a navigator layer", async () => {
    const { packets, analysis } = await plant();
    const blocks = techniqueBlocks(packets.map((p) => p.row), analysis.findings);
    expect(blocks.some((b) => b.id === "T0836" && b.tacticName === "Impair Process Control")).toBe(true);
    expect(blocks.some((b) => b.legacy?.includes("T0855"))).toBe(true);
    const layer = JSON.parse(navigatorLayer("plant-shift.pcap", "ics", analysis.findings)) as { techniques: { techniqueID: string }[]; domain: string };
    expect(layer.domain).toBe("ics-attack");
    expect(layer.techniques.some((t) => t.techniqueID === "T0836")).toBe(true);
    expect(layer.techniques.some((t) => t.techniqueID === "T0855")).toBe(false);
  });
});

describe("ask your capture", () => {
  it("names the device that wrote to the PLC and cites packets", async () => {
    const { packets, analysis } = await plant();
    const answer = answerOffline("which devices wrote to the PLC?", { fileName: "plant-shift.pcap", rows: packets.map((p) => p.row), analysis });
    expect(answer.text).toContain("10.10.1.80");
    expect(answer.packets.length).toBeGreaterThan(0);
    expect(answer.tools).toContain("writers");
  });

  it("treats beacons and exfil as C2-like", async () => {
    const { packets, analysis } = await plant();
    const answer = answerOffline("anything that looks like C2?", { fileName: "plant-shift.pcap", rows: packets.map((p) => p.row), analysis });
    expect(answer.text.toLowerCase()).toMatch(/beacon|upload|public/);
    expect(answer.packets.length).toBeGreaterThan(0);
  });

  it("redacts addresses", () => {
    expect(redact("from 10.10.1.80 to 203.0.113.50 mac 02:00:00:00:00:80")).not.toContain("10.10.1.80");
    expect(redact("from 10.10.1.80 and 10.10.1.80")).toContain("host-1");
  });
});
