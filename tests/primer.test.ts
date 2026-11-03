import { describe, expect, it } from "vitest";
import { getTechnique } from "../src/lib/attack.ts";
import { dissect } from "../src/lib/dissect.ts";
import { compileFilter, FilterError } from "../src/lib/filter.ts";
import { udpIpv6Frame } from "../src/lib/frame.ts";
import { dnsQuery } from "../src/lib/frame.ts";
import { inspectCapture } from "../src/lib/inspect.ts";
import { Bit } from "../src/lib/model.ts";
import { encodePcap, encodePcapng, parseCapture } from "../src/lib/pcap.ts";
import { reportJson, reportPdf } from "../src/lib/report.ts";
import {
  buildBenign,
  buildCleartext,
  buildDnsTunnel,
  buildIcsCommands,
  buildModbusWrites,
  buildPlantShift,
  buildPortScan,
  generateLarge,
  HOST,
} from "../src/lib/scenarios.ts";

async function open(packets: { ts: number; data: Uint8Array }[], ng = false) {
  const bytes = ng ? encodePcapng(packets) : encodePcap(packets);
  return inspectCapture(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
}

function ids(findings: { techniques: string[]; legacy?: { id: string }[]; id: string }[]) {
  return findings.flatMap((f) => [...f.techniques, ...(f.legacy ?? []).map((l) => l.id)]);
}

describe("pcap", () => {
  it("round-trips classic pcap and pcapng", () => {
    const packets = buildPortScan().slice(0, 2);
    for (const encoded of [encodePcap(packets), encodePcapng(packets)]) {
      const parsed = parseCapture(encoded.buffer.slice(encoded.byteOffset, encoded.byteOffset + encoded.byteLength));
      expect(parsed.packets).toHaveLength(2);
      expect(parsed.packets[0].data).toEqual(packets[0].data);
      expect(parsed.packets[1].data).toEqual(packets[1].data);
    }
  });
});

describe("dissection", () => {
  it("decodes the plant protocols", async () => {
    const { packets } = await open(buildPlantShift());
    const protos = new Set(packets.map((p) => p.row.proto));
    for (const name of ["ARP", "DNS", "DHCP", "HTTP", "TLS", "Modbus", "MQTT", "BACnet", "IEC 104", "ICMP", "S7comm", "DNP3", "EtherNet/IP", "OPC UA", "FTP", "SMB2", "SSH", "SMTP"]) {
      expect(protos.has(name), name).toBe(true);
    }
    const sni = packets.find((p) => p.row.tlsSni);
    expect(sni?.row.tlsSni).toBe("intranet.plant.local");
    const cn = packets.find((p) => p.row.tlsCn);
    expect(cn?.row.tlsCn).toBe("intranet.plant.local");
    expect(cn?.row.tlsIssuer).toBe("Plant CA");
    const smb = packets.find((p) => p.row.smbPath);
    expect(smb?.row.smbPath).toContain("ADMIN$");
    const user = packets.find((p) => p.row.smbUser);
    expect(user?.row.smbUser).toBe("badactor");
    const ftp = packets.find((p) => p.row.ftpCmd === "PASS" && p.row.ftpArg === "Summer-Plant-24");
    expect(ftp).toBeTruthy();
    const http = packets.find((p) => p.row.httpAuth);
    expect(http?.row.httpAuth).toContain("historian");
    const mqtt = packets.find((p) => p.row.mqttPass);
    expect(mqtt?.row.mqttPass).toBe("plc-secret");
    const opc = packets.find((p) => p.row.opcUrl);
    expect(opc?.row.opcUrl).toContain("opc.tcp://");
  });

  it("decodes IPv6 DNS", () => {
    const frame = udpIpv6Frame({
      srcMac: HOST.hmi.mac,
      dstMac: HOST.dns.mac,
      srcIp: "fd00::20",
      dstIp: "fd00::53",
      sp: 53000,
      dp: 53,
      payload: dnsQuery(9, "hmi.plant.local"),
    });
    const { row } = dissect(frame, { n: 1, ts: 1 }, true);
    expect(row.layers & Bit.ipv6).toBeTruthy();
    expect(row.proto).toBe("DNS");
    expect(row.dnsQ).toBe("hmi.plant.local");
    expect(row.src).toBe("fd00::20");
  });
});

describe("filters", () => {
  it("matches fields, protocols, and lists", async () => {
    const { packets, analysis } = await open(buildModbusWrites());
    const writes = compileFilter("modbus.func == 16 || modbus.func == 6 || modbus.func == 5");
    const hit = packets.filter((p) => writes.test(p.row, analysis.t0));
    expect(hit.length).toBe(3);
    const syn = compileFilter("tcp.flags.syn == 1 && tcp.flags.ack == 0");
    const scan = await open(buildPortScan());
    expect(scan.packets.filter((p) => syn.test(p.row, scan.analysis.t0)).length).toBe(scan.packets.length);
    const listed = compileFilter("frame.number in {1, 2, 3}");
    expect(scan.packets.filter((p) => listed.test(p.row, 0)).length).toBe(3);
    expect(() => compileFilter("tcp &&")).toThrow(FilterError);
  });
});

describe("detections", () => {
  it("keeps the benign plant quiet", async () => {
    const { analysis } = await open(buildBenign());
    const loud = analysis.findings.filter((f) => f.severity !== "info");
    expect(loud.map((f) => f.id)).toEqual([]);
  });

  it("maps the plant shift onto ATT&CK", async () => {
    const { analysis } = await open(buildPlantShift());
    expect(analysis.devices).toHaveLength(12);
    expect(analysis.headline).toMatch(/12 devices/);
    const found = new Set(ids(analysis.findings));
    for (const id of ["T1046", "T0846.001", "T1040", "T0842", "T1071.004", "T0869.001", "T1071", "T1021.002", "T1110", "T1041", "T0836", "T1692.001", "T0855", "T0881", "T0816", "T0843", "T0845", "T0861", "T0806"]) {
      expect(found.has(id), id).toBe(true);
    }
    const stop = analysis.findings.find((f) => f.id === "s7-stop");
    expect(stop?.severity).toBe("critical");
    const write = analysis.findings.find((f) => f.id === "modbus-write");
    expect(write?.legacy?.[0]).toEqual({ id: "T0855", replacedBy: "T1692.001" });
    expect(write?.evidence.length).toBeGreaterThan(0);
    const report = reportJson({ fileName: "plant-shift.pcap", packetCount: 1, generatedAt: "test" }, analysis);
    expect(report).toContain("T1046");
    expect(report).toContain("T1692.001");
    const pdf = reportPdf({ fileName: "plant-shift.pcap", packetCount: 1, generatedAt: "test" }, analysis);
    expect(pdf[0]).toBe(0x25);
    expect(new TextDecoder().decode(pdf.slice(0, 8))).toBe("%PDF-1.4");
  });

  it("fires each focused sample", async () => {
    expect(ids((await open(buildPortScan())).analysis.findings)).toEqual(expect.arrayContaining(["T1046", "T0846.001"]));
    expect(ids((await open(buildCleartext())).analysis.findings)).toEqual(expect.arrayContaining(["T1040", "T0842"]));
    expect(ids((await open(buildDnsTunnel())).analysis.findings)).toEqual(expect.arrayContaining(["T1071.004", "T0869.001"]));
    expect(ids((await open(buildModbusWrites())).analysis.findings)).toEqual(expect.arrayContaining(["T0836", "T1692.001", "T0855"]));
    const ics = ids((await open(buildIcsCommands(), true)).analysis.findings);
    for (const id of ["T0881", "T0843", "T0845", "T1692.001", "T0806"]) {
      expect(ics, id).toContain(id);
    }
  });
});

describe("attack bundle", () => {
  it("resolves current and revoked techniques offline", () => {
    const scan = getTechnique("T1046");
    expect(scan?.name).toBe("Network Service Discovery");
    expect(scan?.mitigationIds.length).toBeGreaterThan(0);
    expect(scan?.url).toContain("attack.mitre.org");
    const legacy = getTechnique("T0855");
    expect(legacy?.revoked).toBe(true);
    expect(legacy?.revokedBy).toBe("T1692.001");
    expect(getTechnique("T1692.001")?.name).toBe("Command Message");
    expect(getTechnique("T0881")?.domain).toBe("ics");
  });
});

describe("scale", () => {
  it("parses and filters 100k packets", async () => {
    const packets = generateLarge(100_000);
    const encoded = encodePcap(packets);
    const started = performance.now();
    const inspected = await inspectCapture(encoded.buffer.slice(0));
    const filter = compileFilter("modbus.func == 3 && ip.addr == 10.10.1.50");
    let n = 0;
    for (const p of inspected.packets) if (filter.test(p.row, inspected.analysis.t0)) n++;
    const elapsed = performance.now() - started;
    expect(inspected.packets).toHaveLength(100_000);
    expect(n).toBe(100_000);
    expect(inspected.analysis.findings.some((f) => f.severity === "high" || f.severity === "critical")).toBe(false);
    expect(elapsed).toBeLessThan(20_000);
  }, 30_000);
});
