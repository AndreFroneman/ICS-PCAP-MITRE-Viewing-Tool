import { mkdirSync, writeFileSync } from "node:fs";
import { encodePcap, encodePcapng } from "../src/lib/pcap.ts";
import {
  buildBenign,
  buildCleartext,
  buildDnsTunnel,
  buildIcsCommands,
  buildModbusWrites,
  buildPlantShift,
  buildPortScan,
} from "../src/lib/scenarios.ts";

const dir = new URL("../public/samples/", import.meta.url);
mkdirSync(dir, { recursive: true });

const files: [string, Uint8Array][] = [
  ["plant-shift.pcap", encodePcap(buildPlantShift())],
  ["benign-plant.pcap", encodePcap(buildBenign())],
  ["port-scan.pcap", encodePcap(buildPortScan())],
  ["cleartext-creds.pcap", encodePcap(buildCleartext())],
  ["dns-tunnel.pcap", encodePcap(buildDnsTunnel())],
  ["modbus-writes.pcap", encodePcap(buildModbusWrites())],
  ["ics-commands.pcapng", encodePcapng(buildIcsCommands())],
];

for (const [name, bytes] of files) {
  writeFileSync(new URL(name, dir), bytes);
  console.log(name, bytes.length);
}
