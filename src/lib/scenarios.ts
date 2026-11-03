import { concat, encodeUtf8 } from "./bytes.ts";
import {
  ACK,
  PSH,
  SYN,
  TcpPair,
  arpFrame,
  bacnetConfirmed,
  bacnetUnconfirmed,
  basicAuth,
  dhcpDiscover,
  dnp3Request,
  dnsQuery,
  dnsResponseA,
  enipCip,
  httpRequest,
  httpResponse,
  icmpEchoFrame,
  iec104I,
  iec104U,
  miniCertificate,
  modbusPdu,
  mqttConnect,
  mqttPublish,
  ntlmAuthenticate,
  opcuaHello,
  s7Job,
  smb2SessionSetup,
  smb2TreeConnect,
  tcpIpv4Frame,
  tinyGif,
  tlsCertificateRecord,
  tlsClientHello,
  tlsServerHello,
  udpIpv4Frame,
  type Host,
} from "./frame.ts";
import type { TimedPacket } from "./pcap.ts";

export const T0 = Date.UTC(2026, 10, 2, 6, 40, 0) / 1000;

export const HOST = {
  gw: { mac: "02:00:00:00:00:01", ip: "10.10.1.1" },
  eng: { mac: "02:00:00:00:00:10", ip: "10.10.1.10" },
  hmi: { mac: "02:00:00:00:00:20", ip: "10.10.1.20" },
  scada: { mac: "02:00:00:00:00:30", ip: "10.10.1.30" },
  hist: { mac: "02:00:00:00:00:40", ip: "10.10.1.40" },
  plc: { mac: "02:00:00:00:00:50", ip: "10.10.1.50" },
  plc2: { mac: "02:00:00:00:00:51", ip: "10.10.1.51" },
  rtu: { mac: "02:00:00:00:00:60", ip: "10.10.1.60" },
  dc: { mac: "02:00:00:00:00:70", ip: "10.10.1.70" },
  atk: { mac: "02:00:00:00:00:80", ip: "10.10.1.80" },
  dns: { mac: "02:00:00:00:00:35", ip: "10.10.1.53" },
  broker: { mac: "02:00:00:00:00:88", ip: "10.10.1.88" },
  ext: { mac: "02:11:22:33:44:50", ip: "203.0.113.50" },
} satisfies Record<string, Host>;

function at(sec: number): number {
  return T0 + sec;
}

function push(out: TimedPacket[], ts: number, data: Uint8Array) {
  out.push({ ts, data });
}

function handshake(out: TimedPacket[], ts: number, pair: TcpPair) {
  push(out, ts, pair.fromA("", SYN));
  push(out, ts + 0.002, pair.fromB("", SYN | ACK));
  push(out, ts + 0.004, pair.fromA("", ACK));
}

function noise(seed: number, n = 48): string {
  const alphabet = "abcdefghijkmnopqrstuvwxyz0123456789";
  let x = seed || 1;
  let s = "";
  for (let i = 0; i < n; i++) {
    x = (Math.imul(x, 1103515245) + 12345) & 0x7fffffff;
    s += alphabet[x % alphabet.length];
  }
  return s;
}

function benign(out: TimedPacket[]) {
  const { gw, eng, hmi, scada, hist, plc, rtu, dns, broker } = HOST;
  push(out, at(0), arpFrame(1, scada, "00:00:00:00:00:00", plc.ip));
  push(out, at(0.01), arpFrame(2, plc, scada.mac, scada.ip, scada.mac));
  push(out, at(0.4), udpIpv4Frame({ src: eng, dst: gw, sp: 68, dp: 67, payload: dhcpDiscover(eng.mac, "eng-laptop") }));
  push(out, at(1), udpIpv4Frame({ src: hmi, dst: dns, sp: 53001, dp: 53, payload: dnsQuery(1, "historian.plant.local") }));
  push(out, at(1.02), udpIpv4Frame({ src: dns, dst: hmi, sp: 53, dp: 53001, payload: dnsResponseA(1, "historian.plant.local", hist.ip) }));
  push(out, at(1.2), udpIpv4Frame({ src: scada, dst: dns, sp: 53002, dp: 53, payload: dnsQuery(2, "plc.plant.local") }));
  push(out, at(1.22), udpIpv4Frame({ src: dns, dst: scada, sp: 53, dp: 53002, payload: dnsResponseA(2, "plc.plant.local", plc.ip) }));
  push(out, at(1.4), udpIpv4Frame({ src: hmi, dst: dns, sp: 53003, dp: 53, payload: dnsQuery(3, "scada.plant.local") }));
  push(out, at(1.42), udpIpv4Frame({ src: dns, dst: hmi, sp: 53, dp: 53003, payload: dnsResponseA(3, "scada.plant.local", scada.ip) }));

  const web = new TcpPair(hmi, hist, 52010, 80);
  handshake(out, at(2), web);
  push(out, at(2.05), web.fromA(httpRequest("GET", "/logo.gif", "historian.plant.local")));
  push(out, at(2.08), web.fromB(httpResponse(200, "OK", tinyGif(), "image/gif")));

  const tls = new TcpPair(hmi, hist, 52110, 443);
  handshake(out, at(3), tls);
  push(out, at(3.05), tls.fromA(tlsClientHello("intranet.plant.local")));
  push(out, at(3.08), tls.fromB(concat(tlsServerHello(), tlsCertificateRecord(miniCertificate("intranet.plant.local", "Plant CA")))));

  const poll = new TcpPair(scada, plc, 51000, 502);
  handshake(out, at(4), poll);
  for (let i = 0; i < 8; i++) {
    const req = modbusPdu(1, Uint8Array.of(3, 0, 0, 0, 4), i + 1);
    push(out, at(4.2 + i * 2), poll.fromA(req));
    const resp = modbusPdu(1, Uint8Array.of(3, 8, 0, 10, 0, 11, 0, 12, 0, 13), i + 1);
    push(out, at(4.21 + i * 2), poll.fromB(resp));
  }

  const mqtt = new TcpPair(HOST.rtu, broker, 18830, 1883);
  handshake(out, at(5), mqtt);
  push(out, at(5.05), mqtt.fromA(mqttConnect("line1-sensor")));
  push(out, at(5.1), mqtt.fromA(mqttPublish("plant/line1/temp", "41.2")));

  push(out, at(6), udpIpv4Frame({
    src: scada,
    dst: { ...rtu, mac: "ff:ff:ff:ff:ff:ff" },
    sp: 47808,
    dp: 47808,
    payload: bacnetUnconfirmed(8),
  }));

  const iec = new TcpPair(scada, rtu, 24040, 2404);
  handshake(out, at(7), iec);
  push(out, at(7.05), iec.fromA(iec104U(0x07)));
  push(out, at(7.08), iec.fromB(iec104U(0x0b)));
  push(out, at(7.2), iec.fromA(iec104I(100, 6)));

  push(out, at(8), icmpEchoFrame(eng, gw, 7, 1));
}

function attacks(out: TimedPacket[]) {
  const { atk, plc, plc2, hist, rtu, dc, dns, broker, ext } = HOST;
  const ports = [21, 22, 23, 80, 102, 135, 139, 443, 445, 502, 1433, 2404, 3389, 4840, 5900, 8080, 8443, 20000, 44818, 47808];
  ports.forEach((port, i) => {
    push(out, at(50 + i * 0.03), tcpIpv4Frame({
      src: atk, dst: plc, sp: 41000 + i, dp: port, seq: 1, ack: 0, flags: SYN,
    }));
  });
  for (let i = 0; i < 4; i++) {
    push(out, at(51 + i * 0.03), tcpIpv4Frame({
      src: atk, dst: plc2, sp: 42000 + i, dp: 502, seq: 1, ack: 0, flags: SYN,
    }));
  }

  const ftp = new TcpPair(atk, hist, 41021, 21);
  handshake(out, at(60), ftp);
  push(out, at(60.1), ftp.fromB("220 historian FTP ready\r\n"));
  for (let i = 0; i < 8; i++) {
    push(out, at(60.2 + i * 0.2), ftp.fromA(`USER historian\r\n`));
    push(out, at(60.25 + i * 0.2), ftp.fromB("331 Password required\r\n"));
    push(out, at(60.3 + i * 0.2), ftp.fromA(`PASS wrong-${i}\r\n`));
    push(out, at(60.35 + i * 0.2), ftp.fromB("530 Login incorrect\r\n"));
  }
  push(out, at(62.2), ftp.fromA("USER historian\r\n"));
  push(out, at(62.25), ftp.fromB("331 Password required\r\n"));
  push(out, at(62.3), ftp.fromA("PASS Summer-Plant-24\r\n"));
  push(out, at(62.35), ftp.fromB("230 Login successful\r\n"));
  push(out, at(62.5), ftp.fromA("RETR trends.csv\r\n"));

  const web = new TcpPair(atk, hist, 41080, 80);
  handshake(out, at(70), web);
  push(out, at(70.1), web.fromA(httpRequest("GET", "/admin", "historian.plant.local", basicAuth("historian", "Summer-Plant-24"))));

  const mail = new TcpPair(atk, hist, 41025, 25);
  handshake(out, at(72), mail);
  push(out, at(72.1), mail.fromB("220 mail ready\r\n"));
  push(out, at(72.2), mail.fromA("EHLO laptop\r\n"));
  const token = btoa("\0historian\0Summer-Plant-24");
  push(out, at(72.3), mail.fromA(`AUTH PLAIN ${token}\r\n`));

  const mqtt = new TcpPair(atk, broker, 41883, 1883);
  handshake(out, at(74), mqtt);
  push(out, at(74.1), mqtt.fromA(mqttConnect("intruder", "operator", "plc-secret")));

  for (let i = 0; i < 5; i++) {
    const qname = `${noise(20 + i)}.${noise(80 + i)}.tunnel.test`;
    push(out, at(80 + i * 0.2), udpIpv4Frame({
      src: atk, dst: dns, sp: 44000 + i, dp: 53, payload: dnsQuery(100 + i, qname),
    }));
  }

  const smb = new TcpPair(atk, dc, 41445, 445);
  handshake(out, at(90), smb);
  push(out, at(90.1), smb.fromA(smb2SessionSetup(ntlmAuthenticate("badactor", "PLANT"))));
  push(out, at(90.2), smb.fromA(smb2TreeConnect("\\\\10.10.1.70\\ADMIN$")));

  const beacon = new TcpPair(atk, ext, 41443, 443);
  handshake(out, at(100), beacon);
  for (let i = 0; i < 10; i++) {
    push(out, at(100.2 + i * 10), beacon.fromA("ping"));
  }

  const bulk = new TcpPair(atk, ext, 41444, 4444);
  handshake(out, at(150), bulk);
  const chunk = encodeUtf8("A".repeat(1500));
  for (let i = 0; i < 30; i++) push(out, at(150.2 + i * 0.02), bulk.fromA(chunk));

  const mb = new TcpPair(atk, plc, 41502, 502);
  handshake(out, at(200), mb);
  push(out, at(200.2), mb.fromA(modbusPdu(1, Uint8Array.of(16, 0, 100, 0, 2, 4, 0, 50, 0, 60), 1)));
  push(out, at(200.4), mb.fromA(modbusPdu(1, Uint8Array.of(5, 0, 0, 0xff, 0), 2)));
  for (let i = 0; i < 12; i++) {
    push(out, at(201 + i * 0.05), mb.fromA(modbusPdu(1, Uint8Array.of(5, 0, i, i % 2 ? 0xff : 0, 0), 10 + i)));
  }
  for (let i = 0; i < 16; i++) {
    const addr = i * 10;
    push(out, at(202.5 + i * 0.04), mb.fromA(modbusPdu(1, Uint8Array.of(3, (addr >> 8) & 0xff, addr & 0xff, 0, 1), 40 + i)));
  }

  const s7 = new TcpPair(atk, plc, 41102, 102);
  handshake(out, at(210), s7);
  push(out, at(210.2), s7.fromA(s7Job(0x29)));
  push(out, at(210.5), s7.fromA(s7Job(0x1a, encodeUtf8("OB1"))));
  push(out, at(210.8), s7.fromA(s7Job(0x1d, encodeUtf8("OB1"))));

  const iec = new TcpPair(atk, rtu, 42404, 2404);
  handshake(out, at(220), iec);
  push(out, at(220.2), iec.fromA(iec104I(45, 6)));

  const dnp = new TcpPair(atk, rtu, 42000, 20000);
  handshake(out, at(222), dnp);
  push(out, at(222.2), dnp.fromA(dnp3Request(5, 1, 80)));

  const bac = new TcpPair(atk, rtu, 47808, 47808);
  handshake(out, at(224), bac);
  push(out, at(224.2), bac.fromA(bacnetConfirmed(15)));

  const enip = new TcpPair(atk, plc, 44818, 44818);
  handshake(out, at(226), enip);
  push(out, at(226.2), enip.fromA(enipCip(0x4d)));

  const opc = new TcpPair(atk, plc, 48400, 4840);
  handshake(out, at(228), opc);
  push(out, at(228.2), opc.fromA(opcuaHello("opc.tcp://10.10.1.50:4840")));

  for (let i = 0; i < 8; i++) {
    push(out, at(230 + i * 0.1), tcpIpv4Frame({
      src: atk,
      dst: plc,
      sp: 43000 + i,
      dp: 22,
      seq: 10 + i,
      ack: 1,
      flags: PSH | ACK,
      payload: encodeUtf8("SSH-2.0-OpenSSH_9.6\r\n"),
    }));
  }
}

export function buildPlantShift(): TimedPacket[] {
  const out: TimedPacket[] = [];
  benign(out);
  attacks(out);
  return out.sort((a, b) => a.ts - b.ts);
}

export function buildBenign(): TimedPacket[] {
  const out: TimedPacket[] = [];
  benign(out);
  return out;
}

export function buildPortScan(): TimedPacket[] {
  const { atk, plc } = HOST;
  const ports = [21, 22, 23, 80, 102, 135, 139, 443, 445, 502, 1433, 2404, 3389, 4840, 5900, 8080, 8443, 20000, 44818, 47808];
  return ports.map((port, i) => ({
    ts: at(i * 0.02),
    data: tcpIpv4Frame({ src: atk, dst: plc, sp: 45000 + i, dp: port, seq: 1, ack: 0, flags: SYN }),
  }));
}

export function buildCleartext(): TimedPacket[] {
  const { atk, hist, broker } = HOST;
  const out: TimedPacket[] = [];
  const ftp = new TcpPair(atk, hist, 21_001, 21);
  handshake(out, at(0), ftp);
  push(out, at(0.1), ftp.fromB("220 ready\r\n"));
  push(out, at(0.2), ftp.fromA("USER historian\r\n"));
  push(out, at(0.3), ftp.fromA("PASS Summer-Plant-24\r\n"));
  const web = new TcpPair(atk, hist, 21_080, 80);
  handshake(out, at(1), web);
  push(out, at(1.1), web.fromA(httpRequest("GET", "/admin", "historian.plant.local", basicAuth("historian", "Summer-Plant-24"))));
  const mqtt = new TcpPair(atk, broker, 21_883, 1883);
  handshake(out, at(2), mqtt);
  push(out, at(2.1), mqtt.fromA(mqttConnect("intruder", "operator", "plc-secret")));
  return out;
}

export function buildDnsTunnel(): TimedPacket[] {
  const { atk, dns } = HOST;
  const out: TimedPacket[] = [];
  for (let i = 0; i < 5; i++) {
    const qname = `${noise(20 + i)}.${noise(80 + i)}.tunnel.test`;
    push(out, at(i * 0.2), udpIpv4Frame({ src: atk, dst: dns, sp: 46000 + i, dp: 53, payload: dnsQuery(100 + i, qname) }));
  }
  return out;
}

export function buildModbusWrites(): TimedPacket[] {
  const { scada, plc, atk } = HOST;
  const out: TimedPacket[] = [];
  const poll = new TcpPair(scada, plc, 51000, 502);
  handshake(out, at(0), poll);
  for (let i = 0; i < 4; i++) {
    push(out, at(0.2 + i), poll.fromA(modbusPdu(1, Uint8Array.of(3, 0, 0, 0, 4), i + 1)));
  }
  const mb = new TcpPair(atk, plc, 41502, 502);
  handshake(out, at(6), mb);
  push(out, at(6.2), mb.fromA(modbusPdu(1, Uint8Array.of(16, 0, 100, 0, 2, 4, 0, 50, 0, 60), 1)));
  push(out, at(6.4), mb.fromA(modbusPdu(1, Uint8Array.of(6, 0, 20, 0, 75), 2)));
  push(out, at(6.6), mb.fromA(modbusPdu(1, Uint8Array.of(5, 0, 1, 0xff, 0), 3)));
  return out;
}

export function buildIcsCommands(): TimedPacket[] {
  const { atk, plc, rtu } = HOST;
  const out: TimedPacket[] = [];
  const s7 = new TcpPair(atk, plc, 41102, 102);
  handshake(out, at(0), s7);
  push(out, at(0.2), s7.fromA(s7Job(0x29)));
  push(out, at(0.4), s7.fromA(s7Job(0x1a, encodeUtf8("OB1"))));
  push(out, at(0.6), s7.fromA(s7Job(0x1d, encodeUtf8("OB1"))));
  const iec = new TcpPair(atk, rtu, 42404, 2404);
  handshake(out, at(1), iec);
  push(out, at(1.2), iec.fromA(iec104I(45, 6)));
  const dnp = new TcpPair(atk, rtu, 42000, 20000);
  handshake(out, at(2), dnp);
  push(out, at(2.2), dnp.fromA(dnp3Request(5)));
  const bac = new TcpPair(atk, rtu, 47810, 47808);
  handshake(out, at(3), bac);
  push(out, at(3.2), bac.fromA(bacnetConfirmed(15)));
  const enip = new TcpPair(atk, plc, 44820, 44818);
  handshake(out, at(4), enip);
  push(out, at(4.2), enip.fromA(enipCip(0x4d)));
  const opc = new TcpPair(atk, plc, 48410, 4840);
  handshake(out, at(5), opc);
  push(out, at(5.2), opc.fromA(opcuaHello("opc.tcp://10.10.1.50:4840")));
  const mb = new TcpPair(atk, plc, 41510, 502);
  handshake(out, at(6), mb);
  for (let i = 0; i < 12; i++) {
    push(out, at(6.2 + i * 0.05), mb.fromA(modbusPdu(1, Uint8Array.of(5, 0, i, 0xff, 0), i + 1)));
  }
  return out;
}

export function generateLarge(count = 100_000): TimedPacket[] {
  const payload = modbusPdu(1, Uint8Array.of(3, 0, 0, 0, 4), 1);
  const template = tcpIpv4Frame({
    src: HOST.scada,
    dst: HOST.plc,
    sp: 51000,
    dp: 502,
    seq: 1000,
    ack: 8000,
    flags: PSH | ACK,
    payload,
  });
  const t0 = Date.UTC(2026, 10, 2, 9, 0, 0) / 1000;
  const out = new Array<TimedPacket>(count);
  for (let i = 0; i < count; i++) {
    const data = template.slice();
    data[54] = (i >>> 8) & 0xff;
    data[55] = i & 0xff;
    out[i] = { ts: t0 + i * 0.01, data };
  }
  return out;
}
