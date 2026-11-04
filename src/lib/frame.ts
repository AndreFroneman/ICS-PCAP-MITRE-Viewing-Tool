import { be16, concat, encodeUtf8, inetChecksum, le16 } from "./bytes.ts";
import { parseIpv4, parseIpv6, parseMac } from "./ip.ts";

export interface Host {
  mac: string;
  ip: string;
}

export const FIN = 0x01;
export const SYN = 0x02;
export const RST = 0x04;
export const PSH = 0x08;
export const ACK = 0x10;

let ipId = 1;

export function ethFrame(dstMac: string, srcMac: string, ethertype: number, payload: Uint8Array): Uint8Array {
  return concat(parseMac(dstMac), parseMac(srcMac), be16(ethertype), payload);
}

export function ipv4Packet(src: string, dst: string, proto: number, payload: Uint8Array, ttl = 64): Uint8Array {
  const header = new Uint8Array(20);
  header[0] = 0x45;
  const total = 20 + payload.length;
  header[2] = (total >> 8) & 0xff;
  header[3] = total & 0xff;
  const id = ipId++ & 0xffff;
  header[4] = (id >> 8) & 0xff;
  header[5] = id & 0xff;
  header[6] = 0x40;
  header[8] = ttl;
  header[9] = proto;
  header.set(parseIpv4(src), 12);
  header.set(parseIpv4(dst), 16);
  const sum = inetChecksum([header]);
  header[10] = (sum >> 8) & 0xff;
  header[11] = sum & 0xff;
  return concat(header, payload);
}

export function ipv6Packet(src: string, dst: string, next: number, payload: Uint8Array): Uint8Array {
  const header = new Uint8Array(40);
  header[0] = 0x60;
  header[4] = (payload.length >> 8) & 0xff;
  header[5] = payload.length & 0xff;
  header[6] = next;
  header[7] = 64;
  header.set(parseIpv6(src), 8);
  header.set(parseIpv6(dst), 24);
  return concat(header, payload);
}

function tcpChecksum(src: string, dst: string, segment: Uint8Array): number {
  const pseudo = new Uint8Array(12);
  pseudo.set(parseIpv4(src), 0);
  pseudo.set(parseIpv4(dst), 4);
  pseudo[9] = 6;
  pseudo[10] = (segment.length >> 8) & 0xff;
  pseudo[11] = segment.length & 0xff;
  return inetChecksum([pseudo, segment]);
}

export function tcpSegment(opts: {
  srcIp: string;
  dstIp: string;
  sp: number;
  dp: number;
  seq: number;
  ack: number;
  flags: number;
  payload?: Uint8Array;
  win?: number;
}): Uint8Array {
  const payload = opts.payload ?? new Uint8Array();
  const seg = new Uint8Array(20 + payload.length);
  const v = new DataView(seg.buffer);
  v.setUint16(0, opts.sp);
  v.setUint16(2, opts.dp);
  v.setUint32(4, opts.seq >>> 0);
  v.setUint32(8, opts.ack >>> 0);
  seg[12] = 5 << 4;
  seg[13] = opts.flags;
  v.setUint16(14, opts.win ?? 65535);
  seg.set(payload, 20);
  const sum = tcpChecksum(opts.srcIp, opts.dstIp, seg);
  seg[16] = (sum >> 8) & 0xff;
  seg[17] = sum & 0xff;
  return seg;
}

export function udpDatagram(opts: {
  srcIp: string;
  dstIp: string;
  sp: number;
  dp: number;
  payload: Uint8Array;
}): Uint8Array {
  const u = new Uint8Array(8 + opts.payload.length);
  const v = new DataView(u.buffer);
  v.setUint16(0, opts.sp);
  v.setUint16(2, opts.dp);
  v.setUint16(4, u.length);
  u.set(opts.payload, 8);
  const pseudo = new Uint8Array(12);
  pseudo.set(parseIpv4(opts.srcIp), 0);
  pseudo.set(parseIpv4(opts.dstIp), 4);
  pseudo[9] = 17;
  pseudo[10] = (u.length >> 8) & 0xff;
  pseudo[11] = u.length & 0xff;
  const sum = inetChecksum([pseudo, u]);
  u[6] = (sum >> 8) & 0xff;
  u[7] = sum & 0xff;
  return u;
}

export function tcpIpv4Frame(opts: {
  src: Host;
  dst: Host;
  sp: number;
  dp: number;
  seq: number;
  ack: number;
  flags: number;
  payload?: Uint8Array;
}): Uint8Array {
  const seg = tcpSegment({
    srcIp: opts.src.ip,
    dstIp: opts.dst.ip,
    sp: opts.sp,
    dp: opts.dp,
    seq: opts.seq,
    ack: opts.ack,
    flags: opts.flags,
    payload: opts.payload,
  });
  const ip = ipv4Packet(opts.src.ip, opts.dst.ip, 6, seg);
  return ethFrame(opts.dst.mac, opts.src.mac, 0x0800, ip);
}

export function udpIpv4Frame(opts: {
  src: Host;
  dst: Host;
  sp: number;
  dp: number;
  payload: Uint8Array;
}): Uint8Array {
  const udp = udpDatagram({
    srcIp: opts.src.ip,
    dstIp: opts.dst.ip,
    sp: opts.sp,
    dp: opts.dp,
    payload: opts.payload,
  });
  return ethFrame(opts.dst.mac, opts.src.mac, 0x0800, ipv4Packet(opts.src.ip, opts.dst.ip, 17, udp));
}

export function udpIpv6Frame(opts: {
  srcMac: string;
  dstMac: string;
  srcIp: string;
  dstIp: string;
  sp: number;
  dp: number;
  payload: Uint8Array;
}): Uint8Array {
  const udp = new Uint8Array(8 + opts.payload.length);
  const v = new DataView(udp.buffer);
  v.setUint16(0, opts.sp);
  v.setUint16(2, opts.dp);
  v.setUint16(4, udp.length);
  udp.set(opts.payload, 8);
  const ip = ipv6Packet(opts.srcIp, opts.dstIp, 17, udp);
  return ethFrame(opts.dstMac, opts.srcMac, 0x86dd, ip);
}

export function arpFrame(op: number, sender: Host, targetMac: string, targetIp: string, dstMac?: string): Uint8Array {
  const body = new Uint8Array(28);
  const v = new DataView(body.buffer);
  v.setUint16(0, 1);
  v.setUint16(2, 0x0800);
  body[4] = 6;
  body[5] = 4;
  v.setUint16(6, op);
  body.set(parseMac(sender.mac), 8);
  body.set(parseIpv4(sender.ip), 14);
  body.set(parseMac(targetMac), 18);
  body.set(parseIpv4(targetIp), 24);
  const dst = dstMac ?? (op === 1 ? "ff:ff:ff:ff:ff:ff" : targetMac);
  return ethFrame(dst, sender.mac, 0x0806, body);
}

export function icmpEchoFrame(src: Host, dst: Host, ident = 1, seq = 1): Uint8Array {
  const icmp = new Uint8Array(16);
  icmp[0] = 8;
  icmp[4] = (ident >> 8) & 0xff;
  icmp[5] = ident & 0xff;
  icmp[6] = (seq >> 8) & 0xff;
  icmp[7] = seq & 0xff;
  icmp.set(encodeUtf8("primer"), 8);
  const sum = inetChecksum([icmp]);
  icmp[2] = (sum >> 8) & 0xff;
  icmp[3] = sum & 0xff;
  return ethFrame(dst.mac, src.mac, 0x0800, ipv4Packet(src.ip, dst.ip, 1, icmp));
}

export function asBytes(payload: string | Uint8Array): Uint8Array {
  return typeof payload === "string" ? encodeUtf8(payload) : payload;
}

/** Tracks sequence numbers for one TCP conversation. */
export class TcpPair {
  aSeq = 1000;
  bSeq = 8000;
  a: Host;
  b: Host;
  aPort: number;
  bPort: number;
  constructor(a: Host, b: Host, aPort: number, bPort: number) {
    this.a = a;
    this.b = b;
    this.aPort = aPort;
    this.bPort = bPort;
  }

  fromA(payload: string | Uint8Array, flags = PSH | ACK): Uint8Array {
    return this.send(true, payload, flags);
  }

  fromB(payload: string | Uint8Array, flags = PSH | ACK): Uint8Array {
    return this.send(false, payload, flags);
  }

  private send(fromA: boolean, payload: string | Uint8Array, flags: number): Uint8Array {
    const data = asBytes(payload);
    const frame = tcpIpv4Frame({
      src: fromA ? this.a : this.b,
      dst: fromA ? this.b : this.a,
      sp: fromA ? this.aPort : this.bPort,
      dp: fromA ? this.bPort : this.aPort,
      seq: fromA ? this.aSeq : this.bSeq,
      ack: fromA ? this.bSeq : this.aSeq,
      flags,
      payload: data,
    });
    let adv = data.length;
    if (flags & SYN) adv += 1;
    if (flags & FIN) adv += 1;
    if (fromA) this.aSeq += adv;
    else this.bSeq += adv;
    return frame;
  }
}

export function modbusPdu(unit: number, pdu: Uint8Array, tx = 1): Uint8Array {
  const len = 1 + pdu.length;
  const mbap = new Uint8Array(7);
  const v = new DataView(mbap.buffer);
  v.setUint16(0, tx);
  v.setUint16(2, 0);
  v.setUint16(4, len);
  mbap[6] = unit;
  return concat(mbap, pdu);
}

export function dnsQuery(id: number, name: string, qtype = 1): Uint8Array {
  const hdr = new Uint8Array(12);
  const v = new DataView(hdr.buffer);
  v.setUint16(0, id);
  v.setUint16(2, 0x0100);
  v.setUint16(4, 1);
  return concat(hdr, dnsName(name), be16(qtype), be16(1));
}

export function dnsResponseA(id: number, name: string, ip: string): Uint8Array {
  const q = dnsQuery(id, name);
  const flags = new DataView(q.buffer, q.byteOffset, q.byteLength);
  flags.setUint16(2, 0x8180);
  flags.setUint16(6, 1);
  const ans = concat(
    Uint8Array.of(0xc0, 0x0c),
    be16(1),
    be16(1),
    new Uint8Array([0, 0, 0, 60]),
    be16(4),
    parseIpv4(ip),
  );
  return concat(q, ans);
}

function dnsName(name: string): Uint8Array {
  const parts: number[] = [];
  for (const label of name.split(".")) {
    if (!label) continue;
    const bytes = encodeUtf8(label);
    parts.push(bytes.length, ...bytes);
  }
  parts.push(0);
  return Uint8Array.from(parts);
}

export function dhcpDiscover(mac: string, hostname: string): Uint8Array {
  const pkt = new Uint8Array(240 + 64);
  pkt[0] = 1;
  pkt[1] = 1;
  pkt[2] = 6;
  const v = new DataView(pkt.buffer);
  v.setUint32(4, 0x12345678);
  pkt.set(parseMac(mac), 28);
  pkt[236] = 0x63;
  pkt[237] = 0x82;
  pkt[238] = 0x53;
  pkt[239] = 0x63;
  const host = encodeUtf8(hostname);
  const opts = concat(
    Uint8Array.of(53, 1, 1),
    Uint8Array.of(12, host.length),
    host,
    Uint8Array.of(255),
  );
  pkt.set(opts, 240);
  return pkt.subarray(0, 240 + opts.length);
}

export function httpRequest(method: string, path: string, host: string, extra = ""): string {
  return `${method} ${path} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: PrimerSample\r\n${extra}Connection: close\r\n\r\n`;
}

export function httpResponse(status: number, reason: string, body: Uint8Array, contentType: string): Uint8Array {
  const head = encodeUtf8(
    `HTTP/1.1 ${status} ${reason}\r\nContent-Type: ${contentType}\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`,
  );
  return concat(head, body);
}

export function basicAuth(user: string, pass: string): string {
  const token = btoa(`${user}:${pass}`);
  return `Authorization: Basic ${token}\r\n`;
}

export function mqttStr(s: string): Uint8Array {
  const b = encodeUtf8(s);
  return concat(be16(b.length), b);
}

export function mqttRemaining(len: number): Uint8Array {
  const out: number[] = [];
  let n = len;
  do {
    let b = n % 128;
    n = Math.floor(n / 128);
    if (n > 0) b |= 0x80;
    out.push(b);
  } while (n > 0);
  return Uint8Array.from(out);
}

export function mqttConnect(clientId: string, user?: string, pass?: string): Uint8Array {
  let flags = 0x02;
  if (user) flags |= 0x80;
  if (pass) flags |= 0x40;
  const parts = [mqttStr("MQTT"), Uint8Array.of(4, flags), be16(30), mqttStr(clientId)];
  if (user) parts.push(mqttStr(user));
  if (pass) parts.push(mqttStr(pass));
  const rest = concat(...parts);
  return concat(Uint8Array.of(0x10), mqttRemaining(rest.length), rest);
}

export function mqttPublish(topic: string, message: string): Uint8Array {
  const rest = concat(mqttStr(topic), encodeUtf8(message));
  return concat(Uint8Array.of(0x30), mqttRemaining(rest.length), rest);
}

export function tlsClientHello(sni: string): Uint8Array {
  const name = encodeUtf8(sni);
  const sniBody = concat(be16(name.length + 3), Uint8Array.of(0), be16(name.length), name);
  const sniExt = concat(be16(0), be16(sniBody.length), sniBody);
  const body = concat(
    be16(0x0303),
    new Uint8Array(32).map((_, i) => (i === 0 ? 0x20 : i)),
    Uint8Array.of(0),
    be16(2),
    be16(0x1301),
    Uint8Array.of(1, 0),
    be16(sniExt.length),
    sniExt,
  );
  const hs = concat(Uint8Array.of(1), be24(body.length), body);
  return tlsRecord(22, hs);
}

function be24(n: number): Uint8Array {
  return Uint8Array.of((n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
}

function tlsRecord(type: number, payload: Uint8Array): Uint8Array {
  return concat(Uint8Array.of(type, 0x03, 0x03), be16(payload.length), payload);
}

function derLen(n: number): Uint8Array {
  if (n < 128) return Uint8Array.of(n);
  if (n < 256) return Uint8Array.of(0x81, n);
  return Uint8Array.of(0x82, (n >> 8) & 0xff, n & 0xff);
}

function der(tag: number, content: Uint8Array): Uint8Array {
  return concat(Uint8Array.of(tag), derLen(content.length), content);
}

function derSeq(items: Uint8Array[]): Uint8Array {
  return der(0x30, concat(...items));
}

export function miniCertificate(subjectCn: string, issuerCn: string): Uint8Array {
  const oidCn = der(0x06, Uint8Array.of(0x55, 0x04, 0x03));
  const oidAlg = der(0x06, Uint8Array.of(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b));
  const oidRsa = der(0x06, Uint8Array.of(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01));
  const nullB = Uint8Array.of(0x05, 0x00);
  const name = (cn: string) => derSeq([der(0x31, derSeq([oidCn, der(0x13, encodeUtf8(cn))]))]);
  const tbs = derSeq([
    der(0xa0, der(0x02, Uint8Array.of(0x02))),
    der(0x02, Uint8Array.of(0x01, 0x02, 0x03)),
    derSeq([oidAlg, nullB]),
    name(issuerCn),
    derSeq([der(0x17, encodeUtf8("251101000000Z")), der(0x17, encodeUtf8("271101000000Z"))]),
    name(subjectCn),
    derSeq([derSeq([oidRsa, nullB]), der(0x03, concat(Uint8Array.of(0), Uint8Array.of(1, 2, 3, 4)))]),
  ]);
  return derSeq([
    tbs,
    derSeq([oidAlg, nullB]),
    der(0x03, concat(Uint8Array.of(0), Uint8Array.of(0xaa, 0xbb, 0xcc))),
  ]);
}

export function tlsCertificateRecord(cert: Uint8Array): Uint8Array {
  const list = concat(be24(cert.length), cert);
  const body = concat(be24(list.length), list);
  const hs = concat(Uint8Array.of(11), be24(body.length), body);
  return tlsRecord(22, hs);
}

export function tlsServerHello(): Uint8Array {
  const body = concat(be16(0x0303), new Uint8Array(32), Uint8Array.of(0), be16(0x1301), Uint8Array.of(0), be16(0));
  const hs = concat(Uint8Array.of(2), be24(body.length), body);
  return tlsRecord(22, hs);
}

export function smb2Header(command: number, sessionId = 0): Uint8Array {
  const h = new Uint8Array(64);
  h.set([0xfe, 0x53, 0x4d, 0x42]);
  const v = new DataView(h.buffer);
  v.setUint16(4, 64, true);
  v.setUint16(12, command, true);
  v.setBigUint64(40, BigInt(sessionId), true);
  return h;
}

export function ntlmAuthenticate(user: string, domain: string): Uint8Array {
  const enc = new TextEncoder();
  const u = utf16(user);
  const d = utf16(domain);
  const w = utf16("LAPTOP");
  const base = 64;
  const msg = new Uint8Array(base + d.length + u.length + w.length);
  msg.set(enc.encode("NTLMSSP\0"));
  const v = new DataView(msg.buffer);
  v.setUint32(8, 3, true);
  const put = (field: number, dataOff: number, data: Uint8Array) => {
    v.setUint16(field, data.length, true);
    v.setUint16(field + 2, data.length, true);
    v.setUint32(field + 4, dataOff, true);
  };
  let o = base;
  put(12, o, new Uint8Array());
  put(20, o, new Uint8Array());
  put(28, o, d);
  msg.set(d, o);
  o += d.length;
  put(36, o, u);
  msg.set(u, o);
  o += u.length;
  put(44, o, w);
  msg.set(w, o);
  o += w.length;
  put(52, o, new Uint8Array());
  v.setUint32(60, 0x00000001, true);
  return msg.subarray(0, o);
}

function utf16(s: string): Uint8Array {
  const out = new Uint8Array(s.length * 2);
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    out[i * 2] = c & 0xff;
    out[i * 2 + 1] = c >> 8;
  }
  return out;
}

export function smb2TreeConnect(path: string): Uint8Array {
  const encoded = utf16(path);
  const body = new Uint8Array(8 + encoded.length);
  const v = new DataView(body.buffer);
  v.setUint16(0, 9, true);
  v.setUint16(4, 72, true);
  v.setUint16(6, encoded.length, true);
  body.set(encoded, 8);
  return concat(smb2Header(3, 1), body);
}

export function smb2SessionSetup(security: Uint8Array): Uint8Array {
  const body = new Uint8Array(24 + security.length);
  const v = new DataView(body.buffer);
  v.setUint16(0, 25, true);
  body[2] = 0;
  body[3] = 1;
  v.setUint32(4, 1, true);
  v.setUint32(8, 0, true);
  v.setUint16(12, 64 + 24, true);
  v.setUint16(14, security.length, true);
  body.set(security, 24);
  return concat(smb2Header(1, 0), body);
}

export function s7Job(func: number, paramTail: Uint8Array = new Uint8Array()): Uint8Array {
  const param = concat(Uint8Array.of(func), paramTail);
  const header = new Uint8Array(10);
  header[0] = 0x32;
  header[1] = 0x01;
  header[4] = 0;
  header[5] = 1;
  header[6] = (param.length >> 8) & 0xff;
  header[7] = param.length & 0xff;
  const s7 = concat(header, param);
  const cotp = Uint8Array.of(0x02, 0xf0, 0x80);
  const tpktLen = 4 + cotp.length + s7.length;
  return concat(Uint8Array.of(0x03, 0x00, (tpktLen >> 8) & 0xff, tpktLen & 0xff), cotp, s7);
}

export function dnp3Request(func: number, dest = 1, src = 10): Uint8Array {
  const user = Uint8Array.of(0xc0, 0xc4, func);
  const length = 5 + user.length;
  const head = Uint8Array.of(0x05, 0x64, length, 0xc4, dest & 0xff, (dest >> 8) & 0xff, src & 0xff, (src >> 8) & 0xff);
  return concat(head, dnpCrc(head), user, dnpCrc(user));
}

export function dnpCrc(data: Uint8Array): Uint8Array {
  let crc = 0;
  for (const b of data) {
    crc ^= b;
    for (let i = 0; i < 8; i++) {
      crc = crc & 1 ? (crc >>> 1) ^ 0xa6bc : crc >>> 1;
    }
  }
  return le16((~crc) & 0xffff);
}

export function iec104I(typeId: number, cot = 6): Uint8Array {
  const asdu = Uint8Array.of(typeId, 0x01, cot & 0xff, (cot >> 8) & 0xff, 0x01, 0x00, 0x10, 0x00, 0x00, typeId >= 45 ? 0x01 : 0x00);
  const len = 4 + asdu.length;
  return concat(Uint8Array.of(0x68, len, 0x00, 0x00, 0x00, 0x00), asdu);
}

export function iec104U(control = 0x07): Uint8Array {
  return Uint8Array.of(0x68, 0x04, control, 0x00, 0x00, 0x00);
}

export function bacnetUnconfirmed(service: number): Uint8Array {
  const apdu = Uint8Array.of(0x10, service);
  const npdu = Uint8Array.of(0x01, 0x00);
  const len = 4 + npdu.length + apdu.length;
  return concat(Uint8Array.of(0x81, 0x0a, (len >> 8) & 0xff, len & 0xff), npdu, apdu);
}

export function bacnetConfirmed(service: number): Uint8Array {
  const apdu = Uint8Array.of(0x00, 0x05, 0x07, service, 0x0c, 0x00, 0x00, 0x00, 0x01);
  const npdu = Uint8Array.of(0x01, 0x04);
  const len = 4 + npdu.length + apdu.length;
  return concat(Uint8Array.of(0x81, 0x0a, (len >> 8) & 0xff, len & 0xff), npdu, apdu);
}

export function enipCip(service: number): Uint8Array {
  const cip = Uint8Array.of(service, 0x02, 0x20, 0x04, 0x24, 0x01, 0xc1, 0x00, 0x2a);
  const items = concat(Uint8Array.of(0x00, 0x00, 0x00, 0x00), Uint8Array.of(0xb2, 0x00), le16(cip.length), cip);
  const body = concat(new Uint8Array(4), be16(10), le16(2), items);
  const header = new Uint8Array(24);
  const v = new DataView(header.buffer);
  v.setUint16(0, 0x006f, true);
  v.setUint16(2, body.length, true);
  return concat(header, body);
}

export function opcuaHello(url: string): Uint8Array {
  const u = encodeUtf8(url);
  const fields = new Uint8Array(24);
  const v = new DataView(fields.buffer);
  v.setUint32(0, 0, true);
  v.setUint32(4, 65535, true);
  v.setUint32(8, 65535, true);
  v.setUint32(12, 0, true);
  v.setUint32(16, 0, true);
  v.setUint32(20, u.length, true);
  const body = concat(fields, u);
  const size = 8 + body.length;
  const head = encodeUtf8("HELF");
  const sz = new Uint8Array(4);
  new DataView(sz.buffer).setUint32(0, size, true);
  return concat(head, sz, body);
}

export function tinyGif(): Uint8Array {
  return encodeUtf8("GIF89a");
}
