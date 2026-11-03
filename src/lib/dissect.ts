import {
  decodeUtf16LE,
  latin1,
  printableStrings,
  readBe16,
  readBe32,
  readLe16,
  readLe32,
} from "./bytes.ts";
import { formatIpv4, formatIpv6, formatMac } from "./ip.ts";
import { Bit, type Row, type TreeNode } from "./model.ts";

const text = new TextDecoder();

export interface DissectMeta {
  n: number;
  ts: number;
  /** DLT / pcapng link type. Omitted only for frames that are already Ethernet. */
  linkType?: number;
}

export function dissect(data: Uint8Array, meta: DissectMeta, wantTree: boolean): { row: Row; tree: TreeNode[] } {
  const row = blankRow(meta, data.length);
  const tree: TreeNode[] = [];
  try {
    dissectLink(data, row, tree, wantTree, meta.linkType);
  } catch {
    row.info = "This frame could not be fully decoded";
    if (wantTree) {
      tree.push(leaf("Capture", "Decode stopped early", 0, data.length, "The bytes did not match the shape Primer expected. The hex view still shows the raw frame."));
    }
  }
  if (!row.info) row.info = row.proto === "Ethernet" ? "Ethernet frame" : row.proto;
  return { row, tree };
}

function blankRow(meta: DissectMeta, len: number): Row {
  return {
    n: meta.n,
    ts: meta.ts,
    len,
    macSrc: "",
    macDst: "",
    src: "",
    dst: "",
    sp: 0,
    dp: 0,
    ipProto: 0,
    tcpFlags: 0,
    tcpSeq: 0,
    tcpAck: 0,
    appOff: 0,
    appLen: 0,
    layers: 0,
    proto: "Raw",
    info: "",
  };
}

function leaf(label: string, value: string, offset: number, length: number, explain: string, filter?: string, children: TreeNode[] = []): TreeNode {
  return { label, value, offset, length, explain, filter, children };
}

function add(tree: TreeNode[], want: boolean, node: TreeNode | null): TreeNode | null {
  if (!want || !node) return null;
  tree.push(node);
  return node;
}

function child(parent: TreeNode | null, want: boolean, node: TreeNode): TreeNode | null {
  if (!want || !parent) return null;
  parent.children.push(node);
  return node;
}

function dissectLink(data: Uint8Array, row: Row, tree: TreeNode[], want: boolean, linkType?: number) {
  if (linkType !== undefined && linkType !== 1) {
    if (linkType === 0 || linkType === 108) return dissectNull(data, row, tree, want, linkType === 108);
    if (linkType === 113) return dissectLinuxSll(data, row, tree, want);
    if (linkType === 276) return dissectLinuxSll2(data, row, tree, want);
    if (linkType === 9) return dissectPpp(data, row, tree, want);
    if (linkType === 101 || linkType === 12) return dissectRawIp(data, row, tree, want);
    if (linkType === 105) return dissectDot11(data, 0, row, tree, want);
    if (linkType === 127) return dissectRadiotap(data, row, tree, want);
  }
  if (data.length >= 14 && (data[12] === 0x08 || data[12] === 0x86 || data[12] === 0x81 || data[12] === 0x00)) {
    dissectEthernet(data, 0, row, tree, want);
    return;
  }
  if (data.length >= 16 && readBe32(data, 0) <= 20 && (data[14] === 0x08 || data[14] === 0x86 || data[14] === 0x00)) {
    dissectLinuxSll(data, row, tree, want);
    return;
  }
  if (data.length >= 20 && data[0] >> 4 === 4) {
    row.layers |= Bit.ip;
    row.proto = "IPv4";
    const node = add(tree, want, leaf("Raw IPv4", "No link-layer header", 0, data.length, "This capture stored IP packets without an Ethernet header."));
    dissectIpv4(data, 0, row, node, want);
    return;
  }
  if (data.length >= 40 && data[0] >> 4 === 6) {
    row.layers |= Bit.ipv6;
    row.proto = "IPv6";
    const node = add(tree, want, leaf("Raw IPv6", "No link-layer header", 0, data.length, "This capture stored IPv6 packets without an Ethernet header."));
    dissectIpv6(data, 0, row, node, want);
    return;
  }
  row.info = "Unsupported link layer, shown as raw bytes";
  add(tree, want, leaf("Frame", `${data.length} bytes`, 0, data.length, "Primer did not recognise the link layer. You can still inspect the hex."));
}

function dissectLinuxSll(data: Uint8Array, row: Row, tree: TreeNode[], want: boolean) {
  if (data.length < 16) {
    row.info = "Truncated Linux cooked header";
    return;
  }
  const proto = readBe16(data, 14);
  row.layers |= Bit.eth;
  row.proto = "Linux cooked";
  const node = add(tree, want, leaf("Linux cooked capture (SLL)", `protocol 0x${proto.toString(16)}`, 0, 16, "This capture was taken on Linux without a full Ethernet header. Primer skips the 16-byte cooked header and decodes the packet inside."));
  dispatchEthertype(data, 16, proto, row, node, want);
}

function dissectLinuxSll2(data: Uint8Array, row: Row, tree: TreeNode[], want: boolean) {
  if (data.length < 20) {
    row.info = "Truncated Linux cooked v2 header";
    return;
  }
  const proto = readBe16(data, 0);
  row.layers |= Bit.eth;
  row.proto = "Linux cooked v2";
  const node = add(tree, want, leaf("Linux cooked capture (SLL2)", `protocol 0x${proto.toString(16)}`, 0, 20, "SLL2 is the newer Linux cooked header. The protocol number is at the start, and the frame follows 20 bytes later."));
  dispatchEthertype(data, 20, proto, row, node, want);
}

function dissectNull(data: Uint8Array, row: Row, tree: TreeNode[], want: boolean, networkOrder: boolean) {
  if (data.length < 4) {
    row.info = "Truncated loopback header";
    return;
  }
  const le = readLe32(data, 0);
  const be = readBe32(data, 0);
  const family = networkOrder ? be : le;
  const ipv6 = family === 10 || family === 24 || family === 28 || family === 30;
  row.proto = "Loopback";
  const node = add(tree, want, leaf("Null / loopback", ipv6 ? "IPv6" : "IPv4", 0, 4, "Some captures store a 4-byte address family instead of an Ethernet header. The IP packet starts immediately after it."));
  if (ipv6) dissectIpv6(data, 4, row, node, want);
  else dissectIpv4(data, 4, row, node, want);
}

function dissectRawIp(data: Uint8Array, row: Row, tree: TreeNode[], want: boolean) {
  const node = add(tree, want, leaf("Raw IP", "No link-layer header", 0, 0, "This capture stored IP packets directly."));
  if (data.length > 0 && data[0] >> 4 === 6) dissectIpv6(data, 0, row, node, want);
  else dissectIpv4(data, 0, row, node, want);
}

function dissectPpp(data: Uint8Array, row: Row, tree: TreeNode[], want: boolean) {
  let o = 0;
  if (data.length >= 2 && data[0] === 0xff && data[1] === 0x03) o = 2;
  let proto = 0;
  if (o < data.length && data[o] === 0x21) {
    proto = 0x21;
    o += 1;
  } else if (o + 1 < data.length) {
    proto = readBe16(data, o);
    o += 2;
  }
  row.proto = "PPP";
  const node = add(tree, want, leaf("PPP", `protocol 0x${proto.toString(16)}`, 0, o, "PPP carries IP with a small protocol number instead of an Ethernet header. 0x0021 is IPv4 and 0x0057 is IPv6."));
  if (proto === 0x21 || proto === 0x0021) dissectIpv4(data, o, row, node, want);
  else if (proto === 0x57 || proto === 0x0057) dissectIpv6(data, o, row, node, want);
  else row.info = `PPP protocol 0x${proto.toString(16)}`;
}

function dissectRadiotap(data: Uint8Array, row: Row, tree: TreeNode[], want: boolean) {
  if (data.length < 8) {
    row.info = "Truncated radiotap header";
    return;
  }
  const len = readLe16(data, 2);
  const header = Math.min(Math.max(len, 8), data.length);
  row.proto = "802.11 radiotap";
  const node = add(tree, want, leaf("Radiotap", `${header} byte radio header`, 0, header, "Radiotap is metadata from the Wi-Fi card (signal, rate, channel). The 802.11 frame starts after it."));
  dissectDot11(data.subarray(header), 0, row, tree, want, node);
}

function dissectDot11(frame: Uint8Array, base: number, row: Row, tree: TreeNode[], want: boolean, parent?: TreeNode | null) {
  if (frame.length < 10) {
    row.info = row.info || "Short 802.11 frame";
    return;
  }
  const fc0 = frame[0];
  const fc1 = frame[1];
  const type = (fc0 >> 2) & 0x3;
  const subtype = (fc0 >> 4) & 0xf;
  const typeName = type === 0 ? "management" : type === 1 ? "control" : type === 2 ? "data" : "extension";
  row.proto = "802.11";
  row.info = `802.11 ${typeName}`;
  const node = parent ?? add(tree, want, leaf("IEEE 802.11", typeName, base, frame.length, "A Wi-Fi frame. Primer reads open data frames. Encrypted ones stay as radio frames because the payload is not visible."));
  if (type !== 2) {
    child(node, want, leaf("Frame type", typeName, base, 2, "Management frames are beacons and associations. Control frames are short radio housekeeping."));
    return;
  }
  if (fc1 & 0x40) {
    row.info = "802.11 encrypted data";
    child(node, want, leaf("Protected", "yes", base + 1, 1, "The Protected flag means the payload is encrypted (WEP or WPA). Primer does not have the Wi-Fi key, so the IP inside stays hidden."));
    return;
  }
  const fourAddr = (fc1 & 0x03) === 0x03;
  const qos = (subtype & 0x08) !== 0;
  let off = 24 + (fourAddr ? 6 : 0) + (qos ? 2 : 0);
  if (frame.length >= off + 8 && frame[off] === 0xaa && frame[off + 1] === 0xaa) {
    const ethertype = readBe16(frame, off + 6);
    child(node, want, leaf("SNAP", `0x${ethertype.toString(16)}`, base + off, 8, "LLC/SNAP wraps the same EtherType you would see on Ethernet."));
    dispatchEthertype(frame, off + 8, ethertype, row, node, want);
    return;
  }
  if (frame.length > off && frame[off] >> 4 === 4) dissectIpv4(frame, off, row, node, want);
  else row.info = "802.11 data";
}

function dissectEthernet(data: Uint8Array, off: number, row: Row, tree: TreeNode[], want: boolean) {
  if (data.length < off + 14) {
    row.info = "Truncated Ethernet header";
    return;
  }
  row.macDst = formatMac(data, off);
  row.macSrc = formatMac(data, off + 6);
  let ethertype = readBe16(data, off + 12);
  let payload = off + 14;
  row.layers |= Bit.eth;
  row.proto = "Ethernet";
  const node = add(
    tree,
    want,
    leaf(
      "Ethernet II",
      `${row.macSrc} → ${row.macDst}`,
      off,
      14,
      "Ethernet is the local network envelope. It names the sending and receiving network cards, not the IP addresses you usually care about.",
      undefined,
      [
        leaf("Destination", row.macDst, off, 6, "The network card this frame was addressed to. ff:ff:ff:ff:ff:ff means everyone on the local segment.", `eth.dst == ${row.macDst}`),
        leaf("Source", row.macSrc, off + 6, 6, "The network card that sent this frame.", `eth.src == ${row.macSrc}`),
      ],
    ),
  );
  if (ethertype === 0x8100 && data.length >= payload + 4) {
    const tci = readBe16(data, payload);
    const vid = tci & 0x0fff;
    row.layers |= Bit.vlan;
    child(node, want, leaf("802.1Q VLAN", `VLAN ${vid}`, payload, 4, "A VLAN tag keeps traffic for different plant zones logically separate on the same wire.", `vlan.id == ${vid}`));
    ethertype = readBe16(data, payload + 2);
    payload += 4;
    if (node) node.length = payload - off;
  }
  child(node, want, leaf("Type", `0x${ethertype.toString(16).padStart(4, "0")}`, payload - 2, 2, ethertypeExplain(ethertype)));
  dispatchEthertype(data, payload, ethertype, row, node, want);
}

function ethertypeExplain(t: number): string {
  if (t === 0x0800) return "0x0800 means the payload is IPv4.";
  if (t === 0x86dd) return "0x86DD means the payload is IPv6.";
  if (t === 0x0806) return "0x0806 means ARP, a request that asks which network card owns an IP address.";
  return "EtherType tells you which protocol is inside the Ethernet frame.";
}

function dispatchEthertype(data: Uint8Array, off: number, ethertype: number, row: Row, parent: TreeNode | null, want: boolean) {
  if (ethertype === 0x0800) dissectIpv4(data, off, row, parent, want);
  else if (ethertype === 0x86dd) dissectIpv6(data, off, row, parent, want);
  else if (ethertype === 0x0806) dissectArp(data, off, row, parent, want);
  else row.info = `Ethernet type 0x${ethertype.toString(16)}`;
}

function dissectArp(data: Uint8Array, off: number, row: Row, parent: TreeNode | null, want: boolean) {
  if (data.length < off + 28) {
    row.info = "Truncated ARP";
    return;
  }
  const op = readBe16(data, off + 6);
  const spa = formatIpv4(data, off + 14);
  const tpa = formatIpv4(data, off + 24);
  const sha = formatMac(data, off + 8);
  row.layers |= Bit.arp;
  row.proto = "ARP";
  row.src = spa;
  row.dst = tpa;
  row.macSrc = row.macSrc || sha;
  row.info = op === 1 ? `Who has ${tpa}? Tell ${spa}` : op === 2 ? `${spa} is at ${sha}` : `ARP operation ${op}`;
  child(
    parent,
    want,
    leaf("ARP", row.info, off, 28, "ARP connects an IP address to a physical network card on the local segment. Devices announce themselves this way, and so do spoofers.", undefined, [
      leaf("Opcode", op === 1 ? "request (1)" : op === 2 ? "reply (2)" : String(op), off + 6, 2, op === 1 ? "A request asks the network who owns an IP." : "A reply claims that an IP belongs to a particular network card."),
      leaf("Sender IP", spa, off + 14, 4, "The IP address of the device asking or answering.", `ip.src == ${spa}`),
      leaf("Target IP", tpa, off + 24, 4, "The IP address being looked up.", `ip.dst == ${tpa}`),
    ]),
  );
}

function dissectIpv4(data: Uint8Array, off: number, row: Row, parent: TreeNode | null, want: boolean) {
  if (data.length < off + 20) {
    row.info = "Truncated IPv4 header";
    return;
  }
  const ihl = (data[off] & 0x0f) * 4;
  const total = readBe16(data, off + 2);
  const proto = data[off + 9];
  const src = formatIpv4(data, off + 12);
  const dst = formatIpv4(data, off + 16);
  row.layers |= Bit.ip;
  row.proto = "IPv4";
  row.src = src;
  row.dst = dst;
  row.ipProto = proto;
  const end = Math.min(data.length, off + Math.max(ihl, total || data.length));
  const node = child(
    parent,
    want,
    leaf("Internet Protocol version 4", `${src} → ${dst}`, off, ihl, "IPv4 carries the packet across networks. The source and destination here are the logical addresses, which matter more than the MAC addresses once a packet has been routed.", undefined, [
      leaf("Source", src, off + 12, 4, "The device that sent this IP packet.", `ip.src == ${src}`),
      leaf("Destination", dst, off + 16, 4, "The device this IP packet is trying to reach.", `ip.dst == ${dst}`),
      leaf("Protocol", ipProtoName(proto), off + 9, 1, "The next header: TCP, UDP, ICMP, or something else."),
    ]),
  );
  const payload = off + ihl;
  if (payload > data.length) return;
  if (proto === 6) dissectTcp(data, payload, end, row, node, want);
  else if (proto === 17) dissectUdp(data, payload, end, row, node, want);
  else if (proto === 1) dissectIcmp(data, payload, row, node, want);
  else row.info = `IPv4 ${src} → ${dst} protocol ${proto}`;
}

function dissectIpv6(data: Uint8Array, off: number, row: Row, parent: TreeNode | null, want: boolean) {
  if (data.length < off + 40) {
    row.info = "Truncated IPv6 header";
    return;
  }
  let next = data[off + 6];
  const src = formatIpv6(data, off + 8);
  const dst = formatIpv6(data, off + 24);
  row.layers |= Bit.ipv6;
  row.proto = "IPv6";
  row.src = src;
  row.dst = dst;
  let pos = off + 40;
  for (let hop = 0; hop < 6; hop++) {
    if (next !== 0 && next !== 43 && next !== 44 && next !== 60 && next !== 51) break;
    if (pos + 2 > data.length) break;
    const extLen = next === 44 ? 8 : (data[pos + 1] + 1) * 8;
    next = data[pos];
    pos += extLen;
  }
  row.ipProto = next;
  const node = child(
    parent,
    want,
    leaf("Internet Protocol version 6", `${src} → ${dst}`, off, pos - off, "IPv6 is the newer addressing scheme. Primer treats private and link-local IPv6 as internal, the same way it treats 10.x and 192.168.x.", undefined, [
      leaf("Source", src, off + 8, 16, "The sending IPv6 address.", `ipv6.src == ${src}`),
      leaf("Destination", dst, off + 24, 16, "The IPv6 address this packet is going to.", `ipv6.dst == ${dst}`),
    ]),
  );
  if (next === 6) dissectTcp(data, pos, data.length, row, node, want);
  else if (next === 17) dissectUdp(data, pos, data.length, row, node, want);
  else if (next === 58) dissectIcmp(data, pos, row, node, want, true);
  else row.info = `IPv6 ${src} → ${dst}`;
}

function ipProtoName(p: number): string {
  if (p === 6) return "TCP (6)";
  if (p === 17) return "UDP (17)";
  if (p === 1) return "ICMP (1)";
  return String(p);
}

function dissectIcmp(data: Uint8Array, off: number, row: Row, parent: TreeNode | null, want: boolean, v6 = false) {
  if (data.length < off + 2) return;
  const type = data[off];
  const code = data[off + 1];
  row.layers |= Bit.icmp;
  row.proto = v6 ? "ICMPv6" : "ICMP";
  const name = icmpName(type, v6);
  row.info = `${name} (${row.src} → ${row.dst})`;
  child(parent, want, leaf(row.proto, `${name}, code ${code}`, off, Math.min(8, data.length - off), icmpExplain(type, v6)));
}

function icmpName(type: number, v6: boolean): string {
  if (!v6 && type === 8) return "Echo request";
  if (!v6 && type === 0) return "Echo reply";
  if (!v6 && type === 3) return "Destination unreachable";
  if (!v6 && type === 11) return "Time exceeded";
  if (v6 && type === 128) return "Echo request";
  if (v6 && type === 129) return "Echo reply";
  if (v6 && type === 135) return "Neighbor solicitation";
  if (v6 && type === 136) return "Neighbor advertisement";
  return `Type ${type}`;
}

function icmpExplain(type: number, v6: boolean): string {
  if (type === 8 || type === 128) return "A ping. Someone is checking whether this address answers. A few pings are normal; a sweep of many addresses is reconnaissance.";
  if (type === 0 || type === 129) return "The reply to a ping. The address is alive.";
  if (!v6 && type === 3) return "The destination could not be reached. This often follows a scan of a closed network.";
  return "ICMP is the network's error and probe channel. It is not an industrial protocol, but scans often start here.";
}

function dissectTcp(data: Uint8Array, off: number, end: number, row: Row, parent: TreeNode | null, want: boolean) {
  if (data.length < off + 20) {
    row.info = "Truncated TCP header";
    return;
  }
  const sp = readBe16(data, off);
  const dp = readBe16(data, off + 2);
  const seq = readBe32(data, off + 4);
  const ack = readBe32(data, off + 8);
  const dataOff = ((data[off + 12] >> 4) & 0x0f) * 4;
  const flags = data[off + 13];
  row.layers |= Bit.tcp;
  row.proto = "TCP";
  row.sp = sp;
  row.dp = dp;
  row.tcpFlags = flags;
  row.tcpSeq = seq;
  row.tcpAck = ack;
  const payload = off + dataOff;
  const limit = Math.min(data.length, end);
  row.appOff = payload;
  row.appLen = Math.max(0, limit - payload);
  const flagText = tcpFlagText(flags);
  row.info = `${row.src}:${sp} → ${row.dst}:${dp} [${flagText}]`;
  const node = child(
    parent,
    want,
    leaf("Transmission Control Protocol", `${sp} → ${dp} [${flagText}]`, off, dataOff, "TCP is a reliable conversation between two ports. The port numbers are the best first clue to the application.", undefined, [
      leaf("Source port", String(sp), off, 2, "The port on the sender. Ephemeral ports are usually above 1024; well-known ports name a service.", `tcp.srcport == ${sp}`),
      leaf("Destination port", String(dp), off + 2, 2, portExplain(dp), `tcp.dstport == ${dp}`),
      leaf("Flags", flagText || "none", off + 13, 1, tcpFlagExplain(flags), undefined, [
        leaf("SYN", flags & 0x02 ? "1" : "0", off + 13, 1, "SYN starts a connection. A burst of SYNs to many ports is a port scan.", `tcp.flags.syn == ${flags & 0x02 ? 1 : 0}`),
        leaf("ACK", flags & 0x10 ? "1" : "0", off + 13, 1, "ACK means this segment acknowledges data the other side sent.", `tcp.flags.ack == ${flags & 0x10 ? 1 : 0}`),
        leaf("FIN", flags & 0x01 ? "1" : "0", off + 13, 1, "FIN asks to close the connection politely."),
        leaf("RST", flags & 0x04 ? "1" : "0", off + 13, 1, "RST aborts the connection. Closed ports often answer a scan with RST."),
      ]),
      leaf("Sequence", String(seq), off + 4, 4, "TCP uses sequence numbers to put the stream back in order. Follow stream uses these."),
    ]),
  );
  if (row.appLen > 0) dissectApp(data, payload, row.appLen, row, node, want, true);
  else if (!flagText.includes("SYN") && !flagText.includes("FIN") && !flagText.includes("RST")) {
    row.info = `${row.src}:${sp} → ${row.dst}:${dp} [${flagText || "ACK"}]`;
  }
}

function dissectUdp(data: Uint8Array, off: number, end: number, row: Row, parent: TreeNode | null, want: boolean) {
  if (data.length < off + 8) {
    row.info = "Truncated UDP header";
    return;
  }
  const sp = readBe16(data, off);
  const dp = readBe16(data, off + 2);
  const len = readBe16(data, off + 4);
  row.layers |= Bit.udp;
  row.proto = "UDP";
  row.sp = sp;
  row.dp = dp;
  const payload = off + 8;
  const limit = Math.min(data.length, end, off + (len || data.length));
  row.appOff = payload;
  row.appLen = Math.max(0, limit - payload);
  row.info = `${row.src}:${sp} → ${row.dst}:${dp} UDP ${row.appLen} bytes`;
  const node = child(
    parent,
    want,
    leaf("User Datagram Protocol", `${sp} → ${dp}`, off, 8, "UDP is a short message, not a conversation. DNS, DHCP, BACnet, and some industrial discovery use it.", undefined, [
      leaf("Source port", String(sp), off, 2, "The sending UDP port.", `udp.srcport == ${sp}`),
      leaf("Destination port", String(dp), off + 2, 2, portExplain(dp), `udp.dstport == ${dp}`),
      leaf("Length", String(len), off + 4, 2, "Length of the UDP header plus its payload."),
    ]),
  );
  if (row.appLen > 0) dissectApp(data, payload, row.appLen, row, node, want, false);
}

function tcpFlagText(flags: number): string {
  const names: string[] = [];
  if (flags & 0x02) names.push("SYN");
  if (flags & 0x10) names.push("ACK");
  if (flags & 0x08) names.push("PSH");
  if (flags & 0x01) names.push("FIN");
  if (flags & 0x04) names.push("RST");
  if (flags & 0x20) names.push("URG");
  return names.join(", ");
}

function tcpFlagExplain(flags: number): string {
  if ((flags & 0x02) && !(flags & 0x10)) return "A SYN without ACK is the first knock on a door. Many of these, to many ports, is a port scan.";
  if ((flags & 0x12) === 0x12) return "SYN, ACK accepts the connection. The service is open.";
  if (flags & 0x04) return "Reset. The host refused the connection or aborted it.";
  return "TCP flags say whether this segment opens, continues, or closes a connection.";
}

function portExplain(port: number): string {
  const known: Record<number, string> = {
    21: "Port 21 is FTP. Logins on FTP are usually cleartext.",
    22: "Port 22 is SSH, an encrypted remote shell.",
    25: "Port 25 is SMTP email.",
    53: "Port 53 is DNS, the internet's phone book. It can also hide a tunnel.",
    67: "Port 67 is the DHCP server.",
    68: "Port 68 is the DHCP client.",
    80: "Port 80 is ordinary web traffic, HTTP, which is not encrypted.",
    102: "Port 102 is ISO-TSAP, the usual door for Siemens S7 communication.",
    443: "Port 443 is HTTPS. Primer can see the handshake, not the encrypted page.",
    445: "Port 445 is SMB, Windows file sharing. Admin shares here are a lateral-movement smell.",
    502: "Port 502 is Modbus/TCP. Reads are normal polling; writes change the process.",
    1883: "Port 1883 is MQTT without encryption. Passwords in CONNECT are visible.",
    2404: "Port 2404 is IEC 60870-5-104, a common SCADA protocol.",
    4840: "Port 4840 is OPC UA.",
    20000: "Port 20000 is a common DNP3 port.",
    44818: "Port 44818 is EtherNet/IP, used by Rockwell and other CIP devices.",
    47808: "Port 47808 is BACnet/IP, common in building systems.",
  };
  return known[port] ?? `Port ${port} is the service number. Well-known ports under 1024 are registered; higher ports may be assigned by the application.`;
}

function dissectApp(data: Uint8Array, off: number, len: number, row: Row, parent: TreeNode | null, want: boolean, tcp: boolean) {
  const payload = data.subarray(off, off + len);
  const ports = [row.sp, row.dp];
  const has = (p: number) => ports.includes(p);
  const tryOrder: Array<() => boolean> = [];
  const push = (pred: boolean, fn: () => boolean) => {
    if (pred) tryOrder.push(fn);
  };
  push(has(53), () => tryDns(payload, off, row, parent, want, tcp));
  push(has(67) || has(68), () => tryDhcp(payload, off, row, parent, want));
  push(has(502), () => tryModbus(payload, off, row, parent, want));
  push(has(102), () => tryS7(payload, off, row, parent, want));
  push(has(20000), () => tryDnp3(payload, off, row, parent, want));
  push(has(44818), () => tryEnip(payload, off, row, parent, want));
  push(has(47808), () => tryBacnet(payload, off, row, parent, want));
  push(has(2404), () => tryIec(payload, off, row, parent, want));
  push(has(4840), () => tryOpcua(payload, off, row, parent, want));
  push(has(1883) || has(8883), () => tryMqtt(payload, off, row, parent, want));
  push(has(445) || has(139), () => trySmb(payload, off, row, parent, want));
  push(has(22), () => trySsh(payload, off, row, parent, want));
  push(has(21), () => tryFtp(payload, off, row, parent, want));
  push(has(25) || has(587), () => trySmtp(payload, off, row, parent, want));
  push(has(80) || has(8080) || has(8000), () => tryHttp(payload, off, row, parent, want));
  push(has(443) || has(8443), () => tryTls(payload, off, row, parent, want));
  for (const fn of tryOrder) if (fn()) return;
  if (tryHttp(payload, off, row, parent, want)) return;
  if (tryTls(payload, off, row, parent, want)) return;
  if (trySsh(payload, off, row, parent, want)) return;
  if (tryMqtt(payload, off, row, parent, want)) return;
  if (trySmb(payload, off, row, parent, want)) return;
  if (payload[0] === 0x05 && payload[1] === 0x64 && tryDnp3(payload, off, row, parent, want)) return;
  if (payload[0] === 0x03 && payload[1] === 0x00 && tryS7(payload, off, row, parent, want)) return;
  if (tryModbus(payload, off, row, parent, want, true)) return;
}

const MODBUS_FUNC: Record<number, string> = {
  1: "Read Coils",
  2: "Read Discrete Inputs",
  3: "Read Holding Registers",
  4: "Read Input Registers",
  5: "Write Single Coil",
  6: "Write Single Register",
  8: "Diagnostics",
  15: "Write Multiple Coils",
  16: "Write Multiple Registers",
  22: "Mask Write Register",
  23: "Read/Write Multiple Registers",
  43: "Encapsulated Interface",
};

function tryModbus(payload: Uint8Array, off: number, row: Row, parent: TreeNode | null, want: boolean, strict = false): boolean {
  if (payload.length < 8) return false;
  const proto = readBe16(payload, 2);
  const len = readBe16(payload, 4);
  const unit = payload[6];
  const func = payload[7];
  const base = func & 0x7f;
  if (proto !== 0) return false;
  if (len < 2 || len > payload.length - 6 + 8) return false;
  if (!MODBUS_FUNC[base] && strict) return false;
  if (!MODBUS_FUNC[base] && base > 24 && base !== 43) return false;
  const name = MODBUS_FUNC[base] ?? `Function ${base}`;
  const ex = func & 0x80 ? " (exception)" : "";
  row.layers |= Bit.modbus;
  row.proto = "Modbus";
  row.modbusFunc = base;
  row.modbusUnit = unit;
  let addr: number | undefined;
  let qty: number | undefined;
  const request = row.dp === 502 || (row.sp !== 502 && (len === 6 || base === 15 || base === 16));
  if (request && payload.length >= 12 && (base <= 6 || base === 15 || base === 16)) {
    addr = readBe16(payload, 8);
    qty = readBe16(payload, 10);
    row.modbusAddr = addr;
    row.modbusQty = base === 5 || base === 6 ? 1 : qty;
  }
  const where = addr !== undefined ? `, unit ${unit}, address ${addr}${qty !== undefined && base !== 5 && base !== 6 ? `, quantity ${qty}` : ""}` : `, unit ${unit}`;
  row.info = `Modbus ${name}${ex}${where}`;
  const write = [5, 6, 15, 16, 22, 23].includes(base);
  child(
    parent,
    want,
    leaf("Modbus/TCP", `${name}${ex}`, off, Math.min(payload.length, 6 + len), write
      ? "This is a Modbus write. Unlike a poll, a write asks the device to change a coil or register — a setpoint, a command bit, or a forced output."
      : "This is a Modbus read. SCADA systems poll the same registers over and over. That is usually normal.", `modbus.func == ${base}`, [
      leaf("Unit", String(unit), off + 6, 1, "The Modbus unit (slave) identifier. One IP can front several units.", `modbus.unit == ${unit}`),
      leaf("Function", `${base} ${name}`, off + 7, 1, modbusFuncExplain(base), `modbus.func == ${base}`),
      ...(addr !== undefined
        ? [leaf("Address", String(addr), off + 8, 2, "The register or coil address. A sweep through many addresses is point and tag identification.", `modbus.addr == ${addr}`)]
        : []),
    ]),
  );
  return true;
}

function modbusFuncExplain(func: number): string {
  if (func === 5) return "Function 5 forces a single coil on or off. That is a direct command to an output.";
  if (func === 6) return "Function 6 writes one holding register, often a setpoint.";
  if (func === 15) return "Function 15 writes several coils at once.";
  if (func === 16) return "Function 16 writes several holding registers. This is a common way to push a block of setpoints.";
  if (func === 3) return "Function 3 reads holding registers. Steady reads of the same addresses look like normal polling.";
  if (func === 1) return "Function 1 reads coils, the on/off points.";
  return "The function code says whether this is a read, a write, or a diagnostic.";
}

const S7_FUNC: Record<number, string> = {
  0x00: "CPU services",
  0x04: "Read Var",
  0x05: "Write Var",
  0xf0: "Setup communication",
  0x1a: "Request download",
  0x1b: "Download block",
  0x1c: "Download ended",
  0x1d: "Start upload",
  0x1e: "Upload",
  0x1f: "End upload",
  0x28: "PI-Service",
  0x29: "PLC Stop",
};

function tryS7(payload: Uint8Array, off: number, row: Row, parent: TreeNode | null, want: boolean): boolean {
  if (payload.length < 7 || payload[0] !== 0x03 || payload[1] !== 0x00) return false;
  const cotpLi = payload[4];
  const cotpType = payload[5];
  const s7off = 5 + cotpLi;
  const typeName = cotpType === 0xe0 ? "Connection request" : cotpType === 0xd0 ? "Connection confirm" : cotpType === 0xf0 ? "Data" : `0x${cotpType.toString(16)}`;
  row.layers |= Bit.s7;
  row.proto = "S7comm";
  if (payload.length < s7off + 10 || payload[s7off] !== 0x32) {
    row.info = `S7 COTP ${typeName}`;
    child(parent, want, leaf("TPKT / COTP", typeName, off, Math.min(payload.length, s7off), "Siemens S7 rides on TPKT and COTP before the PLC message. A connection request is the handshake, not yet a command."));
    return true;
  }
  const rosctr = payload[s7off + 1];
  const paramLen = readBe16(payload, s7off + 6);
  let p = s7off + 10;
  if (rosctr === 2 || rosctr === 3) p += 2;
  const func = p < payload.length ? payload[p] : -1;
  const paramEnd = Math.min(payload.length, p + paramLen);
  const strings = printableStrings(payload.subarray(p, paramEnd), 3);
  const pi = strings.join(" ");
  row.s7Func = func;
  if (pi) row.s7Pi = pi;
  const fname = S7_FUNC[func] ?? `Function 0x${func.toString(16)}`;
  row.info = pi ? `S7 ${fname} ${pi}` : `S7 ${fname}`;
  const explain = s7Explain(func, pi);
  child(
    parent,
    want,
    leaf("S7 Communication", row.info, off, payload.length, explain, func >= 0 ? `s7.func == ${func}` : undefined, [
      leaf("ROSCTR", rosctrName(rosctr), off + s7off + 1, 1, "Job is a request. Ack-Data is the PLC's answer."),
      leaf("Function", fname, off + p, 1, explain, `s7.func == ${func}`),
      ...(pi ? [leaf("Parameter text", pi, off + p, paramEnd - p, "Printable text inside the S7 parameter. Names such as P_PROGRAM or a block name tell you whether this is a stop, a download, or an upload.")] : []),
    ]),
  );
  return true;
}

function rosctrName(r: number): string {
  if (r === 1) return "Job (1)";
  if (r === 2) return "Ack (2)";
  if (r === 3) return "Ack-Data (3)";
  if (r === 7) return "Userdata (7)";
  return String(r);
}

function s7Explain(func: number, pi: string): string {
  if (func === 0x29 || /stop/i.test(pi)) return "PLC Stop asks the CPU to leave RUN. Production stops. This is rare outside a planned maintenance window.";
  if (func === 0x1a || func === 0x1b || func === 0x1c) return "A program download pushes logic into the PLC. Whoever can do this can change how the process runs.";
  if (func === 0x1d || func === 0x1e || func === 0x1f) return "A program upload copies the PLC logic out. That is how an attacker, or an engineer, takes a copy of the program.";
  if (func === 0x05) return "Write Var changes values in the PLC, similar in spirit to a Modbus write.";
  if (func === 0x04) return "Read Var fetches values from the PLC. Engineering tools and historians both do this.";
  if (func === 0xf0) return "Setup communication negotiates how big the S7 messages can be. It is a handshake, not a command.";
  return "S7comm is the Siemens protocol used to program and operate S7 PLCs.";
}

const DNP_FUNC: Record<number, string> = {
  0: "Confirm",
  1: "Read",
  2: "Write",
  3: "Select",
  4: "Operate",
  5: "Direct Operate",
  6: "Direct Operate, no ack",
  13: "Cold Restart",
  14: "Warm Restart",
  18: "Stop Application",
  129: "Response",
};

function tryDnp3(payload: Uint8Array, off: number, row: Row, parent: TreeNode | null, want: boolean): boolean {
  if (payload.length < 10 || payload[0] !== 0x05 || payload[1] !== 0x64) return false;
  const dest = readLe16(payload, 4);
  const src = readLe16(payload, 6);
  let func = -1;
  if (payload.length >= 13) func = payload[12];
  row.layers |= Bit.dnp3;
  row.proto = "DNP3";
  if (func >= 0) row.dnp3Func = func;
  const fname = DNP_FUNC[func] ?? (func >= 0 ? `Function ${func}` : "link frame");
  row.info = `DNP3 ${fname}, master ${src} → outstation ${dest}`;
  const control = [3, 4, 5, 6, 13, 14, 18].includes(func);
  child(
    parent,
    want,
    leaf("DNP3", fname, off, payload.length, control
      ? "Operate, select, and restart functions tell a DNP3 outstation to act or to reboot. That is a command, not telemetry."
      : "DNP3 is widely used by utilities. Reads collect status. Confirm and response frames keep the session honest.", func >= 0 ? `dnp3.func == ${func}` : undefined, [
      leaf("Destination", String(dest), off + 4, 2, "The DNP3 link address this frame is going to."),
      leaf("Source", String(src), off + 6, 2, "The DNP3 link address that sent this frame."),
      ...(func >= 0 ? [leaf("Function", fname, off + 12, 1, "Application function code. Select and operate are the control path.", `dnp3.func == ${func}`)] : []),
    ]),
  );
  return true;
}

function tryEnip(payload: Uint8Array, off: number, row: Row, parent: TreeNode | null, want: boolean): boolean {
  if (payload.length < 24) return false;
  const cmd = readLe16(payload, 0);
  const known = cmd === 0x0065 || cmd === 0x006f || cmd === 0x0070 || cmd === 0x0063 || cmd === 0x0004;
  if (!known) return false;
  const names: Record<number, string> = {
    0x0065: "Register Session",
    0x006f: "Send RR Data",
    0x0070: "Send Unit Data",
    0x0063: "List Services",
    0x0004: "List Services (legacy)",
  };
  row.layers |= Bit.enip;
  row.proto = "EtherNet/IP";
  row.enipCmd = cmd;
  let cip = -1;
  if ((cmd === 0x006f || cmd === 0x0070) && payload.length >= 30) {
    let p = 24;
    if (payload.length >= p + 8) {
      p += 6;
      const count = readLe16(payload, p);
      p += 2;
      for (let i = 0; i < count && p + 4 <= payload.length; i++) {
        const type = readLe16(payload, p);
        const len = readLe16(payload, p + 2);
        if ((type === 0x00b2 || type === 0x00b1) && p + 4 < payload.length) cip = payload[p + 4];
        p += 4 + len;
      }
    }
  }
  if (cip >= 0) row.cipSvc = cip & 0x7f;
  const cipName = cip >= 0 ? cipServiceName(cip & 0x7f) : "";
  row.info = cipName ? `EtherNet/IP ${names[cmd] ?? cmd}, CIP ${cipName}` : `EtherNet/IP ${names[cmd] ?? "command " + cmd}`;
  const write = cip >= 0 && [0x10, 0x4d, 0x53].includes(cip & 0x7f);
  child(parent, want, leaf("EtherNet/IP", row.info, off, payload.length, write
    ? "A CIP write changes a tag or attribute on a Logix-style controller. Treat it like a setpoint change."
    : "EtherNet/IP wraps CIP, the Common Industrial Protocol. Register Session is just a handshake.", cip >= 0 ? `cip.service == ${cip & 0x7f}` : undefined));
  return true;
}

function cipServiceName(s: number): string {
  if (s === 0x01) return "Get Attributes All";
  if (s === 0x0e) return "Get Attribute Single";
  if (s === 0x10) return "Set Attribute Single";
  if (s === 0x4c) return "Read Tag";
  if (s === 0x4d) return "Write Tag";
  if (s === 0x52) return "Read Tag Fragmented";
  if (s === 0x53) return "Write Tag Fragmented";
  return `Service 0x${s.toString(16)}`;
}

function tryBacnet(payload: Uint8Array, off: number, row: Row, parent: TreeNode | null, want: boolean): boolean {
  if (payload.length < 6 || payload[0] !== 0x81) return false;
  let p = 4;
  if (p + 2 > payload.length || payload[p] !== 0x01) return false;
  const control = payload[p + 1];
  p += 2;
  if (control & 0x20) {
    if (p + 3 > payload.length) return false;
    const dlen = payload[p + 2];
    p += 3 + dlen + 1;
  }
  if (control & 0x08) {
    if (p + 3 > payload.length) return false;
    const slen = payload[p + 2];
    p += 3 + slen;
  }
  if (p >= payload.length) return false;
  if (control & 0x80) {
    row.layers |= Bit.bacnet;
    row.proto = "BACnet";
    row.info = "BACnet network message";
    child(parent, want, leaf("BACnet", "Network-layer message", off, payload.length, "A BACnet network message, not an application request."));
    return true;
  }
  const pdu = payload[p] >> 4;
  let svc = -1;
  let confirmed = false;
  if (pdu === 0 && p + 3 < payload.length) {
    svc = payload[p + 3];
    confirmed = true;
  } else if (pdu === 1 && p + 1 < payload.length) {
    svc = payload[p + 1];
  } else if (pdu === 3 && p + 2 < payload.length) {
    svc = payload[p + 2];
  }
  row.layers |= Bit.bacnet;
  row.proto = "BACnet";
  if (svc >= 0) row.bacnetSvc = svc;
  row.bacnetConfirmed = confirmed;
  const sname = bacnetService(pdu, svc);
  row.info = `BACnet ${sname}`;
  child(parent, want, leaf("BACnet/IP", sname, off, payload.length, bacnetExplain(pdu, svc), svc >= 0 ? `bacnet.service == ${svc}` : undefined));
  return true;
}

function bacnetService(pdu: number, svc: number): string {
  if (pdu === 1 && svc === 8) return "Who-Is";
  if (pdu === 1 && svc === 0) return "I-Am";
  if (pdu === 0 && svc === 12) return "ReadProperty";
  if (pdu === 0 && svc === 14) return "ReadPropertyMultiple";
  if (pdu === 0 && svc === 15) return "WriteProperty";
  if (pdu === 2) return "SimpleACK";
  if (pdu === 3) return "ComplexACK";
  return svc >= 0 ? `PDU ${pdu} service ${svc}` : `PDU ${pdu}`;
}

function bacnetExplain(pdu: number, svc: number): string {
  if (pdu === 1 && svc === 8) return "Who-Is asks every BACnet device to introduce itself. One of these is normal discovery. A storm of them is mapping the building.";
  if (pdu === 0 && svc === 15) return "WriteProperty changes a BACnet object: a setpoint, a schedule, or a binary output.";
  if (pdu === 0 && svc === 12) return "ReadProperty fetches one BACnet value. Building management systems do this constantly.";
  return "BACnet is the common language of building automation: HVAC, access, and lighting.";
}

const IEC_TYPE: Record<number, string> = {
  1: "Single-point information",
  3: "Double-point information",
  9: "Measured value, normalized",
  11: "Measured value, scaled",
  13: "Measured value, float",
  30: "Single-point with time",
  36: "Measured float with time",
  45: "Single command",
  46: "Double command",
  47: "Regulating step command",
  48: "Setpoint, normalized",
  49: "Setpoint, scaled",
  50: "Setpoint, float",
  51: "Bitstring command",
  58: "Single command with time",
  59: "Double command with time",
  60: "Regulating step with time",
  61: "Setpoint, normalized, with time",
  62: "Setpoint, scaled, with time",
  63: "Setpoint, float, with time",
  64: "Bitstring command with time",
  100: "Interrogation command",
  103: "Clock synchronisation",
};

function tryIec(payload: Uint8Array, off: number, row: Row, parent: TreeNode | null, want: boolean): boolean {
  if (payload.length < 6 || payload[0] !== 0x68) return false;
  const apduLen = payload[1];
  if (apduLen < 4) return false;
  const c0 = payload[2];
  row.layers |= Bit.iec;
  row.proto = "IEC 104";
  if ((c0 & 0x03) === 0x03) {
    const u = c0 & 0xfc;
    const name = u === 0x04 ? "STARTDT activate" : u === 0x08 ? "STARTDT confirm" : u === 0x10 ? "STOPDT activate" : u === 0x40 ? "TESTFR activate" : "U-format";
    row.info = `IEC 104 ${name}`;
    child(parent, want, leaf("IEC 60870-5-104", name, off, payload.length, "U-format frames start, stop, or test the IEC 104 connection. They are session control, not process commands."));
    return true;
  }
  if ((c0 & 0x01) === 0x01) {
    row.info = "IEC 104 S-format supervisory";
    child(parent, want, leaf("IEC 60870-5-104", "S-format", off, payload.length, "An S-format frame acknowledges I-frames. It carries no process data."));
    return true;
  }
  if (payload.length < 7) return true;
  const typeId = payload[6];
  row.iecType = typeId;
  const name = IEC_TYPE[typeId] ?? `Type ${typeId}`;
  row.info = `IEC 104 ${name}`;
  const command = (typeId >= 45 && typeId <= 64) || typeId === 100 || typeId === 103;
  child(parent, want, leaf("IEC 60870-5-104", name, off, payload.length, iecExplain(typeId), `iec.type == ${typeId}`, [
    leaf("Type ID", `${typeId} ${name}`, off + 6, 1, iecExplain(typeId), `iec.type == ${typeId}`),
  ]));
  void command;
  return true;
}

function iecExplain(typeId: number): string {
  if (typeId >= 45 && typeId <= 64) return "This type ID is a command or setpoint. It tells a controlled station to switch, step, or adopt a new value. General interrogation is different; this one acts.";
  if (typeId === 100) return "General interrogation asks the station to send its current points. SCADA masters do this when a session starts. It is a read, not a command to move equipment.";
  if (typeId === 103) return "Clock sync keeps the RTU's timestamps aligned. Usually benign, worth noting if you did not expect it.";
  if (typeId <= 40) return "This is telemetry: the station reporting a point or a measurement.";
  return "Type ID selects the kind of IEC 104 information object.";
}

function tryOpcua(payload: Uint8Array, off: number, row: Row, parent: TreeNode | null, want: boolean): boolean {
  if (payload.length < 8) return false;
  const kind = latin1(payload.subarray(0, 3));
  if (!["HEL", "ACK", "ERR", "OPN", "MSG", "CLO"].includes(kind)) return false;
  const chunk = String.fromCharCode(payload[3]);
  if (!["F", "C", "A"].includes(chunk)) return false;
  row.layers |= Bit.opcua;
  row.proto = "OPC UA";
  let url = "";
  if (kind === "HEL" && payload.length >= 32) {
    const urlLen = readLe32(payload, 28);
    if (urlLen > 0 && 32 + urlLen <= payload.length) url = text.decode(payload.subarray(32, 32 + urlLen));
  }
  if (url) row.opcUrl = url;
  row.info = url ? `OPC UA Hello ${url}` : `OPC UA ${kind}${chunk}`;
  child(parent, want, leaf("OPC UA", row.info, off, payload.length, url
    ? "The Hello message names the OPC UA endpoint the client wants. Primer does not decrypt the session that follows."
    : "OPC UA is a modern industrial protocol. Hello, Open, and Message chunks set up a secure channel. Primer shows the framing, not the inner service calls."));
  return true;
}

const MQTT_TYPE = ["", "CONNECT", "CONNACK", "PUBLISH", "PUBACK", "PUBREC", "PUBREL", "PUBCOMP", "SUBSCRIBE", "SUBACK", "UNSUBSCRIBE", "UNSUBACK", "PINGREQ", "PINGRESP", "DISCONNECT"];

function tryMqtt(payload: Uint8Array, off: number, row: Row, parent: TreeNode | null, want: boolean): boolean {
  if (payload.length < 2) return false;
  const type = payload[0] >> 4;
  if (type < 1 || type > 14) return false;
  let mul = 1;
  let remaining = 0;
  let i = 1;
  for (; i < 5 && i < payload.length; i++) {
    remaining += (payload[i] & 0x7f) * mul;
    mul *= 128;
    if ((payload[i] & 0x80) === 0) break;
  }
  if (i >= payload.length) return false;
  const body = payload.subarray(i + 1, Math.min(payload.length, i + 1 + remaining));
  const looks = type === 1 && body.length >= 6 && body[0] === 0 && body[1] === 4 && latin1(body.subarray(2, 6)) === "MQTT";
  const portish = row.sp === 1883 || row.dp === 1883 || row.sp === 8883 || row.dp === 8883;
  if (!looks && !portish) return false;
  row.layers |= Bit.mqtt;
  row.proto = "MQTT";
  row.mqttType = type;
  let extra = "";
  if (looks) {
    let p = 2 + 4 + 1;
    if (p + 1 < body.length) {
      const flags = body[p];
      p += 1 + 2;
      const client = mqttRead(body, p);
      p = client.next;
      extra = client.value ? ` client ${client.value}` : "";
      if (flags & 0x04) {
        const willT = mqttRead(body, p);
        p = willT.next;
        const willM = mqttRead(body, p);
        p = willM.next;
      }
      if (flags & 0x80) {
        const user = mqttRead(body, p);
        p = user.next;
        if (user.value) row.mqttUser = user.value;
      }
      if (flags & 0x40) {
        const pass = mqttRead(body, p);
        if (pass.value) row.mqttPass = pass.value;
      }
    }
  } else if (type === 3) {
    const topic = mqttRead(body, 0);
    if (topic.value) {
      row.mqttTopic = topic.value;
      extra = ` ${topic.value}`;
    }
  }
  row.info = `MQTT ${MQTT_TYPE[type] ?? type}${extra}`;
  const passNote = row.mqttPass ? " The password is in the clear." : "";
  child(parent, want, leaf("MQTT", row.info, off, payload.length, `MQTT publishes and subscribes to topics. CONNECT can carry a username and password with no encryption on port 1883.${passNote}`, `mqtt.type == ${type}`, [
    ...(row.mqttUser ? [leaf("Username", row.mqttUser, off, 0, "The MQTT username travelled with the packet.")] : []),
    ...(row.mqttPass ? [leaf("Password", row.mqttPass, off, 0, "This password was not encrypted. Anyone who can see the capture can read it.", "mqtt.password")] : []),
    ...(row.mqttTopic ? [leaf("Topic", row.mqttTopic, off, 0, "The topic is the subject line of the message, such as a temperature or a command.")] : []),
  ]));
  return true;
}

function mqttRead(buf: Uint8Array, o: number): { value: string; next: number } {
  if (o + 2 > buf.length) return { value: "", next: buf.length };
  const len = readBe16(buf, o);
  const start = o + 2;
  const end = Math.min(buf.length, start + len);
  return { value: text.decode(buf.subarray(start, end)), next: end };
}

const SMB2 = ["Negotiate", "Session Setup", "Logoff", "Tree Connect", "Tree Disconnect", "Create", "Close", "Flush", "Read", "Write", "Lock", "Ioctl", "Cancel", "Echo", "Query Directory", "Change Notify", "Query Info", "Set Info"];

function trySmb(payload: Uint8Array, off: number, row: Row, parent: TreeNode | null, want: boolean): boolean {
  let base = 0;
  if (payload.length >= 8 && payload[4] === 0xfe && payload[5] === 0x53) base = 4;
  if (!(payload.length >= base + 64 && payload[base] === 0xfe && payload[base + 1] === 0x53 && payload[base + 2] === 0x4d && payload[base + 3] === 0x42)) {
    if (!(payload.length >= 4 && payload[0] === 0xff && payload[1] === 0x53)) return false;
    row.layers |= Bit.smb;
    row.proto = "SMB";
    row.info = "SMB1";
    child(parent, want, leaf("SMB", "SMB1 header", off, payload.length, "SMB1 is the older Windows file-sharing dialect. It is obsolete and often disabled for a reason."));
    return true;
  }
  const cmd = readLe16(payload, base + 12);
  row.layers |= Bit.smb;
  row.proto = "SMB2";
  row.smbCmd = SMB2[cmd] ?? `Command ${cmd}`;
  const smb = payload.subarray(base);
  const ntlm = indexOfAscii(smb, "NTLMSSP\0");
  if (ntlm >= 0 && ntlm + 64 <= smb.length && readLe32(smb, ntlm + 8) === 3) {
    const user = ntlmField(smb, ntlm, 36);
    if (user) row.smbUser = user;
  }
  if (cmd === 3 && smb.length >= 72) {
    const pathOff = readLe16(smb, 64 + 4);
    const pathLen = readLe16(smb, 64 + 6);
    if (pathOff + pathLen <= smb.length) {
      row.smbPath = decodeUtf16LE(smb.subarray(pathOff, pathOff + pathLen)).replace(/\0/g, "");
    }
  }
  if (!row.smbPath) {
    const hit = printableStrings(smb, 6).find((s) => /ADMIN\$|IPC\$|C\$/i.test(s));
    if (hit) row.smbPath = hit;
  }
  row.info = row.smbPath ? `SMB2 ${row.smbCmd} ${row.smbPath}` : row.smbUser ? `SMB2 ${row.smbCmd} user ${row.smbUser}` : `SMB2 ${row.smbCmd}`;
  const share = /ADMIN\$|C\$/i.test(row.smbPath ?? "");
  child(parent, want, leaf("SMB2", row.info, off, payload.length, share
    ? "A connection to an admin share (ADMIN$ or C$) is a common Windows lateral-movement step. It is sometimes also a legitimate admin tool."
    : "SMB2 is Windows file sharing. Negotiate and session setup are the handshake. Tree connect chooses the share.", `smb.cmd == "${row.smbCmd}"`, [
    ...(row.smbUser ? [leaf("NTLM user", row.smbUser, off, 0, "The username inside NTLM was visible in this packet. The password hash is not the same thing as a cleartext password, but the account name is.")] : []),
    ...(row.smbPath ? [leaf("Share", row.smbPath, off, 0, "The share path the client asked to open.")] : []),
  ]));
  return true;
}

function ntlmField(smb: Uint8Array, start: number, field: number): string {
  const len = readLe16(smb, start + field);
  const rel = readLe32(smb, start + field + 4);
  if (len === 0 || start + rel + len > smb.length) return "";
  return decodeUtf16LE(smb.subarray(start + rel, start + rel + len));
}

function indexOfAscii(buf: Uint8Array, needle: string): number {
  const n = new TextEncoder().encode(needle);
  outer: for (let i = 0; i + n.length <= buf.length; i++) {
    for (let j = 0; j < n.length; j++) if (buf[i + j] !== n[j]) continue outer;
    return i;
  }
  return -1;
}

function trySsh(payload: Uint8Array, off: number, row: Row, parent: TreeNode | null, want: boolean): boolean {
  const line = latin1(payload.subarray(0, Math.min(payload.length, 120))).split(/\r?\n/)[0] ?? "";
  if (!line.startsWith("SSH-") && row.sp !== 22 && row.dp !== 22) return false;
  if (!line.startsWith("SSH-") && payload.length > 0 && payload[0] !== 0x53) return false;
  if (!line.startsWith("SSH-") && payload.length === 0) return false;
  row.layers |= Bit.ssh;
  row.proto = "SSH";
  if (line.startsWith("SSH-")) row.sshBanner = line;
  row.info = row.sshBanner ? row.sshBanner : "SSH binary packet";
  child(parent, want, leaf("SSH", row.info, off, payload.length, "SSH encrypts the session after this banner. Primer can see the version string, not the commands typed inside."));
  return true;
}

const FTP_CMDS = new Set(["USER", "PASS", "QUIT", "PORT", "PASV", "TYPE", "RETR", "STOR", "LIST", "NLST", "CWD", "PWD", "MKD", "RMD", "DELE", "SYST", "FEAT", "AUTH", "NOOP"]);

function tryFtp(payload: Uint8Array, off: number, row: Row, parent: TreeNode | null, want: boolean): boolean {
  const line = latin1(payload).replace(/\0/g, "").trim();
  const first = line.split(/\r?\n/)[0] ?? "";
  const cmd = first.match(/^([A-Z]{3,4})(?:\s(.*))?$/);
  const reply = first.match(/^(\d{3})(?:\s|-)?(.*)$/);
  const portOk = row.sp === 21 || row.dp === 21;
  if (!cmd && !reply) return false;
  if (cmd && !FTP_CMDS.has(cmd[1]) && !portOk) return false;
  if (reply && !portOk && !cmd) return false;
  row.layers |= Bit.ftp;
  row.proto = "FTP";
  if (cmd) {
    row.ftpCmd = cmd[1];
    row.ftpArg = cmd[2] ?? "";
    row.info = `FTP ${cmd[1]}${row.ftpArg ? " " + row.ftpArg : ""}`;
  } else if (reply) {
    row.ftpCmd = reply[1];
    row.ftpArg = reply[2] ?? "";
    row.info = `FTP ${reply[1]} ${reply[2] ?? ""}`.trim();
  }
  const secret = row.ftpCmd === "PASS";
  child(parent, want, leaf("FTP", row.info, off, payload.length, secret
    ? "FTP PASS sends the password with no encryption. It is now in this capture, in the clear."
    : "FTP is a cleartext file transfer protocol. USER names the account. RETR and STOR name files.", row.ftpCmd ? `ftp.request.command == ${row.ftpCmd}` : undefined));
  return true;
}

function trySmtp(payload: Uint8Array, off: number, row: Row, parent: TreeNode | null, want: boolean): boolean {
  const line = (latin1(payload).split(/\r?\n/)[0] ?? "").trim();
  if (!/^(EHLO|HELO|MAIL|RCPT|AUTH|DATA|QUIT|RSET|VRFY|STARTTLS)\b/i.test(line) && !/^\d{3} /.test(line)) return false;
  if (!/^(EHLO|HELO|MAIL|RCPT|AUTH|DATA|QUIT|RSET|VRFY|STARTTLS)\b/i.test(line) && row.sp !== 25 && row.dp !== 25 && row.sp !== 587 && row.dp !== 587) return false;
  row.layers |= Bit.smtp;
  row.proto = "SMTP";
  row.smtpLine = line;
  const auth = line.match(/^AUTH\s+PLAIN\s+(\S+)/i) ?? line.match(/^AUTH\s+LOGIN/i);
  if (auth && auth[1]) {
    const decoded = decodeB64(auth[1]);
    const parts = decoded.split("\0").filter(Boolean);
    if (parts.length >= 2) row.smtpAuth = `${parts[parts.length - 2]}:${parts[parts.length - 1]}`;
    else if (decoded) row.smtpAuth = decoded;
  }
  row.info = `SMTP ${line.slice(0, 80)}`;
  child(parent, want, leaf("SMTP", line.slice(0, 120), off, payload.length, row.smtpAuth
    ? "SMTP AUTH PLAIN carried a username and password that anyone on the path can read."
    : "SMTP is email. AUTH is the login. The message itself follows DATA."));
  return true;
}

function tryHttp(payload: Uint8Array, off: number, row: Row, parent: TreeNode | null, want: boolean): boolean {
  const head = latin1(payload.subarray(0, Math.min(payload.length, 1500)));
  if (!/^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE) /.test(head) && !/^HTTP\/1\.[01] /.test(head)) return false;
  const splitAt = head.indexOf("\r\n\r\n");
  const headerText = splitAt >= 0 ? head.slice(0, splitAt) : head;
  const lines = headerText.split(/\r?\n/);
  const start = lines[0] ?? "";
  row.layers |= Bit.http;
  row.proto = "HTTP";
  const headers: Record<string, string> = {};
  for (const line of lines.slice(1)) {
    const c = line.indexOf(":");
    if (c > 0) headers[line.slice(0, c).trim().toLowerCase()] = line.slice(c + 1).trim();
  }
  if (headers.host) row.httpHost = headers.host;
  if (headers.authorization) {
    const m = headers.authorization.match(/^Basic\s+([A-Za-z0-9+/=]+)/i);
    row.httpAuth = m ? decodeB64(m[1]) : headers.authorization;
  }
  const req = start.match(/^([A-Z]+)\s+(\S+)\s+HTTP\/1/);
  const res = start.match(/^HTTP\/1\.[01]\s+(\d{3})/);
  if (req) {
    row.httpMethod = req[1];
    row.httpPath = req[2];
    row.info = `HTTP ${req[1]} ${headers.host ?? ""}${req[2]}`.trim();
  } else if (res) {
    row.httpStatus = Number(res[1]);
    row.info = `HTTP ${res[1]}`;
  } else row.info = "HTTP";
  child(parent, want, leaf("HTTP", start, off, Math.min(payload.length, Math.max(headerText.length, 1)), row.httpAuth
    ? "This HTTP request used Basic authentication. The user and password are only base64, which is encoding, not encryption."
    : "HTTP is the web, without encryption. Anyone on the path can read the URL, headers, and body.", row.httpMethod ? `http.request.method == ${row.httpMethod}` : undefined, [
    ...(row.httpHost ? [leaf("Host", row.httpHost, off, 0, "The website or device name the client asked for.", `http.host == ${row.httpHost}`)] : []),
    ...(row.httpPath ? [leaf("Path", row.httpPath, off, 0, "The path on that host.")] : []),
    ...(row.httpAuth ? [leaf("Authorization", row.httpAuth, off, 0, "Decoded Basic credentials. They were visible on the wire.")] : []),
  ]));
  return true;
}

function tryTls(payload: Uint8Array, off: number, row: Row, parent: TreeNode | null, want: boolean): boolean {
  if (payload.length < 5 || payload[0] !== 22 || payload[1] !== 3) return false;
  row.layers |= Bit.tls;
  row.proto = "TLS";
  let sni = "";
  let cn = "";
  let issuer = "";
  let hello = false;
  let o = 0;
  while (o + 5 <= payload.length && payload[o] >= 20 && payload[o] <= 23 && payload[o + 1] === 3) {
    const len = readBe16(payload, o + 3);
    const rec = payload.subarray(o + 5, Math.min(payload.length, o + 5 + len));
    if (payload[o] === 22) {
      let h = 0;
      while (h + 4 <= rec.length) {
        const ht = rec[h];
        const hl = (rec[h + 1] << 16) | (rec[h + 2] << 8) | rec[h + 3];
        const body = rec.subarray(h + 4, Math.min(rec.length, h + 4 + hl));
        if (ht === 1) {
          hello = true;
          sni = sni || parseSni(body);
        } else if (ht === 11) {
          const found = findCns(body);
          if (found.length) {
            issuer = issuer || found[0];
            cn = found[found.length - 1];
          }
        }
        h += 4 + hl;
        if (hl === 0) break;
      }
    }
    o += 5 + len;
    if (len === 0) break;
  }
  if (sni) row.tlsSni = sni;
  if (cn) row.tlsCn = cn;
  if (issuer && issuer !== cn) row.tlsIssuer = issuer;
  row.info = sni ? `TLS ClientHello SNI ${sni}` : cn ? `TLS certificate CN ${cn}` : hello ? "TLS ClientHello" : "TLS handshake";
  child(parent, want, leaf("TLS", row.info, off, payload.length, sni
    ? "SNI is the name the client asked for, sent before encryption starts. It tells you the destination service, not the page contents."
    : cn
      ? "The certificate names the server. Primer reads the subject from the handshake. It does not decrypt the session."
      : "A TLS handshake sets up encryption. Primer stops at the metadata.", sni ? `tls.sni == ${sni}` : undefined, [
    ...(sni ? [leaf("Server name", sni, off, 0, "Server Name Indication, the hostname in the ClientHello.", `tls.sni == ${sni}`)] : []),
    ...(cn ? [leaf("Certificate subject", cn, off, 0, "The common name on the certificate the server presented.")] : []),
    ...(row.tlsIssuer ? [leaf("Certificate issuer", row.tlsIssuer, off, 0, "Who signed the certificate. A private plant CA is normal. An unexpected issuer is worth a look.")] : []),
  ]));
  return true;
}

function parseSni(body: Uint8Array): string {
  if (body.length < 40) return "";
  let p = 34;
  if (p >= body.length) return "";
  const sidLen = body[p];
  p += 1 + sidLen;
  if (p + 2 > body.length) return "";
  const csLen = readBe16(body, p);
  p += 2 + csLen;
  if (p + 1 > body.length) return "";
  const compLen = body[p];
  p += 1 + compLen;
  if (p + 2 > body.length) return "";
  const extLen = readBe16(body, p);
  p += 2;
  const end = Math.min(body.length, p + extLen);
  while (p + 4 <= end) {
    const et = readBe16(body, p);
    const el = readBe16(body, p + 2);
    if (et === 0 && p + 4 + el <= body.length && el >= 5) {
      const nameLen = readBe16(body, p + 7);
      const start = p + 9;
      if (start + nameLen <= body.length) return text.decode(body.subarray(start, start + nameLen));
    }
    p += 4 + el;
  }
  return "";
}

function findCns(buf: Uint8Array): string[] {
  const out: string[] = [];
  for (let i = 0; i + 5 < buf.length; i++) {
    if (buf[i] === 0x06 && buf[i + 1] === 0x03 && buf[i + 2] === 0x55 && buf[i + 3] === 0x04 && buf[i + 4] === 0x03) {
      let j = i + 5;
      if (j + 2 > buf.length) break;
      const tag = buf[j];
      let len = buf[j + 1];
      let n = 2;
      if (len & 0x80) {
        const nb = len & 0x7f;
        len = 0;
        for (let k = 0; k < nb && j + 2 + k < buf.length; k++) len = (len << 8) | buf[j + 2 + k];
        n = 2 + nb;
      }
      if ((tag === 0x13 || tag === 0x0c || tag === 0x16) && j + n + len <= buf.length) {
        out.push(text.decode(buf.subarray(j + n, j + n + len)));
      }
    }
  }
  return out;
}

function tryDns(payload: Uint8Array, off: number, row: Row, parent: TreeNode | null, want: boolean, tcp: boolean): boolean {
  let p = payload;
  let delta = 0;
  if (tcp && payload.length >= 14) {
    const l = readBe16(payload, 0);
    if (l === payload.length - 2 || l < payload.length) {
      p = payload.subarray(2);
      delta = 2;
    }
  }
  if (p.length < 12) return false;
  const flags = readBe16(p, 2);
  const qd = readBe16(p, 4);
  const an = readBe16(p, 6);
  if (qd > 8 || qd === 0) return false;
  const name = readDnsName(p, 12);
  if (!name.name) return false;
  const isResp = (flags & 0x8000) !== 0;
  row.layers |= Bit.dns;
  row.proto = "DNS";
  row.dnsQ = name.name;
  let answer = "";
  if (isResp && an > 0 && name.next + 4 <= p.length) {
    const ans = readDnsName(p, name.next + 4);
    if (ans.next + 10 <= p.length) {
      const typ = readBe16(p, ans.next);
      const rdlen = readBe16(p, ans.next + 8);
      if (typ === 1 && rdlen === 4 && ans.next + 10 + 4 <= p.length) answer = formatIpv4(p, ans.next + 10);
    }
  }
  if (answer) row.dnsA = answer;
  const qtypeOff = name.next;
  const qtype = qtypeOff + 2 <= p.length ? readBe16(p, qtypeOff) : 1;
  row.info = isResp
    ? `DNS response ${name.name}${answer ? " → " + answer : ""}`
    : `DNS query ${dnsType(qtype)} ${name.name}`;
  child(parent, want, leaf("Domain Name System", row.info, off, payload.length, dnsExplain(name.name), `dns.qry.name == ${name.name}`, [
    leaf("Query", name.name, off + delta + 12, Math.max(1, name.consumed), "The name being looked up. Very long, random-looking names can be a tunnel hiding data inside DNS.", `dns.qry.name == ${name.name}`),
    leaf("Type", dnsType(qtype), off + delta + qtypeOff, 2, "A is an IPv4 address. AAAA is IPv6. TXT is sometimes used to carry tunnelled data."),
    ...(answer ? [leaf("Answer", answer, off, 0, "The address the server returned for this name.")] : []),
  ]));
  return true;
}

function dnsExplain(name: string): string {
  if (name.length > 50) return "This DNS name is unusually long. Attackers hide stolen data or commands inside DNS queries because DNS is often allowed out.";
  return "DNS turns a name into an address. Normal lookups are short names you would recognise.";
}

function dnsType(t: number): string {
  if (t === 1) return "A";
  if (t === 28) return "AAAA";
  if (t === 16) return "TXT";
  if (t === 5) return "CNAME";
  if (t === 12) return "PTR";
  if (t === 15) return "MX";
  return String(t);
}

function readDnsName(buf: Uint8Array, offset: number): { name: string; next: number; consumed: number } {
  const labels: string[] = [];
  let pos = offset;
  let next = offset;
  let jumped = false;
  let guard = 0;
  const start = offset;
  while (pos < buf.length && guard++ < 40) {
    const len = buf[pos];
    if (len === 0) {
      if (!jumped) next = pos + 1;
      break;
    }
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= buf.length) break;
      if (!jumped) next = pos + 2;
      jumped = true;
      pos = ((len & 0x3f) << 8) | buf[pos + 1];
      continue;
    }
    if (pos + 1 + len > buf.length) break;
    labels.push(latin1(buf.subarray(pos + 1, pos + 1 + len)));
    pos += 1 + len;
    if (!jumped) next = pos;
  }
  return { name: labels.join("."), next, consumed: Math.max(1, (jumped ? next : pos + 1) - start) };
}

const DHCP_TYPES = ["", "Discover", "Offer", "Request", "Decline", "ACK", "NAK", "Release", "Inform"];

function tryDhcp(payload: Uint8Array, off: number, row: Row, parent: TreeNode | null, want: boolean): boolean {
  if (payload.length < 240) return false;
  if (payload[236] !== 0x63 || payload[237] !== 0x82 || payload[238] !== 0x53 || payload[239] !== 0x63) return false;
  let kind = 0;
  let host = "";
  let reqIp = "";
  let p = 240;
  while (p < payload.length) {
    const code = payload[p];
    if (code === 255) break;
    if (code === 0) {
      p += 1;
      continue;
    }
    const len = payload[p + 1] ?? 0;
    const val = payload.subarray(p + 2, p + 2 + len);
    if (code === 53 && val.length) kind = val[0];
    if (code === 12) host = text.decode(val);
    if (code === 50 && val.length === 4) reqIp = formatIpv4(val, 0);
    p += 2 + len;
  }
  const yi = formatIpv4(payload, 16);
  row.layers |= Bit.dhcp;
  row.proto = "DHCP";
  row.dhcpKind = DHCP_TYPES[kind] ?? `type ${kind}`;
  if (host) row.dhcpHost = host;
  if (reqIp) row.dhcpIp = reqIp;
  else if (yi !== "0.0.0.0") row.dhcpIp = yi;
  row.info = `DHCP ${row.dhcpKind}${host ? " " + host : ""}${row.dhcpIp ? " " + row.dhcpIp : ""}`;
  child(parent, want, leaf("DHCP", row.info, off, payload.length, "DHCP hands out IP addresses. The hostname option is often the device's own name, which is useful when you are still learning the network.", undefined, [
    leaf("Message type", row.dhcpKind, off, 0, "Discover and Request come from the device. Offer and ACK come from the server."),
    ...(host ? [leaf("Hostname", host, off, 0, "The name the device claims. Trust it as a label, not as proof.")] : []),
  ]));
  return true;
}

function decodeB64(s: string): string {
  try {
    const bin = atob(s);
    let out = "";
    for (let i = 0; i < bin.length; i++) out += bin[i] >= " " && bin[i] <= "~" ? bin[i] : bin[i] === "\0" ? "\0" : "";
    return out;
  } catch {
    return "";
  }
}
