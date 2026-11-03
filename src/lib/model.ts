export const Bit = {
  eth: 1 << 0,
  vlan: 1 << 1,
  arp: 1 << 2,
  ip: 1 << 3,
  ipv6: 1 << 4,
  icmp: 1 << 5,
  tcp: 1 << 6,
  udp: 1 << 7,
  dns: 1 << 8,
  dhcp: 1 << 9,
  http: 1 << 10,
  tls: 1 << 11,
  smb: 1 << 12,
  ssh: 1 << 13,
  ftp: 1 << 14,
  smtp: 1 << 15,
  modbus: 1 << 16,
  dnp3: 1 << 17,
  s7: 1 << 18,
  enip: 1 << 19,
  bacnet: 1 << 20,
  iec: 1 << 21,
  opcua: 1 << 22,
  mqtt: 1 << 23,
} as const;

export type LayerBit = (typeof Bit)[keyof typeof Bit];

export const LAYER_BY_NAME: Record<string, number> = {
  eth: Bit.eth,
  ethernet: Bit.eth,
  vlan: Bit.vlan,
  arp: Bit.arp,
  ip: Bit.ip,
  ipv4: Bit.ip,
  ipv6: Bit.ipv6,
  icmp: Bit.icmp,
  tcp: Bit.tcp,
  udp: Bit.udp,
  dns: Bit.dns,
  dhcp: Bit.dhcp,
  http: Bit.http,
  tls: Bit.tls,
  ssl: Bit.tls,
  smb: Bit.smb,
  ssh: Bit.ssh,
  ftp: Bit.ftp,
  smtp: Bit.smtp,
  modbus: Bit.modbus,
  dnp3: Bit.dnp3,
  s7: Bit.s7,
  s7comm: Bit.s7,
  enip: Bit.enip,
  cip: Bit.enip,
  bacnet: Bit.bacnet,
  iec: Bit.iec,
  iec104: Bit.iec,
  opcua: Bit.opcua,
  mqtt: Bit.mqtt,
};

export interface TreeNode {
  label: string;
  value: string;
  offset: number;
  length: number;
  explain: string;
  filter?: string;
  children: TreeNode[];
}

/** Compact per-packet facts. Optional fields are omitted when absent so 100k rows stay lighter. */
export interface Row {
  n: number;
  ts: number;
  len: number;
  macSrc: string;
  macDst: string;
  src: string;
  dst: string;
  sp: number;
  dp: number;
  ipProto: number;
  tcpFlags: number;
  tcpSeq: number;
  tcpAck: number;
  appOff: number;
  appLen: number;
  layers: number;
  proto: string;
  info: string;
  dnsQ?: string;
  dnsA?: string;
  httpMethod?: string;
  httpHost?: string;
  httpPath?: string;
  httpAuth?: string;
  httpStatus?: number;
  tlsSni?: string;
  tlsCn?: string;
  tlsIssuer?: string;
  ftpCmd?: string;
  ftpArg?: string;
  smtpLine?: string;
  smtpAuth?: string;
  modbusFunc?: number;
  modbusUnit?: number;
  modbusAddr?: number;
  modbusQty?: number;
  s7Func?: number;
  s7Pi?: string;
  dnp3Func?: number;
  iecType?: number;
  bacnetSvc?: number;
  bacnetConfirmed?: boolean;
  enipCmd?: number;
  cipSvc?: number;
  mqttType?: number;
  mqttTopic?: string;
  mqttUser?: string;
  mqttPass?: string;
  smbCmd?: string;
  smbPath?: string;
  smbUser?: string;
  sshBanner?: string;
  dhcpKind?: string;
  dhcpHost?: string;
  dhcpIp?: string;
  /** DHCP option 60, when the capture actually contains it. */
  dhcpVendor?: string;
  opcUrl?: string;
  /** IPv4 TTL or IPv6 hop limit. A stack habit, not a place. */
  ttl?: number;
  /** Short TCP option list, for example "mss:1460,nop,sack,ts". */
  tcpOptions?: string;
  httpUa?: string;
  /** SMB2 dialect name, only when a negotiate response named one we recognise. */
  smbDialect?: string;
  /** Present only when TShark supplied it. Primer does not compute a JA3. */
  tlsJa3?: string;
  /** Present only when TShark supplied an RDP keyboard-layout id. */
  rdpKeyboard?: string;
  /** pcap link type, so the detail view decodes the same way as the list. */
  linkType?: number;
}

export interface RawPacket {
  n: number;
  ts: number;
  origLen: number;
  data: Uint8Array;
  linkType: number;
  /**
   * Offset of `data` inside the file that was parsed.
   * After gzip is removed, this refers to the inflated bytes, which is the
   * evidence file the case stores.
   */
  fileOffset?: number;
}

export interface CaptureFile {
  format: "pcap" | "pcapng";
  packets: RawPacket[];
  warnings: string[];
  linkType: number;
}

export interface PacketRec {
  row: Row;
  raw: Uint8Array;
  fileOffset?: number;
  capLen?: number;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** What the bytes themselves show, or a reading those bytes are only consistent with. */
export type ClaimStatus = "observed" | "possible";
export type Confidence = "low" | "medium" | "high";
export type ValidationStatus = "pending" | "approved" | "rejected" | "escalated";
/** 1 anomaly, 2 suspicious activity, 3 enough to open an investigation. Never "confirmed exploit". */
export type TriageLevel = 1 | 2 | 3;

export interface Evidence {
  n: number;
  detail: string;
}

export interface LegacyTechnique {
  id: string;
  replacedBy: string;
}

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  summary: string;
  meaning: string;
  action: string;
  techniques: string[];
  legacy?: LegacyTechnique[];
  evidence: Evidence[];
  evidenceCount: number;
  /** primer, suricata, tshark, or correlation. Omitted on older in-memory findings. */
  engine?: string;
  ruleId?: string;
  confidence?: Confidence;
  triageLevel?: TriageLevel;
  claimStatus?: ClaimStatus;
  alternativeExplanation?: string;
  validation?: ValidationStatus;
  validatedBy?: string;
  validatedAt?: string | null;
  /** Whether the technique ids are observed facts or a possible reading. */
  techniqueSupport?: ClaimStatus;
  ts?: number;
}

export interface Conversation {
  a: string;
  b: string;
  proto: string;
  aPort: number;
  bPort: number;
  packets: number;
  bytes: number;
  aToB: number;
  bToA: number;
  start: number;
  end: number;
}

export interface Endpoint {
  addr: string;
  kind: "ip" | "mac";
  packets: number;
  bytesSent: number;
  bytesRecv: number;
  tx: number;
  rx: number;
}

export interface HierNode {
  name: string;
  packets: number;
  bytes: number;
  children: HierNode[];
}

export interface TimelineBucket {
  t: number;
  packets: number;
  bytes: number;
}

export interface DnsObject {
  n: number;
  ts: number;
  src: string;
  dst: string;
  name: string;
  answer: string;
}

export interface HttpObject {
  n: number;
  ts: number;
  src: string;
  dst: string;
  method: string;
  host: string;
  path: string;
  status: number;
  auth: string;
}

export interface TlsObject {
  n: number;
  ts: number;
  src: string;
  dst: string;
  sni: string;
  subject: string;
  issuer: string;
}

export interface FileObject {
  id: string;
  n: number;
  name: string;
  type: string;
  size: number;
  source: string;
  data: Uint8Array;
}

export interface Analysis {
  findings: Finding[];
  conversations: Conversation[];
  endpoints: Endpoint[];
  hierarchy: HierNode[];
  timeline: TimelineBucket[];
  dns: DnsObject[];
  http: HttpObject[];
  tls: TlsObject[];
  files: FileObject[];
  names: Record<string, string>;
  devices: string[];
  headline: string;
  detail: string;
  marks: { n: number; severity: Severity }[];
  t0: number;
  t1: number;
}

export const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function worse(a: Severity, b: Severity): Severity {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}
