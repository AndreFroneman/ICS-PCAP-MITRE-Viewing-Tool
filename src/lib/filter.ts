import { LAYER_BY_NAME, type Row } from "./model.ts";

export class FilterError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FilterError";
  }
}

type Value = string | number | number[];

interface Cmp {
  kind: "cmp";
  field: string;
  op: string;
  value: Value;
}
interface Proto {
  kind: "proto";
  name: string;
}
interface Not {
  kind: "not";
  expr: Expr;
}
interface Bin {
  kind: "and" | "or";
  left: Expr;
  right: Expr;
}
type Expr = Cmp | Proto | Not | Bin;

export interface CompiledFilter {
  text: string;
  test: (row: Row, t0: number) => boolean;
}

export function compileFilter(input: string): CompiledFilter {
  const text = input.trim();
  if (!text) return { text: "", test: () => true };
  const parser = new Parser(text);
  const expr = parser.parseOr();
  parser.skip();
  if (!parser.eof()) throw new FilterError(`Unexpected text near “${parser.rest()}”.`);
  return {
    text,
    test: (row, t0) => evalExpr(expr, row, t0),
  };
}

class Parser {
  i = 0;
  src: string;
  constructor(src: string) {
    this.src = src;
  }
  eof(): boolean {
    return this.i >= this.src.length;
  }
  rest(): string {
    return this.src.slice(this.i, this.i + 24);
  }
  skip() {
    while (this.i < this.src.length && /\s/.test(this.src[this.i])) this.i++;
  }
  peek(s: string): boolean {
    this.skip();
    return this.src.startsWith(s, this.i);
  }
  eat(s: string): boolean {
    if (this.peek(s)) {
      this.i += s.length;
      return true;
    }
    return false;
  }
  parseOr(): Expr {
    let left = this.parseAnd();
    while (this.eat("||")) left = { kind: "or", left, right: this.parseAnd() };
    return left;
  }
  parseAnd(): Expr {
    let left = this.parseUnary();
    while (this.eat("&&")) left = { kind: "and", left, right: this.parseUnary() };
    return left;
  }
  parseUnary(): Expr {
    this.skip();
    if (this.eat("!")) return { kind: "not", expr: this.parseUnary() };
    return this.parsePrimary();
  }
  parsePrimary(): Expr {
    this.skip();
    if (this.eat("(")) {
      const e = this.parseOr();
      if (!this.eat(")")) throw new FilterError("Missing closing parenthesis.");
      return e;
    }
    const field = this.readField();
    if (!field) throw new FilterError("Expected a field or protocol name.");
    this.skip();
    const op = this.readOp();
    if (!op) {
      if (field === "frame") throw new FilterError("frame needs a comparison, for example frame contains \"PASS\".");
      if (!LAYER_BY_NAME[field] && field !== "frame") {
        throw new FilterError(`Unknown protocol “${field}”. Try tcp, dns, modbus, s7, dnp3…`);
      }
      return { kind: "proto", name: field };
    }
    const value = this.readValue(op);
    return { kind: "cmp", field, op, value };
  }
  readField(): string {
    this.skip();
    const m = /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*/.exec(this.src.slice(this.i));
    if (!m) return "";
    this.i += m[0].length;
    return m[0].toLowerCase();
  }
  readOp(): string {
    this.skip();
    const ops = ["==", "!=", ">=", "<=", ">", "<"];
    for (const op of ops) if (this.eat(op)) return op;
    const word = this.src.slice(this.i);
    const m = /^(contains|matches|in)\b/i.exec(word);
    if (m) {
      this.i += m[0].length;
      return m[1].toLowerCase();
    }
    return "";
  }
  readValue(op: string): Value {
    this.skip();
    if (op === "in") {
      if (!this.eat("{")) throw new FilterError("in expects a list in braces, such as {1, 2, 3}.");
      const nums: number[] = [];
      while (!this.eof()) {
        this.skip();
        if (this.eat("}")) break;
        this.eat(",");
        this.skip();
        const n = this.readNumber();
        if (n === null) throw new FilterError("Only numbers are allowed in an in-list.");
        nums.push(n);
        this.skip();
        this.eat(",");
      }
      if (!nums.length) throw new FilterError("The in-list is empty.");
      return nums;
    }
    const ip = /^(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]*:[0-9a-f:]+)/i.exec(this.src.slice(this.i));
    if (ip) {
      this.i += ip[0].length;
      return ip[0];
    }
    if (this.peek("\"") || this.peek("'")) {
      const q = this.src[this.i];
      this.i++;
      let s = "";
      while (this.i < this.src.length && this.src[this.i] !== q) {
        if (this.src[this.i] === "\\" && this.i + 1 < this.src.length) {
          s += this.src[this.i + 1];
          this.i += 2;
          continue;
        }
        s += this.src[this.i];
        this.i++;
      }
      if (this.src[this.i] !== q) throw new FilterError("Missing closing quote.");
      this.i++;
      return s;
    }
    const num = this.readNumber();
    if (num !== null) return num;
    const ident = /^[^\s&|!)]+/.exec(this.src.slice(this.i));
    if (!ident) throw new FilterError("Expected a value.");
    this.i += ident[0].length;
    return ident[0];
  }
  readNumber(): number | null {
    const m = /^-?\d+(?:\.\d+)?/.exec(this.src.slice(this.i));
    if (!m) return null;
    const n = Number(m[0]);
    if (Number.isNaN(n)) return null;
    this.i += m[0].length;
    return n;
  }
}

function evalExpr(expr: Expr, row: Row, t0: number): boolean {
  if (expr.kind === "and") return evalExpr(expr.left, row, t0) && evalExpr(expr.right, row, t0);
  if (expr.kind === "or") return evalExpr(expr.left, row, t0) || evalExpr(expr.right, row, t0);
  if (expr.kind === "not") return !evalExpr(expr.expr, row, t0);
  if (expr.kind === "proto") {
    const bit = LAYER_BY_NAME[expr.name];
    return bit ? (row.layers & bit) !== 0 : false;
  }
  if (expr.kind !== "cmp") return false;
  const values = fieldValues(expr.field, row, t0);
  if (values.length === 0) return false;
  return values.some((v) => compare(v, expr.op, expr.value));
}

function fieldValues(field: string, row: Row, t0: number): Array<string | number> {
  if (field === "ip.addr" || field === "ipv6.addr") return [row.src, row.dst].filter(Boolean);
  if (field === "eth.addr") return [row.macSrc, row.macDst].filter(Boolean);
  if (field === "tcp.port" || field === "udp.port") return [row.sp, row.dp];
  const one = oneField(field, row, t0);
  return one === undefined ? [] : [one];
}

function oneField(field: string, row: Row, t0: number): string | number | undefined {
  switch (field) {
    case "frame.number":
      return row.n;
    case "frame.len":
    case "frame.length":
      return row.len;
    case "frame.time_relative":
      return row.ts - t0;
    case "frame.time":
      return row.ts;
    case "eth.src":
      return row.macSrc;
    case "eth.dst":
      return row.macDst;
    case "ip.src":
    case "ipv6.src":
      return row.src;
    case "ip.dst":
    case "ipv6.dst":
      return row.dst;
    case "ip.proto":
      return row.ipProto;
    case "tcp.srcport":
    case "udp.srcport":
      return row.sp;
    case "tcp.dstport":
    case "udp.dstport":
      return row.dp;
    case "tcp.flags.syn":
      return row.tcpFlags & 0x02 ? 1 : 0;
    case "tcp.flags.ack":
      return row.tcpFlags & 0x10 ? 1 : 0;
    case "tcp.flags.fin":
      return row.tcpFlags & 0x01 ? 1 : 0;
    case "tcp.flags.rst":
      return row.tcpFlags & 0x04 ? 1 : 0;
    case "tcp.flags":
      return row.tcpFlags;
    case "tcp.len":
    case "udp.len":
      return row.appLen;
    case "dns.qry.name":
      return row.dnsQ;
    case "http.host":
      return row.httpHost;
    case "http.request.method":
      return row.httpMethod;
    case "http.request.uri":
      return row.httpPath;
    case "http.response.code":
      return row.httpStatus;
    case "tls.sni":
      return row.tlsSni;
    case "modbus.func":
      return row.modbusFunc;
    case "modbus.unit":
      return row.modbusUnit;
    case "modbus.addr":
      return row.modbusAddr;
    case "s7.func":
      return row.s7Func;
    case "dnp3.func":
      return row.dnp3Func;
    case "iec.type":
      return row.iecType;
    case "bacnet.service":
      return row.bacnetSvc;
    case "cip.service":
      return row.cipSvc;
    case "mqtt.type":
      return row.mqttType;
    case "ftp.request.command":
      return row.ftpCmd;
    case "smb.cmd":
      return row.smbCmd;
    case "frame":
      return [row.info, row.dnsQ, row.httpHost, row.httpPath, row.tlsSni, row.ftpArg, row.smbPath, row.s7Pi, row.mqttTopic, row.sshBanner]
        .filter(Boolean)
        .join(" ");
    default:
      return undefined;
  }
}

function compare(left: string | number, op: string, right: Value): boolean {
  if (op === "in") {
    if (typeof left !== "number" || !Array.isArray(right)) return false;
    return right.includes(left);
  }
  if (op === "contains" || op === "matches") {
    const hay = String(left).toLowerCase();
    const needle = String(right);
    if (op === "contains") return hay.includes(needle.toLowerCase());
    if (needle.length > 80) return false;
    try {
      return new RegExp(needle, "i").test(String(left));
    } catch {
      return false;
    }
  }
  if (typeof right === "number" && typeof left === "number") {
    if (op === "==") return left === right;
    if (op === "!=") return left !== right;
    if (op === ">") return left > right;
    if (op === "<") return left < right;
    if (op === ">=") return left >= right;
    if (op === "<=") return left <= right;
  }
  const a = String(left).toLowerCase();
  const b = String(right).toLowerCase();
  if (op === "==") return a === b;
  if (op === "!=") return a !== b;
  const na = Number(left);
  const nb = Number(right);
  if (!Number.isNaN(na) && !Number.isNaN(nb) && String(right).trim() !== "") {
    if (op === ">") return na > nb;
    if (op === "<") return na < nb;
    if (op === ">=") return na >= nb;
    if (op === "<=") return na <= nb;
  }
  return false;
}

export interface FilterField {
  id: string;
  label: string;
  type: "number" | "string" | "ip";
  group: string;
}

export const FILTER_FIELDS: FilterField[] = [
  { group: "Frame", id: "frame.number", label: "Packet number", type: "number" },
  { group: "Frame", id: "frame.len", label: "Length", type: "number" },
  { group: "Frame", id: "frame.time_relative", label: "Seconds from start", type: "number" },
  { group: "Ethernet", id: "eth.src", label: "Source MAC", type: "string" },
  { group: "Ethernet", id: "eth.dst", label: "Destination MAC", type: "string" },
  { group: "IP", id: "ip.src", label: "Source", type: "ip" },
  { group: "IP", id: "ip.dst", label: "Destination", type: "ip" },
  { group: "IP", id: "ip.addr", label: "Address (either side)", type: "ip" },
  { group: "TCP", id: "tcp.srcport", label: "Source port", type: "number" },
  { group: "TCP", id: "tcp.dstport", label: "Destination port", type: "number" },
  { group: "TCP", id: "tcp.port", label: "Port (either side)", type: "number" },
  { group: "TCP", id: "tcp.flags.syn", label: "SYN flag", type: "number" },
  { group: "TCP", id: "tcp.flags.ack", label: "ACK flag", type: "number" },
  { group: "UDP", id: "udp.port", label: "Port (either side)", type: "number" },
  { group: "DNS", id: "dns.qry.name", label: "Query name", type: "string" },
  { group: "HTTP", id: "http.host", label: "Host", type: "string" },
  { group: "HTTP", id: "http.request.method", label: "Method", type: "string" },
  { group: "TLS", id: "tls.sni", label: "Server name", type: "string" },
  { group: "Modbus", id: "modbus.func", label: "Function code", type: "number" },
  { group: "Modbus", id: "modbus.addr", label: "Address", type: "number" },
  { group: "S7", id: "s7.func", label: "Function", type: "number" },
  { group: "DNP3", id: "dnp3.func", label: "Function", type: "number" },
  { group: "IEC 104", id: "iec.type", label: "Type ID", type: "number" },
  { group: "BACnet", id: "bacnet.service", label: "Service", type: "number" },
  { group: "CIP", id: "cip.service", label: "Service", type: "number" },
  { group: "FTP", id: "ftp.request.command", label: "Command", type: "string" },
];

export const FILTER_PRESETS: { label: string; expr: string }[] = [
  { label: "Modbus writes", expr: "modbus.func == 5 || modbus.func == 6 || modbus.func == 15 || modbus.func == 16" },
  { label: "DNS", expr: "dns" },
  { label: "FTP passwords", expr: "ftp.request.command == PASS" },
  { label: "Connection attempts", expr: "tcp.flags.syn == 1 && tcp.flags.ack == 0" },
  { label: "Industrial", expr: "modbus || s7 || dnp3 || enip || bacnet || iec104 || opcua || mqtt" },
];
