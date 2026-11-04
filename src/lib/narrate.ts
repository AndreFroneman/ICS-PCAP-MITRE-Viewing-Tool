import type { Row } from "./model.ts";

export function narrate(row: Row): { title: string; body: string } {
  const who = `${row.src || row.macSrc || "Someone"}`;
  const whom = `${row.dst || row.macDst || "someone"}`;
  if (row.modbusFunc) {
    const write = [5, 6, 15, 16, 22, 23].includes(row.modbusFunc);
    return {
      title: write ? "A Modbus write" : "A Modbus read",
      body: write
        ? `${who} asked ${whom} to change Modbus data (function ${row.modbusFunc}${row.modbusAddr !== undefined ? `, address ${row.modbusAddr}` : ""}). Writes alter coils or registers. Confirm an operator meant to do that.`
        : `${who} asked ${whom} for Modbus data${row.modbusAddr !== undefined ? ` starting at address ${row.modbusAddr}` : ""}. Repeated reads of the same addresses are what normal polling looks like.`,
    };
  }
  if (row.s7Func === 0x29 || (row.s7Func === 0x28 && /stop/i.test(row.s7Pi ?? ""))) {
    return { title: "A PLC stop", body: `${who} sent an S7 message asking ${whom} to stop the CPU. If this was not a planned stop, the process may halt.` };
  }
  if (row.s7Func !== undefined && [0x1a, 0x1b, 0x1c].includes(row.s7Func)) {
    return { title: "A PLC program download", body: `${who} is pushing program logic toward ${whom}. That changes what the controller will do.` };
  }
  if (row.s7Func !== undefined && [0x1d, 0x1e, 0x1f].includes(row.s7Func)) {
    return { title: "A PLC program upload", body: `${who} is copying program logic out of ${whom}.` };
  }
  if (row.s7Func !== undefined) {
    return { title: "Siemens S7", body: `${who} is speaking S7 to ${whom}. ${row.info}` };
  }
  if (row.dnp3Func !== undefined && [3, 4, 5, 6].includes(row.dnp3Func)) {
    return { title: "A DNP3 command", body: `${who} sent a DNP3 select or operate toward ${whom}. That is a request to act, not just to report.` };
  }
  if (row.iecType !== undefined && row.iecType >= 45 && row.iecType <= 64) {
    return { title: "An IEC 104 command", body: `${who} sent a command or setpoint to ${whom}. Measurements travel the other way; this one asks the station to do something.` };
  }
  if (row.iecType === 100) {
    return { title: "An IEC 104 interrogation", body: `${who} asked ${whom} to report its current points. Masters do this when a session starts.` };
  }
  if (row.bacnetConfirmed && row.bacnetSvc === 15) {
    return { title: "A BACnet write", body: `${who} wrote a BACnet property on ${whom}. That can change a setpoint or an output.` };
  }
  if (row.bacnetSvc === 8 && !row.bacnetConfirmed) {
    return { title: "BACnet Who-Is", body: `${who} asked which BACnet devices are present. One of these is ordinary discovery.` };
  }
  if (row.cipSvc !== undefined && [0x10, 0x4d, 0x53].includes(row.cipSvc)) {
    return { title: "A CIP write", body: `${who} wrote a CIP tag or attribute on ${whom}.` };
  }
  if (row.mqttPass) {
    return { title: "MQTT login, in the clear", body: `${who} connected to the MQTT broker at ${whom} and included a password. Port 1883 does not encrypt it.` };
  }
  if (row.mqttType) {
    return { title: "MQTT", body: `${who} sent an MQTT ${row.mqttTopic ? `message on “${row.mqttTopic}”` : "packet"} to ${whom}.` };
  }
  if (row.ftpCmd === "PASS") {
    return { title: "An FTP password", body: `${who} sent an FTP password to ${whom}. FTP does not encrypt it, so it is now in this capture.` };
  }
  if (row.ftpCmd) {
    return { title: "FTP", body: `${who} sent FTP ${row.ftpCmd} to ${whom}. The whole session is readable.` };
  }
  if (row.httpAuth) {
    return { title: "A web password", body: `${who} sent HTTP Basic credentials to ${whom}. Base64 hides nothing from someone reading the packet.` };
  }
  if (row.httpMethod) {
    return { title: "A web request", body: `${who} asked ${row.httpHost || whom} for ${row.httpPath || "a page"} over HTTP, which is not encrypted.` };
  }
  if (row.tlsSni) {
    return { title: "An encrypted session starting", body: `${who} started TLS with ${whom} and asked for ${row.tlsSni}. Primer can see the name, not the pages inside.` };
  }
  if (row.tlsCn) {
    return { title: "A TLS certificate", body: `${whom} presented a certificate for ${row.tlsCn}. That names the service. It does not show the encrypted contents.` };
  }
  if (row.dnsQ && row.dnsQ.length > 50) {
    return { title: "A long DNS name", body: `${who} looked up ${row.dnsQ}. Names this long and random can be a tunnel.` };
  }
  if (row.dnsQ) {
    return { title: "A DNS lookup", body: row.dnsA ? `${who} asked about ${row.dnsQ} and got ${row.dnsA}.` : `${who} asked ${whom} to resolve ${row.dnsQ}.` };
  }
  if (row.smbPath) {
    return { title: "A Windows share", body: `${who} opened ${row.smbPath} on ${whom}${row.smbUser ? ` as ${row.smbUser}` : ""}. Admin shares are a common way to move between machines.` };
  }
  if (row.smbCmd) {
    return { title: "Windows file sharing", body: `${who} sent SMB ${row.smbCmd} to ${whom}.` };
  }
  if (row.sshBanner) {
    return { title: "An SSH banner", body: `${row.sshBanner}. The session encrypts itself after this line, so Primer will not see the commands.` };
  }
  if (row.smtpAuth) {
    return { title: "An email password", body: `${who} authenticated to mail at ${whom}. The secret in this packet is readable.` };
  }
  if (row.opcUrl) {
    return { title: "OPC UA hello", body: `${who} opened an OPC UA channel toward ${row.opcUrl}.` };
  }
  if (row.dhcpKind) {
    return { title: "DHCP", body: `${row.dhcpHost || who} sent a DHCP ${row.dhcpKind}${row.dhcpIp ? ` for ${row.dhcpIp}` : ""}. This is how a device asks for or receives an address.` };
  }
  if ((row.layers & 4) !== 0) {
    return { title: "ARP", body: row.info || `${who} is resolving a local address.` };
  }
  if (row.tcpFlags & 0x02 && !(row.tcpFlags & 0x10)) {
    return { title: "A connection attempt", body: `${who} sent a SYN to ${whom}${row.dp ? ` port ${row.dp}` : ""}. One of these opens a service. Many of them are a scan.` };
  }
  if (row.proto === "ICMP" || row.proto === "ICMPv6") {
    return { title: "A ping or network notice", body: row.info };
  }
  return {
    title: row.proto || "Packet",
    body: row.info || `${who} sent ${row.len} bytes to ${whom}. Open the decode tree to walk the headers one layer at a time.`,
  };
}
