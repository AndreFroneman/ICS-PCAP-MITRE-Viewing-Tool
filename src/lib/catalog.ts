export interface SampleCard {
  file: string;
  title: string;
  tag: string;
  blurb: string;
}

export const SAMPLES: SampleCard[] = [
  {
    file: "plant-shift.pcap",
    title: "Plant shift",
    tag: "Start here",
    blurb: "Twelve devices, ordinary polling, then a scan, cleartext passwords, a DNS tunnel, and commands sent to the PLC.",
  },
  {
    file: "benign-plant.pcap",
    title: "Quiet morning",
    tag: "Benign",
    blurb: "DHCP, DNS, a web request, Modbus polling, MQTT, and a BACnet Who-Is. The checks should stay quiet.",
  },
  {
    file: "port-scan.pcap",
    title: "Port scan",
    tag: "T1046",
    blurb: "SYN packets to the usual industrial ports on a PLC, with no completed handshakes.",
  },
  {
    file: "cleartext-creds.pcap",
    title: "Cleartext passwords",
    tag: "T1040",
    blurb: "FTP, HTTP Basic, and an MQTT password, each readable in the packet bytes.",
  },
  {
    file: "dns-tunnel.pcap",
    title: "DNS tunnel",
    tag: "T1071.004",
    blurb: "Several long, random-looking queries under one parent domain.",
  },
  {
    file: "modbus-writes.pcap",
    title: "Modbus writes",
    tag: "T0836",
    blurb: "Steady reads of the same registers, then function 5, 6, and 16 writes.",
  },
  {
    file: "ics-commands.pcapng",
    title: "Controller commands",
    tag: "ICS",
    blurb: "S7 stop and program transfer, plus IEC 104, DNP3, BACnet, CIP, and repeated coil forces. pcapng.",
  },
];
