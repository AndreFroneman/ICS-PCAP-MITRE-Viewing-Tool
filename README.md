# Primer

Primer is a packet-capture analyser for people who are not packet experts. It is aimed at an OT/ICS consultant: open a `.pcap` or `.pcapng`, read a plain-language summary, inspect each frame, and see suspicious behaviour mapped to MITRE ATT&CK for Enterprise and for ICS.

Captures are parsed in the browser. They are not uploaded.

## Why this shape

The app is **Vite + React + TypeScript**, with parsing and detection in a **Web Worker**.

A server framework would imply a place to send the file. Primer has no upload API and no analytics call. The worker keeps the page responsive while a large capture is decoded (the test suite parses and filters 100,000 packets). The same UI is wrapped with [Tauri](https://tauri.app/) for Windows (`src-tauri/`). The web build stays the default for a browser.

## Run

```bash
npm install
npm run dev
```

The dev server listens on port **8734**. Open the URL it prints (typically `http://127.0.0.1:8734`).

```bash
npm test          # parsers, dissectors, filters, detections, 100k packets
npm run samples   # regenerate public/samples
npm run attack    # re-download official STIX and rebuild src/data/attack.json
npm run build         # typecheck and static build
npm run preview       # serve dist on port 8734
npm run desktop       # Tauri window, needs Rust
npm run desktop:build # NSIS and MSI on Windows
```

## Using it

Drop a capture on the page, or open one of the synthetic samples. **Plant shift** is the one to start with: twelve plant devices, ordinary polling, then a scan, cleartext passwords, a DNS tunnel, beacons, an admin-share connection, and industrial commands.

- Opens classic pcap and pcapng without Wireshark or Npcap: both endians, microsecond and nanosecond timestamps, modified (Kuznetsov) pcap, versions other than 2.4, several pcapng sections, gzip (`.pcap.gz`), and link types including Ethernet, Linux cooked, raw IP, loopback, PPP, and 802.11 radiotap. Primer sniffs the header, not the filename. An unexpected version is a warning, and the packets are still read.
- The summary is the first sentence. Findings are colour-coded and each one says what it means and what to do.
- The packet list, decode tree, and hex view work like a small Wireshark. Click a field for a plain-language explanation, or to filter on it.
- Filters accept `tcp.port == 502`, `modbus.func == 16`, `dns.qry.name contains tunnel`, `ip.addr == 10.10.1.80`, `&&`, `||`, and `frame.number in {1, 2, 3}`. There is also a point-and-click builder.
- Follow stream shows a TCP or UDP conversation in order.
- Conversations, endpoints, protocol hierarchy, an I/O timeline, and extracted DNS, HTTP, TLS names, and small files are under Overview.
- **Ask** answers plain questions from the capture tools (who wrote to the PLC, what looks like C2) and cites packet numbers. The default analyst is offline. Settings can add an in-browser WebGPU model, Ollama on localhost, or a cloud key. Cloud calls show the exact summary first and can redact IP and MAC addresses. The raw capture is never sent. ChatGPT and Claude account sign-in is not available to third-party apps; those providers need an API key.
- Export writes findings HTML, PDF, and JSON; an ATT&CK report (HTML and PDF) grouped by tactic and technique, with confidence, mitigations, and the T0855 → T1692.001 note; ATT&CK Navigator layer JSON for ICS and Enterprise; and CSV for the filtered packet list, conversations, endpoints, DNS, HTTP, TLS, and findings.

## Look

The interface follows the Horizon site and company profile: near-black field, cyan `#22e6ff`, Orbitron headlines, Rajdhani body, JetBrains Mono labels, clipped buttons, a fixed top bar, a network-field background, and the ring cursor. Fonts and the cursor are bundled. Nothing is loaded from t-horizon.co.za.

## Windows desktop

`src-tauri` associates `.pcap` and `.pcapng` and remembers a capture folder. The suggested default is `C:\Virtual Share\Pcap`. API keys in the desktop build go to the OS keychain (`keyring`). In the browser they stay in local storage.

The Windows NSIS `.exe` and MSI are built by `.github/workflows/windows.yml` on a Windows runner (`tauri build --bundles nsis,msi`). The current app version is 1.0.1, so the installer name is `Primer_1.0.1_x64-setup.exe`. It is not code-signed: Windows SmartScreen may say it is unrecognised; choose More info, then Run anyway. On a Windows machine with Rust, `npm run desktop:build` writes the same files under `src-tauri/target/release/bundle/`.

## ATT&CK data

Technique names, descriptions, tactics, mitigations, and attack.mitre.org links come from a compact bundle built from the official STIX:

- Enterprise: `mitre-attack/attack-stix-data` `enterprise-attack.json`
- ICS: `mitre-attack/attack-stix-data` `ics-attack.json`

The copy in this repo is **ATT&CK 20.0**, spec **3.3.0**, modified **13 October 2026**. `npm run attack` downloads the current master bundles and rewrites `src/data/attack.json`.

**T0855 Unauthorized Command Message was revoked** in this release and replaced by **T1692.001 Command Message**. Primer maps command-like industrial writes to the current id and still shows T0855 as the legacy id, so older notes line up.

Other mappings the detectors use:

| What you see | Techniques |
| --- | --- |
| Port scan, including industrial ports | T1046, and T0846.001 when an OT port is in the scan |
| Cleartext passwords (FTP, HTTP Basic, SMTP, MQTT) | T1040, T0842; MQTT also T0859 and T0869 |
| DNS tunnel (long, high-entropy names) | T1071.004, T0869.001 |
| Regular connections to a public host | T1071, T0869, T0885 |
| SMB ADMIN$ or C$ | T1021.002 |
| Repeated logons | T1110 |
| Large upload to a public host | T1041 when that host was also a beacon, otherwise T1048.003 |
| Modbus write / force | T0836, T1692.001 (legacy T0855) |
| Many Modbus writes | T0806 as well |
| S7 PLC stop | T0881, T0816 |
| S7 program download / upload | T0843 / T0845 |
| IEC 104 command, DNP3 operate, BACnet WriteProperty, CIP write | T1692.001, T0836 (legacy T0855) |
| Modbus register sweep | T0861 |

These are heuristics for triage. A match is a lead, not proof of compromise. Steady Modbus polling inside the plant is not treated as beaconing.

## Samples

Generated by `scripts/generate-samples.ts` and stored in `public/samples/`:

- `plant-shift.pcap` — the mixed day
- `benign-plant.pcap` — should stay quiet
- `port-scan.pcap`
- `cleartext-creds.pcap`
- `dns-tunnel.pcap`
- `modbus-writes.pcap`
- `ics-commands.pcapng` — S7, IEC 104, DNP3, BACnet, CIP, OPC UA hello, repeated coil forces

The app can also build 100,000 synthetic Modbus reads locally (Samples menu) to exercise the virtualised list.

## Protocols

Ethernet (and a basic Linux cooked / raw IP path), ARP, IPv4, IPv6, ICMP, TCP, UDP, DNS, DHCP, HTTP, TLS handshakes (SNI and certificate common names), SMB2/NTLM names, SSH banners, FTP, SMTP, Modbus/TCP, DNP3, S7comm, EtherNet/IP-CIP, BACnet, IEC 60870-5-104, OPC UA Hello, and MQTT.

## Privacy

There is no backend for captures. Opening a file reads it with `File.arrayBuffer()` and transfers that buffer to the worker. Sample files are static assets shipped with the app. Links to attack.mitre.org are ordinary links; the descriptions themselves are in the bundle.
