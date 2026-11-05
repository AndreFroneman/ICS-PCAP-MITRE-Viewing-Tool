# Primer

**Network captures, explained for humans.**

Primer opens a packet capture (`.pcap` or `.pcapng`) and tells you, in plain English, what the traffic is doing, which machines look like plant equipment, and how that maps to MITRE ATT&CK for Enterprise and for ICS. It is a Windows app for people who are not packet experts. You do not need Wireshark.

![Primer home screen](https://raw.githubusercontent.com/AndreFroneman/ICS-PCAP-MITRE-Viewing-Tool/main/docs/images/primer-home.png)

Built by **Andre Froneman** · GitHub: [AndreFroneman](https://github.com/AndreFroneman)

---

## Download

**[Download Primer 2.0.2 for Windows — `Primer_2.0.2_x64-setup.exe`](https://github.com/AndreFroneman/ICS-PCAP-MITRE-Viewing-Tool/releases/download/v2.0.2/Primer_2.0.2_x64-setup.exe)**

The [release page](https://github.com/AndreFroneman/ICS-PCAP-MITRE-Viewing-Tool/releases/latest) has three files: the installer, this README, and the GPL licence.

## Install

1. Run `Primer_2.0.2_x64-setup.exe`.
2. Windows SmartScreen will say it does not recognise the app, because the installer is not code-signed. Choose **More info**, then **Run anyway**.
3. The installer is for your Windows user only. You do not need an administrator to analyse a saved capture.

Works on 64-bit Windows 10 and Windows 11. Everything Primer needs is inside the installer, including Microsoft's WebView2 runtime for PCs with no internet. On a brand-new Windows 10 PC that runtime may ask for an administrator once. Windows 11 already has it.

## Quick start

1. Double-click a `.pcap` or `.pcapng`, or open Primer and choose a file. Your captures folder `C:\Virtual Share\Pcap` is offered by default. To see what Primer does first, open the **Plant shift** sample.
2. Read the **triage line** at the top (see below).
3. Open **Findings** and **OT**. Mark each finding **Approve**, **Reject**, or **Escalate** once you have decided.
4. Type a question in **Ask**. Click a packet number in the answer to see that packet.
5. Export the investigation report from **Report** (HTML, PDF, JSON, or CSV).

Primer copies each capture into `Documents\Primer\Cases`, records its SHA-256, and makes the copy read-only. Your original file is never changed.

## The triage line

| Level | What it means | What it does not mean |
| --- | --- | --- |
| 1 Anomaly | Something looks unusual, or this is a normal plant. It may be maintenance, a bad configuration, or a test. | It is not an incident. |
| 2 Suspicious activity | Worth a person's time. Keep the capture. | Not enough, on its own, to open a formal incident. |
| 3 Credible incident evidence | Several independent checks line up. Open a formal investigation and preserve the evidence. | Still not proof that a controller was exploited. You also need controller diagnostics, the engineering PC's logs, and the change ticket. |

Each finding says whether it is **observed** (the bytes show it, for example a Modbus write) or **possible** (the bytes are only consistent with that reading, for example "looks like a tunnel"). Every industrial write also says it may be maintenance.

## The screens

- **Overview**: the case on one page, with the triage level, the loudest findings, and the likely role of each device.
- **Assets**: a "likely" role for each address (PLC, engineering workstation, SCADA, historian, and others), with a confidence and an alternative.
- **Packets**: the packet list, decode, hex, follow-stream, and a simple filter such as `modbus.func == 16` or `ip.addr == 10.10.1.50`.
- **Talk**: who talked to whom, over which service, and how much.
- **OT**: industrial function codes and addresses, and who wrote versus who only read.
- **Findings**: the evidence cards. **Industrial** is the default view, so IT noise cannot hide a PLC write.
- **ATT&CK**: the MITRE ATT&CK 20.0 matrices for Enterprise and ICS, coloured where a finding maps to a technique.
- **Timeline**: findings in the order the capture recorded them.
- **Attribution**: technical fingerprints (TTL, TCP options, DHCP names, user agents). These are never proof of nationality or sponsor.
- **Ask**: plain-English questions, answered from the packets.
- **Case**: name, investigator, hash, notes, and a log of every decision.
- **Report**: the investigation report.

Industrial protocols decoded: Modbus/TCP, DNP3, S7comm, EtherNet/IP/CIP, BACnet, IEC 60870-5-104, OPC UA (Hello), and MQTT, alongside ordinary IT protocols.

## Questions Ask answers offline

No AI model or internet connection is needed for these:

- "Did anyone write to the controller?"
- "Show me all traffic going to PLC1."
- "Which engineering workstation communicated with 10.10.1.50?"
- "Show me suspicious activity between 6:00 AM and 8:00 AM." (Times are the capture's clock, in UTC.)
- "Which devices communicated with the Internet?"
- "Was there evidence of network reconnaissance?"
- "Which MITRE ATT&CK techniques are supported by the evidence?"
- "Can you reconstruct the sequence of events before the PLC stopped communicating?"
- "Is there enough evidence to open a formal incident investigation?"

In **Settings** you can optionally add a smarter narrator: a model inside Primer, Ollama on this PC, or a cloud service with your own API key. Before anything goes to the cloud, Primer shows you the exact text it will send, with IP and MAC addresses redacted by default. The capture itself is never uploaded.

## Live capture (optional)

Primer can record live traffic only if **Npcap** is already installed. Get it from [npcap.com](https://npcap.com/#download); its licence does not allow Primer to include it. Recording may ask for an administrator. When you stop recording, the file opens as a normal case.

## Privacy

Your captures stay on your computer unless you turn on a cloud narrator and approve the exact text Primer shows you.

## Licence

Primer is free software under the GNU General Public License, version 2 or later. The full text is in [`LICENSE`](LICENSE), and it is the GPL file on the release page.

The installer includes TShark 4.6.9 from the Wireshark project as a separate, unmodified program. Wireshark is also GPL. Its matching source code is at <https://www.wireshark.org/download/src/all-versions/wireshark-4.6.9.tar.xz> (SHA-256 `d062d416a1ab3a49975aafe3a671c882dde0562ccd71b078808ceb59d465fc0f`). If you pass the installer on, pass that link on with it. Wireshark is a trademark of the Wireshark Foundation, and Primer is not endorsed by the Wireshark project.

Primer's own source code is in this repository.

## Disclaimer

Primer is an analysis aid. Check every finding before you act on it, and only analyse traffic you are allowed to inspect. A packet capture cannot prove that a controller was successfully exploited.
