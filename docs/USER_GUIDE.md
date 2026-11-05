# Primer user guide

This is the walkthrough for someone investigating a capture. You do not need to know Wireshark.

## Install

Download `Primer_2.0.2_x64-setup.exe` from the [release page](https://github.com/AndreFroneman/ICS-PCAP-MITRE-Viewing-Tool/releases/latest). The page has three files: the installer, `README.md`, and `GPL-2.0-LICENSE.txt`.

The file is not code-signed. Windows SmartScreen will warn you. Choose **More info**, then **Run anyway**.

The install is for your Windows user. You do not need an administrator to open a saved capture. A brand-new Windows 10 PC may ask once, because Primer carries Microsoft's WebView2 runtime installer and that runtime is a machine component. Windows 11 already has it.

## Open a file

- Double-click a `.pcap` or `.pcapng`, or use **Open**.
- Or start with **Plant shift**, which is a made-up shift that contains both ordinary plant traffic and nasty traffic, so you can see what the screens do.
- **Quiet plant** is the control. It should stay at triage level 1.

Primer decides the file type from the bytes. A wrong extension does not matter. Gzip is unpacked locally.

On the desktop app, Primer copies the file into `Documents\Primer\Cases`, hashes it, and makes that copy read-only. Your original file is not edited. The hash is on the case screen. If it ever stops matching, that is a custody event, not a silent reload.

## How to read the triage line

| Level | What it means | What it does not mean |
| --- | --- | --- |
| 1 Anomaly | Something looks unusual, or the capture is simply a normal plant. It may be maintenance, a bad configuration, or a test. | It is not an incident. |
| 2 Suspicious activity | Worth a person's time. Keep the capture. | It is not yet enough, on its own, to open a formal incident. |
| 3 Credible incident evidence | Several independent checks line up. Open a formal investigation and preserve the evidence. | It is still not proof the controller was exploited. You still need controller diagnostics, the engineering PC's logs, and the change ticket. |

Primer will not say "confirmed exploit" from a capture.

## The screens

The strip under the summary is the whole investigation. The old packet, findings, ATT&CK, and Ask tools are all still there.

- **Overview** is the case in one page: the triage, the loud findings, and the likely roles.
- **Assets** is a hypothesis for each address. "Likely PLC" means the traffic looks like a PLC. The confidence is on the card. There is always an alternative ("could be a gateway").
- **Packets** is the list, the decode, the hex, and follow-stream. A display filter works like a small Wireshark filter: `modbus.func == 16`, `ip.addr == 10.10.1.50`.
- **Talk** is the conversation log (who talked to whom, which service, how much). Primer builds this itself. There is no Zeek program in the installer.
- **OT** is the worksheet: function codes, addresses, who wrote, who only polled. Every write says it may be maintenance.
- **Findings** are the cards. **Industrial** is the default, so a noisy signature feed cannot hide a Modbus write. **Signature hits** is there when Suricata has run.
- **ATT&CK** is the matrix. A coloured technique was mapped from a finding. The list is not a story of an attack chain.
- **Timeline** is the findings in capture-clock order. The volume graph is still on Overview. Times are the capture's clock, not "the plant's local time", unless you know the zone yourself.
- **Attribution** lists technical observations: TTL, TCP options, DHCP names, user agents, SMB dialects, and, when TShark provided them, JA3 and an RDP keyboard id. The caution at the top cannot be hidden. None of this is nationality or sponsorship.
- **Ask** answers from the packets. Try the questions in the next section.
- **Case** is the name, the investigator, the hash, notes, and the log of decisions.
- **Report** writes the investigation report.

On a finding, **Approve**, **Reject**, and **Escalate** are yours. They are stored with your name and the time. Closing the desktop app and opening the case again keeps that decision.

## Questions that work offline

- "Did anyone write to the controller?"
- "Show me all traffic going to PLC1." If nothing is literally named PLC1, Primer says so and uses the likely PLC, and it says which address that is.
- "Which engineering workstation communicated with 10.10.1.50?"
- "Show me suspicious activity between 6:00 AM and 8:00 AM." Times are the capture clock, in UTC. If the window misses the capture, the answer has no packet numbers. Primer will not borrow numbers from outside the window.
- "Which devices communicated with the Internet?"
- "Was there evidence of network reconnaissance?"
- "Show all connections involving 10.10.1.80."
- "Which MITRE ATT&CK techniques are supported by the evidence?"
- "Can you reconstruct the sequence of events before the PLC stopped communicating?"
- "Is there enough evidence to open a formal incident investigation?"

The last one returns the triage level, the gaps, and a recommendation. It does not declare an incident.

Click a packet number to jump to that frame.

## What a card is claiming

**Observed** means the bytes show the fact: a Modbus function 16, a password, a SYN scan, an S7 stop job.

**Possible** means an interpretation: "this looks like a tunnel", "this looks like beaconing". The technique id on either kind of card is a possible reading of those bytes, not a conviction.

Every industrial write carries an alternative: it is consistent with maintenance until someone who knows the shift says otherwise.

## Live capture

Live capture is optional and off to the side. The button is on the home page.

If Npcap is not installed, Primer says so and links to npcap.com. It will not download Npcap and it will not put Npcap in the installer.

If Npcap is installed, you can record an interface to a pcapng. That may ask for an administrator, or for your account to have been allowed when Npcap was installed. When you stop, Primer opens that file as a normal case. From then on it is just a capture.

## If something looks wrong

- A quiet plant that comes out as level 3 is a bug. The bundled quiet sample does not.
- A single Modbus write is level 1 or 2, with the maintenance alternative. It is not level 3 by itself.
- "No Suricata alerts" does not mean "no OT finding". Suricata is an IT signature layer, and in this build it is not even bundled.
- TShark, when it is present, adds fields. It does not replace the packet list. If the two decodes disagree, both stay visible when you ask TShark for that one frame.
