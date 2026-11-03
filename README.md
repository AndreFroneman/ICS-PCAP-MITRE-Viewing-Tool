# Primer – ICS PCAP Tool

**Network captures, explained for humans.**
Primer opens `.pcap` / `.pcapng` files and tells you, in plain English, what happened on the network and how it maps to MITRE ATT&CK (Enterprise + ICS). Wireshark-grade parsing, built for people who are not Wireshark experts.

Built by **Andre Froneman** (Frogman1981) – OT security specialist.
LinkedIn: https://www.linkedin.com/in/andrefroneman/

---

## Download

Grab the latest Windows installer from the **Releases** page:
`Primer_1.0.0_x64-setup.exe`

> The installer is not code-signed yet. Windows SmartScreen will warn you –
> click **More info** then **Run anyway**.

- Installs for the current user (no admin needed)
- Opens `.pcap` and `.pcapng` files on double-click
- Suggests `C:\Virtual Share\Pcap` as the default capture folder

---

## Features

**Open and explore**
- Reads `.pcap` and `.pcapng` captures
- Packet list, conversations, protocol breakdown and timeline
- Parsing runs in a background worker so large captures stay responsive

**ICS / OT aware**
- Recognises industrial protocols (e.g. Modbus) alongside normal IT traffic
- Flags risky activity such as unexpected writes to PLCs

**MITRE ATT&CK mapping**
- Findings mapped to ATT&CK Enterprise and ATT&CK for ICS (bundled STIX data, v20.0)
- ATT&CK report grouped by tactic
- Export ATT&CK Navigator layers

**Ask your capture (natural language)**
- Ask questions like *"Which device wrote to the PLC?"* and get answers with clickable packet numbers
- Works fully offline with the built-in analyst – no AI or internet needed
- Optional AI providers:
  - In-browser model (WebLLM / WebGPU)
  - Local: Ollama
  - Free cloud tiers: Groq, Gemini, OpenRouter
  - Your own API key: OpenAI, Anthropic (Claude), DeepSeek
- **Private by default:** redaction is on, and Primer shows you exactly what will be sent and asks before anything leaves your machine

**Export**
- CSV: packets, conversations, findings (with ATT&CK technique IDs)
- ATT&CK report
- ATT&CK Navigator layer (JSON)

---

## Quick start

1. Install Primer from the Releases page.
2. Double-click any `.pcap` / `.pcapng` file, or open Primer and choose a capture.
3. Read the **Findings** panel for a plain-English summary.
4. Open **ATT&CK Report** to see techniques grouped by tactic.
5. Use **Ask your capture** to question the data.
6. Export to CSV or Navigator from the Export menu.

See `USER_GUIDE.md` for a full walkthrough.

---

## Build from source

Requirements: Node.js 20+, Rust (stable), Tauri prerequisites for Windows.

```
npm install
npm run dev          # web app for development
npm run tauri build  # Windows installer (NSIS / MSI)
```

Windows installers are also built automatically by GitHub Actions
(`.github/workflows/windows.yml`).

Tech stack: Vite, React, TypeScript, Web Workers, Tauri.

---

## Privacy

Captures never leave your computer unless you turn on a cloud AI provider and approve the request. Sensitive values are redacted by default.

---

## Disclaimer

Primer is an analysis aid. Always verify findings before acting on them, and only analyse traffic you are authorised to inspect.

---

© 2026 Andre Froneman. All rights reserved.
