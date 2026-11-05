# Changelog

## 2.0.0

Primer becomes an offline investigation tool. The 1.0.1 decoder, Horizon look, findings, ATT&CK matrices, and offline Ask path are still there.

- A case folder under `Documents\Primer\Cases`, with a read-only evidence copy and SHA-256.
- Findings now carry observed or possible, a confidence, a triage level, an alternative explanation, and an investigator decision.
- Likely asset roles, an OT worksheet, Zeek-style connection logs built in Primer, and an attribution panel that cannot hide its caution.
- Ask can answer a time window, an asset, a sequence, and whether there is enough to open an investigation. It cites only packet numbers the tools returned.
- One investigation report (HTML, PDF, JSON, CSV) with an empty exploit section when nothing reached level 3.
- TShark can be run as a separate program on a fixed field list. The Windows release workflow stages Wireshark 4.6.9's `tshark.exe` and ships the matching source archive. Npcap is not bundled.
- Suricata is a hook only. It is not in the installer, because the usual Windows build needs Npcap even to read a file.
- Optional live capture when Npcap is already installed. The recording becomes an ordinary case.
- One per-user NSIS installer with the WebView2 offline runtime embedded. The installer is not code-signed.
- Primer is GPL-2.0-or-later.

Release build fix (5 November 2026): the first `v2.0.0` workflow runs failed at the installer step and the release had no files. `tauri-apps/tauri-action` runs `npm run tauri build`, and `package.json` had no `tauri` script. The script is added, the workflow now runs `npm test` before building, and the release carries the installer, a documentation bundle (`Primer_2.0.0_docs.zip`), `SHA256SUMS.txt`, and the matching Wireshark source.

## 1.0.1

Imported as the base for 2.0. The in-house reader opens many real pcap and pcapng variants. ATT&CK 20.0. Offline natural-language analyst. The 1.0.0 installer on the old main branch did not contain this source.

## 1.0.0

First public installer. It failed on many real captures. Do not use it.
