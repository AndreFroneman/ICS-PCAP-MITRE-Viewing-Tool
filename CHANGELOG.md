# Changelog

## 2.0.1

The first Windows installer for Primer 2. The app is the same as 2.0.0. The `v2.0.0` tag never produced an installer, so 2.0.1 is the version to download.

- Release build fix: the `v2.0.0` workflow runs failed at the installer step and that release had no files. `tauri-apps/tauri-action` runs `npm run tauri build`, and `package.json` had no `tauri` script. The script is added.
- The workflow runs `npm test` before it builds, reads the version from `tauri.conf.json`, and refuses a tag that does not match it.
- The release carries the installer (`Primer_2.0.1_x64-setup.exe`), a documentation bundle (`Primer_2.0.1_docs.zip`), `SHA256SUMS.txt`, and the matching Wireshark source.
- README: a direct download link, the list of release files, how to check the SHA-256, and a documentation index. The user guide says the same.

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

No installer was published for 2.0.0. Use 2.0.1.

## 1.0.1

Imported as the base for 2.0. The in-house reader opens many real pcap and pcapng variants. ATT&CK 20.0. Offline natural-language analyst. The 1.0.0 installer on the old main branch did not contain this source.

## 1.0.0

First public installer. It failed on many real captures. Do not use it.
