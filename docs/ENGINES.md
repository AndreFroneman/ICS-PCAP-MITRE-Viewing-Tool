# Engines

## TShark

Pinned to Wireshark **4.6.9**. Primer runs it as a separate program:

- On import, a fixed field list (`frame.number`, addresses, ports, protocol, info, and a handful of industrial and fingerprint fields). Not a full JSON tree of every packet.
- When you open one frame, Primer may ask TShark for that frame only (`-Y frame.number==N -V`). Primer's own tree stays on screen.

If TShark is missing or fails, the case still opens. The failure is a line on the evidence, not a dead end.

The Windows workflow installs Wireshark with `/S`, which does not install Npcap, then copies `tshark.exe`, `dumpcap.exe`, the DLLs, and the dissector plugins. It does not copy an Npcap installer.

## Suricata

Not bundled.

The Suricata documentation says Npcap is required for live capture on Windows, and that a build can instead use MSYS2's libpcap if you leave off the Npcap configure flags. That second build can read a pcap and cannot capture. The published Windows packages people actually download are the first kind: users report `wpcap.dll` missing even when they only wanted to read a file, and the DLL appears only after Npcap is installed.

This environment is Linux. It cannot run that Windows binary, and it does not have a clean Windows 10 virtual machine to prove an Npcap-free build. Bundling an unproven binary, or bundling Npcap to make the official one start, would break the "no admin, no Npcap" rule. So the installer has the hook and not the program:

- `src-tauri/src/suricata.rs` runs `suricata -r` with a private yaml and no capture interface, if a binary is on the machine or next to Primer.
- If the binary is absent, Primer says so and keeps its own findings.
- EVE JSON is parsed in Rust and in `src/lib/engines.ts`. A hit that cites the same packets and the same behaviour as a Primer finding becomes one card.
- The Industrial filter hides signature-only hits so a large ruleset cannot cover a Modbus write.
- ET Open is not downloaded and is not in git. `scripts/stage-et-open.ps1` copies a local snapshot and fails if that snapshot has no `LICENSE`.

## Zeek

No Zeek binary. Connection, DNS, HTTP, TLS, and file summaries are built in Primer from the packet rows (`src/lib/forensic.ts`). An external Zeek log import is not turned on.

## Npcap and live capture

Live capture is optional and separate. Primer looks for `C:\Windows\System32\Npcap\wpcap.dll`. If it is missing, the Live capture screen explains that and links to https://npcap.com/#download. Recording uses `dumpcap` and writes a pcapng, which is then opened as a normal case. Capturing may require an administrator or an Npcap permission. Offline analysis never does.

## WebView2

The NSIS package uses Tauri's `offlineInstaller` mode. That embeds Microsoft's WebView2 standalone installer (on the order of 127 MB) so the target PC does not download it. Windows 11 already has the runtime, so the embedded installer is skipped. A clean Windows 10 machine runs it offline. That Microsoft installer has historically needed an administrator to register the runtime for the machine. Primer's own files stay in the per-user install.
