# Test results

Run on 3 November 2026 in the build environment (Linux). Windows, SmartScreen, Npcap, and a real TShark binary were not executed here. The GitHub workflow is what produces the installer.

## Automated

- `npm test`: 36 tests passed (4 files). The imported 1.0.1 tree had 29. The new tests cover offsets, triage, asset wording, a single Modbus write, an investigator rejection that survives a JSON reopen, a mocked TShark JSON row, an EVE alert merged with a Primer card, and the investigation questions on the plant-shift sample.
- The 100,000-packet filter test still passes and still finds nothing high or critical.
- `cargo test` in `src-tauri`: 4 tests passed. A case is created from a tiny pcap, the SHA-256 matches, the copy is read-only, packet number 1 is still packet number 1 after reopen, a one-packet read returns the original bytes, a mocked TShark row keeps frame number 7, an EVE alert keeps packet 12 and `sid:2024897`, and an overlapping Modbus hit becomes one correlation card.
- `tsc -b` completed with no errors.

## Synthetic captures (the ones in the repo)

| File | Packets | Triage | What came out |
| --- | --- | --- | --- |
| `benign-plant.pcap` | 51 | Level 1 Anomaly | No suspicious finding. Likely PLC `10.10.1.50` (high), likely PLC `10.10.1.60` (the RTU; medium), likely SCADA `10.10.1.30`, likely historian `10.10.1.40`, likely engineering workstation `10.10.1.10` only because the DHCP name says eng-laptop (low). The report's exploit section is the empty one. |
| `modbus-writes.pcap` | 13 | Level 2 | Modbus write is **observed**, technique support **possible**, alternative mentions maintenance. A new writer (`10.10.1.80`) is flagged. Not level 3. |
| One Modbus function-16 packet | 1 | Level 2 or below | Stays at level 2. One write is not an incident. |
| `plant-shift.pcap` | 253 | Level 3 | Port scan, cleartext, SMB admin share, Modbus writes, S7 stop and download, and others. The offline "open an investigation?" answer says level 3, says it is not proof, and lists the missing controller log, engineering logs, and change ticket. Packet numbers in the answers are numbers that exist in the file. A question about 10:00–12:00 returns no packet numbers, because this capture's clock is about 06:40 UTC. |

## Public captures (not committed)

Downloaded for this run only, from the ITI `ICS-Security-Tools` repository.

| File | Packets | Triage | What came out |
| --- | --- | --- | --- |
| `pcaps/openics/MODBUS-TestDataPart1.pcap` | 118 | Level 2 | Likely PLCs `10.0.0.3` and `10.0.0.8` (high). `10.0.0.9` is a likely engineering workstation because it sent Modbus writes. One observed Modbus-write finding. Not level 3. |
| `pcaps/ModbusTCP/ModbusTCP.pcap` | 15,387 | Level 2 | Many addresses look like Modbus servers. The file contains a lot of writes, a point sweep, and several "new writer" notes. That is suspicious and worth keeping. It is not raised to level 3, because the checks are all industrial activity in one family. A busy lab capture must not become an incident just because it contains writes. |

No finding was invented for a file that did not contain the bytes. The quiet plant produced none.

## Windows check (5 November 2026)

The first two runs of `.github/workflows/windows.yml` (on `main` and on the `v2.0.0` tag) failed at the installer step, so the release had no files. `tauri-apps/tauri-action` calls `npm run tauri build`, and `package.json` had no `tauri` script. On a Windows 11 PC with Node 24, `npm run tauri` reproduced `Missing script: "tauri"`. With the script added:

- `npm run tauri -- --version` reports `tauri-cli 2.12.4`.
- `npm run build` (`tsc -b && vite build`) completes.
- `npm test`: 36 tests passed (4 files).
- The Tauri crates and the npm packages are on matching versions (`tauri` 2.12, `dialog` 2.8.4, `fs` 2.7.1, `http` 2.8.3).

The workflow now runs `npm test` before it builds. With the fix, the `main` build on the GitHub `windows-latest` runner passed the tests and staged TShark 4.6.9 without Npcap. The installer is released as 2.0.1, because the `v2.0.0` tag points at the commit that could not build. The SHA-256 of each released file is in `SHA256SUMS.txt` on the release.

## Not run here

- Installing the Windows installer on a test PC. `.github/workflows/windows.yml` builds the NSIS package with WebView2 embedded on a Windows runner and, for a `v*` tag, attaches `Primer_<version>_x64-setup.exe`, `Primer_<version>_docs.zip`, `SHA256SUMS.txt`, and `wireshark-4.6.9.tar.xz` to the release.
- TShark itself, Suricata `-r`, and Npcap. The parsers were tested with fixtures. The Suricata binary was left out on purpose; see `docs/ENGINES.md`.
- A clean Windows 10 and Windows 11 virtual machine. That is still the right place to confirm SmartScreen, the per-user install, and that offline analysis does not ask for an administrator.
