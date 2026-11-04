# Third-party notices

Primer is GPL-2.0-or-later. See `LICENSE`. This file is the practical source offer for the programs that may travel with an installer, and the notices for the libraries Primer compiles in.

This is an engineering record, not a legal opinion.

## Wireshark / TShark

Wireshark, including the `tshark` and `dumpcap` programs, is published under the GNU General Public License, version 2 or, at your option, any later version. Confirm that against the `COPYING` file of the version you actually have. Primer 2.0.0 pins **Wireshark 4.6.9**.

- Windows installer that the build copies from: https://www.wireshark.org/download/win64/Wireshark-4.6.9-x64.exe
- SHA-256: `bf9b5ce8a89f244c376a9b1a946276eaa06463dde3e33069a34d7f102f5878cf`
- Matching source: https://www.wireshark.org/download/src/all-versions/wireshark-4.6.9.tar.xz
- SHA-256: `d062d416a1ab3a49975aafe3a671c882dde0562ccd71b078808ceb59d465fc0f`
- Older and newer source tarballs: https://www.wireshark.org/download/src/

The Windows release attaches `wireshark-4.6.9.tar.xz` next to `Primer_2.0.0_x64-setup.exe`. If you received the installer on a USB stick, share, or ticket and you do not have GitHub, the same delivery should include that source archive. A link alone is a weak offer for an air-gapped machine.

Primer runs `tshark.exe` as a separate, unmodified program and reads its output. Primer does not link `libwireshark`, `libwiretap`, or `libwsutil`. The silent Wireshark install used at build time does not install Npcap, and the staging script deletes any Npcap installer it finds. Wireshark is a trademark of the Wireshark Foundation. The Wireshark project does not endorse Primer.

## Suricata

Suricata is published under the GNU GPL, version 2. Many of its files name version 2 only, without "any later version". Treat the engine as GPL-2.0. Read the `COPYING` file of the version you actually run.

Source:

- https://suricata.io/download/ and the release tags at https://github.com/OISF/suricata
- The source tarball for a given version is linked from those pages (`suricata-<version>.tar.gz`).

**Primer 2.0.0 does not bundle a Suricata binary.** The usual Windows build is linked to Npcap's `wpcap.dll` and will not start, even for `suricata -r`, when that DLL is missing. Npcap's free licence forbids bundling the driver, and installing it needs an administrator. An MSYS2 build against libpcap can read a file without Npcap, but that binary was not proven on a clean Windows 10 machine in this environment, so it is not in the installer. The hook in `src-tauri/src/suricata.rs` runs `suricata -r` if you place such a binary yourself. If you do, you must ship the matching Suricata source with that binary, the same way the Wireshark source is shipped.

## Emerging Threats Open

Not bundled. ET Open is BSD. You may ship a snapshot if you keep the `LICENSE` file from that snapshot and you do not imply that Emerging Threats or Proofpoint endorse Primer. ET Pro must not be included and the config must not point at a Pro download. A snapshot is staged only from a local tarball (`scripts/stage-et-open.ps1`). Primer does not download rules.

## Npcap

Not bundled. Free licence: https://npcap.com/dist/npcap-license.txt and the download page https://npcap.com/#download. Live capture is optional and only works when Npcap is already installed.

## SQLite

The case database is SQLite, compiled into Primer through `rusqlite`. SQLite is in the public domain. The `rusqlite` crate is MIT. https://www.sqlite.org/copyright.html

## Other Rust and npm packages

`sha2`, `flate2`, `serde`, Tauri, and the npm packages in `package-lock.json` keep their own licences, mostly MIT or Apache-2.0. The browser build does not add a new network dependency. The optional in-browser model is downloaded only if an investigator turns it on, which was already true in 1.0.1, and that download is not part of the installer.
