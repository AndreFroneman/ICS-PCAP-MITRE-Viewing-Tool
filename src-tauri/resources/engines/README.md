# Engine programs are staged by CI, not committed.

`scripts/stage-tshark.ps1` copies `tshark.exe`, `dumpcap.exe`, their DLLs, and the dissector plugins from a silent Wireshark install. That silent install does not install Npcap, and the script deletes any Npcap installer it finds.

Primer starts these as separate programs. It does not link libwireshark.

Suricata is intentionally absent. See `docs/ENGINES.md`.
