# Emerging Threats Open is not in git.

Primer ships no ruleset. ET Open is BSD and may be redistributed if you keep its own `LICENSE` file and do not imply that Emerging Threats or Proofpoint endorse Primer. ET Pro must not be placed here.

To stage a snapshot you already have:

```
third-party/emerging-threats-open.tar.gz
```

must contain a `LICENSE` file. `scripts/stage-et-open.ps1` copies it into this folder at build time and fails if the licence file is missing. The installer does not download rules.

Suricata itself is not bundled. See `docs/ENGINES.md`.
