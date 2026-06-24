# `threagile attack-navigator` — MITRE ATT&CK Navigator export

Maps every generated risk finding to MITRE ATT&CK (Enterprise) techniques and
writes an [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
layer JSON. Import the file into the Navigator to see the techniques your threat
model exercises highlighted on the ATT&CK matrix — the language a SOC or
detection-engineering team already speaks.

```sh
threagile attack-navigator --model threagile.yaml --output attack-layer.json
```

Then open the Navigator → *Open Existing Layer* → *Upload from local* and select
`attack-layer.json`.

## What the layer contains

- One entry per ATT&CK technique reached by the model's findings.
- **Score** = number of findings mapping to that technique.
- **Color** = the highest severity among those findings (red = Critical/High,
  orange = Elevated, yellow = Medium/Low).
- **Comment** = the technique name, finding count, max severity, and the
  contributing Threagile risk categories.

If some finding categories have no ATT&CK mapping yet, the command prints them
so the coverage gap is visible (rather than silently dropped).

## How the mapping works

The risk-category → technique mapping lives in `pkg/attack/mapping.go`, keyed by
Threagile risk-category ID. It is deliberately conservative — only
well-defended links are included. Many app-exploitable flaws (SQL/LDAP/XXE
injection, SSRF, path traversal, missing auth) map to **T1190 — Exploit
Public-Facing Application**, the accurate ATT&CK abstraction for "attacker
exploits an application bug". To extend coverage, add entries to
`CategoryTechniques` (and the technique's name to `techniqueNames`); a test
enforces that every mapped technique has a name.
