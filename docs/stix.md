# `threagile stix` — STIX 2.1 export

Exports the analyzed model as a [STIX 2.1](https://oasis-open.github.io/cti-documentation/)
bundle for interop with threat-intelligence platforms (OpenCTI, MISP-via-bridge,
TIPs) and the wider OASIS CTI ecosystem.

```sh
threagile stix --model threagile.yaml --output stix-bundle.json
```

## What the bundle contains

| STIX object | From |
|-------------|------|
| `identity` (`identity_class: system`) | the threat model |
| `infrastructure` | each technical asset |
| `vulnerability` | each generated risk, with a **CWE** `external_reference` |
| `attack-pattern` | each MITRE **ATT&CK technique** and **CAPEC** pattern the risk's category maps to (with `mitre-attack` / `capec` external references and URLs) |
| `course-of-action` | each risk category's mitigation/action |
| `relationship` | `vulnerability targets infrastructure`, `attack-pattern targets infrastructure`, `course-of-action mitigates vulnerability` |

The ATT&CK and CAPEC mappings come from the curated tables in
`pkg/attack/mapping.go` (techniques) and `pkg/attack/capec.go` (patterns); finding
categories with no mapping are reported on stderr.

## Determinism

Object IDs are **UUIDv5** derived from stable seeds (synthetic risk IDs, asset
IDs) and `created`/`modified` use a fixed reference timestamp, so the same model
always produces a byte-identical bundle — safe to commit and diff in CI.

## Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--output` | stdout | Write the STIX 2.1 bundle JSON to a file |

(Like the other data commands, the bundle goes to **stdout** so
`threagile stix ... > bundle.json` works.)
