# `threagile import otm` — Open Threat Model → model (deterministic, no AI)

Converts an [Open Threat Model](https://github.com/iriusrisk/OpenThreatModel)
(OTM) JSON document into a Threagile model fragment. OTM is a vendor-neutral
threat-model interchange format (IriusRisk et al.), so unlike generic diagram
formats the conversion is high-fidelity and near-lossless. The conversion is
**deterministic** — no AI is involved. Every generated element is tagged
**`review-otm`**.

```sh
threagile import otm --file model.otm.json --output model-fragment.yaml
threagile analyze-model --model model-fragment.yaml --output out
```

## Mapping

| OTM | Threagile |
|-----|-----------|
| `trustZones` (with nesting via `parent.trustZone`) | Trust boundaries; zones named/rated as low-trust (by name keyword or a low `risk.trustRating`) become untrusted/on-prem boundaries |
| `components` | Technical assets — type classified from `component.type` via an ordered lookup table (e.g. `web-application`→process, `database`/`data-store`→datastore, `load-balancer`→load-balancer), default `process` |
| `dataflows` | Communication links; `bidirectional: true` produces two links |
| `assets` | Data assets — `risk.confidentiality` / `.integrity` / `.availability` (0–100) are bucketed into Threagile's five-value CIA enums |

## Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--file` | stdin | Path to the `.otm.json` file |
| `--output` | stdout | Write the fragment to a file |
| `--label` | `otm` | Short label appended to generated asset IDs |
| `--diff` | false | Print a summary without writing |
| `--scaffold` | true | Annotate inferred fields with `# TODO(review): …` comments — see [docs/import-scaffold.md](./import-scaffold.md) |
| `--mapping` | — | Team nomenclature/style rules — see [docs/import-mapping.md](./import-mapping.md) |
| `--stub-data-assets` | true | Generate stub data assets for datastores/internet-inbound links that have none |
