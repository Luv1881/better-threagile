# `threagile import drawio` — diagram → model (best-effort, no AI)

Converts a [draw.io / diagrams.net](https://www.drawio.com/) (mxGraph) diagram
into a Threagile model fragment. The conversion is **deterministic** (no AI), but
because draw.io is a *generic* diagram format with no built-in threat-model
semantics, it is necessarily **lossy** — shapes are classified by their style and
label. Every generated asset is tagged **`review-drawio`** so you remember to
verify and refine the fragment.

> Prefer [OWASP Threat Dragon import](./import-threat-dragon.md) when you have a
> Threat Dragon model — it is threat-model-native and far higher-fidelity. Use
> draw.io import when a generic architecture diagram is all you have.

```sh
threagile import drawio --diagram architecture.drawio --output model-fragment.yaml
threagile analyze-model --model model-fragment.yaml --output out
```

## Mapping (heuristic)

| draw.io shape | Threagile |
|---------------|-----------|
| Actor shape (`shape=actor`), or label containing user/client/browser/customer/actor/attacker/external | External-entity (internet-facing) |
| Cylinder/database shapes, or label containing db/database/store/postgres/redis/mongo/s3/bucket/queue/cache | Datastore (technology classified from the label) |
| Any other vertex | Process (`web-server`) |
| Edge (with source + target) | Communication link |
| Rectangle styled/named trust/boundary/zone/dmz/vpc/subnet, or a dashed container | Trust boundary — membership by the draw.io `parent` (container) or by absolute geometry (smallest containing box); names containing internet/untrusted/public/dmz become on-prem (external) boundaries |

A vertex that is the direct target of an edge from an actor is marked
internet-facing.

## Compressed files

draw.io often stores the diagram **compressed** (deflate + base64) inside
`<diagram>`. The importer decodes that automatically, but if decoding fails it
asks you to re-export as uncompressed XML (**Extras → Edit Diagram**, or
**File → Export as → XML**, uncompressed). A bare `<mxGraphModel>` (the "Edit
Diagram" copy) is also accepted directly.

## Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--diagram` | stdin | Path to the `.drawio` file |
| `--output` | stdout | Write the fragment to a file |
| `--label` | `drawio` | Short label appended to generated asset IDs |
| `--diff` | false | Print a summary without writing |
