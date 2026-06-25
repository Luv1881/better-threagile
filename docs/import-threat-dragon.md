# `threagile import threat-dragon` — diagram → model (no AI)

Converts an [OWASP Threat Dragon](https://www.threatdragon.com/) (v2) model file
into an analyzable Threagile model fragment. The conversion is **fully
deterministic** — it parses the diagram's shapes and geometry, with no AI or
heuristics-via-LLM in the loop.

```sh
threagile import threat-dragon --tdmodel model.json --output model-fragment.yaml
threagile analyze-model --model model-fragment.yaml --output out
```

## Mapping

| Threat Dragon shape | Threagile |
|---------------------|-----------|
| Actor (`tm.Actor`) | External-entity technical asset, internet-facing (`used_as_client_by_human`) |
| Process (`tm.Process`) | Process technical asset (`web-application` if flagged, else `web-server`) |
| Store (`tm.Store`) | Datastore technical asset (technology classified from the node name — postgres/redis/mongo → database, minio/s3 → file-server, vault → vault, …) |
| Data flow (`tm.Flow`) | Communication link source → target (HTTPS if `isEncrypted`, else the declared protocol / HTTP) |
| Trust-boundary box (`tm.BoundaryBox`) | Trust boundary — **membership resolved by diagram geometry** (a node belongs to the smallest box that contains its centre); boxes named/described "internet"/"untrusted" or marked public become on-prem (external) boundaries |
| `outOfScope` flag | `out_of_scope` on the asset |

A process that is the **direct target of a flow from an actor** is marked
internet-facing. CIA ratings default conservatively and encryption defaults to
`none` — review and refine the fragment before merging.

## Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--tdmodel` | stdin | Path to the Threat Dragon JSON model |
| `--output` | stdout | Write the fragment to a file |
| `--label` | `td` | Short label appended to generated asset IDs |
| `--diff` | false | Print a summary without writing |

## Why no AI

Threat Dragon's JSON is a threat-model-native domain model (typed shapes, trust
boundaries, flows), so a diagram can be projected onto Threagile's asset/link/
boundary model by direct, reviewable rules — no inference required. (Generic
diagram formats like draw.io/Mermaid lose the security semantics — technology,
trust-boundary type, exposure — and are intentionally not supported.)
