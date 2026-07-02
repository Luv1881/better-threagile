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

### Nested boundaries

A boundary container/swimlane placed *inside* another boundary container
becomes a nested trust boundary, to arbitrary depth — not just one level.
Nesting is resolved the same way as top-level membership: first the draw.io
`parent` attribute (if it names another boundary cell), falling back to
geometry containment in the smallest boundary box that still strictly
contains it. The outer boundary's `trust_boundaries_nested` list then names
the inner boundary's id, matching how `pkg/types.TrustBoundary` /
`pkg/input.TrustBoundary` already represent nesting. A boundary that only
wraps other boundaries (no directly-contained assets of its own) is still
emitted — it is not dropped just because `technical_assets_inside` is empty.

### Edge label → protocol guess

Every communication link's `protocol` is guessed from the edge's label (the
same keyword table as [Mermaid import](./import-mermaid.md#edge-label--protocol-guess),
kept in lockstep between the two importers so a diagram redrawn in either
tool gets the same guess). Case-insensitive substring match, first match
wins, defaulting to `https` (a conservative "assume encrypted" default) when
nothing matches:

| Label contains | Guessed protocol |
|---|---|
| `https`, `tls`, `ssl` | `https` |
| `grpc` | `https` |
| `http` | `http` |
| `ssh` | `ssh` |
| `sftp` | `sftp` |
| `ftps` | `ftps` |
| `ftp` | `ftp` |
| `ldaps` | `ldaps` |
| `ldap` | `ldap` |
| `smtps`, `smtp+tls` | `smtp-encrypted` |
| `smtp` | `smtp` |
| `mqtt` | `mqtt` |
| `kafka`, `amqp`, `queue`, `jms` | `jms` |
| `nfs` | `nfs` |
| `smb`, `cifs` | `smb` |
| `sql`, `postgres`, `mysql`, `jdbc`, `odbc` | `sql-access-protocol-encrypted` |
| `nosql`, `mongo`, `redis` | `nosql-access-protocol-encrypted` |
| *(none of the above)* | `https` |

Every guessed protocol is still importer-owned (tagged `review-drawio`), so
review it like any other inferred field — this is a best-effort guess from a
label a human wrote for readability, not a network capture.

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
| `--scaffold` | true | Annotate inferred fields with `# TODO(review): …` comments — see [docs/import-scaffold.md](./import-scaffold.md) |
| `--mapping` | — | Team nomenclature/color/line-style rules — see [docs/import-mapping.md](./import-mapping.md) |
| `--stub-data-assets` | true | Generate stub data assets for datastores/internet-inbound links that have none — diagrams rarely draw data assets, and without them the model analyzes to near-zero risk |
| `--merge` | — | Reconcile against an already-edited model file instead of overwriting it — see [docs/import-merge.md](./import-merge.md) |
| `--page` | *(all pages)* | Import only one `<diagram>` page, by 1-based index (`"2"`) or by its draw.io page name (case-insensitive). By default every page in the file is imported and merged into one model; each page's boundary/geometry containment stays scoped to that page, so a page-2 container never absorbs a page-1 shape, while generated asset IDs stay globally unique across all merged pages |
| `--boundary` | — | Import only the elements inside the named trust boundary's subtree (its own contents plus any nested boundaries' contents, to arbitrary depth), skipping everything else — matched case-insensitively against the boundary's label. Useful for importing one subsystem at a time out of a large enterprise diagram. Composes with `--page` |
