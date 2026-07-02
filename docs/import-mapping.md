# Diagram import mapping (`--mapping`)

Diagram importers (`import drawio`, `import threat-dragon`, `import otm`)
classify shapes with built-in heuristics, but real diagrams use internal
nomenclature ("MinIO", "Blob", team-specific service names) and color/style
conventions (e.g. a red dashed edge meaning "unencrypted") those heuristics
can't know about. `--mapping <rules.yaml>` lets a team encode both without
touching the importer.

```sh
threagile import drawio --diagram architecture.drawio --mapping mappings.yaml
```

## Rule file format

```yaml
rules:
  - match:
      label: '(?i)minio|blob'      # regex tested against the element's label
    set:
      technology: object-storage
      tags: [object-store]

  - match:
      edge: true                    # only match communication links
      color: '#FF0000'
      line_style: dashed
    set:
      encryption: none
      tags: [flagged-unencrypted]

  - match:
      fill_color: '#00AA00'
    set:
      trust_boundary: internal
```

- Rules are evaluated **in order**; for scalar fields (`type`, `technology`,
  `machine`, `encryption`, CIA ratings) the **first matching rule wins**.
  `tags` accumulate and dedupe across every matching rule instead.
- `match.label` is a regular expression tested against the element's
  title/name. `match.edge` restricts the rule to communication links.
  `match.color` / `match.fill_color` / `match.line_style` only fire for
  importers that retain raw diagram style metadata (currently draw.io, via
  its `mxCell` style string) — threat-dragon/otm rarely carry color, so
  those matchers simply won't fire there.
- A rule with no match criteria or no fields to set is rejected at load time
  with a descriptive error (it would otherwise match every element).

## Applies to

`drawio`, `threat-dragon`, `otm` (and future diagram importers, e.g. mermaid).
Not applied to the infrastructure-as-code importers (`terraform`, `openapi`,
`kubernetes`, `compose`), which already carry structured metadata and don't
need style/label heuristics.
