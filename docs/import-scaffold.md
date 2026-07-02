# Editable scaffold output (`--scaffold`)

Diagram importers (`import drawio`, `import threat-dragon`, `import otm`)
guess a lot: asset types, technologies, encryption, CIA ratings. A raw YAML
dump of those guesses looks authoritative and invites adopters to trust it
without review. `--scaffold` (default **on** for these three importers)
instead emits the fragment as a template to finish:

- A file-header comment block: source file, importer, and counts of
  generated technical assets / trust boundaries / communication links / data
  assets.
- A `# TODO(review): <reason>` head-comment on every field the importer only
  ever guessed or defaulted — asset type, technology, machine, encryption,
  and CIA ratings.
- Every generated element additionally carries a `review-<importer>` tag
  (e.g. `review-drawio`) so it's greppable independent of the comments.

```sh
threagile import drawio --diagram architecture.drawio --output model-fragment.yaml
# ...or for a plain fragment with no comments:
threagile import drawio --diagram architecture.drawio --scaffold=false
```

Not applied to the infrastructure-as-code importers (`terraform`, `openapi`,
`kubernetes`, `compose`) — those read structured, non-heuristic metadata and
stay plain.

See also [`--mapping`](./import-mapping.md) (team nomenclature/style rules,
applied before scaffolding) and `--stub-data-assets` (fills in the data
assets diagrams never draw; documented alongside each importer's page).
