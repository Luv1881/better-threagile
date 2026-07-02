# `threagile review` — the human-in-the-loop step after an import

Every deterministic diagram/IaC importer (`threagile import drawio|mermaid|
otm|threat-dragon|...`) tags every heuristically-classified element it
generates with `review-<importer>` (see [docs/import-scaffold.md](./import-scaffold.md)),
and `--stub-data-assets` tags every generated placeholder data asset with
`stub-data-asset` (see [docs/import-mapping.md](./import-mapping.md)). Those
tags are the only state this feature needs: `review` just finds them.

```sh
threagile review --model model-fragment.yaml
threagile review --model model-fragment.yaml --format json
threagile review --model model-fragment.yaml --fail-on-unreviewed
```

## What it scans

`review` walks every `technical_assets`, `data_assets`, `trust_boundaries`
and `communication_links` entry in the model and reports each one that
carries a tag matching `^review-` (any importer) or the exact tag
`stub-data-asset`, together with which tag(s) triggered the flag.

## Clearing a finding

Clearing is **stateless and explicit**: open the model YAML, fix the field(s)
the importer's `# TODO(review): …` comment calls out (see
[docs/import-scaffold.md](./import-scaffold.md)), and delete the
`review-<importer>`/`stub-data-asset` tag. There is no separate
"reviewed"/sign-off file to keep in sync — the tag's presence or absence in
the YAML *is* the review state, so it shows up in `git diff` and code review
like any other change.

## Output formats

- `--format markdown` (default): a human-readable report with counts and one
  table per element kind — safe to post as a PR comment.
- `--format json`: a machine-readable array of `{kind, name, id, parent,
  tags}` objects, for CI tooling that wants to act on individual findings.

## Exit codes

`review` is purely informational and always exits **0** — it never blocks a
build on its own. Pass `--fail-on-unreviewed` to make it exit **3** if
anything is still flagged, matching the exit code [`gate`](./gate.md) uses
for a policy violation.

## Gate integration

To make an unreviewed import block CI outright, set the gate policy key
`fail_on_unreviewed: true` (see [docs/gate.md](./gate.md#blocking-merge-on-unreviewed-imports)):

```yaml
# policy.yaml
fail_on_unreviewed: true
```

`threagile gate` will then fail (exit 3) whenever the model has any
review-flagged element, using the exact same scan `threagile review` uses —
the two commands never disagree about what still needs review.
