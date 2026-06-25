# `threagile attack-tree` — goal-oriented attack trees

Builds a goal-oriented **attack tree** per crown-jewel asset (one storing or
processing confidential / strictly-confidential data). The **root is the
attacker's goal**; the OR-branches are the routes that reach it, merged so shared
sub-paths appear once, with internet-facing **entry points as the leaves**. It
reuses the deterministic [attack-path](./attack-paths.md) analysis — no AI.

```sh
threagile attack-tree --model threagile.yaml
threagile attack-tree --model threagile.yaml --to customer-accounts --format dot --output tree.dot
dot -Tpng tree.dot -o tree.png      # render the Graphviz output
```

Example (text):

```
GOAL: compromise erp-system  (min 3 hop(s))
  exposes: customer-accounts, internal-business-data, …
  └─ apache-webserver  (via ERP System Traffic)
    └─ jenkins-build-server  (via Application Deployment)
      └─ external-dev-client  (ENTRY via Jenkins Web-UI Access)
    └─ load-balancer  (via Web Application Traffic)
      └─ customer-client  (ENTRY via Customer Traffic)
```

## Output formats

| `--format` | Use |
|------------|-----|
| `text` (default) | indented outline for terminals |
| `markdown` | PR-comment-ready |
| `dot` | Graphviz digraph (goals are boxes, entries are diamonds; edges follow the attacker's direction) |
| `json` | nested `{goal, root, or:[…]}` tree |

## Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--from` | `internet` | Entry point: an asset ID, or `internet` for all internet-facing assets |
| `--to` | (all crown jewels) | Goal: a data-asset ID or technical-asset ID |
| `--max-paths` | 0 | Cap the number of paths considered |
| `--format` | `text` | `text`, `markdown`, `json`, or `dot` |
| `--output` | — | Also write the rendered tree to a file |

The tree is a deterministic OR-tree over the shortest routes to each goal (one
shortest route per entry/target pair); see the design note in
[attack-paths.md](./attack-paths.md).
