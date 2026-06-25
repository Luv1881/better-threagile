# `threagile paths` — attack-path analysis

Computes the shortest routes an attacker can take from an **internet-facing
asset** to a **crown-jewel asset** (one that stores or processes confidential or
strictly-confidential data), following communication links in their call
direction. It answers the review question *"if this gets popped, how few hops to
our sensitive data?"*

```sh
threagile paths --model threagile.yaml
```

Example output:

```
Attack-path analysis: 2 entry point(s) → 11 crown-jewel target(s)

12 path(s) (shortest first):

  [0 hop(s)] customer-client (directly internet-facing)
            exposes: customer-accounts, customer-contracts
  [2 hop(s)] customer-client --(Customer Traffic)--> load-balancer --(Web Application Traffic)--> apache-webserver
            exposes: customer-accounts, internal-business-data
```

## How it works

- **Graph:** nodes are technical assets; a directed edge `A → B` exists for every
  communication link from `A` to `B` (the call direction — compromising `A`
  gives the attacker reach to `B`).
- **Entry points:** every internet-facing asset (`internet: true`), or a single
  asset via `--from <asset-id>`.
- **Crown jewels (targets):** any asset that stores or processes a data asset
  rated `confidential` or `strictly-confidential`. Narrow with `--to`.
- **Paths:** breadth-first shortest path from each entry point to each reachable
  target (one per target), reported shortest-first. A 0-hop path means a crown
  jewel is *directly* internet-facing. Cycles and self-loops are handled.

## Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--from` | `internet` | Entry point: an asset ID, or `internet` for all internet-facing assets |
| `--to` | (all crown jewels) | A data-asset ID (assets holding it become targets) or a technical-asset ID |
| `--max-paths` | 0 (no cap) | Cap the number of paths reported |
| `--format` | `text` | `text`, `markdown` (PR-comment ready), or `json` |
| `--output` | — | Also write the rendered report to a file |

## Use in CI

Combine with the [gate](./gate.md): export `--format json` and assert there is no
short path (e.g. ≤ 2 hops) to your most sensitive data assets as a release check.
