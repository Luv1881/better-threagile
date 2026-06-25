# `threagile bootstrap` — zero-config onboarding

The single biggest friction point in adopting threat-modelling-as-code is the
blank page. `bootstrap` removes it: it scans a repository for infrastructure it
already describes and assembles a **starter threat model** from what exists, then
drops a secure-by-default gate policy and prints the next steps — so a team goes
from nothing to an analyzable model in one command. Deterministic, no AI.

```sh
threagile bootstrap                         # scan ., write threagile.yaml + policy.yaml
threagile bootstrap --dir ./infra --with-hooks
threagile bootstrap --policy-profile strict --force
```

## What it detects

| Source | How it's found | Imported? |
|---|---|---|
| docker-compose | `docker-compose.y*ml`, `compose.y*ml` | yes |
| Kubernetes | `*.y*ml` with `apiVersion:` and `kind:` (all merged together) | yes |
| OpenAPI / Swagger | files declaring `openapi:` / `swagger:` | yes |
| Terraform | `*.tf` | advisory only* |

\* Terraform is HCL; the importer needs `terraform show -json`, so `bootstrap`
detects `.tf` files and tells you the one command to run rather than guessing.

The scan skips `.git`, `node_modules`, `vendor`, `.terraform`, `dist`, `build`,
and similar directories, ignores files over 8 MiB, and never treats an existing
`threagile.yaml` / `policy.yaml` as input. Detected fragments are merged
deterministically (first-wins on ID collisions), and the model is written in the
authoring format so it round-trips straight through `analyze-model`.

## What it writes

- **`threagile.yaml`** — the merged starter model (review and refine it).
- **`policy.yaml`** — a [secure-by-default gate policy](./gate.md#secure-by-default-starter-policies-policy-init) (`--policy-profile`, default `balanced`; pass `""` to skip).
- with `--with-hooks`, the git [pre-commit / pre-push hooks](./hooks.md) too.

Existing files are never overwritten unless you pass `--force`. If no importable
infrastructure is found, `bootstrap` says so and points you at `threagile init`
rather than writing an empty model.

## The one-minute adoption path

```sh
threagile bootstrap --with-hooks                     # model + policy + local guardrails
threagile score --model threagile.yaml               # where do we stand?
threagile generate-ci --target github                # same checks in CI
```
