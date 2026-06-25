# `threagile hooks install` — git hook guardrails

Wire the threat model into the normal git workflow so problems surface on the
developer's machine — **before CI, not after**. This is the lowest-friction way
to keep a model honest: no pipeline edits, no new dashboards, just the checks a
developer already expects from a linter.

```sh
threagile hooks install                 # pre-commit + pre-push
threagile hooks install --hook pre-commit
threagile hooks install --print         # preview the scripts without installing
```

## What gets installed

| Hook | Runs | Purpose |
|---|---|---|
| `pre-commit` | `validate` + `lint` | fast feedback — never commit a broken or low-quality model |
| `pre-push` | `validate` + `gate` (if `policy.yaml` exists) | the security gate — don't push code whose model violates policy |

The generated scripts:

- call the **current threagile binary by absolute path**, so they keep working
  regardless of the developer's `PATH`;
- **no-op when the repo has no model yet** (`[ -f "$MODEL" ] || exit 0`), so they
  can be installed org-wide without breaking unrelated repos;
- run `gate` only when a `policy.yaml` is present, so pre-push stays useful even
  before a team adopts the gate (pair with [`policy init`](./gate.md#secure-by-default-starter-policies-policy-init)).

## Flags

| Flag | Default | Description |
|---|---|---|
| `--hook` | `pre-commit,pre-push` | which hooks to install |
| `--dir` | repo's git hooks dir | write hooks somewhere else (e.g. a shared `core.hooksPath`) |
| `--force` | `false` | overwrite existing hook files |
| `--print` | `false` | print the script(s) instead of installing |

Existing hook files are never overwritten unless you pass `--force`. The hooks
directory is discovered with `git rev-parse --git-path hooks`, so worktrees and
a custom `core.hooksPath` are handled automatically.

A typical zero-to-guarded setup is three commands:

```sh
threagile policy init --profile balanced     # secure-by-default gate policy
threagile hooks install                      # local guardrails
threagile generate-ci --target github        # the same checks in CI
```
