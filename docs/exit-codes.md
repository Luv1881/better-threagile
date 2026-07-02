# Exit codes

better-threagile uses a small, stable set of process exit codes so CI can tell
a *policy/quality gate failure* apart from a *tool error* without parsing output.

| Code | Meaning | Examples |
|------|---------|----------|
| `0` | Success — command ran and any gate passed | a clean `gate`, `analyze-model`, `validate` |
| `1` | Runtime or usage error — the tool could not complete | bad flags, unreadable/invalid model, analysis failure |
| `3` | Policy / quality gate failed — the model is well-formed but did not meet a configured bar | see below |

There is intentionally **no code 2** (it previously leaked from an earlier
command; now unified). Codes ≥ 126 are avoided (reserved by the shell for signals).

## What returns `3`

These are *expected, actionable* failures a pipeline should block on — distinct
from a crash:

- `gate` — one or more policy violations
- `diff --fail-on-new-high` / `--fail-on-new-critical` — new findings vs a baseline model
- `sbom --fail-on-kev` — a KEV-listed vulnerability is present
- `score --min <n>` — health score below the threshold
- `validate --fail-on-secrets` — a possible secret in the model file
- `gate`'s `min_score` policy rule — health score below the policy minimum

## CI usage

```sh
threagile gate --model threagile.yaml --policy policy.yaml
case $? in
  0) echo "gate passed" ;;
  3) echo "gate failed — block the merge"; exit 1 ;;
  *) echo "threagile errored — investigate"; exit 1 ;;
esac
```
