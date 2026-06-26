# `threagile summary` — the sprint / PR scorecard

One shareable scorecard from a single analysis pass: the threat-model health
[score](./score.md) plus the top [findings to fix](./prioritize.md) with their
remediation. Drop it in a recurring sprint review or a pull-request comment so a
team tracks one number and a short, actionable to-do list — not a full report.
Deterministic, no AI.

```sh
threagile summary --model threagile.yaml
threagile summary --model threagile.yaml --format markdown --output summary.md
threagile summary --model threagile.yaml --top 3
```

It runs the analysis once and renders both the score headline (grade,
completeness, posture, any caveats) and the ranked "fix these first" list with
action + CWE + cheat-sheet links. `--format` is `markdown` (default), `text`, or
`json`; `--top N` limits the list (`0` = all).
