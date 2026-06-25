# `threagile prioritize` — what to fix first, and how

A full analysis can produce dozens of findings. `prioritize` answers the question
a developer actually asks — **"which few do I fix first, and how?"** — by ranking
the still-at-risk findings on a composite exploitability score and attaching the
remediation guidance the rule already carries (action, CWE, OWASP cheat sheet).
Deterministic, no AI.

```sh
threagile prioritize --model threagile.yaml
threagile prioritize --model threagile.yaml --top 5
threagile prioritize --model threagile.yaml --min-severity high --format markdown
```

## The exploitability score

The score is **additive** over normalized factors, so no single zero factor can
hide a finding entirely (an internal-only bug still surfaces, just lower):

| Factor | Weight | What it measures |
|---|--:|---|
| severity | 0.35 | the finding's severity (Low → Critical) |
| internet-exposure | 0.20 | is the affected asset internet-facing? |
| attack-path-reachable | 0.20 | does the asset lie on a real attack path from the internet to crown-jewel data? (computed from the graph, not self-declared — so it's hard to game) |
| data-sensitivity | 0.15 | highest confidentiality of the data the asset handles |
| confidence | 0.10 | the rule's true-positive confidence |

The reachability factor reuses the same BFS engine as [`paths`](./attack-paths.md),
so "reachable" means an attacker really can get there, not that someone tagged it.

## Output

`text` (default), `markdown` (a ranked table + a numbered remediation list, ideal
for a PR comment), or `json`. `--top N` limits the list (default 10; `0` = all)
and `--min-severity` drops everything below a floor. Each item shows the affected
asset, a `why` breakdown of the factors, and a `fix` line with the concrete action,
CWE, and cheat-sheet link.

Pipe the markdown straight into a pull-request comment so reviewers see the few
findings that matter and exactly how to resolve them.
