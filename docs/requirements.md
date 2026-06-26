# `threagile requirements` — security requirements / test cases from the model

Turns the threat model into an actionable security backlog: one deduplicated,
testable requirement per still-at-risk finding category, derived from the rule's
own remediation (action), verification check, CWE and the affected assets. No AI.

```sh
threagile requirements --model threagile.yaml                       # Markdown checklist
threagile requirements --model threagile.yaml --format gherkin -o security.feature
threagile requirements --model threagile.yaml --format json
```

| Format | Use it for |
|---|---|
| `markdown` *(default)* | a `- [ ]` checklist to paste into a sprint backlog / issue / PR template |
| `gherkin` | `Scenario:` stubs as a starting point for security acceptance tests |
| `json` | feeding a tracker or another tool |

Requirements are deduplicated by finding category (so "Missing Authentication"
across five assets is one requirement listing all five), carry the highest
severity among the covered findings, and are sorted highest-severity first. This
complements [`prioritize`](./prioritize.md) (which *ranks* what to fix) by giving
you the *checklist* of what "done" looks like.
