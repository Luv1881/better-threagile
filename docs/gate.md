# `threagile gate` — policy-as-code quality gate

`gate` turns a model analysis into a CI pass/fail decision driven by a small,
reviewable `policy.yaml`. It is the threat-model equivalent of a lint or
coverage gate: the build fails (exit code **3**) when the model violates the
team's declared risk policy.

```sh
threagile gate --model threagile.yaml --policy policy.yaml
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | All policy rules satisfied. |
| 3 | One or more policy rules violated (the gate failed). |
| 1 | Usage / analysis error (bad model, unreadable policy, etc.). |

The distinct code **3** lets a pipeline tell a *policy* failure from a *tooling*
failure.

## Policy file

Every rule is optional; an empty policy passes everything, so teams can adopt
the gate incrementally and tighten over time.

```yaml
name: "Production security gate"

# Cap still-at-risk findings per severity. mitigated/false-positive findings
# never count against a cap.
max_severity_counts:
  critical: 0
  high: 2

# Cap the total number of still-at-risk findings.
max_total_at_risk: 60

# Every still-at-risk finding at or above this severity must carry a tracking
# decision (i.e. must not be left "unchecked"). This is the governance rule
# auditors ask for.
require_tracking_at_or_above: elevated

# Fail if any risk acceptance has passed its accepted_until date.
fail_on_expired_acceptance: true

# Block NEW findings at or above this severity relative to an approved baseline.
# Requires --baseline; with no baseline the rule fails loudly (never silently
# passes).
forbid_new_at_or_above: high

# Require minimum compliance-control coverage from the loaded rule packs.
framework_coverage:
  - {framework: owasp_top10_2021, min_percent: 70}
  - {framework: nist_800_53,      min_percent: 50}

# Fail if the model still has any element tagged review-<importer> (a
# diagram/IaC import that was never reviewed) or stub-data-asset (a
# generated placeholder data asset). See docs/review.md.
fail_on_unreviewed: true
```

Unknown keys are **rejected** at load time — a typo in a rule name fails the
command rather than silently disabling a gate.

## "No new High in this PR" (baseline diff)

Generate a baseline `risks.json` from the approved/`main` model, then gate the
PR model against it:

```sh
# on main
threagile analyze-model --model threagile.yaml --output baseline --skip-report-pdf

# on the PR
threagile gate --model threagile.yaml --policy policy.yaml \
  --baseline baseline/risks.json
```

`forbid_new_at_or_above` flags any finding (by synthetic ID) at or above the
named severity that is not present in the baseline.

## Blocking merge on unreviewed imports

`fail_on_unreviewed: true` fails the gate if the model has any element still
carrying a `review-<importer>` tag (left by `import drawio`/`mermaid`/`otm`/
`threat-dragon`) or a `stub-data-asset` tag (left by `--stub-data-assets`).
Run `threagile review --model threagile.yaml` locally to see exactly what's
still flagged and clear each tag once you've confirmed the field(s) it
covers — see [docs/review.md](./review.md).

## Gating on the health score

`min_score` requires the [threat-model health score](./score.md) (0–100) to stay
at or above a floor — one number that captures both model completeness and risk
posture. Set it to your current score and raise it over time so quality can only
improve:

```yaml
min_score: 75
```

The gate only computes the score when this rule is present, so it adds no cost to
policies that don't use it.

## Output formats

```sh
threagile gate ... --format text       # default, for CI logs
threagile gate ... --format json       # machine-readable result
threagile gate ... --format markdown --output gate.md   # post as a PR comment
threagile gate ... --format junit --output gate.xml     # JUnit XML for CI test reports
```

The Markdown form is designed to be dropped straight into a pull-request comment
by a CI job (see `threagile generate-ci`).

The **JUnit XML** form turns each configured policy rule into a `<testcase>` (a
rule that fired becomes a `<failure>` listing the offending finding IDs), so the
threat-model gate shows up alongside your unit tests in any CI that renders JUnit
— Jenkins, GitLab CI (`artifacts:reports:junit`), CircleCI, Azure DevOps,
Buildkite, etc. The exit code is still `3` on a violation, so the gate also fails
the job, not just the test report.

## Secure-by-default starter policies (`policy init`)

You don't have to hand-write a policy. `policy init` scaffolds a tuned,
secure-by-default `policy.yaml` so a team can adopt the gate in one minute and
tighten over time — no security expert required.

```sh
threagile policy list                                   # describe each profile
threagile policy init                                   # 'balanced' -> policy.yaml
threagile policy init --profile strict --output ci/policy.yaml
threagile policy init --profile regulated -o -          # print to stdout
```

| Profile | Use it for | Enforces |
|---|---|---|
| `prototype` | early spikes / pre-production | no Critical at risk; expired acceptances fail |
| `balanced` *(default)* | most production services | + no High at risk; Elevated must be triaged |
| `strict` | internet-facing / high-value | + no Elevated at risk; triage required down to Medium |
| `regulated` | audit scope (SOC 2 / ISO / PCI) | strict + every finding triaged + framework-coverage template |

Every profile is validated in CI to parse through the same strict loader the
gate uses, and writing one is refused over an existing file unless you pass
`--force`. The `forbid_new_at_or_above` PR-delta rule is included as a commented
line with the exact `--baseline` workflow to enable it.
