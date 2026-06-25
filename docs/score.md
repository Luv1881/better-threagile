# `threagile score` — threat-model health score

Reduces the whole model to one trackable **0–100 score** (and an **A–F grade**) a
team can watch every sprint, gate on, and show as a badge. Deterministic, no AI.

```sh
threagile score --model threagile.yaml
threagile score --model threagile.yaml --format markdown --output score.md
threagile score --model threagile.yaml --format shields > badge.json
threagile score --model threagile.yaml --min 70        # fail CI (exit 3) below 70
```

## What it measures

The score blends two pure functions of the analyzed model:

**Completeness** (40%) — is the model trustworthy enough to believe its findings?

| Check | Asks |
|---|---|
| `owners` | do in-scope assets have an owner? |
| `trust_boundaries` | are in-scope assets placed inside a trust boundary? |
| `link_protocols` | do communication links declare a known protocol? |
| `data_assets_used` | is every data asset actually processed/stored/transmitted? |
| `metadata` | does the model carry a title and author? |

**Posture** (60%) — how much of the *identified* risk has actually been dealt with?
Every still-relevant finding is weighted by severity (Critical counts 8×, Low 1×)
and credited by its tracking status:

| Status | Credit |
|---|---:|
| mitigated / false-positive | 1.0 |
| accepted | 0.7 |
| in-progress | 0.5 |
| in-discussion | 0.3 |
| unchecked | 0.0 |

So an un-triaged Critical hurts far more than an un-triaged Low, and the fastest
way to raise the score is to mitigate (or consciously accept) the scary findings
— which is exactly the behaviour you want to incentivise.

`overall = round(100 × (0.4 × completeness + 0.6 × posture))`, graded
A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, else F.

### Guards against a misleadingly-high score

The score is designed so a number can't paper over a genuinely unsafe state:

- **Insufficient model → 0 (F).** A model with no in-scope technical assets has
  modelled nothing, so it scores 0 — an empty file can never look "perfect".
- **Un-triaged High/Critical → hard-capped at F.** If any High or Critical
  finding is still `unchecked` (nobody has even looked at it), the score is
  capped until it is reviewed, so mitigating many low-severity findings cannot
  mask a serious one.

Both situations are spelled out in a caveat line on every output, so the score
is never just a bare number. The score measures *the model you provide* — pair
it with the completeness sub-score, which is what makes under-modelling visible.

## Gating and badges

- `--min N` exits **3** (the gate exit code) when the score is below `N`, so a
  team can ratchet quality up over time without hand-writing a policy.
- `--format shields` emits a [shields.io endpoint](https://shields.io/endpoint)
  JSON document — commit it and point a badge at it:
  `https://img.shields.io/endpoint?url=<raw-url>/badge.json`.

## Example

The bundled demo model is fully modelled but largely un-triaged, so it scores in
the D band (high completeness, low posture). Triaging its findings — mitigating or
accepting them — moves it into the B/A band with no architecture change, which is
the trendline a sprint review wants to see.
