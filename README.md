# better-threagile

[![Threagile Community Chat](https://badges.gitter.im/Threagile/community.svg)](https://gitter.im/Threagile/community)

## Agile Threat Modeling Toolkit — Multi-Methodology Fork

`better-threagile` is an enhanced fork of [Threagile](https://threagile.io) that turns the
original STRIDE-only engine into a multi-methodology, enterprise-grade threat-model-as-code
platform. The **same YAML model** can be analyzed through nine different methodologies, scored
with a deterministic 0-100 health score, exported as SARIF for code scanning, governed with
expiring risk acceptances, gated in CI against a declarative policy, mapped to MITRE ATT&CK,
queried for attack paths to your crown-jewel data, generated from your real infrastructure
(Terraform / OpenAPI / Kubernetes / docker-compose), and correlated against live KEV/EPSS
threat intel — without any model changes.

> **What's different from upstream, in one page:** see **[IMPROVEMENTS.md](./IMPROVEMENTS.md)**.
> For the detailed file-level history see [`docs/CHANGES.md`](./docs/CHANGES.md).

### Highlights over upstream Threagile

| Area | Upstream Threagile | better-threagile |
|---|---|---|
| Methodologies | STRIDE only | STRIDE · LINDDUN · PASTA · VAST · OCTAVE · Trike · Cloud-Native · Supply-Chain · AI/ML |
| Rule packs | Built-in Go rules | Built-in Go + 8 embedded YAML packs (`//go:embed` directories) |
| Zero-config onboarding | — | `bootstrap` — scan a repo (compose / k8s / OpenAPI) → starter model + secure-by-default policy + git hooks in one command |
| Local guardrails | — | `hooks install` — git pre-commit (validate+lint) / pre-push (gate) so problems surface before CI |
| Secure-by-default policy | — | `policy init --profile prototype\|balanced\|strict\|regulated` — tuned starter gate, no security expert needed |
| Health score | — | `score` — one 0–100 / A–F number (completeness + risk posture) to track each sprint; `--min` gate, `--format shields` badge |
| Sprint / PR scorecard | — | `summary` — one-pass scorecard (health score + top fixes) for a sprint review or PR comment |
| Prioritization | — | `prioritize` — "fix these first, here's how": ranks findings by exploitability (severity × exposure × reachability × data) with remediation + CWE + cheat sheet |
| Security backlog | — | `requirements` — turns still-at-risk findings into a deduplicated security-requirements backlog / test cases (Markdown checklist, Gherkin, or JSON) |
| Secret hygiene | — | `validate` scans the model for committed credentials (`--fail-on-secrets`) |
| CI / code-scanning output | — | SARIF 2.1.0 (`risks.sarif`) for GitHub, GitLab SAST report (`risks.gl-sast.json`) for the GitLab MR security widget; suppressions from tracking status |
| Policy-as-code gate | — | `gate` — declarative `policy.yaml`, exits 3 on violation (severity caps, require-tracking, expired-acceptance, no-new-vs-baseline, framework coverage, unreviewed-import elements) |
| Human-in-the-loop review | — | `review` — lists every element still tagged `review-<importer>`/`stub-data-asset` after a diagram import (`--format json\|markdown`), plus `--fail-on-unreviewed`/gate's `fail_on_unreviewed: true` to block merging an unreviewed import |
| PR-bot / risk delta / drift gate | — | `diff --format markdown` (added/removed/changed vs. any baseline model) + `generate-ci gate-pr` — posts the risk delta / gate report as a PR comment; `--fail-on-new-high`/`--fail-on-new-critical` turn it into a CI drift gate |
| Attack-path analysis | — | `paths` — shortest routes from internet-facing assets to crown-jewel data |
| Architecture importers | — | `import terraform \| openapi \| kubernetes \| compose` → analyzable model fragments |
| Diagram → model (no AI) | — | `import threat-dragon` (OWASP Threat Dragon JSON), `import drawio` (mxGraph), `import otm` (Open Threat Model JSON) and `import mermaid` (flowchart/graph) — deterministic diagram-to-YAML conversion |
| Editable scaffold output | — | `--scaffold` (default on for diagram importers) annotates every heuristically inferred field with a `# TODO(review): …` comment plus a file-header legend, so the emitted YAML reads as a template to finish, not a dump |
| Diagram nomenclature mapping | — | `--mapping rules.yaml` — ordered label/color/line-style regex rules so teams encode internal naming ("MinIO"→object storage) and diagram color conventions (red dashed edge→unencrypted) into asset type/technology/encryption/tags |
| Data-asset stubs | — | `--stub-data-assets` (default on) — diagrams rarely show data; generates conservative, review-tagged stub data assets for datastores and internet-inbound links so imported models actually produce risks |
| Model → diagram (no Graphviz) | Graphviz PNG only | `mermaid` — GitHub/GitLab-renderable data-flow flowchart (trust boundaries, shaped nodes, encrypted/cleartext edges, risk colouring) for PRs/READMEs/CI |
| SBOM + threat intel | KEV/EPSS reference data | `sbom` — correlate a CycloneDX SBOM's CVEs with KEV/EPSS, VEX-aware, `--fail-on-kev` gate |
| Risk governance | Tracking status only | `accepted_until` / `accepted_by` — analysis fails on expired acceptances |
| Remote rule packs | `--rules-url` (broken upstream) | Fixed — 24 h TTL cache, SHA256-keyed, optional Ed25519 signatures |
| Correctness | Ships injection/SSRF false positives | Fixed; plus data-race, nondeterminism & duplicate-ID fixes in the engine |
| Engineering | Prototype | Blocking lint (0 issues), 1790+ race-tested cases, coverage ratchet, fuzzing, hardened server, GoReleaser pipeline; analysis hot path ~67% fewer allocations |

---

## Get guarded in one minute

`better-threagile` is built to drop into an existing repo with near-zero friction —
no security expert, no blank page, no separate dashboard:

```shell
# 1. Scan the repo and scaffold a model + secure-by-default policy + git hooks
./bin/threagile bootstrap --with-hooks

# 2. See where you stand (one number you can track each sprint)
./bin/threagile score --model threagile.yaml

# 3. Find the few things that matter and how to fix them
./bin/threagile prioritize --model threagile.yaml --top 5

# 4. Enforce it in CI (exit 3 on violation) and in pull requests
./bin/threagile gate --model threagile.yaml --policy policy.yaml
./bin/threagile generate-ci --model threagile.yaml --target gate-pr
```

From there, `validate` catches committed secrets, `mermaid` renders the data-flow
diagram in your README, `summary` produces a one-line sprint/PR scorecard,
`requirements` turns the findings into a security backlog, and
`diff old new --format markdown` posts a PR comment that says exactly what a
change introduced and how to fix it.

`score`, `summary`, and `prioritize` all read the same analysis pass, so they
aren't three overlapping reports — `summary` is the umbrella one-pass scorecard
(health score + top findings in a single document, ideal for a sprint review or
PR comment), and `score` and `prioritize` are its two focused entry points:
`score` is the single gate/badge number (`--min` to fail CI, `--format shields`
for a README badge), and `prioritize` is the drill-down worklist (`--top`,
`--min-severity`) for actually working through the backlog.

## Building from source

```shell
git clone <this-repo>
cd better-threagile
go build -o bin/threagile ./cmd/threagile/
./bin/threagile --version          # threagile version 1.0.0
```

Requires **Go 1.26+** (see `go.mod`). The binary embeds all rule packs and report templates —
no Docker needed for analysis. Editing a rule under `pkg/risks/methodologies/<pack>/` only
requires a rebuild; the packs are embedded **directories** (`//go:embed`), not tarballs.

---

## Supported methodologies and rule packs

| Pack | Methodology | Rules | Focus |
|---|---|---:|---|
| `stride` (default) | stride | 62¹ | Security across the six STRIDE categories |
| `linddun` | linddun | 8 | Privacy / data-protection threats |
| `pasta` | pasta | 9 | Attack-centric, seven-stage decomposition |
| `vast` | vast | 8 | Operational & business-process risk |
| `octave` | octave | 8 | Information-asset-centric org risk |
| `trike` | trike | 8 | Rights / actor-matrix analysis |
| `cloud-native` | stride | 17 | IAM, object storage, managed DBs, serverless, containers, API gateways |
| `supply-chain` | stride | 10 | SBOM, dependency scanning, provenance, signing, SAST (SLSA/CRA) |
| `ai-ml` | stride | 18 | LLM inference, RAG, vector stores, prompt injection (MITRE ATLAS) |

¹ Combined built-in Go rules + embedded STRIDE script rules reported by `list-risk-rules`.

```shell
./bin/threagile rule-pack list            # every pack, with description + rule count
./bin/threagile rule-pack show linddun    # details for one pack
./bin/threagile list-methodologies        # methodology ↔ rule coverage matrix
```

---

## Enterprise workflows

```shell
# SARIF is written on every analyze-model run as output/risks.sarif.
# Upload it in a GitHub Action for native code-scanning alerts:
#   - uses: github/codeql-action/upload-sarif@v3
#     with: { sarif_file: output/risks.sarif }

# Risk-acceptance expiry: an accepted risk with a past accepted_until date fails analysis.
# Downgrade to a warning with:
./bin/threagile analyze-model --model model.yaml --ignore-expired-risk-acceptance
```

See [IMPROVEMENTS.md §2](./IMPROVEMENTS.md#2-new-enterprise-workflows-v3) for the estimates and
tracking YAML formats.

### CI-native security workflows

These commands are built to run in a pipeline — they write machine-readable output to **stdout**
(pipe with `>` or `--format json`) and drive CI via the exit code.

```shell
# Policy-as-code gate — fails the build (exit 3) when the model violates policy.yaml.
./bin/threagile gate --model model.yaml --policy policy.yaml          # docs/gate.md

# "No new High vs the approved baseline" (generate the baseline from main's risks.json):
./bin/threagile gate --model model.yaml --policy policy.yaml --baseline baseline/risks.json

# One-pass sprint / PR scorecard (health score + the top fixes), and a security backlog:
./bin/threagile summary      --model model.yaml --format markdown > scorecard.md   # docs/summary.md
./bin/threagile requirements --model model.yaml --format markdown > backlog.md      # docs/requirements.md

# Risk delta as a PR comment (Markdown), or scaffold a ready-made GitHub Actions workflow:
./bin/threagile diff old.yaml new.yaml --format markdown > delta.md
./bin/threagile generate-ci --model model.yaml --target gate-pr --policy-path policy.yaml

# Drift gate: fail CI if the current model introduces new High/Critical findings vs. an approved baseline:
./bin/threagile diff baseline.yaml model.yaml --fail-on-new-high

# Attack paths to crown-jewel data:
./bin/threagile paths --model model.yaml   # docs/attack-paths.md

# SBOM + threat intel: rank a CycloneDX SBOM's CVEs by KEV/EPSS; gate on KEV.
./bin/threagile sbom --sbom sbom.cdx.json --refresh-kev --epss --fail-on-kev   # docs/sbom.md

# Mermaid data-flow diagram (renders natively in GitHub/GitLab Markdown, no Graphviz):
./bin/threagile mermaid --model model.yaml --format markdown > diagram.md  # docs/mermaid.md
```

### Importing architecture from real infrastructure

Generate an analyzable model fragment from existing infrastructure-as-code, then review/merge it:

```shell
terraform show -json | ./bin/threagile import terraform                 # Terraform
./bin/threagile import openapi    --spec api.yaml                        # OpenAPI 3.x
./bin/threagile import kubernetes --manifests <(kubectl get all,ingress,secret,pvc -A -o yaml)
./bin/threagile import compose    --compose docker-compose.yml          # docker-compose
./bin/threagile import threat-dragon --tdmodel model.json               # OWASP Threat Dragon diagram
./bin/threagile import drawio        --diagram architecture.drawio      # draw.io / diagrams.net (best-effort)
./bin/threagile import otm           --file model.otm.json              # Open Threat Model (IriusRisk et al.)
./bin/threagile import mermaid       --diagram architecture.mmd         # Mermaid flowchart/graph (best-effort)

# Editable scaffold + team nomenclature + data-asset stubs (diagram importers only):
./bin/threagile import drawio --diagram architecture.drawio \
  --mapping mappings.yaml --stub-data-assets --scaffold --output model-fragment.yaml

# Review every element an importer flagged for manual confirmation:
./bin/threagile review --model model-fragment.yaml --format markdown
```

The four **diagram** importers are deterministic, no-AI conversions: Threat
Dragon JSON and OTM are threat-model-native interchange formats (high
fidelity); draw.io and Mermaid are generic diagram formats (lossy best-effort
— assets are tagged `review-drawio`/`review-mermaid`). All four default to
**scaffold output** (`--scaffold=false` for a plain fragment): every
heuristically inferred field gets a `# TODO(review): …` comment, and a header
block explains what to check before trusting the model. `--mapping
<rules.yaml>` lets a team encode its own box-label nomenclature and diagram
color/line-style conventions (see `docs/import-mapping.md`);
`--stub-data-assets` (default on) fills in the data assets diagrams never
draw, since a model with technical assets but no data assets on its links
analyzes to near-zero risk. Run `threagile review` afterwards (see
[docs/review.md](./docs/review.md)) to list every element still carrying a
`review-<importer>`/`stub-data-asset` tag before trusting the model — the gate
policy key `fail_on_unreviewed: true` can block merging until it's clean.
When the diagram is later redrawn, `--merge <model.yaml>` reconciles the
re-import onto your reviewed model instead of overwriting it — confirmed
fields are never clobbered; disagreements get a `merge-conflict:<field>` tag
(see [docs/import-merge.md](./docs/import-merge.md)). For large diagrams,
`--boundary <name>` (drawio/mermaid) imports one trust boundary's subsystem
at a time, and `--page` (drawio) selects a single page of a multi-page file.
See [docs/import-threat-dragon.md](./docs/import-threat-dragon.md),
[docs/import-drawio.md](./docs/import-drawio.md),
[docs/import-otm.md](./docs/import-otm.md),
[docs/import-mermaid.md](./docs/import-mermaid.md), or the end-to-end
walkthrough in
[docs/cookbook-diagram-to-model.md](./docs/cookbook-diagram-to-model.md).

All four importers emit the authoring YAML format and round-trip through `analyze-model`
(workloads/services → technical assets, namespaces/networks → trust boundaries, published ports
→ internet exposure, secrets → data assets, depends_on/selectors → communication links). See
[docs/import-kubernetes.md](./docs/import-kubernetes.md) and
[docs/import-compose.md](./docs/import-compose.md).

---

## Running the VaultNote reference threat model

The `../Threat-model/` directory contains a complete multi-layer threat model for
**VaultNote** — a deliberately-misconfigured Node.js/Express note-taking application — modeled
across **all nine methodologies** and fully triaged (0 unchecked findings).

### Prerequisites

- `better-threagile` binary built at `bin/threagile` (see above)
- `graphviz` installed for diagram rendering (`dot` command)

```shell
which dot || sudo pacman -S graphviz   # Arch
# or: sudo apt install graphviz        # Debian/Ubuntu
```

### Run all nine methodologies

Run from the **repo root** (`better-threagile/`). Output goes to separate subdirectories.
`--ignore-orphaned-risk-tracking` is required because the model annotates `risk_tracking`
entries for all methodologies at once, so each single-methodology run sees the others'
entries as orphans (a warning, not a real finding).

```shell
B=./bin/threagile
M=../Threat-model/threagile/threagile.yaml
OUT=../Threat-model/threagile/output

# STRIDE (default) — full report with PDF + diagrams
$B analyze-model --app-dir . --background pkg/report/template/background.pdf \
  --model "$M" --ignore-orphaned-risk-tracking --output "$OUT/stride" --methodology stride

# Embedded packs (add --rule-pack; methodology packs also take --methodology)
$B analyze-model --app-dir . --model "$M" --ignore-orphaned-risk-tracking \
  --output "$OUT/linddun" --methodology linddun --rule-pack linddun
$B analyze-model --app-dir . --model "$M" --ignore-orphaned-risk-tracking \
  --output "$OUT/pasta"   --methodology pasta   --rule-pack pasta
$B analyze-model --app-dir . --model "$M" --ignore-orphaned-risk-tracking \
  --output "$OUT/vast"    --methodology vast    --rule-pack vast

# Cross-cutting packs (run under the default STRIDE methodology)
for P in cloud-native supply-chain ai-ml octave trike; do
  $B analyze-model --model "$M" --ignore-orphaned-risk-tracking \
    --output "$OUT/$P" --rule-pack "$P"
done
```

### Outputs per run

Each directory receives `report.pdf`, `risks.json`, **`risks.sarif`**, **`risks.gl-sast.json`**
(GitLab SAST report), `risks.xlsx`,
`tags.xlsx`, `technical-assets.json`, `stats.json`, the two diagram PNGs, and `adocReport/`
(raw AsciiDoc). Diagrams/PDF can be skipped with `--skip-report-pdf --skip-report-adoc
--skip-data-flow-diagram --skip-data-asset-diagram` for fast JSON/SARIF-only runs.

### Verified risk counts (VaultNote, 2026-06-13)

| Methodology | Risks | High | Elevated | Status |
|---|---:|---:|---:|---|
| STRIDE | 67 | 2 | 21 | 0 unchecked |
| LINDDUN | 28 | 0 | 16 | 0 unchecked |
| PASTA | 12 | 0 | 11 | 0 unchecked |
| VAST | 10 | 0 | 10 | 0 unchecked |
| Cloud-Native | 83 | 2 | 35 | 0 unchecked |
| Supply-Chain | 79 | 2 | 30 | 0 unchecked |
| AI/ML | 75 | 2 | 29 | 0 unchecked |
| OCTAVE | 99 | 2 | 53 | 0 unchecked |
| Trike | 89 | 2 | 37 | 0 unchecked |

All findings are triaged in `../Threat-model/threagile/feature_risk_review.yaml` (in-progress
items reference VAULT-* tickets; intentional misconfigurations are acceptances expiring
2026-12-31; analytically-inapplicable detections are documented false-positives). FAIR
quantification (`fair-estimates.yaml`) puts the portfolio median ALE at ≈ $787k/yr.

The reference model also exercises the CI-native workflows and importers end-to-end —
see `../Threat-model/threagile/`: `gate-policy.yaml` (gate PASSes; tightening fails exit-3),
`imports/vaultnote-attack-paths.txt` (internet → `postgresql-db` / `minio` paths),
`imports/vaultnote-sbom.cdx.json` (SBOM correlation with live EPSS), and the
Kubernetes/docker-compose imports of the stack (`imports/vaultnote-k8s.yaml`, generated from
the real `docker-compose.yml`).

### Continuous threat modeling in CI → GitHub Issues

The VaultNote repo's `.github/workflows/threat-model.yml` (branch `ci-pipeline`) runs the
fork on every security-relevant change: it builds the binary, installs Graphviz, runs
`analyze-model` (with `--app-dir . --background pkg/report/template/background.pdf`), diffs the
risks against the committed baseline to post a PR comment, and on `push`/`workflow_dispatch`
syncs each still-at-risk finding to a **GitHub Issue** (`scripts/create-tickets.py`) with
CVSS / CISA-KEV / EPSS / RAA severity scoring. Issues are keyed by a `threagile:<synthetic-id>`
label; because GitHub caps label names at 50 chars, long chained synthetic IDs are truncated
with a short content hash so the sync stays idempotent (create / reopen / close as findings
come and go).

---

## Writing custom rules

Custom risk rules can be written as YAML scripts without compiling Go. See the
[script language reference](./docs/scripts/language-reference.md), the
[guide for writing custom risk rules](./docs/scripts/guide.md), and
[how to test your scripts](./docs/scripts/testing.md).

Place new built-in script rules under `pkg/risks/scripts/` (embedded via
`//go:embed scripts/*.yaml`). Place methodology-specific rules in the matching
`pkg/risks/methodologies/<pack>/` directory and rebuild the binary — no tarball step.

---

## Execution via Docker

```shell
docker build -t better-threagile -f Dockerfile .
docker run --rm -it better-threagile --help
```

The included `Dockerfile` builds **this fork** (`./cmd/threagile` + `./cmd/risk_demo`) and runs
the test suite in-image. (Upstream's Dockerfile cloned the upstream repo — fixed here.)

---

## Model schema and tooling

- Full model field reference: [docs/model.md](./docs/model.md)
- CLI command reference: [docs/commands.md](./docs/commands.md)
- All CLI flags: [docs/flags.md](./docs/flags.md)
- Methodologies & rule packs: [docs/methodologies.md](./docs/methodologies.md)
- Onboarding: [docs/bootstrap.md](./docs/bootstrap.md) · Git hooks: [docs/hooks.md](./docs/hooks.md) · Score: [docs/score.md](./docs/score.md) · Summary: [docs/summary.md](./docs/summary.md) · Prioritize: [docs/prioritize.md](./docs/prioritize.md) · Requirements: [docs/requirements.md](./docs/requirements.md)
- Policy gate: [docs/gate.md](./docs/gate.md) · Attack paths: [docs/attack-paths.md](./docs/attack-paths.md) · SBOM: [docs/sbom.md](./docs/sbom.md) · Mermaid diagram: [docs/mermaid.md](./docs/mermaid.md)
- CI exit codes: [docs/exit-codes.md](./docs/exit-codes.md)
- Importers: [Kubernetes](./docs/import-kubernetes.md) · [docker-compose](./docs/import-compose.md) · Cookbook: [diagram → model in 10 minutes](./docs/cookbook-diagram-to-model.md)
- JSON Schema for IDE validation: `support/schema.json`
- OpenAPI spec (server mode): `support/openapi.yaml`

## Releases

Release history and process: [docs/releases.md](./docs/releases.md).

## Contribution

Contributions welcome — see the [contribution guide](./CONTRIBUTING.md), or open a GitHub
discussion or issue.
