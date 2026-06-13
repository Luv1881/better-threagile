# better-threagile

[![Threagile Community Chat](https://badges.gitter.im/Threagile/community.svg)](https://gitter.im/Threagile/community)

## Agile Threat Modeling Toolkit — Multi-Methodology Fork

`better-threagile` is an enhanced fork of [Threagile](https://threagile.io) that turns the
original STRIDE-only engine into a multi-methodology, enterprise-grade threat-model-as-code
platform. The **same YAML model** can be analyzed through nine different methodologies, scored
with FAIR Monte-Carlo loss estimates, exported as SARIF for code scanning, and governed with
expiring risk acceptances — without any model changes.

> **What's different from upstream, in one page:** see **[IMPROVEMENTS.md](./IMPROVEMENTS.md)**.
> For the detailed file-level history see [`docs/CHANGES.md`](./docs/CHANGES.md),
> [`IMPROVEMENT_PLAN.md`](./IMPROVEMENT_PLAN.md), and [`HANDOVER.md`](./HANDOVER.md).

### Highlights over upstream Threagile

| Area | Upstream Threagile | better-threagile |
|---|---|---|
| Methodologies | STRIDE only | STRIDE · LINDDUN · PASTA · VAST · OCTAVE · Trike · Cloud-Native · Supply-Chain · AI/ML |
| Rule packs | Built-in Go rules | Built-in Go + 8 embedded YAML packs (`//go:embed` directories) |
| Risk quantification | — | `quantify` — FAIR Monte-Carlo ALE (p10/p50/p90) + portfolio summary |
| CI / code-scanning output | — | SARIF 2.1.0 (`risks.sarif`), suppressions from tracking status |
| Risk governance | Tracking status only | `accepted_until` / `accepted_by` — analysis fails on expired acceptances |
| Remote rule packs | `--rules-url` (broken upstream) | Fixed — 24 h TTL cache, SHA256-keyed, optional Ed25519 signatures |
| Correctness | Ships injection/SSRF false positives | Fixed; plus data-race, nondeterminism & duplicate-ID fixes in the engine |
| Engineering | Prototype | Blocking lint (0 issues), 1535 race-tested cases, coverage ratchet, fuzzing, hardened server, GoReleaser pipeline |

---

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
# FAIR Monte-Carlo risk quantification (estimates keyed by synthetic-ID or category-ID).
# NOTE: root flags (--model, --ignore-orphaned-risk-tracking) must come BEFORE --estimates.
./bin/threagile quantify \
  --model model.yaml --ignore-orphaned-risk-tracking \
  --estimates fair-estimates.yaml --output-json output/quantify.json

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
$B analyze-model --app-dir . --background report/template/background.pdf \
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

Each directory receives `report.pdf`, `risks.json`, **`risks.sarif`**, `risks.xlsx`,
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
- JSON Schema for IDE validation: `support/schema.json`
- OpenAPI spec (server mode): `support/openapi.yaml`

## Releases

Release history and process: [docs/releases.md](./docs/releases.md).

## Contribution

Contributions welcome — see the [contribution guide](./CONTRIBUTING.md), or open a GitHub
discussion or issue.
