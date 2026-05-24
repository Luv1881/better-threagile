# better-threagile

[![Threagile Community Chat](https://badges.gitter.im/Threagile/community.svg)](https://gitter.im/Threagile/community)

## Agile Threat Modeling Toolkit — Multi-Methodology Fork

`better-threagile` is an enhanced fork of [Threagile](https://threagile.io) that extends the original STRIDE-only engine with support for multiple threat modeling methodologies selectable at runtime. The same YAML model can be analyzed through different lenses without any model changes.

### What's different from upstream Threagile

| Feature | Upstream Threagile | better-threagile |
|---|---|---|
| Methodologies | STRIDE only | STRIDE · LINDDUN · PASTA · VAST · OCTAVE · Trike |
| Rule packs | Built-in Go rules | Built-in Go + embedded YAML packs (LINDDUN/PASTA/VAST) |
| Remote rule packs | `--rules-url` (broken upstream) | Fixed — 24 h TTL cache, SHA256-keyed |
| False positives fixed | — | S3/file-store SQL injection; reverse-proxy SSRF |
| Container likelihood | Same as physical | Elevated — container-to-container sniffing risk |
| New built-in rules | — | `missing-csp-header`, `exposed-default-credentials` |
| New LINDDUN rules | — | `pii-client-side-storage` |
| New PASTA rules | — | `per-operation-rate-limiting-missing` |
| Model features | Core YAML | `pii_categories`, `has_pii`, `rate_limited`, `audit_logged`, `cross_border`, LINDDUN/PASTA/VAST fields |

---

## Building from source

```shell
git clone <this-repo>
cd better-threagile
go build -o bin/threagile ./cmd/threagile/
./bin/threagile --version
```

Requires Go 1.22+. The binary embeds all rule packs and report templates — no Docker needed for analysis.

### Rebuilding rule packs after editing YAML rules

The LINDDUN, PASTA, and VAST rule sets ship as embedded tarballs. After editing any `.yaml` file under `pkg/risks/methodologies/`, rebuild the affected pack before compiling:

```shell
# From the repo root
cd pkg/risks/methodologies
tar -czf linddun.tar.gz linddun/   # after editing linddun rules
tar -czf pasta.tar.gz   pasta/     # after editing pasta rules
tar -czf vast.tar.gz    vast/      # after editing vast rules
cd ../../..
go build -o bin/threagile ./cmd/threagile/
```

---

## Supported methodologies and rule packs

| Flag value | Rules | Pack source |
|---|---|---|
| `stride` (default) | ~40 built-in Go rules | Embedded in binary |
| `linddun` | 9 rules | `pkg/risks/methodologies/linddun.tar.gz` |
| `pasta` | 10 rules | `pkg/risks/methodologies/pasta.tar.gz` |
| `vast` | 8 rules | `pkg/risks/methodologies/vast.tar.gz` |
| `octave` | 0 (planned) | — |
| `trike` | 0 (planned) | — |

Use `bin/threagile rule-pack list` to list all available packs at runtime.

---

## Running the VaultNote threat model (Threat-model demo)

The `../Threat-model/` directory contains a complete multi-layer threat model for **VaultNote** — a deliberately-misconfigured Node.js/Express note-taking application. The model is split into feature files and annotated for all four active methodologies.

### Prerequisites

- `better-threagile` binary built at `bin/threagile` (see above)
- `graphviz` installed for diagram rendering (`dot` command)

```shell
which dot || sudo pacman -S graphviz   # Arch
# or: sudo apt install graphviz        # Debian/Ubuntu
```

### Repository layout

```
Threat-model/threagile/
├── threagile.yaml                  # entry point — includes all feature files
├── meta.yaml                       # title, author, business criticality
├── overview.yaml                   # management summary
├── tags.yaml                       # tag registry
├── feature_frontend.yaml           # Browser SPA + Nginx | Internet / DMZ
├── feature_api.yaml                # Node.js/Express API | App Network | auth data
├── feature_datastores.yaml         # PostgreSQL + Redis + MinIO | Data Tier | Docker runtime
├── feature_threats.yaml            # PASTA threat scenarios
├── feature_business_processes.yaml # VAST business processes
└── output/
    ├── stride/                     # STRIDE analysis outputs
    ├── linddun/                    # LINDDUN privacy analysis outputs
    ├── pasta/                      # PASTA attack-surface analysis outputs
    └── vast/                       # VAST operational analysis outputs
```

### Run all four methodologies

Run each command from the **repo root** (`better-threagile/`). Output goes into separate subdirectories so runs don't overwrite each other.

```shell
THREAGILE=./bin/threagile
MODEL=../Threat-model/threagile/threagile.yaml
APP=.

# ── STRIDE (default — 40+ built-in rules) ────────────────────────────────────
$THREAGILE analyze-model \
  --app-dir "$APP" \
  --background "report/template/background.pdf" \
  --reportLogoImagePath "report/threagile-logo.png" \
  --model "$MODEL" \
  --output ../Threat-model/threagile/output/stride \
  --methodology stride \
  --ignore-orphaned-risk-tracking

# ── LINDDUN (privacy — 9 rules) ───────────────────────────────────────────────
$THREAGILE analyze-model \
  --app-dir "$APP" \
  --background "report/template/background.pdf" \
  --reportLogoImagePath "report/threagile-logo.png" \
  --model "$MODEL" \
  --output ../Threat-model/threagile/output/linddun \
  --methodology linddun \
  --rule-pack linddun \
  --ignore-orphaned-risk-tracking

# ── PASTA (attack-centric — 10 rules) ────────────────────────────────────────
$THREAGILE analyze-model \
  --app-dir "$APP" \
  --background "report/template/background.pdf" \
  --reportLogoImagePath "report/threagile-logo.png" \
  --model "$MODEL" \
  --output ../Threat-model/threagile/output/pasta \
  --methodology pasta \
  --rule-pack pasta \
  --ignore-orphaned-risk-tracking

# ── VAST (operational — 8 rules) ──────────────────────────────────────────────
$THREAGILE analyze-model \
  --app-dir "$APP" \
  --background "report/template/background.pdf" \
  --reportLogoImagePath "report/threagile-logo.png" \
  --model "$MODEL" \
  --output ../Threat-model/threagile/output/vast \
  --methodology vast \
  --rule-pack vast \
  --ignore-orphaned-risk-tracking
```

> **`--ignore-orphaned-risk-tracking`** is required because the model annotates `risk_tracking` entries for all four methodologies simultaneously. Each single-methodology run only evaluates its own rule set, so the other methodologies' tracking entries appear as orphans. The flag downgrades these to warnings instead of errors.

### Expected output per run

Each methodology directory receives:

| File | Description |
|---|---|
| `report.pdf` | Full threat model report (AsciiDoc → PDF) |
| `risks.json` | Machine-readable risk register |
| `risks.xlsx` | Risk register as spreadsheet |
| `data-flow-diagram.png` | Architecture data-flow diagram |
| `data-asset-diagram.png` | Data asset diagram |
| `technical-assets.json` | All technical assets with computed RAA scores |
| `stats.json` | Summary statistics |
| `tags.xlsx` | Tag usage matrix |
| `adocReport/` | Raw AsciiDoc source for the report |

### Expected risk counts (VaultNote)

| Methodology | Risks | Focus areas |
|---|---|---|
| STRIDE | 35 | Crypto gaps, injection, missing hardening, default credentials, missing CSP |
| LINDDUN | 12 | PII on unencrypted links, no audit logging, no consent management, browser-side PII storage |
| PASTA | 5 | Missing SAST, no rate limiting (global + per-operation) |
| VAST | 11 | No redundancy, shared runtime, secrets in env vars, no monitoring |

### Risk tracking tags in the model

The model uses `risk_tracking` entries with the following suppression tags:

| Tag on asset | Suppresses rule |
|---|---|
| `has-csp` | `missing-csp-header` |
| `has-httponly-session` | `pii-client-side-storage` |

Add these tags to a technical asset once the corresponding control is verified in production.

### Listing available rule packs

```shell
./bin/threagile rule-pack list
./bin/threagile rule-pack describe linddun
./bin/threagile rule-pack describe pasta
./bin/threagile rule-pack describe vast
```

---

## Execution via Docker Container

The easiest way to execute the **upstream** Threagile on the command line is via its Docker container:

```shell
docker run --rm -it threagile/threagile --help
```

> Note: the Docker image is from upstream Threagile and does not include the multi-methodology extensions in this fork. Use the locally built binary for full functionality.

## Writing custom rules

Custom risk rules can be written as YAML scripts without compiling Go code. See the [script language reference](./docs/scripts/language-reference.md), the [guide for writing custom risk rules](./docs/scripts/guide.md), and how to [test your scripts](./docs/scripts/testing.md).

Place new built-in script rules under `pkg/risks/scripts/`. They are embedded into the binary via `//go:embed scripts/*.yaml` and loaded automatically on every run.

Place methodology-specific rules in the appropriate subdirectory under `pkg/risks/methodologies/`, then rebuild the methodology tarball and binary (see [Rebuilding rule packs](#rebuilding-rule-packs-after-editing-yaml-rules) above).

## Model schema and tooling

- Full model field reference: [docs/model.md](./docs/model.md)
- CLI command reference: [docs/commands.md](./docs/commands.md)
- All CLI flags: [docs/flags.md](./docs/flags.md)
- JSON Schema for IDE validation: `support/schema.json`
- OpenAPI spec (server mode): `support/openapi.yaml`

## Releases

Release history: [docs/releases.md](./docs/releases.md)

## Contribution

You are very welcome to contribute. If you'd like to add a new feature or fix a bug, please follow the [contribution guide](./CONTRIBUTING.md). Otherwise create a GitHub discussion or issue.
