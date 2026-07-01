# better-threagile — Improvements over upstream Threagile

> Single consolidated record of everything `better-threagile` adds or fixes relative to
> upstream [Threagile](https://threagile.io). Last verified 2026-06-13 against the built
> binary (`threagile version 1.0.0`), 1535 race-clean tests, lint 0.
>
> For the original fork's detailed file-level diff see `docs/CHANGES.md`. This document is
> the canonical summary.

---

## TL;DR

Upstream Threagile is a STRIDE-only threat-model-as-code tool. `better-threagile` turns it
into a **multi-methodology, enterprise-grade platform**:

- **9 threat-modeling methodologies / rule packs** selectable at runtime (was: STRIDE only).
- **3 new enterprise workflows**: SARIF code-scanning output, FAIR Monte-Carlo risk
  quantification (`quantify`), and risk-acceptance expiry governance.
- **Real correctness fixes** in the analysis engine (data races, nondeterminism,
  false-positive rules, duplicate finding IDs) — upstream ships several of these bugs.
- **Production hardening** across 13 engineering phases: blocking lint, race-tested CI,
  coverage ratchet, fuzzing, dependency modernization, a hardened HTTP server, and a
  reproducible release pipeline.

---

## 1. Multi-methodology engine

The single biggest change. Upstream hard-codes STRIDE into every rule, report section, and
the model schema. This fork makes the methodology a **runtime parameter** — the *same* YAML
model is analyzed through any lens with `--methodology` / `--rule-pack`, no model edits.

| Methodology / pack | Focus | Rules | Selection |
|---|---|---|---|
| **STRIDE** (default) | Security across the six STRIDE categories | 62 built-in Go + embedded script rules | `--methodology stride` |
| **LINDDUN** | Privacy & data-protection threats | 8 | `--rule-pack linddun` |
| **PASTA** | Attack-centric, seven-stage decomposition | 9 | `--rule-pack pasta` |
| **VAST** | Operational & business-process risk | 8 | `--rule-pack vast` |
| **OCTAVE Allegro** | Information-asset-centric org risk | 8 | `--rule-pack octave` |
| **Trike** | Rights/actor-matrix based analysis | 8 | `--rule-pack trike` |
| **Cloud-Native** | IAM, object storage, managed DBs, serverless, containers, API gateways | 17 | `--rule-pack cloud-native` |
| **Supply-Chain** | SBOM, dependency scanning, provenance, signing, SAST (SLSA/CRA) | 10 | `--rule-pack supply-chain` |
| **AI/ML** | LLM inference, RAG, vector stores, prompt injection (MITRE ATLAS aligned) | 18 | `--rule-pack ai-ml` |

> Upstream had STRIDE only. OCTAVE and Trike were "planned" in early fork docs — both now
> ship complete 8-rule embedded packs.

**Architecture change:** rule packs are embedded as **YAML directories** via `//go:embed`
(`pkg/risks/methodologies/<name>/`). The old tarball-based loader was removed — editing a
rule no longer requires rebuilding a `.tar.gz`; just rebuild the binary. Run
`threagile rule-pack list` to see every pack with its description and rule count.

---

## 2. New enterprise workflows (v3)

These are net-new capabilities with no upstream equivalent.

### 2.1 SARIF 2.1.0 output — meet developers in the PR

Every analysis writes `risks.sarif` (configurable via `--risks-sarif`, disable with
`--skip-risks-sarif`). Upload it to GitHub/GitLab code scanning and risks appear as native
code-scanning alerts pointing at the model YAML.

- One SARIF *rule* per risk category (carries CWE, STRIDE classification, and a
  `security-severity` score for the forge's severity bucketing).
- One SARIF *result* per generated risk, with a stable `threagileSyntheticId` partial
  fingerprint (so the forge dedupes across runs).
- Risks tracked as **mitigated / false-positive / accepted** emit a SARIF `suppression`
  (justification carried from the tracking entry) so the forge hides them by default.

*Code:* `pkg/report/sarif.go`, golden- and structure-tested.

### 2.2 `threagile quantify` — FAIR Monte-Carlo risk quantification

Wires the (previously unwired) FAIR engine into the CLI. Provide a `--estimates` YAML mapping
**synthetic risk IDs** (exact) or **risk-category IDs** (all risks of that category) to
modified-PERT distributions for loss-event-frequency (events/yr) and loss-magnitude
(USD/event):

```yaml
default_iterations: 20000
estimates:
  exposed-default-credentials@minio-storage:        # exact synthetic ID
    loss_event_frequency: {min: 0.2, most_likely: 1.0, max: 4.0}
    loss_magnitude:       {min: 50000, most_likely: 250000, max: 1500000}
  unencrypted-communication:                         # whole category
    loss_event_frequency: {min: 0.05, most_likely: 0.2, max: 1.0}
    loss_magnitude:       {min: 20000, most_likely: 120000, max: 800000}
```

Output is a per-risk Annualized Loss Expectancy (ALE) table (p10/p50/p90) sorted by median,
plus a portfolio summary; `--output-json` writes the full result. Simulation is
**deterministic per risk** (RNG seeded from the synthetic ID), so results are reproducible
and diffable in CI.

*Code:* `pkg/risks/quant/quantify.go` + `internal/threagile/quantify.go`.

### 2.3 Risk-acceptance expiry — governance that doesn't rot

`risk_tracking` entries with `status: accepted` may now carry an expiry and an owner:

```yaml
risk_tracking:
  lateral-movement-shared-runtime@docker-host:
    status: accepted
    accepted_until: 2026-12-31
    accepted_by: VaultNote Security Team
    justification: single-host compose runtime; AWS/ECS deployment removes it
```

Once `accepted_until` passes, `analyze-model` and `validate` **fail** with a list of expired
acceptances — forcing re-review instead of letting acceptances silently linger forever
(the way threat models actually rot). `--ignore-expired-risk-acceptance` downgrades to a
warning; acceptances without an expiry get an info-level nudge; `accepted_until` on a
non-accepted status is a model error.

*Code:* `pkg/types/risk-tracking.go` (`IsAcceptanceExpired`), `Model.CheckAcceptanceExpiry`.

---

## 3. New & fixed risk rules

### 3.1 New fork-specific built-in rules

- **Lateral-movement family** (STRIDE-LM): credential reuse, service-account scope creep,
  shared-runtime, and transitive-access rules.
- `missing-csp-header`, `exposed-default-credentials` (STRIDE script rules).
- `pii-client-side-storage` (LINDDUN), `per-operation-rate-limiting-missing` (PASTA), and the
  full OCTAVE / Trike / cloud-native / supply-chain / AI-ML rule sets above.

### 3.2 Correctness fixes in the engine (upstream bugs)

| Fix | What was wrong upstream / in the fork's parallel path |
|---|---|
| **2 data races** in parallel risk generation | Rules sorted shared comm-link slices in place; results map written while script workers marshalled the model. Both fixed (copy-before-sort; collect-then-merge). |
| **4 map-iteration nondeterminism bugs** | Same model produced different risk count/order across runs (lateral-movement asset pick, markdown data-asset table, three `DataBreachTechnicalAssetIDs` sets, `AllRisks()`). All now sort. |
| **Wildcard risk-tracking silently ignored** | `rule-id@*` tracking statuses never reached generated risks (a one-shot status cache fired before wildcards were expanded). Statuses now apply at the end of `AnalyzeModel`, so reports/JSON/SARIF all agree. |
| **Duplicate synthetic IDs** | `push-instead-of-pull-deployment` keyed risks on the build pipeline only, colliding (and hiding a finding) when one pipeline deploys to many targets. ID now includes the target. |
| **SQL/NoSQL-injection false positive** | Fired on S3/object stores (no query surface). Now skips `IsFileStorage` assets. |
| **SSRF false positive** | Fired on reverse proxies (Nginx/Traefik) that route by static config. Now excludes traffic-forwarding assets. |
| **Container comm likelihood under-reported** | Container-to-container plaintext sniffing risk was rated as for physical networks; now elevated. |

Every fix landed with a regression test; report goldens lock the deterministic output.

### 3.3 Confidence scoring

Each risk now carries a `confidence` (0–1) score; findings sort by severity × confidence so
high-certainty findings rise to the top.

---

## 4. Model schema extensions

New YAML fields (ignored harmlessly by an upstream binary, used by fork rules):

- **Data assets:** `has_pii`, `pii_categories[]` (e.g. `password-hash`, `session-identifier`,
  `email`, `health-data`, `government-id`), `consent_required`, `cross_border`.
- **Technical assets:** `audit_logged`, `rate_limited`, plus AI/ML technology types
  (`llm-inference-endpoint`, `vector-store`, `rag-pipeline`, `ml-training-pipeline`,
  `embedding-service`) and cloud-native types (managed-database, object-storage,
  serverless-function, cloud-api-gateway, container-registry, container-platform).
- **New top-level sections:** `information_assets` (OCTAVE), `trike_actors` / `trike_matrix`,
  PASTA threat scenarios, VAST business processes.
- **Risk tracking:** `accepted_until`, `accepted_by` (§2.3).
- **Tags as feature flags:** presence suppresses the matching rule (e.g. `has-csp` suppresses
  `missing-csp-header`).

---

## 5. New / extended CLI commands

Beyond upstream's `analyze-model` / `server`, the fork adds (verified in `--help`):

`quantify` (FAIR ALE), `diff` & `drift` (risk-delta between model versions), `lint` &
`validate` & `fmt` (fast CI-safe model checks), `intel` (KEV/EPSS threat
feeds with TTL-cached fetch), `coverage`
(control-framework coverage), `rule-pack` (list/show/install packs), `test-rules` (golden
tests for script packs), `generate-ci` (pipeline scaffolding), `import` / `import-model`
(Terraform & OpenAPI importers), `init` & `create-*` (scaffolding), `lsp` (IDE language
server), and `completion`. Remote rule packs (`--rules-url`) — broken upstream — now work with
a 24 h-TTL, SHA256-keyed cache and optional Ed25519 signature verification.

---

## 6. Engineering & production hardening (Phases 0–13)

The fork was taken from a research prototype to a release-grade codebase:

- **Quality gates (blocking in CI):** `golangci-lint` at **0 issues**, `go vet` clean,
  `go test -race` (**1535 tests**, 30 packages), a **coverage ratchet** (floor 52%), and a
  fuzz smoke suite (model YAML + Terraform/OpenAPI importers + risk-DSL parser).
- **Determinism safety net:** golden/characterization tests for every report format
  (PDF smoke, AsciiDoc, Excel, Markdown, JSON, SARIF), which is how the races above were
  caught.
- **Dependency modernization:** archived `jung-kurt/gofpdf` → maintained `go-pdf/fpdf`;
  `go-chart` → v2; `mpvl/unique` removed; routine bumps; `go mod tidy` clean. (`gin`
  deliberately pinned at v1.10.0 to avoid the quic-go/mongo-driver surface.)
- **Performance:** script rules used to re-marshal the entire model to YAML *per rule*; now
  converted once and shared read-only across the parallel runner — **−68% time / −89%
  allocations** on the heaviest pack.
- **Server hardening:** explicit `http.Server` with read/write/idle timeouts, graceful
  shutdown, gin release mode, `SetTrustedProxies(nil)`, zip decompression-bomb limits, and
  auth-failure-path tests; `gosec` clean on `pkg/server`.
- **Release pipeline:** GoReleaser config (6 OS/arch binaries + multi-arch container image)
  behind a security-gate job; the `Dockerfile` builds *this* fork (upstream's cloned the
  wrong repo).
- **Docs reconciled** end-to-end against actual flags/commands after the methodology and
  pack-format changes.

---

## 7. VaultNote reference threat model

The companion `../Threat-model/` repository is a complete, deliberately-vulnerable
Node.js/Express note-taking app modeled across **all 9 methodologies** — the reference for the
whole platform. Verified 2026-06-13 with this binary:

| Methodology | Risks | High | Elevated | Medium | Low |
|---|---:|---:|---:|---:|---:|
| STRIDE | 67 | 2 | 21 | 38 | 6 |
| LINDDUN | 28 | 0 | 16 | 12 | 0 |
| PASTA | 12 | 0 | 11 | 0 | 1 |
| VAST | 10 | 0 | 10 | 0 | 0 |
| Cloud-Native | 83 | 2 | 35 | 40 | 6 |
| Supply-Chain | 79 | 2 | 30 | 41 | 6 |
| AI/ML | 75 | 2 | 29 | 38 | 6 |
| OCTAVE | 99 | 2 | 53 | 38 | 6 |
| Trike | 89 | 2 | 37 | 44 | 6 |

- **All findings triaged to 0 unchecked** in every methodology, via a single
  `feature_risk_review.yaml` (wildcard + direct tracking): in-progress items reference
  VAULT-* tickets, intentional misconfigurations are acceptances expiring 2026-12-31, and
  analytically-inapplicable detections are documented false-positives.
- **Every run emits a valid SARIF 2.1.0 file** (result count == risk count; suppressions
  applied for tracked findings).
- **FAIR quantification** (`fair-estimates.yaml`): portfolio **median ALE ≈ $787k/yr**,
  dominated by `exposed-default-credentials@minio-storage` (≈ $450k/yr median) — quantitatively
  confirming the model's qualitative "critical launch blocker" call.

---

## 8. Compatibility notes

- **No LLM dependency.** All conclusions come from static analysis of developer-authored YAML
  rules — the speculative `llm` command tree was removed by design.
- **Upstream model compatibility:** existing Threagile models analyze unchanged; new fields
  are additive.
- **CLI flag ordering:** root persistent flags (e.g. `--model`,
  `--ignore-orphaned-risk-tracking`) may now appear in any position relative to
  command-local flags. (Previously a `pflag` quirk required them to come first;
  the flag-extraction pass now whitelists unknown flags so later root flags are
  no longer dropped.)

---

*Owner decisions on record: no LLM features (static analysis only); upstream mergeability is
a non-goal (refactor/delete freely).*
