# Plan v2: Toward the Most Accurate & Complete Threat-Model-as-Code Platform

## Where we are today (baseline)

The original plan (now in git history) has landed end-to-end:

- **Four working methodologies** — STRIDE (40+ built-in Go rules + YAML scripts), LINDDUN (9 YAML rules), PASTA (10 YAML rules), VAST (8 YAML rules), selected at runtime via `--methodology`.
- **Rule-pack tarball system** — `pkg/risks/methodologies/{linddun,pasta,vast}.tar.gz` embedded via `//go:embed`; loaded into a temp dir on demand. Same shape works for remote `--rules-url` packs with 24h cache + SHA256 pinning + optional Ed25519 signatures + 100 MiB / 500 MiB OOM caps.
- **Methodology-aware schema** — `has_pii`, `pii_categories`, `audit_logged`, `rate_limited`, `cross_border`, `lawful_basis`, `business_processes`, `threat_scenarios`, and ~30 sibling fields. All optional; legacy models still parse.
- **12 new CLI commands** — `validate`, `lint`, `diff`, `fmt`, `watch`, `test-rules`, `init`, `lsp`, `completion`, `generate-ci`, `rule-pack list/describe`.
- **Three false-positive fixes** — MinIO SQL-injection, Nginx SSRF, container-to-container unencrypted likelihood calibration.
- **Two new built-in STRIDE rules** — `missing-csp-header`, `exposed-default-credentials`.
- **VaultNote demo** — multi-file model exercising all four methodologies; verified risk counts of 35/12/5/11.
- **AI-author guide** — 21-section `SKILL.md` so any agent can write or edit Threagile YAML correctly.

What we **don't** have yet: anything outside hand-written YAML. The platform still requires a human (or another agent) to describe the architecture by hand. Rules are static — they don't pull live threat intel, don't reason about cloud services as cloud services, don't talk to OPA, don't know what an OpenAPI spec is. Severity calibration is enum-based and uncalibrated. Findings are not linked to MITRE ATT&CK, control frameworks, or detection coverage. There is no notion of confidence.

This document is the next-generation plan to close those gaps and turn `better-threagile` into the most accurate, broadest-coverage, most-automated TMaC platform.

---

## Design Principles (v2)

1. **Lift the model from "hand-typed YAML" to "discovered + curated YAML".** Auto-ingest from IaC, OpenAPI, K8s manifests, SBOMs. Humans annotate, do not draft.
2. **Quantitative beats categorical wherever possible.** Replace 5-bucket likelihood/impact with FAIR-style ranges + Monte Carlo. Categorical outputs are derived, not authored.
3. **Every finding carries provenance.** Which rule fired, which model facts matched, which external feed (CVE/CTI/control catalog) contributed, what the confidence interval is, who/what last touched the underlying facts.
4. **Methodologies are lenses; control catalogs are axes.** A LINDDUN finding can simultaneously map to NIST 800-53 SC-8, OWASP ASVS V9.1, MITRE ATT&CK T1040, CWE-319, and PCI-DSS 4.2.1. Don't pick one.
5. **Cloud-native and AI/ML are first-class domains, not afterthoughts.** New methodology packs and technology attributes for AWS/Azure/GCP/K8s and for LLM/RAG/training-data threats.
6. **Backward compatibility is non-negotiable.** Every new field stays optional. Every legacy model under `demo/example/` and the upstream Threagile test suite keeps producing identical output under `--methodology=stride --legacy-mode=v1`.
7. **Determinism over magic.** Auto-discovery emits a YAML diff for human review before merging into the model. We never silently change the source of truth. LLM-assisted features are opt-in (`--llm-suggest`), always produce reviewable artifacts, and never block the deterministic rule engine.

---

## Phase A — Accuracy: quantitative risk, confidence, calibration

**Problem**: Current severities are five buckets (`very-low` → `critical`) multiplied to a 5×5 matrix. This collides wildly different findings into the same cell and gives no way to express "we are 90% confident impact is between $50k and $300k loss" — which is what risk committees actually need.

### A.1 FAIR-style quantitative risk model

Add an optional `fair:` block to each rule and each finding:

```yaml
fair:
  loss_event_frequency:        # times per year, lognormal
    min: 0.1
    most_likely: 1
    max: 12
  loss_magnitude:              # USD per event, lognormal
    min: 25_000
    most_likely: 250_000
    max: 5_000_000
  confidence: 0.7              # 0–1; how sure are we
```

A new `pkg/risks/quant/` package runs Monte Carlo (10k iterations default) to produce per-finding **Annualized Loss Expectancy** distributions (P10/P50/P90). Categorical likelihood/impact are derived from the distribution for backwards-compatible report fields.

Critical files:
- `pkg/types/quant.go` *(new)* — `LossDistribution`, `MonteCarloResult`, `PERTSample` types.
- `pkg/risks/quant/monte_carlo.go` *(new)* — modified PERT sampling, deterministic RNG seeded from model hash for reproducibility.
- `pkg/risks/quant/aggregate.go` *(new)* — portfolio-level ALE roll-up across all findings with correlation matrix support.
- `pkg/report/excel.go` — new "Quantitative Risk" sheet with per-finding P10/P50/P90 columns and a portfolio-loss distribution histogram.

### A.2 Confidence scoring per finding

Every finding gets a `confidence` field (0–1) derived from:
- How specific the rule's match conditions were (more facts matched = higher confidence)
- Whether the underlying model fields are auto-discovered or human-confirmed
- Age of the underlying facts (stale facts decay confidence)
- Whether the rule has passing golden tests (`pkg/risks/test_runner.go`) at HEAD

Report sections sort by `severity * confidence` instead of severity alone, so a low-confidence "critical" doesn't drown out a high-confidence "high".

### A.3 Calibration harness

`threagile calibrate` — new CLI command that:
- Loads a corpus of past findings (CSV/JSON) with ground-truth outcomes (did it become an incident?)
- Fits per-rule likelihood priors via Bayesian updating
- Emits a `calibration.yaml` overlay that callers can pass via `--calibration calibration.yaml`
- Produces a Brier-score report so users can track whether their model is becoming better-calibrated over time

### A.4 Per-org severity weighting

`severity-profile.yaml` — declarative overlay that scales severity per business context:
```yaml
business_drivers:
  regulatory_pressure: high       # HIPAA-regulated → confidentiality weight ×1.5
  reputational_sensitivity: medium
  uptime_requirement: high        # availability weight ×2
weights:
  confidentiality: 1.5
  integrity: 1.0
  availability: 2.0
```
Multiplied into the existing impact calculation.

---

## Phase B — Coverage: more methodologies, more domains

### B.1 OCTAVE Allegro

OCTAVE is org-centric (information-asset focused, not technical-asset focused). Implement as a new rule pack + new top-level model section.

New types:
- `pkg/types/information_asset.go` — `InformationAsset` struct with `containers []string` (which technical assets hold/transmit/process it), `area_of_concern []string` (free-form threats), `requirements []string` (CIA + privacy + regulatory).
- `pkg/risks/methodologies/octave/*.yaml` — 8–10 rules around "information asset has containers in differing trust zones with conflicting requirements", "areas of concern with no mitigating control", etc.

### B.2 Trike

Trike is rights-based: subjects × actions × objects → acceptable risk per cell. Implement:
- `pkg/types/trike_actor.go` — `Actor` (subject) with `type` (human/system), `trust_level`.
- `pkg/types/trike_action.go` — `Action` enum (`create`, `read`, `update`, `delete`, `execute`).
- A matrix-shaped rule engine pass (`pkg/risks/trike/matrix.go`) that synthesizes one finding per (actor × asset × action) cell where authorization is missing or weaker than declared trust level.

### B.3 STRIDE-LM (with Lateral Movement)

Augment the STRIDE enum with `LateralMovement`. Add ~6 new built-in rules covering credential reuse across trust boundaries, shared-runtime privilege escalation paths, service-account scope creep.

### B.4 Cloud-native methodology pack (AWS, Azure, GCP, K8s)

`pkg/risks/methodologies/cloud-native/` (new pack, ~25 rules):

| Domain | Sample rules |
|---|---|
| IAM | `cross-account-trust-without-external-id`, `wildcard-resource-in-policy`, `service-account-with-no-rotation` |
| Network | `security-group-allows-0.0.0.0-to-database`, `vpc-flow-logs-disabled`, `nat-gateway-traversal-for-egress-control` |
| Data | `s3-bucket-public-without-cloudfront-oai`, `rds-snapshot-public`, `unencrypted-ebs-volume-attached-to-pii-asset` |
| Container | `image-from-untrusted-registry`, `privileged-container-mounting-host-socket`, `secrets-in-env-vars-instead-of-secrets-manager` |
| Serverless | `lambda-with-vpc-but-no-egress-restrictions`, `function-url-without-iam-auth` |

Technology attributes added to `pkg/types/technologies.yaml`: `aws_service`, `azure_service`, `gcp_service`, `kubernetes_workload`, `serverless_compute` so rules can target by category.

### B.5 AI/ML methodology pack (MITRE ATLAS aligned)

`pkg/risks/methodologies/ai-ml/` (new pack, ~18 rules) covering MITRE ATLAS tactics:

| Tactic | Sample rule |
|---|---|
| Reconnaissance | `model-card-exposes-training-data-source` |
| Initial Access | `inference-endpoint-no-auth` |
| ML Model Access | `model-weights-publicly-downloadable` |
| Execution | `prompt-injection-in-rag-context-window` |
| Persistence | `training-pipeline-without-data-versioning` |
| Defense Evasion | `no-prompt-shield-on-llm-input` |
| Exfiltration | `embedding-store-extracts-pii-via-query` |
| Impact | `model-output-flows-to-irreversible-action-without-human-in-loop` |

New model fields:
- On `DataAsset`: `is_training_data bool`, `is_model_weights bool`, `is_embedding_vector bool`.
- On `TechnicalAsset`: `is_llm_inference bool`, `is_vector_store bool`, `rag_context_sources []string`.

### B.6 Supply-chain methodology pack (SLSA aligned)

`pkg/risks/methodologies/supply-chain/` (~12 rules):
- `dependency-with-known-cve` (CVE database lookup)
- `build-without-provenance-attestation` (SLSA L2+)
- `unsigned-container-image`
- `transitive-dependency-from-recently-registered-namespace`
- `package-with-typosquat-risk`

Reads SBOMs (CycloneDX / SPDX JSON) from `--sbom` flag and treats every component as a synthetic technical asset for analysis.

### B.7 OWASP Top 10 + ASVS overlay packs

Instead of new rules, ship a `mappings/` directory:
- `mappings/owasp-top-10-2021.yaml` — for each OWASP entry, list which existing rule IDs cover it.
- `mappings/asvs-4.0.yaml` — ASVS requirement → rule ID matrix.
- `mappings/mitre-attack-enterprise.yaml` — ATT&CK technique → rule ID.

`threagile coverage --framework owasp-top-10-2021` prints a heatmap showing which OWASP entries the active rule set covers, which it misses, and which findings exist for each.

---

## Phase C — Automation: discovery, not authoring

The biggest accuracy win: stop relying on humans to remember every asset, link, and data flow.

### C.1 IaC ingestion

`threagile import` subcommand with adapters:

| Source | Adapter | Produces |
|---|---|---|
| Terraform plan JSON (`terraform show -json`) | `pkg/import/terraform/` | Technical assets + comm links + trust boundaries from resource graph |
| CloudFormation template | `pkg/import/cloudformation/` | Same, AWS-flavored |
| Kubernetes manifests (`kubectl get -o yaml`) | `pkg/import/kubernetes/` | One asset per Deployment/StatefulSet/DaemonSet, comm links from Services + NetworkPolicies, trust boundaries from Namespaces |
| Pulumi state | `pkg/import/pulumi/` | Same as Terraform |
| Docker Compose | `pkg/import/compose/` | One asset per service, links from `depends_on` + ports |
| Helm chart (rendered) | wraps Kubernetes adapter | Same |
| AWS account live read (read-only IAM role) | `pkg/import/aws/` | Live discovery from EC2/S3/RDS/Lambda APIs |

The output is **a YAML diff against the existing model**, not an overwrite. `threagile import terraform --plan plan.json --diff` shows what would be added/changed/removed; `--apply` writes the merge after human confirmation.

### C.2 OpenAPI / AsyncAPI ingestion

`threagile import openapi --spec api.yaml` parses an OpenAPI 3 spec and:
- Creates one comm link per path × method
- Sets `rate_limited`/`authentication_type` from spec security schemes
- Sets `protocol: https` if servers declare https
- Cross-references `requestBody`/`responseBody` schemas against existing `data_assets` (name match) and creates new data assets for unmatched schemas with `has_pii` heuristically inferred from field names (`email`, `password`, `ssn`, `name`...).

### C.3 Source-code data-flow inference

`threagile import code --repo .` runs language-aware static analysis:
- **Go/JS/TS**: detects database driver imports → infers DB technology, parses connection strings to identify host.
- **Python**: detects ORM models (`sqlalchemy.Column`, `django.db.models`) → infers stored data assets.
- **Any**: greps for known secret patterns (AWS keys, JWT signing keys) to flag `intentional-misconfiguration` candidates.

Uses tree-sitter for parsing (`pkg/import/code/treesitter.go`). Adapters are pluggable per language.

### C.4 Trust-boundary inference

Given a set of comm links and network metadata (subnets/VPC IDs/K8s namespaces), `threagile suggest boundaries` proposes a trust boundary partition that minimizes cross-boundary links while respecting hard separators (different VPCs, different K8s namespaces, different cloud accounts). Output is a YAML diff for review.

### C.5 Asset auto-classification heuristics

For each data asset/technical asset, suggest:
- `confidentiality` / `integrity` / `availability` from name keywords (`secret`, `pii`, `audit-log`, `cache`) — published as a transparent rule table.
- `usage` (`business` vs `devops`) from technology category.
- `has_pii` from data asset name keywords + cross-referenced against a configurable PII pattern dictionary.

Always advisory; produces `--annotate-suggestions` comments inline in the YAML, never silent overwrites.

---

## Phase D — Integration: feeds, frameworks, ticketing

### D.1 External threat-intel feeds

`pkg/intel/` (new module) — pluggable feed adapters that enrich findings with live data:

| Feed | Adapter | Enriches |
|---|---|---|
| NVD CVE feed | `pkg/intel/nvd/` | Component → CVE list → CVSS scores |
| EPSS scoring | `pkg/intel/epss/` | Exploitation probability for CVEs |
| KEV catalog (CISA Known Exploited Vulns) | `pkg/intel/kev/` | Marks CVEs known-exploited-in-wild |
| MITRE ATT&CK | `pkg/intel/attack/` | Technique → mitigations → detections |
| MITRE CAPEC | `pkg/intel/capec/` | Attack-pattern context |
| OSV.dev | `pkg/intel/osv/` | Cross-ecosystem vulnerability DB |
| GitHub advisories | `pkg/intel/ghsa/` | Per-language vuln database |

Feeds are cached locally (TTL configurable per-feed); analyses run offline by default, with `--refresh-intel` to force update.

### D.2 Control-framework mapping

Every rule's metadata gains an optional `controls:` block:
```yaml
controls:
  nist_800_53: [SC-8, SC-13]
  iso_27001: [A.10.1.1, A.13.2.1]
  soc2_cc: [CC6.1, CC6.7]
  pci_dss_4: [4.2.1]
  hipaa: ["164.312(e)(1)"]
  nis2: [Art. 21(2)(g)]
  cmmc: [SC.L2-3.13.8]
```

`threagile coverage --framework <name>` prints control coverage; `threagile audit --framework <name>` produces an audit-evidence bundle per control.

### D.3 Ticketing integration

`threagile sync` — bidirectional sync between findings and a ticket backend:

| Backend | Adapter |
|---|---|
| Jira | `pkg/sync/jira/` |
| Linear | `pkg/sync/linear/` |
| GitHub Issues | `pkg/sync/github/` |
| GitLab Issues | `pkg/sync/gitlab/` |
| ServiceNow | `pkg/sync/servicenow/` |

Each finding's `synthetic_id` becomes the external ID. Closed tickets feed back as `risk_tracking` entries with `status: mitigated`. Reopened findings reopen tickets.

### D.4 SIEM / detection-coverage mapping

For each finding, optionally declare a `detections:` block listing log sources / Sigma rules / Splunk searches / Elastic detections that would catch the threat materializing. `threagile coverage --detections` reports what % of findings have a paired detection. Drives a "shift-left vs shift-right" gap analysis.

### D.5 OPA / Rego export

`threagile export rego --findings risks.json` emits Rego policies that any downstream OPA-enabled system (Kyverno, Gatekeeper, Conftest, Styra) can enforce. Closes the loop: model → finding → policy → runtime enforcement.

---

## Phase E — Intelligence: LLM-assisted, never LLM-decided

LLMs are great at narrative and at proposing model edits a human will review. They are not great at deterministic risk calculation. Use them strictly as a drafting and translation layer.

### E.1 LLM-assisted model drafting

`threagile init --llm` — interview-style scaffolder. Asks "what does this system do?", "who are the users?", "what data does it handle?" and drafts an initial model YAML. Output is always a diff for human review.

### E.2 LLM-assisted finding narrative

`threagile narrate --finding <id>` — uses the rule metadata + matched facts + control framework mappings + intel feeds to produce a stakeholder-friendly narrative: "Why does this matter?", "What attack chain does it enable?", "What would a competent attacker do next?", "What's the cheapest mitigation?". Cited; provenance preserved.

### E.3 LLM-assisted rule authoring

`threagile rule draft --description "..."` — given a natural-language description of a threat, drafts a YAML script rule (using the DSL documented in `SKILL.md`). Always shown for review; never committed automatically. Integrates with `test-rules` so the LLM is asked to produce a test fixture alongside the rule.

### E.4 LLM-assisted false-positive triage

When the human marks a finding as a false positive in `risk_tracking`, `threagile triage` analyses the pattern across past FPs and proposes a rule refinement (e.g. "this rule fires on file-storage assets that are not vulnerable — propose adding `&& !is_file_storage` to the match clause"). The proposal is a code diff; never auto-merged.

### E.5 Guardrails

All LLM features:
- Run against an internal sandbox prompt that pins the DSL spec from `SKILL.md`.
- Never have write access to the model or rule files — they emit unified diffs that go through `git`-level review.
- Cite which model facts they used (provenance JSON returned alongside the prose).
- Are configurable to use any OpenAI-compatible / Anthropic / local-LLM endpoint via `--llm-provider` and `--llm-endpoint`.
- Default to disabled; `--llm-suggest` opts in per-invocation.

---

## Phase F — Continuous & portfolio operations

### F.1 Continuous mode

`threagile daemon` — long-running process that:
- Watches a Git repo for model + IaC changes.
- Re-runs analysis on each change.
- Posts deltas to a webhook (Slack/Teams/PagerDuty).
- Maintains a time-series history of risk posture in a local SQLite (`risks.db`).

`threagile timeline --since 90d` plots risk count and ALE over time per methodology — answers "are we getting safer?".

### F.2 Portfolio mode

`threagile portfolio --models-dir ./models/` runs N models, produces a cross-project dashboard:
- Which projects have the worst CVE/EPSS exposure?
- Which projects share a shared-runtime risk (e.g. all using the same Postgres tenant)?
- Which projects are missing controls required by a chosen framework?

Output is a single static HTML site (`portfolio.html`) suitable for stapling into a leadership readout.

### F.3 Drift detection

`threagile drift --baseline baseline.yaml --current current.yaml` — semantic drift report against an approved baseline. Used in CI to gate PRs: "this change adds 2 new high-severity risks; require security review before merge."

### F.4 Risk-acceptance workflow

First-class `risk_acceptance` block in the model:
```yaml
risk_acceptance:
  - finding: unencrypted-asset@minio-storage
    accepted_by: ciso@example.com
    accepted_on: 2026-05-10
    valid_until: 2026-11-10
    compensating_controls:
      - "network-level TLS termination at the load balancer"
    review_cadence: quarterly
```
Acceptances expire automatically; `threagile audit --expired-acceptances` lists ones needing re-review.

---

## Phase G — Schema, model, and DSL improvements

### G.1 Schema versioning

Add `threagile_version: "2.0"` top-level key. Schemas are versioned; the binary can read v1 (current) and v2 (this plan) models. Migration helper: `threagile migrate --from v1 --to v2`.

### G.2 DSL upgrades

The YAML script rule DSL gains:
- `not:` operator (sugar over assign/loop tag-absence pattern — the current workaround).
- `regex_match:` operator.
- `transitive_reachable:` operator (graph walk over comm links with optional protocol filter).
- `count:` returning an integer (so rules can express "more than 3 incoming links from different trust zones").
- `between:` for range comparison on numeric fields (e.g. RAA scores).
- Built-in functions: `lower()`, `trim()`, `len()`.

### G.3 Strongly-typed model in Go

Replace string-typed fields where enums exist (`Confidentiality`, `Authentication`, `Encryption`) with their enum types end-to-end. Removes a class of validation bugs and makes the LSP completions free.

### G.4 Validation phases

Split `validate` into discrete phases the user can run independently:
- `validate schema` — JSON Schema conformance.
- `validate references` — every ID referenced from `data_assets_processed`, `communication_links`, etc. exists.
- `validate semantics` — e.g. encryption claimed on a link must be supported by the protocol; an asset marked `human-interaction: true` should have a corresponding actor.
- `validate completeness` — flags missing optional fields that materially improve analysis (`has_pii` absent on a data asset whose name contains "user").

---

## Phase H — Reporting overhaul

### H.1 Modern HTML report

`threagile analyze-model --output-format html` produces an interactive single-page site (Tailwind + Alpine; no build step):
- Filter by methodology / severity / status / control framework.
- Click any finding to see provenance, matched facts, mitigation, narrative.
- Network-graph visualization (D3) of assets and comm links with risk overlay.

### H.2 Markdown export

`threagile analyze-model --output-format md` produces a GitHub-flavored markdown report suitable for committing to the repo and rendering inline in PR reviews.

### H.3 Risk register CSV with stable columns

A canonical CSV schema (versioned) for downstream tooling (Tableau, BigQuery, Splunk).

### H.4 Per-stakeholder views

`threagile report --audience exec|engineer|auditor` filters and rewrites sections appropriately:
- **Exec**: top 5 ALE, portfolio trends, framework compliance %.
- **Engineer**: full finding list with code-pointer references.
- **Auditor**: control framework crosswalk, evidence bundle, acceptance ledger.

---

## Phase I — Performance & scalability

- Parallel rule evaluation (`pkg/risks/runner.go` — goroutine-per-rule with bounded worker pool). Currently sequential.
- Incremental analysis: hash each rule's input fact-set; skip rules whose inputs haven't changed since last run. Speeds up `watch` mode dramatically.
- Streaming JSON output for very large models (>10k assets).
- Sharded report generation: each methodology's report rendered in parallel.

Target: a 1k-asset, 10k-link, 50-rule-pack analysis in under 2 seconds.

---

## Phase J — Distribution & ecosystem

### J.1 Plugin SDK

`pkg/plugin/` (new) — Go and WASM plugin ABIs so third parties can ship:
- Custom rule packs (already supported as YAML — extend to compiled-Go rule packs).
- Custom import adapters (IaC types we don't natively support).
- Custom report renderers.
- Custom severity calculators.

### J.2 Signed rule-pack registry

Run a small public registry at `registry.threagile.io` (or self-hosted) where rule packs are published with Ed25519 signatures. `threagile rule-pack install owasp-llm-top-10` resolves through the registry.

### J.3 VS Code / JetBrains extensions

A thin client over the LSP server (`internal/threagile/lsp.go` — already shipped). Adds:
- CodeLens: "X risks affect this asset" inline.
- Hover provenance: "this field is auto-discovered from `terraform.tfstate` line 412".
- Quick fixes: "add `has-csp` tag to suppress this finding" as a one-click action.

### J.4 GitHub App

A pre-built GitHub App that:
- On every PR: runs `threagile diff` against `main`, comments the risk delta.
- On every push to `main`: opens issues for newly-introduced high-severity findings.
- On a daily schedule: refreshes intel feeds and reports new CVE-driven findings without any code change.

---

## Critical files at a glance (v2 additions)

**Accuracy core**: `pkg/types/quant.go`, `pkg/risks/quant/{monte_carlo,aggregate,calibration}.go`, `pkg/risks/confidence/`, `internal/threagile/calibrate.go`.

**Methodology packs (new)**: `pkg/risks/methodologies/{octave,trike,cloud-native,ai-ml,supply-chain}/`, `pkg/types/{information_asset,trike_actor,trike_action}.go`.

**Discovery/import**: `pkg/import/{terraform,cloudformation,kubernetes,pulumi,compose,aws,openapi,code}/`, `internal/threagile/import.go`.

**Intel**: `pkg/intel/{nvd,epss,kev,attack,capec,osv,ghsa}/`, `internal/threagile/refresh_intel.go`.

**Framework mapping**: `mappings/{owasp-top-10-2021,asvs-4.0,nist-800-53,iso-27001,soc2,pci-dss-4,hipaa,nis2,mitre-attack-enterprise,mitre-atlas}.yaml`, `internal/threagile/coverage.go`, `internal/threagile/audit.go`.

**Ticketing/SIEM**: `pkg/sync/{jira,linear,github,gitlab,servicenow}/`, `pkg/export/{rego,sigma,splunk}/`.

**LLM**: `pkg/llm/{provider,prompts,sandbox}.go`, `internal/threagile/{narrate,rule_draft,triage}.go`.

**Continuous/portfolio**: `internal/threagile/{daemon,portfolio,drift,timeline}.go`, `pkg/storage/sqlite.go`.

**DSL/schema**: `pkg/risks/script/expressions/{not,regex_match,transitive_reachable,count,between}.go`, `internal/threagile/migrate.go`.

**Reporting**: `pkg/report/{html_report,markdown_report,audience_filter}.go`, `pkg/report/web/` (static SPA assets).

**Performance**: `pkg/risks/runner_parallel.go`, `pkg/risks/incremental.go`.

**Distribution**: `pkg/plugin/{abi,wasm,go}.go`, `registry/` (separate repo for the signing infra).

---

## Phased delivery (suggested sequence)

| Wave | Phases | Why first |
|---|---|---|
| 1 | A.1, A.2, G.2 (`not:`), I (parallel rules) | Wins for accuracy and speed; no new external dependencies; unblocks every downstream phase by making the engine faster and findings more meaningful |
| 2 | C.1 (Terraform), C.2 (OpenAPI), B.4 (cloud-native pack) | Highest external-value moves: most users live in cloud + Terraform + OpenAPI; eliminates the model-authoring burden for the 80% case |
| 3 | D.1 (NVD/EPSS/KEV), D.2 (control mapping), B.6 (supply chain) | Connects findings to live threat reality and compliance reality |
| 4 | A.3 (calibration), A.4 (severity profile), F.3 (drift) | Operationalization: make this thing a daily-use platform, not a once-a-quarter audit |
| 5 | B.5 (AI/ML), B.1/B.2 (OCTAVE/Trike), B.3 (STRIDE-LM) | Coverage expansion to specialized domains |
| 6 | E (LLM features), D.3 (ticketing), H (reporting overhaul), J (plugins/extensions/GitHub App) | Polish and ecosystem |

Each wave preserves backward compatibility, ships behind feature flags, and is independently shippable. The VaultNote demo is extended at each wave to exercise the new capability end-to-end.

---

## Verification — what "done" looks like

At the end of Phase J, the following single workflow is one command per step:

```bash
# 1. Discover the architecture instead of typing it
threagile import terraform --plan plan.json --apply
threagile import openapi --spec api.yaml --apply
threagile import code --repo . --apply

# 2. Refresh live intel
threagile refresh-intel

# 3. Run every methodology in parallel
threagile analyze-model --methodologies stride,linddun,pasta,vast,cloud-native,ai-ml,supply-chain \
  --output ./out --calibration ./calibration.yaml --severity-profile ./profile.yaml

# 4. Quantitative roll-up
threagile portfolio --models-dir ./models --output-format html

# 5. Compliance evidence
threagile audit --framework nist-800-53 --output audit-bundle.zip

# 6. Continuous gate
threagile drift --baseline ./baseline.yaml --current ./current.yaml --fail-on-new-high

# 7. Ticket sync + policy export
threagile sync jira --project SEC
threagile export rego --findings ./out/risks.json > policy.rego
```

The model file becomes annotation, not authorship. The analysis becomes continuous, not periodic. The output becomes machine-actionable (Rego, Sigma, ticket sync) and stakeholder-actionable (HTML, exec PDF, audit bundle). The accuracy is quantitative, calibrated, and citable.

That is what "the most accurate and complete automated threat-model-as-code platform" means concretely — and every block above is incremental on the foundation that has already shipped.
