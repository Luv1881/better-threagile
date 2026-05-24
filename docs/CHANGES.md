# better-threagile vs Upstream Threagile — Full Differences & Change Log

This document is a comprehensive record of every divergence between `better-threagile` and upstream [Threagile](https://threagile.io), organised by category. It covers both the original fork work and all changes made during the multi-methodology + VaultNote session.

---

## 1. Core Philosophy Shift: STRIDE-only → Multi-Methodology

Upstream Threagile is a STRIDE-only tool. Every rule, every report section, and the entire model schema is built around the six STRIDE threat categories. `better-threagile` lifts that constraint and makes the methodology a runtime parameter.

The same YAML model can be fed through four different analytical lenses in a single pipeline:

| Methodology | Focus | Rule count |
|---|---|---|
| `stride` (default) | Security threats across six categories | ~40 built-in Go rules |
| `linddun` | Privacy and data-protection threats | 9 YAML rules |
| `pasta` | Attack-centric, seven-stage decomposition | 10 YAML rules |
| `vast` | Operational and business-process risks | 8 YAML rules |
| `octave` | Org-level risk posture (planned) | — |
| `trike` | Rights-based risk analysis (planned) | — |

The methodology is selected at runtime: `--methodology stride` (or linddun/pasta/vast). No model changes are required to switch.

---

## 2. New Type System — Methodology-Specific Fields

### 2.1 New Go types

Six new files were added under `pkg/types/`:

**`pkg/types/methodology.go`** — The `Methodology` enum with parser/validator, the `--methodology` flag binding, and methodology-specific config structs.

**`pkg/types/linddun.go`** — Enums and struct fields for the LINDDUN privacy model:
- `LinddunThreatCategory` enum: `Linkability`, `Identifiability`, `NonRepudiation`, `Detectability`, `DataDisclosure`, `Unawareness`, `NonCompliance`
- `has_pii` bool field on `DataAsset`
- `pii_categories` string slice on `DataAsset` (e.g. `password-hash`, `session-identifier`, `email`, `name`, `health-data`, `financial-data`, `location`, `government-id`)
- `audit_logged` bool on `TechnicalAsset`
- `consent_required` bool on `DataAsset`
- `cross_border` bool on `DataAsset`
- `lawful_basis` string enum on `DataAsset` (`consent`, `contract`, `legal-obligation`, `vital-interests`, `public-task`, `legitimate-interests`)

**`pkg/types/pasta.go`** — Enums and struct fields for PASTA:
- `PastaStage` enum: `stage-objectives`, `stage-tech-scope`, `stage-decomposition`, `stage-threat-analysis`, `stage-vuln-analysis`, `stage-attack-modeling`, `stage-risk-analysis`
- `ThreatScenario` struct for threat scenario entries in the model
- `rate_limited` bool on `CommunicationLink`
- `ThreatScenarios` map on `Model`

**`pkg/types/vast.go`** — Enums and struct fields for VAST:
- `VastThreatType` enum: `application`, `operational`
- `BusinessProcess` struct with `criticality`, `owner`, `assets`, `business_processes` fields
- `BusinessProcesses` map on `Model`

**`pkg/types/risk-category.go`** — Extended `RiskCategory` to hold methodology-specific fields (`linddun`, `pasta`, `vast` tags that map to their respective enum values for report sectioning).

**`pkg/types/threat_scenario.go`** — New `ThreatScenario` struct for PASTA stage 1 (business objectives / threat scenarios declared in model).

### 2.2 Extended existing types

**`pkg/types/data_asset.go`** — Added `HasPii`, `PiiCategories`, `ConsentRequired`, `CrossBorder`, `LawfulBasis` fields to `DataAsset`.

**`pkg/types/technical_asset.go`** — Added `AuditLogged`, `RateLimited` fields.

**`pkg/types/communication_link.go`** — Added `RateLimited` bool field.

**`pkg/types/business_process.go`** — New file; full `BusinessProcess` type.

**`pkg/types/technologies.yaml`** — Added 33 new technology aliases used by methodology rules.

---

## 3. Rule Pack System

### 3.1 Architecture

Upstream Threagile has no concept of swappable rule packs. All rules are compiled Go code. `better-threagile` introduces an embedded tarball system:

- `pkg/risks/methodologies/linddun.tar.gz` — LINDDUN rules
- `pkg/risks/methodologies/pasta.tar.gz` — PASTA rules
- `pkg/risks/methodologies/vast.tar.gz` — VAST rules

Each tarball is a `tar -czf` of the corresponding YAML rule directory. The Go binary embeds all three via `//go:embed methodologies/*.tar.gz` in `pkg/risks/packs.go`. At runtime, the appropriate pack is extracted to a temp directory and the rules are loaded by the existing YAML script engine.

**`pkg/risks/packs.go`** (new, 55 lines) — Registers all three embedded packs, wires them into the CLI `rule-pack list/describe` subcommands, and provides `LoadPack(methodology string) ([]RuleFile, error)`.

**`pkg/risks/registry.go`** (new, 83 lines) — In-process registry that maps methodology name → pack loader. Allows the analyze pipeline to call `registry.Load("linddun")` without knowing where the files live.

### 3.2 Remote rule packs (`--rules-url`)

Upstream has a `--rules-url` flag that is documented but broken. `better-threagile` fully implements it.

**`pkg/risks/remote.go`** (280 lines, largely rewritten from ~180):

- Downloads `.tar.gz` or `.zip` archives from arbitrary HTTPS URLs
- SHA256 verification via URL fragment: `--rules-url https://host/rules.tar.gz#sha256=abc123`
- TTL-based local disk cache (24 h default, overridable via `#ttl=2h` fragment)
- Cache key is SHA256 of the URL — collision-safe across multiple remote packs
- OOM protection: 100 MiB download cap, 500 MiB extracted-bytes cap (decompression bomb guard)
- Optional Ed25519 signature verification via `.sig` sidecar file (`FetchOptions.TrustedKeys`, `FetchOptions.RequireSigned`)
- `httpClient` timeout: 60 s
- `ruleCacheTTL` constant (24 h)

---

## 4. New CLI Commands

Upstream Threagile exposes `analyze-model`, `create-editing-support`, `server`, and a handful of utility commands. `better-threagile` adds twelve new commands:

| Command | File | Description |
|---|---|---|
| `rule-pack list` | `internal/threagile/rule_pack.go` | List all available rule packs with version and rule count |
| `rule-pack describe <pack>` | `internal/threagile/rule_pack.go` | Print metadata and all rule IDs for a named pack |
| `validate` | `internal/threagile/validate.go` | Schema-validate a model YAML without running analysis |
| `lint` | `internal/threagile/lint.go` | Lint a model for style issues, orphaned assets, missing fields |
| `diff` | `internal/threagile/diff.go` | Show structural diff between two model YAML files |
| `fmt` | `internal/threagile/fmt.go` | Canonically format (normalise) a model YAML in-place |
| `watch` | `internal/threagile/watch.go` | Watch model files for changes and re-run analysis automatically |
| `test-rules` | `internal/threagile/test_rules.go` | Run YAML rule unit tests against embedded fixtures |
| `init` | `internal/threagile/init_cmd.go` | Scaffold a new model from an interactive template |
| `lsp` | `internal/threagile/lsp.go` | Start a Language Server Protocol server for IDE completion |
| `completion` | `internal/threagile/completion.go` | Generate shell completion scripts (bash/zsh/fish/powershell) |
| `generate-ci` | `internal/threagile/generate-ci.go` | Write a ready-to-use GitHub Actions workflow YAML |

### `generate-ci` details

Writes `.github/workflows/threat-model.yml` that:
- Runs weekly on a cron schedule
- Runs `analyze-model` for all enabled methodologies
- Commits outputs back to the repo
- Posts a PR comment with risk counts when run on a pull request

### `lsp` details

Full LSP server (`internal/threagile/lsp.go`, 207 lines) providing:
- Auto-completion for all YAML keys (methodology fields, technology names, enum values)
- Hover documentation (field descriptions inline)
- Diagnostic markers for schema violations
- Go-to-definition for `data_assets_processed`, `data_assets_stored`, `communication_links` IDs

---

## 5. `feature_includes` — Model Splitting

**Problem**: Large models become unmaintainable in a single file.

**Solution**: A new `feature_includes` top-level YAML key that accepts glob patterns:

```yaml
feature_includes:
  - "feature_*.yaml"
  - "teams/*/model.yaml"
```

At parse time (`pkg/model/read.go`, `pkg/input/model.go`), all matching files are loaded and merged into the main model before analysis begins. Technical assets, data assets, trust boundaries, communication links, shared runtimes, business processes, and threat scenarios are all deep-merged. Duplicate IDs raise a validation error.

This is how the VaultNote demo model is structured — five feature files (`feature_frontend.yaml`, `feature_api.yaml`, `feature_datastores.yaml`, `feature_threats.yaml`, `feature_business_processes.yaml`) plus supporting metadata files, all assembled via a root `threagile.yaml`.

---

## 6. New Model Fields (YAML Schema Additions)

All fields below are additive — models without them still parse and analyze correctly.

### On `data_assets.<id>`:

| Field | Type | Purpose |
|---|---|---|
| `has_pii` | bool | Marks data asset as containing personal data; gates LINDDUN rules |
| `pii_categories` | []string | Fine-grained PII type list (`email`, `name`, `password-hash`, `session-identifier`, `health-data`, `financial-data`, `location`, `government-id`, `device-id`, `biometric`) |
| `consent_required` | bool | GDPR — does processing require explicit consent? |
| `cross_border` | bool | Is this data transferred across jurisdictional borders? |
| `lawful_basis` | string | GDPR lawful basis enum |

### On `technical_assets.<id>`:

| Field | Type | Purpose |
|---|---|---|
| `audit_logged` | bool | Is access to this asset recorded in an audit log? |
| `rate_limited` | bool | Is this asset protected by a rate limiter? |

### On `communication_links.<id>`:

| Field | Type | Purpose |
|---|---|---|
| `rate_limited` | bool | Does this link have per-operation or global rate limiting? |

### Top-level model sections:

| Section | Purpose |
|---|---|
| `business_processes` | VAST — named business processes with criticality, owner, linked assets |
| `threat_scenarios` | PASTA — stage 1 threat scenarios declared in the model |

### Tags used as feature flags (suppress rules when present):

| Tag | Suppresses |
|---|---|
| `has-csp` | `missing-csp-header` |
| `has-httponly-session` | `pii-client-side-storage` |
| `intentional-misconfiguration` | (triggers) `exposed-default-credentials` |

---

## 7. New YAML Rule Pack — LINDDUN (9 rules)

All rules live in `pkg/risks/methodologies/linddun/` and ship in `linddun.tar.gz`.

| Rule file | ID | Fires when |
|---|---|---|
| `linking-pii-multi-boundary.yaml` | `linking-pii-multi-boundary` | Asset processes PII and sends it across multiple trust boundaries |
| `identifying-pii-stored-unencrypted.yaml` | `identifying-pii-stored-unencrypted` | Asset stores PII data with storage_encryption = none |
| `non-repudiation-missing-access-log.yaml` | `non-repudiation-missing-access-log` | Process-type asset processes PII and `audit_logged` is false |
| `detecting-no-audit-logging.yaml` | `detecting-no-audit-logging` | Datastore storing PII has no audit trail |
| `data-disclosure-pii-unencrypted-link.yaml` | `data-disclosure-pii-unencrypted-link` | PII flows over an unencrypted communication link |
| `unawareness-no-consent-technology.yaml` | `unawareness-no-consent-technology` | Asset processes `consent_required` data without a consent-management technology present |
| `non-compliance-no-lawful-basis.yaml` | `non-compliance-no-lawful-basis` | `has_pii` data asset has no `lawful_basis` set |
| `non-compliance-cross-border-transfer.yaml` | `non-compliance-cross-border-transfer` | `cross_border` data asset lacks SCCs or equivalent safeguards |
| `pii-client-side-storage.yaml` *(new, this session)* | `pii-client-side-storage` | Browser-technology asset processes PII and is not tagged `has-httponly-session` |

---

## 8. New YAML Rule Pack — PASTA (10 rules)

All rules live in `pkg/risks/methodologies/pasta/` and ship in `pasta.tar.gz`.

| Rule file | ID | PASTA stage | Fires when |
|---|---|---|---|
| `stage-objectives-missing-threat-scenario.yaml` | `missing-threat-scenario` | stage-objectives | Internet-facing asset has no declared threat scenario |
| `stage-decomposition-undocumented-entry-point.yaml` | `undocumented-entry-point` | stage-decomposition | Asset reachable from internet-trust-boundary has no description |
| `stage-decomposition-wide-attack-surface.yaml` | `wide-attack-surface` | stage-decomposition | Asset has more than a threshold number of incoming links from different trust zones |
| `stage-scope-custom-development-no-sast.yaml` | `custom-development-no-sast` | stage-tech-scope | Custom-developed asset has no SAST tag |
| `stage-attack-weak-auth-on-entry-point.yaml` | `weak-auth-on-entry-point` | stage-attack-modeling | Internet-facing entry point uses authentication below a minimum strength |
| `stage-threat-analysis-unencrypted-external-traffic.yaml` | `unencrypted-external-traffic` | stage-threat-analysis | Outgoing link from internet-facing asset is unencrypted |
| `stage-vuln-no-rate-limiting-public-api.yaml` | `no-rate-limiting-public-api` | stage-vuln-analysis | Internet-facing process asset has `rate_limited: false` on outgoing links |
| `stage-vuln-outdated-tls.yaml` | `outdated-tls` | stage-vuln-analysis | Communication link uses TLS 1.0 or 1.1 |
| `stage-risk-internet-reachable-datastore.yaml` | `internet-reachable-datastore` | stage-risk-analysis | Datastore is directly reachable from the internet trust boundary |
| `stage-vuln-per-operation-rate-limiting.yaml` *(new, this session)* | `per-operation-rate-limiting-missing` | stage-vuln-analysis | Custom process handles auth data (`password-hash`/`session-identifier`) with outgoing links where `rate_limited: false` |

---

## 9. New YAML Rule Pack — VAST (8 rules)

All rules live in `pkg/risks/methodologies/vast/` and ship in `vast.tar.gz`.

| Rule file | ID | VAST threat type | Fires when |
|---|---|---|---|
| `application-business-process-no-auth.yaml` | `business-process-no-auth` | application | Business process has no authentication check on its entry asset |
| `application-no-input-validation.yaml` | `no-input-validation` | application | Custom-developed asset processes external data without input-validation tag |
| `application-process-without-business-owner.yaml` | `process-without-business-owner` | application | Business process has no declared owner |
| `application-secrets-across-processes.yaml` | `secrets-across-processes` | application | Shared-runtime spans multiple business processes — credential blast-radius risk |
| `operational-critical-process-no-redundancy.yaml` | `critical-process-no-redundancy` | operational | Critical business process has only a single instance (no HA/redundancy) |
| `operational-multi-tenant-critical-process.yaml` | `multi-tenant-critical-process` | operational | Critical business process runs in a multi-tenant shared runtime |
| `operational-shared-runtime-critical-process.yaml` | `shared-runtime-critical-process` | operational | Critical process shares its runtime with other processes |
| `operational-unmonitored-critical-process.yaml` | `unmonitored-critical-process` | operational | Critical process has no monitoring / alerting declared |

---

## 10. New Built-in STRIDE Rules (YAML scripts)

Two new rules were added to `pkg/risks/scripts/` (embedded into the binary, always active for STRIDE runs):

### `missing-csp-header.yaml`

- **Rule ID**: `missing-csp-header`
- **CWE**: 693 (Protection Mechanism Failure)
- **Fires when**: In-scope technical asset uses `reverse-proxy` or `web-application` technology, processes at least one PII data asset, and is not tagged `has-csp`
- **Severity**: `calculate_severity(likely, medium)`
- **Suppression**: Add `has-csp` tag to the asset once CSP is deployed and verified
- **Why it was added**: The upstream rules flag many hardening gaps but have no rule for the single most common web misconfiguration — missing `Content-Security-Policy`. CSP is the primary mitigation for XSS-based data exfiltration and it gates several downstream LINDDUN findings.

### `exposed-default-credentials.yaml`

- **Rule ID**: `exposed-default-credentials`
- **CWE**: 1392 (Use of Default Credentials)
- **Fires when**: In-scope technical asset is tagged `intentional-misconfiguration` AND stores at least one data asset with `confidentiality >= confidential`
- **Severity**: `calculate_severity(very-likely, high)`, `data_breach_probability: probable`
- **Why it was added**: The VaultNote demo deliberately models MinIO with `minioadmin/minioadmin` default credentials. Upstream has no rule for this pattern. It is one of the highest-signal, lowest-noise rules possible — if the tag and confidentiality conditions are both true, it is a confirmed finding with no analysis needed.

---

## 11. Bug Fixes in Built-in Go Rules

### 11.1 SQL/NoSQL Injection — False Positive on S3 / File Stores

**File**: `pkg/risks/builtin/sql_nosql_injection_rule.go`

**Root cause**: The upstream rule uses two detection paths:
1. `potentialDatabaseAccessProtocol` (database-type technology) + `isVulnerableToQueryInjection` — correct
2. `potentialLaxDatabaseAccessProtocol` — returns true for HTTP and binary protocols, intending to catch REST-based document databases (CouchDB, Elasticsearch)

The second path fired unconditionally for any asset reachable over HTTP — including MinIO (S3-compatible object store). Object stores have no query language; there is no injection surface. The rule was producing a `sql-nosql-injection@minio-storage` finding that had no real-world basis.

**Fix**:
```go
// Before:
if potentialDatabaseAccessProtocol && isVulnerableToQueryInjection ||
    potentialLaxDatabaseAccessProtocol {

// After:
isFileStorage := technicalAsset.Technologies.GetAttribute(types.IsFileStorage)
if (potentialDatabaseAccessProtocol && isVulnerableToQueryInjection) ||
    (potentialLaxDatabaseAccessProtocol && !isFileStorage) {
```

The `IsFileStorage` technology attribute is already set on `file-server` / `s3-compatible-storage` technology types. Adding `&& !isFileStorage` to the lax path eliminates the false positive class without affecting any legitimate database detection.

### 11.2 SSRF — False Positive on Reverse Proxies

**File**: `pkg/risks/builtin/server_side_request_forgery_rule.go`

**Root cause**: SSRF requires a server that makes outbound HTTP requests based on user-supplied input. Reverse proxies (Nginx, Traefik, HAProxy) route traffic based on static configuration — they do not accept user-controlled destination URLs. Upstream's exclusion list only skipped `IsClient` and `LoadBalancer`; it did not exclude `IsTrafficForwarding`.

The rule was producing `server-side-request-forgery@nginx-ingress` findings that were architectural noise — Nginx cannot be exploited for SSRF in the traditional sense.

**Fix**:
```go
// Before:
if technicalAsset.OutOfScope ||
    technicalAsset.Technologies.GetAttribute(types.IsClient) ||
    technicalAsset.Technologies.GetAttribute(types.LoadBalancer) {

// After:
if technicalAsset.OutOfScope ||
    technicalAsset.Technologies.GetAttribute(types.IsClient) ||
    technicalAsset.Technologies.GetAttribute(types.LoadBalancer) ||
    technicalAsset.Technologies.GetAttribute(types.IsTrafficForwarding) {
```

### 11.3 Unencrypted Communication — Container Likelihood Under-Reported

**File**: `pkg/risks/builtin/unencrypted_communication_rule.go`

**Root cause**: Upstream sets exploitation likelihood to `Unlikely` when source and target are in the same trust boundary, on the logic that network-layer sniffing is hard within the same network segment. This assumption holds for physical and virtual machines on managed switches. It does not hold for containers.

In a Docker network, all containers on the same bridge network share Layer 2. A compromised container can run `tcpdump` on the bridge interface or perform ARP spoofing to intercept plaintext traffic from any sibling container without any privileges beyond network access. The real-world likelihood is `Likely`, not `Unlikely`.

**Fix** (added inside `createRisk()`, after the existing same-boundary downgrade block):
```go
} else if technicalAsset.Machine == types.Container || target.Machine == types.Container {
    // Within the same Docker network, a compromised container can sniff plaintext traffic
    // between sibling containers via ARP spoofing or tcpdump — treat as Likely even intra-boundary.
    likelihood = types.Likely
}
```

This applies whenever either the source or the target is a container. If both are physical/virtual in the same boundary, the original `Unlikely` logic is unchanged.

---

## 12. Server-Mode Extensions

**`pkg/server/phase6.go`** (new, 238 lines) — A new analysis phase that runs after the core STRIDE pipeline and before report generation. Phase 6 performs:
- Cross-methodology risk aggregation (collecting risks from all loaded packs)
- Risk deduplication across methodologies (same finding from two packs → one entry with merged methodology tags)
- Business-process risk propagation (VAST risks on assets are elevated if the asset participates in a critical business process)

**`pkg/server/execute.go`** — Extended to invoke Phase 6 when `--methodology` is not `stride`, and to wire `--rules-url` downloads into the analysis pipeline.

**`pkg/server/report.go`** — Extended to include methodology-specific report sections (LINDDUN threat tree, PASTA stage breakdown table, VAST operational risk matrix) when the corresponding methodology is active.

**`pkg/server/server.go`** — Added `/rule-packs` REST endpoint that returns available packs as JSON; wired the methodology flag into the server config.

**`pkg/server/model.go`** — Extended model-editing API to accept and persist the new methodology-specific fields (`has_pii`, `pii_categories`, `rate_limited`, etc.).

---

## 13. Web UI Extensions

**`server/static/dashboard.html`** (new, 221 lines) — A static dashboard page added to the server-mode web UI that shows:
- Methodology selector (switches active methodology without restarting the server)
- Risk count summary cards per methodology
- Rule pack status (loaded / version / rule count)

**`server/static/edit-model.html`** — Added methodology-specific field sections to the model editor form:
- LINDDUN section: `has_pii`, `pii_categories` multi-select, `lawful_basis` dropdown, `consent_required`, `cross_border` checkboxes on data asset forms
- PASTA section: `rate_limited` on communication link forms
- VAST section: business process editor

**`server/static/js/edit-model.js`** — JS updated to serialise/deserialise the new fields to/from the YAML model on save.

**`server/static/css/edit-model.css`** — 12 new CSS rules for the methodology field sections.

---

## 14. YAML Script Rule Test Runner

**`pkg/risks/test_runner.go`** (new, 228 lines) — A standalone rule test runner that:
- Loads a YAML rule file
- Loads a fixture model YAML from a parallel `__fixtures__/` directory
- Runs the rule's match expression against the fixture
- Asserts that specific asset IDs do or do not match

**`internal/threagile/test_rules.go`** — Wires the test runner into the `test-rules` CLI command.

This enables rule authors to write unit tests for YAML script rules without compiling Go or standing up the full analysis pipeline.

---

## 15. Documentation Added

| File | Content |
|---|---|
| `README.md` | Full rewrite: comparison table vs upstream, build instructions, tarball rebuild workflow, all four VaultNote run commands, expected risk counts per methodology, suppression tag reference |
| `SKILL.md` | 21-section AI reference guide for writing and editing Threagile YAML models; covers all fields, all enums, all technology names, complete DSL expression reference, common patterns and anti-patterns |
| `docs/methodologies.md` | Deep-dive into each methodology: theory, rule design principles, when to use each |
| `docs/cli-cookbook.md` | Runbook of common tasks (add an asset, add a rule, suppress a finding, run all methodologies, CI integration) |
| `docs/commands.md` | Updated with all new CLI commands and their flags |
| `docs/flags.md` | Updated with new flags: `--methodology`, `--rule-pack`, `--rules-url`, `--rules-dir` |

---

## 16. VaultNote Demo Threat Model

A complete, multi-methodology threat model was written for **VaultNote** — a deliberately misconfigured Node.js/Express note-taking application — in `../Threat-model/threagile/`.

### Architecture modelled

| Layer | Asset | Technology | Zone |
|---|---|---|---|
| Frontend | `browser-spa` | `browser` | Internet |
| Ingress | `nginx-ingress` | `reverse-proxy` | DMZ |
| Application | `api-server` | `application-server` | App Network |
| Database | `postgres-db` | `database` | Data Tier |
| Cache | `redis-cache` | `in-memory-database` | Data Tier |
| Object store | `minio-storage` | `file-server` (S3-compatible) | Data Tier |
| Runtime | `docker-host` | `container-platform` | Data Tier |

### Model split structure

The model uses `feature_includes` to split across six files:

- `threagile.yaml` — entry point with `feature_includes` glob
- `meta.yaml` — title, author, business criticality
- `overview.yaml` — management summary
- `tags.yaml` — tag registry
- `feature_frontend.yaml` — browser SPA + Nginx, Internet/DMZ trust boundaries
- `feature_api.yaml` — Node.js API, App Network trust boundary, auth data assets
- `feature_datastores.yaml` — PostgreSQL, Redis, MinIO, Docker shared runtime, Data Tier trust boundary
- `feature_threats.yaml` — PASTA threat scenarios (stage 1)
- `feature_business_processes.yaml` — VAST business processes (note management, auth, file storage)

### Deliberate misconfigurations modelled

| Misconfiguration | Where | Rules triggered |
|---|---|---|
| Default credentials (`minioadmin/minioadmin`) | `minio-storage` | `exposed-default-credentials` |
| No Content-Security-Policy | `nginx-ingress` | `missing-csp-header` |
| No SAST pipeline | `api-server` | `custom-development-no-sast` |
| No per-operation rate limiting on login/session endpoints | `api-server` communication links | `per-operation-rate-limiting-missing`, `no-rate-limiting-public-api` |
| PII stored in browser localStorage (no HttpOnly cookies) | `browser-spa` | `pii-client-side-storage` |
| Plaintext container-to-container traffic | multiple | `unencrypted-communication` (elevated to `Likely`) |
| No audit logging on PostgreSQL | `postgres-db` | `detecting-no-audit-logging`, `non-repudiation-missing-access-log` |
| No encryption at rest on Redis | `redis-cache` | `unencrypted-asset` |
| Cross-border PII transfer without declared basis | session / user-profile data | `non-compliance-cross-border-transfer`, `non-compliance-no-lawful-basis` |
| No redundancy on critical database | `postgres-db` | `critical-process-no-redundancy` |
| Secrets in environment variables | `docker-host` shared runtime | `application-secrets-across-processes` |

### Verified risk counts after all fixes

| Methodology | Risks | Key findings |
|---|---|---|
| STRIDE | 35 | Crypto gaps, injection, missing hardening, default credentials, missing CSP |
| LINDDUN | 12 | PII on unencrypted links, no audit logging, no consent management, browser-side PII storage |
| PASTA | 5 | Missing SAST, no rate limiting (global + per-operation) |
| VAST | 11 | No redundancy, shared runtime, secrets in env vars, no monitoring |

---

## 17. Summary of Changes by File

### Bug fixes (3 files)

| File | Change |
|---|---|
| `pkg/risks/builtin/sql_nosql_injection_rule.go` | Skip lax-protocol SQL injection check for file/object stores (`IsFileStorage`) |
| `pkg/risks/builtin/server_side_request_forgery_rule.go` | Exclude traffic-forwarding assets (reverse proxies) from SSRF check |
| `pkg/risks/builtin/unencrypted_communication_rule.go` | Elevate likelihood to `Likely` for container-to-container plaintext communication |

### New STRIDE YAML script rules (2 files)

| File | Rule ID |
|---|---|
| `pkg/risks/scripts/missing-csp-header.yaml` | `missing-csp-header` |
| `pkg/risks/scripts/exposed-default-credentials.yaml` | `exposed-default-credentials` |

### New LINDDUN YAML rule (1 file, pack rebuilt)

| File | Rule ID |
|---|---|
| `pkg/risks/methodologies/linddun/pii-client-side-storage.yaml` | `pii-client-side-storage` |
| `pkg/risks/methodologies/linddun.tar.gz` | Rebuilt (8 → 9 rules) |

### New PASTA YAML rule (1 file, pack rebuilt)

| File | Rule ID |
|---|---|
| `pkg/risks/methodologies/pasta/stage-vuln-per-operation-rate-limiting.yaml` | `per-operation-rate-limiting-missing` |
| `pkg/risks/methodologies/pasta.tar.gz` | Rebuilt (9 → 10 rules) |

### Documentation (5 files)

| File | Status |
|---|---|
| `README.md` | Rewritten |
| `SKILL.md` | New |
| `docs/methodologies.md` | New |
| `docs/cli-cookbook.md` | New |
| `docs/commands.md` | Updated |
| `docs/flags.md` | Updated |
