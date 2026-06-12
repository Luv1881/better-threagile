# HANDOVER — better-threagile

> Updated 2026-06-12 at the end of the v3-features working session. This is the single
> document to read before touching the repo. Full history and rationale live in
> `IMPROVEMENT_PLAN.md` (phased v2 plan with per-phase "Results" sections + §8 v3 roadmap).

## 1. Current state (all verified at handover time)

| Check | Result |
|-------|--------|
| `go build ./...` | clean |
| `go vet ./...` | clean |
| `golangci-lint run ./...` (v2.11, blocking config) | **0 issues** |
| `go test -race ./...` | **1535 tests pass**, 30 packages |
| Total coverage | ≥ 54% (CI ratchet floor: 52.0%) |
| `git status` | clean, everything committed on `master` |

No GitHub remote is configured in this working copy. CI/release workflows exist in
`.github/workflows/` but have never run (see §4 item 1).

## 2. What was done THIS session (2026-06-12, after Phase 13)

Three v3-roadmap features shipped, two real engine bugs found & fixed, and the fork was
exercised end-to-end on the VaultNote reference model (`../Threat-model/threagile/`).

### 2.1 New features (IMPROVEMENT_PLAN §8.3)

- **R4 SARIF output — DONE (f3ab03d).** Every analysis now also writes `risks.sarif`
  (SARIF 2.1.0) for GitHub/GitLab code-scanning upload. One rule per risk category
  (CWE, STRIDE, security-severity in properties), one result per risk pointing at the
  model YAML, `threagileSyntheticId` as partial fingerprint. Risks tracked as
  mitigated/false-positive/accepted carry SARIF `suppressions` (justification = tracking
  justification) so forges hide them. Flags: `--risks-sarif <name>` (default
  `risks.sarif`), `--skip-risks-sarif`. Code: `pkg/report/sarif.go` (+golden &
  structure tests); plumbing mirrors risks-json through consts/flags/config/root/generate.

- **R1 `threagile quantify` — DONE (d5a8be0).** FAIR Monte-Carlo ALE over generated
  risks. `--estimates <yaml>` maps **synthetic risk IDs (exact, wins) or category IDs**
  to PERT `loss_event_frequency` (events/yr) + `loss_magnitude` (USD/event);
  `--iterations`, `--output-json`. Deterministic per risk (RNG seeded from synthetic ID).
  Prints table sorted by median ALE + portfolio sums (documented as sum-of-percentiles
  approximation). Code: `pkg/risks/quant/quantify.go` (LoadEstimates validation +
  Quantify), `internal/threagile/quantify.go`. Also extracted the analyze command's
  rule loading into `Threagile.loadRiskRules()` (analyze.go) — reuse it for future
  commands needing the full rule set.

- **R2 risk-acceptance expiry — DONE (6017365).** Tracking entries with
  `status: accepted` may carry `accepted_until: YYYY-MM-DD` + `accepted_by:`.
  Once the date passes, **analyze/validate fail** listing the expired acceptances;
  `--ignore-expired-risk-acceptance` downgrades to warnings. `accepted_until` on a
  non-accepted status is a model error. Acceptance without expiry logs an info nudge.
  Implementation: `pkg/input/risk-tracking.go` (+merge), `pkg/types/risk-tracking.go`
  (`AcceptedUntil *Date` — pointer so YAML/JSON stays clean, `IsAcceptanceExpired`),
  `pkg/model/parse.go`, `Model.CheckAcceptanceExpiry` in `pkg/types/model.go`, called
  from `AnalyzeModel` via an **optional config interface assertion**
  (`interface{ GetIgnoreExpiredRiskAcceptance() bool }`) so other configReader
  implementations didn't need changes.

### 2.2 Engine bugs found by real-world use (both fixed, regression-tested)

- **Wildcard risk tracking was silently broken (4fa3ae1).** `applyRiskGeneration`
  built `GeneratedRisksBySyntheticId` via `SortedRisksOfCategory`, which triggers the
  one-shot `statusApplied` cache in `GeneratedRisksByCategoryWithCurrentStatus` —
  BEFORE `ApplyWildcardRiskTrackingEvaluation` expanded `rule-id@*` entries. Net effect:
  wildcard entries landed in `model.RiskTracking` but risks stayed "unchecked" in every
  output. Fixed by building the map from the raw category map. **Gotcha:** the old
  path's in-place sort was load-bearing for deterministic output — an explicit
  `types.SortByRiskSeverity` per category slice now does that job; do not remove it.
- **Same cache, second face (505b601):** with `--skip-report-pdf` etc., nothing ever
  applied tracking statuses before `WriteRisksJSON`/SARIF, so skip-report runs emitted
  all-unchecked output. `AnalyzeModel` now applies statuses once at its end (after
  wildcard expansion + expiry check). Regression test:
  `pkg/model/wildcard_tracking_test.go` asserts raw `GeneratedRisksByCategory` carries
  statuses post-analysis.
- **Duplicate synthetic IDs (in 4fa3ae1):** `push-instead-of-pull-deployment` keyed
  risks as `category@buildpipeline`, colliding when one pipeline deploys to N targets —
  broke per-risk tracking and even hid a finding (demo golden total 65→66). ID now
  includes the target asset. If other rules have N-target patterns, audit their IDs the
  same way.

### 2.3 VaultNote application (../Threat-model — separate git repo, committed b932beb2)

- All **9 methodology runs** green (stride, linddun, pasta, vast + cloud-native,
  supply-chain, ai-ml, octave, trike packs), each emitting SARIF.
- **Full triage of all 542 findings — 0 unchecked anywhere.** New include
  `threagile/feature_risk_review.yaml` (wired into `threagile.yaml` includes): wildcard
  + direct tracking entries; in-progress → tickets VAULT-145..172; intentional
  misconfigurations (it's a deliberately-vulnerable training app — grep
  `INTENTIONAL`) → **acceptances with `accepted_until: 2026-12-31`** so they must be
  re-confirmed; analytically-wrong detections → false-positive with reasoning.
- **Expiry verified end-to-end**: back-dating one acceptance makes analyze fail with
  the expected message.
- **`quantify` on real data**: `threagile/fair-estimates.yaml`; portfolio median ALE
  ≈ **$787k/yr**, dominated by `exposed-default-credentials@minio-storage`
  (median ≈ $450k/yr) — matches the qualitative "CRITICAL launch blocker" tracking.
- **CLI wart (pre-existing, documented in the model header):** root persistent flags
  must precede command-local flags (`pflag` stops at the first unknown flag), e.g.
  `quantify --model … --ignore-orphaned-risk-tracking --estimates …` works;
  `--estimates` first silently drops later root flags. Candidate small fix.
- Note: `Threat-model/scripts/create-tickets.py` has pre-existing **uncommitted user
  changes** (GitHub label-length handling) — deliberately left untouched/uncommitted.

## 3. Immediate next steps (in order)

1. **Exercise one tagged release end-to-end** (Phase 13 exit criterion, still open):
   push to GitHub, tag `v1.0.0`. `.goreleaser.yaml` hardcodes
   `ghcr.io/threagile/threagile` + owner `threagile` — change to the real org/repo
   first. **Blocked on user decision** (no remote configured).
2. **Docs follow-ups for new features**: `docs/flags.md` + `docs/commands.md` updated
   this session; consider a dedicated `docs/quantify.md` and SARIF upload example in
   `docs/cli-cookbook.md` / `generate-ci` templates (natural follow-on: R5 PR-bot).
3. **Fix the root-persistent-flag ordering wart** (see §2.3) — small, real UX win.
4. **Audit other rules for duplicate synthetic IDs** (same class as the
   push-instead-of-pull bug): any rule that loops over multiple targets but keys the
   ID on a single asset.
5. **Phase 5b leftovers** (unchanged): ~77 TODO/FIXME/HACK; 198 `_ =` discards;
   52 nolint/#nosec suppressions.
6. **Next roadmap items** (IMPROVEMENT_PLAN §8.3, in suggested order): R5/R6 (PR-bot +
   policy gate — `diff` engine exists, SARIF now exists), R7 k8s importer, R11 ATT&CK
   mapping, R9 SBOM+intel correlation. D3 is resolved (quantify shipped); D6 (CLI layer
   least tested) improved slightly via quantify tests.

## 4. How to build / test / release

```sh
go build ./...                                   # build
go test -race ./...                              # full suite (~2 min)
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11 run ./...   # lint (must be 0)
go test ./pkg/model/... -bench=. -benchmem -run='^$'   # benchmarks (also: task bench)
UPDATE_GOLDEN=1 go test ./pkg/report/...         # regenerate report goldens (dedicated commit only)
go run github.com/goreleaser/goreleaser/v2@v2.5.1 release --snapshot --clean --skip=docker,publish  # local release dry-run
```

CI (`ci.yml`): build → vet → race tests → coverage ratchet (≥52%) → fuzz smoke →
lint (blocking). Release (`release.yml`): on `v*` tag, security gate → goreleaser.

VaultNote model runs: see the command catalogue in
`../Threat-model/threagile/threagile.yaml` header (all 9 methodologies + quantify).

## 5. Gotchas & conventions (learned the hard way)

- **Goldens are the safety net.** Never change report output and regenerate goldens in
  the same commit as a refactor; regeneration needs a stated reason. (This session's
  golden change was a deliberate bug-fix consequence, documented in 4fa3ae1.)
- **Determinism matters.** Risk generation runs rules in parallel; never sort or mutate
  shared model slices in place inside a rule. When building ID lists from maps, sort.
  `applyRiskGeneration` now owns the explicit per-category `SortByRiskSeverity` — it is
  load-bearing for byte-identical reports.
- **The `statusApplied` cache bites.** `GeneratedRisksByCategoryWithCurrentStatus()` is
  one-shot; anything that calls it (incl. `SortedRisksOfCategory`) before tracking is
  fully populated freezes statuses. `AnalyzeModel` is the only place that should
  trigger the first application.
- **`.golangci.yml` is policy, not accident** (documented disabled checks). Lint stays 0.
- **gin stays at v1.10.0** (quic-go/mongo-driver surface rejected — Phase 8).
- **Root persistent flags** only reach subcommand config via
  `processSystemArgs(os.Args[1:])` in `Init()` — in tests use `newTestAppWithArgs(...)`;
  on the CLI, root flags must come before command-local flags.
- **Script-rule model map** is converted once and shared read-only across workers
  (Phase 11); rules must never write to it.
- `pkg/server` zip limits are package vars so tests can lower them — keep it that way.
- Owner decisions: **no LLM features ever** (static analysis only); **upstream
  mergeability is a non-goal**.

## 6. Key file map

| Path | What it is |
|------|------------|
| `IMPROVEMENT_PLAN.md` | Phases 0–13 with results + §8 v3 roadmap (R1/R2/R4 done) |
| `internal/threagile/` | CLI layer; `quantify.go` new; `loadRiskRules()` in analyze.go |
| `pkg/model/read.go` | analyze pipeline: parallel rules, wildcard tracking, expiry check, status application (ORDER MATTERS — see §5) |
| `pkg/risks/quant/` | FAIR Monte-Carlo engine + estimates loading (now CLI-wired) |
| `pkg/report/sarif.go` | SARIF 2.1.0 writer (golden-tested) |
| `pkg/types/risk-tracking.go` | tracking incl. `AcceptedUntil`/`IsAcceptanceExpired` |
| `pkg/report/` | all report formats, golden tests in `testdata/` |
| `pkg/server/` | REST server (hardened Phase 12) |
| `pkg/intel/`, `pkg/sync/github/` | KEV/EPSS feeds; findings↔tickets sync |
| `.goreleaser.yaml`, `release.yml` | release pipeline (never exercised — §3.1) |
| `../Threat-model/threagile/` | VaultNote reference model: 9 methodologies, `feature_risk_review.yaml` triage, `fair-estimates.yaml` |
