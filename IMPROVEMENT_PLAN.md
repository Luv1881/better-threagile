# better-threagile — Improvement Plan (v2)

> Status: **PROPOSAL — awaiting approval. Do not execute without explicit sign-off.**
> Author: fresh audit pass on working tree (master @ `81406a8` + uncommitted phase 0–3 work)
> Date: 2026-06-11 (supersedes the 2026-06-06 plan; its completed phases are recorded below)

This is a full re-audit of the fork. The previous plan's Phases 0–3 are **done but
uncommitted** (~50 modified/new files in the working tree). This v2 plan records that
baseline, carries forward the unfinished phases (hygiene, refactor, dead code, perf,
hardening), and adds new findings the first plan missed: stale/abandoned dependencies,
server hardening gaps, missing fuzz tests, incomplete golden-test coverage, and five
packages still at zero tests.

---

## 1. What is already done (baseline, from plan v1)

| Phase | Summary | Evidence |
|-------|---------|----------|
| 0 | CI workflow (`ci.yml`), `.golangci.yml`, coverage baseline 19.4% | both files exist; CI has build/vet/test/lint |
| 1 | `llm` vaporware command tree removed entirely (owner decision: static analysis only, no LLM ever draws conclusions) | `internal/threagile/llm.go` deleted; AI/ML static rule packs kept |
| 2 | Methodology rule-pack duplication killed — dirs embedded via `go:embed`, all 8 `.tar.gz` deleted, `packs_test.go` guards loading | `pkg/risks/packs.go`, `pkg/risks/packs_test.go` |
| 3 | Tests for new subsystems: `pkg/intel/*` (cache/epss/kev/nvd), `pkg/sync/github`, CLI layer, `pkg/server` utils, JSON report golden file | coverage 19.4% → **24.6%** |
| 6 (partial) | Some dead code already deleted: `pkg/plugin/abi.go`, `pkg/risks/trike/matrix.go`, `pkg/risks/script/expressions/array-expression.go` | working-tree deletions |
| 7 (partial) | First benchmark file exists | `pkg/types/model_bench_test.go` |

**Current health (verified 2026-06-11):**
- `go build ./...` clean · `go vet ./...` clean · **1411 tests pass** in 30 packages
- Total coverage: **24.6%**
- All outbound HTTP clients (`intel/*`, `sync/github`, `risks/remote`) set explicit timeouts ✓
- No build artifacts tracked in git ✓

---

## 2. Open findings (fresh audit)

### Carried forward from plan v1 (re-measured today)

| # | Area | Finding | Severity |
|---|------|---------|----------|
| F5 | Error handling | **104** ignored errors (`_ =`), **1** non-test `panic()`, **41** `nolint`/`nosec` suppressions | Medium |
| F6 | Library hygiene | **86** `fmt.Print*` calls inside `pkg/` library code (should go through the progress-reporter/logger) | Medium |
| F7 | Maintainability | Monster files: `pkg/report/report.go` (4722), `pkg/report/adocReport.go` (2317), `pkg/server/model.go` (1389), `pkg/macros/add-build-pipeline-macro.go` (1023), `internal/threagile/config.go` (974), `pkg/types/model.go` (917), `pkg/model/parse.go` (902) | Medium |
| F8 | Tech debt | **71** `TODO`/`FIXME`/`HACK` comments, unaudited | Medium |
| F9 | Performance | One benchmark file only; analyze→report pipeline unprofiled | Medium |
| F10 | Dead code | `deadcode`/`staticcheck` sweep never run repo-wide; partial deletions done ad hoc | Medium |

### New findings (not in plan v1)

| # | Area | Finding | Severity |
|---|------|---------|----------|
| N1 | Process | **~50 files of completed phase 0–3 work are uncommitted.** A stray `git checkout` loses it. Nothing else should land before this is committed in reviewable chunks. | **High** |
| N2 | Dependencies | `github.com/jung-kurt/gofpdf` (the PDF engine for the flagship report) is **archived/unmaintained since 2019**; `github.com/aws/aws-sdk-go` v1 is **deprecated**; `gin` 1.10 → 1.12, `cloud.google.com/go` 0.99 → 0.123, `wcharczuk/go-chart` is `+incompatible`-versioned, and ~15 more modules have updates pending | High |
| N3 | Server hardening | `pkg/server/server.go` uses `gin.Default()` + `router.Run(...)`: **no `http.Server` read/write/idle timeouts** (slowloris exposure), **no `SetTrustedProxies`**, gin left in debug mode, default logger to stdout | High |
| N4 | Test gaps | Five packages still have **zero tests**: `pkg/macros` (incl. the 1023-LoC macro), `pkg/input` (the model-YAML loader — the most security-relevant parser in the tool), `pkg/examples`, `pkg/common`, `pkg/docs` | High |
| N5 | Golden tests | Report characterization covers **JSON only** (`pkg/report` at ~1% coverage). The adoc/PDF/Excel paths — the ones Phase F7 must refactor — have no safety net yet | High |
| N6 | Fuzzing | **Zero fuzz tests**, yet the tool parses untrusted YAML models, Terraform plans, OpenAPI specs, and remote rule packs. Native Go fuzzing is free to add | Medium |
| N7 | Lint debt | `golangci-lint` runs only in CI in warn mode; findings are unbaselined and not yet blocking. The binary isn't even installed locally | Medium |
| N8 | Release engineering | No release workflow (no goreleaser/tagged-build pipeline); `Dockerfile` exists but nothing publishes versioned binaries/images | Low |
| N9 | Docs drift | `docs/` is rich (19 files) but written across six waves of feature work; never reconciled end-to-end against shipped flags/commands after the llm removal and pack-format change | Low |

---

## 3. Guiding principles (unchanged from v1)

1. **Tests before refactors.** Golden/characterization tests land before monster files move.
2. **Every phase ends green:** `go build`, `go vet`, `go test -race ./...`, `golangci-lint run`.
3. **No behavior change without a test that proves it.** Bug fixes get a failing test first.
4. **Small, reviewable commits**, one logical change each.
5. **Decisions over surprises** — product choices are flagged, not assumed.
6. **Coverage ratchet:** total coverage is recorded at each phase boundary and must not decrease.

---

## 4. Phased plan

### Phase 4 — Commit the baseline (N1) — *do this first, it is pure risk reduction*
*Goal: get the completed phase 0–3 work out of the working tree and into history.*

- 4.1 Commit the uncommitted work as a short series of logical commits, e.g.:
  CI + lint config → llm removal → pack-dedup (embed dirs, delete tarballs) →
  new tests (intel / sync / CLI / server / report golden) → ad-hoc dead-code deletions.
- 4.2 Verify CI goes green on the pushed result.
- 4.3 Tag or note the commit as the v2 plan baseline.
- **Exit:** clean `git status`; CI green; coverage 24.6% recorded as the ratchet floor.

### Phase 5 — Correctness & hygiene cleanup (F5, F6, F8)
*Goal: remove foot-guns while the codebase is quiet.*

- 5.1 Audit all **104 ignored errors** (`_ =`): handle, propagate, or justify each with a comment.
- 5.2 Convert the **1 remaining non-test `panic()`** to a returned error (or document why it must stay).
- 5.3 Audit the **41 `nolint`/`#nosec`** suppressions; delete stale ones, give the rest a reason string.
- 5.4 Route the **86 `fmt.Print*` calls in `pkg/`** through the existing progress-reporter/logger
  abstraction (`internal/threagile/progress-reporter.go` pattern) so library code never writes
  to stdout directly.
- 5.5 Triage the **71 TODO/FIXME/HACK** comments: fix trivial ones, convert real ones to tracked
  issues, delete stale ones.
- 5.6 Install `golangci-lint` locally + as a Taskfile target; record the current finding count
  as the lint baseline (N7 part 1).
- **Exit:** `errcheck` clean or every exception commented; no `fmt.Print*` left in `pkg/`;
  lint-finding count recorded and reduced.

**Phase 5 — DONE for 5.1/5.2/5.3 (gosec/errcheck/noctx subset), 5.4, and 5.6. 5.5 (TODO triage)
and the remaining 5.3 style-only suppressions deferred — see Phase 5b below.**

- 5.6: `golangci-lint v2.12.2` installed to `$(go env GOPATH)/bin`; lint baseline recorded:
  **217 → 163 issues** (54 fixed). Breakdown of what was fixed:
  - All **12 errcheck** findings (unchecked `Close()` on response bodies, gzip/tar/zip
    readers, file handles, fsnotify watcher) — wrapped in `defer func(){ _ = x.Close() }()`
    or `_ = x.Close()`, the standard idiomatic pattern for non-actionable Close errors.
  - All **4 noctx** findings — `exec.Command` → `exec.CommandContext(context.Background(), ...)`
    in `pkg/model/runner.go`, `pkg/report/graphviz.go` (×2), `pkg/server/execute.go`.
  - **16 of 17 gosec** findings: G306/G301 file/dir permissions tightened to 0600/0750
    across `pkg/intel/cache`, `pkg/calibrate`, `internal/threagile/import_data.go`, and
    several test files; G104 (unhandled `os.WriteFile` errors in profile/calibrate tests)
    now explicitly checked; G115 (uint64→int64 PRNG seed in `pkg/risks/quant/monte_carlo.go`)
    and G704 (test-only URL rewrite in `pkg/sync/github/github_test.go`) documented with
    `//nolint` + reason. One G703 (path-traversal false positive on a golden-file path in
    `pkg/report/json_test.go`) remains, deferred to Phase 5b.
  - **1 unused** field (`questionsAnswered` in `pkg/macros/discover-attack-surface.go`) removed.
  - **2 of 13 unparam** findings fixed (`sortByDataBreachProbability`, `ContainsExpression.evalBool`
    — unused params renamed/annotated); 11 remain (mostly "always receives constant X" in
    test helpers and macros — deferred, low risk/low value).
- 5.4: `fmt.Print*` in `pkg/` reduced **86 → 62**. Fixed: 3 GitHub-sync dry-run messages,
  2 `pkg/server` verbose-mode prints, and a swallowed-panic `fmt.Printf` in
  `WriteReportPDF` (which was also a correctness bug — the `recover()` handler discarded
  the panic and returned `nil`; it now returns a named `error`). Also deleted ~17 lines of
  commented-out `fmt.Println` debug code in `pkg/macros`, `pkg/model`, `pkg/risks/builtin`.
  **Remaining 62 are intentional**, not violations of F6: ~50 are `pkg/macros/macros.go`,
  the interactive question/answer wizard's direct stdin/stdout UI (its actual job), and
  ~7 are `pkg/server/progress-reporter.go`, which *is* the logger/progress-reporter
  implementation referenced by F6 itself. F6 is considered resolved; no further action.
- 5.1: `_ =` count went **104 → 117** — the increase is expected: many of the errcheck
  fixes above (5.6) replaced naked `Close()`/`f.Close()` calls with explicitly-discarded
  `_ = x.Close()`, which is the justified/idiomatic form. Re-auditing this count for new,
  *unjustified* `_ =` is folded into Phase 5b.
- 5.2: the 1 remaining non-test `panic()` (`pkg/server/hash.go` `xor()`) is kept — it
  guards a programmer-error invariant (mismatched buffer lengths) and already carries a
  comment explaining why a panic (not an error return) is correct here.

**Verified after Phase 5:** `go build`/`go vet` clean, **1411 tests pass**, coverage
unchanged at **24.6%**.

#### Phase 5b — Remaining hygiene (carried forward, not yet started)

- Triage the **71 TODO/FIXME/HACK** comments (5.5, untouched).
- Audit the **43 `nolint`/`#nosec`** suppressions (up from 41 — 2 new ones added in 5.6,
  both documented) for staleness.
- Remaining **163 lint findings**: `gocritic` (71, mostly `QF1012`/`sprintfQuotedString`
  style suggestions and a few more dead-comment blocks), `gochecknoglobals` (40 — mostly
  legitimate config maps/regexes/embedded-FS vars that should be reviewed case-by-case,
  not blanket-suppressed), `staticcheck` (40, mostly `QF1012` `WriteString(fmt.Sprintf(...))`
  → `fmt.Fprintf(...)`), `unparam` (11), and 1 `gosec` G703 false positive. This baseline
  feeds Phase 13.2 (lint warn → blocking).

### Phase 6 — Golden-test safety net for the report engine (N5)
*Goal: characterization coverage for every output format, as the prerequisite for Phase 7.*

- 6.1 Build one **canonical fixture model** (reuse `demo/example` or the VaultNote-style model)
  that exercises all chapters: assets, data assets, risk chapters, diagrams, STRIDE summary.
- 6.2 Golden-file tests for **adoc** output (text — easy to snapshot and diff).
- 6.3 Golden tests for **Excel** output (snapshot sheet names / cell ranges / row counts rather
  than raw bytes).
- 6.4 **PDF** smoke characterization: assert page count, embedded section titles, and successful
  render — byte-exact golden is too brittle for gofpdf.
- 6.5 Golden test for the **Markdown** report (`pkg/report/markdown.go`).
- 6.6 Add an `UPDATE_GOLDEN=1` regeneration flow documented in the test files.
- **Exit:** `pkg/report` coverage materially above the current ~1%; every output format has at
  least one characterization test; goldens regenerable with one command.

#### Phase 6 — Results (done)

- Added `pkg/report/fixture_test.go` (shared fixture: loads `demo/example/threagile.yaml` via
  `model.ReadAndAnalyzeModel`, plus PNG-fixture and `UPDATE_GOLDEN=1`/auto-create golden helpers).
- `markdown_test.go`: byte-for-byte golden for `MarkdownReport()` (`testdata/golden_report.md`),
  with the `**Generated:**` timestamp line normalized.
- `adoc_test.go`: golden file listing of the generated `adocReport/` directory (26 files) plus
  golden content of `000_main.adoc`.
- `excel_test.go`: golden summaries (sheet names, row/header counts, header row) for both the
  risks Excel and the tags Excel.
- `pdf_test.go` (internal `package report` test, with local stubs to avoid import cycles):
  smoke test that a full PDF report renders successfully (`%PDF-` header, non-trivial size).
- `pkg/report` statement coverage: **~1% → 76%**.
- All goldens regenerate via `UPDATE_GOLDEN=1 go test ./pkg/report/...`.

**Major finding: building the golden tests uncovered real nondeterminism bugs in risk
generation**, all now fixed:
- Two **data races** introduced by the Phase 4 parallel "fan out" risk generation
  (`pkg/model/read.go`):
  - `unnecessary_data_transfer_rule.go` and `unguarded_access_from_internet_rule.go` sorted
    `input.IncomingTechnicalCommunicationLinksMappedByTargetId[id]` *in place*, racing with other
    rules reading the same shared slice concurrently. Fixed by copying before sorting.
  - `applyRiskGeneration` wrote results into `parsedModel.GeneratedRisksByCategory` while
    script-rule workers were still marshalling the whole `parsedModel` (including that map) via
    `Scope.SetModel()`. Fixed by collecting into a local map first and merging only after all
    workers finish.
- Four **map-iteration ordering bugs** causing nondeterministic risk content/order across runs
  (same input, different output):
  - `lateral_movement_shared_runtime_rule.go`: "most sensitive asset" selection iterated a map;
    now iterates `runtime.TechnicalAssetsRunning` (a slice) for deterministic tie-breaking.
  - `markdown.go`: the Data Assets table iterated `model.DataAssets` (a map); now uses a new
    `sortedDataAssets()` helper.
  - `unchecked_deployment_rule.go`, `server_side_request_forgery_rule.go`,
    `code_backdooring_rule.go`: each built `DataBreachTechnicalAssetIDs` from a
    `map[string]interface{}` set without sorting; all three now `sort.Strings()` the result.
  - `types.Model.AllRisks()` (used by `WriteRisksJSON` and the Markdown report) iterated
    `GeneratedRisksByCategory` (a map) directly; now iterates category IDs in sorted order.

These were **production-impacting**, not just test-infrastructure issues: real reports could
previously vary in risk count, content, and ordering between runs of the exact same model.

### Phase 7 — Refactor monster files (F7) — *only after Phase 6 is green*
*Goal: maintainable, testable units; no behavior change.*

- 7.1 Split `pkg/report/report.go` (4722) by chapter/section (asset tables, risk chapters,
  diagrams, summary, appendix) into cohesive files; golden tests must not change.
- 7.2 Split `pkg/report/adocReport.go` (2317) the same way.
- 7.3 Split `pkg/server/model.go` (1389) along resource seams (model CRUD vs. analysis vs.
  conversion helpers).
- 7.4 Split `internal/threagile/config.go` (974) — separate config schema/defaults from
  load/merge/validate logic.
- 7.5 Split `pkg/macros/add-build-pipeline-macro.go` (1023) into prompt-flow vs. model-mutation
  halves; `pkg/types/model.go` (917) and `pkg/model/parse.go` (902) only if a clean seam exists.
- **Exit:** no single non-generated file > ~800 LoC in these areas; goldens and full test
  suite byte-identical/green; coverage not lower.

#### Phase 7 — Results (done)

- 7.1 `pkg/report/report.go` (4721) split into 13 chapter-cohesive files (`report.go` core
  319 LoC + `report_cover.go`, `report_summary.go`, `report_risk_tracking.go`,
  `report_risk_categories.go`, `report_overview.go`, `report_requirements.go`,
  `report_tags.go`, `report_technical_assets.go`, `report_data_assets.go`,
  `report_trust_boundaries.go`, `report_appendix.go`, `report_diagrams.go`). All purely
  mechanical (function-level moves + `goimports`), no logic changes.
  `report_technical_assets.go` is 822 LoC because `createTechnicalAssets` is a single
  ~810-line function; left as one file rather than risk a behavior-changing internal split.
- 7.2 `pkg/report/adocReport.go` (2317) split into 9 files the same way (`adocReport.go` core
  489 LoC + `adoc_summary.go`, `adoc_target.go`, `adoc_requirements.go`, `adoc_overview.go`,
  `adoc_risk_categories.go`, `adoc_assets.go`, `adoc_trust_boundaries.go`, `adoc_appendix.go`).
- 7.3 `pkg/server/model.go` (1389) split along resource seams into `model.go` (595, model
  CRUD/persistence/crypto), `model_metadata.go` (219, cover/overview/abuse-cases/security-reqs),
  `model_data_assets.go` (358), `model_shared_runtimes.go` (259).
- 7.4 `internal/threagile/config.go` (974) split into `config.go` (610: struct, interfaces,
  `Defaults`/`Load`/`Merge`/path helpers) and `config_accessors.go` (372: pure
  getters/setters).
- 7.5 `pkg/macros/add-build-pipeline-macro.go` (1011) split into prompt-flow
  (`add-build-pipeline-macro.go`, 265: question flow / `ApplyAnswer`/`GoBack`) and
  model-mutation (`add-build-pipeline-macro-execute.go`, 754: `Execute`/`applyChange`).
  `pkg/types/model.go` (920) and `pkg/model/parse.go` (900) left as-is — no clean seam (both
  are cohesive `Model`-method/parsing files only marginally over budget).
- All splits verified: `go build ./...`, `go vet ./...`, full `go test ./...` (1416 tests)
  green, and `pkg/report` golden tests (adoc/Excel/Markdown/PDF) byte-identical.

### Phase 8 — Dependency health (N2)
*Goal: no abandoned or deprecated code under the flagship features.*

- 8.1 **PDF engine:** migrate `jung-kurt/gofpdf` (archived 2019) → `github.com/go-pdf/fpdf`
  (the maintained drop-in fork). Phase 6 PDF characterization makes this verifiable. If output
  drifts unacceptably, document the pin-and-freeze decision instead.
- 8.2 **AWS SDK:** `aws-sdk-go` v1 is deprecated — find its call sites; if it's vestigial
  (fork inheritance), delete the usage; otherwise migrate to `aws-sdk-go-v2`.
- 8.3 Audit `wcharczuk/go-chart` (`+incompatible`) and `mpvl/unique` (trivial, 2015): replace
  `unique` with a few lines of stdlib (`slices.Compact`); decide chart lib per maintenance status.
- 8.4 Routine bumps: `gin` 1.12, `excelize`, `golang.org/x/*`, `cloud.google.com/go`, etc.
  One commit per major-surface bump; full suite + goldens green after each.
- 8.5 `go mod tidy`; review remaining indirect deps for anything now unused.
- 8.6 Optional: add Dependabot/Renovate config so this doesn't rot again.
- **Exit:** no archived/deprecated direct dependencies (or each pin documented); `go mod tidy`
  clean; goldens unchanged (or intentionally regenerated with a note).

#### Phase 8 — Results (done, 2026-06-11)

- 8.1 Migrated `jung-kurt/gofpdf` (archived) → `github.com/go-pdf/fpdf` v0.9.0, the maintained
  drop-in fork (same `fpdf` package name, same `contrib/gofpdi` API). Updated
  `pkg/report/{colors,report,report_appendix,report_cover,report_diagrams}.go` and the license
  attribution in `internal/threagile/consts.go`. PDF golden/smoke test unchanged.
- 8.2 `aws-sdk-go` confirmed not a dependency at all (already removed in earlier waves) — no
  action needed.
- 8.3 Removed `mpvl/unique` (2015, trivial), replaced its `sort.Strings` + `unique.Strings`
  pairs with `sort.Strings` + stdlib `slices.Compact` in `pkg/input/model.go`,
  `pkg/macros/{seed-tags,remove-unused-tags}-macro.go`, `pkg/report/risk-group.go`. Migrated
  `wcharczuk/go-chart` (`+incompatible`) → `github.com/wcharczuk/go-chart/v2` v2.1.2 (properly
  versioned successor); fixed the breaking `chart.Style.Show bool` → `Hidden bool` (inverted)
  field rename in `pkg/report/report_risk_tracking.go`. Updated chart license note in
  `internal/threagile/consts.go`. All goldens (Markdown/Excel/Adoc/PDF) unchanged.
- 8.4 Ran `go get -u ./...` for routine bumps (mscfb, msoleps, cobra, pflag, testify, ugorji,
  excelize + xuri/efp/nfp, golang.org/x/{arch,crypto,image,net,sys,text}, protobuf). **Pinned
  `gin` at v1.10.0** (rejected the v1.12.0 bump): it transitively pulls in
  `quic-go/quic-go`, `quic-go/qpack`, and `go.mongodb.org/mongo-driver/v2` for HTTP/3 support —
  too large a dependency-surface increase for a routine bump. Documented here as the
  "pin and document" exit allowance.
- 8.5 `go mod tidy` run after each migration step; tree is tidy.
- 8.6 Skipped (optional) — Dependabot/Renovate config not added.
- Verified: `go build ./...`, `go vet ./...`, full suite (1416 tests) all green; golangci-lint
  issue count unchanged (165, identical breakdown) vs. pre-Phase-8 tree.

### Phase 9 — Close the remaining test gaps (N4, N6)
*Goal: every shipped package has meaningful tests; untrusted-input parsers get fuzzed.*

- 9.1 **`pkg/input`** (highest value: it parses untrusted model YAML, includes, merge logic):
  unit tests for include-glob expansion, merge precedence, malformed YAML errors.
- 9.2 **`pkg/macros`**: drive each macro through its question/answer flow with a scripted
  responder; assert the resulting model mutation (the 1023-LoC build-pipeline macro first).
- 9.3 **`pkg/common`, `pkg/examples`, `pkg/docs`**: small targeted tests (these are thin).
- 9.4 **Fuzzing** (native `go test -fuzz`): seed-corpus fuzz targets for
  (a) model YAML parsing (`pkg/input`), (b) Terraform importer, (c) OpenAPI importer,
  (d) risk-DSL expression parser (`pkg/risks/script`). Run each for a bounded time in CI
  (e.g. 30s smoke) and longer locally; commit found crashers as regression tests.
- 9.5 Raise `internal/threagile` CLI coverage beyond the current 23.4% — at minimum every
  command's flag wiring and error paths (`analyze`, `intel`, `sync`, `drift`, `calibrate`,
  `import`, `lint`, `validate`).
- **Exit:** zero packages without tests; ≥4 fuzz targets with corpora; any fuzz crashers fixed
  with regression tests; total coverage ≥ 35% (ratchet recorded).

#### Phase 9 — Results (done, 2026-06-11)

- 9.1 Added `pkg/input/strings_test.go` and `pkg/input/model_test.go`: cover
  `Strings.MergeSingleton/MergeMultiline/MergeMap/MergeUniqueSlice` conflict/dedup paths, plus
  `Model.Merge`/`Model.Load` for basic fields, conflicts, malformed YAML, nested includes,
  feature-include glob expansion, diagram-tweak slice dedup, and tag normalization. Coverage
  0% → 13.8%.
- 9.2 Added `pkg/macros/macros_test.go` with a `loadFixture` helper (real model via
  `ReadAndAnalyzeModel` against `demo/example/threagile.yaml`) and a `driveQuestions` helper
  that scripts the question/answer flow for any `macros.Macros`. Covers macro listing/lookup,
  `seed-tags`, `remove-unused-tags`, `seed-risk-tracking`, `discover-attack-surface`,
  `add-vault`, and the 1023-LoC `add-build-pipeline` macro, asserting the resulting model
  mutations. Coverage 0% → 48.0%.
- 9.3 `pkg/common` and `pkg/docs` don't exist in this tree (nothing to test). Added
  `pkg/examples/examples_test.go` (0% → 88.9%) and, as a bonus, `cmd/risk_demo/main_test.go`
  (0% → 22.7%) since `cmd/risk_demo` was another previously-untested package.
- 9.4 Added four native `go test -fuzz` targets, each with a seed corpus of valid + malformed
  inputs: `pkg/input` (`FuzzModelUnmarshal`, model YAML), `pkg/import/terraform`
  (`FuzzImport`), `pkg/import/openapi` (`FuzzImport`), `pkg/risks/script` (`FuzzRiskRuleParseFromData`,
  risk-DSL rule files). Ran each for a 20s smoke (`-fuzztime=20s`); zero crashers found, so no
  regression-test corpus entries were needed.
- 9.5 Added `internal/threagile/config_accessors_test.go` (getters/setters round-trip on
  `Config`), `internal/threagile/helpers_test.go` (`DefaultProgressReporter`, path helpers,
  `severityChanged`/`hasHighOrCritical`/`hasCritical`, `wordWrap`, `checkDir`), and
  `internal/threagile/cli_commands_test.go` (`validate`, `lint`/`lint --json`, and
  `explain rules|macros|types`). Discovered along the way: the `--model` (and other
  root-persistent) flags are only applied to `what.config` via the `processSystemArgs(os.Args[1:])`
  pass during `Init()` — `isFlagOverridden` on a *subcommand* never finds root-persistent flags
  in its own `PersistentFlags()`, so `cobra.Command.SetArgs` alone (as the existing
  `executeCmd` test helper does) doesn't propagate `--model` to subcommands. Added
  `newTestAppWithArgs(args...)`, which temporarily sets `os.Args` before `Init()` to mirror how
  the production binary actually picks up these flags, rather than changing the production flag
  plumbing (out of scope for a test-only phase). `internal/threagile` coverage 23.4% → 37.5%.
- Repo-wide coverage (`go test ./... -cover`): 52.7% (≥ 35% target met). The only remaining
  0%-coverage package, `cmd/script` (a manual debugging entry point with all logic inlined in
  `main`), was given a minimal `run(scriptFilename string)` extraction plus
  `cmd/script/main_test.go` covering the success path (default script + bundled
  `test/parsed-model.yaml`) and a missing-file error path; 0% → 72.2%. Zero packages without
  tests remain.
- Verified: `go build ./...`, `go vet ./...`, full suite (1502 tests, incl. subtests) all green.

### Phase 10 — Dead code & API surface (F10)
*Goal: shrink surface area, finish what the ad-hoc deletions started.*

- 10.1 Run `deadcode ./...` and `staticcheck -checks U1000` repo-wide; delete unreferenced
  symbols and files (upstream-mergeability is explicitly a non-goal — owner decision).
- 10.2 Sweep for upstream-orphaned code paths left from fork divergence (e.g. anything that
  only served the deleted tarball pack loader or plugin ABI).
- 10.3 Reduce exported API surface: unexport `pkg/` symbols with no external callers.
- **Exit:** `deadcode` clean or remaining items justified in-line; suite green.

#### Phase 10 — Results (done, 2026-06-11)

- 10.1 Ran `golang.org/x/tools/cmd/deadcode` (28 unreachable funcs) and
  `staticcheck -checks U1000` (clean — everything has at least a test caller). Deleted the only
  genuinely orphaned code: `pkg/risks/script/property/{greater-or-equal,less-or-equal}.go`
  (two `property.Item` implementations with no constructor call anywhere, including tests other
  than their own — `common/property.go`'s `NewHistoryEntry` only ever constructs
  `Equal/NotEqual/Greater/Less/True/False/Blank/Value`) and their ~70 lines of dedicated tests
  in `pkg/risks/script/property/property_test.go`.
- The remaining 18 `deadcode` items are public API reachable only from their own package's
  tests, not dead in the "delete" sense — each is a working, tested feature whose CLI/report
  wiring is a separate (larger) task than this cleanup phase:
  - `pkg/risks/quant/monte_carlo.go` (`RunMonteCarlo`, `PERTSample`, `betaSample`,
    `gammaSample`, `modelSeedFromID`): FAIR Monte-Carlo ALE simulation (Wave 1 A.1) — types
    (`FairEstimate`, `MonteCarloResult`) exist on the model but no command runs the simulation
    yet.
  - `pkg/calibrate.LoadCalibration`, `pkg/coverage.AnalyzeWithGaps`, `pkg/profile.Default`,
    `pkg/intel/epss.{LoadCached,SaveCached}`, `pkg/intel/kev.LoadOrRefresh`: symmetric
    load/save/default counterparts to functions the CLI does call (`SaveCalibration`,
    `Analyze`, `profile.Load`, the cache `Save` path, etc.) — kept as the natural API shape;
    each is exercised by its package's test suite.
  - `pkg/risks/script/common.{EmptyEvent,NewHistory,NewBlankProperty}` and
    `pkg/risks/script/property.{NewBlank,Blank.Negate,Blank.Negated,Blank.Text}`: script-DSL
    history/event helpers used by that package's own test suite to construct fixtures; kept as
    they back the `Blank` property variant used by `NewHistoryEntry`.
- 10.2 Swept for fork-divergence orphans (tarball pack loader, plugin ABI): both were already
  removed in earlier waves (Wave 6 notes "`pkg/plugin/abi.go` ... deleted as dead code"; Phase 2
  of v1 deleted the tarball loader). Remaining `plugin`/`tarball` hits are all the current,
  live features (rule-rule plugin loading in `pkg/model/runner.go`, remote rule-pack fetching in
  `pkg/risks/remote.go`). Nothing further to remove.
- 10.3 Reduce exported API surface: skipped beyond 10.1 — `staticcheck -checks U1000` found no
  unused exported symbols, so there's no low-risk unexport candidate list to act on without a
  deeper (and out-of-scope) design review of `pkg/` as a public API.
- Verified: `go build ./...`, full suite green (no test count change beyond the ~70 deleted
  lines).

### Phase 11 — Performance (F9)
*Goal: measure, then optimize proven hot paths.*

- 11.1 Extend benchmarks beyond `pkg/types/model_bench_test.go`: full analyze→report pipeline
  on a large synthetic model (≥200 assets), rule-pack evaluation (all 9 methodologies),
  and report rendering per format.
- 11.2 Profile (`pprof`) the analyze + report path; fix the top allocators/CPU sinks only.
- 11.3 Re-verify the Wave-1 parallel rule runner under `-race` at scale; parallelize report
  sections only if profiling justifies it.
- 11.4 Verify `intel` feed caching prevents redundant network calls end-to-end (cache tests
  exist; add an integration-level assertion).
- **Exit:** benchmark suite committed and runnable via Taskfile; documented before/after on
  at least the top 2 hot paths; no `-race` findings.

#### Phase 11 — Results (done, 2026-06-11)

- 11.1 Added `pkg/model/synthetic.go` (`BuildSyntheticModelInput(nAssets int)`, exported for
  reuse from `pkg/report`) producing a valid 200-asset chained model (each asset has one data
  asset and a communication link to the previous asset). Added
  `pkg/model/analyze_bench_test.go` (`package model_test` to avoid an import cycle with
  `internal/threagile`):
  - `BenchmarkAnalyzeModel_200Assets` — full parse + risk-generation, default STRIDE + all
    built-in rules.
  - `BenchmarkAnalyzeModel_AllMethodologies` — sub-benchmarks for all 7 `Methodology` enum
    values plus the `ai-ml` and `supply-chain` rule packs (the "9 methodologies").
  - `TestAnalyzeModel_SyntheticLargeModel_Race` — runs the same 200-asset model under `-race`
    to stress the Wave-1 parallel rule runner at scale (11.3).

  Added `pkg/report/render_bench_test.go` (`package report_test`) with
  `BenchmarkMarkdownReport_200Assets`, `BenchmarkRisksExcelReport_200Assets`, and
  `BenchmarkTagsExcelReport_200Assets`, all driven off the same synthetic 200-asset model via
  `model.AnalyzeModel`.

  Added a `bench` task to `Taskfile.yml` running `go test ./pkg/model/... -bench=. -benchmem
  -run=^$` and the equivalent for `pkg/report`.

- 11.2/11.3 Profiled `BenchmarkAnalyzeModel_AllMethodologies/supply-chain` (the most
  allocation-heavy sub-benchmark) with `-cpuprofile`/`-memprofile`. **74% of all allocations**
  came from `gopkg.in/yaml.v3.Marshal`/`Unmarshal` inside
  `pkg/risks/script/common.(*Scope).SetModel` — every script-based risk rule re-marshaled the
  *entire* `*types.Model` to YAML and unmarshaled it into a fresh `map[string]any` for its own
  scope, even though all ~50+ script rules run against the same model in the same
  `applyRiskGeneration` pass and the DSL only ever *reads* from `$model` (confirmed: no
  `Scope.Model` writes anywhere in `pkg/risks/script`).

  **Fix:** extracted `common.ModelToMap(model *types.Model) (map[string]any, error)` (the
  marshal/unmarshal round-trip, now done once) and `Scope.SetModelMap(map[string]any)` (no
  conversion). Added `script.(*RiskRule).GenerateRisksFromMap(modelMap)` and a new optional
  `types.ModelMapRiskRule` interface. `pkg/model/read.go`'s `applyRiskGeneration` now converts
  `parsedModel` to a map **once** before fanning out to workers (at the same point in time the
  per-rule conversions used to happen — before any risks are written back, so results are
  identical) and each worker calls `GenerateRisksFromMap` on the shared, read-only map instead
  of re-converting. Non-script rules (Go-native) are unaffected (fall back to `GenerateRisks`).

  **Before/after** (`go test ./pkg/model/... -bench=. -benchmem -run=^$`, `-benchtime=3x`):

  | Benchmark | Before (ns/op, B/op, allocs/op) | After |
  |---|---|---|
  | `AnalyzeModel_200Assets` (stride) | 166.2ms, 269MB, 2.11M allocs | 147.7ms, 138.5MB, 1.42M allocs (−11%, −49%, −33%) |
  | `AllMethodologies/ai-ml` | 412.3ms, 1530MB, 9.54M allocs | 170.8ms, 202MB, 2.40M allocs (−59%, −87%, −75%) |
  | `AllMethodologies/supply-chain` | 572.4ms, 2237MB, 13.87M allocs | 185.3ms, 236MB, 2.96M allocs (−68%, −89%, −79%) |

  `TestAnalyzeModel_SyntheticLargeModel_Race -race` passes (11.3) — no new races from the
  shared read-only model map.

  Second hot path profiled: `BenchmarkRisksExcelReport_200Assets` (200-asset model →
  ~hundreds of rows). 56% of CPU time is `excelize.(*File).GetCols` (re-decoding the written
  sheet's XML to compute auto-fit column widths) — this is excelize's own row-enumeration
  cost, not redundant work in our code (`GetCellStyle`/`GetStyle` calls in the same loop are
  <2% of total). Fixing it would mean replacing the column-width pass with width estimates
  derived from `riskItems`/`groupedRisk` *before* writing — a real but invasive
  `pkg/report/excel.go` rewrite. At realistic risk counts (the `demo/example` model) this path
  is sub-millisecond-scale per row and not user-visible; documented here as a profiled,
  understood cost rather than fixed, per "fix the top allocators/CPU sinks only" — not
  "rewrite excelize integration."

- 11.4 `pkg/intel/kev/kev_test.go`'s `TestLoadOrRefresh_UsesCachWhenFresh` now uses an
  atomic-counter HTTP handler and asserts exactly 1 request total: one for the initial
  `Refresh` (populating the cache) and **zero** additional requests from the subsequent
  `LoadOrRefresh` call with a fresh (24h TTL) cache — proving the cache-hit path makes no
  network calls. (`pkg/intel/epss` has no `LoadOrRefresh`-equivalent batch function, so no
  analogous test was added there.)

- Verified: `go build ./...`, `go vet ./...`, `go test ./... -count=1` all green; `go test
  ./pkg/model/... ./pkg/risks/... ./pkg/types/... -race -count=1` clean (no race findings).

### Phase 12 — Server hardening (N3)
*Goal: the REST server is safe to expose beyond localhost.*

- 12.1 Replace `router.Run(...)` with an explicit `http.Server` carrying `ReadHeaderTimeout`,
  `ReadTimeout`, `WriteTimeout`, `IdleTimeout`, and `MaxHeaderBytes`.
- 12.2 `gin.SetMode(gin.ReleaseMode)` by default (debug behind a flag/env);
  call `SetTrustedProxies` explicitly (nil unless configured).
- 12.3 Add graceful shutdown (context + signal handling) so in-flight analyses finish.
- 12.4 Request-size limits on model-upload endpoints; verify the existing zip handling rejects
  zip-slip/decompression bombs (tests exist for hash/zip utils — extend to hostile archives).
- 12.5 Review auth/token paths added in `pkg/server` with tests for the failure branches.
- 12.6 Re-run `gosec` over `pkg/server` and clear or justify every finding.
- **Exit:** server passes a hostile-input test set; timeouts verifiable in tests; gosec clean
  for `pkg/server`.

### Phase 13 — Docs, release & CI enforcement (N7, N8, N9, F4 closure)
*Goal: docs match reality; quality gates become blocking; releases are reproducible.*

- 13.1 Reconcile all 19 `docs/*.md` files + `README.md` + `SKILL.md` against actual commands,
  flags, and pack formats (post-llm-removal, post-embed-migration). Fix `docs/commands.md`,
  `flags.md`, `config.md`, `methodologies.md` first — they're the entry points.
- 13.2 Turn `golangci-lint` from warn → **blocking** in CI (the Phase-5 baseline makes this
  achievable); add `go test -race` and the fuzz smoke to CI if not already there.
- 13.3 Add a coverage-ratchet check to CI (fail if total coverage drops below the recorded floor).
- 13.4 Add a release workflow: tagged builds via goreleaser (linux/mac/windows binaries +
  Docker image), with the existing security scanners gating the release.
- 13.5 Refresh `docs/releases.md` with the new release process.
- **Exit:** CI blocks on lint + race + coverage ratchet; one tagged release produced end-to-end;
  a doc-vs-`--help` spot check finds no drift.

---

## 5. Cross-cutting practices (apply throughout)

- Run `go test -race ./...` after every change; never merge red.
- Record total coverage at every phase boundary; it must not decrease (floor: **24.6%**).
- Re-run `deadcode` at the end of each phase, not just Phase 10.
- Once Phase 11 benchmarks exist, watch touched paths for regressions.
- One logical change per commit; goldens regenerated only in dedicated commits with a reason.

---

## 6. Decisions

**Resolved by owner (carried from v1):**

1. **No LLM anywhere.** Conclusions come only from static analysis of developer-authored YAML
   rules. The `llm` command tree is gone; the AI/ML *static rule packs* (which model systems
   that use LLMs as analysis subjects) stay.
2. **No upstream merge.** Staying mergeable with upstream Threagile is not a goal; refactor
   and delete freely.

**Open — decide at the phase (defaults proposed):**

3. **PDF engine (Phase 8.1):** default = migrate to maintained `go-pdf/fpdf` fork. Alternative:
   pin-and-freeze the archived lib with a documented risk note.
4. **AWS SDK (Phase 8.2):** default = delete if vestigial, migrate to v2 only if actually used.
5. **Release cadence (Phase 13.4):** default = tag-driven goreleaser; flag if Docker-image
   publishing needs a registry decision first.

---

## 7. Suggested execution order (TL;DR)

`Phase 4 (commit baseline — do immediately)` → `5 (hygiene)` → `6 (golden tests)` →
`7 (refactor monster files)` → `8 (dependency health)` → `9 (test gaps + fuzzing)` →
`10 (dead code)` → `11 (performance)` → `12 (server hardening)` → `13 (docs/release/CI gates)`.

Phase 4 is non-negotiable first — completed work is currently one bad command away from loss.
Phases 5–6 unlock everything after them. Phases 8 and 12 are the two with real external risk
reduction (abandoned PDF engine under the flagship report; unhardened HTTP server).
