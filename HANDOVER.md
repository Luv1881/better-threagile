# HANDOVER — better-threagile

> Written 2026-06-11 at the end of a working session. This is the single document to read
> before touching the repo. Full history and rationale live in `IMPROVEMENT_PLAN.md`
> (the phased v2 plan, with per-phase "Results" sections, plus the new §8 v3 roadmap).

## 1. Current state (all verified at handover time)

| Check | Result |
|-------|--------|
| `go build ./...` | clean |
| `go vet ./...` | clean |
| `golangci-lint run ./...` (v2.11, blocking config) | **0 issues** |
| `go test -race ./...` | **1503 tests pass**, 30 packages |
| Total coverage | **54.3%** (CI ratchet floor: 52.0%) |
| `git status` | clean, everything committed on `master` |

The repo is **not** a git remote-tracked fork in this working copy — no GitHub remote is
configured. CI/release workflows exist in `.github/workflows/` but have never run; pushing
to a GitHub repo is needed to exercise them (see §4).

## 2. What has been done (Phases 0–13 of IMPROVEMENT_PLAN.md)

Condensed; each phase has a detailed "Results" section in the plan.

- **0–4**: CI workflow, lint config, llm command-tree removal (owner decision: no LLM,
  static analysis only), rule-pack embed migration, first test waves, baseline committed.
- **5/5b**: hygiene — errcheck/noctx/gosec fixes, `fmt.Print*` cleanup in `pkg/`,
  lint baseline recorded. (5b leftovers: TODO triage — see §3.)
- **6**: golden/characterization tests for every report format (adoc, Excel, PDF smoke,
  Markdown, JSON). Found and fixed **real nondeterminism bugs**: 2 data races in parallel
  risk generation, 4 map-iteration ordering bugs. `pkg/report` ~1% → 76% coverage.
- **7**: monster-file splits (report.go 4722→13 files, adocReport.go, server/model.go,
  config.go, build-pipeline macro) — purely mechanical, goldens byte-identical.
- **8**: dependency health — gofpdf→go-pdf/fpdf, go-chart→v2, mpvl/unique removed,
  routine bumps. **gin pinned at v1.10.0** deliberately (v1.12 pulls in quic-go + mongo
  driver; rejected). `go mod tidy` clean.
- **9**: test gaps closed — zero untested packages; 4 fuzz targets (`pkg/input`,
  `pkg/import/{terraform,openapi}`, `pkg/risks/script`); coverage → 52.7%.
- **10**: dead-code sweep (deleted orphaned script-DSL property types; remaining
  "deadcode" hits are deliberate API kept for symmetry — documented in plan).
- **11**: performance — benchmarks + pprof; **the big win**: script rules used to
  re-marshal the whole model to YAML per rule; now converted once and shared
  (−68% time / −89% allocs on the heaviest pack). Known remaining hot spot: excelize
  `GetCols` (56% of Excel render CPU) — documented, deliberately not fixed.
- **12**: server hardening — explicit `http.Server` with timeouts, graceful shutdown,
  gin release mode, `SetTrustedProxies(nil)`, zip decompression-bomb limits, auth
  failure-branch tests, gosec clean on `pkg/server`.
- **13 (mostly done)**:
  - 13.2 lint **179 → 0 issues** and now **blocking** in CI (`.golangci.yml` has
    documented policy decisions: gocritic typeSwitchVar/singleCaseSwitch/ifElseChain
    disabled; gochecknoglobals not enabled — read the comments in that file before
    "fixing" them).
  - 13.3 coverage ratchet in `ci.yml` (fails < 52.0%).
  - Fuzz smoke (4 × 10s) added to `ci.yml`.
  - 13.4 release pipeline: `.goreleaser.yaml` (validated; snapshot build of all 6
    OS/arch targets succeeded locally) + `Dockerfile.goreleaser` +
    `.github/workflows/release.yml` (v* tags, security-gate job before goreleaser).
  - 13.5 `docs/releases.md` refreshed.
  - **13.1 docs reconciliation DONE (2026-06-12)** — see §3.

## 3. Immediate next steps (in order)

1. ~~Fix D1 — `Dockerfile` builds the wrong code.~~ **Done (2026-06-12).** Rewrote to
   `COPY . /app`, builds `./cmd/threagile` + `./cmd/risk_demo`; verified via `docker build`
   (runs `go test ./...` in-image) and `docker run ... list-methodologies` showing
   fork-specific packs (octave/trike/cloud-native/ai-ml/supply-chain).
2. ~~Fix D2 — pin `securego/gosec@master`~~ **Done (2026-06-12).** Pinned to commit SHA
   `f1c81de5fcdf7b466b229fb24ca02d1a8406dd09` in `gosec-analysis.yml` and `release.yml`.
   No other unpinned mutable-ref third-party actions found.
3. ~~Finish 13.1 docs reconciliation.~~ **Done (2026-06-12).** Rewrote `docs/flags.md`
   (double-dash names, correct defaults incl. `--temp-dir`/`--server-dir`, `--skip-*` as
   primary with `--generate-*` deprecated, all 8 rule packs documented), `docs/config.md`
   (single-dash flag refs → double-dash, removed broken "or `--v`" text), and
   `docs/methodologies.md` (fixed false claim that OCTAVE/Trike ship no rule packs — both
   have embedded 8-rule packs; removed bogus "Custom methodologies" section since
   `--methodology custom` isn't valid; added cloud-native/supply-chain/ai-ml section).
   Also updated `docs/asciidoctor-report.md` to use `--skip-report-pdf` instead of
   deprecated `--generate-report-*` flags. Remaining 15 docs/README/SKILL.md spot-checked
   clean (no stale `llm` command refs, no other single-dash flags).
4. **Exercise one tagged release end-to-end** (Phase 13 exit criterion): push to GitHub,
   tag `v1.0.0`, confirm the security gate + goreleaser produce binaries, archives, and
   ghcr images. Note: `.goreleaser.yaml` hardcodes `ghcr.io/threagile/threagile` and
   release owner `threagile` — change these to the actual GitHub org/repo before tagging.
   **Blocked**: no GitHub remote configured in this working copy; requires user decision on
   target org/repo before any tag is pushed.
5. **Phase 5b leftovers**: 77 TODO/FIXME/HACK comments untriaged; 198 `_ =` discards
   (mostly justified `Close()` patterns, never re-audited); 52 nolint/#nosec suppressions.
6. Then start the **v3 roadmap** — `IMPROVEMENT_PLAN.md` §8. Recommended first features:
   SARIF output (R4, highest leverage/effort), then `threagile quantify` (R1 — the FAIR
   Monte-Carlo engine in `pkg/risks/quant` is implemented and tested but wired to no
   command), then risk-acceptance expiry (R2).

## 4. How to build / test / release

```sh
go build ./...                                   # build
go test -race ./...                              # full suite (~2 min)
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11 run ./...   # lint (must be 0)
go test ./pkg/model/... -bench=. -benchmem -run='^$'   # benchmarks (also: task bench)
UPDATE_GOLDEN=1 go test ./pkg/report/...         # regenerate report goldens (dedicated commit only)
go run github.com/goreleaser/goreleaser/v2@v2.5.1 release --snapshot --clean --skip=docker,publish  # local release dry-run
```

CI (`.github/workflows/ci.yml`): build → vet → race tests → coverage ratchet (≥52%) →
fuzz smoke → lint (blocking). Release (`release.yml`): on `v*` tag, security gate
(build/vet/race/lint/gosec) → goreleaser (6 binaries + multi-arch ghcr image).

## 5. Gotchas & conventions (learned the hard way)

- **Goldens are the safety net.** Never change report output and regenerate goldens in
  the same commit as a refactor. Regeneration is its own commit with a reason.
- **Determinism matters.** Risk generation runs rules in parallel; never sort or mutate
  shared model slices in place inside a rule (caused real races, fixed in Phase 6).
  When building ID lists from maps, always sort.
- **`.golangci.yml` is policy, not accident.** The disabled gocritic checks and absent
  gochecknoglobals each have justification comments. Lint must stay at 0 — CI blocks.
- **gin stays at v1.10.0** unless someone consciously accepts the quic-go/mongo-driver
  dependency surface (documented in Phase 8 results).
- **Root persistent flags** (e.g. `--model`) only reach subcommand config via the
  `processSystemArgs(os.Args[1:])` pass in `Init()` — in tests use
  `newTestAppWithArgs(...)` (see `internal/threagile/cli_commands_test.go`), not
  `cmd.SetArgs` alone.
- **Script-rule model map**: `applyRiskGeneration` converts the model to a map once and
  shares it read-only across rule workers (Phase 11 perf fix). Rules must never write to it.
- `pkg/server` zip limits (`maxUnzipFiles`, `maxUnzipTotalSize`) are package vars so
  tests can lower them — keep it that way.
- Owner decisions on record: **no LLM features ever** (static analysis only); **upstream
  mergeability is a non-goal** (refactor/delete freely).

## 6. Key file map

| Path | What it is |
|------|------------|
| `IMPROVEMENT_PLAN.md` | The full phased plan: Phases 0–13 with results + §8 v3 roadmap |
| `internal/threagile/` | CLI layer (cobra commands, config) — least-tested area (37.5%) |
| `pkg/model/` | parse + analyze pipeline (incl. `synthetic.go` benchmark model builder) |
| `pkg/risks/builtin/` | Go-native risk rules |
| `pkg/risks/script/` | YAML risk-rule DSL engine (fuzzed) |
| `pkg/risks/quant/` | FAIR Monte-Carlo — **implemented, tested, unwired** (roadmap R1) |
| `pkg/report/` | all report formats, golden tests in `testdata/` |
| `pkg/server/` | REST server (hardened Phase 12) |
| `pkg/intel/` | KEV/EPSS threat-intel feeds with caching |
| `pkg/sync/github/` | findings↔tickets sync (only backend so far) |
| `.golangci.yml` | blocking lint policy (read comments before editing) |
| `.goreleaser.yaml`, `Dockerfile.goreleaser`, `.github/workflows/release.yml` | release pipeline |
