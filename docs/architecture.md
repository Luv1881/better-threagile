# Architecture

This page is the map for contributors: how a run flows through the code, which
packages own what, and the invariants that are easy to break. Feature-level
documentation lives next to it in `docs/` (see [docs/commands.md](./commands.md)
for the command catalogue).

## The shape of the tool

One static Go binary (plus an optional `server` mode for the REST API/UI). A threat model is a YAML file; the
binary parses it, runs risk rules over the resulting typed model, and writes
reports (PDF/AsciiDoc/JSON/SARIF/Excel), gate verdicts and diagrams. Everything
is deterministic: the same model produces byte-identical output, which is what
makes golden tests and `diff`-based CI workflows possible.

## Data flow of a run

```
model YAML ──► pkg/input          raw schema (yaml tags, includes:, defaults)
                 │  input.Model
                 ▼
              pkg/model/parse.go  typed conversion; enum values, references,
                 │                trust boundary membership, risk tracking
                 ▼  types.Model
              pkg/model/read.go   analysis pipeline
                 │                ├─ RAA (relative attacker attractiveness)
                 │                ├─ parallel rule execution (WaitGroup)
                 │                └─ wildcard tracking, expiry, status application
                 ▼
              pkg/report          PDF, AsciiDoc, JSON, SARIF, GitLab SAST,
                 │                Excel, diagrams (Graphviz/DOT)
              pkg/gate            policy verdicts (exit 3)
              internal/threagile  CLI: flags → Config → commands
```

`internal/threagile` is the only place that knows about flags, config files and
process exit codes; production code in `pkg/` never imports `internal/`.

## Package map

| Path | Owns |
|---|---|
| `cmd/threagile` | `main`, version stamp |
| `internal/threagile` | CLI commands, config resolution, exit codes (0 ok / 1 error / 3 gate), `--dry-run` previews |
| `pkg/input` | The YAML schema users write; `includes:` merging; defaults |
| `pkg/types` | The domain model (`Model`, `TechnicalAsset`, `Risk`, ...), enums, risk status/acceptance (the RAA *field* lives on `TechnicalAsset`; its calculation is `pkg/model/raa.go`) |
| `pkg/model` | `ParseModel` (input → types) and `ReadAndAnalyzeModel` (parse + rules + statuses + RAA) |
| `pkg/risks` | Built-in Go rules (`builtin/`), the script-rule DSL (`script/`), methodology packs (`methodologies/`, embedded) |
| `pkg/report` | Every output format and the embedded report template/logo |
| `pkg/import` | IaC and diagram importers: compose, kubernetes, terraform, openapi, drawio, mermaid, otm, threat-dragon, plus `imageclass` (shared image hints) and `mapping` (rule-based overrides) |
| `pkg/bootstrap` | Zero-config onboarding: scan a repo → starter model |
| `pkg/gate`, `pkg/coverage`, `pkg/prioritize`, `pkg/sbom`, `pkg/intel` | Policy gate, compliance coverage, exploitability ranking, SBOM/KEV/EPSS correlation |
| `pkg/server` | REST/server-mode UI (hardened; embedded static assets seeded on start) |
| `test/e2e` | Subprocess harness over the built binary |
| `test/fidelity` | Corpus comparison against hand-authored reference models |
| `demo/`, `support/`, `server/static` | Canonical copies of everything embedded into the binary (sync tests guard drift) |

## Invariants that bite

- **Determinism is enforced by sorting, not by luck.** Map iteration order is
  random: anything that writes IDs/titles to output must sort first
  (`SortedTechnicalAssetIDs`, `sort.Strings` on collected lists). Parallel rules
  must never mutate shared model slices; build local slices and attach them to
  the model afterwards. Golden tests fail loudly when this slips.
- **The risk-status cache is one-shot.** `GeneratedRisksByCategoryWithCurrentStatus`
  (`pkg/types/model.go`) applies tracking/status lazily and caches the result;
  anything that calls it before tracking is fully populated freezes the wrong
  statuses. `AnalyzeModel` is the only place that should trigger the first
  application.
- **Script rules get a read-only model.** The script-rule engine converts the
  model to its map form once and shares it across workers; rules must not write.
- **Embedded assets have canonical sources at the repo root.** `pkg/examples/assets`
  snapshots `demo/` and `support/`, and `pkg/server/static` snapshots
  `server/static`; `assets_sync_test.go` and `static_sync_test.go` compare them
  byte-for-byte. Change the canonical file, re-copy, and the test passes.
  (`pkg/report/template` holds its files directly — templates are edited in
  place, no snapshot copy.)
- **App-folder files win over embedded ones.** Importers and report generation
  prefer a file in `--app-dir` and fall back to the embedded copy, so Docker
  layouts and hand-customized assets keep working.
- **Root and command-local flags may appear in either order.** The extraction
  pass (`processSystemArgs`) whitelists unknown flags so a root flag after a
  command-local one is still honoured; `flag_ordering_test.go` guards this.
  Tests construct the app via `newTestAppWithArgs(...)` because `Init()` reads
  `os.Args`.
- **`validate` must never accept a model `analyze-model` rejects.** `validate`
  runs the same typed conversion (without rules) — if you add a parse-time
  check, validate picks it up for free; don't add a second parser.
- **Exit codes are a contract**: 0 success, 1 error, 3 gate/quality failure
  (`docs/exit-codes.md`). No code 2.

## Adding things

| Task | Start here |
|---|---|
| A Go risk rule | `pkg/risks/builtin/` — copy a neighbour, register it (`risks.go`), add a test with a minimal model |
| A script rule / methodology pack | `pkg/risks/scripts/` or `pkg/risks/methodologies/<pack>/` (embedded dir, rebuild picks it up); see `docs/custom-risk-rules.md` |
| An importer | `pkg/import/<format>/` — `Import(data, ImportOptions) (*types.Model, error)`, deterministic IDs, fuzz target, fixtures in `testdata/` |
| A report format | `pkg/report/` — one file per format; register it in `generate.go`; add a golden test (`UPDATE_GOLDEN=1` regenerates, only with a stated reason) |
| A CLI command | `internal/threagile/<command>.go`, wired in `threagile.go`; add it to `docs/commands.md` and the e2e harness |
| A bootstrap heuristic | `pkg/bootstrap/` (`classify` for detection, `BuildModel` for assembly) |

## Testing and gates

```sh
go build ./... && go vet ./...
go test -race ./...                              # full suite (~2 min, includes test/e2e)
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11 run ./...   # must be 0
UPDATE_GOLDEN=1 go test ./pkg/report/...         # regenerate report goldens (dedicated commit)
python3 test/fidelity/compare.py test/fidelity/corpus.tsv --binary ./bin/threagile   # fidelity baseline
```

- Golangci-lint caches aggressively. A count that looks wrong after an edit
  usually means a stale cache: rerun with `GOLANGCI_LINT_CACHE=$(mktemp -d)`.
- `#nosec` annotations require a one-line justification comment (see
  `pkg/report/report_diagrams.go` for the house style).
- CI enforces a coverage floor (52%) and runs fuzz smoke tests for a subset of
  the importers; every parser has a fuzz target, run them all locally with
  `go test ./pkg/import/... -run=NONE -fuzz=FuzzImport -fuzztime=10s`.
- When changing behaviour of a command, add or update the assertion in
  `test/e2e/e2e_test.go` — it runs the real binary and checks exit codes and
  written artefacts, not just in-process return values.

## Where the interesting documents are

- Command catalogue: [docs/commands.md](./commands.md) · flags: [docs/flags.md](./flags.md)
- Model field reference: [docs/model.md](./model.md)
- Multi-file models: [docs/includes.md](./includes.md) · custom rules: [docs/custom-risk-rules.md](./custom-risk-rules.md)
- Gate policies: [docs/gate.md](./gate.md) · exit codes: [docs/exit-codes.md](./exit-codes.md)
