# Bootstrap fidelity corpus

Compares `threagile bootstrap` output against hand-authored threat models that
already exist in public repositories. The point is not to score 1.0 — a starter
model cannot know the domain semantics a human wrote down — but to catch real
regressions and drive importer fixes that help *several* projects at once.

## What is measured

For every project: `threagile bootstrap` runs against the project's IaC, then
the result is compared with the project's committed model:

| Metric | Meaning |
|---|---|
| Assets coverage | share of reference technical assets also present |
| Assets precision | share of generated technical assets that are in the reference |
| Type agreement | of matched assets, share with the same asset type |
| Boundaries | share of reference trust boundaries matched |
| Data assets | share of reference data assets represented |

Matching is normalised titles first (exact, then containment — both sides at
least 5 characters and the shorter at least half the longer, so a short
`api`-style name cannot match a long reference title by accident), then
**structural**: a trust boundary matches when it contains the same matched
assets (≥50% of the reference side's matched assets, and no more than twice
its size, so a catch-all namespace boundary cannot absorb every reference),
and a data asset matches when the same matched assets process or store it.
Structural matching matters because generated names come from the
infrastructure ("`vaultnote/postgres`") while references are semantic
("`PostgreSQL Database`").

**Anti-overfitting rule:** judge changes on the aggregate across all projects.
A change that improves one project while regressing another does not land.

## Corpus setup

Clone the public references shallowly (paths as in `corpus.tsv`):

```sh
mkdir -p /tmp/corpus && cd /tmp/corpus
git clone --depth 1 https://github.com/artefactual-sdps/enduro
git clone --depth 1 https://github.com/AErmie/DevSecOps
git clone --depth 1 https://github.com/ChillAndImprove/DEF        # not in corpus.tsv yet
git clone --depth 1 https://github.com/vkhere/Project-Kavach
# VaultNote is the local companion model: ~/Desktop/coding/Threat-model
```

Every reference model was validated first: the legacy enum compatibility fix
(`enduser-identity-propagation`) is what makes enduro, DevSecOps and the other
real-world models analyzable at all. Project-Kavach and iTwinUI reference
models leave required fields empty (upstream threagile rejects them too), so
only their inventories are comparable — the comparator reads them with a plain
YAML parser, not the analyzer.

## Running

The comparator needs Python 3 and PyYAML (`pip install pyyaml`).

```sh
go build -o /tmp/threagile ./cmd/threagile/
python3 test/fidelity/compare.py test/fidelity/corpus.tsv \
    --binary /tmp/threagile --md test/fidelity/results.md --verbose
```

`results.md` is the current baseline; each run overwrites it.

## Reading the baseline

The aggregate is intentionally dominated by *entity naming*, which a machine
cannot bridge: e.g. DevSecOps' reference calls the web tier "Apache Webserver"
while the compose service is `eshopwebmvc`. What the numbers are good for:

- **Type agreement 1.00 on VaultNote/enduro** — every matched asset has the
  right type; regressions here are bugs.
- **Asset precision** — a low value means the scan imported noise (this is how
  the virtualenv/site-packages pollution and the `launchSettings.json` false
  positive were caught).
- **Boundary/data coverage near zero** — a measurement of the naming gap, not
  (only) missing structure: generated boundaries carry the source construct
  (`Network: frontend-net`) and stub data assets are invented placeholders.

**Baseline revisions are expected.** The first review of this tooling found the
structural boundary pass was a no-op (translated titles were checked against
the reference index) and the containment rule accepted short-name accidents;
fixing both lowered the reported score from 0.237 to **0.176** without any
change in `bootstrap` behaviour. Treat a score change as meaningful only when
it comes from a rebuild of the binary, not from comparator edits.

Real fidelity improvements driven by this corpus so far: `validate`↔analyze
parity, legacy enum aliases, virtualenv/cache skipping, OpenAPI detection
requiring a version, clean titles for specs without `info.title`, and the
shared container-image classification table (token-boundary matching, an
exporter guard, and datastore preference for pods with sidecars — which is why
enduro's Keycloak, SeaweedFS, MySQL and Temporal workloads and DevSecOps' SQL
Server now carry the same technologies and asset types as their reference
models).
