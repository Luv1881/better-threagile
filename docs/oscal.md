# `threagile oscal` — OSCAL assessment-results export

Exports the analyzed model as a [NIST OSCAL](https://pages.nist.gov/OSCAL/)
**assessment-results** document, turning a threat-model run into machine-readable
compliance evidence a GRC tool can ingest directly — instead of findings being
re-keyed into spreadsheets. Deterministic (UUIDv5 IDs, fixed timestamp), no AI.

```sh
threagile oscal --model threagile.yaml > assessment-results.json
threagile oscal --model threagile.yaml --output assessment-results.json
```

## Mapping

| Threagile | OSCAL |
|---|---|
| the model | `assessment-results` + `metadata` (title, version, `oscal-version`) |
| each generated risk | a `finding` under the single `result` |
| the risk's category | the finding's `target` (`objective-id`) |
| still-at-risk vs resolved | finding status `not-satisfied` / `satisfied` |
| severity & tracking status | finding `props` |

Findings are sorted by synthetic ID so the document is byte-stable across runs
and diffs cleanly in version control. The output round-trips as JSON and follows
the OSCAL `assessment-results` model (`oscal-version: 1.1.2`); pair it with your
assessment plan via the `import-ap` reference.

This complements the [STIX export](./stix.md) (threat-intel interop) with the
compliance/GRC side of the same analysis.
