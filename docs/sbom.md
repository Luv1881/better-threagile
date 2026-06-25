# `threagile sbom` — SBOM + threat-intel correlation

Ingests a **CycloneDX** SBOM (as emitted by Trivy, Grype, or Syft), extracts its
components and embedded vulnerabilities, and correlates the CVEs against live
threat intelligence — the **CISA KEV** catalog and **FIRST EPSS** scores — so a
dependency inventory becomes a prioritized, exploitability-aware report.

```sh
# generate an SBOM with embedded vulns, e.g.:
trivy image --format cyclonedx --scanners vuln myimage:tag > sbom.cdx.json

# correlate (uses cached KEV; refresh first with 'threagile intel refresh')
threagile sbom --sbom sbom.cdx.json

# refresh KEV and fetch live EPSS for the SBOM's CVEs
threagile sbom --sbom sbom.cdx.json --refresh-kev --epss
```

## Prioritization

Findings are ranked so the most actionable rows are on top:

1. **KEV-listed** (known exploited in the wild) — marked `‼`.
2. Highest **EPSS** probability (likelihood of exploitation in the next 30 days).
3. Highest **CVSS** base score.

## VEX

A vulnerability whose CycloneDX `analysis.state` is `not_affected`,
`false_positive`, or `resolved` is **suppressed by default** (counted but hidden).
Pass `--include-suppressed` to show them (struck through / marked).

## CI gate

```sh
threagile sbom --sbom sbom.cdx.json --fail-on-kev
```

Exits **3** if any non-suppressed KEV-listed CVE is present — drop it into a
pipeline to block releases shipping a known-exploited dependency.

## Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--sbom` | (required) | CycloneDX SBOM JSON file |
| `--cache-dir` | `~/.config/threagile/intel` | Intel cache directory |
| `--refresh-kev` | false | Refresh the KEV catalog if stale (network) |
| `--epss` | false | Fetch live EPSS scores for the SBOM's CVEs (network) |
| `--include-suppressed` | false | Show VEX-suppressed vulnerabilities |
| `--fail-on-kev` | false | Exit 3 if any KEV-listed CVE is present |
| `--format` | `text` | `text`, `markdown` (PR-comment ready), or `json` |
| `--output` | — | Also write the rendered report to a file |

## Notes

- Correlation operates on vulnerabilities **embedded in the SBOM** (CVE IDs from
  a scanner). A components-only SBOM with no `vulnerabilities` array yields no
  findings — scan it first.
- Only real `CVE-…` IDs are correlated against KEV/EPSS; advisory IDs (GHSA, etc.)
  are listed but not intel-correlated.
