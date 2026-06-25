# `threagile d3fend` — D3FEND defensive recommendations

Maps the model's still-at-risk findings to [MITRE D3FEND](https://d3fend.mitre.org/)
defensive countermeasures — the **defensive complement** of the ATT&CK / CAPEC
(offensive) mappings. The report lists each recommended D3FEND technique, the
risk categories it addresses, and how many findings it would help defend, sorted
by coverage. No AI.

```sh
threagile d3fend --model threagile.yaml
threagile d3fend --model threagile.yaml --format json --output d3fend.json
```

Example (text):

```
D3FEND defensive recommendations: 10 countermeasure(s)

  D3-ITF    Inbound Traffic Filtering  (6 finding(s))
            addresses: dos-risky-access-across-trust-boundary, unguarded-access-from-internet
            https://d3fend.mitre.org/technique/d3f:InboundTrafficFiltering/
  D3-MAN    Message Analysis  (5 finding(s))
            addresses: path-traversal, sql-nosql-injection, untrusted-deserialization, xml-external-entity
            ...
```

## Mapping

The risk-category → D3FEND countermeasure table lives in `pkg/attack/d3fend.go`
(a curated, conservative starter set alongside the ATT&CK and CAPEC tables).
Finding categories with no clear D3FEND technique are reported as unmapped. Each
recommendation links to the canonical `d3fend.mitre.org` technique page.

## Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--format` | `text` | `text`, `markdown`, or `json` |
| `--output` | — | Also write the rendered report to a file |
| `--include-mitigated` | false | Also count mitigated/false-positive findings |
