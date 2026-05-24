# Flags

## Common flags

| Flag                             | Type                           | Description                                                                                 | Default Value  |
|----------------------------------|--------------------------------|---------------------------------------------------------------------------------------------| ---------------|
| `-config`                        | string(path to file)           | path to config file (more details [here](./config.md))                                      | ""             |
| `-model`                         | string(path to file)           | path to threagile model (more details [here](./model.md))                                   | threagile.yaml |
| `-interactive` or `--i`          | bool                           | turn on [interactive mode](./mode-interactive.md)                                           | false          |
| `-app-dir`                       | string(path to directory)      | path to directory where all support files (example models, license, schema etc) are located | /app           |
| `-output`                        | string(path to directory)      | path to directory where generated results will be saved                                     | ""             |
| `-tmp-dir`                       | string(path to directory)      | path to directory where temporary files will be created                                     | dev/shm        |
| `-ignore-orphaned-risk-tracking` | bool                           | do not fail the application when risk tracking does not match any risk id                   | false          |
| `-skip-risk-rules`               | string (comma separated array) | allow to ignore certain rules                                                               | ""             |
| `-custom-risk-rules-plugin`      | string (comma separated array) | comma-separated list of plugins file names with custom risk rules to load                   | ""             |
| `-verbose` or `--v`              | bool                           | add more verbosity in output, perfect for debugging and troubleshooting                     | false          |

## Analyze flags

This flags is used when application run in [analyze mode](./mode-analyze.md)

| Flag                              | Type                 | Description                                                        | Default Value             |
|-----------------------------------|----------------------|--------------------------------------------------------------------| --------------------------|
| `-diagram-dpi`                    | int                  | [GraphViz dpi](https://graphviz.org/docs/attrs/dpi/)               | 100                       |
| `-background`                     | string(path to file) | path to pdf which will be used as background during pdf generation | background.pdf            |
| `-reportLogoImagePath`            | string(path to file) | path to logo image file which will be used in adoc report          | report/threagile-logo.png |
| `-generate-data-flow-diagram`     | bool                 | specify if data flow diagram shall be generated                    | true                      |
| `-generate-data-asset-diagram`    | bool                 | specify if data asset diagram shall be generated                   | true                      |
| `-generate-risks-json`            | bool                 | specify if JSON with risks shall be generated                      | true                      |
| `-generate-technical-assets-json` | bool                 | specify if JSON with technical assets shall be generated           | true                      |
| `-generate-stats-json`            | bool                 | specify if JSON with risk statistic shall be generated             | true                      |
| `-generate-risks-excel`           | bool                 | specify if Excel with risks shall be generated                     | true                      |
| `-generate-tags-excel`            | bool                 | specify if Excel with tags shall be generated                      | true                      |
| `-generate-report-pdf`            | bool                 | specify if PDF with the analyse report shall be generated          | true                      |
| `-generate-report-adoc`           | bool                 | specify if adoc report with the analysis  shall be generated       | true                      |

## Server flags

This flags is used when application run in [server mode](./mode-server.md)

| Flag           | Type                      | Description                                             | Default Value  |
|----------------|---------------------------|---------------------------------------------------------| ---------------|
| `-server-dir`  | string(path to directory) | path to directory where static server files are located | /server        |
| `-server-port` | int                       | which port will be used to run the server               | 8080           |

## Methodology and rule-pack flags

These flags are accepted by `analyze-model`, `diff`, `watch`, `lint`, `validate`, and `test-rules`.

| Flag                     | Type                           | Description                                                                                         | Default Value |
|--------------------------|--------------------------------|-----------------------------------------------------------------------------------------------------|---------------|
| `--methodology`          | string                         | Active threat modeling methodology: `stride`, `linddun`, `pasta`, `vast`, `octave`, `trike`, `custom` | `stride`    |
| `--rule-pack`            | string                         | Load a built-in methodology rule pack by name (`linddun`, `pasta`, `vast`)                          | `""`          |
| `--rules-dir`            | string(path to directory)      | Directory containing additional YAML script risk rules to load                                      | `""`          |
| `--rules-url`            | string (repeatable)            | URL of a rules archive (`.tar.gz` or `.zip`); supports `#sha256=` and `#ttl=` fragments             | `""`          |
| `--rules-url-file`       | string(path to file)           | Newline-delimited file of rules archive URLs (blank lines and `#` comments ignored)                 | `""`          |
| `--rules-trusted-key`    | string (repeatable, base64)    | Ed25519 public key for verifying `.sig` sidecar signatures on rule archives                         | `""`          |
| `--rules-require-signed` | bool                           | Reject any remote rule archive that lacks a valid signature from a trusted key                      | `false`       |
