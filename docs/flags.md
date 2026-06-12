# Flags

All flags are GNU-style double-dash flags (`--flag value` or `--flag=value`), provided by
[cobra](https://github.com/spf13/cobra)/[pflag](https://github.com/spf13/pflag). Run
`threagile --help` or `threagile <command> --help` for the authoritative, up-to-date list —
this page is a curated overview grouped by purpose.

## Common flags (root, inherited by subcommands)

| Flag                                | Type                            | Description                                                                | Default Value     |
|--------------------------------------|---------------------------------|-----------------------------------------------------------------------------|--------------------|
| `--config`                           | string(path to file)            | path to config file (more details [here](./config.md))                      | `""`               |
| `--model`                            | string(path to file)            | input model yaml file (more details [here](./model.md))                     | `threagile.yaml`   |
| `-i`, `--interactive`                | bool                             | turn on [interactive mode](./mode-interactive.md)                           | `false`            |
| `--app-dir`                          | string(path to directory)       | app folder (support files: example models, license, schema, etc.)          | `/app`             |
| `--data-dir`                         | string(path to directory)       | data directory                                                               | `/data`            |
| `--output`                           | string(path to directory)       | output directory for generated results                                      | `.`                |
| `--temp-dir`                         | string(path to directory)       | temporary folder location                                                    | `/dev/shm`         |
| `--key-dir`                          | string(path to directory)       | key folder location (server mode)                                            | `keys`             |
| `--plugin-dir`                       | string(path to directory)       | plugin directory                                                             | `/app`             |
| `--ignore-orphaned-risk-tracking`    | bool                             | do not fail when risk tracking entries don't match any risk id              | `false`            |
| `--skip-risk-rules`                  | string (comma-separated)        | comma-separated list of risk rules (by ID) to skip                          | `""`               |
| `--custom-risk-rules-plugin`         | string (comma-separated)        | comma-separated list of plugin file names with custom risk rules to load    | `""`               |
| `--technology`                       | string                           | file name of additional technologies                                        | `""`               |
| `--imported-model`                   | string                           | imported input model yaml file                                              | `""`               |
| `--add-model-title`                  | bool                             | add model title                                                              | `false`            |
| `--backup-history-files-to-keep`     | int                              | number of backup history files to keep                                       | `50`               |
| `--keep-diagram-source-files`        | bool                             | keep diagram (.gv) source files alongside generated PNGs                    | `false`            |
| `-v`, `--verbose`                    | bool                             | verbose output, useful for debugging                                        | `false`            |
| `--version`                          | bool                             | print version                                                                | `false`            |

## Analyze flags

Used by [`analyze-model`](./mode-analyze.md) (and shared by `diff`, `watch`, `lint`,
`validate`, `test-rules` where applicable):

| Flag                              | Type                 | Description                                                              | Default Value               |
|------------------------------------|----------------------|----------------------------------------------------------------------------|-------------------------------|
| `--diagram-dpi`                   | int                  | DPI used to render diagrams (maximum 300)                                | `100`                          |
| `--background`                    | string(path to file) | template PDF used as background for PDF generation                       | `background.pdf`               |
| `--reportLogoImagePath`           | string(path to file) | logo image used in the adoc report                                       | `report/threagile-logo.png`    |
| `--data-flow-diagram-dot`         | string               | data-flow diagram DOT file name                                           | `data-flow-diagram.gv`          |
| `--data-flow-diagram-png`         | string               | data-flow diagram PNG file name                                           | `data-flow-diagram.png`         |
| `--data-asset-diagram-dot`        | string               | data-asset diagram DOT file name                                          | `data-asset-diagram.gv`         |
| `--data-asset-diagram-png`        | string               | data-asset diagram PNG file name                                          | `data-asset-diagram.png`        |
| `--report`                        | string               | PDF report file name                                                      | `report.pdf`                    |
| `--risks-json`                    | string               | risks JSON file name                                                      | `risks.json`                    |
| `--technical-assets-json`         | string               | technical assets JSON file name                                           | `technical-assets.json`         |
| `--stats-json`                    | string               | risk statistics JSON file name                                            | `stats.json`                    |
| `--risks-excel`                   | string               | risks Excel file name                                                     | `risks.xlsx`                    |
| `--tags-excel`                    | string               | tags Excel file name                                                      | `tags.xlsx`                     |
| `--skip-data-flow-diagram`        | bool                 | skip generating the data-flow diagram                                    | `false`                         |
| `--skip-data-asset-diagram`       | bool                 | skip generating the data-asset diagram                                   | `false`                         |
| `--skip-report-pdf`               | bool                 | skip generating the PDF report (including diagrams)                     | `false`                         |
| `--skip-report-adoc`              | bool                 | skip generating the adoc report (including diagrams)                    | `false`                         |
| `--skip-risks-json`               | bool                 | skip generating the risks JSON                                           | `false`                         |
| `--skip-technical-assets-json`    | bool                 | skip generating the technical-assets JSON                                | `false`                         |
| `--skip-stats-json`               | bool                 | skip generating the risk-statistics JSON                                 | `false`                         |
| `--skip-risks-excel`              | bool                 | skip generating the risks Excel                                          | `false`                         |
| `--skip-tags-excel`               | bool                 | skip generating the tags Excel                                           | `false`                         |

> The older `--generate-*` boolean flags (`--generate-data-flow-diagram`,
> `--generate-report-pdf`, etc., all defaulting to `true`) are **deprecated** in favour of
> the `--skip-*` flags above, but still accepted for backward compatibility.

## Server flags

Used by [`server`](./mode-server.md):

| Flag             | Type                       | Description                                       | Default Value |
|-------------------|-----------------------------|-----------------------------------------------------|------------------|
| `--server-dir`   | string(path to directory)  | base folder for server mode                       | `/data`          |
| `--server-port`  | int                        | server port                                       | `8080`           |

## Macro flags

| Flag                       | Type   | Description                              | Default Value |
|------------------------------|--------|---------------------------------------------|------------------|
| `--execute-model-macro`     | string | ID of the [macro](./macros.md) to execute   | `""`             |

## Methodology and rule-pack flags

Accepted by `analyze-model`, `diff`, `watch`, `lint`, `validate`, and `test-rules`:

| Flag                     | Type                          | Description                                                                                                   | Default Value |
|--------------------------|--------------------------------|------------------------------------------------------------------------------------------------------------------|---------------|
| `--methodology`         | string                         | active threat-modeling methodology: `stride`, `linddun`, `pasta`, `vast`, `octave`, `trike`                      | `stride`      |
| `--rule-pack`           | string                         | load a built-in methodology rule pack by name — see `threagile rule-pack list` for all packs (`linddun`, `pasta`, `vast`, `octave`, `trike`, `cloud-native`, `supply-chain`, `ai-ml`) | `""`          |
| `--rules-dir`           | string(path to directory)      | directory of extra YAML risk rule files to load at runtime                                                       | `""`          |
| `--rules-url`           | string (repeatable)            | URL to fetch extra YAML risk rules (`.tar.gz` or `.zip`); repeatable; supports `#sha256=...` and `#ttl=24h`      | `""`          |
| `--rules-url-file`      | string(path to file)           | file containing rules URLs to fetch, one per line                                                                | `""`          |
| `--rules-trusted-key`   | string (repeatable)            | trusted Ed25519 public key for remote rule signatures; repeatable                                                | `""`          |
| `--rules-require-signed`| bool                            | require remote rule archives to have a valid `.sig` sidecar signature                                            | `false`       |
