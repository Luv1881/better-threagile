# Commands

## Analysis

| Command                  | Description                                                                         | Aliases                                      |
|--------------------------|-------------------------------------------------------------------------------------|----------------------------------------------|
| `analyze-model`          | Run threat model analysis; produces PDF, Excel, JSON, diagrams                      | `analyze`, `analyse`, `run`, `analyse-model` |
| `validate`               | Parse and validate the model YAML without running risk rules (fast, CI-safe); also scans for committed secrets (`--fail-on-secrets`) | `check` |
| `lint`                   | Check the model for style and best-practice issues; `--fix` applies mechanical fixes; `--json` for machine output |                               |
| `diff <old> <new>`       | Show the risk delta (added / removed / unchanged) between two model versions; `--format text\|markdown\|json`, `--output <file>` (Markdown is PR-comment ready, with a "how to fix the new findings" remediation list) |                          |
| `gate`                   | [Policy-as-code CI gate](./gate.md): evaluate `--policy policy.yaml`, exit 3 on violation; `--baseline risks.json`, `--format text\|markdown\|json` |              |
| `explain risk <id>`      | Print full explanation of a specific risk by synthetic ID                           |                                              |
| `watch`                  | Watch the model directory and re-analyze on every save                              |                                              |
| `fmt [files...]`         | Canonicalise YAML whitespace and field ordering                                     |                                              |
| `quantify`               | FAIR Monte-Carlo ALE simulation over generated risks (`--estimates` YAML file; `--output-json` for full result) |                  |
| `attack-navigator`       | Export a [MITRE ATT&CK Navigator layer](./attack-navigator.md) mapping findings to ATT&CK techniques (`--output`) |              |
| `paths`                  | [Attack-path analysis](./attack-paths.md): shortest routes from internet-facing assets to crown-jewel data (`--from`, `--to`, `--format`) |       |
| `attack-tree`            | [Goal-oriented attack trees](./attack-tree.md) per crown-jewel asset; `--format text\|markdown\|json\|dot` |       |
| `d3fend`                 | [D3FEND defensive recommendations](./d3fend.md): map findings to MITRE D3FEND countermeasures |       |
| `sbom`                   | [SBOM + threat-intel correlation](./sbom.md): correlate a CycloneDX SBOM's CVEs with KEV/EPSS, VEX-aware, `--fail-on-kev` gate |       |
| `stix`                   | [STIX 2.1 export](./stix.md): deterministic bundle (assets, vulnerabilities+CWE, ATT&CK/CAPEC attack-patterns, mitigations) for TIP/OpenCTI interop |       |
| `oscal`                  | [OSCAL assessment-results export](./oscal.md): findings → objectives with satisfied/not-satisfied status, for GRC/compliance pipelines |       |
| `mermaid`                | [Mermaid data-flow diagram](./mermaid.md): GitHub/GitLab-renderable flowchart of the model (no Graphviz needed); `--format flowchart\|markdown`, `--direction`, `--with-risks` |       |
| `policy init` / `policy list` | Scaffold a [secure-by-default gate policy](./gate.md#secure-by-default-starter-policies-policy-init): `--profile prototype\|balanced\|strict\|regulated` |       |
| `score`                  | [Threat-model health score](./score.md) 0-100 + A-F grade (completeness + risk posture); `--min` gates CI, `--format shields` for a badge |       |
| `prioritize`             | [Rank findings by exploitability](./prioritize.md) ("fix these first, here's how"): severity × exposure × reachability × data sensitivity, with remediation; `--top`, `--min-severity` |       |
| `summary`                | [Sprint/PR scorecard](./summary.md): one document — health score + top findings to fix (one analysis pass); `--format markdown\|text\|json`, `--top` |       |

## Scaffolding

| Command                  | Description                                                                         | Aliases |
|--------------------------|-------------------------------------------------------------------------------------|---------|
| `bootstrap`              | [Zero-config onboarding](./bootstrap.md): scan a repo (compose/k8s/openapi) → starter model + policy (+ hooks) |         |
| `init`                   | Interactively scaffold a new threat model (`threagile.yaml` + feature files)        |         |
| `hooks install`          | Install [git pre-commit / pre-push hooks](./hooks.md) that run validate/lint/gate    |         |
| `create-example-model`   | Write a comprehensive example model YAML to `--output`                              |         |
| `create-stub-model`      | Write a minimal starter model YAML to `--output`                                    |         |
| `create-editing-support` | Regenerate the JSON schema file used for IDE autocompletion                         |         |

## Discovery and listing

| Command                  | Description                                                                         | Aliases |
|--------------------------|-------------------------------------------------------------------------------------|---------|
| `list-methodologies`     | Print the matrix of supported methodologies and which rules cover each              |         |
| `list-risk-rules`        | List all available built-in and custom [risk rules](./risk-rules.md)                |         |
| `list-model-macros`      | List all available [macros](./macros.md)                                            |         |
| `list-types`             | List all supported enum types (confidentiality, protocol, technology, …)            |         |
| `explain`                | Alias entry point for `explain risk <id>`                                           |         |

## Rule packs

| Command                  | Description                                                                         | Aliases   |
|--------------------------|-------------------------------------------------------------------------------------|-----------|
| `rule-pack list`         | List curated (embedded + remote) rule packs                                         |           |
| `rule-pack show <name>`  | Show details about a named rule pack                                                |           |
| `rule-pack install <name>` | Install or refresh a rule pack (embedded packs extract immediately; remote packs are cached) | `update` |
| `test-rules <dir>`       | Run golden tests for a script rule pack directory                                   |           |

## Macros

| Command                  | Description                                                                         | Aliases |
|--------------------------|-------------------------------------------------------------------------------------|---------|
| `execute-model-macro`    | Execute a [macro](./macros.md) on the model (interactive or batch)                  |         |

## CI/CD and IDE

| Command                  | Description                                                                         | Aliases |
|--------------------------|-------------------------------------------------------------------------------------|---------|
| `generate-ci`            | Generate a CI/CD pipeline config (`--target github\|gate-pr\|gitlab\|jenkins\|generic`); `gate-pr` runs the policy gate on PRs and posts the Markdown report as a PR comment (`--policy-path`) |       |
| `completion bash\|zsh\|fish` | Print shell completion script; source it to enable tab-completion              |         |
| `lsp`                    | Start the Language Server (stdio) for IDE integration (completion, hover, diagnostics, go-to-definition) | |

## Server and other

| Command                  | Description                                                                         | Aliases               |
|--------------------------|-------------------------------------------------------------------------------------|-----------------------|
| `server`                 | Run in [server mode](./mode-server.md) with REST API and Web UI                     |                       |
| `print-license`          | Print the software license                                                          |                       |
| `quit`                   | Exit interactive mode                                                               | `exit`, `bye`, `x`, `q` |

See [CLI Cookbook](./cli-cookbook.md) for real examples of every command.
