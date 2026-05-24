# Commands

## Analysis

| Command                  | Description                                                                         | Aliases                                      |
|--------------------------|-------------------------------------------------------------------------------------|----------------------------------------------|
| `analyze-model`          | Run threat model analysis; produces PDF, Excel, JSON, diagrams                      | `analyze`, `analyse`, `run`, `analyse-model` |
| `validate`               | Parse and validate the model YAML without running risk rules (fast, CI-safe)        |                                              |
| `lint`                   | Check the model for style and best-practice issues; `--fix` applies mechanical fixes; `--json` for machine output |                               |
| `diff <old> <new>`       | Show the risk delta (added / removed / unchanged) between two model versions        |                                              |
| `explain risk <id>`      | Print full explanation of a specific risk by synthetic ID                           |                                              |
| `watch`                  | Watch the model directory and re-analyze on every save                              |                                              |
| `fmt [files...]`         | Canonicalise YAML whitespace and field ordering                                     |                                              |

## Scaffolding

| Command                  | Description                                                                         | Aliases |
|--------------------------|-------------------------------------------------------------------------------------|---------|
| `init`                   | Interactively scaffold a new threat model (`threagile.yaml` + feature files)        |         |
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
| `generate-ci`            | Generate a CI/CD pipeline config (`--target github\|gitlab\|jenkins\|azure\|generic`) |       |
| `completion bash\|zsh\|fish` | Print shell completion script; source it to enable tab-completion              |         |
| `lsp`                    | Start the Language Server (stdio) for IDE integration (completion, hover, diagnostics, go-to-definition) | |

## Server and other

| Command                  | Description                                                                         | Aliases               |
|--------------------------|-------------------------------------------------------------------------------------|-----------------------|
| `server`                 | Run in [server mode](./mode-server.md) with REST API and Web UI                     |                       |
| `print-license`          | Print the software license                                                          |                       |
| `quit`                   | Exit interactive mode                                                               | `exit`, `bye`, `x`, `q` |

See [CLI Cookbook](./cli-cookbook.md) for real examples of every command.
