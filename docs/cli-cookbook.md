# CLI Cookbook

Practical examples for every better-threagile command. Commands are shown with the binary called directly; when running via Docker, prepend `docker run --rm -v "$(pwd)":/work ghcr.io/threagile/threagile`.

---

## Core analysis

### Run a STRIDE analysis (default)

```bash
threagile analyze-model \
  --model Threat-model/threagile.yaml \
  --output /tmp/out
```

### Run a LINDDUN privacy analysis

```bash
threagile analyze-model \
  --model Threat-model/threagile.yaml \
  --output /tmp/out-linddun \
  --methodology linddun \
  --rule-pack linddun \
  --ignore-orphaned-risk-tracking
```

### Run a PASTA attack-surface analysis

```bash
threagile analyze-model \
  --model Threat-model/threagile.yaml \
  --output /tmp/out-pasta \
  --methodology pasta \
  --rule-pack pasta
```

### Run a VAST operational + application analysis

```bash
threagile analyze-model \
  --model Threat-model/threagile.yaml \
  --output /tmp/out-vast \
  --methodology vast \
  --rule-pack vast
```

### Skip specific rules

```bash
threagile analyze-model \
  --model threagile.yaml \
  --skip-risk-rules "unencrypted-asset,mixed-targets-on-shared-runtime"
```

### Load custom YAML rules from a directory

```bash
threagile analyze-model \
  --model threagile.yaml \
  --rules-dir ./my-custom-rules
```

### Load rules from a remote signed archive

```bash
threagile analyze-model \
  --model threagile.yaml \
  --rules-url "https://example.com/packs/appsec.tar.gz#sha256=abcdef1234&ttl=48h" \
  --rules-trusted-key "$(cat trusted-key.pub.b64)" \
  --rules-require-signed
```

---

## Model scaffolding and formatting

### Scaffold a new model interactively

```bash
threagile init
# Prompts: project title, author, first component name(s)
# Writes: threagile.yaml + feature_*.yaml per component
```

### Pretty-print / canonicalise a model

```bash
threagile fmt threagile.yaml

# Canonicalise multiple files in-place
threagile fmt Threat-model/*.yaml
```

### Create example or stub models

```bash
threagile create-example-model --output ./examples
threagile create-stub-model    --output ./my-project
```

---

## Validation and linting

### Validate model structure (fast, no rules)

```bash
threagile validate Threat-model/threagile.yaml
# Exit 0 → valid. Exit 1 → prints first structural error.
```

Common validation checks:
- Duplicate IDs across data assets, technical assets, trust boundaries
- Dangling references in `data_assets_processed`, `data_assets_stored`, etc.
- Unknown technology values
- Schema conformance

### Break a reference and see the error

```bash
# Temporarily corrupt a reference
sed 's/customer-accounts/customer-accounts-typo/' threagile.yaml > broken.yaml
threagile validate broken.yaml
# → error: data asset 'customer-accounts-typo' referenced but not defined
```

### Lint for style and best-practice issues

```bash
threagile lint Threat-model/threagile.yaml

# Machine-readable output
threagile lint Threat-model/threagile.yaml --json

# Auto-fix mechanical issues (e.g. missing tags_available entries)
threagile lint Threat-model/threagile.yaml --fix
```

Common lint warnings:
- Technical assets with no `description`
- Communication links missing `data_assets_sent`
- Trust boundaries containing only one asset
- Data assets not referenced by any technical asset

---

## Diffing and watching

### Show the risk delta between two model versions

```bash
threagile diff Threat-model/threagile.yaml Threat-model/threagile.yaml.proposed
# Output:
#   + 3 added risks (high: 2, medium: 1)
#   - 2 removed risks
#   = 31 unchanged risks
```

Diff with a specific methodology:

```bash
threagile diff old.yaml new.yaml --methodology linddun --rule-pack linddun
```

### Watch the model directory and re-analyze on every save

```bash
threagile watch --model-dir Threat-model/ --output /tmp/out
# Re-runs analyze-model whenever any .yaml in Threat-model/ changes.
# Ctrl-C to stop.
```

---

## Explaining risks

### Print a full explanation of a specific risk

```bash
threagile explain risk hardcoded-credentials@minio-storage \
  --model Threat-model/threagile.yaml
```

Output includes:
- Risk title and severity
- Rule description and detection logic
- The model facts that triggered it (asset, data, comm-link)
- Mitigation steps and ASVS / CWE references
- Current `risk_tracking` status if one exists

### List all risks with their IDs (for copy-pasting into explain)

```bash
threagile analyze-model --model threagile.yaml --output /tmp/out
cat /tmp/out/risks.json | jq '.[].synthetic_id'
```

---

## Rule packs

### List all available rule packs

```bash
threagile rule-pack list
# NAME         METHODOLOGY  KIND      DESCRIPTION
# linddun      linddun      embedded  LINDDUN privacy threat modeling — 8 rules ...
# pasta        pasta        embedded  PASTA attack-centric threat modeling — 9 rules ...
# vast         vast         embedded  VAST threat modeling — 8 rules ...
```

### Show details about a pack

```bash
threagile rule-pack show linddun
```

### Install (cache) a pack from the registry

```bash
threagile rule-pack install linddun
# Rule pack "linddun" is embedded and ready (8 rules).
```

### Run golden tests for a rule pack directory

```bash
threagile test-rules ./pkg/risks/methodologies/linddun --methodology linddun
# PASS unawareness-no-consent-technology
# PASS data-disclosure-pii-unencrypted-link
# ...
# All 8 rule test(s) passed.
```

Each test lives at `<rules-dir>/tests/<rule-id>/model.yaml` + `expected.json`. The test runner runs the single rule against its model and diffs the resulting synthetic IDs against `expected.json`. Failing tests exit non-zero — useful for blocking CI on a regression.

---

## Listing types and methodologies

### List supported methodologies and which rules cover each

```bash
threagile list-methodologies
```

### List all built-in risk rules

```bash
threagile list-risk-rules
```

### List all available model macros

```bash
threagile list-model-macros
```

### List all supported enum types

```bash
threagile list-types
```

---

## Macros

### Run the discover-attack-surface macro

Walks the model and prints a draft `threat_scenarios:` block for PASTA:

```bash
threagile execute-model-macro --model threagile.yaml --macro discover-attack-surface
```

### Seed risk tracking stubs

```bash
threagile execute-model-macro --model threagile.yaml --macro seed-risk-tracking
```

### Remove unused tags

```bash
threagile execute-model-macro --model threagile.yaml --macro remove-unused-tags
```

---

## CI/CD pipeline generation

### Generate a GitHub Actions workflow

```bash
threagile generate-ci \
  --target github \
  --output .github/workflows/threat-model.yml \
  --schedule "0 3 * * 1"   # every Monday at 03:00
```

### Generate a GitLab CI job

```bash
threagile generate-ci --target gitlab --output .gitlab-ci-threagile.yml
```

### Generate for Jenkins / Azure DevOps / generic shell

```bash
threagile generate-ci --target jenkins --output Jenkinsfile.threagile
threagile generate-ci --target azure   --output azure-pipelines-threagile.yml
threagile generate-ci --target generic --output run-threat-model.sh
```

All generated templates run `analyze-model` in a Docker container and fail the pipeline if any **critical** or **high** risks are unmitigated.

---

## Shell completion

### Install completions (one-time per shell)

```bash
# bash
threagile completion bash >> ~/.bashrc && source ~/.bashrc

# zsh (oh-my-zsh)
threagile completion zsh > "${fpath[1]}/_threagile"

# fish
threagile completion fish > ~/.config/fish/completions/threagile.fish
```

After installation, `threagile <Tab>` completes subcommands, flags, and (where the shell supports it) enum values.

---

## LSP / IDE integration

Start the Language Server (stdio transport, works with any LSP-capable editor):

```bash
threagile lsp
```

**VS Code** — add to `.vscode/settings.json`:

```json
{
  "yaml.customTags": [],
  "yaml.schemas": {
    "/path/to/schema.json": "threagile*.yaml"
  },
  "[yaml]": {
    "editor.defaultFormatter": "redhat.vscode-yaml"
  }
}
```

For full go-to-definition, hover, and inline diagnostics, point the editor's LSP client at the `threagile lsp` command. The server supports:

- **Completion** — asset IDs, enum values, technology names, tag names
- **Hover** — asset and tag descriptions
- **Diagnostics** — validates the model on every save (same checks as `threagile validate`)
- **Go-to-definition** — jump from a `data_assets_processed` ID to the asset declaration

---

## Server mode

```bash
threagile server --server-port 8080 --server-dir ./server
```

Key endpoints:

| Endpoint | Description |
|----------|-------------|
| `GET /meta/methodologies` | List supported methodologies |
| `GET /meta/risk-rules` | List all available risk rules |
| `GET /meta/model-macros` | List all model macros |
| `POST /direct/analyze` | Analyze an uploaded YAML or ZIP |
| `POST /direct/diff` | Risk delta between two JSON-encoded models |
| `POST /direct/check` | Validate model syntax |
| `GET /models/:id/risk-tracking-summary` | Status breakdown for a stored model |
| `POST /models/:id/explain-risk` | Full explanation of a specific risk |
| `GET /dashboard` | Web risk dashboard (upload YAML, choose methodology) |
| `GET /edit-model` | Interactive YAML editor with live diagram |

---

## Docker quick-start

```bash
# Pull latest
docker pull ghcr.io/threagile/threagile:latest

# Analyze
docker run --rm \
  -v "$(pwd)/Threat-model":/model \
  -v "$(pwd)/output":/output \
  ghcr.io/threagile/threagile:latest \
  analyze-model --model /model/threagile.yaml --output /output

# LINDDUN with embedded rule pack
docker run --rm \
  -v "$(pwd)/Threat-model":/model \
  -v "$(pwd)/output":/output \
  ghcr.io/threagile/threagile:latest \
  analyze-model \
    --model /model/threagile.yaml \
    --output /output \
    --methodology linddun \
    --rule-pack linddun
```
