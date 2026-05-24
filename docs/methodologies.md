# Threat Modeling Methodologies

better-threagile supports multiple threat-modeling methodologies selectable at analysis time.
The built-in rules remain STRIDE-only; other methodologies are loaded from **rule packs** that ship embedded in the binary or can be fetched from a URL.

## Choosing a methodology

```bash
threagile analyze-model \
  --model threagile.yaml \
  --methodology stride        # default; omit flag for identical behaviour

threagile analyze-model \
  --model threagile.yaml \
  --methodology linddun \
  --rule-pack linddun         # load the embedded LINDDUN rule pack

threagile analyze-model \
  --model threagile.yaml \
  --methodology pasta \
  --rule-pack pasta

threagile analyze-model \
  --model threagile.yaml \
  --methodology vast \
  --rule-pack vast
```

Rules whose `RiskCategory` carries no classification for the active methodology are silently skipped. A model that runs cleanly under STRIDE will always run cleanly under LINDDUN (it will simply produce zero findings until LINDDUN-aware fields and a LINDDUN rule pack are added).

List all supported methodologies and the rules that cover each:

```bash
threagile list-methodologies
```

---

## STRIDE (default)

STRIDE is the built-in methodology. No flag or rule pack is required.

**Classification categories:** Spoofing · Tampering · Repudiation · Information Disclosure · Denial of Service · Elevation of Privilege

**Rule count:** ~40 built-in Go rules + any script rules in `--rules-dir`.

**When to use:** General-purpose security threat modeling for application and infrastructure reviews. The STRIDE column in Excel output and the STRIDE chapter in the PDF report are populated automatically.

No schema changes are needed to use STRIDE — existing models work as-is.

---

## LINDDUN (privacy)

LINDDUN maps threats to privacy categories defined in the [LINDDUN framework](https://linddun.org). It is most useful for systems that process personal data subject to GDPR or similar regulations.

**Classification categories:** Linking · Identifying · Non-repudiation · Detecting · Data Disclosure · Unawareness · Non-compliance

**Rule pack:** `linddun` (embedded; no download needed)

```bash
threagile analyze-model --methodology linddun --rule-pack linddun --model threagile.yaml
```

### Schema additions

All fields below are **optional** — existing models continue to work without them.

#### `data_assets` additions

```yaml
data_assets:
  Customer Accounts:
    id: customer-accounts
    # ... existing fields ...

    # LINDDUN: privacy classification
    pii_categories:                 # PII categories contained in this asset
      - email
      - name
      - address
    data_subject_category: customer # employee | customer | minor | anonymous
    lawful_basis: contract          # consent | contract | legal_obligation |
                                    # vital_interest | public_task | legitimate_interest
    retention_period: "2 years"     # free-text; surfaced in the privacy report
    processing_purpose: "Order fulfilment and account management"
    cross_border_transfer: false    # true if data leaves the EU/EEA
```

#### `technical_assets` additions

```yaml
technical_assets:
  Customer API:
    id: customer-api
    # ... existing fields ...

    # LINDDUN: controller / processor role
    is_pii_controller: true   # asset determines purposes and means of processing
    is_pii_processor: false   # asset processes on behalf of a controller
    data_minimisation: true   # explicitly declare that only necessary data is collected
```

#### `communication_links` additions

```yaml
communication_links:
  API to Database:
    # ... existing fields ...
    cross_border: false   # true if link crosses a national/EU border
    audit_logged: true    # true if the link is fully audit-logged
```

### Included rules

| Rule ID | LINDDUN category | Trigger |
|---------|-----------------|---------|
| `unawareness-no-consent-technology` | Unawareness | PII processed with no consent-management component |
| `data-disclosure-pii-unencrypted-link` | Data Disclosure | PII sent over an unencrypted communication link |
| `detecting-no-audit-logging` | Detecting | PII-carrying link without `audit_logged: true` |
| `non-compliance-no-lawful-basis` | Non-compliance | Data asset with PII and no `lawful_basis` declared |
| `non-compliance-cross-border-transfer` | Non-compliance | `cross_border_transfer: true` without a safeguard |
| `identifying-pii-stored-unencrypted` | Identifying | PII stored in an asset with `encryption: none` |
| `linking-pii-multi-boundary` | Linking | Same data asset processed across multiple trust boundaries |
| `non-repudiation-missing-access-log` | Non-repudiation | PII-processing asset without audit logging on any inbound link |

### Expected report output

The LINDDUN report chapter replaces the STRIDE chapter and groups findings by LINDDUN category. The executive summary includes a **controller / processor map** listing which assets are data controllers and which are processors, and a **PII inventory** table derived from `pii_categories` fields.

---

## PASTA (attack-centric)

PASTA (Process for Attack Simulation and Threat Analysis) is a risk-centric methodology that maps threats to the seven stages of an attacker's kill chain.

**Classification stages:** Stage I Objectives · Stage II Scope · Stage III Decomposition · Stage IV Threat Analysis · Stage V Vulnerability Analysis · Stage VI Attack Modeling · Stage VII Risk Analysis

**Rule pack:** `pasta` (embedded; no download needed)

```bash
threagile analyze-model --methodology pasta --rule-pack pasta --model threagile.yaml
```

### Schema additions

#### `technical_assets` additions

```yaml
technical_assets:
  Customer API:
    id: customer-api
    # ... existing fields ...

    # PASTA: entry-point and attack-surface classification
    entry_point_type: api           # api | web_ui | cli | file_upload |
                                    # webhook | cron | internal_rpc
    attack_surface_exposure: internet  # internet | partner_vpn | internal_lan | air_gapped
    requires_authentication_strength: mfa  # none | mfa | hardware
```

#### `communication_links` additions

```yaml
communication_links:
  Customer Traffic:
    # ... existing fields ...
    rate_limited: true      # true if the link is protected by rate limiting
    tls_version: "1.3"      # minimum TLS version enforced
    api_style: rest         # rest | graphql | grpc | soap | websocket
```

#### `threat_scenarios` block (model-level)

PASTA supports explicitly modelled attack scenarios that rules can cross-reference:

```yaml
threat_scenarios:
  credential-stuffing:
    id: credential-stuffing
    title: "Credential Stuffing via Login API"
    actor_capabilities: script-kiddie   # script-kiddie | insider | nation-state
    entry_assets:
      - customer-api
    kill_chain_steps:
      - "Obtain leaked credential list"
      - "Automate login attempts against /auth/token"
      - "Harvest valid sessions"
    mitigated_by:
      - "rate-limiting on customer-api"
      - "multi-factor authentication"
```

### Included rules

| Rule ID | PASTA stage | Trigger |
|---------|-------------|---------|
| `undocumented-entry-point` | Stage III Decomposition | Internet-exposed asset with no `entry_point_type` |
| `no-rate-limiting-public-api` | Stage V Vulnerability Analysis | Public API endpoint without `rate_limited: true` |
| `weak-auth-high-value-target` | Stage VI Attack Modeling | Critical asset requiring only `none` authentication strength |
| `no-mitigation-internet-datastore` | Stage VII Risk Analysis | Datastore reachable from the internet without compensating controls |

### Expected report output

The PASTA report organises findings as chapters per stage. Each stage chapter lists its threats, the assets involved, and references the threat scenarios that exercise that stage. The Stage III chapter includes an auto-generated **entry point register** derived from `entry_point_type` fields.

---

## VAST (operational + application)

VAST (Visual, Agile, and Simple Threat) splits threats into two models: an **Application Threat Model** for development teams and an **Operational Threat Model** for operations teams. It is oriented around business processes, making findings directly relatable to business impact.

**Classification categories:** Application Threat · Operational Threat

**Rule pack:** `vast` (embedded; no download needed)

```bash
threagile analyze-model --methodology vast --rule-pack vast --model threagile.yaml
```

### Schema additions

#### `business_processes` block (model-level)

```yaml
business_processes:
  customer-checkout:
    id: customer-checkout
    title: "Customer Checkout"
    criticality: critical   # archive | operational | important | critical | mission-critical
    owner: "E-Commerce Team"
    supported_by_technical_assets:
      - customer-api
      - sql-database
      - payment-gateway
    data_assets_in_flight:
      - customer-accounts
      - customer-operational-data
```

#### `technical_assets` additions

```yaml
technical_assets:
  Customer API:
    id: customer-api
    # ... existing fields ...

    # VAST: back-reference to business processes this asset supports
    supported_business_processes:
      - customer-checkout
```

### Included rules

| Rule ID | VAST category | Trigger |
|---------|--------------|---------|
| `application-no-input-validation` | Application Threat | Custom-developed user-facing asset accepting JSON/XML/file without declared validation |
| `application-secrets-coupled` | Application Threat | Secrets shared across multiple technical assets |
| `operational-shared-runtime-critical-process` | Operational Threat | Shared runtime hosting a critical-business-process asset alongside lower-criticality assets |
| `operational-internet-reachable-datastore` | Operational Threat | Datastore directly reachable from the internet |

### Expected report output

The VAST report has two chapters: **Application Threat Model** and **Operational Threat Model**. Each chapter contains a **business process cross-reference table** listing which processes are affected by each finding, making it easy for business stakeholders to assess impact.

---

## OCTAVE and Trike

OCTAVE and Trike are recognised as valid `--methodology` values and can be used with custom rule packs loaded via `--rules-url` or `--rules-dir`. No built-in rule packs ship for these methodologies; use `--methodology octave --rules-dir ./my-octave-rules` with custom YAML script rules that declare `octave:` classifications.

---

## Custom methodologies

Set `--methodology custom` and supply rules via `--rules-dir` or `--rules-url`. Custom rules that do not declare a known methodology classification will still run — their findings appear under the generic "custom" category in reports.

---

## Rule pack management

```bash
# List embedded and remote packs
threagile rule-pack list

# Describe a specific pack
threagile rule-pack show linddun

# Install (or refresh) a remote pack into the local cache
threagile rule-pack install linddun

# Run the golden-test suite for a local rule directory
threagile test-rules ./my-rules --methodology linddun
```

Remote packs can be pinned by SHA256 and verified with Ed25519 signatures:

```bash
threagile analyze-model \
  --rules-url "https://example.com/packs/linddun.tar.gz#sha256=abc123...&ttl=168h" \
  --rules-trusted-key "base64pubkey==" \
  --rules-require-signed \
  --methodology linddun \
  --model threagile.yaml
```

Multiple `--rules-url` flags are accepted. A newline-delimited file of URLs is read with `--rules-url-file urls.txt`.
