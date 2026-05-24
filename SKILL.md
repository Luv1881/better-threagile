# better-threagile AI Skill Reference

This file is the authoritative guide for any AI agent working with this repository.
Read it entirely before writing or editing any threat model YAML, rule YAML, or running any analysis commands.

---

## 1. Project layout

```
better-threagile/
├── bin/threagile                          ← compiled binary (built with `go build -o bin/threagile ./cmd/threagile/`)
├── report/
│   ├── template/background.pdf           ← PDF report background template
│   └── threagile-logo.png                ← logo for PDF reports
├── pkg/risks/
│   ├── builtin/                           ← built-in Go risk rules (~40 rules)
│   ├── scripts/                           ← embedded YAML script rules (builtin, auto-loaded)
│   │   └── *.yaml
│   └── methodologies/
│       ├── linddun/                       ← LINDDUN rule sources
│       │   └── *.yaml
│       ├── linddun.tar.gz                 ← embedded tarball (go:embed)
│       ├── pasta/                         ← PASTA rule sources
│       │   └── *.yaml
│       ├── pasta.tar.gz                   ← embedded tarball
│       ├── vast/                          ← VAST rule sources
│       │   └── *.yaml
│       └── vast.tar.gz                    ← embedded tarball
├── pkg/types/                             ← all enum types and model structs
│   ├── technologies.yaml                  ← technology name → attribute mapping
│   └── *.go
└── support/
    └── schema.json                        ← JSON Schema for IDE autocompletion

# Companion threat model (VaultNote demo app):
../Threat-model/threagile/
├── threagile.yaml                         ← entry point
├── meta.yaml / overview.yaml / tags.yaml
├── feature_*.yaml                         ← one file per application layer
└── output/{stride,linddun,pasta,vast}/    ← analysis outputs
```

---

## 2. Build and run

```shell
# From repo root
go build -o bin/threagile ./cmd/threagile/
./bin/threagile --version

# After editing any YAML rule in pkg/risks/methodologies/<pack>/
cd pkg/risks/methodologies
tar -czf linddun.tar.gz linddun/   # if you edited linddun rules
tar -czf pasta.tar.gz   pasta/     # if you edited pasta rules
tar -czf vast.tar.gz    vast/      # if you edited vast rules
cd ../../..
go build -o bin/threagile ./cmd/threagile/
```

---

## 3. Running analysis — canonical commands

All commands are run from the `better-threagile/` root directory.

```shell
THREAGILE=./bin/threagile
MODEL=../Threat-model/threagile/threagile.yaml
APP=.

# STRIDE (default — 40+ built-in rules)
$THREAGILE analyze-model \
  --app-dir "$APP" \
  --background "report/template/background.pdf" \
  --reportLogoImagePath "report/threagile-logo.png" \
  --model "$MODEL" \
  --output ../Threat-model/threagile/output/stride \
  --methodology stride \
  --ignore-orphaned-risk-tracking

# LINDDUN (9 privacy rules)
$THREAGILE analyze-model --app-dir "$APP" --background "report/template/background.pdf" \
  --reportLogoImagePath "report/threagile-logo.png" \
  --model "$MODEL" --output ../Threat-model/threagile/output/linddun \
  --methodology linddun --rule-pack linddun --ignore-orphaned-risk-tracking

# PASTA (10 attack-surface rules)
$THREAGILE analyze-model --app-dir "$APP" --background "report/template/background.pdf" \
  --reportLogoImagePath "report/threagile-logo.png" \
  --model "$MODEL" --output ../Threat-model/threagile/output/pasta \
  --methodology pasta --rule-pack pasta --ignore-orphaned-risk-tracking

# VAST (8 operational rules)
$THREAGILE analyze-model --app-dir "$APP" --background "report/template/background.pdf" \
  --reportLogoImagePath "report/threagile-logo.png" \
  --model "$MODEL" --output ../Threat-model/threagile/output/vast \
  --methodology vast --rule-pack vast --ignore-orphaned-risk-tracking
```

**Always use `--ignore-orphaned-risk-tracking`** when the model contains cross-methodology `risk_tracking` entries (which VaultNote does). Without it, the run fails with errors on tracking entries for other methodologies.

---

## 4. Model entry point (`threagile.yaml`)

```yaml
threagile_version: 1.0.0   # always "1.0.0"

includes:                   # ordered list of feature YAML files to merge
  - meta.yaml
  - overview.yaml
  - tags.yaml
  - feature_frontend.yaml
  - feature_api.yaml
  - feature_datastores.yaml
  - feature_threats.yaml            # PASTA threat_scenarios (optional)
  - feature_business_processes.yaml # VAST business_processes (optional)
```

The includes are merged in order. All keys are merged recursively — no key may be defined twice across files or the parse will fail with a duplicate key error.

---

## 5. `meta.yaml` — model metadata

```yaml
title: "My Application Threat Model"
date: 2026-05-24          # ISO 8601 date

author:
  name: "Security Team"
  homepage: "https://example.com"   # optional

contributors:             # optional list
  - name: "Alice"
    homepage: ""
  - name: "Bob"

business_criticality: important   # archive | operational | important | critical | mission-critical
```

---

## 6. `overview.yaml` — documentation

```yaml
management_summary_comment: >
  One paragraph executive summary of the threat model.

business_overview:
  description: >
    Business context — what does this system do for the business?
  images: []

technical_overview:
  description: >
    Technical architecture summary.
  images: []
```

---

## 7. `tags.yaml` — available tags

```yaml
tags_available:
  - "nodejs"
  - "react"
  - "nginx"
  - "postgresql"
  - "redis"
  - "docker"
  - "jwt"
  - "tls-termination"
  - "intentional-misconfiguration"
  # suppression tags (add to technical assets to suppress specific rules):
  - "has-csp"              # suppresses missing-csp-header rule
  - "has-httponly-session" # suppresses pii-client-side-storage rule
```

Every tag used in a technical or data asset `tags: []` field must be registered here first.

---

## 8. Data assets — complete field reference

```yaml
data_assets:

  My Data Asset:
    id: my-data-asset          # kebab-case unique identifier, referenced by other assets

    description: >
      What this data is, who owns it, why it matters.

    usage: business            # business | devops

    tags: []                   # list of registered tags

    origin: customer           # free text — who creates this data

    owner: "Team Name"         # free text — who is responsible

    quantity: many             # very-few | few | many | very-many

    confidentiality: confidential
    # public | internal | restricted | confidential | strictly-confidential
    # Rule of thumb:
    #   public            — no sensitivity, freely shareable
    #   internal          — internal-only but no regulatory concern
    #   restricted        — limited distribution, some business sensitivity
    #   confidential      — regulated or contractually protected data
    #   strictly-confidential — PII, credentials, financial data, health records

    integrity: critical
    # archive | operational | important | critical | mission-critical
    # Rule of thumb:
    #   archive           — historical, no current operational use
    #   operational       — affects day-to-day operations if wrong
    #   important         — significant business impact if corrupted
    #   critical          — corruption causes serious harm or breach
    #   mission-critical  — corruption is catastrophic; safety-critical

    availability: operational
    # Same scale as integrity above

    justification_cia_rating: >
      Why these specific ratings were chosen.

    # ── LINDDUN privacy extensions (optional) ────────────────────────────────
    pii_categories: []
    # Any of: email-address | password-hash | session-identifier | name |
    #         phone-number | ip-address | location | health-data |
    #         financial-data | free-text-note-content | user-uploaded-file |
    #         government-id | biometric | device-identifier
    # Leave empty [] for non-personal data.

    data_subject_category: customer
    # customer | employee | minor | patient | public | partner | prospect

    lawful_basis: contract
    # consent | contract | legal-obligation | vital-interest |
    # public-task | legitimate-interest
    # Required under GDPR Article 6 when pii_categories is non-empty.

    processing_purpose: "Authentication and account management"
    # Free text — what the data is being processed for.

    retention_period: "duration of account + 30 days post-deletion"
    # Free text — how long data is retained.

    cross_border_transfer: false
    # true if this data crosses national/EU borders (triggers LINDDUN compliance rules)
```

**`has_pii` is computed automatically** — it is `true` when `pii_categories` is non-empty. LINDDUN rules use `{$model.data_assets.{id}.has_pii}` to check this.

---

## 9. Technical assets — complete field reference

```yaml
technical_assets:

  My Service:
    id: my-service              # kebab-case unique identifier

    description: >
      What this component does, its security significance.

    # ── Classification ───────────────────────────────────────────────────────
    type: process               # external-entity | process | datastore
    # external-entity  — browser, third-party system, end user
    # process          — application server, API, microservice, proxy
    # datastore        — database, cache, object store, file system

    usage: business             # business | devops

    used_as_client_by_human: false   # true for browser/desktop assets

    out_of_scope: false         # true to exclude from all risk generation
    justification_out_of_scope: ""

    # ── Sizing ───────────────────────────────────────────────────────────────
    size: service               # system | service | application | component

    # ── Technology ───────────────────────────────────────────────────────────
    technology: web-service-rest
    # Choose the BEST FIT from this list (aliases also accepted):
    #
    # Client-side:
    #   browser | mobile-app | desktop | devops-client | cli
    #
    # Web-facing:
    #   web-application | web-service-rest (alias: rest-api) | web-service-soap (alias: soap-api)
    #   web-server | reverse-proxy | load-balancer (alias: lb) | waf (alias: web-application-firewall)
    #   gateway | application-server (alias: app-server)
    #
    # Data storage:
    #   database (alias: db) | file-server (alias: file-storage) | local-file-system (alias: local-storage)
    #   search-index | search-engine | big-data-platform | data-lake | block-storage
    #   message-queue (alias: mq) | stream-processing
    #
    # Auth & security:
    #   identity-provider (alias: idp) | identity-store-database (alias: identity-store)
    #   identity-store-ldap | vault (alias: hashicorp-vault) | hsm (alias: hardware-security-module)
    #   ids (alias: intrusion-detection-system) | ips (alias: intrusion-prevention-system)
    #   consent-manager (alias: cookie-consent) | pii-processor (alias: data-processor)
    #
    # DevOps / infrastructure:
    #   build-pipeline (alias: ci) | sourcecode-repository (alias: git) | artifact-registry
    #   container-platform (alias: docker, kubernetes) | monitoring (alias: siem)
    #   service-mesh | service-registry (alias: service-discovery) | scheduler (alias: cron)
    #   code-inspection-platform (alias: code-analysis)
    #
    # Other:
    #   ai (alias: ml) | analytics-platform | batch-processing | cms | erp
    #   event-listener | function | library | mail-server | report-engine
    #   task (alias: job) | tool | iot-device | mainframe | unknown-technology

    tags: ["tag1", "tag2"]     # only registered tags_available values

    # ── Network ──────────────────────────────────────────────────────────────
    internet: false             # true = directly reachable from the internet

    machine: container          # physical | virtual | container | serverless

    encryption: none            # none | transparent | data-with-symmetric-shared-key |
                                # data-with-asymmetric-shared-key | data-with-end-user-individual-key

    # ── Ownership ────────────────────────────────────────────────────────────
    owner: "Team Name"

    # ── CIA ratings ──────────────────────────────────────────────────────────
    confidentiality: confidential        # same scale as data assets above
    integrity: critical
    availability: critical
    justification_cia_rating: >
      Why these ratings were chosen for the component itself.

    # ── Characteristics ──────────────────────────────────────────────────────
    multi_tenant: false         # true if this component serves multiple tenants
    redundant: false            # true if a redundant/HA deployment exists
    custom_developed_parts: true  # true for in-house code (triggers SAST rules)

    # ── LINDDUN extensions ───────────────────────────────────────────────────
    is_pii_processor: false     # true if this asset processes PII on behalf of the controller
    is_pii_controller: false    # true if this asset determines how/why PII is processed
    data_minimisation: false    # true if data minimisation has been verified

    # ── PASTA extensions ─────────────────────────────────────────────────────
    entry_point_type: ""        # api | web | grpc | mqtt | websocket | "" (empty = not an entry point)
    attack_surface_exposure: "" # internet | dmz | internal_lan | "" (empty for non-entry-points)

    # ── VAST extensions ──────────────────────────────────────────────────────
    supported_business_processes:   # list of business_process IDs this asset participates in
      - note-creation
      - auth-session

    # ── Data flows ───────────────────────────────────────────────────────────
    data_assets_processed:      # data assets this asset reads, writes, or transforms
      - my-data-asset
    data_assets_stored:         # data assets persisted at rest in this asset (datastores only)
      - my-data-asset
    data_formats_accepted:      # json | xml | serialization | file | csv | yaml
      - json

    # ── Communication links (outgoing) ───────────────────────────────────────
    communication_links:
      # (see Section 10)
```

---

## 10. Communication links — complete field reference

Each entry under a technical asset's `communication_links:` key describes **one outgoing connection** from that asset to another.

```yaml
    communication_links:

      Link Title:                         # human-readable name (used in diagram labels)
        target: other-asset-id            # id of the destination technical asset

        description: >
          What this link is for, any notable security properties.

        # ── Protocol ─────────────────────────────────────────────────────────
        protocol: https
        # Unencrypted:
        #   http | ws | reverse-proxy-web-protocol | mqtt
        #   jdbc | odbc | sql-access-protocol | nosql-access-protocol
        #   binary | text | ftp | ldap | jms | nfs | smb | xmpp
        #   iiop | jrmp | smtp | pop3 | imap
        # Encrypted (use these when TLS/SSH is present):
        #   https | wss | reverse-proxy-web-protocol-encrypted
        #   jdbc-encrypted | odbc-encrypted
        #   sql-access-protocol-encrypted | nosql-access-protocol-encrypted
        #   binary-encrypted | text-encrypted | smb-encrypted
        #   ssh | ssh-tunnel | ftps | sftp | scp | ldaps
        #   smtp-encrypted | pop3-encrypted | imap-encrypted
        #   iiop-encrypted | jrmp-encrypted
        # Process-local (no network risk):
        #   in-process-library-call | inter-process-communication
        #   local-file-access | container-spawning

        # ── Authentication / Authorization ────────────────────────────────────
        authentication: credentials
        # none | credentials | session-id | token | client-certificate |
        # two-factor | externalized

        authorization: technical-user
        # none | technical-user | end-user-identity-propagation

        # ── Link properties ───────────────────────────────────────────────────
        tags: []

        vpn: false              # true if this link runs through a VPN tunnel

        ip_filtered: false      # true if IP allowlisting is enforced

        readonly: false         # true if only reads (no writes) flow this direction

        usage: business         # business | devops
        # devops links get reduced likelihood in several rules and are
        # excluded from some checks entirely

        # ── PASTA extension ───────────────────────────────────────────────────
        rate_limited: false     # true once per-operation rate limiting is implemented
        api_style: rest         # rest | graphql | event-driven | rpc | "" (empty for non-API links)

        # ── LINDDUN extension ─────────────────────────────────────────────────
        audit_logged: false     # true when this link's PII access is audit-logged
        cross_border: false     # true if data crosses national/regulatory borders on this link

        # ── Data assets ───────────────────────────────────────────────────────
        data_assets_sent:       # data assets flowing FROM source TO target on this link
          - my-data-asset
        data_assets_received:   # data assets flowing FROM target TO source (responses)
          - my-data-asset

        # ── Diagram hints ─────────────────────────────────────────────────────
        diagram_tweak_weight: 1          # integer edge weight (higher = more prominent)
        diagram_tweak_constraint: false  # true to constrain this edge in layout
```

### Protocol selection guide

| Scenario | Correct protocol |
|---|---|
| Browser → server (HTTPS) | `https` |
| Nginx → backend (plain HTTP internal) | `http` |
| Nginx acting as reverse proxy (TLS) | `reverse-proxy-web-protocol-encrypted` |
| API → PostgreSQL (no TLS) | `sql-access-protocol` |
| API → PostgreSQL (TLS) | `sql-access-protocol-encrypted` |
| API → Redis (no TLS) | `nosql-access-protocol` |
| API → MinIO S3 (plain HTTP) | `http` |
| API → MinIO S3 (HTTPS) | `https` |
| SSH admin access | `ssh` |
| Internal function call / library | `in-process-library-call` |

---

## 11. Trust boundaries — complete field reference

```yaml
trust_boundaries:

  My Network:
    id: my-network                  # kebab-case unique identifier

    description: >
      What network / isolation boundary this represents.

    type: network-on-prem
    # network-on-prem                  — on-premises network segment (Docker bridge, VLAN)
    # network-dedicated-hoster         — dedicated hosted network
    # network-virtual-lan              — virtual LAN
    # network-cloud-provider           — cloud provider network (AWS VPC, GCP VPC)
    # network-cloud-security-group     — cloud security group / firewall rule
    # network-policy-namespace-isolation — Kubernetes NetworkPolicy namespace
    # execution-environment            — runtime process isolation (container, VM)

    tags: []

    technical_assets_inside:        # list of technical asset IDs inside this boundary
      - api-server
      - browser-spa

    trust_boundaries_nested: []     # list of trust boundary IDs nested inside this one
```

**Internet boundary**: Any technical asset with `internet: true` is implicitly on the internet side. No explicit trust boundary needed for the internet itself — just mark assets with `internet: true`.

---

## 12. Shared runtimes

```yaml
shared_runtimes:

  Docker Host:
    id: docker-host

    description: >
      All containers run on the same Docker host.

    tags: ["docker", "container-runtime"]

    technical_assets_running:       # ALL asset IDs sharing this runtime
      - nginx-proxy
      - api-server
      - postgresql-db
      - redis-cache
      - minio-storage
```

The `mixed-targets-on-shared-runtime` STRIDE rule fires when a shared runtime contains assets with very different sensitivity levels.

---

## 13. Business processes (VAST)

```yaml
business_processes:

  Note Creation and Storage:
    id: note-creation               # kebab-case identifier, referenced by technical assets

    title: "Note Creation and Storage"

    description: >
      What this business process does and its significance.

    criticality: critical           # archive | operational | important | critical | mission-critical

    owner: "Product Team"

    supported_by_technical_assets:  # list of technical asset IDs involved
      - api-server
      - postgresql-db

    data_assets_in_flight:          # data assets processed during this business process
      - note-content
```

Technical assets link back via `supported_business_processes: [note-creation]`.

---

## 14. Threat scenarios (PASTA)

```yaml
threat_scenarios:

  Credential Stuffing via Public API:
    id: cred-stuffing-scenario

    title: "Credential Stuffing Attack"

    description: >
      Automated attacker uses leaked username/password lists against the login endpoint.

    threat_actor: script-kiddie     # free text — script-kiddie | insider | nation-state | competitor

    entry_assets:                   # technical asset IDs that are entry points for this scenario
      - nginx-proxy

    kill_chain_steps:               # free text list of attack steps
      - "Acquire leaked credential list"
      - "Automate POST /auth/login requests"
      - "Collect valid sessions"

    mitigated_by:                   # technical asset IDs or control descriptions
      - "nginx-proxy (rate limiting)"
      - "api-server (authLimiter middleware)"
```

The PASTA `missing-threat-scenario` rule fires when an internet-facing asset with `entry_point_type` set has no matching threat scenario.

---

## 15. Risk tracking

```yaml
risk_tracking:

  # Format: <risk-category-id>@<technical-asset-id>
  # or for communication link risks: <risk-id>@<source-asset-id>@<target-asset-id>@<link-id>
  # Use * wildcard to match multiple synthetic IDs:

  unencrypted-asset@postgresql-db:
    status: accepted
    # unchecked | in-discussion | accepted | in-progress | mitigated | false-positive

    justification: >
      Explain WHY this status was chosen. Reference compensating controls or
      tickets for remediation. Required for accepted/mitigated/false-positive.

    ticket: PROJ-123            # optional — issue tracker reference

    date: 2026-04-15            # ISO 8601 date when this was reviewed

    checked_by: "Security Team" # who reviewed this risk

  # Wildcard example — covers all instances of a rule across assets:
  container-baseimage-backdooring@*:
    status: in-progress
    justification: >
      Image scanning via Trivy is being integrated into CI/CD pipeline.
    ticket: PROJ-456
    date: 2026-04-20
    checked_by: "DevOps Team"
```

### Risk status meaning

| Status | When to use |
|---|---|
| `unchecked` | Default — not yet reviewed |
| `in-discussion` | Under active discussion between teams |
| `accepted` | Risk accepted with documented justification and compensating controls |
| `in-progress` | Remediation is actively underway with a tracked ticket |
| `mitigated` | Control implemented and verified — risk no longer present |
| `false-positive` | Rule fired incorrectly — explain why in justification |

### Risk ID patterns for well-known rules

```
unencrypted-asset@{asset-id}
unencrypted-communication@{link-id}@{source-id}@{target-id}
sql-nosql-injection@{source-id}@{target-id}@{link-id}
missing-authentication@{asset-id}
missing-hardening@{asset-id}
container-baseimage-backdooring@{asset-id}
path-traversal@{source-id}@{target-id}@{link-id}
mixed-targets-on-shared-runtime@{shared-runtime-id}
missing-csp-header@{asset-id}
exposed-default-credentials@{asset-id}
# LINDDUN:
detecting-no-audit-logging@{asset-id}
linking-pii-multi-boundary@{asset-id}
data-disclosure-pii-unencrypted-link@{asset-id}
unawareness-no-consent-technology@{asset-id}
pii-client-side-storage@{asset-id}
# PASTA:
custom-development-no-sast@{asset-id}
no-rate-limiting-public-api@{asset-id}
per-operation-rate-limiting-missing@{asset-id}
# VAST:
operational-unmonitored-critical-process@{asset-id}
operational-critical-process-no-redundancy@{asset-id}
operational-shared-runtime-critical-process@{asset-id}
application-secrets-across-processes@{asset-id}
```

---

## 16. Suppression tags (add to technical asset `tags:`)

These tags suppress specific rules without using `risk_tracking`. Use them when the control is permanently in place.

| Tag | Suppresses |
|---|---|
| `has-csp` | `missing-csp-header` — CSP header verified in production |
| `has-httponly-session` | `pii-client-side-storage` — sessions use HttpOnly cookies |

---

## 17. Feature file pattern and split guidelines

Split the model into feature files by application layer. Each file owns exactly one layer's assets. The entry-point `threagile.yaml` just lists includes.

**Recommended feature file split:**

| File | Contents |
|---|---|
| `meta.yaml` | `title`, `date`, `author`, `contributors`, `business_criticality` |
| `overview.yaml` | `management_summary_comment`, `business_overview`, `technical_overview` |
| `tags.yaml` | `tags_available` |
| `feature_frontend.yaml` | Browser/client assets, CDN, Nginx, Internet/DMZ trust boundaries, frontend risk tracking |
| `feature_api.yaml` | API server, auth data assets (credentials, tokens), app-network trust boundary, API risk tracking |
| `feature_datastores.yaml` | All datastores (DB, cache, object store), shared runtime, data tier trust boundary, datastore risk tracking |
| `feature_threats.yaml` | `threat_scenarios` (PASTA) |
| `feature_business_processes.yaml` | `business_processes` (VAST) |

**Strict rules:**
- No key (data asset ID, technical asset ID, trust boundary ID) may appear in more than one file.
- Communication links live on the SOURCE asset's file (the asset that initiates the connection).
- `risk_tracking` entries live in the feature file that owns the most-relevant technical asset.
- `tags_available` must include every tag string used anywhere in the model.
- `data_assets_stored` should only be set on `datastore`-type assets; `data_assets_processed` applies to all types.

---

## 18. Writing YAML script rules

Place new built-in rules in `pkg/risks/scripts/`. Place methodology-specific rules in `pkg/risks/methodologies/<method>/` (then rebuild the tarball).

### Rule file structure

```yaml
id: my-rule-id               # kebab-case, unique across all rules
title: "Human-Readable Title"

# Methodology classification fields (use as applicable):
function: development        # development | architecture | operations | business-side
stride: tampering            # spoofing | tampering | repudiation | information-disclosure | denial-of-service | elevation-of-privilege
linddun: detecting           # linking | identifying | non-repudiation | detecting | data-disclosure | unawareness | non-compliance
pasta: stage-vuln-analysis   # stage-objectives | stage-scope | stage-decomposition | stage-threat-analysis | stage-vuln-analysis | stage-attack-modeling | stage-risk-analysis
vast: operational-threat     # operational-threat | application-threat
cwe: 693                     # CWE number

description: >
  Detailed description of what this risk is.

impact: >
  What happens if this risk is exploited.

asvs: "V14 - Configuration Verification Requirements"
cheat_sheet: https://cheatsheetseries.owasp.org/cheatsheets/...
action: Short imperative action to take
mitigation: >
  How to fix this.
check: >
  How to verify the fix is in place.
detection_logic: >
  What the rule checks for (human-readable).
risk_assessment: >
  How severity is assessed.
false_positives: >
  Conditions that cause false positives and how to suppress them.

risk:
  id:
    parameter: tech_asset    # the loop variable from match.parameter
    id: "{$risk.id}@{tech_asset.id}"

  data:
    parameter: tech_asset
    title: "<b>Rule Title</b>: <b>{tech_asset.title}</b> ..."
    severity: "calculate_severity(likely, medium)"
    exploitation_likelihood: likely     # unlikely | likely | very-likely | frequent
    exploitation_impact: medium         # low | medium | high | very-high
    data_breach_probability: possible   # improbable | possible | probable
    data_breach_technical_assets:
      - "{tech_asset.id}"
    most_relevant_technical_asset: "{tech_asset.id}"

  match:
    parameter: tech_asset
    do:
      # ... (see expression reference below)
```

### Expression reference (DSL)

All expressions live under `if:`, `any:`, `all:` conditions or inline in `loop:` bodies.

```yaml
# Boolean checks
- false: "{tech_asset.out_of_scope}"          # true if value is false/zero/empty
- true: "{tech_asset.custom_developed_parts}" # true if value is truthy

# Equality
- equal:
    first: "{link.usage}"
    second: devops
- not-equal:
    first: "{tech_asset.entry_point_type}"
    second: ""

# Comparisons (use as: to specify the enum type for ordering)
- equal-or-greater:
    as: confidentiality    # confidentiality | integrity | availability | criticality | ...
    first: "{$model.data_assets.{data_id}.confidentiality}"
    second: confidential

# List membership
- contains:
    item: intentional-misconfiguration
    in: "{tech_asset.tags}"
- contains:
    item: "{tech_asset.id}"
    in: "{scenario.entry_assets}"

# Compound logic
- and:
    - false: "{tech_asset.out_of_scope}"
    - true: "{tech_asset.custom_developed_parts}"
- or:
    - true: "{.attributes.reverse-proxy}"     # . = current iteration item
    - true: "{.attributes.web-application}"

# Iteration
- any:                               # true if ANY item matches
    in: "{tech_asset.technologies}"
    or:
      - true: "{.attributes.reverse-proxy}"
      - true: "{.attributes.web-application}"

- any:                               # with named item variable
    in: "{tech_asset.data_assets_processed}"
    item: data_id
    true: "{$model.data_assets.{data_id}.has_pii}"

- any:
    in: "{tech_asset.communication_links}"
    item: link
    and:
      - equal:
          first: "{link.rate_limited}"
          second: false
      - not-equal:
          first: "{link.usage}"
          second: devops

- all:                               # true if ALL items match
    in: "{tech_asset.communication_links}"
    item: link
    equal:
      first: "{link.audit_logged}"
      second: true

# Logical NOT — negate any bool expression (preferred over assign/loop pattern for tag absence)
- not:
    contains:
      item: has-csp
      in: "{tech_asset.tags}"

# Regex match — test a string value against a regular expression pattern
- regex-match:
    pattern: "(?i)password|secret|token"
    value: "{link.description}"

# Between — inclusive numeric or enum range check
- between:
    value: "{tech_asset.raa}"
    min: 50
    max: 100

- between:
    value: "{data_asset.confidentiality}"
    min: confidential
    max: strictly-confidential
    as: confidentiality

# Built-in string functions (usable in value expressions)
# lower("{tech_asset.id}"), upper("{tech_asset.id}"), trim("{s}"), len("{tech_asset.tags}")
- equal:
    first: "lower({tech_asset.id})"
    second: "api-server"

# Loop with assignment (legacy pattern — still works, use not: when simpler)
- assign:
    my_flag: false
- loop:
    in: "{tech_asset.tags}"
    item: tag
    do:
      - if:
          equal:
            first: "{tag}"
            second: has-csp
          then:
            - assign:
                my_flag: true
- if:
    false: "{my_flag}"    # fire the risk when flag was NOT set
    then:
      return: true

# Model-wide scan (loop over all assets to check for presence of something)
- assign:
    has_waf: false
- loop:
    in: "{$model.technical_assets}"
    item: other_asset
    do:
      - if:
          any:
            in: "{other_asset.technologies}"
            true: "{.attributes.waf}"
          then:
            - assign:
                has_waf: true
- if:
    false: "{has_waf}"
    then:
      return: true
```

### Accessing model paths in expressions

```
{tech_asset.id}                               # asset ID string
{tech_asset.title}                            # display name
{tech_asset.out_of_scope}                     # bool
{tech_asset.custom_developed_parts}           # bool
{tech_asset.internet}                         # bool
{tech_asset.machine}                          # physical | virtual | container | serverless
{tech_asset.confidentiality}                  # enum string
{tech_asset.tags}                             # []string
{tech_asset.technologies}                     # []Technology (iterate with any/all/loop)
{tech_asset.data_assets_processed}            # []string (data asset IDs)
{tech_asset.data_assets_stored}               # []string (data asset IDs)
{tech_asset.communication_links}              # []CommunicationLink
{tech_asset.supported_business_processes}     # []string (process IDs)

{.attributes.reverse-proxy}                   # technology attribute (inside technology iteration)
{.attributes.client}
{.attributes.waf}
{.attributes.traffic_forwarding}
{.attributes.file_storage}
{.attributes.vulnerable_to_query_injection}
{.attributes.storing_end_user_data}
{.attributes.build-pipeline}
{.attributes.sourcecode-repository}
{.attributes.consent_collector}

{link.protocol}                               # protocol string
{link.authentication}                         # auth string
{link.authorization}                          # authz string
{link.usage}                                  # business | devops
{link.vpn}                                    # bool
{link.rate_limited}                           # bool
{link.audit_logged}                           # bool
{link.cross_border}                           # bool
{link.data_assets_sent}                       # []string
{link.data_assets_received}                   # []string

{$model.data_assets.{data_id}.confidentiality}
{$model.data_assets.{data_id}.integrity}
{$model.data_assets.{data_id}.has_pii}        # computed bool: len(pii_categories) > 0
{$model.data_assets.{data_id}.pii_categories} # []string

{$model.technical_assets}                     # all assets (use in loop for model-wide scan)
{$model.threat_scenarios}                     # all threat scenarios
{$model.business_processes}                   # all business processes

{$risk.id}                                    # the rule's own ID (for constructing SyntheticId)
```

### Valid `calculate_severity` arguments

```
calculate_severity(<likelihood>, <impact>)

likelihood: unlikely | likely | very-likely | frequent
impact:     low | medium | high | very-high
```

---

## 19. Common patterns and anti-patterns

### Pattern: marking intentional misconfigurations

```yaml
# In technical asset:
tags: ["intentional-misconfiguration"]
```

The `exposed-default-credentials` builtin rule fires on any asset with this tag that also stores confidential data. Use it for demo/dev environments with hardcoded credentials. Remove the tag once credentials are rotated.

### Pattern: cross-methodology risk tracking

When a model covers multiple methodologies, use one `risk_tracking` block per feature file and include entries for all relevant methodologies. Always run with `--ignore-orphaned-risk-tracking` so each single-methodology run silently skips the other methodologies' tracking entries.

```yaml
risk_tracking:
  # STRIDE risks
  unencrypted-asset@my-datastore:
    status: accepted
    justification: Production uses disk encryption. Demo environment accepted.
    ticket: PROJ-001
    date: 2026-04-01
    checked_by: Security Team

  # LINDDUN risks (orphaned in STRIDE run, active in LINDDUN run)
  detecting-no-audit-logging@my-datastore:
    status: in-progress
    justification: Audit logging is being implemented per PROJ-002.
    ticket: PROJ-002
    date: 2026-04-15
    checked_by: Security Team

  # PASTA risks
  custom-development-no-sast@my-service:
    status: in-progress
    justification: Semgrep integration in progress per PROJ-003.
    ticket: PROJ-003
    date: 2026-04-20
    checked_by: DevOps Team
```

### Pattern: browser SPA with JWT

A React/Angular/Vue SPA that stores JWT in localStorage needs:

```yaml
# Browser SPA asset
Browser SPA:
  id: browser-spa
  type: external-entity
  technology: browser
  used_as_client_by_human: true
  internet: true
  machine: physical
  # DO NOT add has-httponly-session unless you verified HttpOnly cookies are used
  data_assets_processed:
    - session-tokens
    - user-credentials
```

This will trigger:
- `pii-client-side-storage` (LINDDUN) — browser processes PII without HttpOnly session
- `missing-authentication-second-factor` (STRIDE) — no MFA on a browser client

Once HttpOnly cookies are implemented, add `has-httponly-session` to the asset's tags.

### Pattern: Docker internal network

Mark all container-to-container communication links with the unencrypted protocol and `authentication: credentials`. The `unencrypted-communication` rule will elevate these to `likelihood=likely` because both endpoints are containers (even within the same trust boundary).

```yaml
PostgreSQL Connection:
  target: postgresql-db
  protocol: sql-access-protocol   # NOT sql-access-protocol-encrypted unless TLS is configured
  authentication: credentials
  authorization: technical-user
  audit_logged: false
  rate_limited: false
```

### Pattern: datastore that stores user files

For object stores (MinIO, S3, GCS):

```yaml
My Object Store:
  id: my-object-store
  type: datastore
  technology: file-server          # NOT database — avoids false-positive SQL injection
  encryption: none                 # or transparent/data-with-symmetric-shared-key
  data_assets_stored:
    - file-attachments             # must have integrity >= critical to trigger unencrypted-asset
```

Set `integrity: critical` (not `important`) on file data assets if you want `unencrypted-asset` to fire. The rule threshold is `confidentiality >= confidential AND integrity >= critical`.

### Anti-pattern: wrong technology for object store

```yaml
# WRONG — triggers false-positive SQL injection risk:
technology: database

# CORRECT — file-server has file_storage attribute, excluded from injection rules:
technology: file-server
```

### Anti-pattern: forgetting `data_assets_stored` on datastores

`unencrypted-asset` only fires if `data_assets_stored` is non-empty. The `data_assets_processed` list alone is insufficient to trigger storage-related rules.

---

## 20. Validation and debugging

```shell
# Validate model syntax
./bin/threagile validate --model ../Threat-model/threagile/threagile.yaml

# Lint (check for model quality issues)
./bin/threagile lint --model ../Threat-model/threagile/threagile.yaml

# List all registered risk rules (builtin + script)
./bin/threagile list risk-rules

# List all rule packs
./bin/threagile rule-pack list

# Describe a specific pack
./bin/threagile rule-pack describe linddun
./bin/threagile rule-pack describe pasta
./bin/threagile rule-pack describe vast

# List all enum values usable in YAML
./bin/threagile list types

# Run with verbose output to see risk generation details
./bin/threagile analyze-model ... --verbose
```

### Reading orphaned risk tracking warnings

```
Risk tracking references unknown risk (risk id not found): detecting-no-audit-logging@api-server
```

This warning appears when a `risk_tracking` entry exists but the rule did not generate a matching risk. Common causes:

1. **Cross-methodology** — running STRIDE but the entry is for a LINDDUN rule. Expected; use `--ignore-orphaned-risk-tracking`.
2. **Rule condition not met** — the asset doesn't meet the rule's trigger conditions. Check the rule's `detection_logic` and verify the asset's fields.
3. **Wrong synthetic ID** — the `@asset-id` suffix doesn't match any generated risk. Check for typos in asset IDs.
4. **Asset out of scope** — `out_of_scope: true` on the asset suppresses all risks.

---

## 21. Checklist for writing a new threat model

- [ ] All data assets have `pii_categories` set (even if empty `[]`)
- [ ] All data assets that store credentials have `confidentiality: strictly-confidential` and `integrity: critical`
- [ ] All technical assets have `machine:` set correctly (physical/virtual/container/serverless)
- [ ] All datastores have `data_assets_stored:` populated (not just `data_assets_processed:`)
- [ ] Object stores use `technology: file-server`, not `technology: database`
- [ ] Communication links use the correct protocol — unencrypted where TLS is absent
- [ ] `rate_limited: false` on links where no per-operation rate limiting exists
- [ ] `audit_logged: false` on links where PII flows aren't individually logged
- [ ] Browser/SPA assets have `used_as_client_by_human: true` and `type: external-entity`
- [ ] Every tag in `tags: [...]` fields is listed in `tags_available`
- [ ] `custom_developed_parts: true` on in-house code (triggers SAST rules)
- [ ] `is_pii_processor: true` / `is_pii_controller: true` set correctly on LINDDUN-relevant assets
- [ ] Business processes have `criticality:` set and `supported_by_technical_assets:` populated
- [ ] Technical assets reference back via `supported_business_processes:` with matching IDs
- [ ] `risk_tracking` entries use exact synthetic IDs from the generated `risks.json`
- [ ] Model runs cleanly (only orphaned risk tracking warnings, no parse errors) with `--ignore-orphaned-risk-tracking`
