# Threat Model Report

**Model:** Some Example Application  
**Generated:** <normalized>
**Author:** John Doe  

---

## Summary

| Severity | Count |
|---|---|
| 🟠 High | 2 |
| 🟡 Elevated | 28 |
| 🔵 Medium | 31 |
| ⚪ Low | 4 |
| **Total** | **65** |

## Findings

### [HIGH] SQL/NoSQL-Injection risk at Backoffice ERP System against database Customer Contract Database via Database Traffic

- **ID:** `sql-nosql-injection@erp-system@sql-database@erp-system>database-traffic`
- **Category:** `sql-nosql-injection`
- **Impact:** high
- **Likelihood:** very-likely
- **Asset:** Backoffice ERP System
- **Data Breach Scope:** Customer Contract Database

### [HIGH] XML External Entity (XXE) risk at Backoffice ERP System

- **ID:** `xml-external-entity@erp-system`
- **Category:** `xml-external-entity`
- **Impact:** high
- **Likelihood:** very-likely
- **Asset:** Backoffice ERP System
- **Data Breach Scope:** Backoffice ERP System

### [ELEVATED] Lateral Movement via Credential Reuse from Jenkins Build Server authenticating across 2 trust zones

- **ID:** `lateral-movement-credential-reuse@jenkins-build-server`
- **Category:** `lateral-movement-credential-reuse`
- **Impact:** high
- **Likelihood:** likely
- **Asset:** Jenkins Build Server
- **Data Breach Scope:** Apache Webserver

### [ELEVATED] Lateral Movement via Shared Runtime on WebApp and Backoffice Virtualization: assets from 2 trust zones co-located

- **ID:** `lateral-movement-shared-runtime@webapp-virtualization`
- **Category:** `lateral-movement-shared-runtime`
- **Impact:** high
- **Likelihood:** likely
- **Asset:** Backoffice ERP System
- **Data Breach Scope:** Backoffice ERP System

### [ELEVATED] LDAP-Injection risk at Identity Provider against LDAP server LDAP Auth Server via LDAP Credential Check Traffic

- **ID:** `ldap-injection@identity-provider@ldap-auth-server@identity-provider>ldap-credential-check-traffic`
- **Category:** `ldap-injection`
- **Impact:** high
- **Likelihood:** likely
- **Asset:** Identity Provider
- **Data Breach Scope:** LDAP Auth Server

### [ELEVATED] LDAP-Injection risk at Marketing CMS against LDAP server LDAP Auth Server via Auth Traffic

- **ID:** `ldap-injection@marketing-cms@ldap-auth-server@marketing-cms>auth-traffic`
- **Category:** `ldap-injection`
- **Impact:** high
- **Likelihood:** likely
- **Asset:** Marketing CMS
- **Data Breach Scope:** LDAP Auth Server

### [ELEVATED] Missing Authentication covering communication link NFS Filesystem Access from Backoffice ERP System to Contract File Server

- **ID:** `missing-authentication@erp-system>nfs-filesystem-access@erp-system@contract-file-server`
- **Category:** `missing-authentication`
- **Impact:** medium
- **Likelihood:** likely
- **Asset:** Contract File Server
- **Data Breach Scope:** Contract File Server

### [ELEVATED] Missing Authentication covering communication link CMS Content Traffic from Load Balancer to Marketing CMS

- **ID:** `missing-authentication@load-balancer>cms-content-traffic@load-balancer@marketing-cms`
- **Category:** `missing-authentication`
- **Impact:** medium
- **Likelihood:** likely
- **Asset:** Marketing CMS
- **Data Breach Scope:** Marketing CMS

### [ELEVATED] Missing Cloud Hardening (EC2) risk at Apache Webserver: CIS Benchmark for Amazon Linux

- **ID:** `missing-cloud-hardening@apache-webserver@ec2`
- **Category:** `missing-cloud-hardening`
- **Impact:** very-high
- **Likelihood:** unlikely
- **Data Breach Scope:** Apache Webserver

### [ELEVATED] Missing Cloud Hardening (AWS) risk at Application Network: CIS Benchmark for AWS

- **ID:** `missing-cloud-hardening@application-network@aws`
- **Category:** `missing-cloud-hardening`
- **Impact:** very-high
- **Likelihood:** unlikely
- **Data Breach Scope:** Load Balancer, Apache Webserver, Marketing CMS, Backoffice ERP System, Contract File Server, Customer Contract Database, Identity Provider, LDAP Auth Server

### [ELEVATED] Missing Cloud Hardening risk at ERP DMZ

- **ID:** `missing-cloud-hardening@erp-dmz`
- **Category:** `missing-cloud-hardening`
- **Impact:** very-high
- **Likelihood:** unlikely
- **Data Breach Scope:** Backoffice ERP System, Contract File Server, Customer Contract Database

### [ELEVATED] Missing Cloud Hardening risk at Web DMZ

- **ID:** `missing-cloud-hardening@web-dmz`
- **Category:** `missing-cloud-hardening`
- **Impact:** very-high
- **Likelihood:** unlikely
- **Data Breach Scope:** Apache Webserver, Marketing CMS

### [ELEVATED] Missing Cloud Hardening risk at WebApp and Backoffice Virtualization

- **ID:** `missing-cloud-hardening@webapp-virtualization`
- **Category:** `missing-cloud-hardening`
- **Impact:** very-high
- **Likelihood:** unlikely
- **Data Breach Scope:** Apache Webserver, Marketing CMS, Backoffice ERP System, Contract File Server, Customer Contract Database

### [ELEVATED] Missing File Validation risk at Apache Webserver

- **ID:** `missing-file-validation@apache-webserver`
- **Category:** `missing-file-validation`
- **Impact:** medium
- **Likelihood:** very-likely
- **Asset:** Apache Webserver
- **Data Breach Scope:** Apache Webserver

### [ELEVATED] Missing Hardening risk at Apache Webserver

- **ID:** `missing-hardening@apache-webserver`
- **Category:** `missing-hardening`
- **Impact:** medium
- **Likelihood:** likely
- **Asset:** Apache Webserver
- **Data Breach Scope:** Apache Webserver

### [ELEVATED] Missing Hardening risk at Backoffice ERP System

- **ID:** `missing-hardening@erp-system`
- **Category:** `missing-hardening`
- **Impact:** medium
- **Likelihood:** likely
- **Asset:** Backoffice ERP System
- **Data Breach Scope:** Backoffice ERP System

### [ELEVATED] Missing Hardening risk at Identity Provider

- **ID:** `missing-hardening@identity-provider`
- **Category:** `missing-hardening`
- **Impact:** medium
- **Likelihood:** likely
- **Asset:** Identity Provider
- **Data Breach Scope:** Identity Provider

### [ELEVATED] Missing Hardening risk at Jenkins Build Server

- **ID:** `missing-hardening@jenkins-build-server`
- **Category:** `missing-hardening`
- **Impact:** medium
- **Likelihood:** likely
- **Asset:** Jenkins Build Server
- **Data Breach Scope:** Jenkins Build Server

### [ELEVATED] Missing Hardening risk at LDAP Auth Server

- **ID:** `missing-hardening@ldap-auth-server`
- **Category:** `missing-hardening`
- **Impact:** medium
- **Likelihood:** likely
- **Asset:** LDAP Auth Server
- **Data Breach Scope:** LDAP Auth Server

### [ELEVATED] Missing Hardening risk at Customer Contract Database

- **ID:** `missing-hardening@sql-database`
- **Category:** `missing-hardening`
- **Impact:** medium
- **Likelihood:** likely
- **Asset:** Customer Contract Database
- **Data Breach Scope:** Customer Contract Database

### [ELEVATED] Path-Traversal risk at Backoffice ERP System against filesystem Contract File Server via NFS Filesystem Access

- **ID:** `path-traversal@erp-system@contract-file-server@erp-system>nfs-filesystem-access`
- **Category:** `path-traversal`
- **Impact:** medium
- **Likelihood:** very-likely
- **Asset:** Backoffice ERP System
- **Data Breach Scope:** Contract File Server

### [ELEVATED] Server-Side Request Forgery (SSRF) risk at Apache Webserver server-side web-requesting the target Backoffice ERP System via ERP System Traffic

- **ID:** `server-side-request-forgery@apache-webserver@erp-system@apache-webserver>erp-system-traffic`
- **Category:** `server-side-request-forgery`
- **Impact:** medium
- **Likelihood:** likely
- **Asset:** Apache Webserver
- **Data Breach Scope:** Apache Webserver, Marketing CMS

### [ELEVATED] Server-Side Request Forgery (SSRF) risk at Apache Webserver server-side web-requesting the target Identity Provider via Auth Credential Check Traffic

- **ID:** `server-side-request-forgery@apache-webserver@identity-provider@apache-webserver>auth-credential-check-traffic`
- **Category:** `server-side-request-forgery`
- **Impact:** medium
- **Likelihood:** likely
- **Asset:** Apache Webserver
- **Data Breach Scope:** Apache Webserver, Marketing CMS

### [ELEVATED] Unencrypted Communication named Web Application Traffic between Load Balancer and Apache Webserver transferring authentication data (like credentials, token, session-id, etc.)

- **ID:** `unencrypted-communication@load-balancer>web-application-traffic@load-balancer@apache-webserver`
- **Category:** `unencrypted-communication`
- **Impact:** high
- **Likelihood:** likely
- **Asset:** Load Balancer
- **Data Breach Scope:** Apache Webserver

### [ELEVATED] Unencrypted Communication named Auth Traffic between Marketing CMS and LDAP Auth Server transferring authentication data (like credentials, token, session-id, etc.)

- **ID:** `unencrypted-communication@marketing-cms>auth-traffic@marketing-cms@ldap-auth-server`
- **Category:** `unencrypted-communication`
- **Impact:** high
- **Likelihood:** likely
- **Asset:** Marketing CMS
- **Data Breach Scope:** LDAP Auth Server

### [ELEVATED] Unguarded Access from Internet of Git Repository by External Development Client via Git-Repo Code Write Access

- **ID:** `unguarded-access-from-internet@git-repo@external-dev-client@external-dev-client>git-repo-code-write-access`
- **Category:** `unguarded-access-from-internet`
- **Impact:** medium
- **Likelihood:** very-likely
- **Asset:** Git Repository
- **Data Breach Scope:** Git Repository

### [ELEVATED] Unguarded Access from Internet of Git Repository by External Development Client via Git-Repo Web-UI Access

- **ID:** `unguarded-access-from-internet@git-repo@external-dev-client@external-dev-client>git-repo-web-ui-access`
- **Category:** `unguarded-access-from-internet`
- **Impact:** medium
- **Likelihood:** very-likely
- **Asset:** Git Repository
- **Data Breach Scope:** Git Repository

### [ELEVATED] Unguarded Access from Internet of Jenkins Build Server by External Development Client via Jenkins Web-UI Access

- **ID:** `unguarded-access-from-internet@jenkins-build-server@external-dev-client@external-dev-client>jenkins-web-ui-access`
- **Category:** `unguarded-access-from-internet`
- **Impact:** medium
- **Likelihood:** very-likely
- **Asset:** Jenkins Build Server
- **Data Breach Scope:** Jenkins Build Server

### [ELEVATED] Untrusted Deserialization risk at Backoffice ERP System

- **ID:** `untrusted-deserialization@erp-system`
- **Category:** `untrusted-deserialization`
- **Impact:** very-high
- **Likelihood:** likely
- **Asset:** Backoffice ERP System
- **Data Breach Scope:** Backoffice ERP System

### [ELEVATED] Untrusted Deserialization risk at Jenkins Build Server

- **ID:** `untrusted-deserialization@jenkins-build-server`
- **Category:** `untrusted-deserialization`
- **Impact:** very-high
- **Likelihood:** likely
- **Asset:** Jenkins Build Server
- **Data Breach Scope:** Jenkins Build Server

### [MEDIUM] Accidental Secret Leak(Git) risk at Git Repository: Git Leak Prevention

- **ID:** `accidental-secret-leak@git-repo`
- **Category:** `accidental-secret-leak`
- **Impact:** high
- **Likelihood:** unlikely
- **Asset:** Git Repository
- **Data Breach Scope:** Git Repository

### [MEDIUM] Code Backdooring risk at Git Repository

- **ID:** `code-backdooring@git-repo`
- **Category:** `code-backdooring`
- **Impact:** high
- **Likelihood:** unlikely
- **Asset:** Git Repository
- **Data Breach Scope:** Git Repository

### [MEDIUM] Code Backdooring risk at Jenkins Build Server

- **ID:** `code-backdooring@jenkins-build-server`
- **Category:** `code-backdooring`
- **Impact:** high
- **Likelihood:** unlikely
- **Asset:** Jenkins Build Server
- **Data Breach Scope:** Apache Webserver, Jenkins Build Server, Marketing CMS

### [MEDIUM] Container Base Image Backdooring risk at Apache Webserver

- **ID:** `container-baseimage-backdooring@apache-webserver`
- **Category:** `container-baseimage-backdooring`
- **Impact:** high
- **Likelihood:** unlikely
- **Asset:** Apache Webserver
- **Data Breach Scope:** Apache Webserver

### [MEDIUM] Container Base Image Backdooring risk at Marketing CMS

- **ID:** `container-baseimage-backdooring@marketing-cms`
- **Category:** `container-baseimage-backdooring`
- **Impact:** high
- **Likelihood:** unlikely
- **Asset:** Marketing CMS
- **Data Breach Scope:** Marketing CMS

### [MEDIUM] Transitive Lateral Movement via bridge Apache Webserver → high-trust target Backoffice ERP System

- **ID:** `lateral-movement-transitive-access@apache-webserver@erp-system`
- **Category:** `lateral-movement-transitive-access`
- **Impact:** high
- **Likelihood:** unlikely
- **Asset:** Apache Webserver
- **Data Breach Scope:** Backoffice ERP System

### [MEDIUM] Missing Two-Factor Authentication covering communication link DB Update Access from Backend Admin Client to Customer Contract Database

- **ID:** `missing-authentication-second-factor@backend-admin-client>db-update-access@backend-admin-client@sql-database`
- **Category:** `missing-authentication-second-factor`
- **Impact:** medium
- **Likelihood:** unlikely
- **Asset:** Customer Contract Database
- **Data Breach Scope:** Customer Contract Database

### [MEDIUM] Missing Two-Factor Authentication covering communication link ERP Web Access from Backend Admin Client to Backoffice ERP System

- **ID:** `missing-authentication-second-factor@backend-admin-client>erp-web-access@backend-admin-client@erp-system`
- **Category:** `missing-authentication-second-factor`
- **Impact:** medium
- **Likelihood:** unlikely
- **Asset:** Backoffice ERP System
- **Data Breach Scope:** Backoffice ERP System

### [MEDIUM] Missing Two-Factor Authentication covering communication link User Management Access from Backend Admin Client to LDAP Auth Server

- **ID:** `missing-authentication-second-factor@backend-admin-client>user-management-access@backend-admin-client@ldap-auth-server`
- **Category:** `missing-authentication-second-factor`
- **Impact:** medium
- **Likelihood:** unlikely
- **Asset:** LDAP Auth Server
- **Data Breach Scope:** LDAP Auth Server

### [MEDIUM] Missing Two-Factor Authentication covering communication link ERP Internal Access from Backoffice Client to Backoffice ERP System

- **ID:** `missing-authentication-second-factor@backoffice-client>erp-internal-access@backoffice-client@erp-system`
- **Category:** `missing-authentication-second-factor`
- **Impact:** medium
- **Likelihood:** unlikely
- **Asset:** Backoffice ERP System
- **Data Breach Scope:** Backoffice ERP System

### [MEDIUM] Missing Two-Factor Authentication covering communication link Git-Repo Code Write Access from External Development Client to Git Repository

- **ID:** `missing-authentication-second-factor@external-dev-client>git-repo-code-write-access@external-dev-client@git-repo`
- **Category:** `missing-authentication-second-factor`
- **Impact:** medium
- **Likelihood:** unlikely
- **Asset:** Git Repository
- **Data Breach Scope:** Git Repository

### [MEDIUM] Missing Two-Factor Authentication covering communication link Git-Repo Web-UI Access from External Development Client to Git Repository

- **ID:** `missing-authentication-second-factor@external-dev-client>git-repo-web-ui-access@external-dev-client@git-repo`
- **Category:** `missing-authentication-second-factor`
- **Impact:** medium
- **Likelihood:** unlikely
- **Asset:** Git Repository
- **Data Breach Scope:** Git Repository

### [MEDIUM] Missing Two-Factor Authentication covering communication link Jenkins Web-UI Access from External Development Client to Jenkins Build Server

- **ID:** `missing-authentication-second-factor@external-dev-client>jenkins-web-ui-access@external-dev-client@jenkins-build-server`
- **Category:** `missing-authentication-second-factor`
- **Impact:** medium
- **Likelihood:** unlikely
- **Asset:** Jenkins Build Server
- **Data Breach Scope:** Jenkins Build Server

### [MEDIUM] Missing Two-Factor Authentication covering communication link CMS Content Traffic from Customer Web Client forwarded via Load Balancer to Marketing CMS

- **ID:** `missing-authentication-second-factor@load-balancer>cms-content-traffic@load-balancer@marketing-cms`
- **Category:** `missing-authentication-second-factor`
- **Impact:** medium
- **Likelihood:** unlikely
- **Asset:** Marketing CMS
- **Data Breach Scope:** Marketing CMS

### [MEDIUM] Missing Two-Factor Authentication covering communication link Web Application Traffic from Customer Web Client forwarded via Load Balancer to Apache Webserver

- **ID:** `missing-authentication-second-factor@load-balancer>web-application-traffic@load-balancer@apache-webserver`
- **Category:** `missing-authentication-second-factor`
- **Impact:** medium
- **Likelihood:** unlikely
- **Asset:** Apache Webserver
- **Data Breach Scope:** Apache Webserver

### [MEDIUM] Missing Cloud Hardening (S3) risk at Contract File Server: Security Best Practices for AWS S3

- **ID:** `missing-cloud-hardening@contract-file-server@s3`
- **Category:** `missing-cloud-hardening`
- **Impact:** high
- **Likelihood:** unlikely
- **Data Breach Scope:** Contract File Server

### [MEDIUM] Missing End User Identity Propagation over communication link ERP System Traffic from Apache Webserver to Backoffice ERP System

- **ID:** `missing-identity-propagation@apache-webserver>erp-system-traffic@apache-webserver@erp-system`
- **Category:** `missing-identity-propagation`
- **Impact:** medium
- **Likelihood:** unlikely
- **Asset:** Backoffice ERP System
- **Data Breach Scope:** Backoffice ERP System

### [MEDIUM] Missing Vault (Secret Storage) in the threat model (referencing asset Backoffice ERP System as an example)

- **ID:** `missing-vault@erp-system`
- **Category:** `missing-vault`
- **Impact:** medium
- **Likelihood:** unlikely
- **Asset:** Backoffice ERP System

### [MEDIUM] Mixed Targets on Shared Runtime named WebApp and Backoffice Virtualization might enable attackers moving from one less valuable target to a more valuable one

- **ID:** `mixed-targets-on-shared-runtime@webapp-virtualization`
- **Category:** `mixed-targets-on-shared-runtime`
- **Impact:** medium
- **Likelihood:** unlikely
- **Data Breach Scope:** Apache Webserver, Marketing CMS, Backoffice ERP System, Contract File Server, Customer Contract Database

### [MEDIUM] Push instead of Pull Deployment at Marketing CMS via build pipeline asset Jenkins Build Server

- **ID:** `push-instead-of-pull-deployment@jenkins-build-server`
- **Category:** `push-instead-of-pull-deployment`
- **Impact:** medium
- **Likelihood:** unlikely
- **Asset:** Marketing CMS
- **Data Breach Scope:** Marketing CMS

### [MEDIUM] Unchecked Deployment risk at External Development Client

- **ID:** `unchecked-deployment@external-dev-client`
- **Category:** `unchecked-deployment`
- **Impact:** medium
- **Likelihood:** unlikely
- **Asset:** External Development Client
- **Data Breach Scope:** External Development Client, Git Repository, Jenkins Build Server

### [MEDIUM] Unchecked Deployment risk at Jenkins Build Server

- **ID:** `unchecked-deployment@jenkins-build-server`
- **Category:** `unchecked-deployment`
- **Impact:** medium
- **Likelihood:** unlikely
- **Asset:** Jenkins Build Server
- **Data Breach Scope:** Apache Webserver, Jenkins Build Server, Marketing CMS

### [MEDIUM] Unencrypted Technical Asset named Apache Webserver

- **ID:** `unencrypted-asset@apache-webserver`
- **Category:** `unencrypted-asset`
- **Impact:** high
- **Likelihood:** unlikely
- **Asset:** Apache Webserver
- **Data Breach Scope:** Apache Webserver

### [MEDIUM] Unencrypted Technical Asset named Contract File Server

- **ID:** `unencrypted-asset@contract-file-server`
- **Category:** `unencrypted-asset`
- **Impact:** medium
- **Likelihood:** unlikely
- **Asset:** Contract File Server
- **Data Breach Scope:** Contract File Server

### [MEDIUM] Unencrypted Technical Asset named Backoffice ERP System missing end user individual encryption with data-with-end-user-individual-key

- **ID:** `unencrypted-asset@erp-system`
- **Category:** `unencrypted-asset`
- **Impact:** high
- **Likelihood:** unlikely
- **Asset:** Backoffice ERP System
- **Data Breach Scope:** Backoffice ERP System

### [MEDIUM] Unencrypted Technical Asset named Git Repository

- **ID:** `unencrypted-asset@git-repo`
- **Category:** `unencrypted-asset`
- **Impact:** high
- **Likelihood:** unlikely
- **Asset:** Git Repository
- **Data Breach Scope:** Git Repository

### [MEDIUM] Unencrypted Technical Asset named Jenkins Build Server

- **ID:** `unencrypted-asset@jenkins-build-server`
- **Category:** `unencrypted-asset`
- **Impact:** high
- **Likelihood:** unlikely
- **Asset:** Jenkins Build Server
- **Data Breach Scope:** Jenkins Build Server

### [MEDIUM] Unencrypted Technical Asset named Marketing CMS

- **ID:** `unencrypted-asset@marketing-cms`
- **Category:** `unencrypted-asset`
- **Impact:** high
- **Likelihood:** unlikely
- **Asset:** Marketing CMS
- **Data Breach Scope:** Marketing CMS

### [MEDIUM] Unencrypted Technical Asset named Customer Contract Database missing end user individual encryption with data-with-end-user-individual-key

- **ID:** `unencrypted-asset@sql-database`
- **Category:** `unencrypted-asset`
- **Impact:** medium
- **Likelihood:** unlikely
- **Asset:** Customer Contract Database
- **Data Breach Scope:** Customer Contract Database

### [MEDIUM] Unencrypted Communication named Database Traffic between Backoffice ERP System and Customer Contract Database transferring authentication data (like credentials, token, session-id, etc.)

- **ID:** `unencrypted-communication@erp-system>database-traffic@erp-system@sql-database`
- **Category:** `unencrypted-communication`
- **Impact:** high
- **Likelihood:** unlikely
- **Asset:** Backoffice ERP System
- **Data Breach Scope:** Customer Contract Database

### [MEDIUM] Unencrypted Communication named NFS Filesystem Access between Backoffice ERP System and Contract File Server

- **ID:** `unencrypted-communication@erp-system>nfs-filesystem-access@erp-system@contract-file-server`
- **Category:** `unencrypted-communication`
- **Impact:** medium
- **Likelihood:** unlikely
- **Asset:** Backoffice ERP System
- **Data Breach Scope:** Contract File Server

### [LOW] Denial-of-Service risky access of Backoffice ERP System by Apache Webserver via ERP System Traffic

- **ID:** `dos-risky-access-across-trust-boundary@erp-system@apache-webserver@apache-webserver>erp-system-traffic->`
- **Category:** `dos-risky-access-across-trust-boundary`
- **Impact:** low
- **Likelihood:** unlikely
- **Asset:** Backoffice ERP System

### [LOW] Denial-of-Service risky access of Backoffice ERP System by Backoffice Client via ERP Internal Access

- **ID:** `dos-risky-access-across-trust-boundary@erp-system@backoffice-client@backoffice-client>erp-internal-access->`
- **Category:** `dos-risky-access-across-trust-boundary`
- **Impact:** low
- **Likelihood:** unlikely
- **Asset:** Backoffice ERP System

### [LOW] Denial-of-Service risky access of Marketing CMS by Backoffice Client via Marketing CMS Editing

- **ID:** `dos-risky-access-across-trust-boundary@marketing-cms@backoffice-client@backoffice-client>marketing-cms-editing->`
- **Category:** `dos-risky-access-across-trust-boundary`
- **Impact:** low
- **Likelihood:** unlikely
- **Asset:** Marketing CMS

### [LOW] Unchecked Deployment risk at Git Repository

- **ID:** `unchecked-deployment@git-repo`
- **Category:** `unchecked-deployment`
- **Impact:** low
- **Likelihood:** unlikely
- **Asset:** Git Repository
- **Data Breach Scope:** Git Repository

## Technical Assets

| Asset | Type | Internet | Confidentiality | Integrity | Availability |
|---|---|---|---|---|---|
| Apache Webserver | process | No | strictly-confidential | mission-critical | critical |
| Backend Admin Client | external-entity | No | strictly-confidential | critical | critical |
| Backoffice Client | external-entity | No | strictly-confidential | critical | critical |
| Backoffice ERP System | process | No | strictly-confidential | mission-critical | mission-critical |
| Contract File Server | datastore | No | confidential | critical | important |
| Customer Contract Database | datastore | No | strictly-confidential | mission-critical | mission-critical |
| Customer Web Client | external-entity | **Yes** | strictly-confidential | critical | critical |
| External Development Client | external-entity | **Yes** | confidential | mission-critical | important |
| Git Repository | process | No | confidential | mission-critical | important |
| Identity Provider | process | No | strictly-confidential | critical | critical |
| Jenkins Build Server | process | No | confidential | mission-critical | important |
| LDAP Auth Server | datastore | No | strictly-confidential | critical | critical |
| Load Balancer | process | No | strictly-confidential | mission-critical | mission-critical |
| Marketing CMS | process | No | strictly-confidential | critical | critical |

## Data Assets

| Asset | Confidentiality | PII |
|---|---|---|
| Build Job Config | restricted | No |
| Client Application Code | public | No |
| Customer Accounts | strictly-confidential | **Yes** |
| Customer Contract Summaries | restricted | **Yes** |
| Customer Contracts | confidential | **Yes** |
| Customer Operational Data | confidential | **Yes** |
| Database Customizing and Dumps | strictly-confidential | No |
| ERP Customizing Data | confidential | No |
| ERP Logs | restricted | No |
| Marketing Material | public | No |
| Server Application Code | internal | No |
| Some Internal Business Data | strictly-confidential | No |

---
*Generated by [threagile](https://github.com/threagile/threagile)*
