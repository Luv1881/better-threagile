# Bootstrap fidelity report

| Project | Assets coverage | Assets precision | Type agreement | Boundaries | Data assets | Risk profile | Score |
|---|---|---|---|---|---|---|---|
| VaultNote | 1/18 (0.06) | 0.06 | 1.00 | 0/7 (0.00) | 0/8 (0.00) | 12/26 (0.46) | 0.26 |
| enduro | 7/13 (0.54) | 0.23 | 1.00 | 0/4 (0.00) | 0/9 (0.00) | 6/13 (0.46) | 0.37 |
| DevSecOps | 0/14 (0.00) | 0.00 | - | 0/5 (0.00) | 0/12 (0.00) | 9/26 (0.35) | 0.07 |
| Project-Kavach | 1/8 (0.12) | 0.33 | 0.00 | 1/6 (0.17) | 0/5 (0.00) | - | 0.12 |

Aggregate score: **0.207** over 4 projects

## VaultNote

Technical assets: coverage 0.06, precision 0.06
Type agreement: 1.00
- missing from bootstrap (17): API Server, AWS API Gateway, AWS ECR Container Registry, AWS RDS PostgreSQL, AWS S3 Notes Bucket, AWS SES, Browser SPA, ECS Container Platform, GitHub Actions Build Pipeline, LLM Note Summarizer, Lambda Email Notifier, MinIO Object Storage, Nginx Reverse Proxy, Note RAG Pipeline, PostgreSQL Database, VaultNote Source Repository, VaultNote Vector Store
- extra in bootstrap (17): Ingress, Internet client, Internet client (Service), PVC: pgdata, api, db, minio, nginx, vaultnote-assets, vaultnote/api, vaultnote/minio, vaultnote/nginx, vaultnote/postgres, vaultnote/redis, vaultnote_alb, vaultnote_pg, vaultnote_redis

Trust boundaries: coverage 0.00, precision 0.00
- missing from bootstrap (7): AI Services, AWS Cloud, Application Network, DMZ, Data Tier, External CI/CD, Internet
- extra in bootstrap (3): Namespace: vaultnote, Network: backend-net, Network: frontend-net

Data assets: coverage 0.00, precision 0.00
- missing from bootstrap (8): AI Model Responses, Build Artifacts, Embedding Vectors, File Attachments, Note Content, Notification Payloads, Session Tokens, User Credentials
- extra in bootstrap (3): Application Secrets, Imported Data (review and classify), Secret: vaultnote-secrets

Risk profile: coverage 0.46 (12/26 categories)
- missing from bootstrap (14): accidental-secret-leak, code-backdooring, dos-risky-access-across-trust-boundary, exposed-default-credentials, lateral-movement-shared-runtime, missing-authentication-second-factor, missing-csp-header, missing-identity-store, missing-waf, mixed-targets-on-shared-runtime, unchecked-deployment, unencrypted-asset, unencrypted-communication, unguarded-direct-datastore-access
- extra in bootstrap (3): lateral-movement-transitive-access, unnecessary-communication-link, unnecessary-data-asset

## enduro

Technical assets: coverage 0.54, precision 0.23
Type agreement: 1.00
- missing from bootstrap (6): A3M, BlobStorageService, IdentityProvider, IngressController, OpenSearch, UserWebClient
- extra in bootstrap (23): Enduro API - ingest, Enduro API - storage, Enduro API Client, PVC: enduro-internal-storage, PVC: mysql-persistentvolumeclaim, PVC: redis-persistentvolumeclaim, PVC: seaweedfs-pvc, alloy, ambox, enduro-am, keycloak, lgtm, mysql-create-a3m-location, mysql-create-am-location, mysql-recreate-databases, seaweedfs, temporal-admintools, temporal-history, temporal-matching, temporal-namespace-1-2-0-1

Trust boundaries: coverage 0.00, precision 0.00
- missing from bootstrap (4): ApplicationNetwork, AuthenticationNetwork, EnduroA3mWorkerPod, EnduroNetwork
- extra in bootstrap (1): Namespace: default

Data assets: coverage 0.00, precision 0.00
- missing from bootstrap (9): ClientApplicationCode, CollectionWorkflowStatus, FileBlobDetails, GrpcTransferStartRequest, OAuth2.0AccessToken, OIDCIdToken, PreservationContent, PreservationMetadata, UserCredentials
- extra in bootstrap (24): AMSSConfig, BatchCollection, BatchCreatedEvent, BatchUpdatedEvent, Enduro API Data, EnduroIngestBatch, EnduroIngestBatches, EnduroIngestSip, EnduroIngestSips, EnduroIngestUser, EnduroIngestUsers, S3Config, SFTPConfig, SIPCollection, SIPCreatedEvent, SIPUpdatedEvent, Secret: ambox-hostkey, Secret: enduro-am-secret, Secret: enduro-dashboard-secret, Secret: keycloak-secret

Risk profile: coverage 0.46 (6/13 categories)
- missing from bootstrap (7): missing-authentication-second-factor, missing-cloud-hardening, missing-identity-store, path-traversal, server-side-request-forgery, sql-nosql-injection, unencrypted-asset
- extra in bootstrap (6): container-platform-escape, missing-identity-provider-isolation, unguarded-access-from-internet, unnecessary-communication-link, unnecessary-data-asset, unnecessary-technical-asset

## DevSecOps

Technical assets: coverage 0.00, precision 0.00
- missing from bootstrap (14): Apache Webserver, Backend Admin Client, Backoffice Client, Backoffice ERP System, Contract Fileserver, Customer Contract Database, Customer Web Client, External Development Client, Git Repository, Identity Provider, Jenkins Buildserver, LDAP Auth Server, Load Balancer, Marketing CMS
- extra in bootstrap (30): GameScores, Internet client, acctestsa, aurora-cluster-demo, aurora-cluster-demo-0, aurora-cluster-demo-1, bar, eshoppublicapi, eshopwebmvc, example, example (aws-elasticache-replication-group-example-tf), example-app-service, example-appserviceplan, example-mysqlserver, example-psqlserver, foopolicy, front_end, front_end (aws-lb-listener-front-end-tf), front_end (aws-lb-target-group-front-end-tf), mybucket

Trust boundaries: coverage 0.00, precision 0.00
- missing from bootstrap (5): Application Network, Auth Handling Environment, Dev Network, ERP DMZ, Web DMZ
- extra in bootstrap (4): Network: default, example1, example2, main

Data assets: coverage 0.00, precision 0.00
- missing from bootstrap (12): Build Job Config, Client Application Code, Customer Accounts, Customer Contract Summaries, Customer Contracts, Customer Operational Data, Database Customizing and Dumps, ERP Customizing Data, ERP Logs, Marketing Material, Server Application Code, Some Internal Business Data
- extra in bootstrap (2): Application Secrets, Imported Data (review and classify)

Risk profile: coverage 0.35 (9/26 categories)
- missing from bootstrap (17): accidental-secret-leak, code-backdooring, dos-risky-access-across-trust-boundary, lateral-movement-credential-reuse, lateral-movement-shared-runtime, lateral-movement-transitive-access, ldap-injection, missing-authentication-second-factor, missing-file-validation, missing-identity-propagation, mixed-targets-on-shared-runtime, path-traversal, push-instead-of-pull-deployment, unencrypted-asset, unencrypted-communication, untrusted-deserialization, xml-external-entity
- extra in bootstrap (6): container-platform-escape, cross-site-scripting, missing-build-infrastructure, unnecessary-communication-link, unnecessary-data-asset, unnecessary-technical-asset

## Project-Kavach

Technical assets: coverage 0.12, precision 0.33
Type agreement: 0.00
- missing from bootstrap (7): attacker_c2_server, domain_controller, dvwa_portal, jump_host, portal_database, secure_web_gateway, user_workstation
- extra in bootstrap (2): Internet client, dvwa

Trust boundaries: coverage 0.17, precision 1.00
- missing from bootstrap (5): internet_untrusted, management_vlan, perimeter_security_zone, restricted_server_vlan, user_workstation_vlan

Data assets: coverage 0.00, precision 0.00
- missing from bootstrap (5): ad_credentials, c2_beacon_traffic, customer_pii, portal_login_credentials, session_tokens
- extra in bootstrap (1): Application Secrets

Risk profile: not analyzable in the reference
