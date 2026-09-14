# Bootstrap fidelity report

| Project | Assets coverage | Assets precision | Type agreement | Boundaries | Data assets | Score |
|---|---|---|---|---|---|---|
| VaultNote | 4/18 (0.22) | 0.29 | 1.00 | 0/7 (0.00) | 1/8 (0.12) | 0.33 |
| enduro | 7/13 (0.54) | 0.23 | 1.00 | 0/4 (0.00) | 2/9 (0.22) | 0.40 |
| DevSecOps | 0/14 (0.00) | 0.00 | - | 0/5 (0.00) | 0/12 (0.00) | 0.00 |
| Project-Kavach | 2/8 (0.25) | 0.67 | 0.00 | 0/6 (0.00) | 1/5 (0.20) | 0.22 |

Aggregate score: **0.237** over 4 projects

## VaultNote

Technical assets: coverage 0.22, precision 0.29
Type agreement: 1.00
- missing from bootstrap (14): AWS API Gateway, AWS ECR Container Registry, AWS RDS PostgreSQL, AWS S3 Notes Bucket, AWS SES, Browser SPA, ECS Container Platform, GitHub Actions Build Pipeline, LLM Note Summarizer, Lambda Email Notifier, Note RAG Pipeline, PostgreSQL Database, VaultNote Source Repository, VaultNote Vector Store
- extra in bootstrap (10): Ingress, Internet client, Internet client (Service), PVC: pgdata, db, vaultnote/api, vaultnote/minio, vaultnote/nginx, vaultnote/postgres, vaultnote/redis

Trust boundaries: coverage 0.00, precision 0.00
- missing from bootstrap (7): AI Services, AWS Cloud, Application Network, DMZ, Data Tier, External CI/CD, Internet
- extra in bootstrap (3): Namespace: vaultnote, Network: backend-net, Network: frontend-net

Data assets: coverage 0.12, precision 0.50
- missing from bootstrap (7): AI Model Responses, Build Artifacts, Embedding Vectors, File Attachments, Note Content, Notification Payloads, User Credentials
- extra in bootstrap (1): Secret: vaultnote-secrets

## enduro

Technical assets: coverage 0.54, precision 0.23
Type agreement: 1.00
- missing from bootstrap (6): A3M, BlobStorageService, IdentityProvider, IngressController, OpenSearch, UserWebClient
- extra in bootstrap (23): Enduro API - storage, Enduro API Client, PVC: enduro-internal-storage, PVC: mysql-persistentvolumeclaim, PVC: redis-persistentvolumeclaim, PVC: seaweedfs-pvc, alloy, ambox, enduro-am, enduro-dashboard, keycloak, lgtm, mysql-create-a3m-location, mysql-create-am-location, mysql-recreate-databases, seaweedfs, temporal-frontend, temporal-history, temporal-matching, temporal-namespace-1-2-0-1

Trust boundaries: coverage 0.00, precision 0.00
- missing from bootstrap (4): ApplicationNetwork, AuthenticationNetwork, EnduroA3mWorkerPod, EnduroNetwork
- extra in bootstrap (1): Namespace: default

Data assets: coverage 0.22, precision 0.08
- missing from bootstrap (7): ClientApplicationCode, CollectionWorkflowStatus, OAuth2.0AccessToken, OIDCIdToken, PreservationContent, PreservationMetadata, UserCredentials
- extra in bootstrap (22): AMSSConfig, BatchCollection, BatchCreatedEvent, BatchUpdatedEvent, EnduroIngestBatch, EnduroIngestBatches, EnduroIngestSip, EnduroIngestSips, EnduroIngestUser, EnduroIngestUsers, S3Config, SFTPConfig, SIPCollection, SIPCreatedEvent, SIPUpdatedEvent, Secret: ambox-hostkey, Secret: enduro-am-secret, Secret: enduro-dashboard-secret, Secret: keycloak-secret, Secret: seaweedfs-secret

## DevSecOps

Technical assets: coverage 0.00, precision 0.00
- missing from bootstrap (14): Apache Webserver, Backend Admin Client, Backoffice Client, Backoffice ERP System, Contract Fileserver, Customer Contract Database, Customer Web Client, External Development Client, Git Repository, Identity Provider, Jenkins Buildserver, LDAP Auth Server, Load Balancer, Marketing CMS
- extra in bootstrap (4): Internet client, eshoppublicapi, eshopwebmvc, sqlserver

Trust boundaries: coverage 0.00, precision 0.00
- missing from bootstrap (5): Application Network, Auth Handling Environment, Dev Network, ERP DMZ, Web DMZ
- extra in bootstrap (1): Network: default

Data assets: coverage 0.00, precision 0.00
- missing from bootstrap (12): Build Job Config, Client Application Code, Customer Accounts, Customer Contract Summaries, Customer Contracts, Customer Operational Data, Database Customizing and Dumps, ERP Customizing Data, ERP Logs, Marketing Material, Server Application Code, Some Internal Business Data
- extra in bootstrap (1): Application Secrets

## Project-Kavach

Technical assets: coverage 0.25, precision 0.67
Type agreement: 0.00
- missing from bootstrap (6): attacker_c2_server, domain_controller, jump_host, portal_database, secure_web_gateway, user_workstation
- extra in bootstrap (1): Internet client

Trust boundaries: coverage 0.00, precision 0.00
- missing from bootstrap (6): internet_untrusted, management_vlan, perimeter_security_zone, restricted_server_vlan, user_workstation_vlan, web_application_dmz
- extra in bootstrap (1): Network: default

Data assets: coverage 0.20, precision 1.00
- missing from bootstrap (4): ad_credentials, c2_beacon_traffic, customer_pii, portal_login_credentials
