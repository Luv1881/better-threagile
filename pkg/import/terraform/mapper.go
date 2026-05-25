package terraform

import "strings"

// resourceMapping describes how a Terraform resource type maps to Threagile properties.
type resourceMapping struct {
	technology  string // Threagile technology slug
	assetType   string // "process" | "datastore"
	internet    bool   // default internet exposure
	encryption  string // default encryption guess
	isBoundary  bool   // true if this resource should become a TrustBoundary
	boundaryKind string // "network" | "vpc" | "subnet"
}

// techMappings maps Terraform resource type prefixes/exact-matches to Threagile resources.
// Checked in order; first match wins.
var techMappings = []struct {
	prefix  string
	mapping resourceMapping
}{
	// Object storage
	{"aws_s3_bucket", resourceMapping{technology: "object-storage", assetType: "datastore", encryption: "none"}},
	{"google_storage_bucket", resourceMapping{technology: "object-storage", assetType: "datastore", encryption: "none"}},
	{"azurerm_storage_account", resourceMapping{technology: "object-storage", assetType: "datastore", encryption: "transparent"}},
	{"azurerm_storage_blob", resourceMapping{technology: "object-storage", assetType: "datastore", encryption: "transparent"}},

	// Managed databases
	{"aws_db_instance", resourceMapping{technology: "managed-database", assetType: "datastore", encryption: "none"}},
	{"aws_rds_cluster", resourceMapping{technology: "managed-database", assetType: "datastore", encryption: "none"}},
	{"aws_dynamodb_table", resourceMapping{technology: "managed-database", assetType: "datastore", encryption: "none"}},
	{"google_sql_database_instance", resourceMapping{technology: "managed-database", assetType: "datastore", encryption: "transparent"}},
	{"google_spanner_instance", resourceMapping{technology: "managed-database", assetType: "datastore", encryption: "transparent"}},
	{"azurerm_sql_server", resourceMapping{technology: "managed-database", assetType: "datastore", encryption: "transparent"}},
	{"azurerm_cosmosdb_account", resourceMapping{technology: "managed-database", assetType: "datastore", encryption: "transparent"}},
	{"azurerm_postgresql_server", resourceMapping{technology: "managed-database", assetType: "datastore", encryption: "transparent"}},
	{"azurerm_mysql_server", resourceMapping{technology: "managed-database", assetType: "datastore", encryption: "transparent"}},

	// Serverless
	{"aws_lambda_function", resourceMapping{technology: "serverless-function", assetType: "process", encryption: "none"}},
	{"google_cloudfunctions_function", resourceMapping{technology: "serverless-function", assetType: "process", encryption: "none"}},
	{"google_cloudfunctions2_function", resourceMapping{technology: "serverless-function", assetType: "process", encryption: "none"}},
	{"azurerm_function_app", resourceMapping{technology: "serverless-function", assetType: "process", encryption: "none"}},
	{"azurerm_linux_function_app", resourceMapping{technology: "serverless-function", assetType: "process", encryption: "none"}},

	// API Gateways
	{"aws_api_gateway_rest_api", resourceMapping{technology: "cloud-api-gateway", assetType: "process", internet: true}},
	{"aws_apigatewayv2_api", resourceMapping{technology: "cloud-api-gateway", assetType: "process", internet: true}},
	{"google_api_gateway_api", resourceMapping{technology: "cloud-api-gateway", assetType: "process", internet: true}},
	{"azurerm_api_management", resourceMapping{technology: "cloud-api-gateway", assetType: "process", internet: true}},

	// Container platforms
	{"aws_ecs_cluster", resourceMapping{technology: "container-platform", assetType: "process"}},
	{"aws_eks_cluster", resourceMapping{technology: "container-platform", assetType: "process"}},
	{"google_container_cluster", resourceMapping{technology: "container-platform", assetType: "process"}},
	{"azurerm_kubernetes_cluster", resourceMapping{technology: "container-platform", assetType: "process"}},
	{"azurerm_container_group", resourceMapping{technology: "container-platform", assetType: "process"}},

	// Container registries
	{"aws_ecr_repository", resourceMapping{technology: "container-registry", assetType: "datastore"}},
	{"google_artifact_registry_repository", resourceMapping{technology: "container-registry", assetType: "datastore"}},
	{"azurerm_container_registry", resourceMapping{technology: "container-registry", assetType: "datastore"}},

	// Web apps
	{"aws_elastic_beanstalk_environment", resourceMapping{technology: "web-application", assetType: "process", internet: true}},
	{"aws_amplify_app", resourceMapping{technology: "web-application", assetType: "process", internet: true}},
	{"azurerm_app_service", resourceMapping{technology: "web-application", assetType: "process", internet: true}},
	{"azurerm_linux_web_app", resourceMapping{technology: "web-application", assetType: "process", internet: true}},
	{"azurerm_windows_web_app", resourceMapping{technology: "web-application", assetType: "process", internet: true}},
	{"google_app_engine_application", resourceMapping{technology: "web-application", assetType: "process", internet: true}},

	// Load balancers
	{"aws_alb", resourceMapping{technology: "load-balancer", assetType: "process", internet: true}},
	{"aws_lb", resourceMapping{technology: "load-balancer", assetType: "process", internet: true}},
	{"aws_elb", resourceMapping{technology: "load-balancer", assetType: "process", internet: true}},
	{"google_compute_forwarding_rule", resourceMapping{technology: "load-balancer", assetType: "process"}},
	{"azurerm_lb", resourceMapping{technology: "load-balancer", assetType: "process"}},

	// Message queues
	{"aws_sqs_queue", resourceMapping{technology: "message-queue", assetType: "datastore"}},
	{"aws_sns_topic", resourceMapping{technology: "message-queue", assetType: "process"}},
	{"google_pubsub_topic", resourceMapping{technology: "message-queue", assetType: "process"}},
	{"google_pubsub_subscription", resourceMapping{technology: "message-queue", assetType: "datastore"}},
	{"azurerm_servicebus_queue", resourceMapping{technology: "message-queue", assetType: "datastore"}},
	{"azurerm_servicebus_topic", resourceMapping{technology: "message-queue", assetType: "process"}},

	// Identity
	{"aws_cognito_user_pool", resourceMapping{technology: "identity-provider", assetType: "process", internet: true}},
	{"google_identity_platform_tenant", resourceMapping{technology: "identity-provider", assetType: "process"}},
	{"azurerm_active_directory_domain_service", resourceMapping{technology: "identity-provider", assetType: "process"}},

	// Caches
	{"aws_elasticache_cluster", resourceMapping{technology: "message-queue", assetType: "datastore"}},
	{"aws_elasticache_replication_group", resourceMapping{technology: "message-queue", assetType: "datastore"}},
	{"azurerm_redis_cache", resourceMapping{technology: "message-queue", assetType: "datastore"}},
	{"google_redis_instance", resourceMapping{technology: "message-queue", assetType: "datastore"}},

	// Secrets managers (skip — no corresponding Threagile tech, use vault)
	{"aws_secretsmanager_secret", resourceMapping{technology: "vault", assetType: "datastore"}},
	{"aws_ssm_parameter", resourceMapping{technology: "vault", assetType: "datastore"}},
	{"google_secret_manager_secret", resourceMapping{technology: "vault", assetType: "datastore"}},
	{"azurerm_key_vault", resourceMapping{technology: "vault", assetType: "datastore"}},

	// Networks / VPCs — become TrustBoundaries
	{"aws_vpc", resourceMapping{isBoundary: true, boundaryKind: "network-cloud-provider"}},
	{"google_compute_network", resourceMapping{isBoundary: true, boundaryKind: "network-cloud-provider"}},
	{"azurerm_virtual_network", resourceMapping{isBoundary: true, boundaryKind: "network-cloud-provider"}},
	{"aws_subnet", resourceMapping{isBoundary: true, boundaryKind: "network-cloud-provider"}},
	{"google_compute_subnetwork", resourceMapping{isBoundary: true, boundaryKind: "network-cloud-provider"}},
	{"azurerm_subnet", resourceMapping{isBoundary: true, boundaryKind: "network-cloud-provider"}},
}

// lookupMapping returns the mapping for a Terraform resource type, or nil if unknown.
func lookupMapping(resourceType string) *resourceMapping {
	rt := strings.ToLower(resourceType)
	for i := range techMappings {
		if strings.HasPrefix(rt, techMappings[i].prefix) {
			m := techMappings[i].mapping
			return &m
		}
	}
	return nil
}

// strVal safely extracts a string value from a Terraform values map.
func strVal(values map[string]any, key string) string {
	v, ok := values[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

// boolVal safely extracts a bool value from a Terraform values map.
func boolVal(values map[string]any, key string) bool {
	v, ok := values[key]
	if !ok {
		return false
	}
	b, _ := v.(bool)
	return b
}
