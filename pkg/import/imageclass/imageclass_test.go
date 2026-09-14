package imageclass

import "testing"

func TestClassify(t *testing.T) {
	tests := []struct {
		image     string
		tech      string
		datastore bool
		ok        bool
	}{
		{"postgres:16-alpine", "database", true, true},
		{"mcr.microsoft.com/mssql/server:2022-latest", "database", true, true},
		{"clickhouse/clickhouse-server:24.3", "database", true, true},
		{"docker.elastic.co/elasticsearch/elasticsearch:8.13.0", "search-engine", true, true},
		{"minio/minio:latest", "file-server", true, true},
		{"chrislusf/seaweedfs:3.67", "file-server", true, true},
		{"redis:7", "database", true, true},
		{"rabbitmq:3-management", "message-queue", false, true},
		{"redpandadata/redpanda:latest", "message-queue", false, true},
		{"quay.io/keycloak/keycloak:25.0", "identity-provider", false, true},
		{"nginx:1.25", "reverse-proxy", false, true},
		{"traefik:v3", "reverse-proxy", false, true},
		{"haproxy:2.9", "load-balancer", false, true},
		{"hashicorp/vault:1.16", "vault", false, true},
		{"jenkins/jenkins:lts", "build-pipeline", false, true},
		{"prom/prometheus:v2.52", "monitoring", false, true},
		// Exporter/sidecar images must not be mistaken for the observed product.
		{"prometheuscommunity/postgres-exporter:v0.15", "monitoring", false, true},
		{"nginx/nginx-prometheus-exporter:1.1", "monitoring", false, true},
		{"vaultwarden/server:1.32", "web-application", false, true},
		{"bitnami/mongodb:7.0", "database", true, true},
		{"bitnami/postgresql:16", "database", true, true},
		// Non-matches: unrelated images must not be classified.
		{"oraclelinux:9", "", false, false}, // "oracle" alone is not a rule
		{"alpine:3.19", "", false, false},
		{"", "", false, false},
	}

	for _, test := range tests {
		hint, ok := Classify(test.image)
		if ok != test.ok {
			t.Errorf("Classify(%q): ok=%v, want %v", test.image, ok, test.ok)
			continue
		}
		if !ok {
			continue
		}
		if hint.Technology != test.tech || hint.Datastore != test.datastore {
			t.Errorf("Classify(%q) = {%s, datastore=%v}, want {%s, datastore=%v}",
				test.image, hint.Technology, hint.Datastore, test.tech, test.datastore)
		}
	}
}

// First match wins so classification is deterministic when several needles fit.
func TestClassify_OrderIsDeterministic(t *testing.T) {
	hint, ok := Classify("mycompany/postgres-nginx:latest")
	if !ok || hint.Technology != "database" {
		t.Fatalf("postgres must win over nginx (rule order), got %+v ok=%v", hint, ok)
	}
}

// Azure SQL Edge is the image the eShopOnWeb compose stack uses for SQL Server.
func TestClassify_AzureSQLEdge(t *testing.T) {
	hint, ok := Classify("mcr.microsoft.com/azure-sql-edge")
	if !ok || hint.Technology != "database" || !hint.Datastore {
		t.Fatalf("azure-sql-edge must classify as a database datastore, got %+v ok=%v", hint, ok)
	}
}
