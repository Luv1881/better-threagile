// Package imageclass maps container image references to Threagile technology
// hints. It is shared by the docker-compose and Kubernetes importers so the two
// cannot drift apart, and it is ordered: the first matching needle wins, which
// keeps classification deterministic when an image name contains several.
package imageclass

import "strings"

// Hint is a technology suggestion for a container image.
type Hint struct {
	// Technology is a canonical Threagile technology name (pkg/types).
	Technology string
	// Datastore marks technologies that are stored data (databases, search
	// indexes, file stores): callers map those to the datastore asset type.
	Datastore bool
}

// Rules is ordered by specificity: put longer/more specific needles before
// generic ones that could occur inside them.
var Rules = []struct {
	Needle string
	Hint   Hint
}{
	// Databases and data stores.
	{"postgres", Hint{"database", true}},
	{"mysql", Hint{"database", true}},
	{"mariadb", Hint{"database", true}},
	{"mongo", Hint{"database", true}},
	{"redis", Hint{"database", true}},
	{"memcached", Hint{"database", true}},
	{"cassandra", Hint{"database", true}},
	{"cockroach", Hint{"database", true}},
	{"mssql", Hint{"database", true}},
	{"microsoft/sql-server", Hint{"database", true}},
	{"azure-sql", Hint{"database", true}},
	{"clickhouse", Hint{"database", true}},
	{"influxdb", Hint{"database", true}},
	{"timescale", Hint{"database", true}},
	{"neo4j", Hint{"database", true}},
	{"couchdb", Hint{"database", true}},
	{"couchbase", Hint{"database", true}},
	{"hbase", Hint{"database", true}},
	{"scylla", Hint{"database", true}},
	{"ibmcom/db2", Hint{"database", true}},
	{"dynamodb-local", Hint{"database", true}},
	{"etcd", Hint{"database", true}},
	{"elasticsearch", Hint{"search-engine", true}},
	{"opensearch", Hint{"search-engine", true}},
	{"solr", Hint{"search-engine", true}},
	{"meilisearch", Hint{"search-engine", true}},
	{"typesense", Hint{"search-engine", true}},
	{"minio", Hint{"file-server", true}},
	{"seaweedfs", Hint{"file-server", true}},
	{"ceph", Hint{"file-server", true}},

	// Queues, streams and workflow engines.
	{"rabbitmq", Hint{"message-queue", false}},
	{"kafka", Hint{"message-queue", false}},
	{"redpanda", Hint{"message-queue", false}},
	{"pulsar", Hint{"message-queue", false}},
	{"activemq", Hint{"message-queue", false}},
	{"nats", Hint{"message-queue", false}},
	{"temporal", Hint{"message-queue", false}},

	// Identity, secrets and directories.
	{"keycloak", Hint{"identity-provider", false}},
	{"authentik", Hint{"identity-provider", false}},
	{"oauth2-proxy", Hint{"identity-provider", false}},
	{"openldap", Hint{"ldap-server", true}},
	{"vault", Hint{"vault", false}},

	// Edge, application and mail servers.
	{"nginx", Hint{"reverse-proxy", false}},
	{"traefik", Hint{"reverse-proxy", false}},
	{"caddy", Hint{"reverse-proxy", false}},
	{"haproxy", Hint{"load-balancer", false}},
	{"httpd", Hint{"web-server", false}},
	{"tomcat", Hint{"application-server", false}},
	{"wildfly", Hint{"application-server", false}},
	{"mailhog", Hint{"mail-server", false}},

	// Build, monitoring and registries.
	{"jenkins", Hint{"build-pipeline", false}},
	{"prometheus", Hint{"monitoring", false}},
	{"grafana", Hint{"monitoring", false}},
	{"jaeger", Hint{"monitoring", false}},
	{"loki", Hint{"monitoring", false}},
	{"harbor", Hint{"artifact-registry", false}},
}

// Classify returns the technology hint for a container image reference, or
// false when the image is not recognised.
func Classify(image string) (Hint, bool) {
	lower := strings.ToLower(image)
	for _, rule := range Rules {
		if strings.Contains(lower, rule.Needle) {
			return rule.Hint, true
		}
	}
	return Hint{}, false
}
