// Package imageclass maps container image references to Threagile technology
// hints. It is shared by the docker-compose and Kubernetes importers so the two
// cannot drift apart, and it is ordered: the first matching needle wins, which
// keeps classification deterministic when an image name contains several.
package imageclass

import (
	"strings"

	"github.com/threagile/threagile/pkg/types"
)

// Hint is a technology suggestion for a container image.
type Hint struct {
	// Technology is a canonical Threagile technology name (pkg/types).
	Technology string
	// Datastore marks technologies that are stored data (databases, search
	// indexes, file stores): callers map those to the datastore asset type.
	Datastore bool
}

// Rules is ordered by specificity: put longer/more specific needles before
// generic ones that could occur inside them. A needle only matches on a token
// boundary, so "vault" matches hashicorp/vault but not vaultwarden; needles
// that are prefixes of other product names need their own entry (mongo vs
// mongodb, postgres vs postgresql).
var Rules = []struct {
	Needle string
	Hint   Hint
}{
	// Databases and data stores.
	{"postgresql", Hint{types.Database, true}},
	{"postgres", Hint{types.Database, true}},
	{"mysql", Hint{types.Database, true}},
	{"mariadb", Hint{types.Database, true}},
	{"mongodb", Hint{types.Database, true}},
	{"mongo", Hint{types.Database, true}},
	{"redis", Hint{types.Database, true}},
	{"memcached", Hint{types.Database, true}},
	{"cassandra", Hint{types.Database, true}},
	{"cockroach", Hint{types.Database, true}},
	{"mssql", Hint{types.Database, true}},
	{"microsoft/sql-server", Hint{types.Database, true}},
	{"azure-sql", Hint{types.Database, true}},
	{"clickhouse", Hint{types.Database, true}},
	{"influxdb", Hint{types.Database, true}},
	{"timescale", Hint{types.Database, true}},
	{"neo4j", Hint{types.Database, true}},
	{"couchdb", Hint{types.Database, true}},
	{"couchbase", Hint{types.Database, true}},
	{"hbase", Hint{types.Database, true}},
	{"scylla", Hint{types.Database, true}},
	{"ibmcom/db2", Hint{types.Database, true}},
	{"dynamodb-local", Hint{types.Database, true}},
	{"etcd", Hint{types.Database, true}},
	{"elasticsearch", Hint{types.SearchEngine, true}},
	{"opensearch", Hint{types.SearchEngine, true}},
	{"solr", Hint{types.SearchEngine, true}},
	{"meilisearch", Hint{types.SearchEngine, true}},
	{"typesense", Hint{types.SearchEngine, true}},
	{"minio", Hint{types.FileServer, true}},
	{"seaweedfs", Hint{types.FileServer, true}},
	{"ceph", Hint{types.FileServer, true}},

	// Queues, streams and workflow engines.
	{"rabbitmq", Hint{types.MessageQueue, false}},
	{"kafka", Hint{types.MessageQueue, false}},
	{"redpanda", Hint{types.MessageQueue, false}},
	{"pulsar", Hint{types.MessageQueue, false}},
	{"activemq", Hint{types.MessageQueue, false}},
	{"nats", Hint{types.MessageQueue, false}},
	{"temporal", Hint{types.MessageQueue, false}},

	// Identity, secrets and directories.
	{"vaultwarden", Hint{types.WebApplication, false}},
	{"keycloak", Hint{types.IdentityProvider, false}},
	{"authentik", Hint{types.IdentityProvider, false}},
	{"oauth2-proxy", Hint{types.IdentityProvider, false}},
	{"openldap", Hint{types.LDAPServer, true}},
	{"vault", Hint{types.Vault, false}},

	// Edge, application and mail servers.
	{"nginx", Hint{types.ReverseProxy, false}},
	{"traefik", Hint{types.ReverseProxy, false}},
	{"caddy", Hint{types.ReverseProxy, false}},
	{"haproxy", Hint{types.LoadBalancer, false}},
	{"httpd", Hint{types.WebServer, false}},
	{"tomcat", Hint{types.ApplicationServer, false}},
	{"wildfly", Hint{types.ApplicationServer, false}},
	{"mailhog", Hint{types.MailServer, false}},

	// Build, monitoring and registries.
	{"jenkins", Hint{types.BuildPipeline, false}},
	{"prometheus", Hint{types.Monitoring, false}},
	{"grafana", Hint{types.Monitoring, false}},
	{"jaeger", Hint{types.Monitoring, false}},
	{"loki", Hint{types.Monitoring, false}},
	{"harbor", Hint{types.ArtifactRegistry, false}},
}

// Classify returns the technology hint for a container image reference, or
// false when the image is not recognised.
//
// Exporter/sidecar images are classified as monitoring: prometheus exporters
// (*-exporter images) carry the name of the product they observe and would
// otherwise be mistaken for that product (postgres-exporter is not a database).
func Classify(image string) (Hint, bool) {
	lower := strings.ToLower(image)
	if matchToken(lower, "exporter") {
		return Hint{types.Monitoring, false}, true
	}
	for _, rule := range Rules {
		if matchToken(lower, rule.Needle) {
			return rule.Hint, true
		}
	}
	return Hint{}, false
}

// matchToken reports whether needle occurs in the image reference on token
// boundaries (start/end or a non-alphanumeric character on both sides), so
// "vault" does not match "vaultwarden" but does match "hashicorp/vault:1.16".
func matchToken(image, needle string) bool {
	offset := 0
	for {
		index := strings.Index(image[offset:], needle)
		if index < 0 {
			return false
		}
		start := offset + index
		end := start + len(needle)
		beforeOK := start == 0 || !isAlnum(image[start-1])
		afterOK := end == len(image) || !isAlnum(image[end])
		if beforeOK && afterOK {
			return true
		}
		offset = start + 1
	}
}

func isAlnum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}
