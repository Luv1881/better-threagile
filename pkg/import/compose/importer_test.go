package compose

import (
	"testing"

	"github.com/threagile/threagile/pkg/types"
)

const sampleCompose = `
version: '3.8'
services:
  nginx:
    image: nginx:alpine
    ports: ["443:443", "80:80"]
    depends_on: [api]
    networks: [frontend-net]
  api:
    build: ./api
    environment:
      - DATABASE_HOST=db
      - JWT_SECRET=change-me
    depends_on:
      db: {condition: service_healthy}
      redis: {condition: service_started}
    networks: [frontend-net, backend-net]
  db:
    image: postgres:16-alpine
    networks: [backend-net]
  redis:
    image: redis:7-alpine
    networks: [backend-net]
networks:
  frontend-net: {}
  backend-net: {internal: true}
`

func importSample(t *testing.T) *types.Model {
	t.Helper()
	m, err := Import([]byte(sampleCompose), ImportOptions{})
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}
	return m
}

func TestServicesBecomeAssets(t *testing.T) {
	m := importSample(t)
	for _, id := range []string{"nginx-compose", "api-compose", "db-compose", "redis-compose"} {
		if m.TechnicalAssets[id] == nil {
			t.Fatalf("missing asset %s", id)
		}
	}
	// postgres image -> datastore
	if m.TechnicalAssets["db-compose"].Type != types.Datastore {
		t.Errorf("db should be datastore, got %s", m.TechnicalAssets["db-compose"].Type)
	}
	// build: ./api -> custom-developed
	if !m.TechnicalAssets["api-compose"].CustomDevelopedParts {
		t.Error("api (build) should be custom-developed")
	}
}

func TestPublishedPortsAreInternet(t *testing.T) {
	m := importSample(t)
	if !m.TechnicalAssets["nginx-compose"].Internet {
		t.Error("nginx with published ports should be internet-facing")
	}
	// db has no published ports
	if m.TechnicalAssets["db-compose"].Internet {
		t.Error("db should not be internet-facing")
	}
	if m.TechnicalAssets["external-internet-client-compose"] == nil {
		t.Error("expected a synthetic internet client")
	}
}

func TestDependsOnBecomesLinks(t *testing.T) {
	m := importSample(t)
	// nginx -> api, api -> db, api -> redis
	want := map[string]string{
		"nginx-compose": "api-compose",
		"api-compose":   "db-compose",
	}
	for src, target := range want {
		found := false
		for _, l := range m.TechnicalAssets[src].CommunicationLinks {
			if l.TargetId == target {
				found = true
			}
		}
		if !found {
			t.Errorf("expected link %s -> %s", src, target)
		}
	}
}

func TestSecretEnvProducesDataAsset(t *testing.T) {
	m := importSample(t)
	da := m.DataAssets["application-secrets-compose"]
	if da == nil {
		t.Fatal("expected application-secrets data asset from JWT_SECRET/DATABASE_URL")
	}
	if da.Confidentiality != types.StrictlyConfidential {
		t.Errorf("secrets should be strictly-confidential, got %s", da.Confidentiality)
	}
	// api carries the secret env -> processes the secrets asset
	found := false
	for _, id := range m.TechnicalAssets["api-compose"].DataAssetsProcessed {
		if id == "application-secrets-compose" {
			found = true
		}
	}
	if !found {
		t.Error("api should process the application-secrets data asset")
	}
}

func TestNetworksBecomeBoundaries(t *testing.T) {
	m := importSample(t)
	// backend-net is internal -> security-group; frontend-net -> virtual LAN.
	be := m.TrustBoundaries["network-backend-net-compose"]
	if be == nil || be.Type != types.NetworkCloudSecurityGroup {
		t.Fatalf("backend-net (internal) should be a security-group boundary, got %v", be)
	}
	fe := m.TrustBoundaries["network-frontend-net-compose"]
	if fe == nil || fe.Type != types.NetworkVirtualLAN {
		t.Fatalf("frontend-net should be a virtual-LAN boundary, got %v", fe)
	}
	// Each asset belongs to exactly one boundary (first network).
	count := 0
	for _, tb := range m.TrustBoundaries {
		for _, id := range tb.TechnicalAssetsInside {
			if id == "api-compose" {
				count++
			}
		}
	}
	if count != 1 {
		t.Errorf("api should be in exactly one boundary, found in %d", count)
	}
}

func TestBarePortIsPublished(t *testing.T) {
	// A bare container port still binds to a random host port -> published.
	yaml := "services:\n  app:\n    image: corp/app:1\n    ports: [\"3000\"]\n"
	m, err := Import([]byte(yaml), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !m.TechnicalAssets["app-compose"].Internet {
		t.Error("a bare port under ports: is host-published -> internet-facing")
	}
}

func TestExposeIsNotPublished(t *testing.T) {
	// `expose` is container-internal only, not host-published.
	yaml := "services:\n  app:\n    image: corp/app:1\n    expose: [\"3000\"]\n"
	m, err := Import([]byte(yaml), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if m.TechnicalAssets["app-compose"].Internet {
		t.Error("expose-only service must not be internet-facing")
	}
}

func TestSecretInMapFormEnvValue(t *testing.T) {
	// Map-form environment, secret only in the VALUE.
	yaml := "services:\n  api:\n    image: corp/api:1\n    environment:\n      JWT_SECRET: change-me\n"
	m, err := Import([]byte(yaml), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if m.DataAssets["application-secrets-compose"] == nil {
		t.Error("map-form secret env should produce the application-secrets data asset")
	}
}

func TestBuildNullNotCustom(t *testing.T) {
	yaml := "services:\n  a:\n    image: corp/a:1\n    build:\n"
	m, err := Import([]byte(yaml), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if m.TechnicalAssets["a-compose"].CustomDevelopedParts {
		t.Error("build: null must not mark the asset custom-developed")
	}
}

func TestServiceIDCollisionDisambiguated(t *testing.T) {
	// "svc_a" and "svc-a" both normalise to svc-a-compose; both must survive.
	yaml := "services:\n  svc_a:\n    image: corp/a:1\n  svc-a:\n    image: corp/b:1\n"
	m, err := Import([]byte(yaml), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.TechnicalAssets) != 2 {
		t.Fatalf("collision must not drop a service; got %d assets", len(m.TechnicalAssets))
	}
}

func TestLoopbackPortsNotInternet(t *testing.T) {
	yaml := `
services:
  db:
    image: postgres:16
    ports: ["127.0.0.1:5432:5432"]
  cache:
    image: redis:7
    ports:
      - {target: 6379, published: 6379, host_ip: 127.0.0.1}
  web:
    image: nginx
    ports: ["443:443"]
`
	m, err := Import([]byte(yaml), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if m.TechnicalAssets["db-compose"].Internet {
		t.Error("loopback-bound db port must not be internet-facing")
	}
	if m.TechnicalAssets["cache-compose"].Internet {
		t.Error("long-form host_ip 127.0.0.1 must not be internet-facing")
	}
	if !m.TechnicalAssets["web-compose"].Internet {
		t.Error("0.0.0.0-bound web port should be internet-facing")
	}
}

func TestDefaultNetworkBoundary(t *testing.T) {
	// A service with no explicit networks joins the implicit "default" network.
	yaml := "services:\n  a:\n    image: nginx\n"
	m, err := Import([]byte(yaml), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	tb := m.TrustBoundaries["network-default-compose"]
	if tb == nil {
		t.Fatal("service without networks should join a default-network boundary")
	}
	found := false
	for _, id := range tb.TechnicalAssetsInside {
		if id == "a-compose" {
			found = true
		}
	}
	if !found {
		t.Errorf("service 'a' should be inside the default boundary: %v", tb.TechnicalAssetsInside)
	}
}

func TestImportErrors(t *testing.T) {
	if _, err := Import([]byte(""), ImportOptions{}); err == nil {
		t.Error("empty input should error")
	}
	if _, err := Import([]byte("version: '3'\nfoo: bar\n"), ImportOptions{}); err == nil {
		t.Error("no services should error")
	}
	if _, err := Import([]byte("services: [oops\n"), ImportOptions{}); err == nil {
		t.Error("malformed YAML should error")
	}
}

func TestDeterministicClassification(t *testing.T) {
	yaml := "services:\n  x:\n    image: corp/redis-postgres:1\n    networks: [n]\nnetworks:\n  n: {}\n"
	want := func() string {
		m, _ := Import([]byte(yaml), ImportOptions{})
		return m.TechnicalAssets["x-compose"].Technologies[0].Name
	}()
	for i := 0; i < 20; i++ {
		m, _ := Import([]byte(yaml), ImportOptions{})
		if got := m.TechnicalAssets["x-compose"].Technologies[0].Name; got != want {
			t.Fatalf("non-deterministic classification: %s vs %s", got, want)
		}
	}
}

// Common enterprise images beyond the original shortlist must classify too
// (found by comparing bootstrapped models against hand-authored ones).
func TestImageClassificationCoverage(t *testing.T) {
	compose := `
services:
  sql:
    image: mcr.microsoft.com/mssql/server:2022-latest
  analytics:
    image: clickhouse/clickhouse-server:24.3
  objects:
    image: chrislusf/seaweedfs:3.67
  auth:
    image: quay.io/keycloak/keycloak:25.0
`
	m, err := Import([]byte(compose), ImportOptions{})
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}

	tests := []struct {
		id        string
		tech      string
		datastore bool
	}{
		{"sql-compose", "database", true},
		{"analytics-compose", "database", true},
		{"objects-compose", "file-server", true},
		{"auth-compose", "identity-provider", false},
	}
	for _, test := range tests {
		asset := m.TechnicalAssets[test.id]
		if asset == nil {
			t.Errorf("missing asset %s", test.id)
			continue
		}
		wantType := types.Process
		if test.datastore {
			wantType = types.Datastore
		}
		if asset.Type != wantType {
			t.Errorf("%s: type = %v, want %v", test.id, asset.Type, wantType)
		}
		if len(asset.Technologies) == 0 || asset.Technologies[0].Name != test.tech {
			t.Errorf("%s: technologies = %+v, want %s", test.id, asset.Technologies, test.tech)
		}
	}
}

// Datastores and volume mounts store data: the importer must attach a stub
// data asset so storage/encryption rules can fire, and links into a datastore
// must carry that data (what the communication-encryption rule inspects).
func TestDatastoreDataFlowAttachment(t *testing.T) {
	compose := `
services:
  web:
    image: nginx
    volumes: ["./site:/usr/share/nginx/html"]
    depends_on: [db]
  db:
    image: postgres:16
    volumes: ["pgdata:/var/lib/postgresql/data"]
volumes:
  pgdata: {}
`
	m, err := Import([]byte(compose), ImportOptions{})
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}

	db := m.TechnicalAssets["db-compose"]
	if db == nil || db.Type != types.Datastore {
		t.Fatalf("db must be a datastore, got %+v", db)
	}
	if len(db.DataAssetsStored) == 0 {
		t.Errorf("datastore must store a data asset, got none")
	}
	web := m.TechnicalAssets["web-compose"]
	if len(web.DataAssetsStored) == 0 {
		t.Errorf("service with a volume mount must store a data asset, got none")
	}

	link := m.CommunicationLinks["link-web-to-db-compose"]
	if link == nil {
		t.Fatalf("missing web->db link: %v", m.CommunicationLinks)
	}
	if len(link.DataAssetsSent) == 0 || len(link.DataAssetsReceived) == 0 {
		t.Errorf("link into a datastore must carry its data, got sent=%v received=%v", link.DataAssetsSent, link.DataAssetsReceived)
	}
}

// docker-compose declares no protocol, so links must default to plain HTTP:
// assuming HTTPS would silently suppress the unencrypted-communication rule.
func TestLinksDefaultToHTTP(t *testing.T) {
	m := importSample(t)
	for id, link := range m.CommunicationLinks {
		if link.Protocol != types.HTTP {
			t.Errorf("link %s protocol = %v, want HTTP (compose states no protocol)", id, link.Protocol)
		}
	}
}
