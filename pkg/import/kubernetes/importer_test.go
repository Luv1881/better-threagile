package kubernetes

import (
	"testing"

	"github.com/threagile/threagile/pkg/types"
)

const sampleManifests = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: shop
  labels: {app: web}
spec:
  replicas: 3
  template:
    metadata: {labels: {app: web}}
    spec:
      securityContext: {runAsNonRoot: true}
      containers:
        - name: web
          image: myregistry/web:1.2.3
          ports: [{containerPort: 8080}]
---
apiVersion: v1
kind: Service
metadata: {name: web, namespace: shop}
spec:
  type: LoadBalancer
  selector: {app: web}
  ports: [{port: 443, targetPort: 8080}]
---
apiVersion: apps/v1
kind: StatefulSet
metadata: {name: db, namespace: shop, labels: {app: db}}
spec:
  template:
    metadata: {labels: {app: db}}
    spec:
      containers:
        - name: postgres
          image: postgres:16
          securityContext: {privileged: true}
---
apiVersion: v1
kind: Secret
metadata: {name: db-creds, namespace: shop}
`

func importSample(t *testing.T) *types.Model {
	t.Helper()
	m, err := Import([]byte(sampleManifests), ImportOptions{})
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}
	return m
}

func assetByID(m *types.Model, id string) *types.TechnicalAsset {
	return m.TechnicalAssets[id]
}

func TestImportWorkloadsAndDatastore(t *testing.T) {
	m := importSample(t)

	web := assetByID(m, "shop-web-k8s")
	if web == nil {
		t.Fatal("web deployment asset missing")
	}
	if web.Type != types.Process || web.Technologies[0].Name != types.ContainerPlatform {
		t.Fatalf("web asset wrong type/tech: %s / %s", web.Type, web.Technologies[0].Name)
	}
	if web.Machine != types.Container {
		t.Fatalf("web machine = %s, want container", web.Machine)
	}

	db := assetByID(m, "shop-db-k8s")
	if db == nil {
		t.Fatal("db statefulset asset missing")
	}
	if db.Type != types.Datastore || db.Technologies[0].Name != types.Database {
		t.Fatalf("postgres should be datastore/database, got %s / %s", db.Type, db.Technologies[0].Name)
	}
}

func TestImportTags(t *testing.T) {
	m := importSample(t)
	web := assetByID(m, "shop-web-k8s")
	if !hasTag(web.Tags, "run-as-non-root") {
		t.Errorf("web should carry run-as-non-root tag, got %v", web.Tags)
	}
	db := assetByID(m, "shop-db-k8s")
	if !hasTag(db.Tags, "privileged-container") {
		t.Errorf("db should carry privileged-container tag, got %v", db.Tags)
	}
}

func TestImportInternetExposureAndLink(t *testing.T) {
	m := importSample(t)
	web := assetByID(m, "shop-web-k8s")
	if !web.Internet {
		t.Error("web behind a LoadBalancer service should be internet-exposed")
	}
	if len(m.CommunicationLinks) == 0 {
		t.Fatal("expected a communication link from the internet client to web")
	}
	var foundLink bool
	for _, l := range m.CommunicationLinks {
		if l.TargetId == "shop-web-k8s" {
			foundLink = true
		}
	}
	if !foundLink {
		t.Error("no communication link targeting web")
	}
	// db has only a ClusterIP-less StatefulSet (no exposing service) -> not internet.
	if assetByID(m, "shop-db-k8s").Internet {
		t.Error("db should not be internet-exposed")
	}
}

func TestImportNamespaceBoundary(t *testing.T) {
	m := importSample(t)
	tb := m.TrustBoundaries["namespace-shop-k8s"]
	if tb == nil {
		t.Fatal("namespace trust boundary missing")
	}
	if tb.Type != types.NetworkPolicyNamespaceIsolation {
		t.Fatalf("boundary type = %s, want namespace isolation", tb.Type)
	}
	if !contains(tb.TechnicalAssetsInside, "shop-web-k8s") || !contains(tb.TechnicalAssetsInside, "shop-db-k8s") {
		t.Fatalf("namespace should contain web and db, got %v", tb.TechnicalAssetsInside)
	}
}

func TestImportSecretDataAsset(t *testing.T) {
	m := importSample(t)
	da := m.DataAssets["data-shop-db-creds-k8s"]
	if da == nil {
		t.Fatal("secret data asset missing")
	}
	if da.Confidentiality != types.StrictlyConfidential {
		t.Errorf("secret should be strictly-confidential, got %s", da.Confidentiality)
	}
}

func TestImportEmptyAndInvalid(t *testing.T) {
	if _, err := Import([]byte(""), ImportOptions{}); err == nil {
		t.Error("empty input should error")
	}
	if _, err := Import([]byte("not: a manifest\nfoo: bar\n"), ImportOptions{}); err == nil {
		t.Error("manifest with no kind/objects should error")
	}
	// Malformed YAML must not panic.
	if _, err := Import([]byte("kind: Deployment\nspec: [oops\n"), ImportOptions{}); err == nil {
		t.Error("malformed YAML should error")
	}
}

func TestImportSourceLabel(t *testing.T) {
	m, err := Import([]byte(sampleManifests), ImportOptions{SourceLabel: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	if assetByID(m, "shop-web-prod") == nil {
		t.Fatal("source label not applied to asset IDs")
	}
}

func TestIngressResolvesViaServiceSelector(t *testing.T) {
	// Ingress -> Service "api" -> selector {app: backend} -> the workload whose
	// app label is "backend" (NOT named "api"). The heuristic alone would miss it.
	manifests := `
apiVersion: apps/v1
kind: Deployment
metadata: {name: backend-deploy, namespace: prod, labels: {app: backend}}
spec:
  template:
    metadata: {labels: {app: backend}}
    spec:
      containers: [{name: app, image: corp/backend:1}]
---
apiVersion: v1
kind: Service
metadata: {name: api, namespace: prod}
spec: {type: ClusterIP, selector: {app: backend}, ports: [{port: 80}]}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: web, namespace: prod}
spec:
  rules:
    - host: example.com
      http:
        paths:
          - path: /
            backend: {service: {name: api}}
`
	m, err := Import([]byte(manifests), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	be := m.TechnicalAssets["prod-backend-deploy-k8s"]
	if be == nil || !be.Internet {
		t.Fatalf("ingress should expose the backend workload via the Service selector; internet=%v", be != nil && be.Internet)
	}
}

func TestPVCInNamespaceBoundary(t *testing.T) {
	manifests := `
apiVersion: apps/v1
kind: Deployment
metadata: {name: app, namespace: data, labels: {app: a}}
spec:
  template:
    metadata: {labels: {app: a}}
    spec: {containers: [{name: a, image: corp/a:1}]}
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: storage, namespace: data}
`
	m, err := Import([]byte(manifests), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	tb := m.TrustBoundaries["namespace-data-k8s"]
	if tb == nil {
		t.Fatal("namespace boundary missing")
	}
	if !contains(tb.TechnicalAssetsInside, "data-storage-pvc-k8s") {
		t.Fatalf("PVC should be inside its namespace boundary, got %v", tb.TechnicalAssetsInside)
	}
}

func TestImportDeterministic(t *testing.T) {
	// Image matching multiple datastore needles must classify deterministically.
	manifests := `
apiVersion: v1
kind: Pod
metadata: {name: p, namespace: x, labels: {app: p}}
spec:
  containers: [{name: c, image: registry/redis-postgres-bridge:1}]
`
	first, err := Import([]byte(manifests), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := first.TechnicalAssets["x-p-k8s"].Technologies[0].Name
	for i := 0; i < 20; i++ {
		m, _ := Import([]byte(manifests), ImportOptions{})
		if got := m.TechnicalAssets["x-p-k8s"].Technologies[0].Name; got != want {
			t.Fatalf("non-deterministic classification: %s vs %s", got, want)
		}
	}
}

func hasTag(tags []string, want string) bool { return contains(tags, want) }

func contains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}
