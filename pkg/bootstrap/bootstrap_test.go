package bootstrap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const composeYML = `services:
  web:
    image: nginx
    ports: ["80:80"]
  db:
    image: postgres
`

const openapiYML = `openapi: 3.0.0
info:
  title: Test API
  version: "1.0"
paths:
  /ping:
    get:
      responses:
        "200":
          description: ok
`

const k8sYML = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      containers:
        - name: api
          image: api:latest
`

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestDetectClassifiesSources(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "docker-compose.yml", composeYML)
	writeFile(t, dir, "api/openapi.yaml", openapiYML)
	writeFile(t, dir, "deploy/app.yaml", k8sYML)
	writeFile(t, dir, "infra/main.tf", `resource "aws_s3_bucket" "b" {}`)
	writeFile(t, dir, "README.md", "# not infra")
	writeFile(t, dir, "node_modules/pkg/docker-compose.yml", composeYML) // must be skipped

	sources, err := Detect(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[Kind]int{}
	for _, s := range sources {
		got[s.Kind]++
	}
	if got[Compose] != 1 || got[OpenAPI] != 1 || got[Kubernetes] != 1 || got[Terraform] != 1 {
		t.Fatalf("unexpected detection counts: %+v (sources=%+v)", got, sources)
	}
}

func TestDetectIgnoresOwnOutputs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "threagile.yaml", "title: x\n")
	writeFile(t, dir, "policy.yaml", "name: x\n")
	sources, err := Detect(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 0 {
		t.Errorf("threagile.yaml/policy.yaml must not be treated as sources, got %+v", sources)
	}
}

func TestBuildModelFromCompose(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "docker-compose.yml", composeYML)
	sources, _ := Detect(dir)
	model, notes, err := BuildModel(dir, sources)
	if err != nil {
		t.Fatal(err)
	}
	if len(model.TechnicalAssets) == 0 {
		t.Fatalf("expected assets from compose, got none (notes=%v)", notes)
	}
}

func TestBuildModelTerraformAdvisory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.tf", `resource "aws_s3_bucket" "b" {}`)
	sources, _ := Detect(dir)
	model, notes, err := BuildModel(dir, sources)
	if err != nil {
		t.Fatal(err)
	}
	if len(model.TechnicalAssets) != 0 {
		t.Errorf("terraform HCL should not import assets directly")
	}
	joined := ""
	for _, n := range notes {
		joined += n
	}
	if !strings.Contains(joined, "terraform show -json") {
		t.Errorf("expected a Terraform advisory note, got %v", notes)
	}
}

func TestBuildModelFromOpenAPI(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "openapi.yaml", openapiYML)
	sources, _ := Detect(dir)
	model, notes, err := BuildModel(dir, sources)
	if err != nil {
		t.Fatal(err)
	}
	if len(model.TechnicalAssets) == 0 {
		t.Fatalf("expected assets from OpenAPI, got none (notes=%v)", notes)
	}
}

func TestBuildModelMergesMultipleSources(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "docker-compose.yml", composeYML)
	writeFile(t, dir, "deploy/app.yaml", k8sYML)
	writeFile(t, dir, "api/openapi.yaml", openapiYML)
	sources, _ := Detect(dir)
	model, _, err := BuildModel(dir, sources)
	if err != nil {
		t.Fatal(err)
	}
	// compose (web, db) + k8s (api) + openapi (api server + client) all merged
	if len(model.TechnicalAssets) < 4 {
		t.Errorf("expected merged assets from 3 sources, got %d", len(model.TechnicalAssets))
	}
	// tags_available should be the de-duplicated union (no duplicates)
	seen := map[string]bool{}
	for _, tag := range model.TagsAvailable {
		if seen[tag] {
			t.Errorf("duplicate tag in merged tags_available: %q", tag)
		}
		seen[tag] = true
	}
}

func TestBuildModelSkipsOversizeFile(t *testing.T) {
	dir := t.TempDir()
	// a compose file just over the scan cap must be skipped with a note, not imported
	big := make([]byte, maxScanFileSize+1)
	copy(big, []byte("services:\n  a:\n    image: x\n"))
	writeFile(t, dir, "docker-compose.yml", string(big))
	sources, _ := Detect(dir)
	model, notes, err := BuildModel(dir, sources)
	if err != nil {
		t.Fatal(err)
	}
	if len(model.TechnicalAssets) != 0 {
		t.Errorf("oversize file should be skipped, got %d assets", len(model.TechnicalAssets))
	}
	joined := strings.Join(notes, " ")
	if !strings.Contains(joined, "too large") && !strings.Contains(joined, "skipped") {
		t.Errorf("expected a skip note for the oversize file, got %v", notes)
	}
}

func TestBuildModelDeterministicMerge(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "docker-compose.yml", composeYML)
	writeFile(t, dir, "deploy/app.yaml", k8sYML)
	sources, _ := Detect(dir)
	m1, _, _ := BuildModel(dir, sources)
	m2, _, _ := BuildModel(dir, sources)
	if len(m1.TechnicalAssets) != len(m2.TechnicalAssets) {
		t.Errorf("merge not deterministic: %d vs %d assets", len(m1.TechnicalAssets), len(m2.TechnicalAssets))
	}
}
