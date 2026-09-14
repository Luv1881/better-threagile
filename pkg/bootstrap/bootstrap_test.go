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

func TestDetectSkipsVendoredAndCacheDirs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "docker-compose.yml", composeYML)
	// Python/env noise copied from real repositories: a checked-out virtualenv
	// and a package cache full of unrelated .tf/.yaml files.
	vendored := []string{
		"venv/lib/python3.12/site-packages/slp_tf/terraform_sample.tf",
		".venv-3.12/lib/boto3.tf",
		"__pycache__/cached.tf",
		"site-packages/pkg/openapi.yaml",
		".mypy_cache/3.12/module.tf",
		"node_modules/pkg/docker-compose.yml",
		"bower_components/lib/k8s.yaml",
	}
	for _, rel := range vendored {
		writeFile(t, dir, rel, `resource "aws_s3_bucket" "b" {}`)
	}

	sources, err := Detect(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 1 || sources[0].Kind != Compose {
		t.Fatalf("vendored/cache dirs must be skipped, got %+v", sources)
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

// The OpenAPI classifier must require an actual version declaration: a .NET
// launchSettings.json (or any file with a bare "openapi" section) is not a spec.
func TestClassify_OpenAPIRequiresVersion(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, dir, "launchSettings.json", `{
  "profiles": {"PublicApi": {"commandName": "Project", "launchBrowser": true}},
  "openapi": {"enabled": true}
}`)
	if kind, ok := classify(filepath.Join(dir, "launchSettings.json"), "launchSettings.json"); ok {
		t.Errorf("launchSettings.json with an openapi section must not classify as OpenAPI, got %v", kind)
	}

	writeFile(t, dir, "spec.json", `{"openapi":"3.0.3","info":{"title":"x","version":"1"},"paths":{}}`)
	if kind, ok := classify(filepath.Join(dir, "spec.json"), "spec.json"); !ok || kind != OpenAPI {
		t.Errorf("a real JSON OpenAPI spec must classify as OpenAPI, got %v/%v", kind, ok)
	}

	writeFile(t, dir, "spec.yaml", "openapi: 3.0.3\ninfo:\n  title: x\n")
	if kind, ok := classify(filepath.Join(dir, "spec.yaml"), "spec.yaml"); !ok || kind != OpenAPI {
		t.Errorf("a real YAML OpenAPI spec must classify as OpenAPI, got %v/%v", kind, ok)
	}

	writeFile(t, dir, "swagger.json", `{"swagger":"2.0","info":{"title":"x","version":"1"},"paths":{}}`)
	if kind, ok := classify(filepath.Join(dir, "swagger.json"), "swagger.json"); !ok || kind != OpenAPI {
		t.Errorf("a Swagger 2.0 spec must classify as OpenAPI, got %v/%v", kind, ok)
	}

	// A numeric key is not a version: `swagger: 8080` is a port setting.
	writeFile(t, dir, "config.yaml", "server:\n  swagger: 8080\n")
	if kind, ok := classify(filepath.Join(dir, "config.yaml"), "config.yaml"); ok {
		t.Errorf("swagger: 8080 must not classify as OpenAPI, got %v", kind)
	}

	// Flow-style YAML declarations count too.
	writeFile(t, dir, "flow.yaml", "paths: {}\nopenapi: 3.1.0\n")
	if kind, ok := classify(filepath.Join(dir, "flow.yaml"), "flow.yaml"); !ok || kind != OpenAPI {
		t.Errorf("flow-style openapi declaration must classify, got %v/%v", kind, ok)
	}
}

// `terraform show -json` plan/state files are importable directly (while bare
// .tf stays advisory): the classifier must recognise their shape.
func TestClassify_TerraformPlan(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, dir, "plan.json", `{"format_version":"1.1","terraform_version":"1.7.0","planned_values":{"root_module":{"resources":[{"address":"aws_s3_bucket.b","type":"aws_s3_bucket","name":"b","values":{}}]}}}`)
	if kind, ok := classify(filepath.Join(dir, "plan.json"), "plan.json"); !ok || kind != TerraformPlan {
		t.Errorf("a terraform plan must classify as TerraformPlan, got %v/%v", kind, ok)
	}

	writeFile(t, dir, "terraform.tfstate", `{"format_version":"4","terraform_version":"1.7.0","values":{"root_module":{"resources":[{"address":"aws_s3_bucket.b","type":"aws_s3_bucket","name":"b"}]}}}`)
	if kind, ok := classify(filepath.Join(dir, "terraform.tfstate"), "terraform.tfstate"); !ok || kind != TerraformPlan {
		t.Errorf("a terraform state file must classify as TerraformPlan, got %v/%v", kind, ok)
	}

	// format_version alone (no terraform_version) is somebody else's JSON.
	writeFile(t, dir, "other.json", `{"format_version":"1.1","values":{"a":1}}`)
	if kind, ok := classify(filepath.Join(dir, "other.json"), "other.json"); ok {
		t.Errorf("unrelated JSON must not classify as TerraformPlan, got %v", kind)
	}
}

func TestBuildModelImportsTerraformPlan(t *testing.T) {
	dir := t.TempDir()
	plan := `{"format_version":"1.1","terraform_version":"1.7.0","planned_values":{"root_module":{"resources":[
	  {"address":"aws_db_instance.pg","type":"aws_db_instance","name":"pg","values":{"engine":"postgres"}},
	  {"address":"aws_s3_bucket.assets","type":"aws_s3_bucket","name":"assets","values":{}}
	]}}}`
	writeFile(t, dir, "threagile-plan.json", plan)
	writeFile(t, dir, "infra/main.tf", `resource "aws_s3_bucket" "b" {}`)

	sources, err := Detect(dir)
	if err != nil {
		t.Fatal(err)
	}
	model, notes, err := BuildModel(dir, sources)
	if err != nil {
		t.Fatal(err)
	}
	if len(model.TechnicalAssets) == 0 {
		t.Fatalf("plan resources must become assets, got none (notes=%v)", notes)
	}
	joined := strings.Join(notes, " ")
	if !strings.Contains(joined, "plan/state JSON imported") {
		t.Errorf("notes should say the plan was imported, got %v", notes)
	}
	if strings.Contains(joined, "run `terraform show -json") {
		t.Errorf("plan import must replace the advisory note, got %v", notes)
	}
}
