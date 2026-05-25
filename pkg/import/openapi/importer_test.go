package openapi

import (
	"testing"
)

const sampleSpec = `
openapi: "3.0.3"
info:
  title: "Pet Store API"
  version: "1.0.0"
servers:
  - url: "https://api.petstore.com/v1"
paths:
  /pets:
    get:
      operationId: listPets
      tags: ["Pets"]
      responses:
        "200":
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: "#/components/schemas/Pet"
  /owners:
    post:
      operationId: createOwner
      tags: ["Owners"]
      requestBody:
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/Owner"
      responses:
        "201":
          description: Created
components:
  schemas:
    Pet:
      type: object
      properties:
        id:
          type: string
        name:
          type: string
    Owner:
      type: object
      properties:
        id:
          type: string
        email:
          type: string
        phone:
          type: string
        address:
          type: string
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
`

func TestImport_openapi_basic(t *testing.T) {
	model, err := Import([]byte(sampleSpec), ImportOptions{SourceLabel: "test"})
	if err != nil {
		t.Fatalf("Import failed: %v", err)
	}

	// Should have a client asset
	if _, ok := model.TechnicalAssets["client-test"]; !ok {
		t.Error("expected client-test asset")
	}

	// Should have one asset per tag group (Pets, Owners)
	if _, ok := model.TechnicalAssets["api-pets-test"]; !ok {
		t.Error("expected api-pets-test asset")
	}
	if _, ok := model.TechnicalAssets["api-owners-test"]; !ok {
		t.Error("expected api-owners-test asset")
	}

	// Owner schema has email/phone/address → PII
	ownerDataID := "data-owner-test"
	da, ok := model.DataAssets[ownerDataID]
	if !ok {
		t.Errorf("expected PII data asset %q", ownerDataID)
	} else if !da.HasPii {
		t.Error("expected HasPii=true on Owner data asset")
	}

	// Pet schema has no PII fields
	if _, ok := model.DataAssets["data-pet-test"]; ok {
		t.Error("Pet schema has no PII fields, should not produce a PII data asset")
	}

	// Should have communication links
	if len(model.CommunicationLinks) == 0 {
		t.Error("expected communication links")
	}
}

func TestImport_openapi_internet_detection(t *testing.T) {
	spec := `
openapi: "3.0.3"
info:
  title: "Internal API"
  version: "1.0.0"
servers:
  - url: "http://localhost:8080"
paths:
  /health:
    get:
      responses:
        "200":
          description: OK
`
	model, err := Import([]byte(spec), ImportOptions{})
	if err != nil {
		t.Fatalf("Import failed: %v", err)
	}
	for _, asset := range model.TechnicalAssets {
		if asset.Id == "client-api" {
			continue
		}
		if asset.Internet {
			t.Errorf("localhost server should not be marked internet=true, got asset %s", asset.Id)
		}
	}
}

func TestImport_openapi_json_format(t *testing.T) {
	spec := `{"openapi":"3.0.3","info":{"title":"JSON API","version":"1.0.0"},"paths":{"/health":{"get":{"responses":{"200":{"description":"OK"}}}}}}`
	model, err := Import([]byte(spec), ImportOptions{})
	if err != nil {
		t.Fatalf("JSON format import failed: %v", err)
	}
	if model.Title != "JSON API" {
		t.Errorf("expected title 'JSON API', got %q", model.Title)
	}
}

func TestImport_openapi_pii_heuristic(t *testing.T) {
	tests := []struct {
		field    string
		expectPII bool
	}{
		{"email", true},
		{"user_email", true},
		{"phone", true},
		{"first_name", true},
		{"address", true},
		{"ip_address", true},
		{"credit_card", true},
		{"product_name", false},
		{"item_count", false},
		{"status", false},
	}
	for _, tc := range tests {
		got := looksLikePII(tc.field)
		if got != tc.expectPII {
			t.Errorf("looksLikePII(%q): expected %v, got %v", tc.field, tc.expectPII, got)
		}
	}
}
