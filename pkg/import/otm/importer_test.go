package otm

import (
	"testing"

	"github.com/threagile/threagile/pkg/types"
)

// A compact OTM document: a nested trust zone (public internet inside a
// "external" root zone, plus a private zone), a web app and a database
// component, a dataflow between them, and one data asset.
const sampleOTM = `{
  "otmVersion": "0.2.0",
  "project": {"id": "proj1", "name": "Test Project", "description": "sample"},
  "trustZones": [
    {"id": "tz-external", "name": "External", "risk": {"trustRating": 10}},
    {"id": "tz-internet", "name": "Public Internet", "risk": {"trustRating": 1}, "parent": {"trustZone": "tz-external"}},
    {"id": "tz-private", "name": "Private Network", "risk": {"trustRating": 90}}
  ],
  "components": [
    {"id": "c-web", "name": "Web App", "type": "web-application", "parent": {"trustZone": "tz-internet"}},
    {"id": "c-db", "name": "Postgres Database", "type": "database", "parent": {"trustZone": "tz-private"}}
  ],
  "dataflows": [
    {"id": "df1", "name": "SQL Query", "source": "c-web", "destination": "c-db", "bidirectional": false}
  ],
  "assets": [
    {"id": "a1", "name": "Customer PII", "risk": {"confidentiality": 90, "integrity": 50, "availability": 30}}
  ]
}`

func importSample(t *testing.T) *types.Model {
	t.Helper()
	m, err := Import([]byte(sampleOTM), ImportOptions{})
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}
	return m
}

func TestComponentsClassified(t *testing.T) {
	m := importSample(t)
	if m.Title != "Test Project" {
		t.Errorf("title = %q", m.Title)
	}
	web := m.TechnicalAssets["comp-c-web-otm"]
	if web == nil || web.Type != types.Process || web.Technologies[0].Name != types.WebApplication {
		t.Fatalf("web-application component should be a Process/web-application: %+v", web)
	}
	db := m.TechnicalAssets["comp-c-db-otm"]
	if db == nil || db.Type != types.Datastore || db.Technologies[0].Name != types.Database {
		t.Fatalf("database component should be a Datastore/database: %+v", db)
	}
	if !contains(web.Tags, reviewTag) || !contains(db.Tags, reviewTag) {
		t.Error("every generated technical asset must carry the review-otm tag")
	}
}

func TestDataflowsBecomeLinks(t *testing.T) {
	m := importSample(t)
	if len(m.CommunicationLinks) != 1 {
		t.Fatalf("expected 1 communication link, got %d", len(m.CommunicationLinks))
	}
	for _, l := range m.CommunicationLinks {
		if l.SourceId != "comp-c-web-otm" || l.TargetId != "comp-c-db-otm" {
			t.Errorf("unexpected link endpoints: %+v", l)
		}
	}
}

func TestNestedTrustZones(t *testing.T) {
	m := importSample(t)
	root := m.TrustBoundaries["zone-tz-external-otm"]
	inner := m.TrustBoundaries["zone-tz-internet-otm"]
	private := m.TrustBoundaries["zone-tz-private-otm"]
	if root == nil || inner == nil || private == nil {
		t.Fatal("expected all three trust zones to become trust boundaries")
	}
	if !contains(root.TrustBoundariesNested, inner.Id) {
		t.Errorf("external zone should nest the internet zone: %v", root.TrustBoundariesNested)
	}
	if !contains(inner.TechnicalAssetsInside, "comp-c-web-otm") {
		t.Errorf("internet zone should contain the web component: %v", inner.TechnicalAssetsInside)
	}
	if !contains(private.TechnicalAssetsInside, "comp-c-db-otm") {
		t.Errorf("private zone should contain the db component: %v", private.TechnicalAssetsInside)
	}
	// A very low trustRating (1) marks the zone as network-on-prem
	// (untrusted) even though its name doesn't say "internet"... except here
	// it does; check the rating-driven private zone stays virtual-lan.
	if private.Type != types.NetworkVirtualLAN {
		t.Errorf("high-trust private zone should stay network-virtual-lan, got %s", private.Type)
	}
	if inner.Type != types.NetworkOnPrem {
		t.Errorf("low-trust internet zone should be network-on-prem, got %s", inner.Type)
	}
}

func TestComponentInternetExposureFromZone(t *testing.T) {
	m := importSample(t)
	web := m.TechnicalAssets["comp-c-web-otm"]
	db := m.TechnicalAssets["comp-c-db-otm"]
	if !web.Internet {
		t.Error("component in an untrusted (network-on-prem) zone should be internet-facing")
	}
	if db.Internet {
		t.Error("component in the private zone should not be internet-facing")
	}
}

func TestDataAssetsFromRiskScores(t *testing.T) {
	m := importSample(t)
	if len(m.DataAssets) != 1 {
		t.Fatalf("expected 1 data asset, got %d", len(m.DataAssets))
	}
	for _, da := range m.DataAssets {
		if da.Title != "Customer PII" {
			t.Errorf("title = %q", da.Title)
		}
		// confidentiality=90 -> bucket 4 (StrictlyConfidential)
		if da.Confidentiality != types.StrictlyConfidential {
			t.Errorf("confidentiality = %s, want strictly-confidential", da.Confidentiality)
		}
		// integrity=50 -> bucket 2 (Important)
		if da.Integrity != types.Important {
			t.Errorf("integrity = %s, want important", da.Integrity)
		}
		// availability=30 -> bucket 1 (Operational)
		if da.Availability != types.Operational {
			t.Errorf("availability = %s, want operational", da.Availability)
		}
	}
}

func TestBidirectionalDataflow(t *testing.T) {
	doc := `{"components":[{"id":"a","name":"A","type":"process"},{"id":"b","name":"B","type":"process"}],
	  "dataflows":[{"id":"f1","source":"a","destination":"b","bidirectional":true}]}`
	m, err := Import([]byte(doc), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.CommunicationLinks) != 2 {
		t.Fatalf("bidirectional flow should produce 2 links, got %d", len(m.CommunicationLinks))
	}
}

func TestMissingOptionalFields(t *testing.T) {
	// Minimal document: no project, no trust zones, no assets — just one
	// component so the import doesn't error.
	doc := `{"components":[{"id":"c1","name":"Solo","type":"unknown-thing"}]}`
	m, err := Import([]byte(doc), ImportOptions{})
	if err != nil {
		t.Fatalf("minimal document should still import: %v", err)
	}
	if m.Title != "Imported from OTM" {
		t.Errorf("title fallback = %q", m.Title)
	}
	c := m.TechnicalAssets["comp-c1-otm"]
	if c == nil || c.Type != types.Process || c.Technologies[0].Name != types.UnknownTechnology {
		t.Fatalf("unrecognised component type should default to Process/unknown-technology: %+v", c)
	}
}

func TestImportErrors(t *testing.T) {
	if _, err := Import([]byte("not json"), ImportOptions{}); err == nil {
		t.Error("invalid JSON should error")
	}
	if _, err := Import([]byte(`{}`), ImportOptions{}); err == nil {
		t.Error("no components should error")
	}
	if _, err := Import([]byte(`{"components":[]}`), ImportOptions{}); err == nil {
		t.Error("empty components should error")
	}
}

func TestDeterministic(t *testing.T) {
	first := importSample(t)
	for i := 0; i < 10; i++ {
		m := importSample(t)
		if len(m.TechnicalAssets) != len(first.TechnicalAssets) ||
			len(m.TrustBoundaries) != len(first.TrustBoundaries) ||
			len(m.CommunicationLinks) != len(first.CommunicationLinks) ||
			len(m.DataAssets) != len(first.DataAssets) {
			t.Fatal("non-deterministic import")
		}
	}
}

func TestDuplicateIDsDontCollide(t *testing.T) {
	// Two components whose ids normalise identically ("c 1" vs "c-1").
	doc := `{"components":[{"id":"c 1","name":"First","type":"process"},{"id":"c-1","name":"Second","type":"process"}]}`
	m, err := Import([]byte(doc), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.TechnicalAssets) != 2 {
		t.Fatalf("expected 2 distinct assets, got %d", len(m.TechnicalAssets))
	}
}

func contains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}
