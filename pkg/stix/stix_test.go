package stix

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/threagile/threagile/pkg/types"
)

func buildModel() (*types.Model, []*types.Risk) {
	cat := &types.RiskCategory{ID: "sql-nosql-injection", Title: "SQL/NoSQL Injection", CWE: 89, Mitigation: "Use parameterized queries."}
	m := &types.Model{
		Title: "Test TM",
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"web": {Id: "web", Title: "Web Server"},
			"db":  {Id: "db", Title: "Database"},
		},
		// CustomRiskCategories is what GetRiskCategory resolves first.
		CustomRiskCategories: []*types.RiskCategory{cat},
	}

	risks := []*types.Risk{
		{SyntheticId: "sql-nosql-injection@db", CategoryId: "sql-nosql-injection", Title: "SQLi on db", MostRelevantTechnicalAssetId: "db", Severity: types.HighSeverity},
	}
	return m, risks
}

func TestBuildBundleStructure(t *testing.T) {
	m, risks := buildModel()
	res := Build(m, risks, "9.9.9", "deadbeef")
	b := res.Bundle

	if b.Type != "bundle" || !strings.HasPrefix(b.ID, "bundle--") {
		t.Fatalf("bad bundle envelope: %+v", b.Type)
	}
	counts := map[string]int{}
	for _, o := range b.Objects {
		counts[o.Type]++
		if o.SpecVersion != "2.1" {
			t.Errorf("object %s missing spec_version 2.1", o.ID)
		}
		if !strings.HasPrefix(o.ID, o.Type+"--") {
			t.Errorf("object id %q does not start with type prefix", o.ID)
		}
	}
	if counts["identity"] != 1 {
		t.Errorf("want 1 identity, got %d", counts["identity"])
	}
	for _, o := range b.Objects {
		if o.Type == "identity" {
			if o.XThreagileVersion != "9.9.9" || o.XModelSHA256 != "deadbeef" {
				t.Errorf("identity missing provenance props: %+v", o)
			}
		}
	}
	if counts["infrastructure"] != 2 {
		t.Errorf("want 2 infrastructure (assets), got %d", counts["infrastructure"])
	}
	if counts["vulnerability"] != 1 {
		t.Errorf("want 1 vulnerability, got %d", counts["vulnerability"])
	}
	if counts["attack-pattern"] == 0 {
		t.Error("expected attack-pattern objects for ATT&CK/CAPEC")
	}
}

func TestBuildExternalRefsAndRelationships(t *testing.T) {
	m, risks := buildModel()
	b := Build(m, risks, "", "").Bundle

	idType := map[string]string{}
	for _, o := range b.Objects {
		idType[o.ID] = o.Type
	}

	var sawCWE, sawCAPEC, sawATTACK bool
	rels := map[string][2]string{} // relType -> (srcType, tgtType) of one example
	for _, o := range b.Objects {
		for _, ref := range o.ExternalReferences {
			switch ref.SourceName {
			case "cwe":
				sawCWE = ref.ExternalID == "CWE-89"
			case "capec":
				sawCAPEC = strings.HasPrefix(ref.ExternalID, "CAPEC-") && strings.Contains(ref.URL, "capec.mitre.org")
			case "mitre-attack":
				sawATTACK = strings.HasPrefix(ref.ExternalID, "T") && strings.Contains(ref.URL, "attack.mitre.org")
			}
		}
		if o.Type == "relationship" {
			rels[o.RelationshipType] = [2]string{idType[o.SourceRef], idType[o.TargetRef]}
		}
	}
	if !sawCWE || !sawCAPEC || !sawATTACK {
		t.Errorf("missing external refs: cwe=%v capec=%v attack=%v", sawCWE, sawCAPEC, sawATTACK)
	}
	// STIX 2.1 spec-compliant relationship directions.
	if got := rels["has"]; got != [2]string{"infrastructure", "vulnerability"} {
		t.Errorf("'has' should be infrastructure->vulnerability, got %v", got)
	}
	if got := rels["targets"]; got != [2]string{"attack-pattern", "vulnerability"} {
		t.Errorf("'targets' should be attack-pattern->vulnerability, got %v", got)
	}
	if got := rels["mitigates"]; got != [2]string{"course-of-action", "vulnerability"} {
		t.Errorf("'mitigates' should be course-of-action->vulnerability, got %v", got)
	}
}

func TestDeterministicAndValidJSON(t *testing.T) {
	m, risks := buildModel()
	a, _ := json.Marshal(Build(m, risks, "", "").Bundle)
	b, _ := json.Marshal(Build(m, risks, "", "").Bundle)
	if string(a) != string(b) {
		t.Fatal("STIX bundle is not deterministic")
	}
}

func TestSubTechniqueURL(t *testing.T) {
	// Sub-technique dotted IDs become slashed URLs.
	ref := patternRef("T1078.001")
	if ref.URL != "https://attack.mitre.org/techniques/T1078/001" {
		t.Fatalf("sub-technique URL wrong: %s", ref.URL)
	}
	if patternRef("CAPEC-66").URL != "https://capec.mitre.org/data/definitions/66.html" {
		t.Fatalf("capec URL wrong: %s", patternRef("CAPEC-66").URL)
	}
}
