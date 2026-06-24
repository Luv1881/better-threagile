package attack

import (
	"encoding/json"
	"testing"

	"github.com/threagile/threagile/pkg/types"
)

func r(cat string, sev types.RiskSeverity) *types.Risk {
	return &types.Risk{CategoryId: cat, Severity: sev}
}

func findTechnique(layer Layer, id string) (TechniqueRef, bool) {
	for _, t := range layer.Techniques {
		if t.TechniqueID == id {
			return t, true
		}
	}
	return TechniqueRef{}, false
}

func TestBuildLayerAggregatesByTechnique(t *testing.T) {
	risks := []*types.Risk{
		r("sql-nosql-injection", types.HighSeverity), // T1190
		r("ldap-injection", types.MediumSeverity),    // T1190
		r("path-traversal", types.ElevatedSeverity),  // T1190, T1005
	}
	res := BuildLayer("My Model", risks)

	t1190, ok := findTechnique(res.Layer, "T1190")
	if !ok {
		t.Fatal("T1190 missing")
	}
	if t1190.Score != 3 {
		t.Fatalf("T1190 score = %d, want 3 (all three map to it)", t1190.Score)
	}
	// max severity among the three is High -> red color bucket.
	if t1190.Color != "#e60000" {
		t.Fatalf("T1190 color = %s, want high-severity red", t1190.Color)
	}
	t1005, ok := findTechnique(res.Layer, "T1005")
	if !ok || t1005.Score != 1 {
		t.Fatalf("T1005 should have score 1 (path-traversal), got %+v ok=%v", t1005, ok)
	}
}

func TestBuildLayerSkipsNilRisks(t *testing.T) {
	// BuildLayer is exported; a nil element must not panic.
	res := BuildLayer("m", []*types.Risk{nil, r("sql-nosql-injection", types.HighSeverity), nil})
	if t1190, ok := findTechnique(res.Layer, "T1190"); !ok || t1190.Score != 1 {
		t.Fatalf("expected T1190 score 1 ignoring nils, got %+v ok=%v", t1190, ok)
	}
}

func TestBuildLayerReportsUnmapped(t *testing.T) {
	res := BuildLayer("m", []*types.Risk{r("some-unknown-category", types.LowSeverity)})
	if len(res.Layer.Techniques) != 0 {
		t.Fatalf("unknown category should map to no techniques, got %d", len(res.Layer.Techniques))
	}
	if len(res.UnmappedCategories) != 1 || res.UnmappedCategories[0] != "some-unknown-category" {
		t.Fatalf("unmapped category not reported: %v", res.UnmappedCategories)
	}
}

func TestBuildLayerDeterministicAndValidJSON(t *testing.T) {
	risks := []*types.Risk{
		r("unencrypted-communication", types.ElevatedSeverity),
		r("code-backdooring", types.CriticalSeverity),
	}
	a := BuildLayer("x", risks)
	b := BuildLayer("x", risks)
	ja, _ := json.Marshal(a.Layer)
	jb, _ := json.Marshal(b.Layer)
	if string(ja) != string(jb) {
		t.Fatal("layer output is not deterministic")
	}
	// Techniques must be sorted by ID.
	for i := 1; i < len(a.Layer.Techniques); i++ {
		if a.Layer.Techniques[i-1].TechniqueID > a.Layer.Techniques[i].TechniqueID {
			t.Fatal("techniques not sorted by ID")
		}
	}
	if a.Layer.Domain != "enterprise-attack" || a.Layer.Versions.Layer != "4.5" {
		t.Fatalf("unexpected layer metadata: %+v", a.Layer.Versions)
	}
}

func TestEveryMappedTechniqueHasName(t *testing.T) {
	// Guard against adding a technique to the mapping without a name entry
	// (which would degrade Navigator comments/legend).
	for cat, techniques := range CategoryTechniques {
		for _, tid := range techniques {
			if TechniqueName(tid) == "" {
				t.Errorf("technique %s (category %s) has no name in techniqueNames", tid, cat)
			}
		}
	}
}

func TestModelNameFallback(t *testing.T) {
	res := BuildLayer("", nil)
	if res.Layer.Name != "Threagile threat model" {
		t.Fatalf("empty model name should fall back, got %q", res.Layer.Name)
	}
}
