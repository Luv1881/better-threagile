package mermaid

import (
	"strings"
	"testing"

	"github.com/threagile/threagile/pkg/types"
)

// model: client(internet, external) -> lb(dmz) -> api(internal) -> db(data-tier, nested in internal).
// client is in no boundary (orphan). api has a High risk, db a Critical risk.
func buildModel() *types.Model {
	link := func(target, title string, proto types.Protocol) *types.CommunicationLink {
		return &types.CommunicationLink{TargetId: target, Title: title, Protocol: proto}
	}
	return &types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"client": {Id: "client", Title: "Browser", Type: types.ExternalEntity, Internet: true,
				CommunicationLinks: []*types.CommunicationLink{link("lb", "https", types.HTTPS)}},
			"lb": {Id: "lb", Title: "Load Balancer", Type: types.Process,
				CommunicationLinks: []*types.CommunicationLink{link("api", "forward", types.HTTP)}},
			"api": {Id: "api", Title: "API Server", Type: types.Process,
				CommunicationLinks: []*types.CommunicationLink{link("db", "query", types.JDBC)}},
			"db": {Id: "db", Title: "PostgreSQL", Type: types.Datastore},
		},
		TrustBoundaries: map[string]*types.TrustBoundary{
			"dmz":       {Id: "dmz", Title: "DMZ", TechnicalAssetsInside: []string{"lb"}},
			"internal":  {Id: "internal", Title: "Internal", TechnicalAssetsInside: []string{"api"}, TrustBoundariesNested: []string{"data-tier"}},
			"data-tier": {Id: "data-tier", Title: "Data Tier", TechnicalAssetsInside: []string{"db"}},
		},
		GeneratedRisksByCategory: map[string][]*types.Risk{
			"cat-a": {{Severity: types.HighSeverity, MostRelevantTechnicalAssetId: "api"}},
			"cat-b": {{Severity: types.CriticalSeverity, MostRelevantTechnicalAssetId: "db"}},
		},
	}
}

func TestStructureAndShapes(t *testing.T) {
	out := DataFlowDiagram(buildModel(), Options{WithRisks: true})
	checks := []string{
		"flowchart TB",
		`subgraph tb_dmz["DMZ`,
		`subgraph tb_internal["Internal`,
		`subgraph tb_data_tier["Data Tier`, // nested boundary rendered
		`n_db[("PostgreSQL")]`,             // datastore = cylinder
		`n_client(["Browser"])`,            // external entity = stadium
		`n_lb["Load Balancer"]`,            // process = box
		"%% assets outside any trust boundary",
	}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Errorf("output missing %q\n---\n%s", c, out)
		}
	}
	// each asset node declared exactly once
	if n := strings.Count(out, `n_db[(`); n != 1 {
		t.Errorf("db should be declared once, got %d\n%s", n, out)
	}
}

func TestNestedBoundaryContainsChildNotParentDuplicate(t *testing.T) {
	out := DataFlowDiagram(buildModel(), Options{})
	// data-tier subgraph must be nested inside internal (deeper indentation),
	// and db must not also appear at top level.
	internalIdx := strings.Index(out, "subgraph tb_internal")
	dataTierIdx := strings.Index(out, "subgraph tb_data_tier")
	if internalIdx < 0 || dataTierIdx < 0 || dataTierIdx < internalIdx {
		t.Fatalf("data-tier should be rendered after/within internal:\n%s", out)
	}
	if !strings.Contains(out, `    n_db[(`) { // 4-space indent => depth 2
		t.Errorf("db should be indented as a nested-boundary member:\n%s", out)
	}
}

func TestEdgeEncryptionStyling(t *testing.T) {
	out := DataFlowDiagram(buildModel(), Options{})
	if !strings.Contains(out, `n_client -->|https| n_lb`) {
		t.Errorf("encrypted https link should be a solid edge:\n%s", out)
	}
	if !strings.Contains(out, `n_lb -.->|forward| n_api`) {
		t.Errorf("cleartext http link should be a dashed edge:\n%s", out)
	}
	if !strings.Contains(out, `n_api -.->|query| n_db`) {
		t.Errorf("cleartext jdbc link should be a dashed edge:\n%s", out)
	}
}

func TestEdgeLabelPipeEscaped(t *testing.T) {
	m := buildModel()
	m.TechnicalAssets["client"].CommunicationLinks[0].Title = "HTTPS | TLS"
	out := DataFlowDiagram(m, Options{})
	// the raw '|' must not appear inside the label (it delimits the edge text)
	if !strings.Contains(out, "HTTPS #124; TLS") {
		t.Errorf("pipe in edge label should be entity-escaped:\n%s", out)
	}
	if strings.Contains(out, `|HTTPS | TLS|`) {
		t.Errorf("raw pipe leaked into edge label, breaking syntax:\n%s", out)
	}
}

func TestSubgraphIDCollisionResolved(t *testing.T) {
	m := buildModel()
	// "a-b" and "a_b" both sanitize to "tb_a_b"; they must stay distinct.
	m.TrustBoundaries["a-b"] = &types.TrustBoundary{Id: "a-b", Title: "AB1"}
	m.TrustBoundaries["a_b"] = &types.TrustBoundary{Id: "a_b", Title: "AB2"}
	out := DataFlowDiagram(m, Options{})
	if strings.Count(out, "subgraph tb_a_b[") > 1 && !strings.Contains(out, "tb_a_b_2") {
		t.Errorf("colliding subgraph IDs not disambiguated:\n%s", out)
	}
	// both titles present, each in its own subgraph
	if !strings.Contains(out, `["AB1`) || !strings.Contains(out, `["AB2`) {
		t.Errorf("both boundaries should render:\n%s", out)
	}
}

func TestCyclicBoundaryStillRendered(t *testing.T) {
	// A nests B and B nests A: neither is a top-level root. Assets must not be lost.
	m := &types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"x": {Id: "x", Title: "X", Type: types.Process},
			"y": {Id: "y", Title: "Y", Type: types.Process},
		},
		TrustBoundaries: map[string]*types.TrustBoundary{
			"a": {Id: "a", Title: "A", TechnicalAssetsInside: []string{"x"}, TrustBoundariesNested: []string{"b"}},
			"b": {Id: "b", Title: "B", TechnicalAssetsInside: []string{"y"}, TrustBoundariesNested: []string{"a"}},
		},
	}
	out := DataFlowDiagram(m, Options{})
	if !strings.Contains(out, "n_x[\"X\"]") || !strings.Contains(out, "n_y[\"Y\"]") {
		t.Errorf("assets inside cyclic boundaries must not be dropped:\n%s", out)
	}
	if strings.Count(out, "subgraph tb_a[") != 1 || strings.Count(out, "subgraph tb_b[") != 1 {
		t.Errorf("each boundary should be rendered exactly once:\n%s", out)
	}
}

func TestRiskColoring(t *testing.T) {
	with := DataFlowDiagram(buildModel(), Options{WithRisks: true})
	if !strings.Contains(with, "classDef sevHigh ") || !strings.Contains(with, "classDef sevCritical ") {
		t.Errorf("severity classDefs missing:\n%s", with)
	}
	if !strings.Contains(with, "class n_api sevHigh;") {
		t.Errorf("api should be coloured High:\n%s", with)
	}
	if !strings.Contains(with, "class n_db sevCritical;") {
		t.Errorf("db should be coloured Critical:\n%s", with)
	}
	if !strings.Contains(with, "class n_client internet;") {
		t.Errorf("internet-facing client should get the internet class:\n%s", with)
	}

	without := DataFlowDiagram(buildModel(), Options{WithRisks: false})
	if strings.Contains(without, "sevHigh") {
		t.Errorf("WithRisks=false should not emit severity classes:\n%s", without)
	}
	if !strings.Contains(without, "class n_client internet;") {
		t.Errorf("internet class should still appear without risk colouring:\n%s", without)
	}
}

func TestDirectionLR(t *testing.T) {
	out := DataFlowDiagram(buildModel(), Options{Direction: "lr"})
	if !strings.HasPrefix(out, "flowchart LR\n") {
		t.Errorf("LR direction not honoured:\n%s", out)
	}
}

func TestDanglingLinkSkipped(t *testing.T) {
	m := buildModel()
	m.TechnicalAssets["api"].CommunicationLinks = append(m.TechnicalAssets["api"].CommunicationLinks,
		&types.CommunicationLink{TargetId: "ghost", Title: "nowhere", Protocol: types.HTTPS})
	out := DataFlowDiagram(m, Options{})
	if strings.Contains(out, "ghost") {
		t.Errorf("dangling link target should be skipped:\n%s", out)
	}
}

func TestDeterministic(t *testing.T) {
	first := DataFlowDiagram(buildModel(), Options{WithRisks: true})
	for i := 0; i < 10; i++ {
		if DataFlowDiagram(buildModel(), Options{WithRisks: true}) != first {
			t.Fatal("non-deterministic mermaid output")
		}
	}
}

func TestEscapingAndSanitize(t *testing.T) {
	if got := sanitize("a-b.c/d"); got != "a_b_c_d" {
		t.Errorf("sanitize = %q, want a_b_c_d", got)
	}
	if got := esc(`he said "hi"`); !strings.Contains(got, "#34;") || strings.Contains(got, `"`) {
		t.Errorf("esc did not escape quotes: %q", got)
	}
	if got := esc(`a|b<c>d\e`); strings.ContainsAny(got, `|<>\`) {
		t.Errorf("esc left a syntax-breaking char unescaped: %q", got)
	}
}

func TestEmptyModel(t *testing.T) {
	out := DataFlowDiagram(&types.Model{}, Options{WithRisks: true})
	if !strings.HasPrefix(out, "flowchart TB\n") {
		t.Errorf("empty model should still produce a header:\n%s", out)
	}
}
