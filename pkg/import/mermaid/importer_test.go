package mermaid

import (
	"testing"

	"github.com/threagile/threagile/pkg/types"
)

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// sampleMermaid mirrors the grammar example from improvement.md P5: a stadium
// (user), rectangle (process), and cylinder (datastore), a named subgraph
// boundary, and two labelled edges.
const sampleMermaid = `flowchart TD
  User([User])
  API[API Server]
  DB[(Postgres)]
  subgraph "DMZ"
    API
  end
  User -->|HTTPS| API
  API -->|SQL| DB
`

func importSample(t *testing.T) *types.Model {
	t.Helper()
	m, err := Import([]byte(sampleMermaid), ImportOptions{})
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}
	return m
}

func TestNodeShapesClassified(t *testing.T) {
	m := importSample(t)

	user := m.TechnicalAssets["user-mermaid"]
	if user == nil || user.Type != types.ExternalEntity {
		t.Fatalf("stadium node should be an ExternalEntity: %+v", user)
	}
	if !user.Internet {
		t.Errorf("external entity should be marked internet-facing")
	}

	api := m.TechnicalAssets["api-mermaid"]
	if api == nil || api.Type != types.Process {
		t.Fatalf("rectangle node should be a Process: %+v", api)
	}

	db := m.TechnicalAssets["db-mermaid"]
	if db == nil || db.Type != types.Datastore || db.Technologies[0].Name != types.Database {
		t.Fatalf("cylinder node should be a Datastore/database: %+v", db)
	}

	for _, a := range []*types.TechnicalAsset{user, api, db} {
		if !contains(a.Tags, reviewTag) {
			t.Errorf("%s missing review-mermaid tag", a.Id)
		}
	}
}

func TestEdgesBecomeLinksWithProtocolGuess(t *testing.T) {
	m := importSample(t)
	if len(m.CommunicationLinks) != 2 {
		t.Fatalf("expected 2 communication links, got %d", len(m.CommunicationLinks))
	}
	var sawHTTPS, sawSQL bool
	for _, l := range m.CommunicationLinks {
		switch l.Protocol {
		case types.HTTPS:
			sawHTTPS = true
			if l.SourceId != "user-mermaid" || l.TargetId != "api-mermaid" {
				t.Errorf("unexpected HTTPS link endpoints: %+v", l)
			}
		case types.SqlAccessProtocolEncrypted:
			sawSQL = true
			if l.SourceId != "api-mermaid" || l.TargetId != "db-mermaid" {
				t.Errorf("unexpected SQL link endpoints: %+v", l)
			}
		}
	}
	if !sawHTTPS || !sawSQL {
		t.Errorf("expected HTTPS and SQL-protocol links, sawHTTPS=%v sawSQL=%v", sawHTTPS, sawSQL)
	}
}

func TestSubgraphBecomesTrustBoundary(t *testing.T) {
	m := importSample(t)
	if len(m.TrustBoundaries) != 1 {
		t.Fatalf("expected 1 trust boundary, got %d", len(m.TrustBoundaries))
	}
	for _, tb := range m.TrustBoundaries {
		if tb.Title != "DMZ" {
			t.Errorf("boundary title = %q, want DMZ", tb.Title)
		}
		if !contains(tb.TechnicalAssetsInside, "api-mermaid") {
			t.Errorf("DMZ boundary should contain api-mermaid: %v", tb.TechnicalAssetsInside)
		}
		if tb.Type != types.NetworkOnPrem {
			t.Errorf("DMZ keyword should classify as NetworkOnPrem, got %v", tb.Type)
		}
	}
}

func TestNestedSubgraphs(t *testing.T) {
	src := `flowchart LR
subgraph Outer["Outer Zone"]
  subgraph Inner["Inner Zone"]
    Svc[Service]
  end
  Edge[Edge Proxy]
end
Edge --> Svc
`
	m, err := Import([]byte(src), ImportOptions{})
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}
	if len(m.TrustBoundaries) != 2 {
		t.Fatalf("expected 2 nested trust boundaries, got %d", len(m.TrustBoundaries))
	}
	var outer, inner *types.TrustBoundary
	for _, tb := range m.TrustBoundaries {
		switch tb.Title {
		case "Outer Zone":
			outer = tb
		case "Inner Zone":
			inner = tb
		}
	}
	if outer == nil || inner == nil {
		t.Fatalf("expected both Outer Zone and Inner Zone boundaries, got %+v", m.TrustBoundaries)
	}
	if !contains(outer.TrustBoundariesNested, inner.Id) {
		t.Errorf("outer boundary should nest inner: %v", outer.TrustBoundariesNested)
	}
	if !contains(outer.TechnicalAssetsInside, m.TechnicalAssets["edge-mermaid"].Id) {
		t.Errorf("outer boundary should directly contain Edge Proxy: %v", outer.TechnicalAssetsInside)
	}
	if !contains(inner.TechnicalAssetsInside, m.TechnicalAssets["svc-mermaid"].Id) {
		t.Errorf("inner boundary should contain Service: %v", inner.TechnicalAssetsInside)
	}
	if contains(outer.TechnicalAssetsInside, m.TechnicalAssets["svc-mermaid"].Id) {
		t.Errorf("outer boundary should not directly list the inner boundary's members: %v", outer.TechnicalAssetsInside)
	}
}

func TestBareNodeNoLabel(t *testing.T) {
	src := "graph TD\n  A\n  B\n  A --> B\n"
	m, err := Import([]byte(src), ImportOptions{})
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}
	if len(m.TechnicalAssets) != 2 {
		t.Fatalf("expected 2 technical assets, got %d", len(m.TechnicalAssets))
	}
	a := m.TechnicalAssets["a-mermaid"]
	if a == nil || a.Title != "A" || a.Type != types.Process {
		t.Fatalf("bare node should default to a Process titled after its id: %+v", a)
	}
}

func TestDecisionShapeBecomesProcess(t *testing.T) {
	src := "flowchart TD\n  X{Is Valid?}\n"
	m, err := Import([]byte(src), ImportOptions{})
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}
	x := m.TechnicalAssets["x-mermaid"]
	if x == nil || x.Type != types.Process {
		t.Fatalf("rhombus/decision node should map to Process: %+v", x)
	}
}

func TestDottedAndThickEdges(t *testing.T) {
	src := `flowchart TD
  A[A]
  B[B]
  C[C]
  A -.->|async| B
  B ==> C
`
	m, err := Import([]byte(src), ImportOptions{})
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}
	if len(m.CommunicationLinks) != 2 {
		t.Fatalf("expected 2 links, got %d", len(m.CommunicationLinks))
	}
	var sawDotted bool
	for _, l := range m.CommunicationLinks {
		if contains(l.Tags, "mermaid-dotted-edge") {
			sawDotted = true
		}
	}
	if !sawDotted {
		t.Error("dotted edge should carry the mermaid-dotted-edge tag")
	}
}

func TestPlainEdgeNoArrowhead(t *testing.T) {
	src := "graph TD\n  A[A]\n  B[B]\n  A --- B\n"
	m, err := Import([]byte(src), ImportOptions{})
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}
	if len(m.CommunicationLinks) != 1 {
		t.Fatalf("expected 1 link, got %d", len(m.CommunicationLinks))
	}
}

func TestLegacyGraphKeywordAndDirections(t *testing.T) {
	for _, dir := range []string{"TD", "TB", "LR", "RL", "BT"} {
		src := "graph " + dir + "\n  A[A]\n  B[B]\n  A --> B\n"
		m, err := Import([]byte(src), ImportOptions{})
		if err != nil {
			t.Fatalf("direction %s: import failed: %v", dir, err)
		}
		if len(m.TechnicalAssets) != 2 {
			t.Fatalf("direction %s: expected 2 assets, got %d", dir, len(m.TechnicalAssets))
		}
	}
}

func TestEmptyInputErrors(t *testing.T) {
	_, err := Import([]byte(""), ImportOptions{})
	if err == nil {
		t.Fatal("expected an error for empty input")
	}
}

func TestGarbageInputNeverPanicsAndErrors(t *testing.T) {
	garbage := []string{
		"this is not mermaid at all",
		"flowchart TD\n  ][[[unbalanced",
		"subgraph\nend\nend\nend",
		"-->-->-->",
		"flowchart TD\nend\nend\n",
	}
	for _, g := range garbage {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Import panicked on %q: %v", g, r)
				}
			}()
			_, _ = Import([]byte(g), ImportOptions{})
		}()
	}
}

func TestCommentsStripped(t *testing.T) {
	src := "flowchart TD\n  %% this is a comment\n  A[A] %% trailing comment\n  B[B]\n  A --> B\n"
	m, err := Import([]byte(src), ImportOptions{})
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}
	a := m.TechnicalAssets["a-mermaid"]
	if a == nil || a.Title != "A" {
		t.Fatalf("comment stripping should leave a clean label: %+v", a)
	}
}

func TestDataAssetStubAlwaysGenerated(t *testing.T) {
	m := importSample(t)
	if len(m.DataAssets) != 1 {
		t.Fatalf("expected 1 stub data asset, got %d", len(m.DataAssets))
	}
}

func TestSourceLabelDefaultsAndOverrides(t *testing.T) {
	src := "flowchart TD\n  A[A]\n"
	m, err := Import([]byte(src), ImportOptions{SourceLabel: "custom"})
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}
	if _, ok := m.TechnicalAssets["a-custom"]; !ok {
		t.Fatalf("expected id suffixed with custom label, got %+v", m.TechnicalAssets)
	}
}
