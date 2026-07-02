package drawio

import (
	"strings"
	"testing"

	"github.com/threagile/threagile/pkg/types"
)

const sampleDrawio = `<mxfile><diagram name="P1"><mxGraphModel><root>
  <mxCell id="0"/>
  <mxCell id="1" parent="0"/>
  <mxCell id="tb1" value="Internet (Untrusted)" style="dashed=1;container=1;" vertex="1" parent="1"><mxGeometry x="20" y="20" width="200" height="400" as="geometry"/></mxCell>
  <mxCell id="tb2" value="Data Zone" style="dashed=1;" vertex="1" parent="1"><mxGeometry x="500" y="20" width="240" height="400" as="geometry"/></mxCell>
  <mxCell id="usr" value="Customer Browser" style="shape=actor;" vertex="1" parent="1"><mxGeometry x="60" y="180" width="40" height="80" as="geometry"/></mxCell>
  <mxCell id="api" value="API Server" style="rounded=1;" vertex="1" parent="1"><mxGeometry x="280" y="190" width="120" height="60" as="geometry"/></mxCell>
  <mxCell id="pg" value="PostgreSQL DB" style="shape=cylinder3;" vertex="1" parent="1"><mxGeometry x="560" y="120" width="120" height="80" as="geometry"/></mxCell>
  <mxCell id="e1" value="HTTPS" style="endArrow=classic;" edge="1" parent="1" source="usr" target="api"><mxGeometry relative="1" as="geometry"/></mxCell>
  <mxCell id="e2" value="SQL" style="endArrow=classic;" edge="1" parent="1" source="api" target="pg"><mxGeometry relative="1" as="geometry"/></mxCell>
</root></mxGraphModel></diagram></mxfile>`

func importSample(t *testing.T) *types.Model {
	t.Helper()
	m, err := Import([]byte(sampleDrawio), ImportOptions{})
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}
	return m
}

func TestShapesClassified(t *testing.T) {
	m := importSample(t)
	usr := m.TechnicalAssets["usr-drawio"]
	if usr == nil || usr.Type != types.ExternalEntity || !usr.Internet {
		t.Fatalf("actor shape should be internet external-entity: %+v", usr)
	}
	api := m.TechnicalAssets["api-drawio"]
	if api == nil || api.Type != types.Process {
		t.Fatalf("plain shape should be a process: %+v", api)
	}
	pg := m.TechnicalAssets["pg-drawio"]
	if pg == nil || pg.Type != types.Datastore || pg.Technologies[0].Name != types.Database {
		t.Fatalf("cylinder/named-db should be a database datastore: %+v", pg)
	}
	// Lossy import -> every asset tagged for review.
	for id, a := range m.TechnicalAssets {
		if !contains(a.Tags, reviewTag) {
			t.Errorf("asset %s missing review tag", id)
		}
	}
}

func TestEdgesAndInternet(t *testing.T) {
	m := importSample(t)
	if len(m.CommunicationLinks) != 2 {
		t.Fatalf("expected 2 links, got %d", len(m.CommunicationLinks))
	}
	if !m.TechnicalAssets["api-drawio"].Internet {
		t.Error("api (target of actor flow) should be internet-facing")
	}
	if m.TechnicalAssets["pg-drawio"].Internet {
		t.Error("pg should not be internet-facing")
	}
}

func TestBoundaryGeometry(t *testing.T) {
	m := importSample(t)
	net := m.TrustBoundaries["boundary-tb1-drawio"]
	data := m.TrustBoundaries["boundary-tb2-drawio"]
	if net == nil || data == nil {
		t.Fatal("both boundaries should exist")
	}
	if !contains(net.TechnicalAssetsInside, "usr-drawio") {
		t.Errorf("internet boundary should contain usr: %v", net.TechnicalAssetsInside)
	}
	if !contains(data.TechnicalAssetsInside, "pg-drawio") {
		t.Errorf("data boundary should contain pg: %v", data.TechnicalAssetsInside)
	}
	if net.Type != types.NetworkOnPrem {
		t.Errorf("internet boundary should be on-prem, got %s", net.Type)
	}
}

func TestBareMxGraphModel(t *testing.T) {
	// The "Edit Diagram" form is a bare <mxGraphModel> without <mxfile>.
	bare := `<mxGraphModel><root>
	  <mxCell id="0"/><mxCell id="1" parent="0"/>
	  <mxCell id="a" value="User" style="shape=actor;" vertex="1" parent="1"><mxGeometry x="0" y="0" width="40" height="80" as="geometry"/></mxCell>
	  <mxCell id="b" value="App" style="rounded=1;" vertex="1" parent="1"><mxGeometry x="0" y="120" width="80" height="40" as="geometry"/></mxCell>
	  <mxCell id="e" edge="1" parent="1" source="a" target="b"><mxGeometry as="geometry"/></mxCell>
	</root></mxGraphModel>`
	m, err := Import([]byte(bare), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.TechnicalAssets) != 2 || len(m.CommunicationLinks) != 1 {
		t.Fatalf("bare mxGraphModel parse wrong: %d assets %d links", len(m.TechnicalAssets), len(m.CommunicationLinks))
	}
}

func TestObjectWrappedCell(t *testing.T) {
	// draw.io wraps cells carrying custom attributes in <object label=...>.
	doc := `<mxfile><diagram><mxGraphModel><root>
	  <mxCell id="0"/><mxCell id="1" parent="0"/>
	  <object label="External User" id="u"><mxCell style="shape=actor;" vertex="1" parent="1"><mxGeometry x="0" y="0" width="40" height="80" as="geometry"/></mxCell></object>
	  <mxCell id="p" value="Service" style="rounded=1;" vertex="1" parent="1"><mxGeometry x="0" y="120" width="80" height="40" as="geometry"/></mxCell>
	  <mxCell id="e" edge="1" parent="1" source="u" target="p"><mxGeometry as="geometry"/></mxCell>
	</root></mxGraphModel></diagram></mxfile>`
	m, err := Import([]byte(doc), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	u := m.TechnicalAssets["u-drawio"]
	if u == nil || u.Title != "External User" || u.Type != types.ExternalEntity {
		t.Fatalf("object-wrapped actor not imported: %+v", u)
	}
}

func TestNbspAndHTMLLabel(t *testing.T) {
	// Real draw.io emits &nbsp; (which Go's XML parser rejects) and HTML labels.
	doc := `<mxfile><diagram><mxGraphModel><root>
	  <mxCell id="0"/><mxCell id="1" parent="0"/>
	  <mxCell id="a" value="&lt;b&gt;Auth&amp;nbsp;DB&lt;/b&gt;" style="shape=cylinder3;" vertex="1" parent="1"><mxGeometry x="0" y="0" width="80" height="40" as="geometry"/></mxCell>
	  <mxCell id="p" value="Web&nbsp;Server" style="rounded=1;" vertex="1" parent="1"><mxGeometry x="0" y="120" width="80" height="40" as="geometry"/></mxCell>
	  <mxCell id="e" edge="1" parent="1" source="p" target="a"><mxGeometry as="geometry"/></mxCell>
	</root></mxGraphModel></diagram></mxfile>`
	m, err := Import([]byte(doc), ImportOptions{})
	if err != nil {
		t.Fatalf("&nbsp;/HTML labels must not break parsing: %v", err)
	}
	a := m.TechnicalAssets["a-drawio"]
	if a == nil || a.Type != types.Datastore {
		t.Fatalf("cylinder with 'DB' label should be a datastore: %+v", a)
	}
	if strings.Contains(a.Title, "<b>") {
		t.Errorf("HTML tags should be stripped from title: %q", a.Title)
	}
}

func TestDashboardIsNotDatastore(t *testing.T) {
	// "Dashboard" must not match the "db" datastore word.
	doc := `<mxfile><diagram><mxGraphModel><root>
	  <mxCell id="0"/><mxCell id="1" parent="0"/>
	  <mxCell id="d" value="Admin Dashboard" style="rounded=1;" vertex="1" parent="1"><mxGeometry x="0" y="0" width="80" height="40" as="geometry"/></mxCell>
	</root></mxGraphModel></diagram></mxfile>`
	m, err := Import([]byte(doc), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if m.TechnicalAssets["d-drawio"].Type == types.Datastore {
		t.Error("'Dashboard' must not be classified as a datastore")
	}
}

func TestNamedZoneNotBoundaryWithoutGrouping(t *testing.T) {
	// A plain rounded shape named "Pricing Zone" is NOT a trust boundary.
	doc := `<mxfile><diagram><mxGraphModel><root>
	  <mxCell id="0"/><mxCell id="1" parent="0"/>
	  <mxCell id="z" value="Pricing Zone" style="rounded=1;" vertex="1" parent="1"><mxGeometry x="0" y="0" width="80" height="40" as="geometry"/></mxCell>
	</root></mxGraphModel></diagram></mxfile>`
	m, err := Import([]byte(doc), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if m.TechnicalAssets["z-drawio"] == nil {
		t.Error("a plain 'Pricing Zone' shape should become an asset, not a boundary")
	}
}

func TestImportErrors(t *testing.T) {
	if _, err := Import([]byte("not xml"), ImportOptions{}); err == nil {
		t.Error("invalid XML should error")
	}
	if _, err := Import([]byte(`<mxfile></mxfile>`), ImportOptions{}); err == nil {
		t.Error("no diagrams should error")
	}
	// A compressed-only diagram with undecodable content should error clearly.
	if _, err := Import([]byte(`<mxfile><diagram>not-base64-deflate</diagram></mxfile>`), ImportOptions{}); err == nil {
		t.Error("undecodable compressed diagram should error")
	}
}

func TestDeterministic(t *testing.T) {
	first := importSample(t)
	for i := 0; i < 10; i++ {
		m := importSample(t)
		if len(m.TechnicalAssets) != len(first.TechnicalAssets) ||
			len(m.TrustBoundaries) != len(first.TrustBoundaries) {
			t.Fatal("non-deterministic import")
		}
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

// sampleMultiPage has two <diagram> pages, each with a boundary + two assets
// numbered identically ("1"/"2") to verify page-local containment (page 2's
// "Auth" boundary must not absorb page 1's assets) and cumulative unique-ID
// collision guarding across pages.
const sampleMultiPage = `<mxfile>
<diagram name="Page One"><mxGraphModel><root>
  <mxCell id="0"/><mxCell id="1" parent="0"/>
  <mxCell id="2" value="Frontend Zone" style="dashed=1;container=1;" vertex="1" parent="1"><mxGeometry x="0" y="0" width="200" height="200" as="geometry"/></mxCell>
  <mxCell id="a" value="Web App" style="rounded=1;" vertex="1" parent="2"><mxGeometry x="20" y="20" width="80" height="40" as="geometry"/></mxCell>
</root></mxGraphModel></diagram>
<diagram name="Page Two"><mxGraphModel><root>
  <mxCell id="0"/><mxCell id="1" parent="0"/>
  <mxCell id="2" value="Auth Zone" style="dashed=1;container=1;" vertex="1" parent="1"><mxGeometry x="0" y="0" width="200" height="200" as="geometry"/></mxCell>
  <mxCell id="b" value="Auth Service" style="rounded=1;" vertex="1" parent="2"><mxGeometry x="20" y="20" width="80" height="40" as="geometry"/></mxCell>
</root></mxGraphModel></diagram>
</mxfile>`

func TestMultiPageDefaultImportsAllPagesScoped(t *testing.T) {
	m, err := Import([]byte(sampleMultiPage), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.TechnicalAssets) != 2 {
		t.Fatalf("expected 2 assets across both pages, got %d", len(m.TechnicalAssets))
	}
	if len(m.TrustBoundaries) != 2 {
		t.Fatalf("expected 2 boundaries (one per page, no cross-page merge), got %d", len(m.TrustBoundaries))
	}
	// Each boundary must contain exactly its own page's asset — never the
	// other page's same-numbered cell.
	for _, tb := range m.TrustBoundaries {
		if len(tb.TechnicalAssetsInside) != 1 {
			t.Errorf("boundary %q should contain exactly 1 asset (its own page), got %v", tb.Title, tb.TechnicalAssetsInside)
		}
	}
}

func TestPageFlagSelectsSinglePageByIndexAndName(t *testing.T) {
	byIndex, err := Import([]byte(sampleMultiPage), ImportOptions{Page: "2"})
	if err != nil {
		t.Fatal(err)
	}
	if len(byIndex.TechnicalAssets) != 1 || byIndex.TechnicalAssets["b-drawio"] == nil {
		t.Fatalf("--page 2 should import only page two's asset: %+v", byIndex.TechnicalAssets)
	}

	byName, err := Import([]byte(sampleMultiPage), ImportOptions{Page: "Page One"})
	if err != nil {
		t.Fatal(err)
	}
	if len(byName.TechnicalAssets) != 1 || byName.TechnicalAssets["a-drawio"] == nil {
		t.Fatalf("--page 'Page One' should import only page one's asset: %+v", byName.TechnicalAssets)
	}

	if _, err := Import([]byte(sampleMultiPage), ImportOptions{Page: "3"}); err == nil {
		t.Error("out-of-range page index should error")
	}
	if _, err := Import([]byte(sampleMultiPage), ImportOptions{Page: "No Such Page"}); err == nil {
		t.Error("unknown page name should error")
	}
}

// sampleNestedBoundary has a swimlane-style outer "VPC" boundary containing
// an inner "Private Subnet" boundary (itself containing an asset) plus one
// asset directly in the outer boundary — to arbitrary depth two here.
const sampleNestedBoundary = `<mxfile><diagram><mxGraphModel><root>
  <mxCell id="0"/><mxCell id="1" parent="0"/>
  <mxCell id="outer" value="VPC Zone" style="dashed=1;container=1;" vertex="1" parent="1"><mxGeometry x="0" y="0" width="400" height="400" as="geometry"/></mxCell>
  <mxCell id="inner" value="Private Subnet" style="dashed=1;container=1;" vertex="1" parent="outer"><mxGeometry x="20" y="20" width="200" height="200" as="geometry"/></mxCell>
  <mxCell id="lb" value="Load Balancer" style="rounded=1;" vertex="1" parent="outer"><mxGeometry x="250" y="20" width="80" height="40" as="geometry"/></mxCell>
  <mxCell id="db" value="Backend DB" style="shape=cylinder3;" vertex="1" parent="inner"><mxGeometry x="20" y="20" width="80" height="40" as="geometry"/></mxCell>
</root></mxGraphModel></diagram></mxfile>`

func TestNestedBoundariesBuildParentChildChain(t *testing.T) {
	m, err := Import([]byte(sampleNestedBoundary), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var outer, inner *types.TrustBoundary
	for _, tb := range m.TrustBoundaries {
		switch tb.Title {
		case "VPC Zone":
			outer = tb
		case "Private Subnet":
			inner = tb
		}
	}
	if outer == nil || inner == nil {
		t.Fatalf("expected both outer and inner boundaries, got: %+v", m.TrustBoundaries)
	}
	if !contains(outer.TechnicalAssetsInside, "lb-drawio") {
		t.Errorf("outer boundary should directly contain the load balancer: %v", outer.TechnicalAssetsInside)
	}
	if contains(outer.TechnicalAssetsInside, "db-drawio") {
		t.Errorf("outer boundary should NOT directly list the nested boundary's asset: %v", outer.TechnicalAssetsInside)
	}
	if !contains(inner.TechnicalAssetsInside, "db-drawio") {
		t.Errorf("inner boundary should contain the db: %v", inner.TechnicalAssetsInside)
	}
	if !contains(outer.TrustBoundariesNested, inner.Id) {
		t.Errorf("outer boundary should list inner as a nested boundary: %v", outer.TrustBoundariesNested)
	}
}

func TestBoundaryFlagScopesToSubtree(t *testing.T) {
	m, err := Import([]byte(sampleNestedBoundary), ImportOptions{Boundary: "VPC Zone"})
	if err != nil {
		t.Fatal(err)
	}
	// Scoping to the outer boundary keeps everything (it's the root).
	if len(m.TechnicalAssets) != 2 {
		t.Fatalf("scoping to the root boundary should keep both assets, got %d", len(m.TechnicalAssets))
	}

	inner, err := Import([]byte(sampleNestedBoundary), ImportOptions{Boundary: "Private Subnet"})
	if err != nil {
		t.Fatal(err)
	}
	if len(inner.TechnicalAssets) != 1 || inner.TechnicalAssets["db-drawio"] == nil {
		t.Fatalf("scoping to 'Private Subnet' should keep only the db, got: %+v", inner.TechnicalAssets)
	}
	if len(inner.TrustBoundaries) != 1 {
		t.Fatalf("scoping to 'Private Subnet' should keep only that one boundary, got %d", len(inner.TrustBoundaries))
	}

	if _, err := Import([]byte(sampleNestedBoundary), ImportOptions{Boundary: "No Such Zone"}); err == nil {
		t.Error("unknown boundary name should error")
	}
}
