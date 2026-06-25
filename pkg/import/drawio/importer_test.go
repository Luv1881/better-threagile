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
