// Package import_test contains a cross-importer golden conformance suite
// (improvement.md P9). The same synthetic "3-tier reference app" — one
// external actor, a web frontend, an api server and a database, all inside
// one trust boundary except the actor, wired actor->frontend->api->database
// — is expressed once per diagram/interchange format under ./testdata/ and
// imported through each importer with default options (no mapping,
// --stub-data-assets on). The test then asserts *structural* invariants that
// must hold no matter which importer produced the model, so a future change
// that makes one importer's classifier drift from the others (e.g. drawio
// starts marking databases internet-facing, or otm stops treating "actor" as
// an external entity) fails here instead of silently shipping.
//
// Assertions are deliberately tolerant of everything that legitimately
// differs by format (exact IDs, titles, trust-boundary type, technology
// guesses) and only pin down the shape every format is expected to agree on.
package import_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/threagile/threagile/pkg/import/drawio"
	"github.com/threagile/threagile/pkg/import/mermaid"
	"github.com/threagile/threagile/pkg/import/otm"
	"github.com/threagile/threagile/pkg/import/threatdragon"
	"github.com/threagile/threagile/pkg/types"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", name, err)
	}
	return data
}

func TestConformance_Drawio(t *testing.T) {
	data := readFixture(t, "reference-app.drawio.xml")
	m, err := drawio.Import(data, drawio.ImportOptions{SourceLabel: "conf"})
	if err != nil {
		t.Fatalf("drawio import failed: %v", err)
	}
	checkReferenceApp(t, "drawio", m)
}

func TestConformance_OTM(t *testing.T) {
	data := readFixture(t, "reference-app.otm.json")
	m, err := otm.Import(data, otm.ImportOptions{SourceLabel: "conf"})
	if err != nil {
		t.Fatalf("otm import failed: %v", err)
	}
	checkReferenceApp(t, "otm", m)
}

func TestConformance_Mermaid(t *testing.T) {
	data := readFixture(t, "reference-app.mmd")
	m, err := mermaid.Import(data, mermaid.ImportOptions{SourceLabel: "conf"})
	if err != nil {
		t.Fatalf("mermaid import failed: %v", err)
	}
	checkReferenceApp(t, "mermaid", m)
}

func TestConformance_ThreatDragon(t *testing.T) {
	data := readFixture(t, "reference-app-threatdragon.json")
	m, err := threatdragon.Import(data, threatdragon.ImportOptions{SourceLabel: "conf"})
	if err != nil {
		t.Fatalf("threat-dragon import failed: %v", err)
	}
	checkReferenceApp(t, "threat-dragon", m)
}

// checkReferenceApp asserts the structural invariants every importer's
// output for the reference-app fixture must share. It does not care about
// IDs/titles/technology guesses/trust-boundary type — only about counts,
// classification, topology and internet-exposure correctness.
func checkReferenceApp(t *testing.T, importerName string, m *types.Model) {
	t.Helper()

	if got := len(m.TechnicalAssets); got != 4 {
		t.Fatalf("[%s] expected 4 technical assets, got %d: %+v", importerName, got, assetTitles(m))
	}

	var actors, frontendsOrAPIs, datastores []*types.TechnicalAsset
	for _, a := range m.TechnicalAssets {
		switch a.Type {
		case types.ExternalEntity:
			actors = append(actors, a)
		case types.Datastore:
			datastores = append(datastores, a)
		case types.Process:
			frontendsOrAPIs = append(frontendsOrAPIs, a)
		default:
			t.Errorf("[%s] unexpected technical asset type %v for %q", importerName, a.Type, a.Title)
		}
	}

	if len(actors) != 1 {
		t.Fatalf("[%s] expected exactly 1 external-entity (the actor), got %d", importerName, len(actors))
	}
	actor := actors[0]
	if !actor.Internet {
		t.Errorf("[%s] the external-entity actor should be marked internet-facing", importerName)
	}

	if len(datastores) != 1 {
		t.Fatalf("[%s] expected exactly 1 datastore (the database), got %d", importerName, len(datastores))
	}
	database := datastores[0]
	if database.Internet {
		t.Errorf("[%s] the database must not be internet-facing", importerName)
	}

	if len(frontendsOrAPIs) != 2 {
		t.Fatalf("[%s] expected exactly 2 process assets (frontend + api), got %d", importerName, len(frontendsOrAPIs))
	}

	if got := len(m.CommunicationLinks); got != 3 {
		t.Fatalf("[%s] expected 3 communication links before stub augmentation, got %d", importerName, got)
	}

	// Topology: exactly one link sourced at the actor; its target is the
	// "frontend". Exactly one link targets the database; its source is the
	// "api". The remaining link chains frontend -> api. The database must
	// never appear as a link source (it's the terminal node in this DAG) —
	// this is invariant regardless of which importer produced the model,
	// and would catch a source/target swap bug in any parser.
	var actorOutLink, dbInLink *types.CommunicationLink
	for _, l := range m.CommunicationLinks {
		if l.SourceId == actor.Id {
			if actorOutLink != nil {
				t.Fatalf("[%s] actor should have exactly one outgoing link, found a second: %+v", importerName, l)
			}
			actorOutLink = l
		}
		if l.TargetId == database.Id {
			if dbInLink != nil {
				t.Fatalf("[%s] database should have exactly one incoming link, found a second: %+v", importerName, l)
			}
			dbInLink = l
		}
		if l.SourceId == database.Id {
			t.Errorf("[%s] database must never be a link source (terminal node), but link %+v has it as source", importerName, l)
		}
	}
	if actorOutLink == nil {
		t.Fatalf("[%s] expected a link sourced at the actor", importerName)
	}
	if dbInLink == nil {
		t.Fatalf("[%s] expected a link targeting the database", importerName)
	}

	frontendID := actorOutLink.TargetId
	apiID := dbInLink.SourceId
	if frontendID == apiID {
		t.Fatalf("[%s] actor's link target and database's link source must be different assets (frontend != api)", importerName)
	}
	frontend, okF := m.TechnicalAssets[frontendID]
	api, okA := m.TechnicalAssets[apiID]
	if !okF || frontend.Type != types.Process {
		t.Fatalf("[%s] the actor's link target should be a Process (the frontend): %+v", importerName, frontend)
	}
	if !okA || api.Type != types.Process {
		t.Fatalf("[%s] the database's link source should be a Process (the api): %+v", importerName, api)
	}

	// The middle link must chain frontend -> api.
	var sawFrontendToAPI bool
	for _, l := range m.CommunicationLinks {
		if l.SourceId == frontendID && l.TargetId == apiID {
			sawFrontendToAPI = true
		}
	}
	if !sawFrontendToAPI {
		t.Errorf("[%s] expected a link from frontend to api", importerName)
	}

	// Internet-facing correctness: the api (middle tier) must not be
	// internet-facing regardless of whether a given importer propagates
	// internet-exposure from a direct actor link (drawio/mermaid/
	// threat-dragon do; otm's exposure is zone-based only) — either way, an
	// asset two hops from the actor and never itself directly reached from
	// outside must never be internet-facing.
	if api.Internet {
		t.Errorf("[%s] the api (middle tier, never directly reached from the actor) must not be internet-facing", importerName)
	}

	// Trust boundary: exactly one, containing exactly the 3 non-actor
	// assets (frontend, api, database) and never the actor.
	if got := len(m.TrustBoundaries); got != 1 {
		t.Fatalf("[%s] expected exactly 1 trust boundary, got %d", importerName, got)
	}
	var boundary *types.TrustBoundary
	for _, tb := range m.TrustBoundaries {
		boundary = tb
	}
	inside := map[string]bool{}
	for _, id := range boundary.TechnicalAssetsInside {
		inside[id] = true
	}
	if len(inside) != 3 {
		t.Fatalf("[%s] expected the trust boundary to contain exactly 3 assets, got %d: %v", importerName, len(inside), boundary.TechnicalAssetsInside)
	}
	if inside[actor.Id] {
		t.Errorf("[%s] the actor must not be inside the trust boundary", importerName)
	}
	for _, id := range []string{frontendID, apiID, database.Id} {
		if !inside[id] {
			t.Errorf("[%s] expected asset %q inside the trust boundary, boundary contains: %v", importerName, id, boundary.TechnicalAssetsInside)
		}
	}
}

func assetTitles(m *types.Model) []string {
	titles := make([]string, 0, len(m.TechnicalAssets))
	for _, a := range m.TechnicalAssets {
		titles = append(titles, fmt.Sprintf("%s(%v)", a.Title, a.Type))
	}
	return titles
}
