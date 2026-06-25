package attackpath

import (
	"strings"
	"testing"

	"github.com/threagile/threagile/pkg/types"
)

// buildModel constructs a small model:
//
//	client(internet) --> lb --> api --> db(holds secret-data, strictly-confidential)
//	                              api --> cache(holds public-data)
func buildModel() *types.Model {
	link := func(target, title string) *types.CommunicationLink {
		return &types.CommunicationLink{TargetId: target, Title: title}
	}
	m := &types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"client": {Id: "client", Internet: true, CommunicationLinks: []*types.CommunicationLink{link("lb", "https")}},
			"lb":     {Id: "lb", CommunicationLinks: []*types.CommunicationLink{link("api", "fwd")}},
			"api":    {Id: "api", CommunicationLinks: []*types.CommunicationLink{link("db", "sql"), link("cache", "redis")}, DataAssetsProcessed: []string{"secret-data"}},
			"db":     {Id: "db", DataAssetsStored: []string{"secret-data"}},
			"cache":  {Id: "cache", DataAssetsStored: []string{"public-data"}},
		},
		DataAssets: map[string]*types.DataAsset{
			"secret-data": {Id: "secret-data", Confidentiality: types.StrictlyConfidential},
			"public-data": {Id: "public-data", Confidentiality: types.Public},
		},
	}
	return m
}

func pathStrings(r *Result) []string {
	var out []string
	for _, p := range r.Paths {
		out = append(out, strings.Join(p.Assets, ">"))
	}
	return out
}

func TestAnalyzeFindsInternetToCrownJewel(t *testing.T) {
	r := Analyze(buildModel(), Options{})

	// db and api both hold the strictly-confidential data asset -> both targets.
	if len(r.TargetAssets) != 2 {
		t.Fatalf("expected 2 crown-jewel targets (api, db), got %v", r.TargetAssets)
	}
	// Shortest path to api is client>lb>api (2 hops); to db client>lb>api>db (3).
	got := pathStrings(r)
	if !contains(got, "client>lb>api") || !contains(got, "client>lb>api>db") {
		t.Fatalf("expected paths to api and db, got %v", got)
	}
	// cache holds only public data -> never a target.
	for _, p := range got {
		if strings.HasSuffix(p, ">cache") {
			t.Fatalf("cache (public data) must not be a target: %v", got)
		}
	}
	// Shortest first.
	if r.Paths[0].Hops > r.Paths[len(r.Paths)-1].Hops {
		t.Fatal("paths not sorted shortest-first")
	}
}

func TestAnalyzeToSpecificDataAsset(t *testing.T) {
	r := Analyze(buildModel(), Options{ToTarget: "secret-data"})
	// Only assets holding secret-data (api, db) are targets.
	if !contains(r.TargetAssets, "api") || !contains(r.TargetAssets, "db") || len(r.TargetAssets) != 2 {
		t.Fatalf("unexpected targets: %v", r.TargetAssets)
	}
	for _, p := range r.Paths {
		last := p.Assets[len(p.Assets)-1]
		if last != "api" && last != "db" {
			t.Fatalf("path ends at non-target %q", last)
		}
	}
}

func TestAnalyzeFromSpecificAsset(t *testing.T) {
	r := Analyze(buildModel(), Options{FromAssetID: "lb"})
	if len(r.EntryPoints) != 1 || r.EntryPoints[0] != "lb" {
		t.Fatalf("entry points = %v, want [lb]", r.EntryPoints)
	}
	for _, p := range r.Paths {
		if p.Assets[0] != "lb" {
			t.Fatalf("path does not start at lb: %v", p.Assets)
		}
	}
}

func TestDirectInternetExposureIsZeroHop(t *testing.T) {
	m := buildModel()
	// Make db itself internet-facing -> a 0-hop path (direct exposure).
	m.TechnicalAssets["db"].Internet = true
	r := Analyze(m, Options{})
	var foundZero bool
	for _, p := range r.Paths {
		if len(p.Assets) == 1 && p.Assets[0] == "db" && p.Hops == 0 {
			foundZero = true
		}
	}
	if !foundZero {
		t.Fatalf("expected a 0-hop direct-exposure path for db, got %v", pathStrings(r))
	}
}

func TestNoPathsWhenDisconnected(t *testing.T) {
	m := buildModel()
	// Remove the client->lb link so the crown jewels are unreachable from internet.
	m.TechnicalAssets["client"].CommunicationLinks = nil
	r := Analyze(m, Options{})
	if len(r.Paths) != 0 {
		t.Fatalf("expected no paths when disconnected, got %v", pathStrings(r))
	}
}

func TestDeterministicAndDeduped(t *testing.T) {
	m := buildModel()
	first := pathStrings(Analyze(m, Options{}))
	for i := 0; i < 10; i++ {
		if got := pathStrings(Analyze(m, Options{})); !equal(got, first) {
			t.Fatalf("non-deterministic: %v vs %v", got, first)
		}
	}
	// No duplicate crown-jewel data assets in the exposes list.
	for _, p := range Analyze(m, Options{}).Paths {
		seen := map[string]bool{}
		for _, d := range p.TargetDataAssets {
			if seen[d] {
				t.Fatalf("duplicate exposed data asset %q", d)
			}
			seen[d] = true
		}
	}
}

// A self-loop (a -> a) and a cycle (api -> lb back-edge) must not cause an
// infinite loop and must not corrupt shortest-path reconstruction.
func TestCyclesAndSelfLoops(t *testing.T) {
	m := buildModel()
	// self-loop on api
	m.TechnicalAssets["api"].CommunicationLinks = append(
		m.TechnicalAssets["api"].CommunicationLinks,
		&types.CommunicationLink{TargetId: "api", Title: "self"},
	)
	// back-edge api -> lb (creates lb<->api... actually lb->api->lb cycle)
	m.TechnicalAssets["api"].CommunicationLinks = append(
		m.TechnicalAssets["api"].CommunicationLinks,
		&types.CommunicationLink{TargetId: "lb", Title: "callback"},
	)
	r := Analyze(m, Options{})
	// Shortest path to api is still client>lb>api (the cycle/self-loop add no
	// shorter route and must not duplicate or extend it).
	got := pathStrings(r)
	if !contains(got, "client>lb>api") {
		t.Fatalf("cycle/self-loop broke shortest path to api: %v", got)
	}
	for _, p := range r.Paths {
		// No asset may repeat within a single shortest path.
		seen := map[string]bool{}
		for _, a := range p.Assets {
			if seen[a] {
				t.Fatalf("asset %q repeats in path %v", a, p.Assets)
			}
			seen[a] = true
		}
	}
}

func TestFormatTextAndMarkdown(t *testing.T) {
	r := Analyze(buildModel(), Options{})
	text := FormatText(r)
	if !strings.Contains(text, "Attack-path analysis") || !strings.Contains(text, "hop(s)") {
		t.Fatalf("text report missing content:\n%s", text)
	}
	md := FormatMarkdown(r)
	if !strings.Contains(md, "## Attack-path analysis") || !strings.Contains(md, "| Hops | Path | Exposes |") {
		t.Fatalf("markdown report missing content:\n%s", md)
	}

	empty := Analyze(buildModelDisconnected(), Options{})
	if !strings.Contains(FormatText(empty), "No attack paths found") {
		t.Fatal("empty text report should say no paths")
	}
	if !strings.Contains(FormatMarkdown(empty), "✅") {
		t.Fatal("empty markdown report should show ✅")
	}
}

func buildModelDisconnected() *types.Model {
	m := buildModel()
	m.TechnicalAssets["client"].CommunicationLinks = nil
	return m
}

func contains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
