package attacktree

import (
	"strings"
	"testing"

	"github.com/threagile/threagile/pkg/types"
)

// buildModel: client(internet) -> lb -> api -> db(secret-data, strictly-conf).
// Also client2(internet) -> lb, giving the goal two routes that merge at lb.
func buildModel() *types.Model {
	link := func(target, title string) *types.CommunicationLink {
		return &types.CommunicationLink{TargetId: target, Title: title}
	}
	return &types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"client":  {Id: "client", Internet: true, CommunicationLinks: []*types.CommunicationLink{link("lb", "https")}},
			"client2": {Id: "client2", Internet: true, CommunicationLinks: []*types.CommunicationLink{link("lb", "https2")}},
			"lb":      {Id: "lb", CommunicationLinks: []*types.CommunicationLink{link("api", "fwd")}},
			"api":     {Id: "api", CommunicationLinks: []*types.CommunicationLink{link("db", "sql")}, DataAssetsProcessed: []string{"secret-data"}},
			"db":      {Id: "db", DataAssetsStored: []string{"secret-data"}},
		},
		DataAssets: map[string]*types.DataAsset{
			"secret-data": {Id: "secret-data", Confidentiality: types.StrictlyConfidential},
		},
	}
}

func TestBuildGoalRootedTree(t *testing.T) {
	r := Build(buildModel(), Options{To: "db"})
	if len(r.Trees) != 1 {
		t.Fatalf("expected 1 tree for db, got %d", len(r.Trees))
	}
	tree := r.Trees[0]
	if tree.Goal != "db" {
		t.Fatalf("goal = %s, want db", tree.Goal)
	}
	if tree.Root.AssetID != "db" {
		t.Fatalf("root should be the goal db, got %s", tree.Root.AssetID)
	}
	// db <- api <- lb <- {client, client2}: the two entries merge at lb.
	api := tree.Root.Children
	if len(api) != 1 || api[0].AssetID != "api" {
		t.Fatalf("db should have one child api, got %+v", api)
	}
	lb := api[0].Children
	if len(lb) != 1 || lb[0].AssetID != "lb" {
		t.Fatalf("api should have one child lb, got %+v", lb)
	}
	entries := lb[0].Children
	if len(entries) != 2 {
		t.Fatalf("lb should have 2 OR-branch entries, got %d", len(entries))
	}
	for _, e := range entries {
		if !e.IsEntry {
			t.Errorf("leaf %s should be marked as an entry point", e.AssetID)
		}
	}
}

func TestDirectlyInternetFacingGoal(t *testing.T) {
	// A crown jewel that is itself internet-facing -> 0-hop direct exposure.
	m := buildModel()
	m.TechnicalAssets["db"].Internet = true
	r := Build(m, Options{To: "db"})
	var dbTree *Tree
	for i := range r.Trees {
		if r.Trees[i].Goal == "db" {
			dbTree = &r.Trees[i]
		}
	}
	if dbTree == nil {
		t.Fatal("db tree missing")
	}
	if !dbTree.DirectlyInternetFacing || !dbTree.Root.IsEntry {
		t.Fatalf("directly internet-facing goal not flagged: %+v", dbTree)
	}
	if !strings.Contains(FormatText(r), "directly internet-facing") {
		t.Error("text output should note direct internet exposure")
	}
	// DOT: the goal node must appear exactly once (no styling override).
	dot := FormatDOT(r)
	if strings.Count(dot, `"db" [shape=`) != 1 {
		t.Fatalf("goal 'db' should have exactly one node statement:\n%s", dot)
	}
}

func TestNoTreeWhenUnreachable(t *testing.T) {
	m := buildModel()
	m.TechnicalAssets["client"].CommunicationLinks = nil
	m.TechnicalAssets["client2"].CommunicationLinks = nil
	r := Build(m, Options{})
	if len(r.Trees) != 0 {
		t.Fatalf("expected no trees when goals unreachable, got %d", len(r.Trees))
	}
}

func TestFormatsProduceContent(t *testing.T) {
	r := Build(buildModel(), Options{To: "db"})
	if txt := FormatText(r); !strings.Contains(txt, "GOAL: compromise db") || !strings.Contains(txt, "ENTRY via") {
		t.Fatalf("text format missing content:\n%s", txt)
	}
	if md := FormatMarkdown(r); !strings.Contains(md, "## Attack trees") || !strings.Contains(md, "🎯 Goal: `db`") {
		t.Fatalf("markdown format missing content:\n%s", md)
	}
	dot := FormatDOT(r)
	if !strings.HasPrefix(dot, "digraph attack_trees {") || !strings.Contains(dot, `"db" [shape=box`) {
		t.Fatalf("dot format wrong:\n%s", dot)
	}
	// entries are diamonds, goal->edges follow attacker direction (entry -> ... -> goal)
	if !strings.Contains(dot, `-> "db"`) {
		t.Fatalf("dot should have an edge into the goal:\n%s", dot)
	}
}

func TestDeterministic(t *testing.T) {
	a := FormatDOT(Build(buildModel(), Options{}))
	for i := 0; i < 10; i++ {
		if FormatDOT(Build(buildModel(), Options{})) != a {
			t.Fatal("non-deterministic attack-tree output")
		}
	}
}
