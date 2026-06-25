// Package attacktree builds goal-oriented attack trees from a parsed Threagile
// model. It reuses the deterministic shortest-path analysis (pkg/attackpath):
// each "crown-jewel" asset (one holding confidential+ data) becomes the ROOT
// (the attacker's goal); the branches are the routes that reach it, merged into
// an OR-tree whose leaves are the internet-facing entry points. Output is
// text / JSON / Graphviz DOT — fully deterministic, no AI.
package attacktree

import (
	"sort"

	"github.com/threagile/threagile/pkg/attackpath"
	"github.com/threagile/threagile/pkg/types"
)

// Options controls tree construction.
type Options struct {
	// To restricts the goal to a single data-asset or technical-asset ID
	// (default: every crown-jewel asset). FromAssetID/MaxPaths mirror attackpath.
	To          string
	FromAssetID string
	MaxPaths    int
}

// Node is one step in an attack tree. Children are OR-alternatives moving away
// from the goal (toward the attacker's entry points).
type Node struct {
	AssetID  string  `json:"asset"`
	Via      string  `json:"via,omitempty"`   // link title from this node toward its parent (goal-ward)
	IsEntry  bool    `json:"entry,omitempty"` // an internet-facing entry point (leaf)
	Children []*Node `json:"or,omitempty"`
}

// Tree is one goal-oriented attack tree.
type Tree struct {
	Goal              string   `json:"goal"` // target asset ID (the root)
	ExposedDataAssets []string `json:"exposes,omitempty"`
	MinHops           int      `json:"min_hops"`
	// DirectlyInternetFacing is true when the goal is itself an internet-facing
	// entry point (a 0-hop "path"), i.e. directly exposed.
	DirectlyInternetFacing bool  `json:"directly_internet_facing,omitempty"`
	Root                   *Node `json:"root"`
}

// Result is the set of trees plus the entry points considered.
type Result struct {
	Trees       []Tree   `json:"trees"`
	EntryPoints []string `json:"entry_points"`
}

// Build constructs an attack tree per reachable goal.
func Build(model *types.Model, opts Options) *Result {
	pa := attackpath.Analyze(model, attackpath.Options{
		FromAssetID: opts.FromAssetID,
		ToTarget:    opts.To,
		MaxPaths:    opts.MaxPaths,
	})

	entrySet := map[string]bool{}
	for _, e := range pa.EntryPoints {
		entrySet[e] = true
	}

	// Group paths by goal (the last asset).
	byGoal := map[string][]attackpath.Path{}
	for _, p := range pa.Paths {
		if len(p.Assets) == 0 {
			continue
		}
		goal := p.Assets[len(p.Assets)-1]
		byGoal[goal] = append(byGoal[goal], p)
	}

	result := &Result{EntryPoints: pa.EntryPoints}
	for _, goal := range sortedKeys(byGoal) {
		paths := byGoal[goal]
		tree := Tree{Goal: goal, Root: &Node{AssetID: goal}, MinHops: -1}
		dataSet := map[string]bool{}
		for _, p := range paths {
			if tree.MinHops < 0 || p.Hops < tree.MinHops {
				tree.MinHops = p.Hops
			}
			for _, d := range p.TargetDataAssets {
				dataSet[d] = true
			}
			if len(p.Assets) == 1 {
				// 0-hop: the goal is itself an internet-facing entry point.
				tree.DirectlyInternetFacing = true
				tree.Root.IsEntry = true
				continue
			}
			insertPath(tree.Root, p, entrySet)
		}
		tree.ExposedDataAssets = sortedSet(dataSet)
		sortTree(tree.Root)
		result.Trees = append(result.Trees, tree)
	}
	return result
}

// insertPath merges one entry→goal path into the goal-rooted tree. The path is
// walked backward (goal → … → entry); shared goal-ward prefixes are merged so
// alternative routes appear as OR-branches.
func insertPath(root *Node, p attackpath.Path, entrySet map[string]bool) {
	cur := root
	// p.Assets = [entry, …, goal]; p.Links[i] connects Assets[i]→Assets[i+1].
	for i := len(p.Assets) - 2; i >= 0; i-- {
		childAsset := p.Assets[i]
		via := ""
		if i < len(p.Links) {
			via = p.Links[i] // link from Assets[i] (child) to Assets[i+1] (parent, goal-ward)
		}
		child := findChild(cur, childAsset, via)
		if child == nil {
			child = &Node{AssetID: childAsset, Via: via, IsEntry: entrySet[childAsset]}
			cur.Children = append(cur.Children, child)
		}
		cur = child
	}
}

func findChild(n *Node, assetID, via string) *Node {
	for _, c := range n.Children {
		if c.AssetID == assetID && c.Via == via {
			return c
		}
	}
	return nil
}

func sortTree(n *Node) {
	sort.Slice(n.Children, func(i, j int) bool {
		if n.Children[i].AssetID != n.Children[j].AssetID {
			return n.Children[i].AssetID < n.Children[j].AssetID
		}
		return n.Children[i].Via < n.Children[j].Via
	})
	for _, c := range n.Children {
		sortTree(c)
	}
}

func sortedKeys(m map[string][]attackpath.Path) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
