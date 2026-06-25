// Package attackpath computes attack paths over a parsed Threagile model: the
// shortest routes an attacker can take from an internet-facing asset to a
// "crown-jewel" asset (one that stores or processes high-confidentiality data),
// following communication links in their call direction.
//
// It answers the question architects actually ask in review — "if this gets
// popped, what can the attacker reach, and how few hops to our sensitive data?"
package attackpath

import (
	"sort"

	"github.com/threagile/threagile/pkg/types"
)

// CrownJewelConfidentiality is the minimum data-asset confidentiality that makes
// an asset a default target.
const CrownJewelConfidentiality = types.Confidential

// Options controls the analysis.
type Options struct {
	// FromAssetID restricts entry points to this asset. Empty or "internet" means
	// "every internet-facing asset".
	FromAssetID string
	// ToTarget restricts targets. Empty means "every crown-jewel asset". Otherwise
	// it may be a data-asset ID (assets holding it become targets) or a
	// technical-asset ID (that asset is the target).
	ToTarget string
	// MaxPaths caps the number of paths returned (0 = no cap).
	MaxPaths int
}

// Path is one attacker route, entry → … → target.
type Path struct {
	Assets           []string `json:"assets"`             // technical-asset IDs, entry first, target last
	Links            []string `json:"links"`              // link title used between consecutive assets (len = len(Assets)-1)
	Hops             int      `json:"hops"`               // number of edges (0 = the entry asset is itself the target)
	TargetDataAssets []string `json:"target_data_assets"` // crown-jewel data-asset IDs held by the target
}

// Result is the analysis outcome.
type Result struct {
	Paths        []Path   `json:"paths"`
	EntryPoints  []string `json:"entry_points"`
	TargetAssets []string `json:"target_assets"`
}

type edge struct {
	to    string
	label string
}

// Analyze computes attack paths for the model under the given options.
func Analyze(model *types.Model, opts Options) *Result {
	adj := buildAdjacency(model)
	entries := entryPoints(model, opts.FromAssetID)
	targets, targetData := targetAssets(model, opts.ToTarget)

	result := &Result{EntryPoints: entries, TargetAssets: keysSorted(targets)}

	targetDataFor := func(assetID string) []string {
		if ds, ok := targetData[assetID]; ok {
			return ds
		}
		return nil
	}

	seen := map[string]bool{} // dedupe identical asset sequences
	for _, entry := range entries {
		for _, p := range shortestPaths(adj, entry, targets) {
			p.TargetDataAssets = targetDataFor(p.Assets[len(p.Assets)-1])
			key := pathKey(p.Assets)
			if seen[key] {
				continue
			}
			seen[key] = true
			result.Paths = append(result.Paths, p)
		}
	}

	sortPaths(result.Paths)
	if opts.MaxPaths > 0 && len(result.Paths) > opts.MaxPaths {
		result.Paths = result.Paths[:opts.MaxPaths]
	}
	return result
}

// buildAdjacency builds the directed call graph: source asset → target asset for
// every communication link.
func buildAdjacency(model *types.Model) map[string][]edge {
	adj := map[string][]edge{}
	for id, asset := range model.TechnicalAssets {
		for _, link := range asset.CommunicationLinks {
			if link.TargetId == "" || link.TargetId == id {
				continue
			}
			adj[id] = append(adj[id], edge{to: link.TargetId, label: link.Title})
		}
	}
	// Deterministic edge order. For parallel links between the same pair the BFS
	// keeps the lexicographically-first label — the hop count is unaffected and
	// the choice is stable across runs.
	for id := range adj {
		e := adj[id]
		sort.Slice(e, func(i, j int) bool {
			if e[i].to != e[j].to {
				return e[i].to < e[j].to
			}
			return e[i].label < e[j].label
		})
	}
	return adj
}

func entryPoints(model *types.Model, from string) []string {
	if from != "" && from != "internet" {
		if _, ok := model.TechnicalAssets[from]; ok {
			return []string{from}
		}
		return nil
	}
	var out []string
	for id, asset := range model.TechnicalAssets {
		if asset.Internet {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// targetAssets returns the set of target asset IDs and, for each, the
// crown-jewel data assets that make it a target.
func targetAssets(model *types.Model, to string) (map[string]bool, map[string][]string) {
	targets := map[string]bool{}
	data := map[string][]string{}

	switch {
	case to == "":
		// Default: every asset holding a crown-jewel data asset.
		for id, asset := range model.TechnicalAssets {
			if jewels := crownJewelsHeldBy(model, asset); len(jewels) > 0 {
				targets[id] = true
				data[id] = jewels
			}
		}
	case isDataAsset(model, to):
		// A specific data asset: every asset that stores/processes it.
		for id, asset := range model.TechnicalAssets {
			if assetHolds(asset, to) {
				targets[id] = true
				data[id] = []string{to}
			}
		}
	default:
		// Treat as a technical-asset ID.
		if asset, ok := model.TechnicalAssets[to]; ok {
			targets[to] = true
			data[to] = crownJewelsHeldBy(model, asset)
		}
	}
	return targets, data
}

func crownJewelsHeldBy(model *types.Model, asset *types.TechnicalAsset) []string {
	seen := map[string]bool{}
	var jewels []string
	for _, daID := range heldDataAssets(asset) {
		if seen[daID] {
			continue
		}
		if da, ok := model.DataAssets[daID]; ok && da.Confidentiality >= CrownJewelConfidentiality {
			seen[daID] = true
			jewels = append(jewels, daID)
		}
	}
	sort.Strings(jewels)
	return jewels
}

func heldDataAssets(asset *types.TechnicalAsset) []string {
	out := make([]string, 0, len(asset.DataAssetsProcessed)+len(asset.DataAssetsStored))
	out = append(out, asset.DataAssetsProcessed...)
	out = append(out, asset.DataAssetsStored...)
	return out
}

func assetHolds(asset *types.TechnicalAsset, dataAssetID string) bool {
	for _, id := range heldDataAssets(asset) {
		if id == dataAssetID {
			return true
		}
	}
	return false
}

func isDataAsset(model *types.Model, id string) bool {
	_, ok := model.DataAssets[id]
	return ok
}

// shortestPaths runs a BFS from entry and reconstructs ONE shortest path to every
// target reachable from it. This is a deliberate design choice: reporting a
// single shortest route per (entry, target) keeps output bounded and
// deterministic and still answers "can the attacker reach it, and in how few
// hops". Distinct entry points and distinct targets already produce distinct
// paths; only multiple equal-length routes to the *same* target via different
// intermediates are summarised to one.
func shortestPaths(adj map[string][]edge, entry string, targets map[string]bool) []Path {
	type prev struct {
		node  string
		label string
	}
	visited := map[string]bool{entry: true}
	pred := map[string]prev{}
	queue := []string{entry}

	var paths []Path
	emit := func(target string) {
		assets := []string{target}
		var links []string
		cur := target
		for cur != entry {
			p := pred[cur]
			assets = append(assets, p.node)
			links = append(links, p.label)
			cur = p.node
		}
		reverse(assets)
		reverse(links)
		paths = append(paths, Path{Assets: assets, Links: links, Hops: len(links)})
	}

	if targets[entry] {
		emit(entry) // entry is itself a target (direct internet exposure of a crown jewel)
	}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, e := range adj[cur] {
			if visited[e.to] {
				continue
			}
			visited[e.to] = true
			pred[e.to] = prev{node: cur, label: e.label}
			if targets[e.to] {
				emit(e.to)
			}
			queue = append(queue, e.to)
		}
	}
	return paths
}

func sortPaths(paths []Path) {
	sort.Slice(paths, func(i, j int) bool {
		if paths[i].Hops != paths[j].Hops {
			return paths[i].Hops < paths[j].Hops // shortest (most dangerous) first
		}
		return pathKey(paths[i].Assets) < pathKey(paths[j].Assets)
	})
}

func pathKey(assets []string) string {
	key := ""
	for _, a := range assets {
		key += a + ">"
	}
	return key
}

func keysSorted(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func reverse(s []string) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}
