package attacktree

import (
	"fmt"
	"sort"
	"strings"
)

// FormatText renders the attack trees as an indented text outline (root = goal).
func FormatText(r *Result) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Attack trees: %d goal(s) reachable from %d entry point(s)\n",
		len(r.Trees), len(r.EntryPoints))
	if len(r.Trees) == 0 {
		sb.WriteString("\nNo crown-jewel goal is reachable from an internet-facing entry point.\n")
		return sb.String()
	}
	for _, t := range r.Trees {
		fmt.Fprintf(&sb, "\nGOAL: compromise %s  (min %d hop(s))\n", t.Goal, t.MinHops)
		if t.DirectlyInternetFacing {
			sb.WriteString("  ⚠ directly internet-facing (0-hop direct exposure)\n")
		}
		if len(t.ExposedDataAssets) > 0 {
			fmt.Fprintf(&sb, "  exposes: %s\n", strings.Join(t.ExposedDataAssets, ", "))
		}
		writeNode(&sb, t.Root, 1)
	}
	return sb.String()
}

func writeNode(sb *strings.Builder, n *Node, depth int) {
	for _, c := range n.Children {
		indent := strings.Repeat("  ", depth)
		marker := "via"
		if c.IsEntry {
			marker = "ENTRY via"
		}
		fmt.Fprintf(sb, "%s└─ %s  (%s %s)\n", indent, c.AssetID, marker, c.Via)
		writeNode(sb, c, depth+1)
	}
}

// FormatMarkdown renders a PR-comment-ready version.
func FormatMarkdown(r *Result) string {
	var sb strings.Builder
	sb.WriteString("## Attack trees\n\n")
	fmt.Fprintf(&sb, "%d goal(s) reachable from %d entry point(s).\n", len(r.Trees), len(r.EntryPoints))
	if len(r.Trees) == 0 {
		sb.WriteString("\nNo crown-jewel goal is reachable from an internet-facing entry point. ✅\n")
		return sb.String()
	}
	for _, t := range r.Trees {
		fmt.Fprintf(&sb, "\n### 🎯 Goal: `%s` (min %d hop(s))\n", t.Goal, t.MinHops)
		if t.DirectlyInternetFacing {
			sb.WriteString("\n⚠️ **Directly internet-facing** (0-hop direct exposure)\n")
		}
		if len(t.ExposedDataAssets) > 0 {
			fmt.Fprintf(&sb, "\nExposes: %s\n", strings.Join(t.ExposedDataAssets, ", "))
		}
		sb.WriteString("\n```\n")
		fmt.Fprintf(&sb, "%s\n", t.Goal)
		writeNodePlain(&sb, t.Root, 1)
		sb.WriteString("```\n")
	}
	return sb.String()
}

func writeNodePlain(sb *strings.Builder, n *Node, depth int) {
	for _, c := range n.Children {
		indent := strings.Repeat("  ", depth)
		tag := ""
		if c.IsEntry {
			tag = " [ENTRY]"
		}
		fmt.Fprintf(sb, "%s<- %s (%s)%s\n", indent, c.AssetID, c.Via, tag)
		writeNodePlain(sb, c, depth+1)
	}
}

// FormatDOT renders all trees as a single Graphviz digraph. Edges follow the
// attacker's direction (entry → … → goal); goals are boxes, entry points are
// diamonds.
func FormatDOT(r *Result) string {
	var sb strings.Builder
	sb.WriteString("digraph attack_trees {\n")
	sb.WriteString("  rankdir=LR;\n  node [fontname=\"Helvetica\"];\n")

	goals := map[string]bool{}
	entries := map[string]bool{}
	edges := map[string]bool{} // "src->dst [label]" dedup

	var walk func(parent *Node)
	walk = func(parent *Node) {
		for _, c := range parent.Children {
			// attacker moves from child (entry-ward) to parent (goal-ward).
			edge := fmt.Sprintf("  %q -> %q [label=%q];\n", c.AssetID, parent.AssetID, c.Via)
			edges[edge] = true
			if c.IsEntry {
				entries[c.AssetID] = true
			}
			walk(c)
		}
	}
	for _, t := range r.Trees {
		goals[t.Goal] = true
		if t.DirectlyInternetFacing {
			entries[t.Goal] = true
		}
		walk(t.Root)
	}

	for _, g := range sortedBoolKeys(goals) {
		// A goal that is also directly internet-facing keeps the goal box but is
		// given an entry-coloured fill so the dual role is visible (and there is
		// exactly one node statement per id — no later override).
		fill := "#ffd9d9"
		if entries[g] {
			fill = "#ffb3b3"
		}
		fmt.Fprintf(&sb, "  %q [shape=box, style=filled, fillcolor=%q];\n", g, fill)
	}
	for _, e := range sortedBoolKeys(entries) {
		if goals[e] {
			continue // already declared as a goal box above
		}
		fmt.Fprintf(&sb, "  %q [shape=diamond, style=filled, fillcolor=\"#d9e8ff\"];\n", e)
	}
	for _, e := range sortedBoolKeys(edges) {
		sb.WriteString(e)
	}
	sb.WriteString("}\n")
	return sb.String()
}

func sortedBoolKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
