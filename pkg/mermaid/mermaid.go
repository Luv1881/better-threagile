// Package mermaid renders a Threagile model as a Mermaid flowchart.
//
// Unlike the Graphviz data-flow diagram (which needs the external `dot` binary
// and produces a PNG), Mermaid is text that GitHub, GitLab and most Markdown
// renderers display natively. That makes it ideal for embedding an
// architecture / data-flow picture directly in a pull-request comment, README
// or CI summary without any image-rendering toolchain.
//
// The conversion is fully deterministic (all map iteration is sorted) and uses
// no AI.
package mermaid

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/threagile/threagile/pkg/types"
)

// Options controls how the flowchart is rendered.
type Options struct {
	// Direction is the Mermaid flow direction: "TB" (top-bottom, default) or "LR".
	Direction string
	// WithRisks colours each technical asset by the highest severity of its
	// still-at-risk findings. Requires an analyzed model (risks populated).
	WithRisks bool
}

// severity → CSS-ish class name for the node fill.
var severityClass = map[types.RiskSeverity]string{
	types.LowSeverity:      "sevLow",
	types.MediumSeverity:   "sevMedium",
	types.ElevatedSeverity: "sevElevated",
	types.HighSeverity:     "sevHigh",
	types.CriticalSeverity: "sevCritical",
}

// DataFlowDiagram renders the model as a Mermaid flowchart string (with a
// trailing newline). Trust boundaries become subgraphs (nested boundaries are
// rendered inside their parent), technical assets become shaped nodes, and
// communication links become edges in their call direction (solid when
// encrypted/VPN, dashed when cleartext).
func DataFlowDiagram(model *types.Model, opts Options) string {
	d := &diagram{
		model:      model,
		opts:       opts,
		nodeID:     map[string]string{},
		boundaryID: map[string]string{},
		rendered:   map[string]bool{},
		sev:        map[string]types.RiskSeverity{},
		hasSev:     map[string]bool{},
	}
	d.assignNodeIDs()
	d.assignBoundaryIDs()
	if opts.WithRisks {
		d.computeSeverities()
	}
	return d.render()
}

type diagram struct {
	model      *types.Model
	opts       Options
	nodeID     map[string]string // technical-asset ID -> sanitized Mermaid node ID
	boundaryID map[string]string // trust-boundary ID -> sanitized Mermaid subgraph ID
	rendered   map[string]bool   // trust-boundary IDs already emitted (cycle/orphan guard)
	sev        map[string]types.RiskSeverity
	hasSev     map[string]bool
}

func (d *diagram) sortedAssetIDs() []string {
	ids := make([]string, 0, len(d.model.TechnicalAssets))
	for id := range d.model.TechnicalAssets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (d *diagram) assignNodeIDs() {
	used := map[string]bool{}
	for _, id := range d.sortedAssetIDs() {
		base := "n_" + sanitize(id)
		cand := base
		for i := 2; used[cand]; i++ {
			cand = base + "_" + strconv.Itoa(i)
		}
		used[cand] = true
		d.nodeID[id] = cand
	}
}

// assignBoundaryIDs gives every trust boundary a unique Mermaid subgraph ID,
// resolving collisions the same way node IDs do (e.g. "a-b" and "a_b").
func (d *diagram) assignBoundaryIDs() {
	used := map[string]bool{}
	for _, id := range d.sortedBoundaryIDs() {
		base := "tb_" + sanitize(id)
		cand := base
		for i := 2; used[cand]; i++ {
			cand = base + "_" + strconv.Itoa(i)
		}
		used[cand] = true
		d.boundaryID[id] = cand
	}
}

func (d *diagram) computeSeverities() {
	for _, risk := range d.model.AllRisks() {
		if !risk.RiskStatus.IsStillAtRisk() {
			continue
		}
		id := risk.MostRelevantTechnicalAssetId
		if id == "" {
			continue
		}
		if _, ok := d.model.TechnicalAssets[id]; !ok {
			continue
		}
		if cur, ok := d.sev[id]; !ok || risk.Severity > cur {
			d.sev[id] = risk.Severity
		}
		d.hasSev[id] = true
	}
}

func (d *diagram) render() string {
	var b strings.Builder
	dir := strings.ToUpper(d.opts.Direction)
	if dir != "LR" {
		dir = "TB"
	}
	fmt.Fprintf(&b, "flowchart %s\n", dir)

	// Map every asset to its directly-containing trust boundary, and every
	// nested boundary to its parent, so we can render the boundary tree.
	assetBoundary := map[string]string{}  // asset ID -> directly-containing boundary ID
	boundaryParent := map[string]string{} // nested boundary ID -> parent boundary ID
	for _, bID := range d.sortedBoundaryIDs() {
		tb := d.model.TrustBoundaries[bID]
		for _, a := range tb.TechnicalAssetsInside {
			if _, ok := assetBoundary[a]; !ok {
				assetBoundary[a] = bID
			}
		}
		for _, child := range tb.TrustBoundariesNested {
			if _, ok := boundaryParent[child]; !ok {
				boundaryParent[child] = bID
			}
		}
	}

	emitted := map[string]bool{}
	// Render top-level boundaries (those with no parent) and their contents.
	for _, bID := range d.sortedBoundaryIDs() {
		if _, nested := boundaryParent[bID]; nested {
			continue
		}
		d.renderBoundary(&b, bID, assetBoundary, boundaryParent, emitted, 1)
	}
	// Safety net: a cyclic or otherwise orphaned nesting (e.g. A nests B and B
	// nests A) leaves boundaries with a parent but no top-level root, so the
	// loop above never reaches them. Render any leftover boundary at the top
	// level so its assets are never silently dropped.
	for _, bID := range d.sortedBoundaryIDs() {
		if !d.rendered[bID] {
			d.renderBoundary(&b, bID, assetBoundary, boundaryParent, emitted, 1)
		}
	}

	// Render assets that belong to no trust boundary at the top level.
	var orphans []string
	for _, id := range d.sortedAssetIDs() {
		if _, inBoundary := assetBoundary[id]; !inBoundary && !emitted[id] {
			orphans = append(orphans, id)
		}
	}
	if len(orphans) > 0 {
		b.WriteString("  %% assets outside any trust boundary\n")
		for _, id := range orphans {
			b.WriteString("  " + d.nodeDecl(id) + "\n")
			emitted[id] = true
		}
	}

	d.renderEdges(&b)
	d.renderClasses(&b)
	return b.String()
}

func (d *diagram) sortedBoundaryIDs() []string {
	ids := make([]string, 0, len(d.model.TrustBoundaries))
	for id := range d.model.TrustBoundaries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (d *diagram) renderBoundary(b *strings.Builder, bID string, assetBoundary, boundaryParent map[string]string, emitted map[string]bool, depth int) {
	tb, ok := d.model.TrustBoundaries[bID]
	if !ok {
		return
	}
	if d.rendered[bID] {
		return // already emitted (guards against nesting cycles)
	}
	d.rendered[bID] = true
	indent := strings.Repeat("  ", depth)
	label := tb.Title
	if tb.Type.String() != "" {
		label = fmt.Sprintf("%s (%s)", tb.Title, tb.Type.String())
	}
	fmt.Fprintf(b, "%ssubgraph %s[\"%s\"]\n", indent, d.boundaryID[bID], esc(label))

	// Direct assets, sorted.
	inside := append([]string{}, tb.TechnicalAssetsInside...)
	sort.Strings(inside)
	for _, a := range inside {
		if emitted[a] {
			continue
		}
		if _, exists := d.model.TechnicalAssets[a]; !exists {
			continue
		}
		// Only render here if this boundary is the asset's direct boundary.
		if assetBoundary[a] != bID {
			continue
		}
		fmt.Fprintf(b, "%s  %s\n", indent, d.nodeDecl(a))
		emitted[a] = true
	}

	// Nested boundaries, sorted.
	nested := append([]string{}, tb.TrustBoundariesNested...)
	sort.Strings(nested)
	for _, child := range nested {
		if boundaryParent[child] == bID {
			d.renderBoundary(b, child, assetBoundary, boundaryParent, emitted, depth+1)
		}
	}
	fmt.Fprintf(b, "%send\n", indent)
}

// nodeDecl returns the Mermaid node declaration with a type-appropriate shape:
// datastores as cylinders, external entities as stadiums, processes as boxes.
func (d *diagram) nodeDecl(assetID string) string {
	ta := d.model.TechnicalAssets[assetID]
	label := esc(ta.Title)
	if label == "" {
		label = esc(assetID)
	}
	id := d.nodeID[assetID]
	switch ta.Type {
	case types.Datastore:
		return fmt.Sprintf("%s[(\"%s\")]", id, label)
	case types.ExternalEntity:
		return fmt.Sprintf("%s([\"%s\"])", id, label)
	default: // Process
		return fmt.Sprintf("%s[\"%s\"]", id, label)
	}
}

func (d *diagram) renderEdges(b *strings.Builder) {
	wrote := false
	for _, srcID := range d.sortedAssetIDs() {
		ta := d.model.TechnicalAssets[srcID]
		links := append([]*types.CommunicationLink{}, ta.CommunicationLinks...)
		sort.Slice(links, func(i, j int) bool {
			if links[i].Title != links[j].Title {
				return links[i].Title < links[j].Title
			}
			return links[i].TargetId < links[j].TargetId
		})
		for _, cl := range links {
			tgtID := cl.TargetId
			if _, ok := d.model.TechnicalAssets[tgtID]; !ok {
				continue // dangling link target; skip
			}
			if !wrote {
				b.WriteString("  %% communication links (solid = encrypted/VPN, dashed = cleartext)\n")
				wrote = true
			}
			arrow := "-.->"
			if cl.Protocol.IsEncrypted() || cl.VPN {
				arrow = "-->"
			}
			label := cl.Title
			if label == "" {
				label = cl.Protocol.String()
			}
			// Edge labels are delimited by the surrounding pipes; the label
			// itself is left unquoted (outer quotes would render literally) and
			// any embedded '|' is entity-escaped so it can't break the edge.
			fmt.Fprintf(b, "  %s %s|%s| %s\n", d.nodeID[srcID], arrow, esc(label), d.nodeID[tgtID])
		}
	}
}

func (d *diagram) renderClasses(b *strings.Builder) {
	// Collect, in sorted order, which classes are actually used so the output
	// is minimal and deterministic.
	type assignment struct{ node, class string }
	var assignments []assignment
	usedClass := map[string]bool{}

	for _, id := range d.sortedAssetIDs() {
		ta := d.model.TechnicalAssets[id]
		node := d.nodeID[id]
		if d.opts.WithRisks && d.hasSev[id] {
			c := severityClass[d.sev[id]]
			assignments = append(assignments, assignment{node, c})
			usedClass[c] = true
		} else if ta.OutOfScope {
			assignments = append(assignments, assignment{node, "outofscope"})
			usedClass["outofscope"] = true
		}
		if ta.Internet {
			assignments = append(assignments, assignment{node, "internet"})
			usedClass["internet"] = true
		}
	}

	if len(assignments) == 0 {
		return
	}

	b.WriteString("  %% styling\n")
	// classDefs in a fixed order.
	for _, def := range classDefs {
		if usedClass[def.name] {
			fmt.Fprintf(b, "  classDef %s %s;\n", def.name, def.style)
		}
	}
	for _, a := range assignments {
		fmt.Fprintf(b, "  class %s %s;\n", a.node, a.class)
	}
}

var classDefs = []struct{ name, style string }{
	{"sevCritical", "fill:#b71c1c,color:#ffffff,stroke:#7f0000,stroke-width:2px"},
	{"sevHigh", "fill:#e53935,color:#ffffff,stroke:#b71c1c,stroke-width:2px"},
	{"sevElevated", "fill:#fb8c00,color:#000000,stroke:#e65100,stroke-width:2px"},
	{"sevMedium", "fill:#fdd835,color:#000000,stroke:#f9a825,stroke-width:1px"},
	{"sevLow", "fill:#c0ca33,color:#000000,stroke:#9e9d24,stroke-width:1px"},
	{"internet", "stroke:#1565c0,stroke-width:4px"},
	{"outofscope", "fill:#f5f5f5,color:#9e9e9e,stroke-dasharray:5 5"},
}

// sanitize maps an arbitrary model ID to a safe Mermaid identifier fragment
// ([A-Za-z0-9_]); non-conforming runes become underscores.
func sanitize(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	s := b.String()
	if s == "" {
		return "_"
	}
	return s
}

// esc makes a label safe for Mermaid, using numeric character codes (#NN;) that
// render correctly both inside a quoted node label and inside an unquoted edge
// label. It neutralises the characters that would otherwise break the syntax:
// the double quote (node-label delimiter), the pipe (edge-label delimiter),
// angle brackets (HTML interpretation) and the backslash (escape char).
func esc(s string) string {
	r := strings.NewReplacer(
		`\`, "#92;",
		`"`, "#34;",
		"|", "#124;",
		"<", "#60;",
		">", "#62;",
		"\n", " ",
		"\r", " ",
	)
	return r.Replace(s)
}
