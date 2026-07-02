package mapping

import (
	"github.com/threagile/threagile/pkg/types"
)

// Element is the generic view of a source-diagram element (a vertex/node or
// an edge/flow) that a Ruleset matches against. Label is always populated by
// every importer; Edge/Color/LineStyle/FillColor are populated only by
// importers whose source format retains that raw style metadata — currently
// just drawio (style-derived stroke/fill colors and dash state). Importers
// that can't supply a field simply leave it at its zero value, so matchers
// on that field never fire for them; that's an intentional degrade, not an
// error (see the package doc).
type Element struct {
	Label     string
	Edge      bool
	Color     string
	LineStyle string
	FillColor string
}

// Applied is the merged result of evaluating every rule in a Ruleset against
// one Element.
type Applied struct {
	Type            string
	Technology      string
	Technologies    []string
	Machine         string
	Encryption      string
	Tags            []string
	TrustBoundary   string
	Confidentiality string
	Integrity       string
	Availability    string
}

// Resolve evaluates every rule in rs against el, in file order, and merges
// the result: for each scalar field the FIRST matching rule that sets it
// wins (classic "first match wins"); set.tags instead accumulate as a
// deduplicated union across every matching rule, because tags are additive
// by nature elsewhere in this codebase (every importer already appends its
// own review tag rather than replacing tags) and dropping tags from a later
// rule just because an earlier rule already set, say, `technology` would be
// surprising. rs may be nil, in which case Resolve is a no-op.
func (rs *Ruleset) Resolve(el Element) Applied {
	var out Applied
	if rs == nil {
		return out
	}

	haveType, haveTech, haveTechs, haveMachine := false, false, false, false
	haveEncryption, haveTrust, haveConf, haveInt, haveAvail := false, false, false, false, false
	seenTag := map[string]bool{}

	for i := range rs.Rules {
		r := &rs.Rules[i]
		if !r.matches(el) {
			continue
		}
		if !haveType && r.Set.Type != "" {
			out.Type, haveType = r.Set.Type, true
		}
		if !haveTech && r.Set.Technology != "" {
			out.Technology, haveTech = r.Set.Technology, true
		}
		if !haveTechs && len(r.Set.Technologies) > 0 {
			out.Technologies = append([]string{}, r.Set.Technologies...)
			haveTechs = true
		}
		if !haveMachine && r.Set.Machine != "" {
			out.Machine, haveMachine = r.Set.Machine, true
		}
		if !haveEncryption && r.Set.Encryption != "" {
			out.Encryption, haveEncryption = r.Set.Encryption, true
		}
		if !haveTrust {
			if r.Set.TrustBoundary != "" {
				out.TrustBoundary, haveTrust = r.Set.TrustBoundary, true
			} else if r.Set.Trust != "" {
				out.TrustBoundary, haveTrust = r.Set.Trust, true
			}
		}
		if !haveConf && r.Set.Confidentiality != "" {
			out.Confidentiality, haveConf = r.Set.Confidentiality, true
		}
		if !haveInt && r.Set.Integrity != "" {
			out.Integrity, haveInt = r.Set.Integrity, true
		}
		if !haveAvail && r.Set.Availability != "" {
			out.Availability, haveAvail = r.Set.Availability, true
		}
		for _, t := range r.Set.Tags {
			if t != "" && !seenTag[t] {
				seenTag[t] = true
				out.Tags = append(out.Tags, t)
			}
		}
	}
	return out
}

// appendTags appends tags to *dst, skipping any already present (so applying
// a ruleset repeatedly, or after an importer already added its own review
// tag, never produces duplicates).
func appendTags(dst *[]string, tags []string) {
	if len(tags) == 0 {
		return
	}
	existing := make(map[string]bool, len(*dst))
	for _, t := range *dst {
		existing[t] = true
	}
	for _, t := range tags {
		if !existing[t] {
			existing[t] = true
			*dst = append(*dst, t)
		}
	}
}

// ApplyToTechnicalAsset resolves rs against el and mutates asset with the
// recognised fields: type, technology/technologies, machine, tags. Values
// that don't parse into the corresponding Threagile enum (a typo in the
// rules file) are silently skipped rather than failing the whole import —
// the field simply keeps its importer-assigned default, same fail-open
// posture the diagram importers already take for everything else they
// can't classify with confidence. Encryption and confidentiality/
// integrity/availability from the rule are also applied here since a
// technical asset carries those fields directly. rs and asset may be nil.
func ApplyToTechnicalAsset(rs *Ruleset, asset *types.TechnicalAsset, el Element) {
	if rs == nil || asset == nil {
		return
	}
	a := rs.Resolve(el)

	if a.Type != "" {
		if t, err := types.ParseTechnicalAssetType(a.Type); err == nil {
			asset.Type = t
		}
	}
	if a.Technology != "" {
		asset.Technologies = types.TechnologyList{&types.Technology{Name: a.Technology}}
	} else if len(a.Technologies) > 0 {
		techs := make(types.TechnologyList, 0, len(a.Technologies))
		for _, name := range a.Technologies {
			techs = append(techs, &types.Technology{Name: name})
		}
		asset.Technologies = techs
	}
	if a.Machine != "" {
		if m, err := types.ParseTechnicalAssetMachine(a.Machine); err == nil {
			asset.Machine = m
		}
	}
	if a.Encryption != "" {
		if e, err := types.ParseEncryptionStyle(a.Encryption); err == nil {
			asset.Encryption = e
		}
	}
	if a.Confidentiality != "" {
		if c, err := types.ParseConfidentiality(a.Confidentiality); err == nil {
			asset.Confidentiality = c
		}
	}
	if a.Integrity != "" {
		if c, err := types.ParseCriticality(a.Integrity); err == nil {
			asset.Integrity = c
		}
	}
	if a.Availability != "" {
		if c, err := types.ParseCriticality(a.Availability); err == nil {
			asset.Availability = c
		}
	}
	tags := a.Tags
	if a.TrustBoundary != "" {
		tags = append(append([]string{}, tags...), "trust:"+a.TrustBoundary)
	}
	appendTags(&asset.Tags, tags)
}

// ApplyToDataAsset resolves rs against el and mutates da's CIA rating and
// tags. rs and da may be nil.
func ApplyToDataAsset(rs *Ruleset, da *types.DataAsset, el Element) {
	if rs == nil || da == nil {
		return
	}
	a := rs.Resolve(el)

	if a.Confidentiality != "" {
		if c, err := types.ParseConfidentiality(a.Confidentiality); err == nil {
			da.Confidentiality = c
		}
	}
	if a.Integrity != "" {
		if c, err := types.ParseCriticality(a.Integrity); err == nil {
			da.Integrity = c
		}
	}
	if a.Availability != "" {
		if c, err := types.ParseCriticality(a.Availability); err == nil {
			da.Availability = c
		}
	}
	appendTags(&da.Tags, a.Tags)
}

// ApplyToCommunicationLink resolves rs against el (el.Edge should normally
// be true for a link) and mutates link's tags. types.CommunicationLink has
// no direct "encryption" field, so a rule's `set.encryption` is recorded as
// a synthesized `encryption:<value>` tag instead of being dropped silently.
// rs and link may be nil.
func ApplyToCommunicationLink(rs *Ruleset, link *types.CommunicationLink, el Element) {
	if rs == nil || link == nil {
		return
	}
	a := rs.Resolve(el)

	tags := a.Tags
	if a.Encryption != "" {
		tags = append(append([]string{}, tags...), "encryption:"+a.Encryption)
	}
	appendTags(&link.Tags, tags)
}
