package threagile

import (
	"fmt"
	"sort"

	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/types"
)

// modelToInput converts an analyzed/internal *types.Model (what the importers
// build) into the *input.Model authoring format that Threagile actually parses.
//
// This is the bridge that makes importer output directly analyzable: the input
// format keys technical_assets / data_assets / trust_boundaries by TITLE (with a
// separate `id` field), nests communication_links under the source asset keyed by
// link title, references other objects by id, and renders every enum as its
// string form. Marshalling a raw types.Model does none of that, so its YAML can
// not be re-parsed — converting first fixes that for every importer.
//
// Scope: this targets the partial models the importers build (technical/data
// assets, trust boundaries, communication links, with the data-flow links that
// drive analysis). Sections the importers never populate — shared runtimes, risk
// tracking, custom risk categories, and the methodology-specific top-level
// sections — are intentionally not carried; revisit if a future caller needs a
// full types.Model round-trip.
func modelToInput(m *types.Model) *input.Model {
	// business_criticality is required by the parser; default it (importers don't
	// know it) so the emitted fragment analyzes without hand-editing.
	businessCriticality := m.BusinessCriticality.String()
	if businessCriticality == "" {
		businessCriticality = types.Important.String()
	}

	out := &input.Model{
		ThreagileVersion:    m.ThreagileVersion,
		Title:               m.Title,
		BusinessCriticality: businessCriticality,
		TagsAvailable:       m.TagsAvailable,
		DataAssets:          map[string]input.DataAsset{},
		TechnicalAssets:     map[string]input.TechnicalAsset{},
		TrustBoundaries:     map[string]input.TrustBoundary{},
	}

	used := map[string]bool{} // guards against duplicate title keys

	for _, da := range sortedDataAssets(m.DataAssets) {
		key := uniqueTitle(da.Title, da.Id, used)
		out.DataAssets[key] = input.DataAsset{
			ID:              da.Id,
			Description:     da.Description,
			Usage:           da.Usage.String(),
			Quantity:        da.Quantity.String(),
			Tags:            da.Tags,
			Confidentiality: da.Confidentiality.String(),
			Integrity:       da.Integrity.String(),
			Availability:    da.Availability.String(),
			PiiCategories:   da.PiiCategories,
		}
	}

	for _, ta := range sortedTechnicalAssets(m.TechnicalAssets) {
		key := uniqueTitle(ta.Title, ta.Id, used)
		links := map[string]input.CommunicationLink{}
		for _, link := range ta.CommunicationLinks {
			linkKey := uniqueLinkTitle(link.Title, link.Id, links)
			links[linkKey] = input.CommunicationLink{
				Target:             link.TargetId,
				Description:        link.Description,
				Protocol:           link.Protocol.String(),
				Authentication:     link.Authentication.String(),
				Authorization:      link.Authorization.String(),
				Usage:              link.Usage.String(),
				Tags:               link.Tags,
				VPN:                link.VPN,
				IpFiltered:         link.IpFiltered,
				Readonly:           link.Readonly,
				DataAssetsSent:     link.DataAssetsSent,
				DataAssetsReceived: link.DataAssetsReceived,
			}
		}

		ia := input.TechnicalAsset{
			ID:                      ta.Id,
			Description:             ta.Description,
			Type:                    ta.Type.String(),
			Size:                    ta.Size.String(),
			Internet:                ta.Internet,
			Machine:                 ta.Machine.String(),
			Encryption:              ta.Encryption.String(),
			Confidentiality:         ta.Confidentiality.String(),
			Integrity:               ta.Integrity.String(),
			Availability:            ta.Availability.String(),
			Tags:                    ta.Tags,
			Owner:                   ta.Owner,
			MultiTenant:             ta.MultiTenant,
			Redundant:               ta.Redundant,
			CustomDevelopedParts:    ta.CustomDevelopedParts,
			OutOfScope:              ta.OutOfScope,
			UsedAsClientByHuman:     ta.UsedAsClientByHuman,
			JustificationOutOfScope: ta.JustificationOutOfScope,
			JustificationCiaRating:  ta.JustificationCiaRating,
			// Data-flow links drive most risk rules — never drop them.
			DataAssetsProcessed: ta.DataAssetsProcessed,
			DataAssetsStored:    ta.DataAssetsStored,
			DataFormatsAccepted: dataFormatsToStrings(ta.DataFormatsAccepted),
		}
		if u := ta.Usage.String(); u != "" {
			ia.Usage = u
		}
		setTechnologies(&ia, ta.Technologies)
		if len(links) > 0 {
			ia.CommunicationLinks = links
		}
		out.TechnicalAssets[key] = ia
	}

	for _, tb := range sortedTrustBoundaries(m.TrustBoundaries) {
		key := uniqueTitle(tb.Title, tb.Id, used)
		out.TrustBoundaries[key] = input.TrustBoundary{
			ID:                    tb.Id,
			Description:           tb.Description,
			Type:                  tb.Type.String(),
			Tags:                  tb.Tags,
			TechnicalAssetsInside: tb.TechnicalAssetsInside,
			TrustBoundariesNested: tb.TrustBoundariesNested,
		}
	}

	// The parser requires every tag used anywhere to be declared in
	// tags_available; collect them so the fragment validates.
	out.TagsAvailable = collectTags(m, out.TagsAvailable)

	return out
}

// collectTags returns the sorted union of the seed tags and every tag used on any
// technical asset, data asset, communication link, or trust boundary.
func collectTags(m *types.Model, seed []string) []string {
	set := map[string]bool{}
	for _, t := range seed {
		set[t] = true
	}
	add := func(tags []string) {
		for _, t := range tags {
			if t != "" {
				set[t] = true
			}
		}
	}
	for _, ta := range m.TechnicalAssets {
		add(ta.Tags)
		for _, link := range ta.CommunicationLinks {
			add(link.Tags)
		}
	}
	for _, da := range m.DataAssets {
		add(da.Tags)
	}
	for _, tb := range m.TrustBoundaries {
		add(tb.Tags)
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func dataFormatsToStrings(formats []types.DataFormat) []string {
	if len(formats) == 0 {
		return nil
	}
	out := make([]string, 0, len(formats))
	for _, f := range formats {
		out = append(out, f.String())
	}
	return out
}

func setTechnologies(ia *input.TechnicalAsset, techs types.TechnologyList) {
	names := make([]string, 0, len(techs))
	for _, t := range techs {
		if t != nil && t.Name != "" {
			names = append(names, t.Name)
		}
	}
	switch len(names) {
	case 0:
	case 1:
		ia.Technology = names[0]
	default:
		ia.Technologies = names
	}
}

// uniqueTitle returns a map key based on the title, falling back to the id and
// disambiguating collisions so two objects never overwrite each other.
func uniqueTitle(title, id string, used map[string]bool) string {
	key := title
	if key == "" {
		key = id
	}
	if used[key] {
		key = fmt.Sprintf("%s (%s)", key, id)
	}
	used[key] = true
	return key
}

func uniqueLinkTitle(title, id string, existing map[string]input.CommunicationLink) string {
	key := title
	if key == "" {
		key = id
	}
	if _, ok := existing[key]; ok {
		key = fmt.Sprintf("%s (%s)", key, id)
	}
	return key
}

func sortedTechnicalAssets(m map[string]*types.TechnicalAsset) []*types.TechnicalAsset {
	out := make([]*types.TechnicalAsset, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Id < out[j].Id })
	return out
}

func sortedDataAssets(m map[string]*types.DataAsset) []*types.DataAsset {
	out := make([]*types.DataAsset, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Id < out[j].Id })
	return out
}

func sortedTrustBoundaries(m map[string]*types.TrustBoundary) []*types.TrustBoundary {
	out := make([]*types.TrustBoundary, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Id < out[j].Id })
	return out
}
