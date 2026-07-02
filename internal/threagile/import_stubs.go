package threagile

import (
	"sort"

	"github.com/threagile/threagile/pkg/types"
)

// This file implements the "data-asset stub generation" post-processing step
// shared by the diagram-derived importers (drawio, threat-dragon, otm) — see
// improvement.md P4. Diagrams show boxes and pipes, never data, but Threagile
// needs data assets wired onto communication links/technical assets or the
// model analyzes to ~zero risks and adopters bounce on day 1.
//
// stubDataAssets runs as a POST-PROCESSING step over the already-built
// *types.Model (after P3 mapping has had a chance to fix asset
// classification — reviewer-mandated ordering, see improvement.md P3/P4 —
// and importer-specific classification/tagging is done), so it's one
// implementation shared by every diagram importer rather than duplicated
// logic per package.

// stubDataAssetTag marks every data asset this step creates, independent of
// the source-specific "review-<importer>" tag, so `threagile review` (P6)
// and any future tooling can find every stub regardless of source.
const stubDataAssetTag = "stub-data-asset"

// stubDataAssets adds one stub data asset per datastore technical asset that
// doesn't already carry a data asset, and one stub data asset per
// communication link that is internet-inbound and doesn't already carry a
// data asset. sourceLabel (e.g. "drawio", "threat-dragon", "otm") is used to
// build the "review-<sourceLabel>" tag and has no effect on IDs, so re-import
// of the same diagram with the same importer produces byte-identical stub
// IDs/titles (required for P7 merge later and for golden-file tests).
func stubDataAssets(m *types.Model, sourceLabel string) {
	if m == nil {
		return
	}
	if m.DataAssets == nil {
		m.DataAssets = map[string]*types.DataAsset{}
	}

	reviewTag := "review-" + sourceLabel
	linksByAsset := groupLinksByAsset(m)

	for _, assetID := range sortedTechnicalAssetIDs(m) {
		asset := m.TechnicalAssets[assetID]
		if asset.Type != types.Datastore {
			continue
		}
		if datastoreAlreadyHasData(asset, linksByAsset[assetID]) {
			continue
		}

		id := asset.Id + "-data"
		if _, exists := m.DataAssets[id]; exists {
			continue
		}
		da := &types.DataAsset{
			Id:              id,
			Title:           asset.Title + "-data",
			Description:     "Stub data asset generated for datastore \"" + asset.Title + "\" — replace with the real data it stores.",
			Confidentiality: types.Confidential,
			Integrity:       types.Critical,
			Availability:    types.Critical,
			Tags:            []string{reviewTag, stubDataAssetTag},
		}
		m.DataAssets[id] = da

		if !containsString(asset.DataAssetsStored, id) {
			asset.DataAssetsStored = append(asset.DataAssetsStored, id)
		}
		for _, link := range linksByAsset[assetID] {
			switch {
			case link.SourceId == assetID && !containsString(link.DataAssetsSent, id):
				link.DataAssetsSent = append(link.DataAssetsSent, id)
			case link.TargetId == assetID && !containsString(link.DataAssetsReceived, id):
				link.DataAssetsReceived = append(link.DataAssetsReceived, id)
			}
		}
	}

	for _, linkID := range sortedCommunicationLinkIDs(m) {
		link := m.CommunicationLinks[linkID]
		if !linkIsInternetInbound(m, link) {
			continue
		}
		if len(link.DataAssetsSent) > 0 || len(link.DataAssetsReceived) > 0 {
			continue
		}

		id := link.Id + "-payload"
		if _, exists := m.DataAssets[id]; exists {
			continue
		}
		da := &types.DataAsset{
			Id:              id,
			Title:           link.Title + "-payload",
			Description:     "Stub data asset generated for internet-inbound link \"" + link.Title + "\" — replace with the real data assets sent/received.",
			Confidentiality: types.Confidential,
			Integrity:       types.Critical,
			Availability:    types.Critical,
			Tags:            []string{reviewTag, stubDataAssetTag},
		}
		m.DataAssets[id] = da
		link.DataAssetsSent = append(link.DataAssetsSent, id)
	}
}

// datastoreAlreadyHasData reports whether asset (or any communication link
// touching it) already carries at least one data asset, in which case no
// stub is generated for it.
func datastoreAlreadyHasData(asset *types.TechnicalAsset, links []*types.CommunicationLink) bool {
	if len(asset.DataAssetsStored) > 0 || len(asset.DataAssetsProcessed) > 0 {
		return true
	}
	for _, link := range links {
		if len(link.DataAssetsSent) > 0 || len(link.DataAssetsReceived) > 0 {
			return true
		}
	}
	return false
}

// linkIsInternetInbound reports whether either endpoint of link is flagged
// Internet: true — the diagram's only inbound-from-internet signal.
func linkIsInternetInbound(m *types.Model, link *types.CommunicationLink) bool {
	if src, ok := m.TechnicalAssets[link.SourceId]; ok && src.Internet {
		return true
	}
	if dst, ok := m.TechnicalAssets[link.TargetId]; ok && dst.Internet {
		return true
	}
	return false
}

// groupLinksByAsset indexes every communication link by every technical
// asset ID it touches (as source or target), sorted deterministically so
// downstream field-append order is stable across runs.
func groupLinksByAsset(m *types.Model) map[string][]*types.CommunicationLink {
	out := map[string][]*types.CommunicationLink{}
	for _, linkID := range sortedCommunicationLinkIDs(m) {
		link := m.CommunicationLinks[linkID]
		out[link.SourceId] = append(out[link.SourceId], link)
		if link.TargetId != link.SourceId {
			out[link.TargetId] = append(out[link.TargetId], link)
		}
	}
	return out
}

func sortedTechnicalAssetIDs(m *types.Model) []string {
	ids := make([]string, 0, len(m.TechnicalAssets))
	for id := range m.TechnicalAssets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func sortedCommunicationLinkIDs(m *types.Model) []string {
	ids := make([]string, 0, len(m.CommunicationLinks))
	for id := range m.CommunicationLinks {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
