package report

import (
	"sort"

	"github.com/threagile/threagile/pkg/types"
)

func (r *pdfReporter) createTagListing(parsedModel *types.Model) {
	r.pdf.SetTextColor(0, 0, 0)
	chapTitle := "Tag Listing"
	r.addHeadline(chapTitle, false)
	r.defineLinkTarget("{tag-listing}")
	r.currentChapterTitleBreadcrumb = chapTitle

	html := r.pdf.HTMLBasicNew()
	html.Write(5, "This chapter lists what tags are used by which elements.")
	r.pdfColorBlack()
	sorted := parsedModel.TagsAvailable
	sort.Strings(sorted)
	for _, tag := range sorted {
		description := "" // TODO: add some separation texts to distinguish between technical assets and data assets etc. for example?
		for _, techAsset := range sortedTechnicalAssetsByTitle(parsedModel) {
			if contains(techAsset.Tags, tag) {
				if len(description) > 0 {
					description += ", "
				}
				description += techAsset.Title
			}
			for _, commLink := range techAsset.CommunicationLinksSorted() {
				if contains(commLink.Tags, tag) {
					if len(description) > 0 {
						description += ", "
					}
					description += commLink.Title
				}
			}
		}
		for _, dataAsset := range sortedDataAssetsByTitle(parsedModel) {
			if contains(dataAsset.Tags, tag) {
				if len(description) > 0 {
					description += ", "
				}
				description += dataAsset.Title
			}
		}
		for _, trustBoundary := range sortedTrustBoundariesByTitle(parsedModel) {
			if contains(trustBoundary.Tags, tag) {
				if len(description) > 0 {
					description += ", "
				}
				description += trustBoundary.Title
			}
		}
		for _, sharedRuntime := range sortedSharedRuntimesByTitle(parsedModel) {
			if contains(sharedRuntime.Tags, tag) {
				if len(description) > 0 {
					description += ", "
				}
				description += sharedRuntime.Title
			}
		}
		if len(description) > 0 {
			if r.pdf.GetY() > 250 {
				r.pageBreak()
				r.pdf.SetY(36)
			} else {
				html.Write(5, "<br><br><br>")
			}
			r.pdfColorBlack()
			uni := r.pdf.UnicodeTranslatorFromDescriptor("")
			html.Write(5, "<b>"+uni(tag)+"</b><br>")
			html.Write(5, uni(description))
		}
	}
}

func sortedSharedRuntimesByTitle(parsedModel *types.Model) []*types.SharedRuntime {
	result := make([]*types.SharedRuntime, 0)
	for _, runtime := range parsedModel.SharedRuntimes {
		result = append(result, runtime)
	}
	sort.Sort(bySharedRuntimeTitleSort(result))
	return result
}

type bySharedRuntimeTitleSort []*types.SharedRuntime

func (what bySharedRuntimeTitleSort) Len() int { return len(what) }

func (what bySharedRuntimeTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }

func (what bySharedRuntimeTitleSort) Less(i, j int) bool {
	return what[i].Title < what[j].Title
}

func sortedTechnicalAssetsByTitle(parsedModel *types.Model) []*types.TechnicalAsset {
	assets := make([]*types.TechnicalAsset, 0)
	for _, asset := range parsedModel.TechnicalAssets {
		assets = append(assets, asset)
	}
	sort.Sort(types.ByTechnicalAssetTitleSort(assets))
	return assets
}
