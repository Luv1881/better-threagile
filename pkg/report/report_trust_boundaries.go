package report

import (
	"sort"
	"strconv"

	"github.com/threagile/threagile/pkg/types"
)

func (r *pdfReporter) createTrustBoundaries(parsedModel *types.Model) {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	title := "Trust Boundaries"
	r.pdfColorBlack()
	r.addHeadline(title, false)

	html := r.pdf.HTMLBasicNew()
	word := "has"
	if len(parsedModel.TrustBoundaries) > 1 {
		word = "have"
	}
	html.Write(5, "In total <b>"+strconv.Itoa(len(parsedModel.TrustBoundaries))+" trust boundaries</b> "+word+" been "+
		"modeled during the threat modeling process.")
	r.currentChapterTitleBreadcrumb = title
	for _, trustBoundary := range sortedTrustBoundariesByTitle(parsedModel) {
		if r.pdf.GetY() > 250 {
			r.pageBreak()
			r.pdf.SetY(36)
		} else {
			html.Write(5, "<br><br><br>")
		}
		colorTwilight(r.pdf)
		if !trustBoundary.Type.IsNetworkBoundary() {
			r.pdfColorLightGray()
		}
		html.Write(5, "<b>"+uni(trustBoundary.Title)+"</b><br>")
		r.defineLinkTarget("{boundary:" + trustBoundary.Id + "}")
		html.Write(5, uni(trustBoundary.Description))
		html.Write(5, "<br><br>")

		r.pdf.SetFont("Helvetica", "", fontSizeBody)

		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "ID:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, trustBoundary.Id, "0", "0", false)

		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Type:", "0", 0, "", false, 0, "")
		colorTwilight(r.pdf)
		if !trustBoundary.Type.IsNetworkBoundary() {
			r.pdfColorLightGray()
		}
		r.pdf.MultiCell(145, 6, trustBoundary.Type.String(), "0", "0", false)
		r.pdfColorBlack()

		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Tags:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		tagsUsedText := ""
		sorted := trustBoundary.Tags
		sort.Strings(sorted)
		for _, tag := range sorted {
			if len(tagsUsedText) > 0 {
				tagsUsedText += ", "
			}
			tagsUsedText += tag
		}
		if len(tagsUsedText) == 0 {
			r.pdfColorGray()
			tagsUsedText = "none"
		}
		r.pdf.MultiCell(145, 6, uni(tagsUsedText), "0", "0", false)

		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Assets inside:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		assetsInsideText := ""
		for _, assetKey := range trustBoundary.TechnicalAssetsInside {
			if len(assetsInsideText) > 0 {
				assetsInsideText += ", "
			}
			assetsInsideText += parsedModel.TechnicalAssets[assetKey].Title // TODO add link to technical asset detail chapter and back
		}
		if len(assetsInsideText) == 0 {
			r.pdfColorGray()
			assetsInsideText = "none"
		}
		r.pdf.MultiCell(145, 6, uni(assetsInsideText), "0", "0", false)

		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Boundaries nested:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		boundariesNestedText := ""
		for _, assetKey := range trustBoundary.TrustBoundariesNested {
			if len(boundariesNestedText) > 0 {
				boundariesNestedText += ", "
			}
			boundariesNestedText += parsedModel.TrustBoundaries[assetKey].Title
		}
		if len(boundariesNestedText) == 0 {
			r.pdfColorGray()
			boundariesNestedText = "none"
		}
		r.pdf.MultiCell(145, 6, uni(boundariesNestedText), "0", "0", false)
	}
}

func (r *pdfReporter) createSharedRuntimes(parsedModel *types.Model) {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	title := "Shared Runtimes"
	r.pdfColorBlack()
	r.addHeadline(title, false)

	html := r.pdf.HTMLBasicNew()
	word, runtime := "has", "runtime"
	if len(parsedModel.SharedRuntimes) > 1 {
		word, runtime = "have", "runtimes"
	}
	html.Write(5, "In total <b>"+strconv.Itoa(len(parsedModel.SharedRuntimes))+" shared "+runtime+"</b> "+word+" been "+
		"modeled during the threat modeling process.")
	r.currentChapterTitleBreadcrumb = title
	for _, sharedRuntime := range sortedSharedRuntimesByTitle(parsedModel) {
		r.pdfColorBlack()
		if r.pdf.GetY() > 250 {
			r.pageBreak()
			r.pdf.SetY(36)
		} else {
			html.Write(5, "<br><br><br>")
		}
		html.Write(5, "<b>"+uni(sharedRuntime.Title)+"</b><br>")
		r.defineLinkTarget("{runtime:" + sharedRuntime.Id + "}")
		html.Write(5, uni(sharedRuntime.Description))
		html.Write(5, "<br><br>")

		r.pdf.SetFont("Helvetica", "", fontSizeBody)

		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "ID:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, sharedRuntime.Id, "0", "0", false)

		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Tags:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		tagsUsedText := ""
		sorted := sharedRuntime.Tags
		sort.Strings(sorted)
		for _, tag := range sorted {
			if len(tagsUsedText) > 0 {
				tagsUsedText += ", "
			}
			tagsUsedText += tag
		}
		if len(tagsUsedText) == 0 {
			r.pdfColorGray()
			tagsUsedText = "none"
		}
		r.pdf.MultiCell(145, 6, uni(tagsUsedText), "0", "0", false)

		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Assets running:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		assetsInsideText := ""
		for _, assetKey := range sharedRuntime.TechnicalAssetsRunning {
			if len(assetsInsideText) > 0 {
				assetsInsideText += ", "
			}
			assetsInsideText += parsedModel.TechnicalAssets[assetKey].Title // TODO add link to technical asset detail chapter and back
		}
		if len(assetsInsideText) == 0 {
			r.pdfColorGray()
			assetsInsideText = "none"
		}
		r.pdf.MultiCell(145, 6, uni(assetsInsideText), "0", "0", false)
	}
}
