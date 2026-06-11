package report

import (
	"sort"
	"strconv"

	"github.com/threagile/threagile/pkg/types"
)

func (r *pdfReporter) createDataAssets(parsedModel *types.Model) {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	title := "Identified Data Breach Probabilities by Data Asset"
	r.pdfColorBlack()
	r.addHeadline(title, false)
	r.defineLinkTarget("{intro-risks-by-data-asset}")
	html := r.pdf.HTMLBasicNew()
	html.Write(5, "In total <b>"+strconv.Itoa(totalRiskCount(parsedModel))+" potential risks</b> have been identified during the threat modeling process "+
		"of which "+
		"<b>"+strconv.Itoa(len(filteredBySeverity(parsedModel, types.CriticalSeverity)))+" are rated as critical</b>, "+
		"<b>"+strconv.Itoa(len(filteredBySeverity(parsedModel, types.HighSeverity)))+" as high</b>, "+
		"<b>"+strconv.Itoa(len(filteredBySeverity(parsedModel, types.ElevatedSeverity)))+" as elevated</b>, "+
		"<b>"+strconv.Itoa(len(filteredBySeverity(parsedModel, types.MediumSeverity)))+" as medium</b>, "+
		"and <b>"+strconv.Itoa(len(filteredBySeverity(parsedModel, types.LowSeverity)))+" as low</b>. "+
		"<br><br>These risks are distributed across <b>"+strconv.Itoa(len(parsedModel.DataAssets))+" data assets</b>. ")
	html.Write(5, "The following sub-chapters of this section describe the derived data breach probabilities grouped by data asset.<br>") // TODO more explanation text
	r.pdf.SetFont("Helvetica", "", fontSizeSmall)
	r.pdfColorGray()
	html.Write(5, "Technical asset names and risk IDs are clickable and link to the corresponding chapter.")
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	r.currentChapterTitleBreadcrumb = title
	for _, dataAsset := range sortedDataAssetsByDataBreachProbabilityAndTitle(parsedModel) {
		if r.pdf.GetY() > 280 { // 280 as only small font previously (not 250)
			r.pageBreak()
			r.pdf.SetY(36)
		} else {
			html.Write(5, "<br><br><br>")
		}
		r.pdfColorBlack()
		switch identifiedDataBreachProbabilityStillAtRisk(parsedModel, dataAsset) {
		case types.Probable:
			colorHighRisk(r.pdf)
		case types.Possible:
			colorMediumRisk(r.pdf)
		case types.Improbable:
			colorLowRisk(r.pdf)
		default:
			r.pdfColorBlack()
		}
		if !isDataBreachPotentialStillAtRisk(parsedModel, dataAsset) {
			r.pdfColorBlack()
		}
		risksStr := parsedModel.IdentifiedDataBreachProbabilityRisks(dataAsset)
		countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(risksStr))
		suffix := strconv.Itoa(countStillAtRisk) + " / " + strconv.Itoa(len(risksStr)) + " Risk"
		if len(risksStr) != 1 {
			suffix += "s"
		}
		title := uni(dataAsset.Title) + ": " + suffix
		r.addHeadline(title, true)
		r.defineLinkTarget("{data:" + dataAsset.Id + "}")
		r.pdfColorBlack()
		html.Write(5, uni(dataAsset.Description))
		html.Write(5, "<br><br>")

		r.pdf.SetFont("Helvetica", "", fontSizeBody)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "ID:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, dataAsset.Id, "0", "0", false)
		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Usage:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, dataAsset.Usage.String(), "0", "0", false)
		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Quantity:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, dataAsset.Quantity.String(), "0", "0", false)
		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Tags:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		tagsUsedText := ""
		sorted := dataAsset.Tags
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
		r.pdf.CellFormat(40, 6, "Origin:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, uni(dataAsset.Origin), "0", "0", false)
		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Owner:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, uni(dataAsset.Owner), "0", "0", false)
		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Confidentiality:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.CellFormat(40, 6, dataAsset.Confidentiality.String(), "0", 0, "", false, 0, "")
		r.pdfColorGray()
		r.pdf.CellFormat(115, 6, dataAsset.Confidentiality.RatingStringInScale(), "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.Ln(-1)
		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Integrity:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.CellFormat(40, 6, dataAsset.Integrity.String(), "0", 0, "", false, 0, "")
		r.pdfColorGray()
		r.pdf.CellFormat(115, 6, dataAsset.Integrity.RatingStringInScale(), "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.Ln(-1)
		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Availability:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.CellFormat(40, 6, dataAsset.Availability.String(), "0", 0, "", false, 0, "")
		r.pdfColorGray()
		r.pdf.CellFormat(115, 6, dataAsset.Availability.RatingStringInScale(), "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.Ln(-1)
		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "CIA-Justification:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, uni(dataAsset.JustificationCiaRating), "0", "0", false)

		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Processed by:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		processedByText := ""
		for _, dataAsset := range parsedModel.ProcessedByTechnicalAssetsSorted(dataAsset) {
			if len(processedByText) > 0 {
				processedByText += ", "
			}
			processedByText += dataAsset.Title // TODO add link to technical asset detail chapter and back
		}
		if len(processedByText) == 0 {
			r.pdfColorGray()
			processedByText = "none"
		}
		r.pdf.MultiCell(145, 6, uni(processedByText), "0", "0", false)

		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Stored by:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		storedByText := ""
		for _, dataAsset := range parsedModel.StoredByTechnicalAssetsSorted(dataAsset) {
			if len(storedByText) > 0 {
				storedByText += ", "
			}
			storedByText += dataAsset.Title // TODO add link to technical asset detail chapter and back
		}
		if len(storedByText) == 0 {
			r.pdfColorGray()
			storedByText = "none"
		}
		r.pdf.MultiCell(145, 6, uni(storedByText), "0", "0", false)

		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Sent via:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		sentViaText := ""
		for _, commLink := range parsedModel.SentViaCommLinksSorted(dataAsset) {
			if len(sentViaText) > 0 {
				sentViaText += ", "
			}
			sentViaText += commLink.Title // TODO add link to technical asset detail chapter and back
		}
		if len(sentViaText) == 0 {
			r.pdfColorGray()
			sentViaText = "none"
		}
		r.pdf.MultiCell(145, 6, uni(sentViaText), "0", "0", false)

		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Received via:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		receivedViaText := ""
		for _, commLink := range parsedModel.ReceivedViaCommLinksSorted(dataAsset) {
			if len(receivedViaText) > 0 {
				receivedViaText += ", "
			}
			receivedViaText += commLink.Title // TODO add link to technical asset detail chapter and back
		}
		if len(receivedViaText) == 0 {
			r.pdfColorGray()
			receivedViaText = "none"
		}
		r.pdf.MultiCell(145, 6, uni(receivedViaText), "0", "0", false)

		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Data Breach:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.SetFont("Helvetica", "B", fontSizeBody)
		dataBreachProbability := identifiedDataBreachProbabilityStillAtRisk(parsedModel, dataAsset)
		riskText := dataBreachProbability.String()
		switch dataBreachProbability {
		case types.Probable:
			colorHighRisk(r.pdf)
		case types.Possible:
			colorMediumRisk(r.pdf)
		case types.Improbable:
			colorLowRisk(r.pdf)
		default:
			r.pdfColorBlack()
		}
		if !isDataBreachPotentialStillAtRisk(parsedModel, dataAsset) {
			r.pdfColorBlack()
			riskText = "none"
		}
		r.pdf.MultiCell(145, 6, riskText, "0", "0", false)
		r.pdf.SetFont("Helvetica", "", fontSizeBody)
		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}

		// how can is this data asset be indirectly lost (i.e. why)
		dataBreachRisksStillAtRisk := identifiedDataBreachProbabilityRisksStillAtRisk(parsedModel, dataAsset)
		sortByDataBreachProbability(dataBreachRisksStillAtRisk, parsedModel)
		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Data Breach Risks:", "0", 0, "", false, 0, "")
		if len(dataBreachRisksStillAtRisk) == 0 {
			r.pdfColorGray()
			r.pdf.MultiCell(145, 6, "This data asset has no data breach potential.", "0", "0", false)
		} else {
			r.pdfColorBlack()
			riskRemainingStr := "risksStr"
			if countStillAtRisk == 1 {
				riskRemainingStr = "risk"
			}
			r.pdf.MultiCell(145, 6, "This data asset has data breach potential because of "+
				""+strconv.Itoa(countStillAtRisk)+" remaining "+riskRemainingStr+":", "0", "0", false)
			for _, dataBreachRisk := range dataBreachRisksStillAtRisk {
				if r.pdf.GetY() > 280 { // 280 as only small font here
					r.pageBreak()
					r.pdf.SetY(36)
				}
				switch dataBreachRisk.DataBreachProbability {
				case types.Probable:
					colorHighRisk(r.pdf)
				case types.Possible:
					colorMediumRisk(r.pdf)
				case types.Improbable:
					colorLowRisk(r.pdf)
				default:
					r.pdfColorBlack()
				}
				if !dataBreachRisk.RiskStatus.IsStillAtRisk() {
					r.pdfColorBlack()
				}
				r.pdf.CellFormat(10, 6, "", "0", 0, "", false, 0, "")
				posY := r.pdf.GetY()
				r.pdf.SetFont("Helvetica", "", fontSizeVerySmall)
				r.pdf.MultiCell(185, 5, dataBreachRisk.DataBreachProbability.Title()+": "+uni(dataBreachRisk.SyntheticId), "0", "0", false)
				r.pdf.SetFont("Helvetica", "", fontSizeBody)
				r.pdf.Link(20, posY, 180, r.pdf.GetY()-posY, r.tocLinkIdByAssetId[dataBreachRisk.CategoryId])
			}
			r.pdfColorBlack()
		}
	}
}

func sortByDataBreachProbability(risks []*types.Risk, _ *types.Model) {
	sort.Slice(risks, func(i, j int) bool {

		if risks[i].DataBreachProbability == risks[j].DataBreachProbability {
			trackingStatusLeft := risks[i].RiskStatus
			trackingStatusRight := risks[j].RiskStatus
			if trackingStatusLeft == trackingStatusRight {
				return risks[i].Title < risks[j].Title
			} else {
				return trackingStatusLeft < trackingStatusRight
			}
		}
		return risks[i].DataBreachProbability > risks[j].DataBreachProbability
	})
}

func identifiedDataBreachProbabilityRisksStillAtRisk(parsedModel *types.Model, dataAsset *types.DataAsset) []*types.Risk {
	result := make([]*types.Risk, 0)
	for _, risk := range filteredByStillAtRisk(parsedModel) {
		for _, techAsset := range risk.DataBreachTechnicalAssetIDs {
			if contains(parsedModel.TechnicalAssets[techAsset].DataAssetsProcessed, dataAsset.Id) {
				result = append(result, risk)
				break
			}
		}
	}
	return result
}

func isDataBreachPotentialStillAtRisk(parsedModel *types.Model, dataAsset *types.DataAsset) bool {
	for _, risk := range filteredByStillAtRisk(parsedModel) {
		for _, techAsset := range risk.DataBreachTechnicalAssetIDs {
			if contains(parsedModel.TechnicalAssets[techAsset].DataAssetsProcessed, dataAsset.Id) {
				return true
			}
		}
	}
	return false
}
