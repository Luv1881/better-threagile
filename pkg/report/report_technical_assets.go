package report

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/threagile/threagile/pkg/types"
)

func (r *pdfReporter) createTechnicalAssets(parsedModel *types.Model) {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	// category title
	title := "Identified Risks by Technical Asset"
	r.pdfColorBlack()
	r.addHeadline(title, false)
	r.defineLinkTarget("{intro-risks-by-technical-asset}")
	html := r.pdf.HTMLBasicNew()
	var text strings.Builder
	text.WriteString("In total <b>" + strconv.Itoa(totalRiskCount(parsedModel)) + " potential risks</b> have been identified during the threat modeling process " +
		"of which " +
		"<b>" + strconv.Itoa(len(filteredBySeverity(parsedModel, types.CriticalSeverity))) + " are rated as critical</b>, " +
		"<b>" + strconv.Itoa(len(filteredBySeverity(parsedModel, types.HighSeverity))) + " as high</b>, " +
		"<b>" + strconv.Itoa(len(filteredBySeverity(parsedModel, types.ElevatedSeverity))) + " as elevated</b>, " +
		"<b>" + strconv.Itoa(len(filteredBySeverity(parsedModel, types.MediumSeverity))) + " as medium</b>, " +
		"and <b>" + strconv.Itoa(len(filteredBySeverity(parsedModel, types.LowSeverity))) + " as low</b>. " +
		"<br><br>These risks are distributed across <b>" + strconv.Itoa(len(parsedModel.InScopeTechnicalAssets())) + " in-scope technical assets</b>. ")
	text.WriteString("The following sub-chapters of this section describe each identified risk grouped by technical asset. ") // TODO more explanation text
	text.WriteString("The RAA value of a technical asset is the calculated \"Relative Attacker Attractiveness\" value in percent.")
	html.Write(5, text.String())
	text.Reset()
	r.currentChapterTitleBreadcrumb = title
	for _, technicalAsset := range sortedTechnicalAssetsByRiskSeverityAndTitle(parsedModel) {
		risksStr := parsedModel.GeneratedRisks(technicalAsset)
		countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(risksStr))
		suffix := strconv.Itoa(countStillAtRisk) + " / " + strconv.Itoa(len(risksStr)) + " Risk"
		if len(risksStr) != 1 {
			suffix += "s"
		}
		if technicalAsset.OutOfScope {
			r.pdfColorOutOfScope()
			suffix = "out-of-scope"
		} else {
			switch types.HighestSeverityStillAtRisk(risksStr) {
			case types.CriticalSeverity:
				colorCriticalRisk(r.pdf)
			case types.HighSeverity:
				colorHighRisk(r.pdf)
			case types.ElevatedSeverity:
				colorElevatedRisk(r.pdf)
			case types.MediumSeverity:
				colorMediumRisk(r.pdf)
			case types.LowSeverity:
				colorLowRisk(r.pdf)
			default:
				r.pdfColorBlack()
			}
			if len(types.ReduceToOnlyStillAtRisk(risksStr)) == 0 {
				r.pdfColorBlack()
			}
		}

		// asset title
		title := technicalAsset.Title + ": " + suffix
		r.addHeadline(uni(title), true)
		r.pdfColorBlack()
		r.defineLinkTarget("{" + technicalAsset.Id + "}")
		r.currentChapterTitleBreadcrumb = title

		// asset description
		html := r.pdf.HTMLBasicNew()
		var text strings.Builder
		text.WriteString("<b>Description</b><br><br>")
		text.WriteString(uni(technicalAsset.Description))
		html.Write(5, text.String())
		text.Reset()
		r.pdf.SetTextColor(0, 0, 0)

		// and more metadata of asset in tabular view
		r.pdf.Ln(-1)
		r.pdf.Ln(-1)
		r.pdf.Ln(-1)
		if r.pdf.GetY() > 260 { // 260 only for major titles (to avoid "Schusterjungen"), for the rest attributes 270
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdf.SetFont("Helvetica", "B", fontSizeBody)
		r.pdfColorBlack()
		r.pdf.CellFormat(190, 6, "Identified Risks of Asset", "0", 0, "", false, 0, "")
		r.pdfColorGray()
		oldLeft, _, _, _ := r.pdf.GetMargins()
		if len(risksStr) > 0 {
			r.pdf.SetFont("Helvetica", "", fontSizeSmall)
			html.Write(5, "Risk finding paragraphs are clickable and link to the corresponding chapter.")
			r.pdf.SetFont("Helvetica", "", fontSizeBody)
			r.pdf.SetLeftMargin(15)
			/*
				r.pdf.Ln(-1)
				r.pdf.Ln(-1)
				r.pdfColorGray()
				r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(185, 6, strconv.Itoa(len(risksStr))+" risksStr in total were identified", "0", 0, "", false, 0, "")
			*/
			headlineCriticalWritten, headlineHighWritten, headlineElevatedWritten, headlineMediumWritten, headlineLowWritten := false, false, false, false, false
			r.pdf.Ln(-1)
			for _, risk := range risksStr {
				text.WriteString("<br>")
				html.Write(5, text.String())
				text.Reset()
				if r.pdf.GetY() > 250 { // 250 only for major titles (to avoid "Schusterjungen"), for the rest attributes 270
					r.pageBreak()
					r.pdf.SetY(36)
				}
				switch risk.Severity {
				case types.CriticalSeverity:
					colorCriticalRisk(r.pdf)
					if !headlineCriticalWritten {
						r.pdf.SetFont("Helvetica", "", fontSizeBody)
						r.pdf.SetLeftMargin(oldLeft + 3)
						html.Write(5, "<br><b><i>Critical Risk Severity</i></b><br><br>")
						headlineCriticalWritten = true
					}
				case types.HighSeverity:
					colorHighRisk(r.pdf)
					if !headlineHighWritten {
						r.pdf.SetFont("Helvetica", "", fontSizeBody)
						r.pdf.SetLeftMargin(oldLeft + 3)
						html.Write(5, "<br><b><i>High Risk Severity</i></b><br><br>")
						headlineHighWritten = true
					}
				case types.ElevatedSeverity:
					colorElevatedRisk(r.pdf)
					if !headlineElevatedWritten {
						r.pdf.SetFont("Helvetica", "", fontSizeBody)
						r.pdf.SetLeftMargin(oldLeft + 3)
						html.Write(5, "<br><b><i>Elevated Risk Severity</i></b><br><br>")
						headlineElevatedWritten = true
					}
				case types.MediumSeverity:
					colorMediumRisk(r.pdf)
					if !headlineMediumWritten {
						r.pdf.SetFont("Helvetica", "", fontSizeBody)
						r.pdf.SetLeftMargin(oldLeft + 3)
						html.Write(5, "<br><b><i>Medium Risk Severity</i></b><br><br>")
						headlineMediumWritten = true
					}
				case types.LowSeverity:
					colorLowRisk(r.pdf)
					if !headlineLowWritten {
						r.pdf.SetFont("Helvetica", "", fontSizeBody)
						r.pdf.SetLeftMargin(oldLeft + 3)
						html.Write(5, "<br><b><i>Low Risk Severity</i></b><br><br>")
						headlineLowWritten = true
					}
				default:
					r.pdfColorBlack()
				}
				if !risk.RiskStatus.IsStillAtRisk() {
					r.pdfColorBlack()
				}
				posY := r.pdf.GetY()
				r.pdf.SetLeftMargin(oldLeft + 10)
				r.pdf.SetFont("Helvetica", "", fontSizeBody)
				text.WriteString(uni(risk.Title) + ": Exploitation likelihood is <i>" + risk.ExploitationLikelihood.Title() + "</i> with <i>" + risk.ExploitationImpact.Title() + "</i> impact.")
				text.WriteString("<br>")
				html.Write(5, text.String())
				text.Reset()

				r.pdf.SetFont("Helvetica", "", fontSizeVerySmall)
				r.pdfColorGray()
				r.pdf.MultiCell(215, 5, uni(risk.SyntheticId), "0", "0", false)
				r.pdf.Link(20, posY, 180, r.pdf.GetY()-posY, r.tocLinkIdByAssetId[risk.CategoryId])
				r.pdf.SetFont("Helvetica", "", fontSizeBody)
				r.writeRiskTrackingStatus(parsedModel, risk)
				r.pdf.SetLeftMargin(oldLeft)
			}
		} else {
			r.pdf.Ln(-1)
			r.pdf.Ln(-1)
			r.pdfColorGray()
			r.pdf.SetFont("Helvetica", "", fontSizeBody)
			r.pdf.SetLeftMargin(15)
			text := "No risksStr were identified."
			if technicalAsset.OutOfScope {
				text = "Asset was defined as out-of-scope."
			}
			html.Write(5, text)
			r.pdf.Ln(-1)
		}
		r.pdf.SetLeftMargin(oldLeft)

		r.pdf.Ln(-1)
		r.pdf.Ln(4)
		if r.pdf.GetY() > 260 { // 260 only for major titles (to avoid "Schusterjungen"), for the rest attributes 270
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorBlack()
		r.pdf.SetFont("Helvetica", "B", fontSizeBody)
		r.pdf.CellFormat(190, 6, "Asset Information", "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "", fontSizeBody)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "ID:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, technicalAsset.Id, "0", "0", false)
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Type:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, technicalAsset.Type.String(), "0", "0", false)
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Usage:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, technicalAsset.Usage.String(), "0", "0", false)
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "RAA:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		textRAA := fmt.Sprintf("%.0f", technicalAsset.RAA) + " %"
		if technicalAsset.OutOfScope {
			r.pdfColorGray()
			textRAA = "out-of-scope"
		}
		r.pdf.MultiCell(145, 6, textRAA, "0", "0", false)
		r.pdfColorBlack()
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Size:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, technicalAsset.Size.String(), "0", "0", false)
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Technology:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, technicalAsset.Technologies.String(), "0", "0", false)
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Tags:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		tagsUsedText := ""
		sorted := technicalAsset.Tags
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
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Internet:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, strconv.FormatBool(technicalAsset.Internet), "0", "0", false)
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Machine:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, technicalAsset.Machine.String(), "0", "0", false)
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Encryption:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, technicalAsset.Encryption.String(), "0", "0", false)
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Multi-Tenant:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, strconv.FormatBool(technicalAsset.MultiTenant), "0", "0", false)
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Redundant:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, strconv.FormatBool(technicalAsset.Redundant), "0", "0", false)
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Custom-Developed:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, strconv.FormatBool(technicalAsset.CustomDevelopedParts), "0", "0", false)
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Client by Human:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, strconv.FormatBool(technicalAsset.UsedAsClientByHuman), "0", "0", false)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Data Processed:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		dataAssetsProcessedText := ""
		for _, dataAsset := range parsedModel.DataAssetsProcessedSorted(technicalAsset) {
			if len(dataAssetsProcessedText) > 0 {
				dataAssetsProcessedText += ", "
			}
			dataAssetsProcessedText += dataAsset.Title
		}
		if len(dataAssetsProcessedText) == 0 {
			r.pdfColorGray()
			dataAssetsProcessedText = "none"
		}
		r.pdf.MultiCell(145, 6, uni(dataAssetsProcessedText), "0", "0", false)

		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Data Stored:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		dataAssetsStoredText := ""
		for _, dataAsset := range parsedModel.DataAssetsStoredSorted(technicalAsset) {
			if len(dataAssetsStoredText) > 0 {
				dataAssetsStoredText += ", "
			}
			dataAssetsStoredText += dataAsset.Title
		}
		if len(dataAssetsStoredText) == 0 {
			r.pdfColorGray()
			dataAssetsStoredText = "none"
		}
		r.pdf.MultiCell(145, 6, uni(dataAssetsStoredText), "0", "0", false)

		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Formats Accepted:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		formatsAcceptedText := ""
		for _, formatAccepted := range technicalAsset.DataFormatsAcceptedSorted() {
			if len(formatsAcceptedText) > 0 {
				formatsAcceptedText += ", "
			}
			formatsAcceptedText += formatAccepted.Title()
		}
		if len(formatsAcceptedText) == 0 {
			r.pdfColorGray()
			formatsAcceptedText = "none of the special data formats accepted"
		}
		r.pdf.MultiCell(145, 6, formatsAcceptedText, "0", "0", false)

		r.pdf.Ln(-1)
		r.pdf.Ln(4)
		if r.pdf.GetY() > 260 { // 260 only for major titles (to avoid "Schusterjungen"), for the rest attributes 270
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorBlack()
		r.pdf.SetFont("Helvetica", "B", fontSizeBody)
		r.pdf.CellFormat(190, 6, "Asset Rating", "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "", fontSizeBody)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Owner:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, uni(technicalAsset.Owner), "0", "0", false)
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Confidentiality:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.CellFormat(40, 6, technicalAsset.Confidentiality.String(), "0", 0, "", false, 0, "")
		r.pdfColorGray()
		r.pdf.CellFormat(115, 6, technicalAsset.Confidentiality.RatingStringInScale(), "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.Ln(-1)
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Integrity:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.CellFormat(40, 6, technicalAsset.Integrity.String(), "0", 0, "", false, 0, "")
		r.pdfColorGray()
		r.pdf.CellFormat(115, 6, technicalAsset.Integrity.RatingStringInScale(), "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.Ln(-1)
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Availability:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.CellFormat(40, 6, technicalAsset.Availability.String(), "0", 0, "", false, 0, "")
		r.pdfColorGray()
		r.pdf.CellFormat(115, 6, technicalAsset.Availability.RatingStringInScale(), "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.Ln(-1)
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "CIA-Justification:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, uni(technicalAsset.JustificationCiaRating), "0", "0", false)

		if technicalAsset.OutOfScope {
			r.pdf.Ln(-1)
			r.pdf.Ln(4)
			if r.pdf.GetY() > 270 {
				r.pageBreak()
				r.pdf.SetY(36)
			}
			r.pdfColorBlack()
			r.pdf.SetFont("Helvetica", "B", fontSizeBody)
			r.pdf.CellFormat(190, 6, "Asset Out-of-Scope Justification", "0", 0, "", false, 0, "")
			r.pdf.Ln(-1)
			r.pdf.Ln(-1)
			r.pdf.SetFont("Helvetica", "", fontSizeBody)
			r.pdf.MultiCell(190, 6, uni(technicalAsset.JustificationOutOfScope), "0", "0", false)
			r.pdf.Ln(-1)
		}
		r.pdf.Ln(-1)

		if len(technicalAsset.CommunicationLinks) > 0 {
			r.pdf.Ln(-1)
			if r.pdf.GetY() > 260 { // 260 only for major titles (to avoid "Schusterjungen"), for the rest attributes 270
				r.pageBreak()
				r.pdf.SetY(36)
			}
			r.pdfColorBlack()
			r.pdf.SetFont("Helvetica", "B", fontSizeBody)
			r.pdf.CellFormat(190, 6, "Outgoing Communication Links: "+strconv.Itoa(len(technicalAsset.CommunicationLinks)), "0", 0, "", false, 0, "")
			r.pdf.SetFont("Helvetica", "", fontSizeSmall)
			r.pdfColorGray()
			html.Write(5, "Target technical asset names are clickable and link to the corresponding chapter.")
			r.pdf.SetFont("Helvetica", "", fontSizeBody)
			r.pdf.Ln(-1)
			r.pdf.Ln(-1)
			r.pdf.SetFont("Helvetica", "", fontSizeBody)
			for _, outgoingCommLink := range technicalAsset.CommunicationLinksSorted() {
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorBlack()
				r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(185, 6, uni(outgoingCommLink.Title)+" (outgoing)", "0", 0, "", false, 0, "")
				r.pdf.Ln(-1)
				r.pdfColorGray()
				r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
				r.pdf.MultiCell(185, 6, uni(outgoingCommLink.Description), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdf.Ln(-1)
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Target:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(125, 6, uni(parsedModel.TechnicalAssets[outgoingCommLink.TargetId].Title), "0", "0", false)
				r.pdf.Link(60, r.pdf.GetY()-5, 70, 5, r.tocLinkIdByAssetId[outgoingCommLink.TargetId])
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Protocol:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, outgoingCommLink.Protocol.String(), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Encrypted:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, strconv.FormatBool(outgoingCommLink.Protocol.IsEncrypted()), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Authentication:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, outgoingCommLink.Authentication.String(), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Authorization:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, outgoingCommLink.Authorization.String(), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Read-Only:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, strconv.FormatBool(outgoingCommLink.Readonly), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Usage:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, outgoingCommLink.Usage.String(), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Tags:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				tagsUsedText := ""
				sorted := outgoingCommLink.Tags
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
				r.pdf.MultiCell(140, 6, uni(tagsUsedText), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "VPN:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, strconv.FormatBool(outgoingCommLink.VPN), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "IP-Filtered:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, strconv.FormatBool(outgoingCommLink.IpFiltered), "0", "0", false)
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Data Sent:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				dataAssetsSentText := ""
				for _, dataAsset := range parsedModel.DataAssetsSentSorted(outgoingCommLink) {
					if len(dataAssetsSentText) > 0 {
						dataAssetsSentText += ", "
					}
					dataAssetsSentText += dataAsset.Title
				}
				if len(dataAssetsSentText) == 0 {
					r.pdfColorGray()
					dataAssetsSentText = "none"
				}
				r.pdf.MultiCell(140, 6, uni(dataAssetsSentText), "0", "0", false)
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Data Received:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				dataAssetsReceivedText := ""
				for _, dataAsset := range parsedModel.DataAssetsReceivedSorted(outgoingCommLink) {
					if len(dataAssetsReceivedText) > 0 {
						dataAssetsReceivedText += ", "
					}
					dataAssetsReceivedText += dataAsset.Title
				}
				if len(dataAssetsReceivedText) == 0 {
					r.pdfColorGray()
					dataAssetsReceivedText = "none"
				}
				r.pdf.MultiCell(140, 6, uni(dataAssetsReceivedText), "0", "0", false)
				r.pdf.Ln(-1)
			}
		}

		incomingCommLinks := parsedModel.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		if len(incomingCommLinks) > 0 {
			r.pdf.Ln(-1)
			if r.pdf.GetY() > 260 { // 260 only for major titles (to avoid "Schusterjungen"), for the rest attributes 270
				r.pageBreak()
				r.pdf.SetY(36)
			}
			r.pdfColorBlack()
			r.pdf.SetFont("Helvetica", "B", fontSizeBody)
			r.pdf.CellFormat(190, 6, "Incoming Communication Links: "+strconv.Itoa(len(incomingCommLinks)), "0", 0, "", false, 0, "")
			r.pdf.SetFont("Helvetica", "", fontSizeSmall)
			r.pdfColorGray()
			html.Write(5, "Source technical asset names are clickable and link to the corresponding chapter.")
			r.pdf.SetFont("Helvetica", "", fontSizeBody)
			r.pdf.Ln(-1)
			r.pdf.Ln(-1)
			r.pdf.SetFont("Helvetica", "", fontSizeBody)
			for _, incomingCommLink := range incomingCommLinks {
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorBlack()
				r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(185, 6, uni(incomingCommLink.Title)+" (incoming)", "0", 0, "", false, 0, "")
				r.pdf.Ln(-1)
				r.pdfColorGray()
				r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
				r.pdf.MultiCell(185, 6, uni(incomingCommLink.Description), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdf.Ln(-1)
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Source:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, uni(parsedModel.TechnicalAssets[incomingCommLink.SourceId].Title), "0", "0", false)
				r.pdf.Link(60, r.pdf.GetY()-5, 70, 5, r.tocLinkIdByAssetId[incomingCommLink.SourceId])
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Protocol:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, incomingCommLink.Protocol.String(), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Encrypted:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, strconv.FormatBool(incomingCommLink.Protocol.IsEncrypted()), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Authentication:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, incomingCommLink.Authentication.String(), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Authorization:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, incomingCommLink.Authorization.String(), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Read-Only:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, strconv.FormatBool(incomingCommLink.Readonly), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Usage:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, incomingCommLink.Usage.String(), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Tags:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				tagsUsedText := ""
				sorted := incomingCommLink.Tags
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
				r.pdf.MultiCell(140, 6, uni(tagsUsedText), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "VPN:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, strconv.FormatBool(incomingCommLink.VPN), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "IP-Filtered:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, strconv.FormatBool(incomingCommLink.IpFiltered), "0", "0", false)
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Data Received:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				dataAssetsSentText := ""
				// yep, here we reverse the sent/received direction, as it's the incoming stuff
				for _, dataAsset := range parsedModel.DataAssetsSentSorted(incomingCommLink) {
					if len(dataAssetsSentText) > 0 {
						dataAssetsSentText += ", "
					}
					dataAssetsSentText += dataAsset.Title
				}
				if len(dataAssetsSentText) == 0 {
					r.pdfColorGray()
					dataAssetsSentText = "none"
				}
				r.pdf.MultiCell(140, 6, uni(dataAssetsSentText), "0", "0", false)
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Data Sent:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				dataAssetsReceivedText := ""
				// yep, here we reverse the sent/received direction, as it's the incoming stuff
				for _, dataAsset := range parsedModel.DataAssetsReceivedSorted(incomingCommLink) {
					if len(dataAssetsReceivedText) > 0 {
						dataAssetsReceivedText += ", "
					}
					dataAssetsReceivedText += dataAsset.Title
				}
				if len(dataAssetsReceivedText) == 0 {
					r.pdfColorGray()
					dataAssetsReceivedText = "none"
				}
				r.pdf.MultiCell(140, 6, uni(dataAssetsReceivedText), "0", "0", false)
				r.pdf.Ln(-1)
			}
		}
	}
}
