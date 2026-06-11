package report

import (
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/threagile/threagile/pkg/types"
)

func (r *pdfReporter) addCategories(parsedModel *types.Model, riskCategories []*types.RiskCategory, severity types.RiskSeverity, bothInitialAndRemainingRisks bool, initialRisks bool, describeImpact bool, describeDescription bool) {
	html := r.pdf.HTMLBasicNew()
	var strBuilder strings.Builder
	sort.Sort(types.ByRiskCategoryTitleSort(riskCategories))
	for _, riskCategory := range riskCategories {
		risksStr := parsedModel.GeneratedRisksByCategory[riskCategory.ID]
		if !initialRisks {
			risksStr = types.ReduceToOnlyStillAtRisk(risksStr)
		}
		if len(risksStr) == 0 {
			continue
		}
		if r.pdf.GetY() > 250 {
			r.pageBreak()
			r.pdf.SetY(36)
		} else {
			strBuilder.WriteString("<br><br>")
		}
		var prefix string
		switch severity {
		case types.CriticalSeverity:
			colorCriticalRisk(r.pdf)
			prefix = "Critical: "
		case types.HighSeverity:
			colorHighRisk(r.pdf)
			prefix = "High: "
		case types.ElevatedSeverity:
			colorElevatedRisk(r.pdf)
			prefix = "Elevated: "
		case types.MediumSeverity:
			colorMediumRisk(r.pdf)
			prefix = "Medium: "
		case types.LowSeverity:
			colorLowRisk(r.pdf)
			prefix = "Low: "
		default:
			r.pdfColorBlack()
			prefix = ""
		}
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
		}
		if len(types.ReduceToOnlyStillAtRisk(risksStr)) == 0 {
			r.pdfColorBlack()
		}
		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		posY := r.pdf.GetY()
		strBuilder.WriteString(prefix)
		strBuilder.WriteString("<b>")
		strBuilder.WriteString(riskCategory.Title)
		strBuilder.WriteString("</b>: ")
		count := len(risksStr)
		initialStr := "Initial"
		if !initialRisks {
			initialStr = "Remaining"
		}
		remainingRisks := types.ReduceToOnlyStillAtRisk(risksStr)
		suffix := strconv.Itoa(count) + " " + initialStr + " Risk"
		if bothInitialAndRemainingRisks {
			suffix = strconv.Itoa(len(remainingRisks)) + " / " + strconv.Itoa(count) + " Risk"
		}
		if count != 1 {
			suffix += "s"
		}
		suffix += " - Exploitation likelihood is <i>"
		if initialRisks {
			suffix += highestExploitationLikelihood(risksStr).Title() + "</i> with <i>" + highestExploitationImpact(risksStr).Title() + "</i> impact."
		} else {
			suffix += highestExploitationLikelihood(remainingRisks).Title() + "</i> with <i>" + highestExploitationImpact(remainingRisks).Title() + "</i> impact."
		}
		strBuilder.WriteString(suffix + "<br>")
		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		r.pdf.SetTextColor(0, 0, 0)
		if describeImpact {
			strBuilder.WriteString(firstParagraph(riskCategory.Impact))
		} else if describeDescription {
			strBuilder.WriteString(firstParagraph(riskCategory.Description))
		} else {
			strBuilder.WriteString(firstParagraph(riskCategory.Mitigation))
		}
		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		r.pdf.Link(9, posY, 190, r.pdf.GetY()-posY+4, r.tocLinkIdByAssetId[riskCategory.ID])
	}
}

func highestExploitationLikelihood(risks []*types.Risk) types.RiskExploitationLikelihood {
	result := types.Unlikely
	for _, risk := range risks {
		if risk.ExploitationLikelihood > result {
			result = risk.ExploitationLikelihood
		}
	}
	return result
}

func highestExploitationImpact(risks []*types.Risk) types.RiskExploitationImpact {
	result := types.LowImpact
	for _, risk := range risks {
		if risk.ExploitationImpact > result {
			result = risk.ExploitationImpact
		}
	}
	return result
}

func firstParagraph(text string) string {
	firstParagraphRegEx := regexp.MustCompile(`(.*?)((<br>)|(<p>))`)
	match := firstParagraphRegEx.FindStringSubmatch(text)
	if len(match) == 0 {
		return text
	}
	return match[1]
}

func getRiskCategories(parsedModel *types.Model, categoryIDs []string) []*types.RiskCategory {
	categoryMap := make(map[string]*types.RiskCategory)
	for _, categoryId := range categoryIDs {
		category := parsedModel.GetRiskCategory(categoryId)
		if category != nil {
			categoryMap[categoryId] = category
		}
	}

	categories := make([]*types.RiskCategory, 0)
	for categoryId := range categoryMap {
		categories = append(categories, categoryMap[categoryId])
	}

	return categories
}

func reduceToSeverityRisk(risksByCategory map[string][]*types.Risk, initialRisks bool, severity types.RiskSeverity) []string {
	categories := make(map[string]struct{}) // Go's trick of unique elements is a map
	for categoryId, risks := range risksByCategory {
		for _, risk := range risks {
			if !initialRisks && !risk.RiskStatus.IsStillAtRisk() {
				continue
			}
			if risk.Severity == severity {
				categories[categoryId] = struct{}{}
			}
		}
	}
	// return as slice (of now unique values)
	return keysAsSlice(categories)
}

func reduceToOnlyStillAtRisk(risksByCategory map[string][]*types.Risk) []string {
	categories := make(map[string]struct{}) // Go's trick of unique elements is a map
	for categoryId, risks := range risksByCategory {
		for _, risk := range risks {
			if !risk.RiskStatus.IsStillAtRisk() {
				continue
			}
			categories[categoryId] = struct{}{}
		}
	}
	// return as slice (of now unique values)
	return keysAsSlice(categories)
}

func keysAsSlice(categories map[string]struct{}) []string {
	result := make([]string, 0, len(categories))
	for k := range categories {
		result = append(result, k)
	}
	return result
}

func (r *pdfReporter) createRiskCategories(parsedModel *types.Model) {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	// category title
	title := "Identified Risks by Vulnerability category"
	r.pdfColorBlack()
	r.addHeadline(title, false)
	r.defineLinkTarget("{intro-risks-by-vulnerability-category}")
	html := r.pdf.HTMLBasicNew()
	var text strings.Builder
	text.WriteString("In total <b>" + strconv.Itoa(totalRiskCount(parsedModel)) + " potential risks</b> have been identified during the threat modeling process " +
		"of which " +
		"<b>" + strconv.Itoa(len(filteredBySeverity(parsedModel, types.CriticalSeverity))) + " are rated as critical</b>, " +
		"<b>" + strconv.Itoa(len(filteredBySeverity(parsedModel, types.HighSeverity))) + " as high</b>, " +
		"<b>" + strconv.Itoa(len(filteredBySeverity(parsedModel, types.ElevatedSeverity))) + " as elevated</b>, " +
		"<b>" + strconv.Itoa(len(filteredBySeverity(parsedModel, types.MediumSeverity))) + " as medium</b>, " +
		"and <b>" + strconv.Itoa(len(filteredBySeverity(parsedModel, types.LowSeverity))) + " as low</b>. " +
		"<br><br>These risks are distributed across <b>" + strconv.Itoa(len(parsedModel.GeneratedRisksByCategory)) + " vulnerability categories</b>. ")
	text.WriteString("The following sub-chapters of this section describe each identified risk category.") // TODO more explanation text
	html.Write(5, text.String())
	text.Reset()
	r.currentChapterTitleBreadcrumb = title
	for _, category := range parsedModel.SortedRiskCategories() {
		risksStr := parsedModel.SortedRisksOfCategory(category)

		// category color
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

		// category title
		countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(risksStr))
		suffix := strconv.Itoa(countStillAtRisk) + " / " + strconv.Itoa(len(risksStr)) + " Risk"
		if len(risksStr) != 1 {
			suffix += "s"
		}
		title := category.Title + ": " + suffix
		r.addHeadline(uni(title), true)
		r.pdfColorBlack()
		r.defineLinkTarget("{" + category.ID + "}")
		r.currentChapterTitleBreadcrumb = title

		// category details
		var text strings.Builder
		cweLink := "n/a"
		if category.CWE > 0 {
			cweLink = "<a href=\"https://cwe.mitre.org/data/definitions/" + strconv.Itoa(category.CWE) + ".html\">CWE " +
				strconv.Itoa(category.CWE) + "</a>"
		}
		text.WriteString("<b>Description</b> (" + category.STRIDE.Title() + "): " + cweLink + "<br><br>")
		text.WriteString(category.Description)
		text.WriteString("<br><br><br><b>Impact</b><br><br>")
		text.WriteString(category.Impact)
		text.WriteString("<br><br><br><b>Detection Logic</b><br><br>")
		text.WriteString(category.DetectionLogic)
		text.WriteString("<br><br><br><b>Risk Rating</b><br><br>")
		text.WriteString(category.RiskAssessment)
		html.Write(5, text.String())
		text.Reset()
		colorRiskStatusFalsePositive(r.pdf)
		text.WriteString("<br><br><br><b>False Positives</b><br><br>")
		text.WriteString(category.FalsePositives)
		html.Write(5, text.String())
		text.Reset()
		colorRiskStatusMitigated(r.pdf)
		text.WriteString("<br><br><br><b>Mitigation</b> (" + category.Function.Title() + "): " + category.Action + "<br><br>")
		text.WriteString(category.Mitigation)

		asvsChapter := category.ASVS
		if len(asvsChapter) == 0 {
			text.WriteString("<br><br>ASVS Chapter: n/a")
		} else {
			text.WriteString("<br><br>ASVS Chapter: <a href=\"https://owasp.org/www-project-application-security-verification-standard/\">" + asvsChapter + "</a>")
		}

		cheatSheetLink := category.CheatSheet
		if len(cheatSheetLink) == 0 {
			cheatSheetLink = "n/a"
		} else {
			lastLinkParts := strings.Split(cheatSheetLink, "/")
			linkText := lastLinkParts[len(lastLinkParts)-1]
			if strings.HasSuffix(linkText, ".html") || strings.HasSuffix(linkText, ".htm") {
				var extension = filepath.Ext(linkText)
				linkText = linkText[0 : len(linkText)-len(extension)]
			}
			cheatSheetLink = "<a href=\"" + cheatSheetLink + "\">" + linkText + "</a>"
		}
		text.WriteString("<br>Cheat Sheet: " + cheatSheetLink)

		text.WriteString("<br><br><br><b>Check</b><br><br>")
		text.WriteString(category.Check)

		html.Write(5, text.String())
		text.Reset()
		r.pdf.SetTextColor(0, 0, 0)

		// risk details
		r.pageBreak()
		r.pdf.SetY(36)
		text.WriteString("<b>Risk Findings</b><br><br>")
		times := strconv.Itoa(len(risksStr)) + " time"
		if len(risksStr) > 1 {
			times += "s"
		}
		text.WriteString("The risk <b>" + category.Title + "</b> was found <b>" + times + "</b> in the analyzed architecture to be " +
			"potentially possible. Each spot should be checked individually by reviewing the implementation whether all " +
			"controls have been applied properly in order to mitigate each risk.<br>")
		html.Write(5, text.String())
		text.Reset()
		r.pdf.SetFont("Helvetica", "", fontSizeSmall)
		r.pdfColorGray()
		html.Write(5, "Risk finding paragraphs are clickable and link to the corresponding chapter.<br>")
		r.pdf.SetFont("Helvetica", "", fontSizeBody)
		oldLeft, _, _, _ := r.pdf.GetMargins()
		headlineCriticalWritten, headlineHighWritten, headlineElevatedWritten, headlineMediumWritten, headlineLowWritten := false, false, false, false, false
		for _, risk := range risksStr {
			text.WriteString("<br>")
			html.Write(5, text.String())
			text.Reset()
			if r.pdf.GetY() > 250 {
				r.pageBreak()
				r.pdf.SetY(36)
			}
			switch risk.Severity {
			case types.CriticalSeverity:
				colorCriticalRisk(r.pdf)
				if !headlineCriticalWritten {
					r.pdf.SetFont("Helvetica", "", fontSizeBody)
					r.pdf.SetLeftMargin(oldLeft)
					text.WriteString("<br><b><i>Critical Risk Severity</i></b><br><br>")
					html.Write(5, text.String())
					text.Reset()
					headlineCriticalWritten = true
				}
			case types.HighSeverity:
				colorHighRisk(r.pdf)
				if !headlineHighWritten {
					r.pdf.SetFont("Helvetica", "", fontSizeBody)
					r.pdf.SetLeftMargin(oldLeft)
					text.WriteString("<br><b><i>High Risk Severity</i></b><br><br>")
					html.Write(5, text.String())
					text.Reset()
					headlineHighWritten = true
				}
			case types.ElevatedSeverity:
				colorElevatedRisk(r.pdf)
				if !headlineElevatedWritten {
					r.pdf.SetFont("Helvetica", "", fontSizeBody)
					r.pdf.SetLeftMargin(oldLeft)
					text.WriteString("<br><b><i>Elevated Risk Severity</i></b><br><br>")
					html.Write(5, text.String())
					text.Reset()
					headlineElevatedWritten = true
				}
			case types.MediumSeverity:
				colorMediumRisk(r.pdf)
				if !headlineMediumWritten {
					r.pdf.SetFont("Helvetica", "", fontSizeBody)
					r.pdf.SetLeftMargin(oldLeft)
					text.WriteString("<br><b><i>Medium Risk Severity</i></b><br><br>")
					html.Write(5, text.String())
					text.Reset()
					headlineMediumWritten = true
				}
			case types.LowSeverity:
				colorLowRisk(r.pdf)
				if !headlineLowWritten {
					r.pdf.SetFont("Helvetica", "", fontSizeBody)
					r.pdf.SetLeftMargin(oldLeft)
					text.WriteString("<br><b><i>Low Risk Severity</i></b><br><br>")
					html.Write(5, text.String())
					text.Reset()
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
			r.pdfColorGray()
			r.pdf.SetFont("Helvetica", "", fontSizeVerySmall)
			r.pdf.MultiCell(215, 5, uni(risk.SyntheticId), "0", "0", false)
			r.pdf.SetFont("Helvetica", "", fontSizeBody)
			if len(risk.MostRelevantSharedRuntimeId) > 0 {
				r.pdf.Link(20, posY, 180, r.pdf.GetY()-posY, r.tocLinkIdByAssetId[risk.MostRelevantSharedRuntimeId])
			} else if len(risk.MostRelevantTrustBoundaryId) > 0 {
				r.pdf.Link(20, posY, 180, r.pdf.GetY()-posY, r.tocLinkIdByAssetId[risk.MostRelevantTrustBoundaryId])
			} else if len(risk.MostRelevantTechnicalAssetId) > 0 {
				r.pdf.Link(20, posY, 180, r.pdf.GetY()-posY, r.tocLinkIdByAssetId[risk.MostRelevantTechnicalAssetId])
			}
			r.writeRiskTrackingStatus(parsedModel, risk)
			r.pdf.SetLeftMargin(oldLeft)
			html.Write(5, text.String())
			text.Reset()
		}
		r.pdf.SetLeftMargin(oldLeft)
	}
}

func (r *pdfReporter) writeRiskTrackingStatus(parsedModel *types.Model, risk *types.Risk) {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	tracking := parsedModel.GetRiskTrackingWithDefault(risk)
	r.pdfColorBlack()
	r.pdf.CellFormat(10, 6, "", "0", 0, "", false, 0, "")
	switch tracking.Status {
	case types.Unchecked:
		colorRiskStatusUnchecked(r.pdf)
	case types.InDiscussion:
		colorRiskStatusInDiscussion(r.pdf)
	case types.Accepted:
		colorRiskStatusAccepted(r.pdf)
	case types.InProgress:
		colorRiskStatusInProgress(r.pdf)
	case types.Mitigated:
		colorRiskStatusMitigated(r.pdf)
	case types.FalsePositive:
		colorRiskStatusFalsePositive(r.pdf)
	default:
		r.pdfColorBlack()
	}
	r.pdf.SetFont("Helvetica", "", fontSizeSmall)
	if tracking.Status == types.Unchecked {
		r.pdf.SetFont("Helvetica", "B", fontSizeSmall)
	}
	r.pdf.CellFormat(25, 4, tracking.Status.Title(), "0", 0, "B", false, 0, "")
	if tracking.Status != types.Unchecked {
		dateStr := tracking.Date.Format("2006-01-02")
		if dateStr == "0001-01-01" {
			dateStr = ""
		}
		justificationStr := tracking.Justification
		r.pdfColorGray()
		r.pdf.CellFormat(20, 4, dateStr, "0", 0, "B", false, 0, "")
		r.pdf.CellFormat(35, 4, uni(tracking.CheckedBy), "0", 0, "B", false, 0, "")
		r.pdf.CellFormat(35, 4, uni(tracking.Ticket), "0", 0, "B", false, 0, "")
		r.pdf.Ln(-1)
		r.pdfColorBlack()
		r.pdf.CellFormat(10, 4, "", "0", 0, "", false, 0, "")
		r.pdf.MultiCell(170, 4, uni(justificationStr), "0", "0", false)
		r.pdf.SetFont("Helvetica", "", fontSizeBody)
	} else {
		r.pdf.Ln(-1)
	}
	r.pdfColorBlack()
}
