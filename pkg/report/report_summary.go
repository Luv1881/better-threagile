package report

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/threagile/threagile/pkg/types"
	chart "github.com/wcharczuk/go-chart/v2"
)

func sortByTechnicalAssetRiskSeverityAndTitleStillAtRisk(assets []*types.TechnicalAsset, parsedModel *types.Model) {
	sort.Slice(assets, func(i, j int) bool {
		risksLeft := types.ReduceToOnlyStillAtRisk(parsedModel.GeneratedRisks(assets[i]))
		risksRight := types.ReduceToOnlyStillAtRisk(parsedModel.GeneratedRisks(assets[j]))
		highestSeverityLeft := types.HighestSeverityStillAtRisk(risksLeft)
		highestSeverityRight := types.HighestSeverityStillAtRisk(risksRight)
		var result bool
		if highestSeverityLeft == highestSeverityRight {
			if len(risksLeft) == 0 && len(risksRight) > 0 {
				return false
			} else if len(risksLeft) > 0 && len(risksRight) == 0 {
				return true
			} else {
				result = assets[i].Title < assets[j].Title
			}
		} else {
			result = highestSeverityLeft > highestSeverityRight
		}
		if assets[i].OutOfScope && assets[j].OutOfScope {
			result = assets[i].Title < assets[j].Title
		} else if assets[i].OutOfScope {
			result = false
		} else if assets[j].OutOfScope {
			result = true
		}
		return result
	})
}

func sortedDataAssetsByDataBreachProbabilityAndTitle(parsedModel *types.Model) []*types.DataAsset {
	assets := make([]*types.DataAsset, 0)
	for _, asset := range parsedModel.DataAssets {
		assets = append(assets, asset)
	}

	sortByDataAssetDataBreachProbabilityAndTitleStillAtRisk(parsedModel, assets)
	return assets
}

func sortByDataAssetDataBreachProbabilityAndTitleStillAtRisk(parsedModel *types.Model, assets []*types.DataAsset) {
	sort.Slice(assets, func(i, j int) bool {
		risksLeft := identifiedDataBreachProbabilityRisksStillAtRisk(parsedModel, assets[i])
		risksRight := identifiedDataBreachProbabilityRisksStillAtRisk(parsedModel, assets[j])
		highestDataBreachProbabilityLeft := identifiedDataBreachProbabilityStillAtRisk(parsedModel, assets[i])
		highestDataBreachProbabilityRight := identifiedDataBreachProbabilityStillAtRisk(parsedModel, assets[j])
		if highestDataBreachProbabilityLeft == highestDataBreachProbabilityRight {
			if len(risksLeft) == 0 && len(risksRight) > 0 {
				return false
			}
			if len(risksLeft) > 0 && len(risksRight) == 0 {
				return true
			}
			return assets[i].Title < assets[j].Title
		}
		return highestDataBreachProbabilityLeft > highestDataBreachProbabilityRight
	})
}

func (r *pdfReporter) createManagementSummary(parsedModel *types.Model, tempFolder string) error {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	r.pdf.SetTextColor(0, 0, 0)
	title := "Management Summary"
	r.addHeadline(title, false)
	r.defineLinkTarget("{management-summary}")
	r.currentChapterTitleBreadcrumb = title
	countCritical := len(filteredBySeverity(parsedModel, types.CriticalSeverity))
	countHigh := len(filteredBySeverity(parsedModel, types.HighSeverity))
	countElevated := len(filteredBySeverity(parsedModel, types.ElevatedSeverity))
	countMedium := len(filteredBySeverity(parsedModel, types.MediumSeverity))
	countLow := len(filteredBySeverity(parsedModel, types.LowSeverity))

	countStatusUnchecked := len(filteredByRiskStatus(parsedModel, types.Unchecked))
	countStatusInDiscussion := len(filteredByRiskStatus(parsedModel, types.InDiscussion))
	countStatusAccepted := len(filteredByRiskStatus(parsedModel, types.Accepted))
	countStatusInProgress := len(filteredByRiskStatus(parsedModel, types.InProgress))
	countStatusMitigated := len(filteredByRiskStatus(parsedModel, types.Mitigated))
	countStatusFalsePositive := len(filteredByRiskStatus(parsedModel, types.FalsePositive))

	html := r.pdf.HTMLBasicNew()
	html.Write(5, "Threagile toolkit was used to model the architecture of \""+uni(parsedModel.Title)+"\" "+
		"and derive risks by analyzing the components and data flows. The risks identified during this analysis are shown "+
		"in the following chapters. Identified risks during threat modeling do not necessarily mean that the "+
		"vulnerability associated with this risk actually exists: it is more to be seen as a list of potential risks and "+
		"threats, which should be individually reviewed and reduced by removing false positives. For the remaining risks it should "+
		"be checked in the design and implementation of \""+uni(parsedModel.Title)+"\" whether the mitigation advices "+
		"have been applied or not."+
		"<br><br>"+
		"Each risk finding references a chapter of the OWASP ASVS (Application Security Verification Standard) audit checklist. "+
		"The OWASP ASVS checklist should be considered as an inspiration by architects and developers to further harden "+
		"the application in a Defense-in-Depth approach. Additionally, for each risk finding a "+
		"link towards a matching OWASP Cheat Sheet or similar with technical details about how to implement a mitigation is given."+
		"<br><br>"+
		"In total <b>"+strconv.Itoa(totalRiskCount(parsedModel))+" initial risks</b> in <b>"+strconv.Itoa(len(parsedModel.GeneratedRisksByCategory))+" categories</b> have "+
		"been identified during the threat modeling process:<br><br>") // TODO plural singular stuff risk/s category/ies has/have

	r.pdf.SetFont("Helvetica", "B", fontSizeBody)

	r.pdf.CellFormat(17, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(60, 6, "", "0", 0, "", false, 0, "")
	colorRiskStatusUnchecked(r.pdf)
	r.pdf.CellFormat(23, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countStatusUnchecked), "0", 0, "R", false, 0, "")
	r.pdf.CellFormat(60, 6, "unchecked", "0", 0, "", false, 0, "")
	r.pdf.Ln(-1)

	colorCriticalRisk(r.pdf)
	r.pdf.CellFormat(17, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countCritical), "0", 0, "R", false, 0, "")
	r.pdf.CellFormat(60, 6, "critical risk", "0", 0, "", false, 0, "")
	colorRiskStatusInDiscussion(r.pdf)
	r.pdf.CellFormat(23, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countStatusInDiscussion), "0", 0, "R", false, 0, "")
	r.pdf.CellFormat(60, 6, "in discussion", "0", 0, "", false, 0, "")
	r.pdf.Ln(-1)

	colorHighRisk(r.pdf)
	r.pdf.CellFormat(17, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countHigh), "0", 0, "R", false, 0, "")
	r.pdf.CellFormat(60, 6, "high risk", "0", 0, "", false, 0, "")
	colorRiskStatusAccepted(r.pdf)
	r.pdf.CellFormat(23, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countStatusAccepted), "0", 0, "R", false, 0, "")
	r.pdf.CellFormat(60, 6, "accepted", "0", 0, "", false, 0, "")
	r.pdf.Ln(-1)

	colorElevatedRisk(r.pdf)
	r.pdf.CellFormat(17, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countElevated), "0", 0, "R", false, 0, "")
	r.pdf.CellFormat(60, 6, "elevated risk", "0", 0, "", false, 0, "")
	colorRiskStatusInProgress(r.pdf)
	r.pdf.CellFormat(23, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countStatusInProgress), "0", 0, "R", false, 0, "")
	r.pdf.CellFormat(60, 6, "in progress", "0", 0, "", false, 0, "")
	r.pdf.Ln(-1)

	colorMediumRisk(r.pdf)
	r.pdf.CellFormat(17, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countMedium), "0", 0, "R", false, 0, "")
	r.pdf.CellFormat(60, 6, "medium risk", "0", 0, "", false, 0, "")
	colorRiskStatusMitigated(r.pdf)
	r.pdf.CellFormat(23, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countStatusMitigated), "0", 0, "R", false, 0, "")
	r.pdf.SetFont("Helvetica", "BI", fontSizeBody)
	r.pdf.CellFormat(60, 6, "mitigated", "0", 0, "", false, 0, "")
	r.pdf.SetFont("Helvetica", "B", fontSizeBody)
	r.pdf.Ln(-1)

	colorLowRisk(r.pdf)
	r.pdf.CellFormat(17, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countLow), "0", 0, "R", false, 0, "")
	r.pdf.CellFormat(60, 6, "low risk", "0", 0, "", false, 0, "")
	colorRiskStatusFalsePositive(r.pdf)
	r.pdf.CellFormat(23, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countStatusFalsePositive), "0", 0, "R", false, 0, "")
	r.pdf.SetFont("Helvetica", "BI", fontSizeBody)
	r.pdf.CellFormat(60, 6, "false positive", "0", 0, "", false, 0, "")
	r.pdf.SetFont("Helvetica", "B", fontSizeBody)
	r.pdf.Ln(-1)

	r.pdf.SetFont("Helvetica", "", fontSizeBody)

	// pie chart: risk severity
	pieChartRiskSeverity := chart.PieChart{
		Width:  1500,
		Height: 1500,
		Values: []chart.Value{
			{Value: float64(countLow), //Label: strconv.Itoa(countLow) + " Low",
				Style: chart.Style{
					FillColor: makeColor(rgbHexColorLowRisk()).WithAlpha(98),
					//FontColor: makeColor(rgbHexColorLowRisk()),
					FontSize: 65}},
			{Value: float64(countMedium), //Label: strconv.Itoa(countMedium) + " Medium",
				Style: chart.Style{
					FillColor: makeColor(rgbHexColorMediumRisk()).WithAlpha(98),
					//FontColor: makeColor(rgbHexColorMediumRisk()),
					FontSize: 65}},
			{Value: float64(countElevated), //Label: strconv.Itoa(countElevated) + " Elevated",
				Style: chart.Style{
					FillColor: makeColor(rgbHexColorElevatedRisk()).WithAlpha(98),
					//FontColor: makeColor(rgbHexColorElevatedRisk()),
					FontSize: 65}},
			{Value: float64(countHigh), //Label: strconv.Itoa(countHigh) + " High",
				Style: chart.Style{
					FillColor: makeColor(rgbHexColorHighRisk()).WithAlpha(98),
					//FontColor: makeColor(rgbHexColorHighRisk()),
					FontSize: 65}},
			{Value: float64(countCritical), //Label: strconv.Itoa(countCritical) + " Critical",
				Style: chart.Style{
					FillColor: makeColor(rgbHexColorCriticalRisk()).WithAlpha(98),
					//FontColor: makeColor(rgbHexColorCriticalRisk()),
					FontSize: 65}},
		},
	}

	// pie chart: risk status
	pieChartRiskStatus := chart.PieChart{
		Width:  1500,
		Height: 1500,
		Values: []chart.Value{
			{Value: float64(countStatusFalsePositive), //Label: strconv.Itoa(countStatusFalsePositive) + " False Positive",
				Style: chart.Style{
					FillColor: makeColor(rgbHexColorRiskStatusFalsePositive()).WithAlpha(98),
					//FontColor: makeColor(rgbHexColorRiskStatusFalsePositive()),
					FontSize: 65}},
			{Value: float64(countStatusMitigated), //Label: strconv.Itoa(countStatusMitigated) + " Mitigated",
				Style: chart.Style{
					FillColor: makeColor(rgbHexColorRiskStatusMitigated()).WithAlpha(98),
					//FontColor: makeColor(rgbHexColorRiskStatusMitigated()),
					FontSize: 65}},
			{Value: float64(countStatusInProgress), //Label: strconv.Itoa(countStatusInProgress) + " InProgress",
				Style: chart.Style{
					FillColor: makeColor(rgbHexColorRiskStatusInProgress()).WithAlpha(98),
					//FontColor: makeColor(rgbHexColorRiskStatusInProgress()),
					FontSize: 65}},
			{Value: float64(countStatusAccepted), //Label: strconv.Itoa(countStatusAccepted) + " Accepted",
				Style: chart.Style{
					FillColor: makeColor(rgbHexColorRiskStatusAccepted()).WithAlpha(98),
					//FontColor: makeColor(rgbHexColorRiskStatusAccepted()),
					FontSize: 65}},
			{Value: float64(countStatusInDiscussion), //Label: strconv.Itoa(countStatusInDiscussion) + " InDiscussion",
				Style: chart.Style{
					FillColor: makeColor(rgbHexColorRiskStatusInDiscussion()).WithAlpha(98),
					//FontColor: makeColor(rgbHexColorRiskStatusInDiscussion()),
					FontSize: 65}},
			{Value: float64(countStatusUnchecked), //Label: strconv.Itoa(countStatusUnchecked) + " Unchecked",
				Style: chart.Style{
					FillColor: makeColor(RgbHexColorRiskStatusUnchecked()).WithAlpha(98),
					//FontColor: makeColor(RgbHexColorRiskStatusUnchecked()),
					FontSize: 65}},
		},
	}

	y := r.pdf.GetY() + 5
	err := r.embedPieChart(pieChartRiskSeverity, 15.0, y, tempFolder)
	if err != nil {
		return fmt.Errorf("unable to embed pie chart: %w", err)
	}

	err = r.embedPieChart(pieChartRiskStatus, 110.0, y, tempFolder)
	if err != nil {
		return fmt.Errorf("unable to embed pie chart: %w", err)
	}

	// individual management summary comment
	r.pdfColorBlack()
	if len(parsedModel.ManagementSummaryComment) > 0 {
		html.Write(5, "<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br>"+
			parsedModel.ManagementSummaryComment)
	}
	return nil
}

func (r *pdfReporter) createImpactInitialRisks(parsedModel *types.Model) {
	r.renderImpactAnalysis(parsedModel, true)
}

func (r *pdfReporter) createImpactRemainingRisks(parsedModel *types.Model) {
	r.renderImpactAnalysis(parsedModel, false)
}

func (r *pdfReporter) renderImpactAnalysis(parsedModel *types.Model, initialRisks bool) {
	r.pdf.SetTextColor(0, 0, 0)
	count, catCount := totalRiskCount(parsedModel), len(parsedModel.GeneratedRisksByCategory)
	if !initialRisks {
		count, catCount = len(filteredByStillAtRisk(parsedModel)), len(reduceToOnlyStillAtRisk(parsedModel.GeneratedRisksByCategoryWithCurrentStatus()))
	}
	riskStr, catStr := "Risks", "Categories"
	if count == 1 {
		riskStr = "Risk"
	}
	if catCount == 1 {
		catStr = "category"
	}
	if initialRisks {
		chapTitle := "Impact Analysis of " + strconv.Itoa(count) + " Initial " + riskStr + " in " + strconv.Itoa(catCount) + " " + catStr
		r.addHeadline(chapTitle, false)
		r.defineLinkTarget("{impact-analysis-initial-risks}")
		r.currentChapterTitleBreadcrumb = chapTitle
	} else {
		chapTitle := "Impact Analysis of " + strconv.Itoa(count) + " Remaining " + riskStr + " in " + strconv.Itoa(catCount) + " " + catStr
		r.addHeadline(chapTitle, false)
		r.defineLinkTarget("{impact-analysis-remaining-risks}")
		r.currentChapterTitleBreadcrumb = chapTitle
	}

	html := r.pdf.HTMLBasicNew()
	var strBuilder strings.Builder
	riskStr = "risks"
	if count == 1 {
		riskStr = "risk"
	}
	initialStr := "initial"
	if !initialRisks {
		initialStr = "remaining"
	}
	strBuilder.WriteString("The most prevalent impacts of the <b>" + strconv.Itoa(count) + " " +
		initialStr + " " + riskStr + "</b> (distributed over <b>" + strconv.Itoa(catCount) + " risk categories</b>) are " +
		"(taking the severity ratings into account and using the highest for each category):<br>")
	html.Write(5, strBuilder.String())
	strBuilder.Reset()
	r.pdf.SetFont("Helvetica", "", fontSizeSmall)
	r.pdfColorGray()
	html.Write(5, "Risk finding paragraphs are clickable and link to the corresponding chapter.")
	r.pdf.SetFont("Helvetica", "", fontSizeBody)

	r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(parsedModel.GeneratedRisksByCategory, initialRisks, types.CriticalSeverity)),
		types.CriticalSeverity, false, initialRisks, true, false)
	r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(parsedModel.GeneratedRisksByCategory, initialRisks, types.HighSeverity)),
		types.HighSeverity, false, initialRisks, true, false)
	r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(parsedModel.GeneratedRisksByCategory, initialRisks, types.ElevatedSeverity)),
		types.ElevatedSeverity, false, initialRisks, true, false)
	r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(parsedModel.GeneratedRisksByCategory, initialRisks, types.MediumSeverity)),
		types.MediumSeverity, false, initialRisks, true, false)
	r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(parsedModel.GeneratedRisksByCategory, initialRisks, types.LowSeverity)),
		types.LowSeverity, false, initialRisks, true, false)

	r.pdf.SetDrawColor(0, 0, 0)
	r.pdf.SetDashPattern([]float64{}, 0)
}

func (r *pdfReporter) createOutOfScopeAssets(parsedModel *types.Model) {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	r.pdf.SetTextColor(0, 0, 0)
	assets := "Assets"
	count := len(parsedModel.OutOfScopeTechnicalAssets())
	if count == 1 {
		assets = "Asset"
	}
	chapTitle := "Out-of-Scope Assets: " + strconv.Itoa(count) + " " + assets
	r.addHeadline(chapTitle, false)
	r.defineLinkTarget("{out-of-scope-assets}")
	r.currentChapterTitleBreadcrumb = chapTitle

	html := r.pdf.HTMLBasicNew()
	var strBuilder strings.Builder
	strBuilder.WriteString("This chapter lists all technical assets that have been defined as out-of-scope. " +
		"Each one should be checked in the model whether it should better be included in the " +
		"overall risk analysis:<br>")
	html.Write(5, strBuilder.String())
	strBuilder.Reset()
	r.pdf.SetFont("Helvetica", "", fontSizeSmall)
	r.pdfColorGray()
	html.Write(5, "Technical asset paragraphs are clickable and link to the corresponding chapter.")
	r.pdf.SetFont("Helvetica", "", fontSizeBody)

	outOfScopeAssetCount := 0
	for _, technicalAsset := range sortedTechnicalAssetsByRAAAndTitle(parsedModel) {
		if technicalAsset.OutOfScope {
			outOfScopeAssetCount++
			if r.pdf.GetY() > 250 {
				r.pageBreak()
				r.pdf.SetY(36)
			} else {
				strBuilder.WriteString("<br><br>")
			}
			html.Write(5, strBuilder.String())
			strBuilder.Reset()
			posY := r.pdf.GetY()
			r.pdfColorOutOfScope()
			strBuilder.WriteString("<b>")
			strBuilder.WriteString(uni(technicalAsset.Title))
			strBuilder.WriteString("</b>")
			strBuilder.WriteString(": out-of-scope")
			strBuilder.WriteString("<br>")
			html.Write(5, strBuilder.String())
			strBuilder.Reset()
			r.pdf.SetTextColor(0, 0, 0)
			strBuilder.WriteString(uni(technicalAsset.JustificationOutOfScope))
			html.Write(5, strBuilder.String())
			strBuilder.Reset()
			r.pdf.Link(9, posY, 190, r.pdf.GetY()-posY+4, r.tocLinkIdByAssetId[technicalAsset.Id])
		}
	}

	if outOfScopeAssetCount == 0 {
		r.pdfColorGray()
		html.Write(5, "<br><br>No technical assets have been defined as out-of-scope.")
	}

	r.pdf.SetDrawColor(0, 0, 0)
	r.pdf.SetDashPattern([]float64{}, 0)
}

func (r *pdfReporter) createModelFailures(parsedModel *types.Model) {
	r.pdf.SetTextColor(0, 0, 0)
	modelFailures := flattenRiskSlice(filterByModelFailures(parsedModel, parsedModel.GeneratedRisksByCategory))
	risksStr := "Risks"
	count := len(modelFailures)
	if count == 1 {
		risksStr = "Risk"
	}
	countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(modelFailures))
	if countStillAtRisk > 0 {
		colorModelFailure(r.pdf)
	}
	chapTitle := "Potential Model Failures: " + strconv.Itoa(countStillAtRisk) + " / " + strconv.Itoa(count) + " " + risksStr
	r.addHeadline(chapTitle, false)
	r.defineLinkTarget("{model-failures}")
	r.currentChapterTitleBreadcrumb = chapTitle
	r.pdfColorBlack()

	html := r.pdf.HTMLBasicNew()
	var strBuilder strings.Builder
	strBuilder.WriteString("This chapter lists potential model failures where not all relevant assets have been " +
		"modeled or the model might itself contain inconsistencies. Each potential model failure should be checked " +
		"in the model against the architecture design:<br>")
	html.Write(5, strBuilder.String())
	strBuilder.Reset()
	r.pdf.SetFont("Helvetica", "", fontSizeSmall)
	r.pdfColorGray()
	html.Write(5, "Risk finding paragraphs are clickable and link to the corresponding chapter.")
	r.pdf.SetFont("Helvetica", "", fontSizeBody)

	modelFailuresByCategory := filterByModelFailures(parsedModel, parsedModel.GeneratedRisksByCategory)
	if len(modelFailuresByCategory) == 0 {
		r.pdfColorGray()
		html.Write(5, "<br><br>No potential model failures have been identified.")
	} else {
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(modelFailuresByCategory, true, types.CriticalSeverity)),
			types.CriticalSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(modelFailuresByCategory, true, types.HighSeverity)),
			types.HighSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(modelFailuresByCategory, true, types.ElevatedSeverity)),
			types.ElevatedSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(modelFailuresByCategory, true, types.MediumSeverity)),
			types.MediumSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(modelFailuresByCategory, true, types.LowSeverity)),
			types.LowSeverity, true, true, false, true)
	}

	r.pdf.SetDrawColor(0, 0, 0)
	r.pdf.SetDashPattern([]float64{}, 0)
}

func filterByModelFailures(parsedModel *types.Model, risksByCat map[string][]*types.Risk) map[string][]*types.Risk {
	result := make(map[string][]*types.Risk)
	for categoryId, risks := range risksByCat {
		category := parsedModel.GetRiskCategory(categoryId)
		if category.ModelFailurePossibleReason {
			result[categoryId] = risks
		}
	}

	return result
}

func flattenRiskSlice(risksByCat map[string][]*types.Risk) []*types.Risk {
	result := make([]*types.Risk, 0)
	for _, risks := range risksByCat {
		result = append(result, risks...)
	}
	return result
}

func (r *pdfReporter) createRAA(parsedModel *types.Model, introTextRAA string) {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	r.pdf.SetTextColor(0, 0, 0)
	chapTitle := "RAA Analysis"
	r.addHeadline(chapTitle, false)
	r.defineLinkTarget("{raa-analysis}")
	r.currentChapterTitleBreadcrumb = chapTitle

	html := r.pdf.HTMLBasicNew()
	var strBuilder strings.Builder
	strBuilder.WriteString(introTextRAA)
	strBuilder.WriteString("<br>")
	html.Write(5, strBuilder.String())
	strBuilder.Reset()
	r.pdf.SetFont("Helvetica", "", fontSizeSmall)
	r.pdfColorGray()
	html.Write(5, "Technical asset paragraphs are clickable and link to the corresponding chapter.")
	r.pdf.SetFont("Helvetica", "", fontSizeBody)

	for _, technicalAsset := range sortedTechnicalAssetsByRAAAndTitle(parsedModel) {
		if technicalAsset.OutOfScope {
			continue
		}
		if r.pdf.GetY() > 250 {
			r.pageBreak()
			r.pdf.SetY(36)
		} else {
			strBuilder.WriteString("<br><br>")
		}
		newRisksStr := parsedModel.GeneratedRisks(technicalAsset)
		switch types.HighestSeverityStillAtRisk(newRisksStr) {
		case types.HighSeverity:
			colorHighRisk(r.pdf)
		case types.MediumSeverity:
			colorMediumRisk(r.pdf)
		case types.LowSeverity:
			colorLowRisk(r.pdf)
		default:
			r.pdfColorBlack()
		}
		if len(types.ReduceToOnlyStillAtRisk(newRisksStr)) == 0 {
			r.pdfColorBlack()
		}

		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		posY := r.pdf.GetY()
		strBuilder.WriteString("<b>")
		strBuilder.WriteString(uni(technicalAsset.Title))
		strBuilder.WriteString("</b>")
		if technicalAsset.OutOfScope {
			strBuilder.WriteString(": out-of-scope")
		} else {
			strBuilder.WriteString(": RAA ")
			fmt.Fprintf(&strBuilder, "%.0f", technicalAsset.RAA)
			strBuilder.WriteString("%")
		}
		strBuilder.WriteString("<br>")
		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		r.pdf.SetTextColor(0, 0, 0)
		strBuilder.WriteString(uni(technicalAsset.Description))
		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		r.pdf.Link(9, posY, 190, r.pdf.GetY()-posY+4, r.tocLinkIdByAssetId[technicalAsset.Id])
	}

	r.pdf.SetDrawColor(0, 0, 0)
	r.pdf.SetDashPattern([]float64{}, 0)
}

/*

func createDataRiskQuickWins() {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	r.pdf.SetTextColor(0, 0, 0)
	assets := "assets"
	count := len(model.SortedTechnicalAssetsByQuickWinsAndTitle())
	if count == 1 {
		assets = "asset"
	}
	chapTitle := "Data Risk Quick Wins: " + strconv.Itoa(count) + " " + assets
	r.addHeadline(chapTitle, false)
	defineLinkTarget("{data-risk-quick-wins}")
	currentChapterTitleBreadcrumb = chapTitle

	html := r.pdf.HTMLBasicNew()
	var strBuilder strings.Builder
	strBuilder.WriteString("For each technical asset it was checked how many data assets at risk might " +
		"get their risk-rating reduced (partly or fully) when the risks of the technical asset are mitigated. " +
		"In general, that means the higher the quick win value is, the more data assets (left side of the Data Risk Mapping diagram) " +
		"turn from red to amber or from amber to blue by mitigating the technical asset's risks. " +
		"This list can be used to prioritize on efforts with the greatest effects of reducing data asset risks:<br>")
	html.Write(5, strBuilder.String())
	strBuilder.Reset()
	r.pdf.SetFont("Helvetica", "", fontSizeSmall)
	r.pdfColorGray()
	html.Write(5, "Technical asset paragraphs are clickable and link to the corresponding chapter.")
	r.pdf.SetFont("Helvetica", "", fontSizeBody)

	for _, technicalAsset := range model.SortedTechnicalAssetsByQuickWinsAndTitle() {
		quickWins := technicalAsset.QuickWins()
		if r.pdf.GetY() > 260 {
			r.pageBreak()
			r.pdf.SetY(36)
		} else {
			strBuilder.WriteString("<br><br>")
		}
		risks := technicalAsset.GeneratedRisks()
		switch model.HighestSeverityStillAtRisk(risks) {
		case model.High:
			colorHighRisk(r.pdf)
		case model.Medium:
			colorMediumRisk(r.pdf)
		case model.Low:
			colorLowRisk(r.pdf)
		default:
			r.pdfColorBlack()
		}
		if len(model.ReduceToOnlyStillAtRisk(risks)) == 0 {
			r.pdfColorBlack()
		}

		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		posY := r.pdf.GetY()
		strBuilder.WriteString("<b>")
		strBuilder.WriteString(uni(technicalAsset.Title))
		strBuilder.WriteString("</b>")
		strBuilder.WriteString(": ")
		strBuilder.WriteString(fmt.Sprintf("%.2f", quickWins))
		strBuilder.WriteString(" Quick Wins")
		strBuilder.WriteString("<br>")
		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		r.pdf.SetTextColor(0, 0, 0)
		strBuilder.WriteString(uni(technicalAsset.Description))
		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		r.pdf.Link(9, posY, 190, r.pdf.GetY()-posY+4, tocLinkIdByAssetId[technicalAsset.ID])
	}

	r.pdf.SetDrawColor(0, 0, 0)
	r.pdf.SetDashPattern([]float64{}, 0)
}
*/
