package report

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/threagile/threagile/pkg/types"
	chart "github.com/wcharczuk/go-chart/v2"
	"github.com/wcharczuk/go-chart/v2/drawing"
)

func (r *pdfReporter) createRiskMitigationStatus(parsedModel *types.Model, tempFolder string) error {
	r.pdf.SetTextColor(0, 0, 0)
	stillAtRisk := filteredByStillAtRisk(parsedModel)
	count := len(stillAtRisk)
	title := "Risk Mitigation"
	r.addHeadline(title, false)
	r.defineLinkTarget("{risk-mitigation-status}")
	r.currentChapterTitleBreadcrumb = title

	html := r.pdf.HTMLBasicNew()
	html.Write(5, "The following chart gives a high-level overview of the risk tracking status (including mitigated risks):")

	risksCritical := filteredBySeverity(parsedModel, types.CriticalSeverity)
	risksHigh := filteredBySeverity(parsedModel, types.HighSeverity)
	risksElevated := filteredBySeverity(parsedModel, types.ElevatedSeverity)
	risksMedium := filteredBySeverity(parsedModel, types.MediumSeverity)
	risksLow := filteredBySeverity(parsedModel, types.LowSeverity)

	countStatusUnchecked := len(filteredByRiskStatus(parsedModel, types.Unchecked))
	countStatusInDiscussion := len(filteredByRiskStatus(parsedModel, types.InDiscussion))
	countStatusAccepted := len(filteredByRiskStatus(parsedModel, types.Accepted))
	countStatusInProgress := len(filteredByRiskStatus(parsedModel, types.InProgress))
	countStatusMitigated := len(filteredByRiskStatus(parsedModel, types.Mitigated))
	countStatusFalsePositive := len(filteredByRiskStatus(parsedModel, types.FalsePositive))

	stackedBarChartRiskTracking := chart.StackedBarChart{
		Width: 4000,
		//Height: 2500,
		XAxis: chart.Style{Hidden: true, FontSize: 26, TextVerticalAlign: chart.TextVerticalAlignBottom},
		YAxis: chart.Style{Hidden: false, FontSize: 26, TextVerticalAlign: chart.TextVerticalAlignBottom},
		Bars: []chart.StackedBar{
			{
				Name:  types.LowSeverity.Title(),
				Width: 130,
				Values: []chart.Value{
					{Value: float64(len(reduceToRiskStatus(risksLow, types.Unchecked))), Label: types.Unchecked.Title(),
						Style: chart.Style{FillColor: makeColor(RgbHexColorRiskStatusUnchecked()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksLow, types.InDiscussion))), Label: types.InDiscussion.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusInDiscussion()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksLow, types.Accepted))), Label: types.Accepted.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusAccepted()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksLow, types.InProgress))), Label: types.InProgress.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusInProgress()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksLow, types.Mitigated))), Label: types.Mitigated.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusMitigated()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksLow, types.FalsePositive))), Label: types.FalsePositive.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusFalsePositive()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
				},
			},
			{
				Name:  types.MediumSeverity.Title(),
				Width: 130,
				Values: []chart.Value{
					{Value: float64(len(reduceToRiskStatus(risksMedium, types.Unchecked))), Label: types.Unchecked.Title(),
						Style: chart.Style{FillColor: makeColor(RgbHexColorRiskStatusUnchecked()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksMedium, types.InDiscussion))), Label: types.InDiscussion.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusInDiscussion()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksMedium, types.Accepted))), Label: types.Accepted.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusAccepted()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksMedium, types.InProgress))), Label: types.InProgress.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusInProgress()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksMedium, types.Mitigated))), Label: types.Mitigated.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusMitigated()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksMedium, types.FalsePositive))), Label: types.FalsePositive.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusFalsePositive()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
				},
			},
			{
				Name:  types.ElevatedSeverity.Title(),
				Width: 130,
				Values: []chart.Value{
					{Value: float64(len(reduceToRiskStatus(risksElevated, types.Unchecked))), Label: types.Unchecked.Title(),
						Style: chart.Style{FillColor: makeColor(RgbHexColorRiskStatusUnchecked()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksElevated, types.InDiscussion))), Label: types.InDiscussion.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusInDiscussion()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksElevated, types.Accepted))), Label: types.Accepted.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusAccepted()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksElevated, types.InProgress))), Label: types.InProgress.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusInProgress()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksElevated, types.Mitigated))), Label: types.Mitigated.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusMitigated()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksElevated, types.FalsePositive))), Label: types.FalsePositive.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusFalsePositive()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
				},
			},
			{
				Name:  types.HighSeverity.Title(),
				Width: 130,
				Values: []chart.Value{
					{Value: float64(len(reduceToRiskStatus(risksHigh, types.Unchecked))), Label: types.Unchecked.Title(),
						Style: chart.Style{FillColor: makeColor(RgbHexColorRiskStatusUnchecked()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksHigh, types.InDiscussion))), Label: types.InDiscussion.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusInDiscussion()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksHigh, types.Accepted))), Label: types.Accepted.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusAccepted()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksHigh, types.InProgress))), Label: types.InProgress.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusInProgress()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksHigh, types.Mitigated))), Label: types.Mitigated.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusMitigated()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksHigh, types.FalsePositive))), Label: types.FalsePositive.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusFalsePositive()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
				},
			},
			{
				Name:  types.CriticalSeverity.Title(),
				Width: 130,
				Values: []chart.Value{
					{Value: float64(len(reduceToRiskStatus(risksCritical, types.Unchecked))), Label: types.Unchecked.Title(),
						Style: chart.Style{FillColor: makeColor(RgbHexColorRiskStatusUnchecked()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksCritical, types.InDiscussion))), Label: types.InDiscussion.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusInDiscussion()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksCritical, types.Accepted))), Label: types.Accepted.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusAccepted()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksCritical, types.InProgress))), Label: types.InProgress.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusInProgress()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksCritical, types.Mitigated))), Label: types.Mitigated.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusMitigated()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksCritical, types.FalsePositive))), Label: types.FalsePositive.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusFalsePositive()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
				},
			},
		},
	}

	y := r.pdf.GetY() + 12
	err := r.embedStackedBarChart(stackedBarChartRiskTracking, 15.0, y, tempFolder)
	if err != nil {
		return err
	}

	// draw the X-Axis legend on my own
	r.pdf.SetFont("Helvetica", "", fontSizeSmall)
	r.pdfColorBlack()
	r.pdf.Text(24.02, 169, "Low ("+strconv.Itoa(len(risksLow))+")")
	r.pdf.Text(46.10, 169, "Medium ("+strconv.Itoa(len(risksMedium))+")")
	r.pdf.Text(69.74, 169, "Elevated ("+strconv.Itoa(len(risksElevated))+")")
	r.pdf.Text(97.95, 169, "High ("+strconv.Itoa(len(risksHigh))+")")
	r.pdf.Text(121.65, 169, "Critical ("+strconv.Itoa(len(risksCritical))+")")

	r.pdf.SetFont("Helvetica", "B", fontSizeBody)
	r.pdf.Ln(20)

	colorRiskStatusUnchecked(r.pdf)
	r.pdf.CellFormat(150, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countStatusUnchecked), "0", 0, "R", false, 0, "")
	r.pdf.CellFormat(60, 6, "unchecked", "0", 0, "", false, 0, "")
	r.pdf.Ln(-1)
	colorRiskStatusInDiscussion(r.pdf)
	r.pdf.CellFormat(150, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countStatusInDiscussion), "0", 0, "R", false, 0, "")
	r.pdf.CellFormat(60, 6, "in discussion", "0", 0, "", false, 0, "")
	r.pdf.Ln(-1)
	colorRiskStatusAccepted(r.pdf)
	r.pdf.CellFormat(150, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countStatusAccepted), "0", 0, "R", false, 0, "")
	r.pdf.CellFormat(60, 6, "accepted", "0", 0, "", false, 0, "")
	r.pdf.Ln(-1)
	colorRiskStatusInProgress(r.pdf)
	r.pdf.CellFormat(150, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countStatusInProgress), "0", 0, "R", false, 0, "")
	r.pdf.CellFormat(60, 6, "in progress", "0", 0, "", false, 0, "")
	r.pdf.Ln(-1)
	colorRiskStatusMitigated(r.pdf)
	r.pdf.CellFormat(150, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countStatusMitigated), "0", 0, "R", false, 0, "")
	r.pdf.SetFont("Helvetica", "BI", fontSizeBody)
	r.pdf.CellFormat(60, 6, "mitigated", "0", 0, "", false, 0, "")
	r.pdf.SetFont("Helvetica", "B", fontSizeBody)
	r.pdf.Ln(-1)
	colorRiskStatusFalsePositive(r.pdf)
	r.pdf.CellFormat(150, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countStatusFalsePositive), "0", 0, "R", false, 0, "")
	r.pdf.SetFont("Helvetica", "BI", fontSizeBody)
	r.pdf.CellFormat(60, 6, "false positive", "0", 0, "", false, 0, "")
	r.pdf.SetFont("Helvetica", "B", fontSizeBody)
	r.pdf.Ln(-1)

	r.pdf.SetFont("Helvetica", "", fontSizeBody)

	r.pdfColorBlack()
	if count == 0 {
		html.Write(5, "<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br>"+
			"After removal of risks with status <i>mitigated</i> and <i>false positive</i> "+
			"<b>"+strconv.Itoa(count)+" remain unmitigated</b>.")
	} else {
		html.Write(5, "<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br>"+
			"After removal of risks with status <i>mitigated</i> and <i>false positive</i> "+
			"the following <b>"+strconv.Itoa(count)+" remain unmitigated</b>:")

		countCritical := len(types.ReduceToOnlyStillAtRisk(filteredBySeverity(parsedModel, types.CriticalSeverity)))
		countHigh := len(types.ReduceToOnlyStillAtRisk(filteredBySeverity(parsedModel, types.HighSeverity)))
		countElevated := len(types.ReduceToOnlyStillAtRisk(filteredBySeverity(parsedModel, types.ElevatedSeverity)))
		countMedium := len(types.ReduceToOnlyStillAtRisk(filteredBySeverity(parsedModel, types.MediumSeverity)))
		countLow := len(types.ReduceToOnlyStillAtRisk(filteredBySeverity(parsedModel, types.LowSeverity)))

		countBusinessSide := len(types.ReduceToOnlyStillAtRisk(filteredByRiskFunction(parsedModel, types.BusinessSide)))
		countArchitecture := len(types.ReduceToOnlyStillAtRisk(filteredByRiskFunction(parsedModel, types.Architecture)))
		countDevelopment := len(types.ReduceToOnlyStillAtRisk(filteredByRiskFunction(parsedModel, types.Development)))
		countOperation := len(types.ReduceToOnlyStillAtRisk(filteredByRiskFunction(parsedModel, types.Operations)))

		pieChartRemainingRiskSeverity := chart.PieChart{
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

		pieChartRemainingRisksByFunction := chart.PieChart{
			Width:  1500,
			Height: 1500,
			Values: []chart.Value{
				{Value: float64(countBusinessSide),
					Style: chart.Style{
						FillColor: makeColor(rgbHexColorBusiness()).WithAlpha(98),
						FontSize:  65}},
				{Value: float64(countArchitecture),
					Style: chart.Style{
						FillColor: makeColor(rgbHexColorArchitecture()).WithAlpha(98),
						FontSize:  65}},
				{Value: float64(countDevelopment),
					Style: chart.Style{
						FillColor: makeColor(rgbHexColorDevelopment()).WithAlpha(98),
						FontSize:  65}},
				{Value: float64(countOperation),
					Style: chart.Style{
						FillColor: makeColor(rgbHexColorOperation()).WithAlpha(98),
						FontSize:  65}},
			},
		}

		if err := r.embedPieChart(pieChartRemainingRiskSeverity, 15.0, 216, tempFolder); err != nil {
			return fmt.Errorf("embed risk severity chart: %w", err)
		}
		if err := r.embedPieChart(pieChartRemainingRisksByFunction, 110.0, 216, tempFolder); err != nil {
			return fmt.Errorf("embed risk function chart: %w", err)
		}

		r.pdf.SetFont("Helvetica", "B", fontSizeBody)
		r.pdf.Ln(8)

		colorCriticalRisk(r.pdf)
		r.pdf.CellFormat(10, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(10, 6, strconv.Itoa(countCritical), "0", 0, "R", false, 0, "")
		r.pdf.CellFormat(60, 6, "unmitigated critical risk", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(22, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(10, 6, "", "0", 0, "R", false, 0, "")
		r.pdf.CellFormat(60, 6, "", "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		colorHighRisk(r.pdf)
		r.pdf.CellFormat(10, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(10, 6, strconv.Itoa(countHigh), "0", 0, "R", false, 0, "")
		r.pdf.CellFormat(60, 6, "unmitigated high risk", "0", 0, "", false, 0, "")
		colorBusiness(r.pdf)
		r.pdf.CellFormat(22, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(10, 6, strconv.Itoa(countBusinessSide), "0", 0, "R", false, 0, "")
		r.pdf.CellFormat(60, 6, "business side related", "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		colorElevatedRisk(r.pdf)
		r.pdf.CellFormat(10, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(10, 6, strconv.Itoa(countElevated), "0", 0, "R", false, 0, "")
		r.pdf.CellFormat(60, 6, "unmitigated elevated risk", "0", 0, "", false, 0, "")
		colorArchitecture(r.pdf)
		r.pdf.CellFormat(22, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(10, 6, strconv.Itoa(countArchitecture), "0", 0, "R", false, 0, "")
		r.pdf.CellFormat(60, 6, "architecture related", "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		colorMediumRisk(r.pdf)
		r.pdf.CellFormat(10, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(10, 6, strconv.Itoa(countMedium), "0", 0, "R", false, 0, "")
		r.pdf.CellFormat(60, 6, "unmitigated medium risk", "0", 0, "", false, 0, "")
		colorDevelopment(r.pdf)
		r.pdf.CellFormat(22, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(10, 6, strconv.Itoa(countDevelopment), "0", 0, "R", false, 0, "")
		r.pdf.CellFormat(60, 6, "development related", "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		colorLowRisk(r.pdf)
		r.pdf.CellFormat(10, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(10, 6, strconv.Itoa(countLow), "0", 0, "R", false, 0, "")
		r.pdf.CellFormat(60, 6, "unmitigated low risk", "0", 0, "", false, 0, "")
		colorOperation(r.pdf)
		r.pdf.CellFormat(22, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(10, 6, strconv.Itoa(countOperation), "0", 0, "R", false, 0, "")
		r.pdf.CellFormat(60, 6, "operations related", "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "", fontSizeBody)
	}
	return nil
}

func (r *pdfReporter) createAssetRegister(parsedModel *types.Model) {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	r.pdf.SetTextColor(0, 0, 0)
	chapTitle := "Asset Register"
	r.addHeadline(chapTitle, false)
	r.defineLinkTarget("{asset-register}")
	r.currentChapterTitleBreadcrumb = chapTitle

	html := r.pdf.HTMLBasicNew()
	var strBuilder strings.Builder
	r.pdf.SetFont("Helvetica", "", fontSizeBody)

	subTitle := "Technical Assets"
	r.addHeadline(subTitle, true)
	r.currentChapterTitleBreadcrumb = subTitle
	for _, technicalAsset := range sortedTechnicalAssetsByTitle(parsedModel) {
		if r.pdf.GetY() > 250 {
			r.pageBreak()
			r.pdf.SetY(36)
		} else {
			strBuilder.WriteString("<br><br>")
		}

		r.pdf.SetTextColor(0, 0, 0)

		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		posY := r.pdf.GetY()
		strBuilder.WriteString("<b>")
		strBuilder.WriteString(uni(technicalAsset.Title))
		strBuilder.WriteString("</b>")
		if technicalAsset.OutOfScope {
			strBuilder.WriteString(": out-of-scope")
		}
		strBuilder.WriteString("<br>")
		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		strBuilder.WriteString(uni(technicalAsset.Description))
		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		r.pdf.Link(9, posY, 190, r.pdf.GetY()-posY+4, r.tocLinkIdByAssetId[technicalAsset.Id])
	}

	subTitle = "Data Assets"
	r.addHeadline(subTitle, true)
	r.currentChapterTitleBreadcrumb = subTitle

	for _, dataAsset := range sortedDataAssetsByTitle(parsedModel) {
		if r.pdf.GetY() > 250 {
			r.pageBreak()
			r.pdf.SetY(36)
		} else {
			strBuilder.WriteString("<br><br>")
		}

		r.pdf.SetTextColor(0, 0, 0)

		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		posY := r.pdf.GetY()
		strBuilder.WriteString("<b>")
		strBuilder.WriteString(uni(dataAsset.Title))
		strBuilder.WriteString("</b>")
		strBuilder.WriteString("<br>")
		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		strBuilder.WriteString(uni(dataAsset.Description))
		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		r.pdf.Link(9, posY, 190, r.pdf.GetY()-posY+4, r.tocLinkIdByAssetId[dataAsset.Id])
	}

	r.pdf.SetDrawColor(0, 0, 0)
	r.pdf.SetDashPattern([]float64{}, 0)
}

// CAUTION: Long labels might cause endless loop, then remove labels and render them manually later inside the PDF
