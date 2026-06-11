package report

import (
	"strconv"
	"strings"

	"github.com/threagile/threagile/pkg/types"
)

func (r *pdfReporter) createAssignmentByFunction(parsedModel *types.Model) {
	r.pdf.SetTextColor(0, 0, 0)
	title := "Assignment by Function"
	r.addHeadline(title, false)
	r.defineLinkTarget("{function-assignment}")
	r.currentChapterTitleBreadcrumb = title

	risksBusinessSideFunction := reduceToFunctionRisk(parsedModel, parsedModel.GeneratedRisksByCategory, types.BusinessSide)
	risksArchitectureFunction := reduceToFunctionRisk(parsedModel, parsedModel.GeneratedRisksByCategory, types.Architecture)
	risksDevelopmentFunction := reduceToFunctionRisk(parsedModel, parsedModel.GeneratedRisksByCategory, types.Development)
	risksOperationFunction := reduceToFunctionRisk(parsedModel, parsedModel.GeneratedRisksByCategory, types.Operations)

	countBusinessSideFunction := countRisks(risksBusinessSideFunction)
	countArchitectureFunction := countRisks(risksArchitectureFunction)
	countDevelopmentFunction := countRisks(risksDevelopmentFunction)
	countOperationFunction := countRisks(risksOperationFunction)
	var intro strings.Builder
	intro.WriteString("This chapter clusters and assigns the risks by functions which are most likely able to " +
		"check and mitigate them: " +
		"In total <b>" + strconv.Itoa(totalRiskCount(parsedModel)) + " potential risks</b> have been identified during the threat modeling process " +
		"of which <b>" + strconv.Itoa(countBusinessSideFunction) + " should be checked by " + types.BusinessSide.Title() + "</b>, " +
		"<b>" + strconv.Itoa(countArchitectureFunction) + " should be checked by " + types.Architecture.Title() + "</b>, " +
		"<b>" + strconv.Itoa(countDevelopmentFunction) + " should be checked by " + types.Development.Title() + "</b>, " +
		"and <b>" + strconv.Itoa(countOperationFunction) + " should be checked by " + types.Operations.Title() + "</b>.<br>")
	html := r.pdf.HTMLBasicNew()
	html.Write(5, intro.String())
	intro.Reset()
	r.pdf.SetFont("Helvetica", "", fontSizeSmall)
	r.pdfColorGray()
	html.Write(5, "Risk finding paragraphs are clickable and link to the corresponding chapter.")
	r.pdf.SetFont("Helvetica", "", fontSizeBody)

	oldLeft, _, _, _ := r.pdf.GetMargins()

	if r.pdf.GetY() > 250 {
		r.pageBreak()
		r.pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	r.pdf.SetTextColor(0, 0, 0)
	html.Write(5, "<b>"+types.BusinessSide.Title()+"</b>")
	r.pdf.SetLeftMargin(15)
	if len(risksBusinessSideFunction) == 0 {
		r.pdf.SetTextColor(150, 150, 150)
		html.Write(5, "<br><br>n/a")
	} else {
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksBusinessSideFunction, true, types.CriticalSeverity)),
			types.CriticalSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksBusinessSideFunction, true, types.HighSeverity)),
			types.HighSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksBusinessSideFunction, true, types.ElevatedSeverity)),
			types.ElevatedSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksBusinessSideFunction, true, types.MediumSeverity)),
			types.MediumSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksBusinessSideFunction, true, types.LowSeverity)),
			types.LowSeverity, true, true, false, false)
	}
	r.pdf.SetLeftMargin(oldLeft)

	if r.pdf.GetY() > 250 {
		r.pageBreak()
		r.pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	r.pdf.SetTextColor(0, 0, 0)
	html.Write(5, "<b>"+types.Architecture.Title()+"</b>")
	r.pdf.SetLeftMargin(15)
	if len(risksArchitectureFunction) == 0 {
		r.pdf.SetTextColor(150, 150, 150)
		html.Write(5, "<br><br>n/a")
	} else {
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksArchitectureFunction, true, types.CriticalSeverity)),
			types.CriticalSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksArchitectureFunction, true, types.HighSeverity)),
			types.HighSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksArchitectureFunction, true, types.ElevatedSeverity)),
			types.ElevatedSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksArchitectureFunction, true, types.MediumSeverity)),
			types.MediumSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksArchitectureFunction, true, types.LowSeverity)),
			types.LowSeverity, true, true, false, false)
	}
	r.pdf.SetLeftMargin(oldLeft)

	if r.pdf.GetY() > 250 {
		r.pageBreak()
		r.pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	r.pdf.SetTextColor(0, 0, 0)
	html.Write(5, "<b>"+types.Development.Title()+"</b>")
	r.pdf.SetLeftMargin(15)
	if len(risksDevelopmentFunction) == 0 {
		r.pdf.SetTextColor(150, 150, 150)
		html.Write(5, "<br><br>n/a")
	} else {
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksDevelopmentFunction, true, types.CriticalSeverity)),
			types.CriticalSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksDevelopmentFunction, true, types.HighSeverity)),
			types.HighSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksDevelopmentFunction, true, types.ElevatedSeverity)),
			types.ElevatedSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksDevelopmentFunction, true, types.MediumSeverity)),
			types.MediumSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksDevelopmentFunction, true, types.LowSeverity)),
			types.LowSeverity, true, true, false, false)
	}
	r.pdf.SetLeftMargin(oldLeft)

	if r.pdf.GetY() > 250 {
		r.pageBreak()
		r.pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	r.pdf.SetTextColor(0, 0, 0)
	html.Write(5, "<b>"+types.Operations.Title()+"</b>")
	r.pdf.SetLeftMargin(15)
	if len(risksOperationFunction) == 0 {
		r.pdf.SetTextColor(150, 150, 150)
		html.Write(5, "<br><br>n/a")
	} else {
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksOperationFunction, true, types.CriticalSeverity)),
			types.CriticalSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksOperationFunction, true, types.HighSeverity)),
			types.HighSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksOperationFunction, true, types.ElevatedSeverity)),
			types.ElevatedSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksOperationFunction, true, types.MediumSeverity)),
			types.MediumSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksOperationFunction, true, types.LowSeverity)),
			types.LowSeverity, true, true, false, false)
	}
	r.pdf.SetLeftMargin(oldLeft)

	r.pdf.SetDrawColor(0, 0, 0)
	r.pdf.SetDashPattern([]float64{}, 0)
}

func (r *pdfReporter) createSTRIDE(parsedModel *types.Model) {
	r.pdf.SetTextColor(0, 0, 0)
	title := "STRIDE Classification of Identified Risks"
	r.addHeadline(title, false)
	r.defineLinkTarget("{stride}")
	r.currentChapterTitleBreadcrumb = title

	risksSTRIDESpoofing := reduceToSTRIDERisk(parsedModel, parsedModel.GeneratedRisksByCategory, types.Spoofing)
	risksSTRIDETampering := reduceToSTRIDERisk(parsedModel, parsedModel.GeneratedRisksByCategory, types.Tampering)
	risksSTRIDERepudiation := reduceToSTRIDERisk(parsedModel, parsedModel.GeneratedRisksByCategory, types.Repudiation)
	risksSTRIDEInformationDisclosure := reduceToSTRIDERisk(parsedModel, parsedModel.GeneratedRisksByCategory, types.InformationDisclosure)
	risksSTRIDEDenialOfService := reduceToSTRIDERisk(parsedModel, parsedModel.GeneratedRisksByCategory, types.DenialOfService)
	risksSTRIDEElevationOfPrivilege := reduceToSTRIDERisk(parsedModel, parsedModel.GeneratedRisksByCategory, types.ElevationOfPrivilege)

	countSTRIDESpoofing := countRisks(risksSTRIDESpoofing)
	countSTRIDETampering := countRisks(risksSTRIDETampering)
	countSTRIDERepudiation := countRisks(risksSTRIDERepudiation)
	countSTRIDEInformationDisclosure := countRisks(risksSTRIDEInformationDisclosure)
	countSTRIDEDenialOfService := countRisks(risksSTRIDEDenialOfService)
	countSTRIDEElevationOfPrivilege := countRisks(risksSTRIDEElevationOfPrivilege)
	var intro strings.Builder
	intro.WriteString("This chapter clusters and classifies the risks by STRIDE categories: " +
		"In total <b>" + strconv.Itoa(totalRiskCount(parsedModel)) + " potential risks</b> have been identified during the threat modeling process " +
		"of which <b>" + strconv.Itoa(countSTRIDESpoofing) + " in the " + types.Spoofing.Title() + "</b> category, " +
		"<b>" + strconv.Itoa(countSTRIDETampering) + " in the " + types.Tampering.Title() + "</b> category, " +
		"<b>" + strconv.Itoa(countSTRIDERepudiation) + " in the " + types.Repudiation.Title() + "</b> category, " +
		"<b>" + strconv.Itoa(countSTRIDEInformationDisclosure) + " in the " + types.InformationDisclosure.Title() + "</b> category, " +
		"<b>" + strconv.Itoa(countSTRIDEDenialOfService) + " in the " + types.DenialOfService.Title() + "</b> category, " +
		"and <b>" + strconv.Itoa(countSTRIDEElevationOfPrivilege) + " in the " + types.ElevationOfPrivilege.Title() + "</b> category.<br>")
	html := r.pdf.HTMLBasicNew()
	html.Write(5, intro.String())
	intro.Reset()
	r.pdf.SetFont("Helvetica", "", fontSizeSmall)
	r.pdfColorGray()
	html.Write(5, "Risk finding paragraphs are clickable and link to the corresponding chapter.")
	r.pdf.SetFont("Helvetica", "", fontSizeBody)

	oldLeft, _, _, _ := r.pdf.GetMargins()

	if r.pdf.GetY() > 250 {
		r.pageBreak()
		r.pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	r.pdf.SetTextColor(0, 0, 0)
	html.Write(5, "<b>"+types.Spoofing.Title()+"</b>")
	r.pdf.SetLeftMargin(15)
	if len(risksSTRIDESpoofing) == 0 {
		r.pdf.SetTextColor(150, 150, 150)
		html.Write(5, "<br><br>n/a")
	} else {
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDESpoofing, true, types.CriticalSeverity)),
			types.CriticalSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDESpoofing, true, types.HighSeverity)),
			types.HighSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDESpoofing, true, types.ElevatedSeverity)),
			types.ElevatedSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDESpoofing, true, types.MediumSeverity)),
			types.MediumSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDESpoofing, true, types.LowSeverity)),
			types.LowSeverity, true, true, false, true)
	}
	r.pdf.SetLeftMargin(oldLeft)

	if r.pdf.GetY() > 250 {
		r.pageBreak()
		r.pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	r.pdf.SetTextColor(0, 0, 0)
	html.Write(5, "<b>"+types.Tampering.Title()+"</b>")
	r.pdf.SetLeftMargin(15)
	if len(risksSTRIDETampering) == 0 {
		r.pdf.SetTextColor(150, 150, 150)
		html.Write(5, "<br><br>n/a")
	} else {
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDETampering, true, types.CriticalSeverity)),
			types.CriticalSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDETampering, true, types.HighSeverity)),
			types.HighSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDETampering, true, types.ElevatedSeverity)),
			types.ElevatedSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDETampering, true, types.MediumSeverity)),
			types.MediumSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDETampering, true, types.LowSeverity)),
			types.LowSeverity, true, true, false, true)
	}
	r.pdf.SetLeftMargin(oldLeft)

	if r.pdf.GetY() > 250 {
		r.pageBreak()
		r.pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	r.pdf.SetTextColor(0, 0, 0)
	html.Write(5, "<b>"+types.Repudiation.Title()+"</b>")
	r.pdf.SetLeftMargin(15)
	if len(risksSTRIDERepudiation) == 0 {
		r.pdf.SetTextColor(150, 150, 150)
		html.Write(5, "<br><br>n/a")
	} else {
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDERepudiation, true, types.CriticalSeverity)),
			types.CriticalSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDERepudiation, true, types.HighSeverity)),
			types.HighSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDERepudiation, true, types.ElevatedSeverity)),
			types.ElevatedSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDERepudiation, true, types.MediumSeverity)),
			types.MediumSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDERepudiation, true, types.LowSeverity)),
			types.LowSeverity, true, true, false, true)
	}
	r.pdf.SetLeftMargin(oldLeft)

	if r.pdf.GetY() > 250 {
		r.pageBreak()
		r.pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	r.pdf.SetTextColor(0, 0, 0)
	html.Write(5, "<b>"+types.InformationDisclosure.Title()+"</b>")
	r.pdf.SetLeftMargin(15)
	if len(risksSTRIDEInformationDisclosure) == 0 {
		r.pdf.SetTextColor(150, 150, 150)
		html.Write(5, "<br><br>n/a")
	} else {
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDEInformationDisclosure, true, types.CriticalSeverity)),
			types.CriticalSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDEInformationDisclosure, true, types.HighSeverity)),
			types.HighSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDEInformationDisclosure, true, types.ElevatedSeverity)),
			types.ElevatedSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDEInformationDisclosure, true, types.MediumSeverity)),
			types.MediumSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDEInformationDisclosure, true, types.LowSeverity)),
			types.LowSeverity, true, true, false, true)
	}
	r.pdf.SetLeftMargin(oldLeft)

	if r.pdf.GetY() > 250 {
		r.pageBreak()
		r.pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	r.pdf.SetTextColor(0, 0, 0)
	html.Write(5, "<b>"+types.DenialOfService.Title()+"</b>")
	r.pdf.SetLeftMargin(15)
	if len(risksSTRIDEDenialOfService) == 0 {
		r.pdf.SetTextColor(150, 150, 150)
		html.Write(5, "<br><br>n/a")
	} else {
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDEDenialOfService, true, types.CriticalSeverity)),
			types.CriticalSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDEDenialOfService, true, types.HighSeverity)),
			types.HighSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDEDenialOfService, true, types.ElevatedSeverity)),
			types.ElevatedSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDEDenialOfService, true, types.MediumSeverity)),
			types.MediumSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDEDenialOfService, true, types.LowSeverity)),
			types.LowSeverity, true, true, false, true)
	}
	r.pdf.SetLeftMargin(oldLeft)

	if r.pdf.GetY() > 250 {
		r.pageBreak()
		r.pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	r.pdf.SetTextColor(0, 0, 0)
	html.Write(5, "<b>"+types.ElevationOfPrivilege.Title()+"</b>")
	r.pdf.SetLeftMargin(15)
	if len(risksSTRIDEElevationOfPrivilege) == 0 {
		r.pdf.SetTextColor(150, 150, 150)
		html.Write(5, "<br><br>n/a")
	} else {
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDEElevationOfPrivilege, true, types.CriticalSeverity)),
			types.CriticalSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDEElevationOfPrivilege, true, types.HighSeverity)),
			types.HighSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDEElevationOfPrivilege, true, types.ElevatedSeverity)),
			types.ElevatedSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDEElevationOfPrivilege, true, types.MediumSeverity)),
			types.MediumSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDEElevationOfPrivilege, true, types.LowSeverity)),
			types.LowSeverity, true, true, false, true)
	}
	r.pdf.SetLeftMargin(oldLeft)

	r.pdf.SetDrawColor(0, 0, 0)
	r.pdf.SetDashPattern([]float64{}, 0)
}
