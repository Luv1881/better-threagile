package report

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/threagile/threagile/pkg/types"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

func (adoc adocReport) writeManagementSummery() error {
	filename := "010_ManagementSummary.adoc"
	ms, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = ms.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	writeLine(ms, "= Management Summary")
	writeLine(ms, "")
	writeLine(ms, "Threagile toolkit was used to model the architecture of \""+adoc.model.Title+"\" and derive risks by analyzing the components and data flows.")
	writeLine(ms, "The risks identified during this analysis are shown in the following chapters.")
	writeLine(ms, "Identified risks during threat modeling do not necessarily mean that the "+
		"vulnerability associated with this risk actually exists: it is more to be seen as a list"+
		" of potential risks and threats, which should be individually reviewed and reduced by removing false positives.")
	writeLine(ms, "For the remaining risks it should be checked in the design and implementation of \""+adoc.model.Title+"\" whether the mitigation advices have been applied or not.")
	writeLine(ms, "\n\n")
	writeLine(ms, "Each risk finding references a chapter of the OWASP ASVS (Application Security Verification Standard) audit checklist.")
	writeLine(ms, "The OWASP ASVS checklist should be considered as an inspiration by architects and developers to further harden the application in a Defense-in-Depth approach.")
	writeLine(ms, "Additionally, for each risk finding a link towards a matching OWASP Cheat Sheet or similar with technical details about how to implement a mitigation is given.")
	writeLine(ms, "\n\n")
	writeLine(ms, "In total *"+strconv.Itoa(totalRiskCount(adoc.model))+" initial risks* in *"+strconv.Itoa(len(adoc.model.GeneratedRisksByCategory))+" categories* have been identified during the threat modeling process:")
	writeLine(ms, "\n\n")

	countCritical := len(filteredBySeverity(adoc.model, types.CriticalSeverity))
	countHigh := len(filteredBySeverity(adoc.model, types.HighSeverity))
	countElevated := len(filteredBySeverity(adoc.model, types.ElevatedSeverity))
	countMedium := len(filteredBySeverity(adoc.model, types.MediumSeverity))
	countLow := len(filteredBySeverity(adoc.model, types.LowSeverity))

	countStatusUnchecked := len(filteredByRiskStatus(adoc.model, types.Unchecked))
	countStatusInDiscussion := len(filteredByRiskStatus(adoc.model, types.InDiscussion))
	countStatusAccepted := len(filteredByRiskStatus(adoc.model, types.Accepted))
	countStatusInProgress := len(filteredByRiskStatus(adoc.model, types.InProgress))
	countStatusMitigated := len(filteredByRiskStatus(adoc.model, types.Mitigated))
	countStatusFalsePositive := len(filteredByRiskStatus(adoc.model, types.FalsePositive))

	pieCharts := `[cols="a,a",frame=none,grid=none]
|===
|
[mermaid]
....
%%{init: {'pie' : {'textPosition' : 0.5}, 'theme': 'base', 'themeVariables': { 'pie1': '` + rgbHexColorCriticalRisk() + `', 'pie2': '` + rgbHexColorHighRisk() + `', 'pie3': '` + rgbHexColorElevatedRisk() + `', 'pie4': '` + rgbHexColorMediumRisk() + `', 'pie5': '` + rgbHexColorLowRisk() + `'}}}%%
pie showData
  "critical risk" : ` + strconv.Itoa(countCritical) + `
  "high risk" : ` + strconv.Itoa(countHigh) + `
  "elevated risk" : ` + strconv.Itoa(countElevated) + `
  "medium risk" : ` + strconv.Itoa(countMedium) + `
  "low risk" : ` + strconv.Itoa(countLow) + `
....

|
[mermaid]
....
%%{init: {'pie' : {'textPosition' : 0.5}, 'theme': 'base', 'themeVariables': { 'pie1': '` + RgbHexColorRiskStatusUnchecked() + `', 'pie2': '` + rgbHexColorRiskStatusInDiscussion() + `', 'pie3': '` + rgbHexColorRiskStatusAccepted() + `', 'pie4': '` + rgbHexColorRiskStatusInProgress() + `', 'pie5': '` + rgbHexColorRiskStatusMitigated() + `', 'pie5': '` + rgbHexColorRiskStatusFalsePositive() + `'}}}%%
pie showData
  "unchecked" : ` + strconv.Itoa(countStatusUnchecked) + `
  "in discussion" : ` + strconv.Itoa(countStatusInDiscussion) + `
  "accepted" : ` + strconv.Itoa(countStatusAccepted) + `
  "in progress" : ` + strconv.Itoa(countStatusInProgress) + `
  "mitigated" : ` + strconv.Itoa(countStatusMitigated) + `
  "false positive" : ` + strconv.Itoa(countStatusFalsePositive) + `
....
|===
`
	writeLine(ms, pieCharts)
	// individual management summary comment
	if len(adoc.model.ManagementSummaryComment) > 0 {
		writeLine(ms, "\n\n\n"+fixBasicHtml(adoc.model.ManagementSummaryComment))
	}

	return nil
}

func (adoc adocReport) addCategories(f *os.File, risksByCategory map[string][]*types.Risk, initialRisks bool, severity types.RiskSeverity, bothInitialAndRemainingRisks bool, describeDescription bool) {
	describeImpact := true
	riskCategories := getRiskCategories(adoc.model, reduceToSeverityRisk(risksByCategory, initialRisks, severity))
	sort.Sort(types.ByRiskCategoryTitleSort(riskCategories))
	for _, riskCategory := range riskCategories {
		risksStr := risksByCategory[riskCategory.ID]
		if !initialRisks {
			risksStr = types.ReduceToOnlyStillAtRisk(risksStr)
		}
		if len(risksStr) == 0 {
			continue
		}

		var prefix string
		colorPrefix, colorSuffix := colorPrefixBySeverity(severity, false)
		switch severity {
		case types.CriticalSeverity:
			prefix = "Critical: "
		case types.HighSeverity:
			prefix = "High: "
		case types.ElevatedSeverity:
			prefix = "Elevated: "
		case types.MediumSeverity:
			prefix = "Medium: "
		case types.LowSeverity:
			prefix = "Low: "
		default:
			prefix = ""
		}
		if len(types.ReduceToOnlyStillAtRisk(risksStr)) == 0 {
			colorPrefix = ""
			colorSuffix = ""
		}
		fullLine := "<<" + riskCategory.ID + "," + colorPrefix + prefix + "*" + riskCategory.Title + "*: "

		count := len(risksStr)
		initialStr := "Initial"
		if !initialRisks {
			initialStr = "Remaining"
		}
		remainingRisks := types.ReduceToOnlyStillAtRisk(risksStr)
		suffix := strconv.Itoa(count) + " " + initialStr + " Risk"
		if count != 1 {
			suffix += "s"
		}
		if bothInitialAndRemainingRisks {
			suffix = riskSuffix(len(remainingRisks), count)
		}
		suffix += " - Exploitation likelihood is _"
		if initialRisks {
			suffix += highestExploitationLikelihood(risksStr).Title() + "_ with _" + highestExploitationImpact(risksStr).Title() + "_ impact."
		} else {
			suffix += highestExploitationLikelihood(remainingRisks).Title() + "_ with _" + highestExploitationImpact(remainingRisks).Title() + "_ impact."
		}

		fullLine += suffix + colorSuffix + ">>::"
		writeLine(f, fullLine)

		if describeImpact {
			writeLine(f, firstParagraph(riskCategory.Impact))
		} else if describeDescription {
			writeLine(f, firstParagraph(riskCategory.Description))
		} else {
			writeLine(f, firstParagraph(riskCategory.Mitigation))
		}
		writeLine(f, "")
	}
}

func (adoc adocReport) impactAnalysis(f *os.File, initialRisks bool) int {

	count := 0
	catCount := 0
	initialStr := ""
	if initialRisks {
		count = totalRiskCount(adoc.model)
		catCount = len(adoc.model.GeneratedRisksByCategory)
		initialStr = "initial"
	} else {
		count = len(filteredByStillAtRisk(adoc.model))
		catCount = len(reduceToOnlyStillAtRisk(adoc.model.GeneratedRisksByCategoryWithCurrentStatus()))
		initialStr = "remaining"
	}

	riskText := "risks"
	if count == 1 {
		riskText = "risk"
	}
	catText := "categories"
	if catCount == 1 {
		catText = "category"
	}

	titleCaser := cases.Title(language.English)
	chapTitle := titleCaser.String("= Impact Analysis of " + strconv.Itoa(count) + " " + initialStr + " " + riskText + " in " + strconv.Itoa(catCount) + " " + catText)
	writeLine(f, chapTitle)
	writeLine(f, ":fn-risk-findings: footnote:riskfinding[Risk finding paragraphs are clickable and link to the corresponding chapter.]")

	writeLine(f,
		"The most prevalent impacts of the *"+strconv.Itoa(count)+" "+initialStr+" "+riskText+"*"+
			" (distributed over *"+strconv.Itoa(catCount)+" risk categories*) are "+
			"(taking the severity ratings into account and using the highest for each category)!{fn-risk-findings}")
	writeLine(f, "")
	adoc.addCategories(f, adoc.model.GeneratedRisksByCategoryWithCurrentStatus(), initialRisks, types.CriticalSeverity, false, false)
	adoc.addCategories(f, adoc.model.GeneratedRisksByCategoryWithCurrentStatus(), initialRisks, types.HighSeverity, false, false)
	adoc.addCategories(f, adoc.model.GeneratedRisksByCategoryWithCurrentStatus(), initialRisks, types.ElevatedSeverity, false, false)
	adoc.addCategories(f, adoc.model.GeneratedRisksByCategoryWithCurrentStatus(), initialRisks, types.MediumSeverity, false, false)
	adoc.addCategories(f, adoc.model.GeneratedRisksByCategoryWithCurrentStatus(), initialRisks, types.LowSeverity, false, false)

	return count
}

func (adoc adocReport) writeImpactInitialRisks() error {
	filename := "020_ImpactIntialRisks.adoc"
	ir, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = ir.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.impactAnalysis(ir, true)
	return nil
}

func (adoc adocReport) riskMitigationStatus(f *os.File) {

	writeLine(f, "= Risk Mitigation")
	writeLine(f, "The following chart gives a high-level overview of the risk tracking status (including mitigated risks):")

	risksCritical := filteredBySeverity(adoc.model, types.CriticalSeverity)
	risksHigh := filteredBySeverity(adoc.model, types.HighSeverity)
	risksElevated := filteredBySeverity(adoc.model, types.ElevatedSeverity)
	risksMedium := filteredBySeverity(adoc.model, types.MediumSeverity)
	risksLow := filteredBySeverity(adoc.model, types.LowSeverity)
	countStatusUnchecked := len(filteredByRiskStatus(adoc.model, types.Unchecked))
	countStatusInDiscussion := len(filteredByRiskStatus(adoc.model, types.InDiscussion))
	countStatusAccepted := len(filteredByRiskStatus(adoc.model, types.Accepted))
	countStatusInProgress := len(filteredByRiskStatus(adoc.model, types.InProgress))
	countStatusMitigated := len(filteredByRiskStatus(adoc.model, types.Mitigated))
	countStatusFalsePositive := len(filteredByRiskStatus(adoc.model, types.FalsePositive))

	lowTitle := types.LowSeverity.Title() + " (" + strconv.Itoa(len(risksLow)) + ")"
	medTitle := types.MediumSeverity.Title() + " (" + strconv.Itoa(len(risksMedium)) + ")"
	elevatedTitle := types.ElevatedSeverity.Title() + " (" + strconv.Itoa(len(risksElevated)) + ")"
	highTitle := types.HighSeverity.Title() + " (" + strconv.Itoa(len(risksHigh)) + ")"
	criticalTitle := types.CriticalSeverity.Title() + " (" + strconv.Itoa(len(risksCritical)) + ")"

	diagram := `
[vegalite]
....
{
  "width": 400,
  "$schema": "https://vega.github.io/schema/vega-lite/v4.json",
  "data": {
    "values": [
      {"risk": "` + lowTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksLow, types.Unchecked))) + `, "status": "Unchecked", "color": "` + RgbHexColorRiskStatusUnchecked() + `"},
      {"risk": "` + lowTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksLow, types.InDiscussion))) + `, "status": "InDiscussion", "color": "` + rgbHexColorRiskStatusInDiscussion() + `"},
      {"risk": "` + lowTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksLow, types.Accepted))) + `, "status": "Accepted", "color": "` + rgbHexColorRiskStatusAccepted() + `"},
      {"risk": "` + lowTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksLow, types.InProgress))) + `, "status": "InProgress", "color": "` + rgbHexColorRiskStatusInProgress() + `"},
      {"risk": "` + lowTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksLow, types.Mitigated))) + `, "status": "Mitigated", "color": "` + rgbHexColorRiskStatusMitigated() + `"},
      {"risk": "` + lowTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksLow, types.FalsePositive))) + `, "status": "FalsePositive", "color": "` + rgbHexColorRiskStatusFalsePositive() + `"},

      {"risk": "` + medTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksMedium, types.Unchecked))) + `, "status": "Unchecked", "color": "` + RgbHexColorRiskStatusUnchecked() + `"},
      {"risk": "` + medTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksMedium, types.InDiscussion))) + `, "status": "InDiscussion", "color": "` + rgbHexColorRiskStatusInDiscussion() + `"},
      {"risk": "` + medTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksMedium, types.Accepted))) + `, "status": "Accepted", "color": "` + rgbHexColorRiskStatusAccepted() + `"},
      {"risk": "` + medTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksMedium, types.InProgress))) + `, "status": "InProgress", "color": "` + rgbHexColorRiskStatusInProgress() + `"},
      {"risk": "` + medTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksMedium, types.Mitigated))) + `, "status": "Mitigated", "color": "` + rgbHexColorRiskStatusMitigated() + `"},
      {"risk": "` + medTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksMedium, types.FalsePositive))) + `, "status": "FalsePositive", "color": "` + rgbHexColorRiskStatusFalsePositive() + `"},

      {"risk": "` + elevatedTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksElevated, types.Unchecked))) + `, "status": "Unchecked", "color": "` + RgbHexColorRiskStatusUnchecked() + `"},
      {"risk": "` + elevatedTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksElevated, types.InDiscussion))) + `, "status": "InDiscussion", "color": "` + rgbHexColorRiskStatusInDiscussion() + `"},
      {"risk": "` + elevatedTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksElevated, types.Accepted))) + `, "status": "Accepted", "color": "` + rgbHexColorRiskStatusAccepted() + `"},
      {"risk": "` + elevatedTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksElevated, types.InProgress))) + `, "status": "InProgress", "color": "` + rgbHexColorRiskStatusInProgress() + `"},
      {"risk": "` + elevatedTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksElevated, types.Mitigated))) + `, "status": "Mitigated", "color": "` + rgbHexColorRiskStatusMitigated() + `"},
      {"risk": "` + elevatedTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksElevated, types.FalsePositive))) + `, "status": "FalsePositive", "color": "` + rgbHexColorRiskStatusFalsePositive() + `"},

      {"risk": "` + highTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksHigh, types.Unchecked))) + `, "status": "Unchecked", "color": "` + RgbHexColorRiskStatusUnchecked() + `"},
      {"risk": "` + highTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksHigh, types.InDiscussion))) + `, "status": "InDiscussion", "color": "` + rgbHexColorRiskStatusInDiscussion() + `"},
      {"risk": "` + highTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksHigh, types.Accepted))) + `, "status": "Accepted", "color": "` + rgbHexColorRiskStatusAccepted() + `"},
      {"risk": "` + highTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksHigh, types.InProgress))) + `, "status": "InProgress", "color": "` + rgbHexColorRiskStatusInProgress() + `"},
      {"risk": "` + highTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksHigh, types.Mitigated))) + `, "status": "Mitigated", "color": "` + rgbHexColorRiskStatusMitigated() + `"},
      {"risk": "` + highTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksHigh, types.FalsePositive))) + `, "status": "FalsePositive", "color": "` + rgbHexColorRiskStatusFalsePositive() + `"},

      {"risk": "` + criticalTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksCritical, types.Unchecked))) + `, "status": "Unchecked", "color": "` + RgbHexColorRiskStatusUnchecked() + `"},
      {"risk": "` + criticalTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksCritical, types.InDiscussion))) + `, "status": "InDiscussion", "color": "` + rgbHexColorRiskStatusInDiscussion() + `"},
      {"risk": "` + criticalTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksCritical, types.Accepted))) + `, "status": "Accepted", "color": "` + rgbHexColorRiskStatusAccepted() + `"},
      {"risk": "` + criticalTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksCritical, types.InProgress))) + `, "status": "InProgress", "color": "` + rgbHexColorRiskStatusInProgress() + `"},
      {"risk": "` + criticalTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksCritical, types.Mitigated))) + `, "status": "Mitigated", "color": "` + rgbHexColorRiskStatusMitigated() + `"},
      {"risk": "` + criticalTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksCritical, types.FalsePositive))) + `, "status": "FalsePositive", "color": "` + rgbHexColorRiskStatusFalsePositive() + `"}
    ]
  },
  "mark": {"type": "bar", "cornerRadiusTopLeft": 3, "cornerRadiusTopRight": 3},
  "encoding": {
    "x": {"field": "risk", "type": "ordinal", "title": "", "sort": [], "axis": {
        "labelAngle": 0
    }},
    "y": {"field": "value", "type": "quantitative", "title": "", "axis": {
      "orient": "right"
    }},
    "color": {
      "field": "status",
      "scale": {
        "domain": ["Unchecked", "InDiscussion", "Accepted", "InProgress", "Mitigated", "FalsePositive"],
        "range": ["` + RgbHexColorRiskStatusUnchecked() + `", "` + rgbHexColorRiskStatusInDiscussion() + `", "` + rgbHexColorRiskStatusAccepted() + `", "` + rgbHexColorRiskStatusInProgress() + `", "` + rgbHexColorRiskStatusMitigated() + `", "` + rgbHexColorRiskStatusFalsePositive() + `"]
      },
      "legend" : {
        "title": "",
        "labelExpr": "datum.label == \"Unchecked\" ? \"` + strconv.Itoa(countStatusUnchecked) +
		` unchecked\" : datum.label == \"InDiscussion\" ? \"` + strconv.Itoa(countStatusInDiscussion) +
		` in discussion\" : datum.label == \"Accepted\" ? \"` + strconv.Itoa(countStatusAccepted) +
		` accepted\" : datum.label == \"InProgress\" ? \"` + strconv.Itoa(countStatusInProgress) +
		` in progress\" : datum.label == \"Mitigated\" ? \"` + strconv.Itoa(countStatusMitigated) +
		` mitigated\" : datum.label == \"FalsePositive\" ? \"` + strconv.Itoa(countStatusFalsePositive) +
		` false positive\" : \"\""
      }
    }
  }
}
....
`
	writeLine(f, diagram)
	writeLine(f, "")
	stillAtRisk := filteredByStillAtRisk(adoc.model)
	count := len(stillAtRisk)
	if count == 0 {
		writeLine(f, "After removal of risks with status _mitigated_ and _false positive_ "+
			"*"+strconv.Itoa(count)+" remain unmitigated*.")
	} else {
		writeLine(f, "After removal of risks with status _mitigated_ and _false positive_ "+
			"the following *"+strconv.Itoa(count)+" remain unmitigated*:")

		countCritical := len(types.ReduceToOnlyStillAtRisk(filteredBySeverity(adoc.model, types.CriticalSeverity)))
		countHigh := len(types.ReduceToOnlyStillAtRisk(filteredBySeverity(adoc.model, types.HighSeverity)))
		countElevated := len(types.ReduceToOnlyStillAtRisk(filteredBySeverity(adoc.model, types.ElevatedSeverity)))
		countMedium := len(types.ReduceToOnlyStillAtRisk(filteredBySeverity(adoc.model, types.MediumSeverity)))
		countLow := len(types.ReduceToOnlyStillAtRisk(filteredBySeverity(adoc.model, types.LowSeverity)))

		countBusinessSide := len(types.ReduceToOnlyStillAtRisk(filteredByRiskFunction(adoc.model, types.BusinessSide)))
		countArchitecture := len(types.ReduceToOnlyStillAtRisk(filteredByRiskFunction(adoc.model, types.Architecture)))
		countDevelopment := len(types.ReduceToOnlyStillAtRisk(filteredByRiskFunction(adoc.model, types.Development)))
		countOperation := len(types.ReduceToOnlyStillAtRisk(filteredByRiskFunction(adoc.model, types.Operations)))

		pieCharts := `[cols="a,a",frame=none,grid=none]
|===
|
[mermaid]
....
%%{init: {'pie' : {'textPosition' : 0.5}, 'theme': 'base', 'themeVariables': { 'pie1': '` + rgbHexColorCriticalRisk() + `', 'pie2': '` + rgbHexColorHighRisk() + `', 'pie3': '` + rgbHexColorElevatedRisk() + `', 'pie4': '` + rgbHexColorMediumRisk() + `', 'pie5': '` + rgbHexColorLowRisk() + `'}}}%%
pie showData
  "unmitigated critical risk" : ` + strconv.Itoa(countCritical) + `
  "unmitigated high risk" : ` + strconv.Itoa(countHigh) + `
  "unmitigated elevated risk" : ` + strconv.Itoa(countElevated) + `
  "unmitigated medium risk" : ` + strconv.Itoa(countMedium) + `
  "unmitigated low risk" : ` + strconv.Itoa(countLow) + `
....

|
[mermaid]
....
%%{init: {'pie' : {'textPosition' : 0.5}, 'theme': 'base', 'themeVariables': { 'pie1': '` + rgbHexColorBusiness() + `', 'pie2': '` + rgbHexColorArchitecture() + `', 'pie3': '` + rgbHexColorDevelopment() + `', 'pie4': '` + rgbHexColorOperation() + `'}}}%%
pie showData
  "business side related" : ` + strconv.Itoa(countBusinessSide) + `
  "architecture related" : ` + strconv.Itoa(countArchitecture) + `
  "development related" : ` + strconv.Itoa(countDevelopment) + `
  "operations related" : ` + strconv.Itoa(countOperation) + `
....
|===
`
		writeLine(f, pieCharts)
	}
}

func (adoc adocReport) writeRiskMitigationStatus() error {
	filename := "030_RiskMitigationStatus.adoc"
	rms, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = rms.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.riskMitigationStatus(rms)
	return nil
}

func (adoc adocReport) assetRegister(f *os.File) {
	writeLine(f, "= Asset Register")
	writeLine(f, "")

	writeLine(f, "== Technical Assets")
	writeLine(f, "")
	for _, technicalAsset := range sortedTechnicalAssetsByTitle(adoc.model) {

		fullLine := "<<" + technicalAsset.Id + ",*" + technicalAsset.Title + "*"
		if technicalAsset.OutOfScope {
			fullLine += ": out-of-scope"
		}
		writeLine(f, fullLine+">>::")
		writeLine(f, "  "+technicalAsset.Description)
		writeLine(f, "")
	}

	writeLine(f, "== Data Assets")
	writeLine(f, "")

	for _, dataAsset := range sortedDataAssetsByTitle(adoc.model) {
		writeLine(f, "<<dataAsset:"+dataAsset.Id+",*"+dataAsset.Title+"*"+">>::")
		writeLine(f, "  "+dataAsset.Description)
		writeLine(f, "")
	}
}

func (adoc adocReport) writeAssetRegister() error {
	filename := "035_AssetRegister.adoc"
	ar, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = ar.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.assetRegister(ar)
	return nil
}

func (adoc adocReport) writeImpactRemainingRisks() error {
	filename := "040_ImpactRemainingRisks.adoc"
	irr, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = irr.Close() }()
	if err != nil {
		return err
	}

	nRemaining := adoc.impactAnalysis(irr, false)
	if nRemaining > 0 || !adoc.hideEmptyChapter {
		adoc.writeMainLine("<<<")
		adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")
	}

	return nil
}

func (adoc adocReport) raa(f *os.File, introTextRAA string) {
	writeLine(f, "= RAA Analysis")
	writeLine(f, ":fn-risk-findings: footnote:riskfinding[Risk finding paragraphs are clickable and link to the corresponding chapter.]")
	writeLine(f, "")
	writeLine(f, fixBasicHtml(introTextRAA)+"{fn-risk-findings}")
	writeLine(f, "")

	for _, technicalAsset := range sortedTechnicalAssetsByRAAAndTitle(adoc.model) {
		if technicalAsset.OutOfScope {
			continue
		}
		newRisksStr := adoc.model.GeneratedRisks(technicalAsset)
		colorPrefix := ""
		switch types.HighestSeverityStillAtRisk(newRisksStr) {
		case types.HighSeverity:
			colorPrefix = "[HighRisk]#"
		case types.MediumSeverity:
			colorPrefix = "[MediumRisk]#"
		case types.LowSeverity:
			colorPrefix = "[LowRisk]#"
		default:
			colorPrefix = ""
		}
		if len(types.ReduceToOnlyStillAtRisk(newRisksStr)) == 0 {
			colorPrefix = ""
		}

		fullLine := "<<" + technicalAsset.Id + "," + colorPrefix + "*" + technicalAsset.Title + "*"
		if technicalAsset.OutOfScope {
			fullLine += ": out-of-scope"
		} else {
			fullLine += ": RAA " + fmt.Sprintf("%.0f", technicalAsset.RAA) + "%"
		}
		if len(colorPrefix) > 0 {
			fullLine += "#"
		}
		writeLine(f, fullLine+">>::")
		writeLine(f, "  "+technicalAsset.Description)
		writeLine(f, "")
	}
}

func (adoc adocReport) writeRAA(introTextRAA string) error {
	filename := "120_RAA.adoc"
	f, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.raa(f, introTextRAA)
	return nil
}

func (adoc adocReport) outOfScopeAssets(f *os.File) {
	assets := "Asset"
	count := len(adoc.model.OutOfScopeTechnicalAssets())
	if count > 1 {
		assets += "s"
	}
	writeLine(f, "= Out-of-Scope Assets: "+strconv.Itoa(count)+" "+assets)
	writeLine(f, ":fn-tech-assets: footnote:techAssets[Technical asset paragraphs are clickable and link to the corresponding chapter.]")
	writeLine(f, "")
	writeLine(f, `
This chapter lists all technical assets that have been defined as out-of-scope.
Each one should be checked in the model whether it should better be included in the overall risk analysis{fn-tech-assets}:
`)
	writeLine(f, "")

	outOfScopeAssetCount := 0
	for _, technicalAsset := range sortedTechnicalAssetsByRAAAndTitle(adoc.model) {
		if technicalAsset.OutOfScope {
			JustificationOutOfScope := technicalAsset.JustificationOutOfScope
			if len(JustificationOutOfScope) == 0 {
				JustificationOutOfScope = "Missing out of scope justification."
			}

			outOfScopeAssetCount++
			writeLine(f, "<<"+technicalAsset.Id+",[OutOfScope]#"+technicalAsset.Title+" : out-of-scope#>>::")
			writeLine(f, "  "+JustificationOutOfScope)
			writeLine(f, "")
		}
	}

	if outOfScopeAssetCount == 0 {
		writeLine(f, "[GreyText]#No technical assets have been defined as out-of-scope.#")
	}
}

func (adoc adocReport) writeOutOfScopeAssets() error {
	filename := "140_OutOfScopeAssets.adoc"
	f, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.outOfScopeAssets(f)
	return nil
}

func (adoc adocReport) modelFailures(f *os.File) {
	modelFailures := flattenRiskSlice(filterByModelFailures(adoc.model, adoc.model.GeneratedRisksByCategoryWithCurrentStatus()))
	count := len(modelFailures)
	countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(modelFailures))
	colorPrefix := ""
	colorSuffix := ""
	if countStillAtRisk > 0 {
		colorPrefix = "[ModelFailure]#"
		colorSuffix = "#"
	}
	suffix := riskSuffix(countStillAtRisk, count)
	writeLine(f, "= "+colorPrefix+"Potential Model Failures: "+suffix+colorSuffix)
	writeLine(f, ":fn-risk-findings: footnote:riskfinding[Risk finding paragraphs are clickable and link to the corresponding chapter.]")
	writeLine(f, "")

	writeLine(f, `
This chapter lists potential model failures where not all relevant assets have been
modeled or the model might itself contain inconsistencies. Each potential model failure should be checked
in the model against the architecture design:{fn-risk-findings}`)
	writeLine(f, "")

	modelFailuresByCategory := filterByModelFailures(adoc.model, adoc.model.GeneratedRisksByCategoryWithCurrentStatus())
	if len(modelFailuresByCategory) == 0 {
		writeLine(f, "No potential model failures have been identified.")
	} else {
		adoc.addCategories(f, modelFailuresByCategory, true, types.CriticalSeverity, true, true)
		adoc.addCategories(f, modelFailuresByCategory, true, types.HighSeverity, true, true)
		adoc.addCategories(f, modelFailuresByCategory, true, types.ElevatedSeverity, true, true)
		adoc.addCategories(f, modelFailuresByCategory, true, types.MediumSeverity, true, true)
		adoc.addCategories(f, modelFailuresByCategory, true, types.LowSeverity, true, true)
	}
}

func (adoc adocReport) writeModelFailures() error {
	filename := "150_ModelFailures.adoc"
	f, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.modelFailures(f)
	return nil
}
