package report

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/threagile/threagile/pkg/types"
)

func (adoc adocReport) riskTrackingStatus(f *os.File, risk *types.Risk) {
	tracking := adoc.model.GetRiskTrackingWithDefault(risk)

	colorName := ""
	switch tracking.Status {
	case types.Unchecked:
		colorName = "RiskStatusUnchecked"
	case types.InDiscussion:
		colorName = "RiskStatusInDiscussion"
	case types.Accepted:
		colorName = "RiskStatusAccepted"
	case types.InProgress:
		colorName = "RiskStatusInProgress"
	case types.Mitigated:
		colorName = "RiskStatusMitigated"
	case types.FalsePositive:
		colorName = "RiskStatusFalsePositive"
	default:
		colorName = ""
	}
	bold := ""
	if tracking.Status == types.Unchecked {
		bold = "*"
	}

	if tracking.Status != types.Unchecked {
		dateStr := tracking.Date.Format("2006-01-02")
		if dateStr == "0001-01-01" {
			dateStr = ""
		}
		justificationStr := tracking.Justification
		ticket := tracking.Ticket
		if len(ticket) == 0 {
			ticket = "-"
		}
		writeLine(f, `
[cols="a,c,c,2c",frame=none,grid=none,options="unbreakable"]
|===
| [.`+colorName+`.small]#`+bold+tracking.Status.Title()+bold+`#
| [.GreyText.small]#`+dateStr+`#
| [.GreyText.small]#`+tracking.CheckedBy+`#
| [.GreyText.small]#`+ticket+`#

4+|[.small]#`+justificationStr+`#
|===
`)
	} else {
		writeLine(f, `
[cols="a,c,c,2c",frame=none,grid=none,options="unbreakable"]
|===
4+| [.`+colorName+`.small]#`+bold+tracking.Status.Title()+bold+`#
|===
`)
	}
}

func (adoc adocReport) riskCategories(f *os.File) {
	writeLine(f, "= Identified Risks by Vulnerability category")
	writeLine(f, "In total *"+strconv.Itoa(totalRiskCount(adoc.model))+" potential risks* have been identified during the threat modeling process "+
		"of which "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.CriticalSeverity)))+" are rated as critical*, "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.HighSeverity)))+" as high*, "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.ElevatedSeverity)))+" as elevated*, "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.MediumSeverity)))+" as medium*, "+
		"and *"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.LowSeverity)))+" as low*. "+
		"\n\nThese risks are distributed across *"+strconv.Itoa(len(adoc.model.GeneratedRisksByCategory))+" vulnerability categories*. ")
	writeLine(f, "The following sub-chapters of this section describe each identified risk category.") // TODO more explanation text
	writeLine(f, "")

	for _, category := range adoc.model.SortedRiskCategories() {
		risksStr := adoc.model.SortedRisksOfCategory(category)

		// category color
		colorPrefix, colorSuffix := colorPrefixBySeverity(types.HighestSeverityStillAtRisk(risksStr), false)
		if len(types.ReduceToOnlyStillAtRisk(risksStr)) == 0 {
			colorPrefix = ""
			colorSuffix = ""
		}

		// category title
		countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(risksStr))
		suffix := riskSuffix(countStillAtRisk, len(risksStr))
		title := colorPrefix + category.Title + ": " + suffix + colorSuffix
		writeLine(f, "[["+category.ID+"]]")
		writeLine(f, "== "+title)
		writeLine(f, "")

		// category details
		cweLink := "n/a"
		if category.CWE > 0 {
			cweLink = "https://cwe.mitre.org/data/definitions/" + strconv.Itoa(category.CWE) + ".html[CWE " +
				strconv.Itoa(category.CWE) + "]"
		}
		writeLine(f, "*Description* ("+category.STRIDE.Title()+"): "+cweLink+"::")
		writeLine(f, fixBasicHtml(category.Description))
		writeLine(f, "")
		writeLine(f, "*Impact*::")
		writeLine(f, fixBasicHtml(category.Impact))
		writeLine(f, "")
		writeLine(f, "*Detection Logic*::")
		writeLine(f, fixBasicHtml(category.DetectionLogic))
		writeLine(f, "")
		writeLine(f, "*Risk Rating*::")
		writeLine(f, fixBasicHtml(category.RiskAssessment))
		writeLine(f, "")

		writeLine(f, "[RiskStatusFalsePositive]#*False Positives*#::")
		if len(category.FalsePositives) > 0 {
			writeLine(f, "[RiskStatusFalsePositive]#"+category.FalsePositives+"#")
		}
		writeLine(f, "")

		writeLine(f, "[RiskStatusMitigated]#*Mitigation*# ("+category.Function.Title()+"): "+category.Action+"::")
		writeLine(f, fixBasicHtml(category.Mitigation))
		writeLine(f, "")

		asvsChapter := category.ASVS
		asvsLink := "n/a"
		if len(asvsChapter) > 0 {
			asvsLink = "https://owasp.org/www-project-application-security-verification-standard/[" + asvsChapter + "]"
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
			cheatSheetLink = cheatSheetLink + "[" + linkText + "]"
		}
		writeLine(f, "")
		writeLine(f, "* [RiskStatusMitigated]#ASVS Chapter#: "+asvsLink)
		writeLine(f, "* [RiskStatusMitigated]#Cheat Sheet#: "+cheatSheetLink)
		writeLine(f, "\n\n*Check*\n")
		writeLine(f, category.Check)

		// risk details
		writeLine(f, "")
		writeLine(f, "=== Risk Findings")
		writeLine(f, ":fn-risk-findings: footnote:riskfinding[Risk finding paragraphs are clickable and link to the corresponding chapter.]")
		times := strconv.Itoa(len(risksStr)) + " time"
		if len(risksStr) > 1 {
			times += "s"
		}
		writeLine(f, "")
		writeLine(f, "The risk *"+category.Title+"* was found *"+times+"* in the analyzed architecture to be "+
			"potentially possible. Each spot should be checked individually by reviewing the implementation whether all "+
			"controls have been applied properly in order to mitigate each risk.{fn-risk-findings}")

		for _, risk := range risksStr {
			colorPrefix, colorSuffix := colorPrefixBySeverity(risk.Severity, false)
			if len(colorPrefix) == 0 {
				colorSuffix = ""
			}

			title := titleOfSeverity(risk.Severity)
			if len(title) > 0 {
				writeLine(f, "")
				writeLine(f, "==== "+colorPrefix+"_"+title+"_"+colorSuffix)
			}

			if !risk.RiskStatus.IsStillAtRisk() {
				colorPrefix = ""
				colorSuffix = ""
			}
			writeLine(f, colorPrefix+fixBasicHtml(risk.Title)+": Exploitation likelihood is _"+risk.ExploitationLikelihood.Title()+"_ with _"+risk.ExploitationImpact.Title()+"_ impact."+colorSuffix)
			linkId := ""
			if len(risk.MostRelevantSharedRuntimeId) > 0 {
				linkId = risk.MostRelevantSharedRuntimeId
			} else if len(risk.MostRelevantTrustBoundaryId) > 0 {
				linkId = risk.MostRelevantTrustBoundaryId
			} else if len(risk.MostRelevantTechnicalAssetId) > 0 {
				linkId = risk.MostRelevantTechnicalAssetId
			}
			writeLine(f, "")
			writeLine(f, "<<"+linkId+",[SmallGrey]#"+risk.SyntheticId+"#>>")

			adoc.riskTrackingStatus(f, risk)
		}
	}
}

func (adoc adocReport) writeRiskCategories() error {
	filename := "170_RiskCategories.adoc"
	f, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.riskCategories(f)
	return nil
}
