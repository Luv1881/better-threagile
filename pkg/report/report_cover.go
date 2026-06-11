package report

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-pdf/fpdf/contrib/gofpdi"
	"github.com/threagile/threagile/pkg/types"
)

func (r *pdfReporter) createCover(parsedModel *types.Model) {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	r.pdf.AddPage()
	gofpdi.UseImportedTemplate(r.pdf, r.coverTemplateId, 0, 0, 0, 300)
	r.pdf.SetFont("Helvetica", "B", 28)
	r.pdf.SetTextColor(0, 0, 0)
	r.pdf.Text(40, 110, "Threat Model Report")
	r.pdf.Text(40, 125, uni(parsedModel.Title))
	r.pdf.SetFont("Helvetica", "", 12)
	reportDate := parsedModel.Date
	if reportDate.IsZero() {
		reportDate = types.Date{Time: time.Now()}
	}
	r.pdf.Text(40.7, 145, reportDate.Format("2 January 2006"))
	r.pdf.Text(40.7, 153, uni(parsedModel.Author.Name))
	r.pdf.SetFont("Helvetica", "", 10)
	r.pdf.SetTextColor(80, 80, 80)
	r.pdf.Text(8.6, 275, parsedModel.Author.Homepage)
	r.pdf.SetFont("Helvetica", "", 12)
	r.pdf.SetTextColor(0, 0, 0)
}

func (r *pdfReporter) createTableOfContents(parsedModel *types.Model) {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	r.pdf.AddPage()
	r.currentChapterTitleBreadcrumb = "Table of Contents"
	r.homeLink = r.pdf.AddLink()
	r.defineLinkTarget("{home}")
	gofpdi.UseImportedTemplate(r.pdf, r.contentTemplateId, 0, 0, 0, 300)
	r.pdf.SetFont("Helvetica", "B", fontSizeHeadline)
	r.pdf.Text(11, 40, "Table of Contents")
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	r.pdf.SetY(46)

	r.pdf.SetLineWidth(0.25)
	r.pdf.SetDrawColor(160, 160, 160)
	r.pdf.SetDashPattern([]float64{0.5, 0.5}, 0)

	// ===============

	var y float64 = 50
	r.pdf.SetFont("Helvetica", "B", fontSizeBody)
	r.pdf.Text(11, y, "Results Overview")
	r.pdf.SetFont("Helvetica", "", fontSizeBody)

	y += 6
	r.pdf.Text(11, y, "    "+"Management Summary")
	r.pdf.Text(175, y, "{management-summary}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	risksStr := "Risks"
	catStr := "Categories"
	count, catCount := totalRiskCount(parsedModel), len(parsedModel.GeneratedRisksByCategory)
	if count == 1 {
		risksStr = "Risk"
	}
	if catCount == 1 {
		catStr = "category"
	}
	y += 6
	r.pdf.Text(11, y, "    "+"Impact Analysis of "+strconv.Itoa(count)+" Initial "+risksStr+" in "+strconv.Itoa(catCount)+" "+catStr)
	r.pdf.Text(175, y, "{impact-analysis-initial-risks}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	y += 6
	r.pdf.Text(11, y, "    "+"Risk Mitigation")
	r.pdf.Text(175, y, "{risk-mitigation-status}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	y += 6
	r.pdf.Text(11, y, "    "+"Asset Register")
	r.pdf.Text(175, y, "{asset-register}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	y += 6
	risksStr = "Risks"
	catStr = "Categories"
	count, catCount = len(filteredByStillAtRisk(parsedModel)), len(reduceToOnlyStillAtRisk(parsedModel.GeneratedRisksByCategoryWithCurrentStatus()))
	if count == 1 {
		risksStr = "Risk"
	}
	if catCount == 1 {
		catStr = "category"
	}
	r.pdf.Text(11, y, "    "+"Impact Analysis of "+strconv.Itoa(count)+" Remaining "+risksStr+" in "+strconv.Itoa(catCount)+" "+catStr)
	r.pdf.Text(175, y, "{impact-analysis-remaining-risks}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	y += 6
	r.pdf.Text(11, y, "    "+"Application Overview")
	r.pdf.Text(175, y, "{target-overview}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	y += 6
	r.pdf.Text(11, y, "    "+"Data-Flow Diagram")
	r.pdf.Text(175, y, "{data-flow-diagram}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	y += 6
	r.pdf.Text(11, y, "    "+"Security Requirements")
	r.pdf.Text(175, y, "{security-requirements}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	y += 6
	r.pdf.Text(11, y, "    "+"Abuse Cases")
	r.pdf.Text(175, y, "{abuse-cases}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	y += 6
	r.pdf.Text(11, y, "    "+"Tag Listing")
	r.pdf.Text(175, y, "{tag-listing}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	y += 6
	r.pdf.Text(11, y, "    "+"STRIDE Classification of Identified Risks")
	r.pdf.Text(175, y, "{stride}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	y += 6
	r.pdf.Text(11, y, "    "+"Assignment by Function")
	r.pdf.Text(175, y, "{function-assignment}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	y += 6
	r.pdf.Text(11, y, "    "+"RAA Analysis")
	r.pdf.Text(175, y, "{raa-analysis}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	y += 6
	r.pdf.Text(11, y, "    "+"Data Mapping")
	r.pdf.Text(175, y, "{data-risk-mapping}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	/*
		y += 6
		assets := "assets"
		count = len(model.SortedTechnicalAssetsByQuickWinsAndTitle())
		if count == 1 {
			assets = "asset"
		}
		r.pdf.Text(11, y, "    "+"Data Risk Quick Wins: "+strconv.Itoa(count)+" "+assets)
		r.pdf.Text(175, y, "{data-risk-quick-wins}")
		r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
		r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())
	*/

	y += 6
	assets := "Assets"
	count = len(parsedModel.OutOfScopeTechnicalAssets())
	if count == 1 {
		assets = "Asset"
	}
	r.pdf.Text(11, y, "    "+"Out-of-Scope Assets: "+strconv.Itoa(count)+" "+assets)
	r.pdf.Text(175, y, "{out-of-scope-assets}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	y += 6
	modelFailures := flattenRiskSlice(filterByModelFailures(parsedModel, parsedModel.GeneratedRisksByCategory))
	risksStr = "Risks"
	count = len(modelFailures)
	if count == 1 {
		risksStr = "Risk"
	}
	countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(modelFailures))
	if countStillAtRisk > 0 {
		colorModelFailure(r.pdf)
	}
	r.pdf.Text(11, y, "    "+"Potential Model Failures: "+strconv.Itoa(countStillAtRisk)+" / "+strconv.Itoa(count)+" "+risksStr)
	r.pdf.Text(175, y, "{model-failures}")
	r.pdfColorBlack()
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	y += 6
	questions := "Questions"
	count = len(parsedModel.Questions)
	if count == 1 {
		questions = "Question"
	}
	if questionsUnanswered(parsedModel) > 0 {
		colorModelFailure(r.pdf)
	}
	r.pdf.Text(11, y, "    "+"Questions: "+strconv.Itoa(questionsUnanswered(parsedModel))+" / "+strconv.Itoa(count)+" "+questions)
	r.pdf.Text(175, y, "{questions}")
	r.pdfColorBlack()
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	// ===============

	if len(parsedModel.GeneratedRisksByCategory) > 0 {
		y += 6
		y += 6
		if y > 260 { // 260 instead of 275 for major group headlines to avoid "Schusterjungen"
			r.pageBreakInLists()
			y = 40
		}
		r.pdf.SetFont("Helvetica", "B", fontSizeBody)
		r.pdf.SetTextColor(0, 0, 0)
		r.pdf.Text(11, y, "Risks by Vulnerability category")
		r.pdf.SetFont("Helvetica", "", fontSizeBody)
		y += 6
		r.pdf.Text(11, y, "    "+"Identified Risks by Vulnerability category")
		r.pdf.Text(175, y, "{intro-risks-by-vulnerability-category}")
		r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
		r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())
		for _, category := range parsedModel.SortedRiskCategories() {
			newRisksStr := parsedModel.SortedRisksOfCategory(category)
			switch types.HighestSeverityStillAtRisk(newRisksStr) {
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
			if len(types.ReduceToOnlyStillAtRisk(newRisksStr)) == 0 {
				r.pdfColorBlack()
			}
			y += 6
			if y > 275 {
				r.pageBreakInLists()
				y = 40
			}
			countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(newRisksStr))
			suffix := strconv.Itoa(countStillAtRisk) + " / " + strconv.Itoa(len(newRisksStr)) + " Risk"
			if len(newRisksStr) != 1 {
				suffix += "s"
			}
			r.pdf.Text(11, y, "    "+uni(category.Title)+": "+suffix)
			r.pdf.Text(175, y, "{"+category.ID+"}")
			r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
			r.tocLinkIdByAssetId[category.ID] = r.pdf.AddLink()
			r.pdf.Link(10, y-5, 172.5, 6.5, r.tocLinkIdByAssetId[category.ID])
		}
	}

	// ===============

	if len(parsedModel.TechnicalAssets) > 0 {
		y += 6
		y += 6
		if y > 260 { // 260 instead of 275 for major group headlines to avoid "Schusterjungen"
			r.pageBreakInLists()
			y = 40
		}
		r.pdf.SetFont("Helvetica", "B", fontSizeBody)
		r.pdf.SetTextColor(0, 0, 0)
		r.pdf.Text(11, y, "Risks by Technical Asset")
		r.pdf.SetFont("Helvetica", "", fontSizeBody)
		y += 6
		r.pdf.Text(11, y, "    "+"Identified Risks by Technical Asset")
		r.pdf.Text(175, y, "{intro-risks-by-technical-asset}")
		r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
		r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())
		for _, technicalAsset := range sortedTechnicalAssetsByRiskSeverityAndTitle(parsedModel) {
			newRisksStr := parsedModel.GeneratedRisks(technicalAsset)
			y += 6
			if y > 275 {
				r.pageBreakInLists()
				y = 40
			}
			countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(newRisksStr))
			suffix := strconv.Itoa(countStillAtRisk) + " / " + strconv.Itoa(len(newRisksStr)) + " Risk"
			if len(newRisksStr) != 1 {
				suffix += "s"
			}
			if technicalAsset.OutOfScope {
				r.pdfColorOutOfScope()
				suffix = "out-of-scope"
			} else {
				switch types.HighestSeverityStillAtRisk(newRisksStr) {
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
				if len(types.ReduceToOnlyStillAtRisk(newRisksStr)) == 0 {
					r.pdfColorBlack()
				}
			}
			r.pdf.Text(11, y, "    "+uni(technicalAsset.Title)+": "+suffix)
			r.pdf.Text(175, y, "{"+technicalAsset.Id+"}")
			r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
			r.tocLinkIdByAssetId[technicalAsset.Id] = r.pdf.AddLink()
			r.pdf.Link(10, y-5, 172.5, 6.5, r.tocLinkIdByAssetId[technicalAsset.Id])
		}
	}

	// ===============

	if len(parsedModel.DataAssets) > 0 {
		y += 6
		y += 6
		if y > 260 { // 260 instead of 275 for major group headlines to avoid "Schusterjungen"
			r.pageBreakInLists()
			y = 40
		}
		r.pdf.SetFont("Helvetica", "B", fontSizeBody)
		r.pdfColorBlack()
		r.pdf.Text(11, y, "Data Breach Probabilities by Data Asset")
		r.pdf.SetFont("Helvetica", "", fontSizeBody)
		y += 6
		r.pdf.Text(11, y, "    "+"Identified Data Breach Probabilities by Data Asset")
		r.pdf.Text(175, y, "{intro-risks-by-data-asset}")
		r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
		r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())
		for _, dataAsset := range sortedDataAssetsByDataBreachProbabilityAndTitle(parsedModel) {
			y += 6
			if y > 275 {
				r.pageBreakInLists()
				y = 40
			}
			newRisksStr := parsedModel.IdentifiedDataBreachProbabilityRisks(dataAsset)
			countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(newRisksStr))
			suffix := strconv.Itoa(countStillAtRisk) + " / " + strconv.Itoa(len(newRisksStr)) + " Risk"
			if len(newRisksStr) != 1 {
				suffix += "s"
			}
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
			r.pdf.Text(11, y, "    "+uni(dataAsset.Title)+": "+suffix)
			r.pdf.Text(175, y, "{data:"+dataAsset.Id+"}")
			r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
			r.tocLinkIdByAssetId[dataAsset.Id] = r.pdf.AddLink()
			r.pdf.Link(10, y-5, 172.5, 6.5, r.tocLinkIdByAssetId[dataAsset.Id])
		}
	}

	// ===============

	if len(parsedModel.TrustBoundaries) > 0 {
		y += 6
		y += 6
		if y > 260 { // 260 instead of 275 for major group headlines to avoid "Schusterjungen"
			r.pageBreakInLists()
			y = 40
		}
		r.pdf.SetFont("Helvetica", "B", fontSizeBody)
		r.pdfColorBlack()
		r.pdf.Text(11, y, "Trust Boundaries")
		r.pdf.SetFont("Helvetica", "", fontSizeBody)
		for _, key := range sortedKeysOfTrustBoundaries(parsedModel) {
			trustBoundary := parsedModel.TrustBoundaries[key]
			y += 6
			if y > 275 {
				r.pageBreakInLists()
				y = 40
			}
			colorTwilight(r.pdf)
			if !trustBoundary.Type.IsNetworkBoundary() {
				r.pdfColorLightGray()
			}
			r.pdf.Text(11, y, "    "+uni(trustBoundary.Title))
			r.pdf.Text(175, y, "{boundary:"+trustBoundary.Id+"}")
			r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
			r.tocLinkIdByAssetId[trustBoundary.Id] = r.pdf.AddLink()
			r.pdf.Link(10, y-5, 172.5, 6.5, r.tocLinkIdByAssetId[trustBoundary.Id])
		}
		r.pdfColorBlack()
	}

	// ===============

	if len(parsedModel.SharedRuntimes) > 0 {
		y += 6
		y += 6
		if y > 260 { // 260 instead of 275 for major group headlines to avoid "Schusterjungen"
			r.pageBreakInLists()
			y = 40
		}
		r.pdf.SetFont("Helvetica", "B", fontSizeBody)
		r.pdfColorBlack()
		r.pdf.Text(11, y, "Shared Runtime")
		r.pdf.SetFont("Helvetica", "", fontSizeBody)
		for _, key := range sortedKeysOfSharedRuntime(parsedModel) {
			sharedRuntime := parsedModel.SharedRuntimes[key]
			y += 6
			if y > 275 {
				r.pageBreakInLists()
				y = 40
			}
			r.pdf.Text(11, y, "    "+uni(sharedRuntime.Title))
			r.pdf.Text(175, y, "{runtime:"+sharedRuntime.Id+"}")
			r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
			r.tocLinkIdByAssetId[sharedRuntime.Id] = r.pdf.AddLink()
			r.pdf.Link(10, y-5, 172.5, 6.5, r.tocLinkIdByAssetId[sharedRuntime.Id])
		}
	}

	// ===============

	y += 6
	y += 6
	if y > 260 { // 260 instead of 275 for major group headlines to avoid "Schusterjungen"
		r.pageBreakInLists()
		y = 40
	}
	r.pdfColorBlack()
	r.pdf.SetFont("Helvetica", "B", fontSizeBody)
	r.pdf.Text(11, y, "About Threagile")
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	y += 6
	if y > 275 {
		r.pageBreakInLists()
		y = 40
	}
	r.pdf.Text(11, y, "    "+"Risk Rules Checked by Threagile")
	r.pdf.Text(175, y, "{risk-rules-checked}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())
	y += 6
	if y > 275 {
		r.pageBreakInLists()
		y = 40
	}
	r.pdfColorDisclaimer()
	r.pdf.Text(11, y, "    "+"Disclaimer")
	r.pdf.Text(175, y, "{disclaimer}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())
	r.pdfColorBlack()

	r.pdf.SetDrawColor(0, 0, 0)
	r.pdf.SetDashPattern([]float64{}, 0)

	// Now write all the sections/pages. Before we start writing, we use `RegisterAlias` to
	// ensure that the alias written in the table of contents will be replaced
	// by the current page number. --> See the "r.pdf.RegisterAlias()" calls during the PDF creation in this file
}

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:

func sortedKeysOfTrustBoundaries(model *types.Model) []string {
	keys := make([]string, 0)
	for k := range model.TrustBoundaries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:

func sortedKeysOfSharedRuntime(model *types.Model) []string {
	keys := make([]string, 0)
	for k := range model.SharedRuntimes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (r *pdfReporter) createDisclaimer(parsedModel *types.Model) {
	r.pdf.AddPage()
	r.currentChapterTitleBreadcrumb = "Disclaimer"
	r.defineLinkTarget("{disclaimer}")
	gofpdi.UseImportedTemplate(r.pdf, r.contentTemplateId, 0, 0, 0, 300)
	r.pdfColorDisclaimer()
	r.pdf.SetFont("Helvetica", "B", fontSizeHeadline)
	r.pdf.Text(11, 40, "Disclaimer")
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	r.pdf.SetY(46)

	var disclaimer strings.Builder
	disclaimer.WriteString(parsedModel.Author.Name + " conducted this threat analysis using the open-source Threagile toolkit " +
		"on the applications and systems that were modeled as of this report's date. " +
		"Information security threats are continually changing, with new " +
		"vulnerabilities discovered on a daily basis, and no application can ever be 100% secure no matter how much " +
		"threat modeling is conducted. It is recommended to execute threat modeling and also penetration testing on a regular basis " +
		"(for example yearly) to ensure a high ongoing level of security and constantly check for new attack vectors. " +
		"<br><br>" +
		"This report cannot and does not protect against personal or business loss as the result of use of the " +
		"applications or systems described. " + parsedModel.Author.Name + " and the Threagile toolkit offers no warranties, representations or " +
		"legal certifications concerning the applications or systems it tests. All software includes defects: nothing " +
		"in this document is intended to represent or warrant that threat modeling was complete and without error, " +
		"nor does this document represent or warrant that the architecture analyzed is suitable to task, free of other " +
		"defects than reported, fully compliant with any industry standards, or fully compatible with any operating " +
		"system, hardware, or other application. Threat modeling tries to analyze the modeled architecture without " +
		"having access to a real working system and thus cannot and does not test the implementation for defects and vulnerabilities. " +
		"These kinds of checks would only be possible with a separate code review and penetration test against " +
		"a working system and not via a threat model." +
		"<br><br>" +
		"By using the resulting information you agree that " + parsedModel.Author.Name + " and the Threagile toolkit " +
		"shall be held harmless in any event." +
		"<br><br>" +
		"This report is confidential and intended for internal, confidential use by the client. The recipient " +
		"is obligated to ensure the highly confidential contents are kept secret. The recipient assumes responsibility " +
		"for further distribution of this document." +
		"<br><br>" +
		"In this particular project, a time box approach was used to define the analysis effort. This means that the " +
		"author allotted a prearranged amount of time to identify and document threats. Because of this, there " +
		"is no guarantee that all possible threats and risks are discovered. Furthermore, the analysis " +
		"applies to a snapshot of the current state of the modeled architecture (based on the architecture information provided " +
		"by the customer) at the examination time." +
		"<br><br><br>" +
		"<b>Report Distribution</b>" +
		"<br><br>" +
		"Distribution of this report (in full or in part like diagrams or risk findings) requires that this disclaimer " +
		"as well as the chapter about the Threagile toolkit and method used is kept intact as part of the " +
		"distributed report or referenced from the distributed parts.")
	html := r.pdf.HTMLBasicNew()
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	html.Write(5, uni(disclaimer.String()))
	r.pdfColorBlack()
}
