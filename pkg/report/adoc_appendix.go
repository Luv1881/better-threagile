package report

import (
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/threagile/threagile/pkg/types"
)

func (adoc adocReport) riskRulesChecked(f *os.File, modelFilename string, skipRiskRules []string, buildTimestamp string, threagileVersion string, modelHash string, customRiskRules types.RiskRules) {
	writeLine(f, "= Risk Rules Checked by Threagile")
	writeLine(f, "")
	timestamp := time.Now()
	writeLine(f, `
[cols="h,1",frame=none,grid=none]
|===
| Threagile Version:             | `+threagileVersion+`
| Threagile Build Timestamp:     | `+buildTimestamp+`
| Threagile Execution Timestamp: | `+timestamp.Format("20060102150405")+`
| Model Filename:                | `+modelFilename+`
| Model Hash (SHA256):           | `+modelHash+`
|===
`)
	writeLine(f, "\n\n")
	writeLine(f, "Threagile (see https://threagile.io[] for more details) is an open-source toolkit for agile threat modeling, created by Christian Schneider (https://christian-schneider.net[]): It allows to model an architecture with its assets in an agile fashion as a YAML file "+
		"directly inside the IDE. Upon execution of the Threagile toolkit all standard risk rules (as well as individual custom rules if present) "+
		"are checked against the architecture model. At the time the Threagile toolkit was executed on the model input file "+
		"the following risk rules were checked:")
	writeLine(f, "")

	// TODO use the new run system to discover risk rules instead of hard-coding them here:
	skipped := ""

	for id, customRule := range customRiskRules {
		if contains(skipRiskRules, id) {
			skipped = "SKIPPED - "
		} else {
			skipped = ""
		}
		writeLine(f, "== "+skipped+customRule.Category().Title)
		writeLine(f, "[.small]#"+id+"#")
		writeLine(f, "")
		writeLine(f, "_Custom Risk Rule_")
		writeLine(f, `
[cols="h,1",frame=none,grid=none]
|===
| STRIDE:      | `+customRule.Category().STRIDE.Title()+`
| Description: | `+firstParagraph(customRule.Category().Description)+`
| Detection:   | `+customRule.Category().DetectionLogic+`
| Rating:      | `+customRule.Category().RiskAssessment+`
|===
`)
	}

	sort.Sort(types.ByRiskCategoryTitleSort(adoc.model.CustomRiskCategories))
	for _, individualRiskCategory := range adoc.model.CustomRiskCategories {
		writeLine(f, "== "+individualRiskCategory.Title)
		writeLine(f, "[.small]#"+individualRiskCategory.ID+"#")
		writeLine(f, "")
		writeLine(f, "_Individual Risk category_")
		writeLine(f, `
[cols="h,1",frame=none,grid=none]
|===
| STRIDE:      | `+individualRiskCategory.STRIDE.Title()+`
| Description: | `+firstParagraph(individualRiskCategory.Description)+`
| Detection:   | `+individualRiskCategory.DetectionLogic+`
| Rating:      | `+individualRiskCategory.RiskAssessment+`
|===
`)
	}

	for _, rule := range adoc.riskRules {
		if contains(skipRiskRules, rule.Category().ID) {
			skipped = "SKIPPED - "
		} else {
			skipped = ""
		}
		writeLine(f, "== "+skipped+rule.Category().Title)
		writeLine(f, "[.small]#"+rule.Category().ID+"#")
		writeLine(f, "")
		writeLine(f, `
[cols="h,1",frame=none,grid=none]
|===
| STRIDE:      | `+rule.Category().STRIDE.Title()+`
| Description: | `+firstParagraph(rule.Category().Description)+`
| Detection:   | `+rule.Category().DetectionLogic+`
| Rating:      | `+rule.Category().RiskAssessment+`
|===
`)
	}
}

func (adoc adocReport) writeRiskRulesChecked(modelFilename string, skipRiskRules []string, buildTimestamp string, threagileVersion string, modelHash string, customRiskRules types.RiskRules) error {
	filename := "220_RiskRulesChecked.adoc"
	f, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.riskRulesChecked(f, modelFilename, skipRiskRules, buildTimestamp, threagileVersion, modelHash, customRiskRules)
	return nil
}

func (adoc adocReport) appendixRating(f *os.File) {
	writeLine(f, "[appendix]")
	writeLine(f, "= Ratings")

	confValues := map[types.Confidentiality]string{
		types.Public:               "1",
		types.Internal:             "2",
		types.Restricted:           "3",
		types.Confidential:         "4",
		types.StrictlyConfidential: "5",
	}

	critValues := map[types.Criticality]string{
		types.Archive:         "1",
		types.Operational:     "2",
		types.Important:       "3",
		types.Critical:        "4",
		types.MissionCritical: "5",
	}

	writeLine(f, "")
	writeLine(f, "[[ref-confidentiality-values]]")
	writeLine(f, ".Confidentiality Values")
	writeLine(f, "[%header,cols=\"3,1,8\"]")
	writeLine(f, "|===")
	writeLine(f, "| Name | Value | Description")
	writeLine(f, "")
	for key, value := range confValues {
		writeLine(f, "| "+key.String()+" | "+value+" | "+key.Explain())
	}
	writeLine(f, "|===")
	writeLine(f, "")

	writeLine(f, "[[ref-criticality-values]]")
	writeLine(f, ".Criticality Values")
	writeLine(f, "[%header,cols=\"3,1,8\"]")
	writeLine(f, "|===")
	writeLine(f, "| Name | Value | Description")
	writeLine(f, "")
	for key, value := range critValues {
		writeLine(f, "| "+key.String()+" | "+value+" | "+key.Explain())
	}
	writeLine(f, "|===")
}

func (adoc adocReport) writeAppendixRating() error {
	filename := "400_AppendixRating.adoc"
	f, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.appendixRating(f)
	return nil
}

func (adoc adocReport) disclaimer(f *os.File) {
	writeLine(f, "[appendix]")
	writeLine(f, "= Disclaimer")

	disclaimerColor := "\n[.Silver]\n"

	writeLine(f, disclaimerColor+
		adoc.model.Author.Name+" conducted this threat analysis using the open-source Threagile toolkit "+
		"on the applications and systems that were modeled as of this report's date. "+
		"Information security threats are continually changing, with new "+
		"vulnerabilities discovered on a daily basis, and no application can ever be 100% secure no matter how much "+
		"threat modeling is conducted. It is recommended to execute threat modeling and also penetration testing on a regular basis "+
		"(for example yearly) to ensure a high ongoing level of security and constantly check for new attack vectors. "+
		"\n\n"+
		disclaimerColor+
		"This report cannot and does not protect against personal or business loss as the result of use of the "+
		"applications or systems described. "+adoc.model.Author.Name+" and the Threagile toolkit offers no warranties, representations or "+
		"legal certifications concerning the applications or systems it tests. All software includes defects: nothing "+
		"in this document is intended to represent or warrant that threat modeling was complete and without error, "+
		"nor does this document represent or warrant that the architecture analyzed is suitable to task, free of other "+
		"defects than reported, fully compliant with any industry standards, or fully compatible with any operating "+
		"system, hardware, or other application. Threat modeling tries to analyze the modeled architecture without "+
		"having access to a real working system and thus cannot and does not test the implementation for defects and vulnerabilities. "+
		"These kinds of checks would only be possible with a separate code review and penetration test against "+
		"a working system and not via a threat model."+
		"\n\n"+
		disclaimerColor+
		"By using the resulting information you agree that "+adoc.model.Author.Name+" and the Threagile toolkit "+
		"shall be held harmless in any event."+
		"\n\n"+
		disclaimerColor+
		"This report is confidential and intended for internal, confidential use by the client. The recipient "+
		"is obligated to ensure the highly confidential contents are kept secret. The recipient assumes responsibility "+
		"for further distribution of this document."+
		"\n\n"+
		disclaimerColor+
		"In this particular project, a time box approach was used to define the analysis effort. This means that the "+
		"author allotted a prearranged amount of time to identify and document threats. Because of this, there "+
		"is no guarantee that all possible threats and risks are discovered. Furthermore, the analysis "+
		"applies to a snapshot of the current state of the modeled architecture (based on the architecture information provided "+
		"by the customer) at the examination time."+
		"\n\n"+
		"== Report Distribution"+
		disclaimerColor+
		"Distribution of this report (in full or in part like diagrams or risk findings) requires that this disclaimer "+
		"as well as the chapter about the Threagile toolkit and method used is kept intact as part of the "+
		"distributed report or referenced from the distributed parts.")
}

func (adoc adocReport) writeDisclaimer() error {
	filename := "500_Disclaimer.adoc"
	f, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.disclaimer(f)
	return nil
}
