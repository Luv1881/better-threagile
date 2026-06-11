package report

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/threagile/threagile/pkg/types"
)

type adocReport struct {
	targetDirectory string
	model           *types.Model
	mainFile        *os.File
	imagesDir       string

	riskRules types.RiskRules

	iconsType        string
	tocDepth         int
	hideEmptyChapter bool
}

func copyFile(source string, destination string) error {
	/* #nosec source is not tainted (see caller restricting it to files we created ourself or are legitimate to be copied) */
	src, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()
	/* #nosec destination is not tainted (see caller restricting it to the desired report output folder) */
	dst, err := os.Create(destination)
	if err != nil {
		return err
	}
	defer func() { _ = dst.Close() }()
	_, err = io.Copy(dst, src)
	if err != nil {
		return err
	}
	return nil
}

func fixBasicHtml(inputWithHtml string) string {
	result := strings.ReplaceAll(inputWithHtml, "<b>", "*")
	result = strings.ReplaceAll(result, "</b>", "*")

	result = strings.ReplaceAll(result, "<i>", "_")
	result = strings.ReplaceAll(result, "</i>", "_")

	result = strings.ReplaceAll(result, "<u>", "[.underline]#")
	result = strings.ReplaceAll(result, "</u>", "#")

	result = strings.ReplaceAll(result, "<br>", "\n")
	result = strings.ReplaceAll(result, "</br>", "\n")

	linkAndName := regexp.MustCompile(`<a href=\"(.*)\".*>(.*)</a>`)
	result = linkAndName.ReplaceAllString(result, "${1}[${2}]")
	return result
}

func NewAdocReport(targetDirectory string, riskRules types.RiskRules, hideEmptyChapter bool) adocReport {
	adoc := adocReport{
		targetDirectory:  filepath.Join(targetDirectory, "adocReport"),
		iconsType:        "font",
		tocDepth:         2,
		imagesDir:        filepath.Join(targetDirectory, "adocReport", "images"),
		riskRules:        riskRules,
		hideEmptyChapter: hideEmptyChapter,
	}
	return adoc
}

func writeLine(file *os.File, line string) {
	_, err := file.WriteString(line + "\n")
	if err != nil {
		log.Fatal("Could not write »" + line + "« into: " + file.Name() + ": " + err.Error())
	}
}

func (adoc adocReport) writeDefaultTheme(logoImagePath string) error {
	err := os.MkdirAll(filepath.Join(adoc.targetDirectory, "theme"), 0750)
	if err != nil {
		return err
	}
	err = os.MkdirAll(adoc.imagesDir, 0750)
	if err != nil {
		return err
	}
	theme, err := os.Create(filepath.Join(adoc.targetDirectory, "theme", "pdf-theme.yml"))
	defer func() { _ = theme.Close() }()
	if err != nil {
		return err
	}
	adocLogoPath := ""
	if logoImagePath != "" {
		if _, err := os.Stat(logoImagePath); err == nil {
			suffix := filepath.Ext(logoImagePath)
			adocLogoPath = "logo" + suffix
			logoDestPath := filepath.Join(adoc.targetDirectory, "theme", adocLogoPath)
			err = copyFile(logoImagePath, logoDestPath)
			if err != nil {
				log.Fatal("Could not copy file: »" + logoImagePath + "« to »" + logoDestPath + "«: " + err.Error())
			}
		} else {
			log.Println("logo image path does not exist: " + logoImagePath)
		}
	}

	writeLine(theme, `extends: default
page:
  layout: portrait
  margin: [3cm, 2.5cm, 2.7cm, 2.5cm]
title-page:
  authors:
    content: "{author}, {author-homepage}[]"
`)
	if adocLogoPath != "" {
		writeLine(theme,
			`  logo:
    image: image:`+adocLogoPath+`[]`)
	}
	writeLine(theme,
		`header:
  height: 2cm
  line-height: 1
  recto:
    center:
      content: "{document-title} -- `+adoc.model.Title+` -- {section-or-chapter-title}"
  verso:
    center:
      content: "{document-title} -- `+adoc.model.Title+` -- {section-or-chapter-title}"
footer:
  height: 2cm
  line-height: 1.2
  recto:
    center:
      content: -- confidential --
    left:
      content: "Version: {DOC_VERSION}"
    right:
      content: "Page {page-number} of {page-count}"
  verso:
    center:
      content: -- confidential --
    left:
      content: "Version: {DOC_VERSION}"
    right:
      content: Page {page-number} of {page-count}
role:
  LowRisk:
    font-color: `+rgbHexColorLowRisk()+`
  MediumRisk:
    font-color: `+rgbHexColorMediumRisk()+`
  ElevatedRisk:
    font-color: `+rgbHexColorElevatedRisk()+`
  HighRisk:
    font-color: `+rgbHexColorHighRisk()+`
  CriticalRisk:
    font-color: `+rgbHexColorCriticalRisk()+`
  OutOfScope:
    font-color: #7f7f7f
  GreyText:
    font-color: #505050
  LightGreyText:
    font-color: #646464
  ModelFailure:
    font-color: #945200
  RiskStatusFalsePositive:
    font-color: `+rgbHexColorRiskStatusFalsePositive()+`
  RiskStatusMitigated:
    font-color: `+rgbHexColorRiskStatusMitigated()+`
  RiskStatusInProgress:
    font-color: `+rgbHexColorRiskStatusInProgress()+`
  RiskStatusAccepted:
    font-color: `+rgbHexColorRiskStatusAccepted()+`
  RiskStatusInDiscussion:
    font-color: `+rgbHexColorRiskStatusInDiscussion()+`
  RiskStatusUnchecked:
    font-color: `+RgbHexColorRiskStatusUnchecked()+`
  Twilight:
    font-color: `+rgbHexColorTwilight()+`
  SmallGrey:
    font-size: 0.5em
    font-color: #505050
  Silver:
    font-color: #C0C0C0
`)

	return nil
}

func (adoc adocReport) writeMainLine(line string) {
	writeLine(adoc.mainFile, line)
}

func (adoc adocReport) WriteReport(model *types.Model,
	dataFlowDiagramFilenamePNG string,
	dataAssetDiagramFilenamePNG string,
	modelFilename string,
	skipRiskRules []string,
	buildTimestamp string,
	threagileVersion string,
	modelHash string,
	introTextRAA string,
	customRiskRules types.RiskRules,
	logoImagePath string,
	hideChapters map[ChaptersToShowHide]bool) error {

	adoc.model = model
	err := adoc.initReport()
	if err != nil {
		return err
	}
	err = adoc.writeDefaultTheme(logoImagePath)
	if err != nil {
		return err
	}
	adoc.writeTitleAndPreamble()
	err = adoc.writeManagementSummery()
	if err != nil {
		return err
	}

	err = adoc.writeImpactInitialRisks()
	if err != nil {
		return fmt.Errorf("error creating impact initial risks: %w", err)
	}
	err = adoc.writeRiskMitigationStatus()
	if err != nil {
		return fmt.Errorf("error creating risk mitigation status: %w", err)
	}
	if val := hideChapters[AssetRegister]; !val {
		err = adoc.writeAssetRegister()
		if err != nil {
			return fmt.Errorf("error creating asset register status: %w", err)
		}
	}
	err = adoc.writeImpactRemainingRisks()
	if err != nil {
		return fmt.Errorf("error creating impact remaining risks: %w", err)
	}
	err = adoc.writeTargetDescription(filepath.Dir(modelFilename))
	if err != nil {
		return fmt.Errorf("error creating target description: %w", err)
	}
	err = adoc.writeDataFlowDiagram(dataFlowDiagramFilenamePNG)
	if err != nil {
		return fmt.Errorf("error creating data flow diagram section: %w", err)
	}
	err = adoc.writeSecurityRequirements()
	if err != nil {
		return fmt.Errorf("error creating security requirements: %w", err)
	}
	err = adoc.writeAbuseCases()
	if err != nil {
		return fmt.Errorf("error creating abuse cases: %w", err)
	}
	err = adoc.writeTagListing()
	if err != nil {
		return fmt.Errorf("error creating tag listing: %w", err)
	}
	err = adoc.writeSTRIDE()
	if err != nil {
		return fmt.Errorf("error creating STRIDE: %w", err)
	}
	err = adoc.writeAssignmentByFunction()
	if err != nil {
		return fmt.Errorf("error creating assignment by function: %w", err)
	}
	err = adoc.writeRAA(introTextRAA)
	if err != nil {
		return fmt.Errorf("error creating RAA: %w", err)
	}
	err = adoc.writeDataRiskMapping(dataAssetDiagramFilenamePNG)
	if err != nil {
		return fmt.Errorf("error creating data risk mapping: %w", err)
	}
	err = adoc.writeOutOfScopeAssets()
	if err != nil {
		return fmt.Errorf("error creating Out of Scope Assets: %w", err)
	}
	err = adoc.writeModelFailures()
	if err != nil {
		return fmt.Errorf("error creating model failures: %w", err)
	}
	err = adoc.writeQuestions()
	if err != nil {
		return fmt.Errorf("error creating questions: %w", err)
	}
	err = adoc.writeRiskCategories()
	if err != nil {
		return fmt.Errorf("error creating risk categories: %w", err)
	}
	err = adoc.writeTechnicalAssets()
	if err != nil {
		return fmt.Errorf("error creating technical assets: %w", err)
	}
	err = adoc.writeDataAssets()
	if err != nil {
		return fmt.Errorf("error creating data assets: %w", err)
	}
	err = adoc.writeTrustBoundaries()
	if err != nil {
		return fmt.Errorf("error creating trust boundaries: %w", err)
	}
	err = adoc.writeSharedRuntimes()
	if err != nil {
		return fmt.Errorf("error creating shared runtimes: %w", err)
	}
	if val := hideChapters[RiskRulesCheckedByThreagile]; !val {
		err = adoc.writeRiskRulesChecked(modelFilename, skipRiskRules, buildTimestamp, threagileVersion, modelHash, customRiskRules)
		if err != nil {
			return fmt.Errorf("error creating risk rules checked: %w", err)
		}
	}
	err = adoc.writeAppendixRating()
	if err != nil {
		return fmt.Errorf("error creating appendix for the rating mappings")
	}
	err = adoc.writeDisclaimer()
	if err != nil {
		return fmt.Errorf("error creating disclaimer: %w", err)
	}
	return nil
}

func (adoc *adocReport) initReport() error {
	// Best-effort cleanup of a previous run; failure is non-fatal — MkdirAll below will catch real problems.
	_ = os.RemoveAll(adoc.targetDirectory)
	err := os.MkdirAll(adoc.targetDirectory, 0750)
	if err != nil {
		return err
	}
	adoc.mainFile, err = os.Create(filepath.Join(adoc.targetDirectory, "000_main.adoc"))
	if err != nil {
		return err
	}

	return nil
}

func (adoc adocReport) writeTitleAndPreamble() {
	adoc.writeMainLine("= Threat Model Report: " + adoc.model.Title)
	adoc.writeMainLine(":title-page:")
	adoc.writeMainLine(":author: " + adoc.model.Author.Name)
	if strings.HasPrefix(adoc.model.Author.Homepage, "http") {
		adoc.writeMainLine(`:author-homepage: ` + adoc.model.Author.Homepage)
	} else {
		adoc.writeMainLine(`:author-homepage: https://` + adoc.model.Author.Homepage)
	}
	adoc.writeMainLine(":email: " + adoc.model.Author.Contact)
	adoc.writeMainLine(":toc:")
	adoc.writeMainLine(":toclevels: " + strconv.Itoa(adoc.tocDepth))
	adoc.writeMainLine(":icons: " + adoc.iconsType)
	reportDate := adoc.model.Date
	if reportDate.IsZero() {
		reportDate = types.Date{Time: time.Now()}
	}
	adoc.writeMainLine(":revdate: " + reportDate.Format("2 January 2006"))
	adoc.writeMainLine("")
}

func colorPrefixBySeverity(severity types.RiskSeverity, smallFont bool) (string, string) {
	start := ""
	switch severity {
	case types.CriticalSeverity:
		start = "[.CriticalRisk"
	case types.HighSeverity:
		start = "[.HighRisk"
	case types.ElevatedSeverity:
		start = "[.ElevatedRisk"
	case types.MediumSeverity:
		start = "[.MediumRisk"
	case types.LowSeverity:
		start = "[.LowRisk"
	default:
		return "", ""
	}
	if smallFont {
		start += ".small"
	}
	return start + "]#", "#"
}

func colorPrefixByDataBreachProbability(probability types.DataBreachProbability, smallFont bool) (string, string) {
	switch probability {
	case types.Probable:
		return colorPrefixBySeverity(types.HighSeverity, smallFont)
	case types.Possible:
		return colorPrefixBySeverity(types.MediumSeverity, smallFont)
	case types.Improbable:
		return colorPrefixBySeverity(types.LowSeverity, smallFont)
	default:
		return "", ""
	}
}

func titleOfSeverity(severity types.RiskSeverity) string {
	switch severity {
	case types.CriticalSeverity:
		return "Critical Risk Severity"
	case types.HighSeverity:
		return "High Risk Severity"
	case types.ElevatedSeverity:
		return "Elevated Risk Severity"
	case types.MediumSeverity:
		return "Medium Risk Severity"
	case types.LowSeverity:
		return "Low Risk Severity"
	default:
		return ""
	}
}

func riskSuffix(remainingRisks int, totalRisks int) string {
	suffix := ""
	if remainingRisks > 0 {
		suffix = strconv.Itoa(remainingRisks) + "/" + strconv.Itoa(totalRisks) + " unmitigated Risk"
	} else {
		suffix = strconv.Itoa(totalRisks) + " mitigated Risk"
	}
	if totalRisks != 1 {
		suffix += "s"
	}

	return suffix
}

func addCustomImages(f *os.File, customImages []map[string]string, baseFolder string) {
	for _, customImage := range customImages {
		for imageFilename := range customImage {
			imageFilenameWithoutPath := filepath.Base(imageFilename)
			imageFullFilename := filepath.Join(baseFolder, imageFilenameWithoutPath)
			writeLine(f, "image::"+imageFullFilename+"[]")
		}
	}
}

func joinedOrNoneString(strs []string, noneValue string) string {
	if noneValue == "" {
		noneValue = "[GrayText]#none#"
	}
	sort.Strings(strs)
	singleLine := strings.Join(strs[:], ", ")
	if len(singleLine) == 0 {
		singleLine = noneValue
	}
	return singleLine
}

func dataAssetListTitleJoinOrNone(assets []*types.DataAsset, noneValue string) string {
	var dataAssetTitles []string
	for _, dataAsset := range assets {
		dataAssetTitles = append(dataAssetTitles, dataAsset.Title)
	}
	return joinedOrNoneString(dataAssetTitles, noneValue)
}

func technicalAssetTitleOrNone(links []*types.TechnicalAsset, noneValue string) string {
	var titles []string
	for _, asset := range links {
		titles = append(titles, asset.Title)
	}
	return joinedOrNoneString(titles, noneValue)
}

func dataFormatTitleJoinOrNone(assets []types.DataFormat, noneValue string) string {
	var dataAssetTitles []string
	for _, dataFormat := range assets {
		dataAssetTitles = append(dataAssetTitles, dataFormat.Title())
	}
	return joinedOrNoneString(dataAssetTitles, noneValue)
}

func communicationLinkTitleOrNone(links []*types.CommunicationLink, noneValue string) string {
	var titles []string
	for _, link := range links {
		titles = append(titles, link.Title)
	}
	return joinedOrNoneString(titles, noneValue)
}
