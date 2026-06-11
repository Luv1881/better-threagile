package report

import (
	"fmt"
	"log"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"
	"github.com/threagile/threagile/pkg/types"
)

func (r *pdfReporter) createRiskRulesChecked(parsedModel *types.Model, modelFilename string, skipRiskRules []string, buildTimestamp string, threagileVersion string, modelHash string, customRiskRules types.RiskRules) {
	r.pdf.SetTextColor(0, 0, 0)
	title := "Risk Rules Checked by Threagile"
	r.addHeadline(title, false)
	r.defineLinkTarget("{risk-rules-checked}")
	r.currentChapterTitleBreadcrumb = title

	html := r.pdf.HTMLBasicNew()
	var strBuilder strings.Builder
	r.pdfColorGray()
	r.pdf.SetFont("Helvetica", "", fontSizeSmall)
	timestamp := time.Now()
	strBuilder.WriteString("<b>Threagile Version:</b> " + threagileVersion)
	strBuilder.WriteString("<br><b>Threagile Build Timestamp:</b> " + buildTimestamp)
	strBuilder.WriteString("<br><b>Threagile Execution Timestamp:</b> " + timestamp.Format("20060102150405"))
	strBuilder.WriteString("<br><b>Model Filename:</b> " + modelFilename)
	strBuilder.WriteString("<br><b>Model Hash (SHA256):</b> " + modelHash)
	html.Write(5, strBuilder.String())
	strBuilder.Reset()
	r.pdfColorBlack()
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	strBuilder.WriteString("<br><br>Threagile (see <a href=\"https://threagile.io\">https://threagile.io</a> for more details) is an open-source toolkit for agile threat modeling, created by Christian Schneider (<a href=\"https://christian-schneider.net\">https://christian-schneider.net</a>): It allows to model an architecture with its assets in an agile fashion as a YAML file " +
		"directly inside the IDE. Upon execution of the Threagile toolkit all standard risk rules (as well as individual custom rules if present) " +
		"are checked against the architecture model. At the time the Threagile toolkit was executed on the model input file " +
		"the following risk rules were checked:")
	html.Write(5, strBuilder.String())
	strBuilder.Reset()

	// TODO use the new run system to discover risk rules instead of hard-coding them here:
	skipped := ""
	r.pdf.Ln(-1)

	for id, customRule := range customRiskRules {
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "B", fontSizeBody)
		if contains(skipRiskRules, id) {
			skipped = "SKIPPED - "
		} else {
			skipped = ""
		}
		r.pdf.CellFormat(190, 3, skipped+customRule.Category().Title, "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "", fontSizeSmall)
		r.pdf.CellFormat(190, 6, id, "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "I", fontSizeBody)
		r.pdf.CellFormat(190, 6, "Custom Risk Rule", "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "", fontSizeBody)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(160, 6, customRule.Category().STRIDE.Title(), "0", "0", false)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(160, 6, firstParagraph(customRule.Category().Description), "0", "0", false)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(160, 6, customRule.Category().DetectionLogic, "0", "0", false)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(160, 6, customRule.Category().RiskAssessment, "0", "0", false)
	}

	sort.Sort(types.ByRiskCategoryTitleSort(parsedModel.CustomRiskCategories))
	for _, individualRiskCategory := range parsedModel.CustomRiskCategories {
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "B", fontSizeBody)
		r.pdf.CellFormat(190, 3, individualRiskCategory.Title, "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "", fontSizeSmall)
		r.pdf.CellFormat(190, 6, individualRiskCategory.ID, "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "I", fontSizeBody)
		r.pdf.CellFormat(190, 6, "Individual Risk category", "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "", fontSizeBody)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(160, 6, individualRiskCategory.STRIDE.Title(), "0", "0", false)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(160, 6, firstParagraph(individualRiskCategory.Description), "0", "0", false)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(160, 6, individualRiskCategory.DetectionLogic, "0", "0", false)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(160, 6, individualRiskCategory.RiskAssessment, "0", "0", false)
	}

	for _, rule := range r.riskRules {
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "B", fontSizeBody)
		if contains(skipRiskRules, rule.Category().ID) {
			skipped = "SKIPPED - "
		} else {
			skipped = ""
		}
		r.pdf.CellFormat(190, 3, skipped+rule.Category().Title, "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "", fontSizeSmall)
		r.pdf.CellFormat(190, 6, rule.Category().ID, "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "", fontSizeBody)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(160, 6, rule.Category().STRIDE.Title(), "0", "0", false)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(160, 6, firstParagraph(rule.Category().Description), "0", "0", false)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(160, 6, rule.Category().DetectionLogic, "0", "0", false)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(160, 6, rule.Category().RiskAssessment, "0", "0", false)
	}
}

func (r *pdfReporter) createTargetDescription(parsedModel *types.Model, baseFolder string) error {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	r.pdf.SetTextColor(0, 0, 0)
	title := "Application Overview"
	r.addHeadline(title, false)
	r.defineLinkTarget("{target-overview}")
	r.currentChapterTitleBreadcrumb = title

	var intro strings.Builder
	html := r.pdf.HTMLBasicNew()

	intro.WriteString("<b>Business Criticality</b><br><br>")
	intro.WriteString("The overall business criticality of \"" + uni(parsedModel.Title) + "\" was rated as:<br><br>")
	html.Write(5, intro.String())
	criticality := parsedModel.BusinessCriticality
	intro.Reset()
	r.pdfColorGray()
	intro.WriteString("(  ")
	if criticality == types.Archive {
		html.Write(5, intro.String())
		intro.Reset()
		r.pdfColorBlack()
		intro.WriteString("<b><u>" + strings.ToUpper(types.Archive.String()) + "</u></b>")
		html.Write(5, intro.String())
		intro.Reset()
		r.pdfColorGray()
	} else {
		intro.WriteString(types.Archive.String())
	}
	intro.WriteString("  |  ")
	if criticality == types.Operational {
		html.Write(5, intro.String())
		intro.Reset()
		r.pdfColorBlack()
		intro.WriteString("<b><u>" + strings.ToUpper(types.Operational.String()) + "</u></b>")
		html.Write(5, intro.String())
		intro.Reset()
		r.pdfColorGray()
	} else {
		intro.WriteString(types.Operational.String())
	}
	intro.WriteString("  |  ")
	if criticality == types.Important {
		html.Write(5, intro.String())
		intro.Reset()
		r.pdfColorBlack()
		intro.WriteString("<b><u>" + strings.ToUpper(types.Important.String()) + "</u></b>")
		html.Write(5, intro.String())
		intro.Reset()
		r.pdfColorGray()
	} else {
		intro.WriteString(types.Important.String())
	}
	intro.WriteString("  |  ")
	if criticality == types.Critical {
		html.Write(5, intro.String())
		intro.Reset()
		r.pdfColorBlack()
		intro.WriteString("<b><u>" + strings.ToUpper(types.Critical.String()) + "</u></b>")
		html.Write(5, intro.String())
		intro.Reset()
		r.pdfColorGray()
	} else {
		intro.WriteString(types.Critical.String())
	}
	intro.WriteString("  |  ")
	if criticality == types.MissionCritical {
		html.Write(5, intro.String())
		intro.Reset()
		r.pdfColorBlack()
		intro.WriteString("<b><u>" + strings.ToUpper(types.MissionCritical.String()) + "</u></b>")
		html.Write(5, intro.String())
		intro.Reset()
		r.pdfColorGray()
	} else {
		intro.WriteString(types.MissionCritical.String())
	}
	intro.WriteString("  )")
	html.Write(5, intro.String())
	intro.Reset()
	r.pdfColorBlack()

	intro.WriteString("<br><br><br><b>Business Overview</b><br><br>")
	intro.WriteString(uni(parsedModel.BusinessOverview.Description))
	html.Write(5, intro.String())
	intro.Reset()
	err := r.addCustomImages(parsedModel.BusinessOverview.Images, baseFolder, html)
	if err != nil {
		return fmt.Errorf("error adding custom images: %w", err)
	}

	intro.WriteString("<br><br><br><b>Technical Overview</b><br><br>")
	intro.WriteString(uni(parsedModel.TechnicalOverview.Description))
	html.Write(5, intro.String())
	intro.Reset()
	err = r.addCustomImages(parsedModel.TechnicalOverview.Images, baseFolder, html)
	if err != nil {
		return fmt.Errorf("error adding custom images: %w", err)
	}
	return nil
}

func (r *pdfReporter) addCustomImages(customImages []map[string]string, baseFolder string, html fpdf.HTMLBasicType) error {
	var text strings.Builder
	for _, customImage := range customImages {
		for imageFilename := range customImage {
			imageFilenameWithoutPath := filepath.Base(imageFilename)
			// check JPEG, PNG or GIF
			extension := strings.ToLower(filepath.Ext(imageFilenameWithoutPath))
			if extension == ".jpeg" || extension == ".jpg" || extension == ".png" || extension == ".gif" {
				imageFullFilename := filepath.Join(baseFolder, imageFilenameWithoutPath)
				heightWhenWidthIsFix, err := getHeightWhenWidthIsFix(imageFullFilename, 180)
				if err != nil {
					return fmt.Errorf("error getting height of image file: %w", err)
				}
				if r.pdf.GetY()+heightWhenWidthIsFix > 250 {
					r.pageBreak()
					r.pdf.SetY(36)
				} else {
					text.WriteString("<br><br>")
				}
				text.WriteString(customImage[imageFilename] + ":<br><br>")
				html.Write(5, text.String())
				text.Reset()

				var options fpdf.ImageOptions
				options.ImageType = ""
				r.pdf.RegisterImage(imageFullFilename, "")
				r.pdf.ImageOptions(imageFullFilename, 15, r.pdf.GetY()+50, 170, 0, true, options, 0, "")
			} else {
				log.Print("Ignoring custom image file: ", imageFilenameWithoutPath)
			}
		}
	}
	return nil
}

// fileExists checks if a file exists and is not a directory before we
// try using it to prevent further errors.
