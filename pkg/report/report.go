package report

import (
	"fmt"
	"image"
	"os"
	"path/filepath"
	"strconv"
	"unicode/utf8"

	"github.com/go-pdf/fpdf"
	"github.com/go-pdf/fpdf/contrib/gofpdi"
	"github.com/threagile/threagile/pkg/types"
	chart "github.com/wcharczuk/go-chart/v2"
	"github.com/wcharczuk/go-chart/v2/drawing"
)

const fontSizeHeadline, fontSizeHeadlineSmall, fontSizeBody, fontSizeSmall, fontSizeVerySmall = 20, 16, 12, 9, 7
const allowedPdfLandscapePages, embedDiagramLegendPage = true, false

type pdfReporter struct {
	isLandscapePage               bool
	pdf                           *fpdf.Fpdf
	coverTemplateId               int
	contentTemplateId             int
	diagramLegendTemplateId       int
	pageNo                        int
	linkCounter                   int
	tocLinkIdByAssetId            map[string]int
	homeLink                      int
	currentChapterTitleBreadcrumb string

	riskRules types.RiskRules
}

func newPdfReporter(types.RiskRules) *pdfReporter {
	return &pdfReporter{}
}

func (r *pdfReporter) initReport() {
	r.pdf = nil
	r.isLandscapePage = false
	r.pageNo = 0
	r.linkCounter = 0
	r.homeLink = 0
	r.currentChapterTitleBreadcrumb = ""
	r.tocLinkIdByAssetId = make(map[string]int)
}

func (r *pdfReporter) WriteReportPDF(reportFilename string,
	templateFilename string,
	dataFlowDiagramFilenamePNG string,
	dataAssetDiagramFilenamePNG string,
	modelFilename string,
	skipRiskRules []string,
	buildTimestamp string,
	threagileVersion string,
	modelHash string,
	introTextRAA string,
	customRiskRules types.RiskRules,
	tempFolder string,
	model *types.Model,
	hideChapters map[ChaptersToShowHide]bool) (err error) {
	defer func() {
		if value := recover(); value != nil {
			err = fmt.Errorf("error creating PDF report: %v", value)
		}
	}()

	r.initReport()
	r.createPdfAndInitMetadata(model)
	r.parseBackgroundTemplate(templateFilename)
	r.createCover(model)
	r.createTableOfContents(model)
	err = r.createManagementSummary(model, tempFolder)
	if err != nil {
		return fmt.Errorf("error creating management summary: %w", err)
	}
	r.createImpactInitialRisks(model)
	err = r.createRiskMitigationStatus(model, tempFolder)
	if err != nil {
		return fmt.Errorf("error creating risk mitigation status: %w", err)
	}
	if val := hideChapters[AssetRegister]; !val {
		r.createAssetRegister(model)
	}
	r.createImpactRemainingRisks(model)
	err = r.createTargetDescription(model, filepath.Dir(modelFilename))
	if err != nil {
		return fmt.Errorf("error creating target description: %w", err)
	}
	r.embedDataFlowDiagram(dataFlowDiagramFilenamePNG, tempFolder)
	r.createSecurityRequirements(model)
	r.createAbuseCases(model)
	r.createTagListing(model)
	r.createSTRIDE(model)
	r.createAssignmentByFunction(model)
	r.createRAA(model, introTextRAA)
	r.embedDataRiskMapping(dataAssetDiagramFilenamePNG, tempFolder)
	// createDataRiskQuickWins()
	r.createOutOfScopeAssets(model)
	r.createModelFailures(model)
	r.createQuestions(model)
	r.createRiskCategories(model)
	r.createTechnicalAssets(model)
	r.createDataAssets(model)
	r.createTrustBoundaries(model)
	r.createSharedRuntimes(model)
	if val := hideChapters[RiskRulesCheckedByThreagile]; !val {
		r.createRiskRulesChecked(model, modelFilename, skipRiskRules, buildTimestamp, threagileVersion, modelHash, customRiskRules)
	}
	r.createDisclaimer(model)
	err = r.writeReportToFile(reportFilename)
	if err != nil {
		return fmt.Errorf("error writing report to file: %w", err)
	}
	return nil
}

func (r *pdfReporter) createPdfAndInitMetadata(model *types.Model) {
	r.pdf = fpdf.New("P", "mm", "A4", "")
	r.pdf.SetCreator(model.Author.Homepage, true)
	r.pdf.SetAuthor(model.Author.Name, true)
	r.pdf.SetTitle("Threat Model Report: "+model.Title, true)
	r.pdf.SetSubject("Threat Model Report: "+model.Title, true)
	//	r.pdf.SetPageBox("crop", 0, 0, 100, 010)
	r.pdf.SetHeaderFunc(func() {
		if r.isLandscapePage {
			return
		}

		gofpdi.UseImportedTemplate(r.pdf, r.contentTemplateId, 0, 0, 0, 300)
		r.pdf.SetTopMargin(35)
	})
	r.pdf.SetFooterFunc(func() {
		r.addBreadcrumb(model)
		r.pdf.SetFont("Helvetica", "", 10)
		r.pdf.SetTextColor(127, 127, 127)
		r.pdf.Text(8.6, 284, "Threat Model Report via Threagile") // : "+parsedModel.Title)
		r.pdf.Link(8.4, 281, 54.6, 4, r.homeLink)
		r.pageNo++
		text := "Page " + strconv.Itoa(r.pageNo)
		if r.pageNo < 10 {
			text = "    " + text
		} else if r.pageNo < 100 {
			text = "  " + text
		}
		if r.pageNo > 1 {
			r.pdf.Text(186, 284, text)
		}
	})
	r.linkCounter = 1 // link counting starts at 1 via r.pdf.AddLink
}

func (r *pdfReporter) addBreadcrumb(parsedModel *types.Model) {
	if len(r.currentChapterTitleBreadcrumb) > 0 {
		uni := r.pdf.UnicodeTranslatorFromDescriptor("")
		r.pdf.SetFont("Helvetica", "", 10)
		r.pdf.SetTextColor(127, 127, 127)
		r.pdf.Text(46.7, 24.5, uni(r.currentChapterTitleBreadcrumb+"   -   "+parsedModel.Title))
	}
}

func (r *pdfReporter) parseBackgroundTemplate(templateFilename string) {
	/*
		imageBox, err := rice.FindBox("template")
		checkErr(err)
		file, err := os.CreateTemp("", "background-*-.r.pdf")
		checkErr(err)
		defer os.Remove(file.Title())
		backgroundBytes := imageBox.MustBytes("background.r.pdf")
		err = os.WriteFile(file.Title(), backgroundBytes, 0644)
		checkErr(err)
	*/
	r.coverTemplateId = gofpdi.ImportPage(r.pdf, templateFilename, 1, "/MediaBox")
	r.contentTemplateId = gofpdi.ImportPage(r.pdf, templateFilename, 2, "/MediaBox")
	r.diagramLegendTemplateId = gofpdi.ImportPage(r.pdf, templateFilename, 3, "/MediaBox")
}

func (r *pdfReporter) defineLinkTarget(alias string) {
	pageNumbStr := strconv.Itoa(r.pdf.PageNo())
	if len(pageNumbStr) == 1 {
		pageNumbStr = "    " + pageNumbStr
	} else if len(pageNumbStr) == 2 {
		pageNumbStr = "  " + pageNumbStr
	}
	r.pdf.RegisterAlias(alias, pageNumbStr)
	r.pdf.SetLink(r.linkCounter, 0, -1)
	r.linkCounter++
}

func (r *pdfReporter) embedStackedBarChart(sbcChart chart.StackedBarChart, x float64, y float64, tempFolder string) error {
	tmpFilePNG, err := os.CreateTemp(tempFolder, "chart-*-.png")
	if err != nil {
		return fmt.Errorf("error creating temporary file for chart: %w", err)
	}
	defer func() { _ = os.Remove(tmpFilePNG.Name()) }()
	file, _ := os.Create(tmpFilePNG.Name())
	defer func() { _ = file.Close() }()
	err = sbcChart.Render(chart.PNG, file)
	if err != nil {
		return fmt.Errorf("error rendering chart: %w", err)
	}
	var options fpdf.ImageOptions
	options.ImageType = ""
	r.pdf.RegisterImage(tmpFilePNG.Name(), "")
	r.pdf.ImageOptions(tmpFilePNG.Name(), x, y, 0, 110, false, options, 0, "")
	return nil
}

func (r *pdfReporter) embedPieChart(pieChart chart.PieChart, x float64, y float64, tempFolder string) error {
	tmpFilePNG, err := os.CreateTemp(tempFolder, "chart-*-.png")
	if err != nil {
		return fmt.Errorf("error creating temporary file for chart: %w", err)
	}
	defer func() { _ = os.Remove(tmpFilePNG.Name()) }()
	file, err := os.Create(tmpFilePNG.Name())
	if err != nil {
		return fmt.Errorf("error creating temporary file for chart: %w", err)
	}
	defer func() { _ = file.Close() }()
	err = pieChart.Render(chart.PNG, file)
	if err != nil {
		return fmt.Errorf("error rendering chart: %w", err)
	}
	var options fpdf.ImageOptions
	options.ImageType = ""
	r.pdf.RegisterImage(tmpFilePNG.Name(), "")
	r.pdf.ImageOptions(tmpFilePNG.Name(), x, y, 60, 0, false, options, 0, "")
	return nil
}

func makeColor(hexColor string) drawing.Color {
	_, i := utf8.DecodeRuneInString(hexColor)
	return drawing.ColorFromHex(hexColor[i:]) // = remove first char, which is # in rgb hex here
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func getHeightWhenWidthIsFix(imageFullFilename string, width float64) (float64, error) {
	if !fileExists(imageFullFilename) {
		return 0, fmt.Errorf("image file does not exist (or is not readable as file): %s", filepath.Base(imageFullFilename))
	}
	/* #nosec imageFullFilename is not tainted (see caller restricting it to image files of model folder only) */
	file, err := os.Open(imageFullFilename)
	defer func() { _ = file.Close() }()
	if err != nil {
		return 0, fmt.Errorf("error opening image file: %w", err)
	}
	img, _, err := image.DecodeConfig(file)
	if err != nil {
		return 0, fmt.Errorf("error decoding image file: %w", err)
	}
	return float64(img.Height) / (float64(img.Width) / width), nil
}

func (r *pdfReporter) writeReportToFile(reportFilename string) error {
	err := r.pdf.OutputFileAndClose(reportFilename)
	if err != nil {
		return fmt.Errorf("error writing PDF report file: %w", err)
	}
	return nil
}

func (r *pdfReporter) addHeadline(headline string, small bool) {
	r.pdf.AddPage()
	gofpdi.UseImportedTemplate(r.pdf, r.contentTemplateId, 0, 0, 0, 300)
	fontSize := fontSizeHeadline
	if small {
		fontSize = fontSizeHeadlineSmall
	}
	r.pdf.SetFont("Helvetica", "B", float64(fontSize))
	r.pdf.Text(11, 40, headline)
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	r.pdf.SetX(17)
	r.pdf.SetY(46)
}

func (r *pdfReporter) pageBreak() {
	r.pdf.SetDrawColor(0, 0, 0)
	r.pdf.SetDashPattern([]float64{}, 0)
	r.pdf.AddPage()
	gofpdi.UseImportedTemplate(r.pdf, r.contentTemplateId, 0, 0, 0, 300)
	r.pdf.SetX(17)
	r.pdf.SetY(20)
}

func (r *pdfReporter) pageBreakInLists() {
	r.pageBreak()
	r.pdf.SetLineWidth(0.25)
	r.pdf.SetDrawColor(160, 160, 160)
	r.pdf.SetDashPattern([]float64{0.5, 0.5}, 0)
}

func (r *pdfReporter) pdfColorDisclaimer() {
	r.pdf.SetTextColor(140, 140, 140)
}

func (r *pdfReporter) pdfColorOutOfScope() {
	r.pdf.SetTextColor(127, 127, 127)
}

func (r *pdfReporter) pdfColorGray() {
	r.pdf.SetTextColor(80, 80, 80)
}

func (r *pdfReporter) pdfColorLightGray() {
	r.pdf.SetTextColor(100, 100, 100)
}

func (r *pdfReporter) pdfColorBlack() {
	r.pdf.SetTextColor(0, 0, 0)
}
