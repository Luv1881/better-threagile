package report

import (
	"image"
	"image/color"
	"image/png"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/risks/builtin"
	"github.com/threagile/threagile/pkg/types"
)

// smokeTestRiskRules returns a small subset of the built-in risk rules.
// It deliberately avoids pkg/risks.GetBuiltInRiskRules(), since pkg/risks
// (via test_runner.go) imports pkg/report and would create an import cycle
// for this in-package test. A non-empty rule set is required so the model
// has at least one generated risk for the PDF's pie charts to render.
func smokeTestRiskRules() types.RiskRules {
	rules := make(types.RiskRules)
	for _, rule := range []types.RiskRule{
		builtin.NewAccidentalSecretLeakRule(),
		builtin.NewCodeBackdooringRule(),
		builtin.NewContainerBaseImageBackdooringRule(),
		builtin.NewContainerPlatformEscapeRule(),
		builtin.NewCrossSiteRequestForgeryRule(),
		builtin.NewCrossSiteScriptingRule(),
		builtin.NewDosRiskyAccessAcrossTrustBoundaryRule(),
		builtin.NewIncompleteModelRule(),
		builtin.NewLdapInjectionRule(),
		builtin.NewMissingAuthenticationRule(),
		builtin.NewMissingAuthenticationSecondFactorRule(builtin.NewMissingAuthenticationRule()),
		builtin.NewMissingBuildInfrastructureRule(),
		builtin.NewMissingCloudHardeningRule(),
		builtin.NewMissingFileValidationRule(),
		builtin.NewMissingHardeningRule(),
		builtin.NewMissingIdentityPropagationRule(),
		builtin.NewMissingIdentityProviderIsolationRule(),
		builtin.NewMissingIdentityStoreRule(),
		builtin.NewMissingNetworkSegmentationRule(),
		builtin.NewMissingVaultRule(),
		builtin.NewMissingVaultIsolationRule(),
		builtin.NewMissingWafRule(),
		builtin.NewMixedTargetsOnSharedRuntimeRule(),
		builtin.NewPathTraversalRule(),
		builtin.NewPushInsteadPullDeploymentRule(),
		builtin.NewSearchQueryInjectionRule(),
		builtin.NewServerSideRequestForgeryRule(),
		builtin.NewServiceRegistryPoisoningRule(),
		builtin.NewSqlNoSqlInjectionRule(),
		builtin.NewUncheckedDeploymentRule(),
		builtin.NewUnencryptedAssetRule(),
		builtin.NewUnencryptedCommunicationRule(),
		builtin.NewUnguardedAccessFromInternetRule(),
		builtin.NewUnguardedDirectDatastoreAccessRule(),
		builtin.NewUnnecessaryCommunicationLinkRule(),
		builtin.NewUnnecessaryDataAssetRule(),
		builtin.NewUnnecessaryDataTransferRule(),
		builtin.NewUnnecessaryTechnicalAssetRule(),
		builtin.NewUntrustedDeserializationRule(),
		builtin.NewWrongCommunicationLinkContentRule(),
		builtin.NewWrongTrustBoundaryContentRule(),
		builtin.NewXmlExternalEntityRule(),
		builtin.NewLateralMovementSharedRuntimeRule(),
		builtin.NewLateralMovementCredentialReuseRule(),
		builtin.NewLateralMovementServiceAccountScopeCreepRule(),
		builtin.NewLateralMovementTransitiveAccessRule(),
	} {
		rules[rule.Category().ID] = rule
	}
	return rules
}

// quietProgressReporter implements types.ProgressReporter without depending
// on pkg/server, which (transitively via pkg/risks) imports pkg/report and
// would otherwise create an import cycle for this in-package test.
type quietProgressReporter struct{}

func (quietProgressReporter) Info(a ...any)                  {}
func (quietProgressReporter) Warn(a ...any)                  { log.Println(a...) }
func (quietProgressReporter) Error(a ...any)                 { log.Println(a...) }
func (quietProgressReporter) Infof(format string, a ...any)  {}
func (quietProgressReporter) Warnf(format string, a ...any)  { log.Printf(format, a...) }
func (quietProgressReporter) Errorf(format string, a ...any) { log.Printf(format, a...) }

// pdfTestConfig is a minimal configReader implementation used to drive
// model.ReadAndAnalyzeModel for the PDF smoke test below. It must live in
// package report (not report_test) since newPdfReporter is unexported, but
// it must avoid importing pkg/risks (which imports pkg/report) to prevent an
// import cycle, so it is built with an empty risk-rule set.
type pdfTestConfig struct {
	inputFile string
}

func (c *pdfTestConfig) GetBuildTimestamp() string                  { return "test" }
func (c *pdfTestConfig) GetVerbose() bool                           { return false }
func (c *pdfTestConfig) GetInteractive() bool                       { return false }
func (c *pdfTestConfig) GetAppFolder() string                       { return "" }
func (c *pdfTestConfig) GetPluginFolder() string                    { return "" }
func (c *pdfTestConfig) GetDataFolder() string                      { return "" }
func (c *pdfTestConfig) GetOutputFolder() string                    { return "" }
func (c *pdfTestConfig) GetServerFolder() string                    { return "" }
func (c *pdfTestConfig) GetTempFolder() string                      { return "" }
func (c *pdfTestConfig) GetKeyFolder() string                       { return "" }
func (c *pdfTestConfig) GetInputFile() string                       { return c.inputFile }
func (c *pdfTestConfig) GetImportedInputFile() string               { return "" }
func (c *pdfTestConfig) GetDataFlowDiagramFilenamePNG() string      { return "" }
func (c *pdfTestConfig) GetDataAssetDiagramFilenamePNG() string     { return "" }
func (c *pdfTestConfig) GetDataFlowDiagramFilenameDOT() string      { return "" }
func (c *pdfTestConfig) GetDataAssetDiagramFilenameDOT() string     { return "" }
func (c *pdfTestConfig) GetReportFilename() string                  { return "" }
func (c *pdfTestConfig) GetExcelRisksFilename() string              { return "" }
func (c *pdfTestConfig) GetExcelTagsFilename() string               { return "" }
func (c *pdfTestConfig) GetJsonRisksFilename() string               { return "" }
func (c *pdfTestConfig) GetJsonTechnicalAssetsFilename() string     { return "" }
func (c *pdfTestConfig) GetJsonStatsFilename() string               { return "" }
func (c *pdfTestConfig) GetTemplateFilename() string                { return "" }
func (c *pdfTestConfig) GetTechnologyFilename() string              { return "" }
func (c *pdfTestConfig) GetRiskRulePlugins() []string                { return nil }
func (c *pdfTestConfig) GetSkipRiskRules() []string                  { return nil }
func (c *pdfTestConfig) GetExecuteModelMacro() string                { return "" }
func (c *pdfTestConfig) GetRiskExcelConfigHideColumns() []string     { return nil }
func (c *pdfTestConfig) GetRiskExcelConfigSortByColumns() []string   { return nil }
func (c *pdfTestConfig) GetRiskExcelConfigWidthOfColumns() map[string]float64 { return nil }
func (c *pdfTestConfig) GetMethodology() string                     { return "" }
func (c *pdfTestConfig) GetServerMode() bool                        { return false }
func (c *pdfTestConfig) GetDiagramDPI() int                         { return 100 }
func (c *pdfTestConfig) GetServerPort() int                         { return 8080 }
func (c *pdfTestConfig) GetGraphvizDPI() int                        { return 120 }
func (c *pdfTestConfig) GetMaxGraphvizDPI() int                     { return 300 }
func (c *pdfTestConfig) GetBackupHistoryFilesToKeep() int           { return 50 }
func (c *pdfTestConfig) GetAddModelTitle() bool                     { return false }
func (c *pdfTestConfig) GetAddLegend() bool                         { return false }
func (c *pdfTestConfig) GetKeepDiagramSourceFiles() bool            { return false }
func (c *pdfTestConfig) GetIgnoreOrphanedRiskTracking() bool        { return true }
func (c *pdfTestConfig) GetThreagileVersion() string                { return "test" }
func (c *pdfTestConfig) GetProgressReporter() types.ProgressReporter {
	return quietProgressReporter{}
}

// TestWriteReportPDF_Smoke is a characterization smoke test for the PDF
// report: it asserts that a non-trivial PDF file is produced for the
// canonical demo/example model, without asserting on exact byte content
// (gofpdf output is not stable enough for byte-exact golden files).
func TestWriteReportPDF_Smoke(t *testing.T) {
	modelPath, absErr := filepath.Abs(filepath.Join("..", "..", "demo", "example", "threagile.yaml"))
	if absErr != nil {
		t.Fatalf("resolve fixture model path: %v", absErr)
	}

	templatePath, absErr2 := filepath.Abs(filepath.Join("..", "..", "report", "template", "background.pdf"))
	if absErr2 != nil {
		t.Fatalf("resolve background template path: %v", absErr2)
	}

	cfg := &pdfTestConfig{inputFile: modelPath}

	result, analyzeErr := model.ReadAndAnalyzeModel(cfg, smokeTestRiskRules(), quietProgressReporter{})
	if analyzeErr != nil {
		t.Fatalf("ReadAndAnalyzeModel: %v", analyzeErr)
	}

	tempFolder := t.TempDir()
	dataFlowPNG := writeTestPNG(t, tempFolder, "data-flow-diagram.png")
	dataAssetPNG := writeTestPNG(t, tempFolder, "data-asset-diagram.png")

	reportPath := filepath.Join(t.TempDir(), "report.pdf")

	reporter := newPdfReporter(nil)
	writeErr := reporter.WriteReportPDF(
		reportPath,
		templatePath,
		dataFlowPNG,
		dataAssetPNG,
		"model.yaml",
		nil,
		"TEST_BUILD",
		"TEST_VERSION",
		"TEST_HASH",
		result.IntroTextRAA,
		nil,
		tempFolder,
		result.ParsedModel,
		map[ChaptersToShowHide]bool{},
	)
	if writeErr != nil {
		t.Fatalf("WriteReportPDF: %v", writeErr)
	}

	data, readErr := os.ReadFile(reportPath)
	if readErr != nil {
		t.Fatalf("read report.pdf: %v", readErr)
	}
	if len(data) < 1024 {
		t.Fatalf("report.pdf is suspiciously small: %d bytes", len(data))
	}
	if string(data[:5]) != "%PDF-" {
		t.Fatalf("report.pdf does not start with PDF magic bytes: %q", data[:5])
	}
}

func writeTestPNG(t *testing.T, dir, name string) string {
	t.Helper()

	img := image.NewRGBA(image.Rect(0, 0, 1600, 1200))
	for y := 0; y < 1200; y++ {
		for x := 0; x < 1600; x++ {
			img.Set(x, y, color.RGBA{R: 200, G: 200, B: 200, A: 255})
		}
	}

	path := filepath.Join(dir, name)
	f, createErr := os.Create(path)
	if createErr != nil {
		t.Fatalf("create png: %v", createErr)
	}
	defer func() { _ = f.Close() }()

	if encodeErr := png.Encode(f, img); encodeErr != nil {
		t.Fatalf("encode png: %v", encodeErr)
	}
	return path
}
