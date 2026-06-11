package threagile

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigAccessors_Getters(t *testing.T) {
	c := new(Config).Defaults("test-timestamp")

	assert.Equal(t, "test-timestamp", c.GetBuildTimestamp())
	assert.Equal(t, ThreagileVersion, c.GetThreagileVersion())
	assert.NotEmpty(t, c.GetDataFolder())
	_ = c.GetKeyFolder()
	_ = c.GetTechnologyFilename()
	assert.NotEmpty(t, c.GetDataFlowDiagramFilenamePNG())
	assert.NotEmpty(t, c.GetDataAssetDiagramFilenamePNG())
	assert.NotEmpty(t, c.GetDataFlowDiagramFilenameDOT())
	assert.NotEmpty(t, c.GetDataAssetDiagramFilenameDOT())
	assert.NotEmpty(t, c.GetReportFilename())
	assert.NotEmpty(t, c.GetExcelRisksFilename())
	assert.NotEmpty(t, c.GetExcelTagsFilename())
	assert.NotEmpty(t, c.GetJsonRisksFilename())
	assert.NotEmpty(t, c.GetJsonTechnicalAssetsFilename())
	assert.NotEmpty(t, c.GetJsonStatsFilename())
	_ = c.GetExecuteModelMacro()
	assert.Equal(t, MinGraphvizDPI, c.GetMinGraphvizDPI())
	assert.Greater(t, c.GetMaxGraphvizDPI(), 0)
	assert.GreaterOrEqual(t, c.GetGraphvizDPI(), 0)
	assert.GreaterOrEqual(t, c.GetBackupHistoryFilesToKeep(), 0)

	// Boolean defaults are simply readable without panicking.
	_ = c.GetHideEmptyChapters()
	_ = c.GetAddModelTitle()
	_ = c.GetAddLegend()
	_ = c.GetKeepDiagramSourceFiles()
	_ = c.GetIgnoreOrphanedRiskTracking()
	_ = c.GetSkipDataFlowDiagram()
	_ = c.GetSkipDataAssetDiagram()
	_ = c.GetSkipRisksJSON()
	_ = c.GetSkipTechnicalAssetsJSON()
	_ = c.GetSkipStatsJSON()
	_ = c.GetSkipRisksExcel()
	_ = c.GetSkipTagsExcel()
	_ = c.GetSkipReportPDF()
	_ = c.GetSkipReportADOC()

	assert.NotNil(t, c.GetProgressReporter())
	assert.NotNil(t, c.GetReportConfigurationHideChapters())
	assert.NotNil(t, c.GetRiskExcelConfigWidthOfColumns())
	_ = c.GetRiskExcelConfigHideColumns()
	_ = c.GetRiskExcelConfigSortByColumns()
	_ = c.GetRiskExcelWrapText()
	_ = c.GetRiskExcelShrinkColumnsToFit()
	_ = c.GetRiskExcelColorText()
	assert.Equal(t, c.AttractivenessValue, c.GetAttractiveness())
	assert.Equal(t, c.ReportConfigurationValue, c.GetReportConfiguration())
}

func TestConfigAccessors_SettersRoundTrip(t *testing.T) {
	c := new(Config).Defaults("test")

	c.SetVerbose(true)
	assert.True(t, c.GetVerbose())

	c.SetInteractive(true)
	assert.True(t, c.GetInteractive())

	c.SetAppFolder("/tmp/app")
	assert.Equal(t, "/tmp/app", c.GetAppFolder())

	c.SetPluginFolder("/tmp/plugins")
	assert.Equal(t, "/tmp/plugins", c.GetPluginFolder())

	c.SetOutputFolder("/tmp/output")
	assert.Equal(t, "/tmp/output", c.GetOutputFolder())

	c.SetServerFolder("/tmp/server")
	assert.Equal(t, "/tmp/server", c.GetServerFolder())

	c.SetTempFolder("/tmp/temp")
	assert.Equal(t, "/tmp/temp", c.GetTempFolder())

	c.SetInputFile("/tmp/model.yaml")
	assert.Equal(t, "/tmp/model.yaml", c.GetInputFile())

	c.SetImportedInputFile("/tmp/imported.yaml")
	assert.Equal(t, "/tmp/imported.yaml", c.GetImportedInputFile())

	c.SetTemplateFilename("template.tex")
	assert.Equal(t, "template.tex", c.GetTemplateFilename())

	c.SetRiskRulePlugins([]string{"plugin-a", "plugin-b"})
	assert.Equal(t, []string{"plugin-a", "plugin-b"}, c.GetRiskRulePlugins())

	c.SetSkipRiskRules([]string{"rule-a"})
	assert.Equal(t, []string{"rule-a"}, c.GetSkipRiskRules())

	c.SetRulesDir("/tmp/rules")
	assert.Equal(t, "/tmp/rules", c.GetRulesDir())

	c.SetRulesURL("https://example.com/rules")
	assert.Equal(t, "https://example.com/rules", c.GetRulesURL())
	assert.Contains(t, c.GetRulesURLs(), "https://example.com/rules")

	c.SetMethodology("octave")
	assert.Equal(t, "octave", c.GetMethodology())

	c.SetRulePack("cloud-native")
	assert.Equal(t, "cloud-native", c.GetRulePack())

	c.SetServerMode(true)
	assert.True(t, c.GetServerMode())

	c.SetServerPort(9090)
	assert.Equal(t, 9090, c.GetServerPort())

	c.SetDiagramDPI(150)
	assert.Equal(t, 150, c.GetDiagramDPI())

	c.SetIgnoreOrphanedRiskTracking(true)
	assert.True(t, c.GetIgnoreOrphanedRiskTracking())
}

func TestConfigAccessors_GetMethodologyDefault(t *testing.T) {
	c := new(Config).Defaults("test")
	c.MethodologyValue = ""
	assert.Equal(t, "stride", c.GetMethodology())
}

func TestConfigAccessors_GetRulesURLsCombinesSingleAndMultiple(t *testing.T) {
	c := new(Config).Defaults("test")
	c.SetRulesURL("https://example.com/a")
	c.RulesURLsValue = []string{"https://example.com/b", "  ", "https://example.com/c"}

	assert.Equal(t, []string{
		"https://example.com/a",
		"https://example.com/b",
		"https://example.com/c",
	}, c.GetRulesURLs())
}
