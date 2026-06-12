package threagile

import (
	"strings"

	"github.com/threagile/threagile/pkg/report"
	"github.com/threagile/threagile/pkg/types"
)

func (c *Config) GetBuildTimestamp() string {
	return c.BuildTimestampValue
}

func (c *Config) GetVerbose() bool {
	return c.VerboseValue
}

func (c *Config) SetVerbose(verbose bool) {
	c.VerboseValue = verbose
}

func (c *Config) GetInteractive() bool {
	return c.InteractiveValue
}

func (c *Config) SetInteractive(interactive bool) {
	c.InteractiveValue = interactive
}

func (c *Config) GetAppFolder() string {
	return c.AppFolderValue
}

func (c *Config) SetAppFolder(appFolder string) {
	c.AppFolderValue = appFolder
}

func (c *Config) GetPluginFolder() string {
	return c.PluginFolderValue
}

func (c *Config) SetPluginFolder(pluginFolder string) {
	c.PluginFolderValue = pluginFolder
}

func (c *Config) GetDataFolder() string {
	return c.DataFolderValue
}

func (c *Config) GetOutputFolder() string {
	return c.OutputFolderValue
}

func (c *Config) SetOutputFolder(outputFolder string) {
	c.OutputFolderValue = outputFolder
}

func (c *Config) GetServerFolder() string {
	return c.ServerFolderValue
}

func (c *Config) SetServerFolder(serverFolder string) {
	c.ServerFolderValue = serverFolder
}

func (c *Config) GetTempFolder() string {
	return c.TempFolderValue
}

func (c *Config) SetTempFolder(tempFolder string) {
	c.TempFolderValue = tempFolder
}

func (c *Config) GetKeyFolder() string {
	return c.KeyFolderValue
}

func (c *Config) GetTechnologyFilename() string {
	return c.TechnologyFilenameValue
}

func (c *Config) GetHideEmptyChapters() bool {
	return c.HideEmptyChaptersValue
}

func (c *Config) GetInputFile() string {
	return c.InputFileValue
}

func (c *Config) SetInputFile(inputFile string) {
	c.InputFileValue = inputFile
}

func (c *Config) GetImportedInputFile() string {
	return c.ImportedInputFileValue
}

func (c *Config) SetImportedInputFile(inputFile string) {
	c.ImportedInputFileValue = inputFile
}

func (c *Config) GetDataFlowDiagramFilenamePNG() string {
	return c.DataFlowDiagramFilenamePNGValue
}

func (c *Config) GetDataAssetDiagramFilenamePNG() string {
	return c.DataAssetDiagramFilenamePNGValue
}

func (c *Config) GetDataFlowDiagramFilenameDOT() string {
	return c.DataFlowDiagramFilenameDOTValue
}

func (c *Config) GetDataAssetDiagramFilenameDOT() string {
	return c.DataAssetDiagramFilenameDOTValue
}

func (c *Config) GetReportFilename() string {
	return c.ReportFilenameValue
}

func (c *Config) GetExcelRisksFilename() string {
	return c.ExcelRisksFilenameValue
}

func (c *Config) GetExcelTagsFilename() string {
	return c.ExcelTagsFilenameValue
}

func (c *Config) GetJsonRisksFilename() string {
	return c.JsonRisksFilenameValue
}

func (c *Config) GetSarifRisksFilename() string {
	return c.SarifRisksFilenameValue
}

func (c *Config) GetJsonTechnicalAssetsFilename() string {
	return c.JsonTechnicalAssetsFilenameValue
}

func (c *Config) GetJsonStatsFilename() string {
	return c.JsonStatsFilenameValue
}

func (c *Config) GetReportLogoImagePath() string {
	return c.ReportLogoImagePathValue
}

func (c *Config) GetTemplateFilename() string {
	return c.TemplateFilenameValue
}

func (c *Config) SetTemplateFilename(templateFilename string) {
	c.TemplateFilenameValue = templateFilename
}

func (c *Config) GetRiskRulePlugins() []string {
	return c.RiskRulePluginsValue
}

func (c *Config) SetRiskRulePlugins(riskRulePlugins []string) {
	c.RiskRulePluginsValue = riskRulePlugins
}

func (c *Config) GetSkipRiskRules() []string {
	return c.SkipRiskRulesValue
}

func (c *Config) SetSkipRiskRules(skipRiskRules []string) {
	c.SkipRiskRulesValue = skipRiskRules
}

func (c *Config) GetExecuteModelMacro() string {
	return c.ExecuteModelMacroValue
}

func (c *Config) GetRulesDir() string {
	return c.RulesDirValue
}

func (c *Config) SetRulesDir(dir string) {
	c.RulesDirValue = dir
}

func (c *Config) GetRulesURL() string {
	return c.RulesURLValue
}

func (c *Config) SetRulesURL(url string) {
	c.RulesURLValue = url
}

func (c *Config) GetRulesURLs() []string {
	urls := make([]string, 0, len(c.RulesURLsValue)+1)
	if strings.TrimSpace(c.RulesURLValue) != "" {
		urls = append(urls, c.RulesURLValue)
	}
	for _, rawURL := range c.RulesURLsValue {
		if strings.TrimSpace(rawURL) != "" {
			urls = append(urls, rawURL)
		}
	}
	return urls
}

func (c *Config) GetRulesURLFile() string {
	return c.RulesURLFileValue
}

func (c *Config) GetRulesTrustedKeys() []string {
	return c.RulesTrustedKeysValue
}

func (c *Config) GetRulesRequireSigned() bool {
	return c.RulesRequireSignedValue
}

func (c *Config) GetMethodology() string {
	if c.MethodologyValue == "" {
		return "stride"
	}
	return c.MethodologyValue
}

func (c *Config) SetMethodology(methodology string) {
	c.MethodologyValue = methodology
}

func (c *Config) GetRulePack() string {
	return c.RulePackValue
}

func (c *Config) SetRulePack(pack string) {
	c.RulePackValue = pack
}

func (c *Config) GetRiskExcelConfigHideColumns() []string {
	return c.RiskExcelValue.HideColumns
}

func (c *Config) GetRiskExcelConfigSortByColumns() []string {
	return c.RiskExcelValue.SortByColumns
}

func (c *Config) GetRiskExcelConfigWidthOfColumns() map[string]float64 {
	return c.RiskExcelValue.WidthOfColumns
}

func (c *Config) GetRiskExcelWrapText() bool {
	return c.RiskExcelValue.WrapText
}

func (c *Config) GetRiskExcelShrinkColumnsToFit() bool {
	return c.RiskExcelValue.ShrinkColumnsToFit
}

func (c *Config) GetRiskExcelColorText() bool {
	return c.RiskExcelValue.ColorText
}

func (c *Config) GetServerMode() bool {
	return c.ServerModeValue
}

func (c *Config) SetServerMode(serverMode bool) {
	c.ServerModeValue = serverMode
}

func (c *Config) GetServerPort() int {
	return c.ServerPortValue
}

func (c *Config) SetServerPort(serverPort int) {
	c.ServerPortValue = serverPort
}

func (c *Config) GetDiagramDPI() int {
	return c.DiagramDPIValue
}

func (c *Config) SetDiagramDPI(diagramDPI int) {
	c.DiagramDPIValue = diagramDPI
}

func (c *Config) GetGraphvizDPI() int {
	return c.GraphvizDPIValue
}

func (c *Config) GetMinGraphvizDPI() int {
	return MinGraphvizDPI
}

func (c *Config) GetMaxGraphvizDPI() int {
	return c.MaxGraphvizDPIValue
}

func (c *Config) GetBackupHistoryFilesToKeep() int {
	return c.BackupHistoryFilesToKeepValue
}

func (c *Config) GetAddModelTitle() bool {
	return c.AddModelTitleValue
}

func (c *Config) GetAddLegend() bool {
	return c.AddLegendValue
}

func (c *Config) GetKeepDiagramSourceFiles() bool {
	return c.KeepDiagramSourceFilesValue
}

func (c *Config) GetIgnoreOrphanedRiskTracking() bool {
	return c.IgnoreOrphanedRiskTrackingValue
}

func (c *Config) GetIgnoreExpiredRiskAcceptance() bool {
	return c.IgnoreExpiredRiskAcceptanceValue
}

func (c *Config) SetIgnoreOrphanedRiskTracking(ignoreOrphanedRiskTracking bool) {
	c.IgnoreOrphanedRiskTrackingValue = ignoreOrphanedRiskTracking
}

func (c *Config) GetSkipDataFlowDiagram() bool {
	return c.SkipDataFlowDiagramValue
}

func (c *Config) GetSkipDataAssetDiagram() bool {
	return c.SkipDataAssetDiagramValue
}

func (c *Config) GetSkipRisksJSON() bool {
	return c.SkipRisksJSONValue
}

func (c *Config) GetSkipRisksSARIF() bool {
	return c.SkipRisksSARIFValue
}

func (c *Config) GetSkipTechnicalAssetsJSON() bool {
	return c.SkipTechnicalAssetsJSONValue
}

func (c *Config) GetSkipStatsJSON() bool {
	return c.SkipStatsJSONValue
}

func (c *Config) GetSkipRisksExcel() bool {
	return c.SkipRisksExcelValue
}

func (c *Config) GetSkipTagsExcel() bool {
	return c.SkipTagsExcelValue
}

func (c *Config) GetSkipReportPDF() bool {
	return c.SkipReportPDFValue
}

func (c *Config) GetSkipReportADOC() bool {
	return c.SkipReportADOCValue
}

func (c *Config) GetAttractiveness() Attractiveness {
	return c.AttractivenessValue
}

func (c *Config) GetReportConfiguration() report.ReportConfiguation {
	return c.ReportConfigurationValue
}

func (c *Config) GetThreagileVersion() string {
	return ThreagileVersion
}

func (c *Config) GetProgressReporter() types.ProgressReporter {
	return DefaultProgressReporter{Verbose: c.VerboseValue}
}

func (c *Config) GetReportConfigurationHideChapters() map[report.ChaptersToShowHide]bool {
	return c.ReportConfigurationValue.HideChapter
}
