package threagile

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/threagile/threagile/pkg/report"
	"github.com/threagile/threagile/pkg/types"
)

type Config struct {
	ConfigGetter
	ConfigSetter

	BuildTimestampValue string `json:"BuildTimestamp,omitempty" yaml:"BuildTimestamp"`
	VerboseValue        bool   `json:"Verbose,omitempty" yaml:"Verbose"`
	InteractiveValue    bool   `json:"Interactive,omitempty" yaml:"Interactive"`

	AppFolderValue    string `json:"AppFolder,omitempty" yaml:"AppFolder"`
	PluginFolderValue string `json:"PluginFolder,omitempty" yaml:"PluginFolder"`
	DataFolderValue   string `json:"DataFolder,omitempty" yaml:"DataFolder"`
	OutputFolderValue string `json:"OutputFolder,omitempty" yaml:"OutputFolder"`
	ServerFolderValue string `json:"ServerFolder,omitempty" yaml:"ServerFolder"`
	TempFolderValue   string `json:"TempFolder,omitempty" yaml:"TempFolder"`
	KeyFolderValue    string `json:"KeyFolder,omitempty" yaml:"KeyFolder"`

	InputFileValue                   string `json:"InputFile,omitempty" yaml:"InputFile"`
	ImportedInputFileValue           string `json:"ImportedInputFile,omitempty" yaml:"ImportedInputFile"`
	DataFlowDiagramFilenamePNGValue  string `json:"DataFlowDiagramFilenamePNG,omitempty" yaml:"DataFlowDiagramFilenamePNG"`
	DataAssetDiagramFilenamePNGValue string `json:"DataAssetDiagramFilenamePNG,omitempty" yaml:"DataAssetDiagramFilenamePNG"`
	DataFlowDiagramFilenameDOTValue  string `json:"DataFlowDiagramFilenameDOT,omitempty" yaml:"DataFlowDiagramFilenameDOT"`
	DataAssetDiagramFilenameDOTValue string `json:"DataAssetDiagramFilenameDOT,omitempty" yaml:"DataAssetDiagramFilenameDOT"`
	ReportFilenameValue              string `json:"ReportFilename,omitempty" yaml:"ReportFilename"`
	ExcelRisksFilenameValue          string `json:"ExcelRisksFilename,omitempty" yaml:"ExcelRisksFilename"`
	ExcelTagsFilenameValue           string `json:"ExcelTagsFilename,omitempty" yaml:"ExcelTagsFilename"`
	JsonRisksFilenameValue           string `json:"JsonRisksFilename,omitempty" yaml:"JsonRisksFilename"`
	JsonTechnicalAssetsFilenameValue string `json:"JsonTechnicalAssetsFilename,omitempty" yaml:"JsonTechnicalAssetsFilename"`
	JsonStatsFilenameValue           string `json:"JsonStatsFilename,omitempty" yaml:"JsonStatsFilename"`
	TemplateFilenameValue            string `json:"TemplateFilename,omitempty" yaml:"TemplateFilename"`
	ReportLogoImagePathValue         string `json:"ReportLogoImagePath,omitempty" yaml:"ReportLogoImagePath"`
	TechnologyFilenameValue          string `json:"TechnologyFilename,omitempty" yaml:"TechnologyFilename"`
	HideEmptyChaptersValue           bool   `json:"HideEmptyChapters,omitempty" yaml:"HideEmptyChapters"`

	RiskRulePluginsValue    []string        `json:"RiskRulePlugins,omitempty" yaml:"RiskRulePlugins"`
	SkipRiskRulesValue      []string        `json:"SkipRiskRules,omitempty" yaml:"SkipRiskRules"`
	ExecuteModelMacroValue  string          `json:"ExecuteModelMacro,omitempty" yaml:"ExecuteModelMacro"`
	RulesDirValue           string          `json:"RulesDir,omitempty" yaml:"RulesDir"`
	RulesURLValue           string          `json:"RulesURL,omitempty" yaml:"RulesURL"`
	RulesURLsValue          []string        `json:"RulesURLs,omitempty" yaml:"RulesURLs"`
	RulesURLFileValue       string          `json:"RulesURLFile,omitempty" yaml:"RulesURLFile"`
	RulesTrustedKeysValue   []string        `json:"RulesTrustedKeys,omitempty" yaml:"RulesTrustedKeys"`
	RulesRequireSignedValue bool            `json:"RulesRequireSigned,omitempty" yaml:"RulesRequireSigned"`
	MethodologyValue        string          `json:"Methodology,omitempty" yaml:"Methodology"`
	RulePackValue           string          `json:"RulePack,omitempty" yaml:"RulePack"`
	RiskExcelValue          RiskExcelConfig `json:"RiskExcel" yaml:"RiskExcel"`

	ServerModeValue               bool `json:"ServerMode,omitempty" yaml:"ServerMode"`
	ServerPortValue               int  `json:"ServerPort,omitempty" yaml:"ServerPort"`
	DiagramDPIValue               int  `json:"DiagramDPI,omitempty" yaml:"DiagramDPI"`
	GraphvizDPIValue              int  `json:"GraphvizDPI,omitempty" yaml:"GraphvizDPI"`
	MaxGraphvizDPIValue           int  `json:"MaxGraphvizDPI,omitempty" yaml:"MaxGraphvizDPI"`
	BackupHistoryFilesToKeepValue int  `json:"BackupHistoryFilesToKeep,omitempty" yaml:"BackupHistoryFilesToKeep"`

	AddModelTitleValue              bool `json:"AddModelTitle,omitempty" yaml:"AddModelTitle"`
	AddLegendValue                  bool `json:"AddLegend,omitempty" yaml:"AddLegend"`
	KeepDiagramSourceFilesValue     bool `json:"KeepDiagramSourceFiles,omitempty" yaml:"KeepDiagramSourceFiles"`
	IgnoreOrphanedRiskTrackingValue bool `json:"IgnoreOrphanedRiskTracking,omitempty" yaml:"IgnoreOrphanedRiskTracking"`

	SkipDataFlowDiagramValue     bool `json:"SkipDataFlowDiagram,omitempty" yaml:"SkipDataFlowDiagram"`
	SkipDataAssetDiagramValue    bool `json:"SkipDataAssetDiagram,omitempty" yaml:"SkipDataAssetDiagram"`
	SkipRisksJSONValue           bool `json:"SkipRisksJSON,omitempty" yaml:"SkipRisksJSON"`
	SkipTechnicalAssetsJSONValue bool `json:"SkipTechnicalAssetsJSON,omitempty" yaml:"SkipTechnicalAssetsJSON"`
	SkipStatsJSONValue           bool `json:"SkipStatsJSON,omitempty" yaml:"SkipStatsJSON"`
	SkipRisksExcelValue          bool `json:"SkipRisksExcel,omitempty" yaml:"SkipRisksExcel"`
	SkipTagsExcelValue           bool `json:"SkipTagsExcel,omitempty" yaml:"SkipTagsExcel"`
	SkipReportPDFValue           bool `json:"SkipReportPDF,omitempty" yaml:"SkipReportPDF"`
	SkipReportADOCValue          bool `json:"SkipReportADOC,omitempty" yaml:"SkipReportADOC"`

	AttractivenessValue Attractiveness `json:"Attractiveness" yaml:"Attractiveness"`

	ReportConfigurationValue report.ReportConfiguation `json:"ReportConfiguration" yaml:"ReportConfiguration"`
}

type ConfigGetter interface {
	GetBuildTimestamp() string
	GetVerbose() bool
	GetInteractive() bool
	GetAppFolder() string
	GetPluginFolder() string
	GetDataFolder() string
	GetOutputFolder() string
	GetServerFolder() string
	GetTempFolder() string
	GetKeyFolder() string
	GetTechnologyFilename() string
	GetInputFile() string
	GetDataFlowDiagramFilenamePNG() string
	GetDataAssetDiagramFilenamePNG() string
	GetDataFlowDiagramFilenameDOT() string
	GetDataAssetDiagramFilenameDOT() string
	GetReportFilename() string
	GetExcelRisksFilename() string
	GetExcelTagsFilename() string
	GetJsonRisksFilename() string
	GetJsonTechnicalAssetsFilename() string
	GetJsonStatsFilename() string
	GetReportLogoImagePath() string
	GetTemplateFilename() string
	GetRiskRulePlugins() []string
	GetSkipRiskRules() []string
	GetExecuteModelMacro() string
	GetRulesDir() string
	GetRulesURL() string
	GetRulesURLs() []string
	GetRulesURLFile() string
	GetRulesTrustedKeys() []string
	GetRulesRequireSigned() bool
	GetMethodology() string
	GetRulePack() string
	GetRiskExcelConfigHideColumns() []string
	GetRiskExcelConfigSortByColumns() []string
	GetRiskExcelConfigWidthOfColumns() map[string]float64
	GetRiskExcelWrapText() bool
	GetRiskExcelShrinkColumnsToFit() bool
	GetRiskExcelColorText() bool
	GetServerMode() bool
	GetServerPort() int
	GetDiagramDPI() int
	GetGraphvizDPI() int
	GetMinGraphvizDPI() int
	GetMaxGraphvizDPI() int
	GetBackupHistoryFilesToKeep() int
	GetAddModelTitle() bool
	GetAddLegend() bool
	GetKeepDiagramSourceFiles() bool
	GetIgnoreOrphanedRiskTracking() bool
	GetSkipDataFlowDiagram() bool
	GetSkipDataAssetDiagram() bool
	GetSkipRisksJSON() bool
	GetSkipTechnicalAssetsJSON() bool
	GetSkipStatsJSON() bool
	GetSkipRisksExcel() bool
	GetSkipTagsExcel() bool
	GetSkipReportPDF() bool
	GetSkipReportADOC() bool
	GetAttractiveness() Attractiveness
	GetReportConfiguration() report.ReportConfiguation
	GetThreagileVersion() string
	GetProgressReporter() types.ProgressReporter
	GetReportConfigurationHideChapters() map[report.ChaptersToShowHide]bool
}
type ConfigSetter interface {
	SetVerbose(verbose bool)
	SetInteractive(interactive bool)
	SetAppFolder(appFolder string)
	SetPluginFolder(pluginFolder string)
	SetOutputFolder(outputFolder string)
	SetServerFolder(serverFolder string)
	SetTempFolder(tempFolder string)
	SetInputFile(inputFile string)
	SetTemplateFilename(templateFilename string)
	SetRiskRulePlugins(riskRulePlugins []string)
	SetSkipRiskRules(skipRiskRules []string)
	SetServerMode(serverMode bool)
	SetServerPort(serverPort int)
	SetDiagramDPI(diagramDPI int)
	SetIgnoreOrphanedRiskTracking(ignoreOrphanedRiskTracking bool)
}

func (c *Config) Defaults(buildTimestamp string) *Config {
	*c = Config{
		BuildTimestampValue: buildTimestamp,
		VerboseValue:        false,
		InteractiveValue:    false,

		AppFolderValue:    AppDir,
		PluginFolderValue: PluginDir,
		DataFolderValue:   DataDir,
		OutputFolderValue: OutputDir,
		ServerFolderValue: ServerDir,
		TempFolderValue:   TempDir,
		KeyFolderValue:    KeyDir,

		InputFileValue:                   InputFile,
		DataFlowDiagramFilenamePNGValue:  DataFlowDiagramFilenamePNG,
		DataAssetDiagramFilenamePNGValue: DataAssetDiagramFilenamePNG,
		DataFlowDiagramFilenameDOTValue:  DataFlowDiagramFilenameDOT,
		DataAssetDiagramFilenameDOTValue: DataAssetDiagramFilenameDOT,
		ReportFilenameValue:              ReportFilename,
		ExcelRisksFilenameValue:          ExcelRisksFilename,
		ExcelTagsFilenameValue:           ExcelTagsFilename,
		JsonRisksFilenameValue:           JsonRisksFilename,
		JsonTechnicalAssetsFilenameValue: JsonTechnicalAssetsFilename,
		JsonStatsFilenameValue:           JsonStatsFilename,
		TemplateFilenameValue:            TemplateFilename,
		ReportLogoImagePathValue:         ReportLogoImagePath,
		TechnologyFilenameValue:          "",
		HideEmptyChaptersValue:           false,

		RiskRulePluginsValue:   make([]string, 0),
		SkipRiskRulesValue:     make([]string, 0),
		ExecuteModelMacroValue: "",
		RulesURLsValue:         make([]string, 0),
		RulesTrustedKeysValue:  make([]string, 0),
		RiskExcelValue: RiskExcelConfig{
			HideColumns:        make([]string, 0),
			SortByColumns:      make([]string, 0),
			WidthOfColumns:     make(map[string]float64),
			ShrinkColumnsToFit: true,
			WrapText:           false,
			ColorText:          true,
		},

		ServerModeValue:               false,
		DiagramDPIValue:               DefaultDiagramDPI,
		ServerPortValue:               DefaultServerPort,
		GraphvizDPIValue:              DefaultGraphvizDPI,
		MaxGraphvizDPIValue:           MaxGraphvizDPI,
		BackupHistoryFilesToKeepValue: DefaultBackupHistoryFilesToKeep,

		AddModelTitleValue:              false,
		AddLegendValue:                  false,
		KeepDiagramSourceFilesValue:     false,
		IgnoreOrphanedRiskTrackingValue: false,

		AttractivenessValue: Attractiveness{
			Quantity: 0,
			Confidentiality: AttackerFocus{
				Asset:                 0,
				ProcessedOrStoredData: 0,
				TransferredData:       0,
			},
			Integrity: AttackerFocus{
				Asset:                 0,
				ProcessedOrStoredData: 0,
				TransferredData:       0,
			},
			Availability: AttackerFocus{
				Asset:                 0,
				ProcessedOrStoredData: 0,
				TransferredData:       0,
			},
		},

		ReportConfigurationValue: report.ReportConfiguation{
			HideChapter: make(map[report.ChaptersToShowHide]bool),
		},
	}

	return c
}

func (c *Config) Load(configFilename string) error {
	if len(configFilename) == 0 {
		return nil
	}

	data, readError := os.ReadFile(filepath.Clean(configFilename))
	if readError != nil {
		return readError
	}

	values := make(map[string]any)
	var config Config

	if strings.HasSuffix(configFilename, ".yaml") {
		parseError := yaml.Unmarshal(data, &values)
		if parseError != nil {
			return fmt.Errorf("failed to parse keys of yaml config file %q: %w", configFilename, parseError)
		}

		unmarshalError := yaml.Unmarshal(data, &config)
		if unmarshalError != nil {
			return fmt.Errorf("failed to parse yaml config file %q: %w", configFilename, unmarshalError)
		}
	} else {
		parseError := json.Unmarshal(data, &values)
		if parseError != nil {
			return fmt.Errorf("failed to parse keys of json config file %q: %w", configFilename, parseError)
		}

		unmarshalError := json.Unmarshal(data, &config)
		if unmarshalError != nil {
			return fmt.Errorf("failed to parse json config file %q: %w", configFilename, unmarshalError)
		}
	}

	c.Merge(config, values)

	errorList := make([]error, 0)
	c.TempFolderValue = c.CleanPath(c.TempFolderValue)
	tempDirError := os.MkdirAll(c.TempFolderValue, 0700)
	if tempDirError != nil {
		errorList = append(errorList, fmt.Errorf("failed to create temp dir %q: %w", c.TempFolderValue, tempDirError))
	}

	c.OutputFolderValue = c.CleanPath(c.OutputFolderValue)
	outDirError := os.MkdirAll(c.OutputFolderValue, 0700)
	if outDirError != nil {
		errorList = append(errorList, fmt.Errorf("failed to create output dir %q: %w", c.OutputFolderValue, outDirError))
	}

	c.AppFolderValue = c.CleanPath(c.AppFolderValue)
	appDirError := c.checkDir(c.AppFolderValue, "app")
	if appDirError != nil {
		errorList = append(errorList, appDirError)
	}

	c.PluginFolderValue = c.CleanPath(c.PluginFolderValue)
	pluginDirError := c.checkDir(c.PluginFolderValue, "plugin")
	if pluginDirError != nil {
		errorList = append(errorList, pluginDirError)
	}

	c.DataFolderValue = c.CleanPath(c.DataFolderValue)
	dataDirError := c.checkDir(c.DataFolderValue, "data")
	if dataDirError != nil {
		errorList = append(errorList, dataDirError)
	}

	if c.TechnologyFilenameValue != "" {
		c.TechnologyFilenameValue = c.CleanPath(c.TechnologyFilenameValue)
	}

	serverFolderError := c.CheckServerFolder()
	if serverFolderError != nil {
		errorList = append(errorList, serverFolderError)
	}

	if len(errorList) > 0 {
		return errors.Join(errorList...)
	}

	return nil
}

func (c *Config) CheckServerFolder() error {
	if c.ServerModeValue {
		c.ServerFolderValue = c.CleanPath(c.ServerFolderValue)
		serverDirError := c.checkDir(c.ServerFolderValue, "server")
		if serverDirError != nil {
			return serverDirError
		}

		keyDirError := os.MkdirAll(filepath.Join(c.ServerFolderValue, c.KeyFolderValue), 0700)
		if keyDirError != nil {
			return fmt.Errorf("failed to create key dir %q: %w", filepath.Join(c.ServerFolderValue, c.KeyFolderValue), keyDirError)
		}
	}

	return nil
}

func (c *Config) Merge(config Config, values map[string]any) {
	for key := range values {
		switch strings.ToLower(key) {
		case strings.ToLower("BuildTimestamp"):
			c.BuildTimestampValue = config.BuildTimestampValue

		case strings.ToLower("Verbose"):
			c.VerboseValue = config.VerboseValue

		case strings.ToLower("Interactive"):
			c.InteractiveValue = config.InteractiveValue

		case strings.ToLower("AppFolder"):
			c.AppFolderValue = config.AppFolderValue

		case strings.ToLower("PluginFolder"):
			c.PluginFolderValue = config.PluginFolderValue

		case strings.ToLower("DataFolder"):
			c.DataFolderValue = config.DataFolderValue

		case strings.ToLower("OutputFolder"):
			c.OutputFolderValue = config.OutputFolderValue

		case strings.ToLower("ServerFolder"):
			c.ServerFolderValue = config.ServerFolderValue

		case strings.ToLower("TempFolder"):
			c.TempFolderValue = config.TempFolderValue

		case strings.ToLower("KeyFolder"):
			c.KeyFolderValue = config.KeyFolderValue

		case strings.ToLower("InputFile"):
			c.InputFileValue = config.InputFileValue

		case strings.ToLower("ImportedInputFile"):
			c.ImportedInputFileValue = config.ImportedInputFileValue

		case strings.ToLower("DataFlowDiagramFilenamePNG"):
			c.DataFlowDiagramFilenamePNGValue = config.DataFlowDiagramFilenamePNGValue

		case strings.ToLower("DataAssetDiagramFilenamePNG"):
			c.DataAssetDiagramFilenamePNGValue = config.DataAssetDiagramFilenamePNGValue

		case strings.ToLower("DataFlowDiagramFilenameDOT"):
			c.DataFlowDiagramFilenameDOTValue = config.DataFlowDiagramFilenameDOTValue

		case strings.ToLower("DataAssetDiagramFilenameDOT"):
			c.DataAssetDiagramFilenameDOTValue = config.DataAssetDiagramFilenameDOTValue

		case strings.ToLower("ReportFilename"):
			c.ReportFilenameValue = config.ReportFilenameValue

		case strings.ToLower("ExcelRisksFilename"):
			c.ExcelRisksFilenameValue = config.ExcelRisksFilenameValue

		case strings.ToLower("ExcelTagsFilename"):
			c.ExcelTagsFilenameValue = config.ExcelTagsFilenameValue

		case strings.ToLower("JsonRisksFilename"):
			c.JsonRisksFilenameValue = config.JsonRisksFilenameValue

		case strings.ToLower("JsonTechnicalAssetsFilename"):
			c.JsonTechnicalAssetsFilenameValue = config.JsonTechnicalAssetsFilenameValue

		case strings.ToLower("JsonStatsFilename"):
			c.JsonStatsFilenameValue = config.JsonStatsFilenameValue

		case strings.ToLower("TemplateFilename"):
			c.TemplateFilenameValue = config.TemplateFilenameValue

		case strings.ToLower("ReportLogoImagePath"):
			c.ReportLogoImagePathValue = config.ReportLogoImagePathValue

		case strings.ToLower("TechnologyFilename"):
			c.TechnologyFilenameValue = config.TechnologyFilenameValue

		case strings.ToLower("HideEmptyChapters"):
			c.HideEmptyChaptersValue = config.HideEmptyChaptersValue

		case strings.ToLower("RiskRulePlugins"):
			c.RiskRulePluginsValue = config.RiskRulePluginsValue

		case strings.ToLower("SkipRiskRules"):
			c.SkipRiskRulesValue = config.SkipRiskRulesValue

		case strings.ToLower("ExecuteModelMacro"):
			c.ExecuteModelMacroValue = config.ExecuteModelMacroValue

		case strings.ToLower("RulesDir"):
			c.RulesDirValue = config.RulesDirValue

		case strings.ToLower("RulesURL"):
			c.RulesURLValue = config.RulesURLValue

		case strings.ToLower("RulesURLs"):
			c.RulesURLsValue = config.RulesURLsValue

		case strings.ToLower("RulesURLFile"):
			c.RulesURLFileValue = config.RulesURLFileValue

		case strings.ToLower("RulesTrustedKeys"):
			c.RulesTrustedKeysValue = config.RulesTrustedKeysValue

		case strings.ToLower("RulesRequireSigned"):
			c.RulesRequireSignedValue = config.RulesRequireSignedValue

		case strings.ToLower("Methodology"):
			c.MethodologyValue = config.MethodologyValue

		case strings.ToLower("RulePack"):
			c.RulePackValue = config.RulePackValue

		case strings.ToLower("RiskExcel"):
			configMap, mapOk := values[key].(map[string]any)
			if !mapOk {
				continue
			}

			for valueName := range configMap {
				switch strings.ToLower(valueName) {
				case strings.ToLower("HideColumns"):
					c.RiskExcelValue.HideColumns = append(c.RiskExcelValue.HideColumns, config.RiskExcelValue.HideColumns...)

				case strings.ToLower("SortByColumns"):
					c.RiskExcelValue.SortByColumns = append(c.RiskExcelValue.SortByColumns, config.RiskExcelValue.SortByColumns...)

				case strings.ToLower("WidthOfColumns"):
					if c.RiskExcelValue.WidthOfColumns == nil {
						c.RiskExcelValue.WidthOfColumns = make(map[string]float64)
					}

					for name, value := range config.RiskExcelValue.WidthOfColumns {
						c.RiskExcelValue.WidthOfColumns[name] = value
					}

				case strings.ToLower("ShrinkColumnsToFit"):
					c.RiskExcelValue.ShrinkColumnsToFit = config.RiskExcelValue.ShrinkColumnsToFit

				case strings.ToLower("WrapText"):
					c.RiskExcelValue.WrapText = config.RiskExcelValue.WrapText

				case strings.ToLower("ColorText"):
					c.RiskExcelValue.ColorText = config.RiskExcelValue.ColorText
				}
			}

		case strings.ToLower("ServerMode"):
			c.ServerModeValue = config.ServerModeValue

		case strings.ToLower("DiagramDPI"):
			c.DiagramDPIValue = config.DiagramDPIValue

		case strings.ToLower("ServerPort"):
			c.ServerPortValue = config.ServerPortValue

		case strings.ToLower("GraphvizDPI"):
			c.GraphvizDPIValue = config.GraphvizDPIValue

		case strings.ToLower("MaxGraphvizDPI"):
			c.MaxGraphvizDPIValue = config.MaxGraphvizDPIValue

		case strings.ToLower("BackupHistoryFilesToKeep"):
			c.BackupHistoryFilesToKeepValue = config.BackupHistoryFilesToKeepValue

		case strings.ToLower("AddModelTitle"):
			c.AddModelTitleValue = config.AddModelTitleValue

		case strings.ToLower("AddLegend"):
			c.AddLegendValue = config.AddLegendValue

		case strings.ToLower("KeepDiagramSourceFiles"):
			c.KeepDiagramSourceFilesValue = config.KeepDiagramSourceFilesValue

		case strings.ToLower("IgnoreOrphanedRiskTracking"):
			c.IgnoreOrphanedRiskTrackingValue = config.IgnoreOrphanedRiskTrackingValue

		case strings.ToLower("Attractiveness"):
			c.AttractivenessValue = config.AttractivenessValue

		case strings.ToLower("ReportConfiguration"):
			configMap, mapOk := values[key].(map[string]any)
			if !mapOk {
				continue
			}

			for valueName := range configMap {
				switch strings.ToLower(valueName) {
				case strings.ToLower("HideChapter"):
					if c.ReportConfigurationValue.HideChapter == nil {
						c.ReportConfigurationValue.HideChapter = make(map[report.ChaptersToShowHide]bool)
					}

					for chapter, value := range config.ReportConfigurationValue.HideChapter {
						c.ReportConfigurationValue.HideChapter[chapter] = value
						if value {
							log.Println("Hiding chapter: ", chapter)
						}
					}
				}
			}
		}
	}
}

func (c *Config) CleanPath(path string) string {
	return filepath.Clean(c.ExpandPath(path))
}

func (c *Config) checkDir(dir string, name string) error {
	dirInfo, dirError := os.Stat(dir)
	if dirError != nil {
		return fmt.Errorf("%v folder %q not good: %w", name, dir, dirError)
	}

	if !dirInfo.IsDir() {
		return fmt.Errorf("%v folder %q is not a folder", name, dir)
	}

	return nil
}

func (c *Config) ExpandPath(path string) string {
	home := c.UserHomeDir()
	if strings.HasPrefix(path, "~") {
		path = strings.Replace(path, "~", home, 1)
	}

	if strings.HasPrefix(path, "$HOME") {
		path = strings.ReplaceAll(path, "$HOME", home)
	}

	return path
}

func (c *Config) UserHomeDir() string {
	switch runtime.GOOS {
	case "windows":
		home := os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
		if home == "" {
			home = os.Getenv("USERPROFILE")
		}
		return home

	default:
		return os.Getenv("HOME")
	}
}
