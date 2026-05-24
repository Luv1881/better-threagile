package risks

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/report"
	"github.com/threagile/threagile/pkg/types"
)

type RulePackTestResult struct {
	Name     string
	Passed   bool
	Expected []string
	Actual   []string
}

type RulePackTestFailure struct {
	Result  RulePackTestResult
	Message string
}

func (f RulePackTestFailure) Error() string {
	return f.Message
}

// RunRulePackTests runs golden tests from <ruleDir>/tests/<rule-id>/{model.yaml,expected.json}.
func RunRulePackTests(ruleDir string, methodology string) ([]RulePackTestResult, error) {
	rules, err := LoadExternalScriptRiskRules(ruleDir)
	if err != nil {
		return nil, err
	}

	testsDir := filepath.Join(ruleDir, "tests")
	entries, err := os.ReadDir(testsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read rule tests from %q: %w", testsDir, err)
	}

	results := make([]RulePackTestResult, 0)
	failures := make([]error, 0)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		result, err := runRulePackTest(filepath.Join(testsDir, entry.Name()), entry.Name(), rules, methodology)
		results = append(results, result)
		if err != nil {
			failures = append(failures, err)
		}
	}

	if len(failures) > 0 {
		return results, fmt.Errorf("%d rule test(s) failed", len(failures))
	}
	return results, nil
}

func runRulePackTest(testDir, ruleID string, rules types.RiskRules, methodology string) (RulePackTestResult, error) {
	result := RulePackTestResult{Name: ruleID}

	modelInput := new(input.Model).Defaults()
	if err := modelInput.Load(filepath.Join(testDir, "model.yaml")); err != nil {
		return result, fmt.Errorf("%s: failed to load model.yaml: %w", ruleID, err)
	}

	expected, err := readExpectedSyntheticIDs(filepath.Join(testDir, "expected.json"))
	if err != nil {
		return result, fmt.Errorf("%s: %w", ruleID, err)
	}
	result.Expected = expected

	selectedRules := make(types.RiskRules)
	if rule, ok := rules[ruleID]; ok {
		selectedRules[ruleID] = rule
	} else {
		return result, fmt.Errorf("%s: no rule with matching ID found in pack", ruleID)
	}

	cfg := ruleTestConfig{
		appFolder:              ".",
		inputFile:              filepath.Join(testDir, "model.yaml"),
		methodology:            methodology,
		ignoreOrphanedTracking: true,
		reporter:               noopProgressReporter{},
	}
	readResult, err := model.AnalyzeModel(modelInput, cfg, selectedRules, make(types.RiskRules), noopProgressReporter{})
	if err != nil {
		return result, fmt.Errorf("%s: failed to analyze model: %w", ruleID, err)
	}

	actual := make([]string, 0, len(readResult.ParsedModel.GeneratedRisksBySyntheticId))
	for _, risk := range readResult.ParsedModel.GeneratedRisksBySyntheticId {
		actual = append(actual, risk.SyntheticId)
	}
	sort.Strings(actual)
	result.Actual = actual
	result.Passed = equalStringSlices(expected, actual)
	if !result.Passed {
		return result, RulePackTestFailure{
			Result: result,
			Message: fmt.Sprintf("%s: expected [%s], got [%s]",
				ruleID, strings.Join(expected, ", "), strings.Join(actual, ", ")),
		}
	}

	return result, nil
}

func readExpectedSyntheticIDs(filename string) ([]string, error) {
	data, err := os.ReadFile(filepath.Clean(filename))
	if err != nil {
		return nil, fmt.Errorf("failed to read expected.json: %w", err)
	}

	var stringIDs []string
	if err := json.Unmarshal(data, &stringIDs); err == nil {
		sort.Strings(stringIDs)
		return stringIDs, nil
	}

	var object struct {
		SyntheticIDs []string `json:"synthetic_ids"`
		Risks        []struct {
			SyntheticID string `json:"synthetic_id"`
		} `json:"risks"`
	}
	if err := json.Unmarshal(data, &object); err != nil {
		return nil, fmt.Errorf("failed to parse expected.json: %w", err)
	}

	ids := append([]string{}, object.SyntheticIDs...)
	for _, risk := range object.Risks {
		if risk.SyntheticID != "" {
			ids = append(ids, risk.SyntheticID)
		}
	}
	sort.Strings(ids)
	return ids, nil
}

func equalStringSlices(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

type ruleTestConfig struct {
	appFolder              string
	inputFile              string
	methodology            string
	ignoreOrphanedTracking bool
	reporter               types.ProgressReporter
}

func (c ruleTestConfig) GetBuildTimestamp() string                            { return "" }
func (c ruleTestConfig) GetVerbose() bool                                     { return false }
func (c ruleTestConfig) GetInteractive() bool                                 { return false }
func (c ruleTestConfig) GetAppFolder() string                                 { return c.appFolder }
func (c ruleTestConfig) GetPluginFolder() string                              { return "" }
func (c ruleTestConfig) GetDataFolder() string                                { return "." }
func (c ruleTestConfig) GetOutputFolder() string                              { return "." }
func (c ruleTestConfig) GetServerFolder() string                              { return "" }
func (c ruleTestConfig) GetTempFolder() string                                { return os.TempDir() }
func (c ruleTestConfig) GetKeyFolder() string                                 { return "" }
func (c ruleTestConfig) GetInputFile() string                                 { return c.inputFile }
func (c ruleTestConfig) GetImportedInputFile() string                         { return "" }
func (c ruleTestConfig) GetDataFlowDiagramFilenamePNG() string                { return "" }
func (c ruleTestConfig) GetDataAssetDiagramFilenamePNG() string               { return "" }
func (c ruleTestConfig) GetDataFlowDiagramFilenameDOT() string                { return "" }
func (c ruleTestConfig) GetDataAssetDiagramFilenameDOT() string               { return "" }
func (c ruleTestConfig) GetReportFilename() string                            { return "" }
func (c ruleTestConfig) GetExcelRisksFilename() string                        { return "" }
func (c ruleTestConfig) GetExcelTagsFilename() string                         { return "" }
func (c ruleTestConfig) GetJsonRisksFilename() string                         { return "" }
func (c ruleTestConfig) GetJsonTechnicalAssetsFilename() string               { return "" }
func (c ruleTestConfig) GetJsonStatsFilename() string                         { return "" }
func (c ruleTestConfig) GetTemplateFilename() string                          { return "" }
func (c ruleTestConfig) GetTechnologyFilename() string                        { return "" }
func (c ruleTestConfig) GetRiskRulePlugins() []string                         { return nil }
func (c ruleTestConfig) GetSkipRiskRules() []string                           { return nil }
func (c ruleTestConfig) GetExecuteModelMacro() string                         { return "" }
func (c ruleTestConfig) GetRiskExcelConfigHideColumns() []string              { return nil }
func (c ruleTestConfig) GetRiskExcelConfigSortByColumns() []string            { return nil }
func (c ruleTestConfig) GetRiskExcelConfigWidthOfColumns() map[string]float64 { return nil }
func (c ruleTestConfig) GetMethodology() string {
	if c.methodology == "" {
		return "stride"
	}
	return c.methodology
}
func (c ruleTestConfig) GetServerMode() bool                         { return false }
func (c ruleTestConfig) GetDiagramDPI() int                          { return 0 }
func (c ruleTestConfig) GetServerPort() int                          { return 0 }
func (c ruleTestConfig) GetGraphvizDPI() int                         { return 0 }
func (c ruleTestConfig) GetMaxGraphvizDPI() int                      { return 0 }
func (c ruleTestConfig) GetBackupHistoryFilesToKeep() int            { return 0 }
func (c ruleTestConfig) GetAddModelTitle() bool                      { return false }
func (c ruleTestConfig) GetAddLegend() bool                          { return false }
func (c ruleTestConfig) GetKeepDiagramSourceFiles() bool             { return false }
func (c ruleTestConfig) GetIgnoreOrphanedRiskTracking() bool         { return c.ignoreOrphanedTracking }
func (c ruleTestConfig) GetThreagileVersion() string                 { return "" }
func (c ruleTestConfig) GetProgressReporter() types.ProgressReporter { return c.reporter }
func (c ruleTestConfig) GetReportConfiguration() report.ReportConfiguation {
	return report.ReportConfiguation{}
}

type noopProgressReporter struct{}

func (noopProgressReporter) Info(a ...any)                  {}
func (noopProgressReporter) Warn(a ...any)                  {}
func (noopProgressReporter) Error(a ...any)                 {}
func (noopProgressReporter) Infof(format string, a ...any)  {}
func (noopProgressReporter) Warnf(format string, a ...any)  {}
func (noopProgressReporter) Errorf(format string, a ...any) {}
