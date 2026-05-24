package model

import (
	"fmt"
	"runtime"
	"sync"

	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"

	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/types"
)

type ReadResult struct {
	ModelInput       *input.Model
	ParsedModel      *types.Model
	IntroTextRAA     string
	BuiltinRiskRules types.RiskRules
	CustomRiskRules  types.RiskRules
}

type explainRiskConfig interface {
}

type explainRiskReporter interface {
}

func (what ReadResult) ExplainRisk(cfg explainRiskConfig, risk string, reporter explainRiskReporter) error {
	return fmt.Errorf("not implemented")
}

// TODO: consider about splitting this function into smaller ones for better reusability

type configReader interface {
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
	GetInputFile() string
	GetImportedInputFile() string
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
	GetTemplateFilename() string
	GetTechnologyFilename() string
	GetRiskRulePlugins() []string
	GetSkipRiskRules() []string
	GetExecuteModelMacro() string
	GetRiskExcelConfigHideColumns() []string
	GetRiskExcelConfigSortByColumns() []string
	GetRiskExcelConfigWidthOfColumns() map[string]float64
	GetMethodology() string
	GetServerMode() bool
	GetDiagramDPI() int
	GetServerPort() int
	GetGraphvizDPI() int
	GetMaxGraphvizDPI() int
	GetBackupHistoryFilesToKeep() int
	GetAddModelTitle() bool
	GetAddLegend() bool
	GetKeepDiagramSourceFiles() bool
	GetIgnoreOrphanedRiskTracking() bool
	GetThreagileVersion() string
	GetProgressReporter() types.ProgressReporter
}

func ReadAndAnalyzeModel(config configReader, builtinRiskRules types.RiskRules, progressReporter types.ProgressReporter) (*ReadResult, error) {
	progressReporter.Infof("Writing into output directory: %v", config.GetOutputFolder())
	progressReporter.Infof("Parsing model: %v", config.GetInputFile())

	customRiskRules := LoadCustomRiskRules(config.GetPluginFolder(), config.GetRiskRulePlugins(), progressReporter)

	modelInput := new(input.Model).Defaults()
	loadError := modelInput.Load(config.GetInputFile())
	if loadError != nil {
		return nil, fmt.Errorf("unable to load model yaml: %w", loadError)
	}

	result, analysisError := AnalyzeModel(modelInput, config, builtinRiskRules, customRiskRules, progressReporter)
	if analysisError == nil {
		writeToFile("model yaml", result.ParsedModel, config.GetImportedInputFile(), progressReporter)
	}

	return result, analysisError
}

func AnalyzeModel(modelInput *input.Model, config configReader, builtinRiskRules types.RiskRules, customRiskRules types.RiskRules, progressReporter types.ProgressReporter) (*ReadResult, error) {

	parsedModel, parseError := ParseModel(config, modelInput, builtinRiskRules, customRiskRules)
	if parseError != nil {
		return nil, fmt.Errorf("unable to parse model yaml: %w", parseError)
	}

	introTextRAA := applyRAA(parsedModel, progressReporter)

	applyRiskGeneration(parsedModel, builtinRiskRules.Merge(customRiskRules), config.GetSkipRiskRules(), config.GetMethodology(), progressReporter)
	err := parsedModel.ApplyWildcardRiskTrackingEvaluation(config.GetIgnoreOrphanedRiskTracking(), progressReporter)
	if err != nil {
		return nil, fmt.Errorf("unable to apply wildcard risk tracking evaluation: %w", err)
	}

	err = parsedModel.CheckRiskTracking(config.GetIgnoreOrphanedRiskTracking(), progressReporter)
	if err != nil {
		return nil, fmt.Errorf("unable to check risk tracking: %w", err)
	}

	return &ReadResult{
		ModelInput:       modelInput,
		ParsedModel:      parsedModel,
		IntroTextRAA:     introTextRAA,
		BuiltinRiskRules: builtinRiskRules,
		CustomRiskRules:  customRiskRules,
	}, nil
}

func applyRiskGeneration(parsedModel *types.Model, rules types.RiskRules,
	skipRiskRules []string, methodology string,
	progressReporter types.ProgressReporter) {
	progressReporter.Info("Applying risk generation")

	activeMethodology, parseErr := types.ParseMethodology(methodology)
	if parseErr != nil {
		progressReporter.Warnf("Unknown methodology %q, falling back to stride: %v", methodology, parseErr)
		activeMethodology = types.StrideMethodology
	}

	parsedModel.ActiveMethodology = activeMethodology

	skippedRules := make(map[string]bool)
	if len(skipRiskRules) > 0 {
		for _, id := range skipRiskRules {
			skippedRules[id] = true
		}
	}

	// Collect the rules that will actually run so we can fan them out to workers.
	type ruleEntry struct {
		id   string
		rule types.RiskRule
	}
	activeRules := make([]ruleEntry, 0, len(rules))
	for id, rule := range rules {
		if _, skip := skippedRules[id]; skip {
			progressReporter.Infof("Skipping risk rule: %v", id)
			delete(skippedRules, id)
			continue
		}
		if !rule.Category().HasClassification(activeMethodology) {
			continue
		}
		// SupportedTags registration is read-only on parsedModel so safe to do here.
		parsedModel.AddToListOfSupportedTags(rule.SupportedTags())
		activeRules = append(activeRules, ruleEntry{id: id, rule: rule})
	}

	// Fan out rule evaluation across a bounded goroutine pool.
	// Each rule reads parsedModel (read-only) and writes only to its own result bucket.
	// We collect results via a channel and merge after all workers finish.
	type ruleResult struct {
		id    string
		risks []*types.Risk
		err   error
	}

	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}

	jobs := make(chan ruleEntry, len(activeRules))
	results := make(chan ruleResult, len(activeRules))
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for entry := range jobs {
				newRisks, riskErr := entry.rule.GenerateRisks(parsedModel)
				results <- ruleResult{id: entry.id, risks: newRisks, err: riskErr}
			}
		}()
	}

	for _, entry := range activeRules {
		jobs <- entry
	}
	close(jobs)

	// Wait for all workers, then close results.
	go func() {
		wg.Wait()
		close(results)
	}()

	for res := range results {
		if res.err != nil {
			progressReporter.Warnf("Error generating risks for %q: %v", res.id, res.err)
			continue
		}
		if len(res.risks) > 0 {
			parsedModel.GeneratedRisksByCategory[res.id] = res.risks
		}
	}

	if len(skippedRules) > 0 {
		keys := make([]string, 0)
		for k := range skippedRules {
			keys = append(keys, k)
		}
		if len(keys) > 0 {
			progressReporter.Infof("Unknown risk rules to skip: %v", keys)
		}
	}

	// save also in map keyed by synthetic risk-id
	for _, category := range parsedModel.SortedRiskCategories() {
		someRisks := parsedModel.SortedRisksOfCategory(category)
		for _, risk := range someRisks {
			parsedModel.GeneratedRisksBySyntheticId[strings.ToLower(risk.SyntheticId)] = risk
		}
	}
}

func writeToFile(name string, item any, filename string, progressReporter types.ProgressReporter) {
	if item == nil {
		return
	}

	if filename == "" {
		return
	}

	exported, exportError := yaml.Marshal(item)
	if exportError != nil {
		progressReporter.Warnf("Unable to export %v: %v", name, exportError)
		return
	}

	_ = os.MkdirAll(filepath.Dir(filename), 0750)

	writeError := os.WriteFile(filename, exported, 0600)
	if writeError != nil {
		progressReporter.Warnf("Unable to write %v to %q: %v", name, filename, writeError)
		return
	}

	progressReporter.Infof("Wrote %v to %q", name, filename)
}
