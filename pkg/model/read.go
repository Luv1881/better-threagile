package model

import (
	"fmt"
	"runtime"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"

	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/risks/script/common"
	"github.com/threagile/threagile/pkg/types"
)

type ReadResult struct {
	ModelInput       *input.Model
	ParsedModel      *types.Model
	IntroTextRAA     string
	BuiltinRiskRules types.RiskRules
	CustomRiskRules  types.RiskRules
}

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

	// Acceptance expiry: fail (or warn, with --ignore-expired-risk-acceptance)
	// when an accepted risk's accepted_until date has passed. Config support is
	// optional so existing configReader implementations keep working.
	ignoreExpired := false
	if expiryConfig, ok := config.(interface{ GetIgnoreExpiredRiskAcceptance() bool }); ok {
		ignoreExpired = expiryConfig.GetIgnoreExpiredRiskAcceptance()
	}
	err = parsedModel.CheckAcceptanceExpiry(types.Date{Time: time.Now()}, ignoreExpired, progressReporter)
	if err != nil {
		return nil, fmt.Errorf("risk acceptance expiry check failed: %w", err)
	}

	// Merge tracking statuses into the generated risks now that all tracking
	// entries (incl. wildcard-expanded ones) exist — downstream consumers
	// (risks JSON/SARIF/reports) must all see the same current statuses.
	parsedModel.GeneratedRisksByCategoryWithCurrentStatus()

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

	// Pre-convert the model to the map representation used by script-rule
	// scopes once, instead of re-marshaling/unmarshaling it for every rule.
	// Safe because script rules only ever read from $model, never write to it.
	modelMap, modelMapErr := common.ModelToMap(parsedModel)
	if modelMapErr != nil {
		progressReporter.Warnf("Unable to convert model to map for script rules: %v", modelMapErr)
	}

	jobs := make(chan ruleEntry, len(activeRules))
	results := make(chan ruleResult, len(activeRules))
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for entry := range jobs {
				var newRisks []*types.Risk
				var riskErr error
				if mapRule, ok := entry.rule.(types.ModelMapRiskRule); ok && modelMap != nil {
					newRisks, riskErr = mapRule.GenerateRisksFromMap(modelMap)
				} else {
					newRisks, riskErr = entry.rule.GenerateRisks(parsedModel)
				}
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

	// Collect into a local map first: writing directly into
	// parsedModel.GeneratedRisksByCategory here would race with script-rule
	// workers that are still running and marshal the whole parsedModel
	// (including this map) via Scope.SetModel.
	collected := make(map[string][]*types.Risk, len(activeRules))
	for res := range results {
		if res.err != nil {
			progressReporter.Warnf("Error generating risks for %q: %v", res.id, res.err)
			continue
		}
		if len(res.risks) > 0 {
			collected[res.id] = res.risks
		}
	}
	for id, riskList := range collected {
		// Rules may emit risks in map-iteration order; sort each category's
		// slice so generated output is deterministic across runs.
		types.SortByRiskSeverity(riskList)
		parsedModel.GeneratedRisksByCategory[id] = riskList
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

	// save also in map keyed by synthetic risk-id; iterate the raw category map
	// directly — going through SortedRisksOfCategory here would trigger the
	// one-shot status-application cache (statusApplied) before wildcard
	// risk-tracking entries are expanded, silently dropping their statuses.
	for _, generatedRisks := range parsedModel.GeneratedRisksByCategory {
		for _, risk := range generatedRisks {
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

	if mkdirErr := os.MkdirAll(filepath.Dir(filename), 0750); mkdirErr != nil {
		progressReporter.Warnf("Unable to create directory for %v: %v", name, mkdirErr)
		return
	}

	writeError := os.WriteFile(filename, exported, 0600)
	if writeError != nil {
		progressReporter.Warnf("Unable to write %v to %q: %v", name, filename, writeError)
		return
	}

	progressReporter.Infof("Wrote %v to %q", name, filename)
}
