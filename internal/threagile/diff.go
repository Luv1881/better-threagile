package threagile

import (
	"fmt"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/risks"
	"github.com/threagile/threagile/pkg/types"
)

func (what *Threagile) initDiff() *Threagile {
	diff := &cobra.Command{
		Use:   DiffCommand + " <old-model.yaml> <new-model.yaml>",
		Short: "Show the risk delta between two versions of a threat model",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			oldFile := args[0]
			newFile := args[1]

			methodology := what.config.GetMethodology()
			progressReporter := DefaultProgressReporter{Verbose: false}
			builtinRules := risks.GetBuiltInRiskRules()

			cmd.Printf("Computing risk delta: %s → %s\n", filepath.Base(oldFile), filepath.Base(newFile))
			cmd.Printf("Methodology: %s\n\n", methodology)

			// Temporarily override input file to run analysis on each model
			originalInput := what.config.GetInputFile()
			defer what.config.SetInputFile(originalInput)

			what.config.SetInputFile(oldFile)
			oldRisks, err := analyzeForDiff(what.config, builtinRules, progressReporter)
			if err != nil {
				return fmt.Errorf("failed to analyze old model: %w", err)
			}

			what.config.SetInputFile(newFile)
			newRisks, err := analyzeForDiff(what.config, builtinRules, progressReporter)
			if err != nil {
				return fmt.Errorf("failed to analyze new model: %w", err)
			}

			added, removed, unchanged := diffRisks(oldRisks, newRisks)

			if len(added) == 0 && len(removed) == 0 {
				cmd.Println("No risk changes detected.")
				return nil
			}

			if len(added) > 0 {
				cmd.Printf("+ %d new risk(s):\n", len(added))
				for _, r := range added {
					cmd.Printf("  + [%s] %s\n", r.Severity.String(), r.SyntheticId)
				}
				cmd.Println()
			}

			if len(removed) > 0 {
				cmd.Printf("- %d resolved risk(s):\n", len(removed))
				for _, r := range removed {
					cmd.Printf("  - [%s] %s\n", r.Severity.String(), r.SyntheticId)
				}
				cmd.Println()
			}

			cmd.Printf("= %d unchanged risk(s)\n", len(unchanged))
			cmd.Printf("\nSummary: +%d added, -%d resolved, =%d unchanged\n", len(added), len(removed), len(unchanged))
			return nil
		},
	}

	what.rootCmd.AddCommand(diff)
	return what
}

func analyzeForDiff(config *Config, rules types.RiskRules, reporter types.ProgressReporter) (map[string]*types.Risk, error) {
	result, err := model.ReadAndAnalyzeModel(config, rules, reporter)
	if err != nil {
		return nil, err
	}
	riskMap := make(map[string]*types.Risk)
	for _, risk := range result.ParsedModel.GeneratedRisksBySyntheticId {
		riskMap[risk.SyntheticId] = risk
	}
	return riskMap, nil
}

func diffRisks(oldRisks, newRisks map[string]*types.Risk) (added, removed, unchanged []*types.Risk) {
	for id, r := range newRisks {
		if _, exists := oldRisks[id]; exists {
			unchanged = append(unchanged, r)
		} else {
			added = append(added, r)
		}
	}
	for id, r := range oldRisks {
		if _, exists := newRisks[id]; !exists {
			removed = append(removed, r)
		}
	}
	sortByID := func(s []*types.Risk) {
		sort.Slice(s, func(i, j int) bool { return s[i].SyntheticId < s[j].SyntheticId })
	}
	sortByID(added)
	sortByID(removed)
	sortByID(unchanged)
	return
}
