package threagile

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/report"
	"github.com/threagile/threagile/pkg/risks"
)

func (what *Threagile) initAnalyze() *Threagile {
	analyze := &cobra.Command{
		Use:     AnalyzeModelCommand,
		Short:   "Analyze model",
		Aliases: []string{"analyze", "analyse", "run", "analyse-model"},
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)
			commands := what.readCommands()
			progressReporter := DefaultProgressReporter{Verbose: what.config.GetVerbose()}

			builtinRules := risks.GetBuiltInRiskRules()

			if dir := what.config.GetRulesDir(); dir != "" {
				extRules, extErr := risks.LoadExternalScriptRiskRules(dir)
				if extErr != nil {
					progressReporter.Warnf("Failed to load external rules from %q: %v", dir, extErr)
				} else {
					builtinRules = builtinRules.Merge(extRules)
				}
			}

			if rawURL := what.config.GetRulesURL(); rawURL != "" {
				cacheDir := filepath.Join(what.config.GetAppFolder(), "rules-cache")
				localDir, fetchErr := risks.FetchAndCacheRules(rawURL, cacheDir)
				if fetchErr != nil {
					progressReporter.Warnf("Failed to fetch rules from %q: %v", rawURL, fetchErr)
				} else {
					remoteRules, remoteErr := risks.LoadExternalScriptRiskRules(localDir)
					if remoteErr != nil {
						progressReporter.Warnf("Failed to load cached remote rules from %q: %v", localDir, remoteErr)
					} else {
						builtinRules = builtinRules.Merge(remoteRules)
					}
				}
			}

			if pack := what.config.GetRulePack(); pack != "" {
				packRules, packErr := risks.LoadRulePack(pack)
				if packErr != nil {
					progressReporter.Warnf("Failed to load rule pack %q: %v", pack, packErr)
				} else {
					progressReporter.Infof("Loaded rule pack %q (%d rules)", pack, len(packRules))
					builtinRules = builtinRules.Merge(packRules)
				}
			}

			r, err := model.ReadAndAnalyzeModel(what.config, builtinRules, progressReporter)
			if err != nil {
				return fmt.Errorf("failed to read and analyze model: %w", err)
			}

			err = report.Generate(what.config, r, commands, builtinRules, progressReporter)
			if err != nil {
				return fmt.Errorf("failed to generate reports: %w", err)
			}
			return nil
		},
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}

	what.rootCmd.AddCommand(analyze)

	return what
}
