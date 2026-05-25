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
	var outputFormat string

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

			rulesURLs := append([]string{}, what.config.GetRulesURLs()...)
			if urlFile := what.config.GetRulesURLFile(); urlFile != "" {
				fileURLs, fileErr := risks.ReadRulesURLFile(urlFile)
				if fileErr != nil {
					progressReporter.Warnf("Failed to read rules URL file %q: %v", urlFile, fileErr)
				} else {
					rulesURLs = append(rulesURLs, fileURLs...)
				}
			}

			if len(rulesURLs) > 0 {
				cacheDir := filepath.Join(what.config.GetAppFolder(), "rules-cache")
				fetchOptions := risks.FetchOptions{
					TrustedKeys:   what.config.GetRulesTrustedKeys(),
					RequireSigned: what.config.GetRulesRequireSigned(),
				}
				localDirs, fetchErr := risks.FetchAndCacheRuleSources(rulesURLs, cacheDir, fetchOptions)
				if fetchErr != nil {
					progressReporter.Warnf("Failed to fetch remote rules: %v", fetchErr)
				}
				for _, localDir := range localDirs {
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

			if outputFormat == "md" || outputFormat == "markdown" {
				cmd.Print(report.MarkdownReport(r.ParsedModel))
				return nil
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

	analyze.Flags().StringVar(&outputFormat, "output-format", "", "Output format: default (PDF/Excel/JSON) | md (Markdown)")
	what.rootCmd.AddCommand(analyze)

	return what
}
