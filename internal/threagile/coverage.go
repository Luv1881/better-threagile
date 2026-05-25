package threagile

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/coverage"
	"github.com/threagile/threagile/pkg/risks"
	"github.com/threagile/threagile/pkg/types"
)

func (what *Threagile) initCoverage() *Threagile {
	var framework string
	var packName string
	var listFrameworks bool

	cmd := &cobra.Command{
		Use:   "coverage",
		Short: "Report compliance-framework control coverage from loaded risk rules",
		Long: `Analyze which compliance controls are covered by the active risk rules and
print a coverage report.

Example:
  # Show NIST 800-53 coverage from the cloud-native rule pack
  threagile coverage --framework nist_800_53 --pack cloud-native

  # Show OWASP Top 10 coverage from all built-in packs
  threagile coverage --framework owasp_top10_2021

  # List all supported frameworks
  threagile coverage --list-frameworks`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			if listFrameworks {
				cmd.Println("Supported compliance frameworks:")
				for _, f := range types.SupportedFrameworks {
					cmd.Printf("  %-20s  %s\n", f, types.FrameworkTitle(f))
				}
				return nil
			}

			if framework == "" {
				return fmt.Errorf("--framework is required (use --list-frameworks to see options)")
			}

			categories, err := loadCategoriesForCoverage(what, packName)
			if err != nil {
				return err
			}

			report, err := coverage.Analyze(framework, categories)
			if err != nil {
				return err
			}

			cmd.Print(coverage.FormatTable(report))
			return nil
		},
	}

	cmd.Flags().StringVar(&framework, "framework", "", "Compliance framework to report (e.g. nist_800_53)")
	cmd.Flags().StringVar(&packName, "pack", "", "Only include rules from this built-in pack (default: all built-in packs + scripts)")
	cmd.Flags().BoolVar(&listFrameworks, "list-frameworks", false, "List all supported compliance frameworks and exit")

	what.rootCmd.AddCommand(cmd)
	return what
}

// loadCategoriesForCoverage collects RiskCategory objects from the relevant rule sources.
func loadCategoriesForCoverage(what *Threagile, packName string) ([]*types.RiskCategory, error) {
	var categories []*types.RiskCategory

	if packName != "" {
		// Load a single named pack
		rules, err := risks.LoadRulePack(packName)
		if err != nil {
			return nil, fmt.Errorf("coverage: %w", err)
		}
		for _, r := range rules {
			cat := r.Category()
			if cat != nil {
				categories = append(categories, cat)
			}
		}
		return categories, nil
	}

	// Load all built-in packs
	for _, name := range risks.AvailableBuiltinPacks {
		rules, err := risks.LoadRulePack(name)
		if err != nil {
			// Non-fatal — log and continue
			fmt.Fprintf(what.rootCmd.ErrOrStderr(), "warning: could not load pack %q: %v\n", name, err)
			continue
		}
		for _, r := range rules {
			cat := r.Category()
			if cat != nil {
				categories = append(categories, cat)
			}
		}
	}

	// Also load any extra rules from --rules-dir
	if rulesDir := what.config.GetRulesDir(); rulesDir != "" {
		extra, err := risks.LoadExternalScriptRiskRules(rulesDir)
		if err != nil {
			fmt.Fprintf(what.rootCmd.ErrOrStderr(), "warning: could not load rules from %s: %v\n", rulesDir, err)
		} else {
			for _, r := range extra {
				cat := r.Category()
				if cat != nil {
					categories = append(categories, cat)
				}
			}
		}
	}

	return categories, nil
}

