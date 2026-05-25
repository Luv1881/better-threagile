package threagile

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/risks"
	"github.com/threagile/threagile/pkg/types"
)

func (what *Threagile) initDrift() *Threagile {
	var baseline string
	var current string
	var failOnNewHigh bool
	var failOnNewCritical bool

	cmd := &cobra.Command{
		Use:   "drift",
		Short: "Semantic risk-drift report between an approved baseline and current model",
		Long: `Compare risk findings between a baseline (approved) model and the current model.
Outputs new, resolved, and severity-changed findings. Designed for CI gates.

Examples:
  threagile drift --baseline baseline.yaml --current threagile.yaml
  threagile drift --baseline baseline.yaml --current threagile.yaml --fail-on-new-high

Exit codes:
  0   No new high/critical risks (or flags not set)
  1   New high or critical findings found (with --fail-on-new-high or --fail-on-new-critical)
  2   Analysis error`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			methodology := what.config.GetMethodology()
			progressReporter := DefaultProgressReporter{Verbose: false}
			builtinRules := risks.GetBuiltInRiskRules()

			cmd.Printf("Risk drift: %s → %s\n", baseline, current)
			cmd.Printf("Methodology: %s\n\n", methodology)

			originalInput := what.config.GetInputFile()
			defer what.config.SetInputFile(originalInput)

			what.config.SetInputFile(baseline)
			baseRisks, err := analyzeForDiff(what.config, builtinRules, progressReporter)
			if err != nil {
				fmt.Fprintf(os.Stderr, "drift: baseline analysis failed: %v\n", err)
				os.Exit(2)
			}

			what.config.SetInputFile(current)
			currRisks, err := analyzeForDiff(what.config, builtinRules, progressReporter)
			if err != nil {
				fmt.Fprintf(os.Stderr, "drift: current analysis failed: %v\n", err)
				os.Exit(2)
			}

			added, removed, unchanged := diffRisks(baseRisks, currRisks)
			changed := severityChanged(baseRisks, currRisks)

			hasNewHigh := hasHighOrCritical(added)
			hasNewCritical := hasCritical(added)

			if len(added) == 0 && len(removed) == 0 && len(changed) == 0 {
				cmd.Println("No risk drift detected — model is at approved baseline.")
				return nil
			}

			if len(added) > 0 {
				cmd.Printf("+ %d NEW finding(s):\n", len(added))
				for _, r := range added {
					marker := "  +"
					if r.Severity == types.CriticalSeverity {
						marker = "  + [CRITICAL]"
					} else if r.Severity == types.HighSeverity {
						marker = "  + [HIGH]"
					}
					cmd.Printf("%s [%s] %s\n", marker, r.Severity.String(), r.SyntheticId)
				}
				cmd.Println()
			}

			if len(removed) > 0 {
				cmd.Printf("- %d RESOLVED finding(s):\n", len(removed))
				for _, r := range removed {
					cmd.Printf("  - [%s] %s\n", r.Severity.String(), r.SyntheticId)
				}
				cmd.Println()
			}

			if len(changed) > 0 {
				cmd.Printf("~ %d severity-CHANGED finding(s):\n", len(changed))
				for _, c := range changed {
					cmd.Printf("  ~ %s: %s → %s\n", c.id, c.oldSev, c.newSev)
				}
				cmd.Println()
			}

			cmd.Printf("= %d unchanged finding(s)\n", len(unchanged))
			cmd.Printf("\nDrift summary: +%d added, -%d resolved, ~%d changed, =%d unchanged\n",
				len(added), len(removed), len(changed), len(unchanged))

			if failOnNewCritical && hasNewCritical {
				cmd.Println("\nCI gate FAILED: new critical-severity findings introduced.")
				os.Exit(1)
			}
			if failOnNewHigh && hasNewHigh {
				cmd.Println("\nCI gate FAILED: new high-or-critical-severity findings introduced.")
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&baseline, "baseline", "", "Approved baseline model YAML (required)")
	cmd.Flags().StringVar(&current, "current", "", "Current model YAML to compare against baseline (required)")
	cmd.Flags().BoolVar(&failOnNewHigh, "fail-on-new-high", false, "Exit 1 if any new High or Critical findings are introduced")
	cmd.Flags().BoolVar(&failOnNewCritical, "fail-on-new-critical", false, "Exit 1 only if new Critical findings are introduced")
	_ = cmd.MarkFlagRequired("baseline")
	_ = cmd.MarkFlagRequired("current")

	what.rootCmd.AddCommand(cmd)
	return what
}

type severityChange struct {
	id     string
	oldSev string
	newSev string
}

func severityChanged(oldRisks, newRisks map[string]*types.Risk) []severityChange {
	var changes []severityChange
	for id, newR := range newRisks {
		if oldR, exists := oldRisks[id]; exists {
			if oldR.Severity != newR.Severity {
				changes = append(changes, severityChange{
					id:     id,
					oldSev: oldR.Severity.String(),
					newSev: newR.Severity.String(),
				})
			}
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].id < changes[j].id })
	return changes
}

func hasHighOrCritical(risks []*types.Risk) bool {
	for _, r := range risks {
		s := strings.ToLower(r.Severity.String())
		if s == "high" || s == "critical" {
			return true
		}
	}
	return false
}

func hasCritical(risks []*types.Risk) bool {
	for _, r := range risks {
		if strings.ToLower(r.Severity.String()) == "critical" {
			return true
		}
	}
	return false
}
