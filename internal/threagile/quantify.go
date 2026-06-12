package threagile

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/risks/quant"
)

func (what *Threagile) initQuantify() *Threagile {
	var estimatesFile string
	var iterations int
	var outputFile string

	cmd := &cobra.Command{
		Use:   "quantify",
		Short: "Run FAIR Monte-Carlo ALE simulation over the model's generated risks",
		Long: `Analyze the model, then simulate Annualized Loss Expectancy (ALE) for every
generated risk that has a FAIR estimate in the --estimates YAML file.

Estimate keys match a risk's synthetic ID exactly, or its risk-category ID
(applying to all risks of that category). Example estimates file:

  default_iterations: 10000
  estimates:
    unencrypted-communication:           # category ID -> all its risks
      loss_event_frequency: {min: 0.1, most_likely: 0.5, max: 2.0}   # events/year
      loss_magnitude:       {min: 1000, most_likely: 25000, max: 500000} # USD/event
      confidence: 0.7
    sql-nosql-injection@api@db:          # exact synthetic risk ID
      loss_event_frequency: {min: 0.5, most_likely: 1.0, max: 4.0}
      loss_magnitude:       {min: 10000, most_likely: 100000, max: 2000000}

Simulation is deterministic per risk (seeded from the synthetic ID). Results
print as a table sorted by median ALE; --output writes the full JSON.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)
			progressReporter := DefaultProgressReporter{Verbose: what.config.GetVerbose()}

			estimates, err := quant.LoadEstimates(estimatesFile)
			if err != nil {
				return fmt.Errorf("quantify: %w", err)
			}

			builtinRules := what.loadRiskRules(progressReporter)
			r, err := model.ReadAndAnalyzeModel(what.config, builtinRules, progressReporter)
			if err != nil {
				return fmt.Errorf("quantify: failed to read and analyze model: %w", err)
			}

			result := quant.Quantify(r.ParsedModel, estimates, iterations)

			if result.Portfolio.QuantifiedRisks == 0 {
				cmd.Printf("No generated risks matched any estimate key (%d risks total).\n", result.Portfolio.TotalRisks)
				return nil
			}

			cmd.Printf("FAIR Monte-Carlo ALE simulation (%d iterations per risk)\n\n", result.Iterations)
			cmd.Printf("%-70s %-10s %12s %12s %12s\n", "RISK", "SEVERITY", "ALE P10", "ALE P50", "ALE P90")
			for _, riskResult := range result.Risks {
				id := riskResult.SyntheticId
				if len(id) > 70 {
					id = id[:67] + "..."
				}
				cmd.Printf("%-70s %-10s %12.0f %12.0f %12.0f\n",
					id, riskResult.Severity, riskResult.Result.ALE_P10, riskResult.Result.ALE_P50, riskResult.Result.ALE_P90)
			}
			cmd.Printf("\nPortfolio (%d of %d risks quantified, USD/year, sum of per-risk percentiles):\n",
				result.Portfolio.QuantifiedRisks, result.Portfolio.TotalRisks)
			cmd.Printf("  P10: %14.0f\n  P50: %14.0f\n  P90: %14.0f\n",
				result.Portfolio.SumALEP10, result.Portfolio.SumALEP50, result.Portfolio.SumALEP90)

			if outputFile != "" {
				jsonBytes, marshalErr := json.MarshalIndent(result, "", "  ")
				if marshalErr != nil {
					return fmt.Errorf("quantify: marshal result: %w", marshalErr)
				}
				if writeErr := os.WriteFile(outputFile, jsonBytes, 0600); writeErr != nil {
					return fmt.Errorf("quantify: write %q: %w", outputFile, writeErr)
				}
				cmd.Printf("\nFull result written to %s\n", outputFile)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&estimatesFile, "estimates", "", "FAIR estimates YAML file (required)")
	cmd.Flags().IntVar(&iterations, "iterations", 0, "Monte-Carlo iterations per risk (default: estimates file or 10000)")
	cmd.Flags().StringVar(&outputFile, "output-json", "", "write full quantification result to this JSON file")
	_ = cmd.MarkFlagRequired("estimates")

	what.rootCmd.AddCommand(cmd)
	return what
}
