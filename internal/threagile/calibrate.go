package threagile

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/calibrate"
)

func (what *Threagile) initCalibrate() *Threagile {
	var corpusFile string
	var outputFile string
	var printReport bool

	cmd := &cobra.Command{
		Use:   "calibrate",
		Short: "Fit Bayesian likelihood priors from a labelled findings corpus",
		Long: `Read a JSON corpus of past findings with ground-truth exploitation outcomes and
fit a Beta posterior for each rule. The resulting calibration.yaml can be passed
to threagile analyze-model via --calibration to adjust likelihood priors.

Corpus format (array of objects):
  [
    {"rule_id": "sql-injection", "finding_id": "foo@bar", "exploited": true},
    {"rule_id": "xss",           "finding_id": "baz@qux", "exploited": false}
  ]

The Brier score (mean squared error) is printed for each rule and overall.
Lower Brier scores indicate better-calibrated rules.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			findings, err := calibrate.LoadCorpus(corpusFile)
			if err != nil {
				return fmt.Errorf("calibrate: %w", err)
			}
			if len(findings) == 0 {
				return fmt.Errorf("calibrate: corpus %q is empty", corpusFile)
			}

			cal := calibrate.Analyze(findings)

			if printReport {
				cmd.Println(calibrate.FormatReport(cal))
			} else {
				cmd.Printf("Calibrated %d rules from %d findings (overall Brier: %.4f)\n",
					len(cal.Rules), cal.CorpusSize, cal.OverallBrier)
			}

			if outputFile != "" {
				if err := calibrate.SaveCalibration(outputFile, cal); err != nil {
					return fmt.Errorf("calibrate: save: %w", err)
				}
				cmd.Printf("Calibration written to %s\n", outputFile)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&corpusFile, "corpus", "", "Path to labelled findings corpus JSON (required)")
	cmd.Flags().StringVar(&outputFile, "output", "calibration.yaml", "Output calibration YAML file")
	cmd.Flags().BoolVar(&printReport, "report", false, "Print full per-rule calibration table")
	_ = cmd.MarkFlagRequired("corpus")

	what.rootCmd.AddCommand(cmd)
	return what
}
