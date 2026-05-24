package threagile

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/risks"
)

func (what *Threagile) initTestRules() *Threagile {
	testRules := &cobra.Command{
		Use:   TestRulesCommand + " <rules-dir>",
		Short: "Run golden tests for a script rule pack",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			results, err := risks.RunRulePackTests(args[0], what.config.GetMethodology())
			for _, result := range results {
				status := "PASS"
				if !result.Passed {
					status = "FAIL"
				}
				cmd.Printf("%s %s\n", status, result.Name)
				if !result.Passed {
					cmd.Printf("  expected: %v\n", result.Expected)
					cmd.Printf("  actual:   %v\n", result.Actual)
				}
			}
			if err != nil {
				return fmt.Errorf("rule pack tests failed: %w", err)
			}
			cmd.Printf("All %d rule test(s) passed.\n", len(results))
			return nil
		},
	}

	what.rootCmd.AddCommand(testRules)
	return what
}
