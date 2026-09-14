package threagile

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func (what *Threagile) initFmt() *Threagile {
	var writeInPlace, dryRun bool

	fmtCmd := &cobra.Command{
		Use:   FmtCommand + " [model.yaml...]",
		Short: "Canonicalise whitespace and key ordering in model YAML files",
		Long:  "Reads one or more model YAML files, normalises formatting, and writes the result. Use --write to update files in place (default: print to stdout), or --dry-run to preview the changes as a unified diff without writing.",
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			if dryRun && writeInPlace {
				return fmt.Errorf("fmt: --dry-run and --write are mutually exclusive")
			}

			files := args
			if len(files) == 0 {
				files = []string{what.config.GetInputFile()}
			}

			for _, f := range files {
				data, err := os.ReadFile(f) //nolint:gosec
				if err != nil {
					return fmt.Errorf("failed to read %q: %w", f, err)
				}

				// Round-trip through yaml to normalise
				var doc yaml.Node
				if err := yaml.Unmarshal(data, &doc); err != nil {
					return fmt.Errorf("failed to parse %q: %w", f, err)
				}

				formatted, err := yaml.Marshal(&doc)
				if err != nil {
					return fmt.Errorf("failed to marshal %q: %w", f, err)
				}

				switch {
				case dryRun:
					changed, diffErr := writeUnifiedDiff(cmd.OutOrStdout(), f, data, formatted)
					if diffErr != nil {
						return fmt.Errorf("failed to render diff for %q: %w", f, diffErr)
					}
					if !changed {
						cmd.Printf("unchanged: %s\n", f)
					}
				case writeInPlace:
					if err := os.WriteFile(f, formatted, 0600); err != nil {
						return fmt.Errorf("failed to write %q: %w", f, err)
					}
					cmd.Printf("formatted: %s\n", f)
				default:
					cmd.Printf("# %s\n", f)
					cmd.Print(string(formatted))
				}
			}
			return nil
		},
	}

	fmtCmd.Flags().BoolVarP(&writeInPlace, "write", "w", false, "write formatted output back to each file in place")
	fmtCmd.Flags().BoolVar(&dryRun, "dry-run", false, "show a unified diff of the changes without writing anything")
	what.rootCmd.AddCommand(fmtCmd)
	return what
}
