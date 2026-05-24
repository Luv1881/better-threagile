package threagile

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func (what *Threagile) initFmt() *Threagile {
	var writeInPlace bool

	fmtCmd := &cobra.Command{
		Use:   FmtCommand + " [model.yaml...]",
		Short: "Canonicalise whitespace and key ordering in model YAML files",
		Long:  "Reads one or more model YAML files, normalises formatting, and writes the result. Use --write to update files in place (default: print to stdout).",
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

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

				if writeInPlace {
					if err := os.WriteFile(f, formatted, 0600); err != nil {
						return fmt.Errorf("failed to write %q: %w", f, err)
					}
					cmd.Printf("formatted: %s\n", f)
				} else {
					cmd.Printf("# %s\n", f)
					cmd.Print(string(formatted))
				}
			}
			return nil
		},
	}

	fmtCmd.Flags().BoolVarP(&writeInPlace, "write", "w", false, "write formatted output back to each file in place")
	what.rootCmd.AddCommand(fmtCmd)
	return what
}
