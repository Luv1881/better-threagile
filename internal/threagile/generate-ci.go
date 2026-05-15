package threagile

import (
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	"github.com/spf13/cobra"
)

type ciTemplateData struct {
	Schedule  string
	ModelPath string
}

// workflowTemplate uses [[ ]] delimiters to avoid clashing with GitHub Actions ${{ }} expressions.
const workflowTemplate = `name: Threagile Threat Model Analysis

on:
  schedule:
    - cron: '[[ .Schedule ]]'
  workflow_dispatch:

jobs:
  threagile:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Run Threagile
        run: |
          docker run --rm \
            -v "${{ github.workspace }}:/app/work" \
            threagile/threagile:latest \
            analyze-model \
            --model /app/work/[[ .ModelPath ]] \
            --output /app/work/threagile-output

      - name: Upload Threagile Output
        uses: actions/upload-artifact@v4
        with:
          name: threagile-report
          path: threagile-output/
`

func (what *Threagile) initGenerateCI() *Threagile {
	generateCI := &cobra.Command{
		Use:   GenerateCICommand,
		Short: "Generate a GitHub Actions workflow for weekly scheduled threat model analysis",
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			outputDir, _ := cmd.Flags().GetString(ciOutputFlagName)
			schedule, _ := cmd.Flags().GetString(ciScheduleFlagName)

			modelPath := what.config.GetInputFile()
			cwd, err := os.Getwd()
			if err == nil {
				if rel, relErr := filepath.Rel(cwd, modelPath); relErr == nil {
					modelPath = rel
				}
			}

			if err := os.MkdirAll(outputDir, 0750); err != nil {
				return fmt.Errorf("failed to create output directory %q: %w", outputDir, err)
			}

			outFile := filepath.Join(outputDir, "threagile.yml")
			f, err := os.OpenFile(outFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600) //nolint:gosec
			if err != nil {
				return fmt.Errorf("failed to create workflow file %q: %w", outFile, err)
			}
			defer f.Close()

			tmpl, err := template.New("workflow").Delims("[[", "]]").Parse(workflowTemplate)
			if err != nil {
				return fmt.Errorf("failed to parse workflow template: %w", err)
			}

			if err := tmpl.Execute(f, ciTemplateData{
				Schedule:  schedule,
				ModelPath: modelPath,
			}); err != nil {
				return fmt.Errorf("failed to render workflow template: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "GitHub Actions workflow written to: %s\n", outFile)
			return nil
		},
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}

	generateCI.Flags().String(ciOutputFlagName, ".github/workflows", "directory to write the generated GitHub Actions workflow file")
	generateCI.Flags().String(ciScheduleFlagName, "0 0 * * 0", "cron expression for the scheduled run (default: weekly Sunday midnight)")

	what.rootCmd.AddCommand(generateCI)
	return what
}
