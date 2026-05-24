package threagile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

const gitlabTemplate = `# Threagile Threat Model Analysis — GitLab CI
threagile:
  image: docker:latest
  services:
    - docker:dind
  schedule: '[[ .Schedule ]]'
  script:
    - docker run --rm
        -v "$CI_PROJECT_DIR:/app/work"
        threagile/threagile:latest
        analyze-model
        --model /app/work/[[ .ModelPath ]]
        --output /app/work/threagile-output
  artifacts:
    paths:
      - threagile-output/
`

const jenkinsTemplate = `// Threagile Threat Model Analysis — Jenkinsfile
pipeline {
    agent any
    triggers { cron('[[ .Schedule ]]') }
    stages {
        stage('Threagile Analysis') {
            steps {
                sh '''
                    docker run --rm \\
                        -v "\$(pwd):/app/work" \\
                        threagile/threagile:latest \\
                        analyze-model \\
                        --model /app/work/[[ .ModelPath ]] \\
                        --output /app/work/threagile-output
                '''
            }
        }
    }
    post {
        always { archiveArtifacts artifacts: 'threagile-output/**', allowEmptyArchive: true }
    }
}
`

const genericTemplate = `#!/usr/bin/env sh
# Threagile Threat Model Analysis — generic CI script
# Schedule: [[ .Schedule ]]
set -eu

docker run --rm \
  -v "$(pwd):/app/work" \
  threagile/threagile:latest \
  analyze-model \
  --model /app/work/[[ .ModelPath ]] \
  --output /app/work/threagile-output
`

var ciTargets = map[string]struct {
	tmpl     string
	filename string
	dir      string
}{
	"github":  {workflowTemplate, "threagile.yml", ".github/workflows"},
	"gitlab":  {gitlabTemplate, ".gitlab-ci.yml", "."},
	"jenkins": {jenkinsTemplate, "Jenkinsfile", "."},
	"generic": {genericTemplate, "run-threagile.sh", "."},
}

func (what *Threagile) initGenerateCI() *Threagile {
	generateCI := &cobra.Command{
		Use:   GenerateCICommand,
		Short: "Generate a CI/CD pipeline configuration for scheduled threat model analysis",
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			outputDir, _ := cmd.Flags().GetString(ciOutputFlagName)
			schedule, _ := cmd.Flags().GetString(ciScheduleFlagName)
			target, _ := cmd.Flags().GetString("target")

			target = strings.ToLower(target)
			ci, ok := ciTargets[target]
			if !ok {
				keys := make([]string, 0, len(ciTargets))
				for k := range ciTargets {
					keys = append(keys, k)
				}
				return fmt.Errorf("unknown target %q — valid options: %s", target, strings.Join(keys, ", "))
			}

			modelPath := what.config.GetInputFile()
			cwd, err := os.Getwd()
			if err == nil {
				if rel, relErr := filepath.Rel(cwd, modelPath); relErr == nil {
					modelPath = rel
				}
			}

			outDirectory := outputDir
			if outDirectory == "" {
				outDirectory = ci.dir
			}
			if err := os.MkdirAll(outDirectory, 0750); err != nil {
				return fmt.Errorf("failed to create output directory %q: %w", outDirectory, err)
			}

			outFile := filepath.Join(outDirectory, ci.filename)
			f, err := os.OpenFile(outFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600) //nolint:gosec
			if err != nil {
				return fmt.Errorf("failed to create CI file %q: %w", outFile, err)
			}
			defer f.Close()

			tmpl, err := template.New("ci").Delims("[[", "]]").Parse(ci.tmpl)
			if err != nil {
				return fmt.Errorf("failed to parse CI template: %w", err)
			}

			if err := tmpl.Execute(f, ciTemplateData{
				Schedule:  schedule,
				ModelPath: modelPath,
			}); err != nil {
				return fmt.Errorf("failed to render CI template: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "CI configuration (%s) written to: %s\n", target, outFile)
			return nil
		},
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}

	generateCI.Flags().String(ciOutputFlagName, "", "directory to write the generated CI file (default: target-specific)")
	generateCI.Flags().String(ciScheduleFlagName, "0 0 * * 0", "cron expression for the scheduled run (default: weekly Sunday midnight)")
	generateCI.Flags().String("target", "github", "CI/CD target: github, gitlab, jenkins, generic")

	what.rootCmd.AddCommand(generateCI)
	return what
}
