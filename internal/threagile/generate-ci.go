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
	Schedule   string
	ModelPath  string
	PolicyPath string
}

// workflowTemplate uses [[ ]] delimiters to avoid clashing with GitHub Actions ${{ }} expressions.
const workflowTemplate = `name: Threagile Threat Model Analysis

on:
  schedule:
    - cron: '[[ .Schedule ]]'
  workflow_dispatch:

permissions:
  contents: read

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
            --model "/app/work/[[ .ModelPath ]]" \
            --output /app/work/threagile-output

      - name: Upload Threagile Output
        uses: actions/upload-artifact@v4
        with:
          name: threagile-report
          path: threagile-output/
`

// gatePRTemplate runs the policy gate on pull requests and posts the Markdown
// gate report as a PR comment, failing the check when the gate fails. It
// expects a policy file at the path given by --policy-path (default policy.yaml).
const gatePRTemplate = `name: Threat-model Gate

on:
  pull_request:
    paths:
      - '[[ .ModelPath ]]'
      - '[[ .PolicyPath ]]'
  workflow_dispatch:

permissions:
  contents: read
  pull-requests: write

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Run threat-model gate
        id: gate
        run: |
          docker run --rm \
            -v "${{ github.workspace }}:/app/work" \
            threagile/threagile:latest \
            gate \
            --model "/app/work/[[ .ModelPath ]]" \
            --policy "/app/work/[[ .PolicyPath ]]" \
            --format markdown \
            --output /app/work/gate-report.md
        continue-on-error: true

      - name: Generate scorecard
        # Adds the health score + the top findings-to-fix to the PR comment so the
        # review is actionable, not just pass/fail. Best-effort.
        continue-on-error: true
        run: |
          docker run --rm \
            -v "${{ github.workspace }}:/app/work" \
            threagile/threagile:latest \
            summary \
            --model "/app/work/[[ .ModelPath ]]" \
            --format markdown \
            --output /app/work/summary.md

      - name: Post scorecard + gate report as PR comment
        # Best-effort: fork PRs run with a read-only token, so commenting may 403.
        # Never let that fail the run — the gate step below owns pass/fail.
        if: github.event_name == 'pull_request'
        continue-on-error: true
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            let body = '';
            if (fs.existsSync('summary.md')) {
              body += fs.readFileSync('summary.md', 'utf8') + '\n\n---\n\n';
            }
            if (fs.existsSync('gate-report.md')) {
              body += fs.readFileSync('gate-report.md', 'utf8');
            }
            if (body === '') {
              core.warning('no scorecard or gate report produced.');
              return;
            }
            await github.rest.issues.createComment({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              body,
            });

      - name: Fail if the gate failed
        if: steps.gate.outcome != 'success'
        run: |
          echo "::error title=Threat-model gate failed::Policy violations — see the gate report (PR comment on pull requests, otherwise the job log artifact)."
          cat gate-report.md 2>/dev/null || true
          exit 1
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
	"gate-pr": {gatePRTemplate, "threat-model-gate.yml", ".github/workflows"},
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
			policyPath, _ := cmd.Flags().GetString("policy-path")

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
			defer func() { _ = f.Close() }()

			tmpl, err := template.New("ci").Delims("[[", "]]").Parse(ci.tmpl)
			if err != nil {
				return fmt.Errorf("failed to parse CI template: %w", err)
			}

			if err := tmpl.Execute(f, ciTemplateData{
				Schedule:   schedule,
				ModelPath:  modelPath,
				PolicyPath: policyPath,
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
	generateCI.Flags().String("target", "github", "CI/CD target: github, gate-pr, gitlab, jenkins, generic")
	generateCI.Flags().String("policy-path", "policy.yaml", "path to the gate policy file (used by the gate-pr target)")

	what.rootCmd.AddCommand(generateCI)
	return what
}
