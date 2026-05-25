package threagile

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	githubsync "github.com/threagile/threagile/pkg/sync/github"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/risks"
)

func (what *Threagile) initSync() *Threagile {
	syncCmd := &cobra.Command{
		Use:   "sync",
		Short: "Bidirectional sync between findings and a ticketing backend",
		Long: `Sync threat model findings to an issue tracker. Open issues are created for new
findings; resolved findings (via --mitigated) close existing issues; reopened
findings reopen closed issues.

Currently supported backends:
  github   GitHub Issues

Example:
  threagile sync github --owner myorg --repo myrepo
  threagile sync github --owner myorg --repo myrepo --dry-run`,
	}
	syncCmd.AddCommand(what.newSyncGitHubCmd())
	what.rootCmd.AddCommand(syncCmd)
	return what
}

func (what *Threagile) newSyncGitHubCmd() *cobra.Command {
	var owner string
	var repo string
	var dryRun bool
	var mitigated string

	cmd := &cobra.Command{
		Use:   "github",
		Short: "Sync findings to GitHub Issues",
		Long: `Creates, updates, or closes GitHub Issues for each finding.

Environment variables:
  GITHUB_TOKEN   Personal access token or GitHub Actions token (required).
                 Required scope: issues:write.

Labels applied to issues:
  threagile:<synthetic-id>   Stable identifier across runs
  threat-severity:<level>    Severity for filtering

Mitigated findings (--mitigated) close their corresponding open issues.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			if owner == "" || repo == "" {
				return fmt.Errorf("sync github: --owner and --repo are required")
			}

			// Run analysis to get current findings
			progressReporter := DefaultProgressReporter{Verbose: false}
			builtinRules := risks.GetBuiltInRiskRules()
			result, err := model.ReadAndAnalyzeModel(what.config, builtinRules, progressReporter)
			if err != nil {
				return fmt.Errorf("sync github: analysis failed: %w", err)
			}

			// Parse mitigated IDs
			var mitigatedIDs []string
			if mitigated != "" {
				for _, id := range strings.Split(mitigated, ",") {
					if id = strings.TrimSpace(id); id != "" {
						mitigatedIDs = append(mitigatedIDs, id)
					}
				}
			}

			client, err := githubsync.NewClient(githubsync.Config{
				Owner:  owner,
				Repo:   repo,
				DryRun: dryRun,
			})
			if err != nil {
				return fmt.Errorf("sync github: %w", err)
			}

			cmd.Printf("Syncing %d findings to %s/%s...\n",
				len(result.ParsedModel.GeneratedRisksBySyntheticId), owner, repo)
			if dryRun {
				cmd.Println("[dry-run mode — no changes will be made]")
			}

			results, err := client.SyncFindings(result.ParsedModel, mitigatedIDs)
			if err != nil {
				return fmt.Errorf("sync github: %w", err)
			}

			created, closed, reopened, skipped, failed := 0, 0, 0, 0, 0
			for _, r := range results {
				switch r.Action {
				case "created":
					created++
					cmd.Printf("  + #%d created: %s\n", r.IssueNumber, r.SyntheticID)
				case "closed":
					closed++
					cmd.Printf("  - #%d closed: %s\n", r.IssueNumber, r.SyntheticID)
				case "reopened":
					reopened++
					cmd.Printf("  ~ #%d reopened: %s\n", r.IssueNumber, r.SyntheticID)
				case "skipped":
					skipped++
				default:
					if r.Error != nil {
						failed++
						cmd.Printf("  ! failed %s: %v\n", r.SyntheticID, r.Error)
					}
				}
			}

			cmd.Printf("\nSync complete: +%d created, -%d closed, ~%d reopened, =%d skipped, !%d failed\n",
				created, closed, reopened, skipped, failed)
			return nil
		},
	}

	cmd.Flags().StringVar(&owner, "owner", "", "GitHub repository owner (user or organisation)")
	cmd.Flags().StringVar(&repo, "repo", "", "GitHub repository name")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print actions without making API calls")
	cmd.Flags().StringVar(&mitigated, "mitigated", "", "Comma-separated synthetic IDs to close (mitigated findings)")
	return cmd
}
