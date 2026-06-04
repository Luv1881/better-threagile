package threagile

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/intel/cache"
	"github.com/threagile/threagile/pkg/intel/epss"
	"github.com/threagile/threagile/pkg/intel/kev"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/risks"
	githubsync "github.com/threagile/threagile/pkg/sync/github"
	"github.com/threagile/threagile/pkg/types"
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
	var intelCacheDir string

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

Mitigated findings (--mitigated) close their corresponding open issues.

Issue bodies include KEV and EPSS threat intelligence for any CVE IDs found in
risk explanations. Run 'threagile intel refresh' first to populate the KEV cache.`,
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

			// Build threat-intel map: extract CVEs per risk, load KEV from cache,
			// batch-fetch EPSS from the API. Non-fatal — warnings printed on failure.
			intelMap := buildIntelMap(result.ParsedModel.GeneratedRisksBySyntheticId, intelCacheDir, cmd)

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

			results, err := client.SyncFindings(result.ParsedModel, mitigatedIDs, intelMap)
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
	cmd.Flags().StringVar(&intelCacheDir, "cache-dir", cache.DefaultCacheDir(), "Directory for cached threat-intel files (KEV)")
	return cmd
}

// buildIntelMap extracts CVE IDs from every risk, loads the KEV catalog from the
// local cache, and batch-fetches EPSS scores. Errors from intel sources are
// non-fatal: a warning is printed and the map is returned with partial data.
func buildIntelMap(risksBySynID map[string]*types.Risk, cacheDir string, cmd *cobra.Command) githubsync.IntelMap {
	// Collect unique CVE IDs across all risks, tracking which risks reference them.
	cvesPerRisk := make(map[string][]string, len(risksBySynID)) // synID -> []cveID
	uniqueCVEs := map[string]bool{}

	for synID, risk := range risksBySynID {
		cves := githubsync.ExtractCVEs(risk)
		if len(cves) > 0 {
			cvesPerRisk[synID] = cves
			for _, c := range cves {
				uniqueCVEs[c] = true
			}
		}
	}

	if len(uniqueCVEs) == 0 {
		return githubsync.IntelMap{} // no CVEs referenced — all architectural risks
	}

	// Load KEV catalog from cache (non-fatal if unavailable).
	kevCatalog, err := kev.Load(cacheDir)
	if err != nil {
		cmd.Printf("  [intel] KEV cache unavailable: %v (run 'threagile intel refresh --source kev')\n", err)
	}

	// Batch-fetch EPSS scores for all referenced CVEs.
	allCVEs := make([]string, 0, len(uniqueCVEs))
	for c := range uniqueCVEs {
		allCVEs = append(allCVEs, c)
	}
	epssScores, err := epss.FetchBatch(allCVEs, "")
	if err != nil {
		cmd.Printf("  [intel] EPSS fetch failed: %v\n", err)
		epssScores = epss.ScoreMap{}
	}

	// Build the IntelMap.
	intelMap := make(githubsync.IntelMap, len(cvesPerRisk))
	for synID, cves := range cvesPerRisk {
		intel := make([]githubsync.CVEIntel, 0, len(cves))
		for _, cveID := range cves {
			ci := githubsync.CVEIntel{CVEID: cveID}

			if kevCatalog != nil {
				if entry := kevCatalog.Lookup(cveID); entry != nil {
					ci.KEV = &githubsync.KEVData{
						VulnerabilityName: entry.VulnerabilityName,
						Product:           entry.VendorProject + " " + entry.Product,
						DateAdded:         entry.DateAdded,
						DueDate:           entry.DueDate,
						KnownRansomware:   entry.KnownRansomware,
						RequiredAction:    entry.RequiredAction,
					}
				}
			}

			if score := epssScores.Get(cveID); score != nil {
				ci.EPSS = &githubsync.EPSSData{
					Score:      score.EPSS,
					Percentile: score.Percentile,
					Date:       score.Date,
				}
			}

			intel = append(intel, ci)
		}
		intelMap[synID] = intel
	}

	return intelMap
}
