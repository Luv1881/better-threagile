package threagile

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/intel/cache"
	"github.com/threagile/threagile/pkg/intel/epss"
	"github.com/threagile/threagile/pkg/intel/kev"
)

func (what *Threagile) initIntel() *Threagile {
	var cacheDir string

	intelCmd := &cobra.Command{
		Use:   "intel",
		Short: "Manage and query threat-intelligence feeds (KEV, EPSS)",
		Long: `Download and cache threat-intelligence feeds for offline analysis.

Available feeds:
  kev   CISA Known Exploited Vulnerabilities catalog
  epss  Exploit Prediction Scoring System (per-CVE exploitation probability)

Example:
  threagile intel refresh --source kev
  threagile intel show CVE-2021-44228
  threagile intel status`,
	}

	intelCmd.PersistentFlags().StringVar(&cacheDir, "cache-dir", cache.DefaultCacheDir(),
		"Directory for cached threat-intel files")

	intelCmd.AddCommand(what.newIntelRefreshCmd(&cacheDir))
	intelCmd.AddCommand(what.newIntelShowCmd(&cacheDir))
	intelCmd.AddCommand(what.newIntelStatusCmd(&cacheDir))

	what.rootCmd.AddCommand(intelCmd)
	return what
}

func (what *Threagile) newIntelRefreshCmd(cacheDir *string) *cobra.Command {
	var source string
	var feedURL string

	cmd := &cobra.Command{
		Use:   "refresh",
		Short: "Download or refresh a threat-intelligence feed",
		Long: `Download the latest threat-intelligence feed data and store it locally.

Sources:
  kev   CISA Known Exploited Vulnerabilities (daily JSON)
  epss  (batch fetch via 'intel show' — there is no full-dump EPSS endpoint)
  all   All available feeds`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			sources := []string{source}
			if source == "all" {
				sources = []string{"kev"}
			}

			for _, s := range sources {
				switch strings.ToLower(s) {
				case "kev":
					cmd.Printf("Refreshing CISA KEV catalog... ")
					catalog, err := kev.Refresh(*cacheDir, feedURL)
					if err != nil {
						return fmt.Errorf("intel refresh kev: %w", err)
					}
					cmd.Printf("done (%d entries, version %s)\n", catalog.Count, catalog.CatalogVersion)

				default:
					return fmt.Errorf("unknown intel source %q (valid: kev, all)", s)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&source, "source", "all", "Feed source to refresh: kev | all")
	cmd.Flags().StringVar(&feedURL, "url", "", "Override the feed download URL")
	return cmd
}

func (what *Threagile) newIntelShowCmd(cacheDir *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show <CVE-ID>",
		Short: "Show threat-intelligence data for a CVE",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			cveID := strings.ToUpper(strings.TrimSpace(args[0]))
			if !strings.HasPrefix(cveID, "CVE-") {
				return fmt.Errorf("invalid CVE ID %q (expected format: CVE-YYYY-NNNNN)", args[0])
			}

			found := false

			// KEV lookup
			catalog, kevErr := kev.Load(*cacheDir)
			if kevErr != nil {
				cmd.Printf("Warning: KEV cache unavailable: %v\n", kevErr)
			} else if catalog != nil {
				entry := catalog.Lookup(cveID)
				if entry != nil {
					found = true
					cmd.Printf("=== CISA KEV ===\n")
					cmd.Printf("CVE:              %s\n", entry.CVEID)
					cmd.Printf("Product:          %s %s\n", entry.VendorProject, entry.Product)
					cmd.Printf("Vulnerability:    %s\n", entry.VulnerabilityName)
					cmd.Printf("Date Added:       %s\n", entry.DateAdded)
					cmd.Printf("Due Date:         %s\n", entry.DueDate)
					cmd.Printf("Required Action:  %s\n", entry.RequiredAction)
					cmd.Printf("Known Ransomware: %s\n", entry.KnownRansomware)
					cmd.Printf("Description:      %s\n\n", entry.ShortDescription)
				} else {
					cmd.Printf("KEV: %s is NOT in the CISA Known Exploited Vulnerabilities catalog.\n\n", cveID)
				}
			} else {
				cmd.Printf("KEV: no local cache found — run 'threagile intel refresh --source kev' first.\n\n")
			}

			// EPSS live lookup
			cmd.Printf("=== EPSS (live) ===\n")
			score, epssErr := epss.FetchScore(cveID, "")
			if epssErr != nil {
				cmd.Printf("EPSS: fetch failed: %v\n", epssErr)
			} else if score != nil {
				found = true
				cmd.Printf("CVE:        %s\n", score.CVE)
				cmd.Printf("EPSS Score: %.4f (%.1f%% exploitation probability in next 30 days)\n",
					score.EPSS, score.EPSS*100)
				cmd.Printf("Percentile: %.1f%% (ranked higher than %.1f%% of all CVEs)\n",
					score.Percentile*100, score.Percentile*100)
				cmd.Printf("Date:       %s\n", score.Date)
			} else {
				cmd.Printf("EPSS: %s not found in EPSS database.\n", cveID)
			}

			if !found {
				cmd.Printf("\n%s was not found in any loaded intel source.\n", cveID)
			}
			return nil
		},
	}
	return cmd
}

func (what *Threagile) newIntelStatusCmd(cacheDir *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the age and size of all cached threat-intel data",
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			feeds := []struct {
				name string
				ttl  time.Duration
			}{
				{"kev", kev.DefaultTTL},
			}

			cmd.Printf("Cache directory: %s\n\n", *cacheDir)
			cmd.Printf("%-12s  %-20s  %-10s  %s\n", "Feed", "Cached At", "Age", "Status")
			cmd.Printf("%-12s  %-20s  %-10s  %s\n",
				strings.Repeat("-", 12), strings.Repeat("-", 20),
				strings.Repeat("-", 10), strings.Repeat("-", 7))

			for _, f := range feeds {
				entry, err := cache.Load(*cacheDir, f.name)
				if err != nil || entry == nil {
					cmd.Printf("%-12s  %-20s  %-10s  MISSING\n", f.name, "-", "-")
					continue
				}

				age := cache.Age(entry)
				status := "FRESH"
				if !entry.IsFresh(f.ttl) {
					status = "STALE"
				}

				// Count entries if possible
				var raw []json.RawMessage
				_ = json.Unmarshal(entry.Payload, &raw)
				countStr := ""
				if len(raw) > 0 {
					countStr = fmt.Sprintf("(%d items)", len(raw))
				}

				cmd.Printf("%-12s  %-20s  %-10s  %s %s\n",
					f.name,
					entry.FetchedAt.Local().Format("2006-01-02 15:04"),
					formatAge(age),
					status,
					countStr)
			}
			return nil
		},
	}
	return cmd
}

func formatAge(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%.0fh", d.Hours())
}
