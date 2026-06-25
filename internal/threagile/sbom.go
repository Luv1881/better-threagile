package threagile

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/intel/cache"
	"github.com/threagile/threagile/pkg/intel/epss"
	"github.com/threagile/threagile/pkg/intel/kev"
	"github.com/threagile/threagile/pkg/sbom"
)

func (what *Threagile) initSBOM() *Threagile {
	var sbomFile string
	var cacheDir string
	var fetchEPSS bool
	var refreshKEV bool
	var includeSuppressed bool
	var failOnKEV bool
	var format string
	var outputFile string

	cmd := &cobra.Command{
		Use:   "sbom",
		Short: "Correlate a CycloneDX SBOM's vulnerabilities with KEV/EPSS threat intel",
		Long: `Ingest a CycloneDX SBOM (as emitted by Trivy, Grype or Syft), extract its
components and embedded vulnerabilities, and correlate the CVEs against the CISA
KEV catalog and FIRST EPSS scores. Findings are ranked by exploitability:
KEV-listed first, then by EPSS probability, then CVSS.

VEX is honoured — vulnerabilities whose CycloneDX analysis.state is
not_affected / false_positive / resolved are suppressed by default.

Examples:
  # offline (uses cached KEV; refresh it first with 'threagile intel refresh')
  threagile sbom --sbom sbom.cdx.json

  # refresh KEV and fetch live EPSS for the SBOM's CVEs
  threagile sbom --sbom sbom.cdx.json --refresh-kev --epss

  # CI gate: non-zero exit if any KEV-listed CVE is present
  threagile sbom --sbom sbom.cdx.json --fail-on-kev`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			data, err := os.ReadFile(sbomFile) //nolint:gosec // operator-supplied SBOM path
			if err != nil {
				return fmt.Errorf("sbom: read %q: %w", sbomFile, err)
			}
			bom, err := sbom.Parse(data)
			if err != nil {
				return err
			}

			kevLookup := loadKEVLookup(cmd, cacheDir, refreshKEV)
			epssLookup := loadEPSSLookup(cmd, cacheDir, bom, fetchEPSS)

			result := sbom.Correlate(bom, kevLookup, epssLookup, sbom.Options{IncludeSuppressed: includeSuppressed})

			var rendered string
			switch strings.ToLower(format) {
			case "", "text":
				rendered = sbom.FormatText(result)
			case "markdown", "md":
				rendered = sbom.FormatMarkdown(result)
			case "json":
				jsonBytes, marshalErr := json.MarshalIndent(result, "", "  ")
				if marshalErr != nil {
					return fmt.Errorf("sbom: marshal result: %w", marshalErr)
				}
				rendered = string(jsonBytes) + "\n"
			default:
				return fmt.Errorf("sbom: unknown --format %q (want text, markdown, or json)", format)
			}

			if outputFile != "" {
				//nolint:gosec // outputFile is an operator-supplied --output path
				if writeErr := os.WriteFile(outputFile, []byte(rendered), 0600); writeErr != nil {
					return fmt.Errorf("sbom: write %q: %w", outputFile, writeErr)
				}
			}
			cmd.Print(rendered)

			if failOnKEV && result.HasKEV() {
				return &exitCodeError{code: 3, msg: fmt.Sprintf("sbom gate failed: %d KEV-listed vulnerability(ies) present", result.KEVCount)}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&sbomFile, "sbom", "", "CycloneDX SBOM JSON file (required)")
	cmd.Flags().StringVar(&cacheDir, "cache-dir", cache.DefaultCacheDir(), "intel cache directory")
	cmd.Flags().BoolVar(&fetchEPSS, "epss", false, "fetch live EPSS scores for the SBOM's CVEs (network)")
	cmd.Flags().BoolVar(&refreshKEV, "refresh-kev", false, "refresh the KEV catalog if stale (network)")
	cmd.Flags().BoolVar(&includeSuppressed, "include-suppressed", false, "include VEX-suppressed vulnerabilities (marked)")
	cmd.Flags().BoolVar(&failOnKEV, "fail-on-kev", false, "exit non-zero (3) if any KEV-listed CVE is present")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text, markdown, or json")
	cmd.Flags().StringVar(&outputFile, "output", "", "also write the rendered report to this file")
	_ = cmd.MarkFlagRequired("sbom")

	what.rootCmd.AddCommand(cmd)
	return what
}

// loadKEVLookup loads the KEV catalog (cache-only, or refreshing if asked). On
// failure or an empty cache it warns and returns nil so correlation still runs
// without KEV.
func loadKEVLookup(cmd *cobra.Command, cacheDir string, refresh bool) sbom.KEVLookup {
	var (
		catalog *kev.Catalog
		err     error
	)
	if refresh {
		catalog, err = kev.LoadOrRefresh(cacheDir, kev.DefaultFeedURL, kev.DefaultTTL)
	} else {
		catalog, err = kev.Load(cacheDir)
	}
	if err != nil || catalog == nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: KEV unavailable (%v) — run 'threagile intel refresh' or pass --refresh-kev\n", err)
		return nil
	}
	return catalog.IsKEV
}

// loadEPSSLookup loads EPSS scores: live batch fetch when --epss is set,
// otherwise the cached map. Returns nil if neither is available.
func loadEPSSLookup(cmd *cobra.Command, cacheDir string, bom *sbom.BOM, fetch bool) sbom.EPSSLookup {
	var scores epss.ScoreMap
	var err error
	if fetch {
		scores, err = epss.FetchBatch(bom.CVEIDs(), "")
	} else {
		scores, err = epss.LoadCached(cacheDir)
	}
	if err != nil || scores == nil {
		if fetch {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: EPSS fetch failed (%v)\n", err)
		}
		return nil
	}
	return func(cve string) (float64, bool) {
		s := scores.Get(cve)
		if s == nil {
			return 0, false
		}
		return s.EPSS, true
	}
}
