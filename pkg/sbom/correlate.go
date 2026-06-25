package sbom

import (
	"regexp"
	"sort"
	"strings"
)

var cveRe = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,}$`)

// KEVLookup reports whether a CVE is on the CISA Known Exploited Vulnerabilities
// catalog. (kev.Catalog.IsKEV satisfies this.)
type KEVLookup func(cveID string) bool

// EPSSLookup returns the EPSS probability (0–1) for a CVE and whether it was found.
type EPSSLookup func(cveID string) (float64, bool)

// Finding is one correlated vulnerability.
type Finding struct {
	CVE                string   `json:"cve"`
	Severity           string   `json:"severity"`
	CVSS               float64  `json:"cvss"`
	KEV                bool     `json:"kev"`
	EPSS               float64  `json:"epss"`
	HasEPSS            bool     `json:"has_epss"`
	AffectedComponents []string `json:"affected_components"`
	Suppressed         bool     `json:"suppressed,omitempty"`
	SuppressionState   string   `json:"suppression_state,omitempty"`
}

// Result is the correlation outcome.
type Result struct {
	Findings        []Finding `json:"findings"`
	TotalComponents int       `json:"total_components"`
	TotalVulns      int       `json:"total_vulns"`
	KEVCount        int       `json:"kev_count"`
	SuppressedCount int       `json:"suppressed_count"`
}

// Options controls correlation.
type Options struct {
	// IncludeSuppressed keeps VEX-suppressed vulnerabilities in the output (marked).
	IncludeSuppressed bool
}

// Correlate joins the SBOM's embedded vulnerabilities with KEV and EPSS intel.
// kev and epss may be nil if that feed is unavailable.
func Correlate(bom *BOM, kev KEVLookup, epss EPSSLookup, opts Options) *Result {
	result := &Result{TotalComponents: len(bom.Components), TotalVulns: len(bom.Vulnerabilities)}

	for _, v := range bom.Vulnerabilities {
		cve := strings.ToUpper(strings.TrimSpace(v.ID))
		suppressed := v.IsSuppressed()
		if suppressed {
			result.SuppressedCount++
			if !opts.IncludeSuppressed {
				continue
			}
		}

		severity, score := v.HighestSeverity()
		f := Finding{
			CVE:                cve,
			Severity:           severity,
			CVSS:               score,
			AffectedComponents: bom.AffectedComponentLabels(v),
			Suppressed:         suppressed,
		}
		if suppressed && v.Analysis != nil {
			f.SuppressionState = v.Analysis.State
		}

		// Intel correlation only applies to real CVE IDs.
		if cveRe.MatchString(cve) {
			if kev != nil && kev(cve) {
				f.KEV = true
				// Count only actionable (non-suppressed) KEV hits, so KEVCount
				// matches what HasKEV()/--fail-on-kev acts on.
				if !suppressed {
					result.KEVCount++
				}
			}
			if epss != nil {
				if p, ok := epss(cve); ok {
					f.EPSS = p
					f.HasEPSS = true
				}
			}
		}
		result.Findings = append(result.Findings, f)
	}

	sortFindings(result.Findings)
	return result
}

// CVEIDs returns the de-duplicated, sorted set of real CVE IDs referenced by the
// SBOM's vulnerabilities — the input for an EPSS batch fetch.
func (b *BOM) CVEIDs() []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range b.Vulnerabilities {
		cve := strings.ToUpper(strings.TrimSpace(v.ID))
		if cveRe.MatchString(cve) && !seen[cve] {
			seen[cve] = true
			out = append(out, cve)
		}
	}
	sort.Strings(out)
	return out
}

// HasKEV reports whether any non-suppressed finding is KEV-listed (drives the
// --fail-on-kev CI gate).
func (r *Result) HasKEV() bool {
	for _, f := range r.Findings {
		if f.KEV && !f.Suppressed {
			return true
		}
	}
	return false
}

// sortFindings orders by exploitability priority: KEV first, then EPSS desc,
// then CVSS desc, then CVE id — so the most actionable rows are on top.
func sortFindings(f []Finding) {
	sort.Slice(f, func(i, j int) bool {
		if f[i].KEV != f[j].KEV {
			return f[i].KEV
		}
		if f[i].EPSS != f[j].EPSS {
			return f[i].EPSS > f[j].EPSS
		}
		if f[i].CVSS != f[j].CVSS {
			return f[i].CVSS > f[j].CVSS
		}
		return f[i].CVE < f[j].CVE
	})
}
