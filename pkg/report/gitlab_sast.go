package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/threagile/threagile/pkg/types"
)

// GitLab SAST report (artifacts:reports:sast) so generated risks render in the
// GitLab merge-request security widget and the project Vulnerability Report —
// GitLab's native format, the GitLab counterpart to the SARIF output we already
// emit for GitHub code scanning. Schema: GitLab security-report-schemas, SAST
// 15.x. One vulnerability per generated risk; the CWE (when known) and the
// threagile risk category are emitted as identifiers so GitLab can de-duplicate
// and link out.

const gitlabSASTSchemaVersion = "15.0.6"

type glSASTReport struct {
	Version         string              `json:"version"`
	Scan            glScan              `json:"scan"`
	Vulnerabilities []glVulnerability   `json:"vulnerabilities"`
}

type glScan struct {
	Scanner   glScanner  `json:"scanner"`
	Analyzer  glAnalyzer `json:"analyzer"`
	Type      string     `json:"type"`
	StartTime string     `json:"start_time"`
	EndTime   string     `json:"end_time"`
	Status    string     `json:"status"`
}

type glScanner struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Version string   `json:"version"`
	URL     string   `json:"url,omitempty"`
	Vendor  glVendor `json:"vendor"`
}

type glAnalyzer struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Vendor  glVendor `json:"vendor"`
}

type glVendor struct {
	Name string `json:"name"`
}

type glVulnerability struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Severity    string         `json:"severity"`
	Solution    string         `json:"solution,omitempty"`
	Location    glLocation     `json:"location"`
	Identifiers []glIdentifier `json:"identifiers"`
}

type glLocation struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

type glIdentifier struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	URL   string `json:"url,omitempty"`
}

// gitlabSeverity maps threagile's five-level severity onto GitLab's enum
// (Unknown, Info, Low, Medium, High, Critical). Threagile's "elevated" sits
// between medium and high; GitLab has no equivalent, so it maps to Medium to
// avoid over-stating it (parity with the SARIF "warning" bucket).
func gitlabSeverity(severity types.RiskSeverity) string {
	switch severity {
	case types.CriticalSeverity:
		return "Critical"
	case types.HighSeverity:
		return "High"
	case types.ElevatedSeverity, types.MediumSeverity:
		return "Medium"
	case types.LowSeverity:
		return "Low"
	default:
		return "Unknown"
	}
}

// BuildGitLabSAST renders the model's generated risks as a GitLab SAST report.
// modelFileURI is the path vulnerabilities point at; version is the tool version.
func BuildGitLabSAST(parsedModel *types.Model, modelFileURI string, version string) ([]byte, error) {
	// Use the model's date (falling back to now) so the artifact is byte-stable
	// across runs of the same model — important for caching, hashing and clean
	// diffs. RFC 3339 (with timezone) is what the GitLab schema's date-time wants.
	scanTime := parsedModel.Date.Time
	if scanTime.IsZero() {
		scanTime = time.Now()
	}
	now := scanTime.UTC().Format(time.RFC3339)

	categoryIDs := make([]string, 0, len(parsedModel.GeneratedRisksByCategory))
	for categoryID := range parsedModel.GeneratedRisksByCategory {
		categoryIDs = append(categoryIDs, categoryID)
	}
	sort.Strings(categoryIDs)

	vulns := make([]glVulnerability, 0)
	for _, categoryID := range categoryIDs {
		category := parsedModel.GetRiskCategory(categoryID)

		risks := make([]*types.Risk, len(parsedModel.GeneratedRisksByCategory[categoryID]))
		copy(risks, parsedModel.GeneratedRisksByCategory[categoryID])
		sort.Slice(risks, func(i, j int) bool {
			if risks[i].SyntheticId != risks[j].SyntheticId {
				return risks[i].SyntheticId < risks[j].SyntheticId
			}
			return risks[i].Title < risks[j].Title
		})

		for _, risk := range risks {
			// Skip findings the team has already dealt with — GitLab has no
			// suppression concept in the SAST schema, so the cleanest behaviour
			// is to only report what is still at risk.
			status := risk.RiskStatus
			if tracking, ok := parsedModel.RiskTracking[risk.SyntheticId]; ok {
				status = tracking.Status
			}
			if status == types.Mitigated || status == types.FalsePositive || status == types.Accepted {
				continue
			}

			// Primary identifier first (GitLab fingerprints on it + location).
			identifiers := []glIdentifier{{
				Type:  "threagile_risk_category",
				Name:  "Threagile: " + categoryID,
				Value: categoryID,
			}}
			var solution string
			if category != nil {
				if category.CWE > 0 {
					identifiers = append(identifiers, glIdentifier{
						Type:  "cwe",
						Name:  fmt.Sprintf("CWE-%d", category.CWE),
						Value: fmt.Sprintf("%d", category.CWE),
						URL:   fmt.Sprintf("https://cwe.mitre.org/data/definitions/%d.html", category.CWE),
					})
				}
				if category.Action != "" {
					solution = stripHTML(category.Action)
				} else {
					solution = stripHTML(category.Mitigation)
				}
			}

			vulns = append(vulns, glVulnerability{
				// Deterministic, unique per finding so GitLab tracks it across runs.
				ID:          fingerprintID(risk.SyntheticId),
				Name:        stripHTML(risk.Title),
				Description: stripHTML(risk.Title),
				Severity:    gitlabSeverity(risk.Severity),
				Solution:    solution,
				Location: glLocation{
					File:      modelFileURI,
					StartLine: 1,
					EndLine:   1,
				},
				Identifiers: identifiers,
			})
		}
	}

	report := glSASTReport{
		Version: gitlabSASTSchemaVersion,
		Scan: glScan{
			Scanner: glScanner{
				ID: "threagile", Name: "Threagile", Version: version,
				URL: "https://threagile.io", Vendor: glVendor{Name: "Threagile"},
			},
			Analyzer: glAnalyzer{
				ID: "threagile", Name: "Threagile", Version: version,
				Vendor: glVendor{Name: "Threagile"},
			},
			Type: "sast", StartTime: now, EndTime: now, Status: "success",
		},
		Vulnerabilities: vulns,
	}

	return json.MarshalIndent(&report, "", "  ")
}

// fingerprintID returns a stable hex id for a synthetic finding id (GitLab
// vulnerability ids must be unique strings; the synthetic id can be long and
// contains '>' / '@', so a sha256 keeps it clean yet deterministic).
func fingerprintID(syntheticID string) string {
	sum := sha256.Sum256([]byte(syntheticID))
	return hex.EncodeToString(sum[:])
}

// WriteRisksGitLabSAST writes the GitLab SAST report to filename.
func WriteRisksGitLabSAST(parsedModel *types.Model, modelFileURI string, version string, filename string) error {
	data, err := BuildGitLabSAST(parsedModel, modelFileURI, version)
	if err != nil {
		return fmt.Errorf("failed to marshal risks to GitLab SAST: %w", err)
	}
	if err := os.WriteFile(filename, data, 0600); err != nil {
		return fmt.Errorf("failed to write risks GitLab SAST file: %w", err)
	}
	return nil
}
