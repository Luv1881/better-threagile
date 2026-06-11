// Package github provides a GitHub Issues sync adapter for threagile findings.
// Each finding is synced to a GitHub issue; the finding's SyntheticId is stored
// as a label so subsequent runs can match findings to existing issues.
//
// Required environment variable: GITHUB_TOKEN (personal access token or Actions token).
// Required scope: issues:write on the target repository.
package github

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/threagile/threagile/pkg/types"
)

const (
	baseURL     = "https://api.github.com"
	labelPrefix = "threagile:"
	userAgent   = "threagile-sync/1.0"
)

// cvePattern matches CVE-YYYY-NNNNN identifiers in free-form text.
var cvePattern = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,7}`)

// Severity score thresholds — mirror GitHub's advisory bands.
const (
	scoreCritical = 9.0
	scoreHigh     = 7.0
	scoreMedium   = 4.0
)

// Config holds GitHub sync configuration.
type Config struct {
	Token  string // GitHub personal access token (falls back to GITHUB_TOKEN env var)
	Owner  string // repo owner (user or org)
	Repo   string // repository name
	DryRun bool   // when true: print actions but don't make API calls
}

// KEVData holds CISA Known Exploited Vulnerabilities catalog data for a CVE.
type KEVData struct {
	VulnerabilityName string
	Product           string
	DateAdded         string
	DueDate           string
	KnownRansomware   string
	RequiredAction    string
}

// NVDData holds NVD CVSS and exploit reference data for a CVE.
type NVDData struct {
	CVSSVersion  string  // "v3" or "v2"
	BaseScore    float64
	Severity     string // CRITICAL / HIGH / MEDIUM / LOW
	VectorString string
	ExploitURLs  []string // URLs tagged "Exploit" in NVD
}

// EPSSData holds EPSS score data for a CVE.
type EPSSData struct {
	Score      float64 // 0.0–1.0 probability of exploitation in next 30 days
	Percentile float64 // 0.0–1.0 relative rank among all CVEs
	Date       string
}

// CVEIntel holds threat-intelligence data for a single CVE referenced in a finding.
type CVEIntel struct {
	CVEID string
	KEV   *KEVData  // nil = not in CISA KEV catalog
	EPSS  *EPSSData // nil = not in EPSS database
	NVD   *NVDData  // nil = NVD lookup unavailable or CVE not found
}

// IntelMap maps risk SyntheticId to the CVE intel collected for that finding.
// Findings with no referenced CVEs are absent from the map.
type IntelMap map[string][]CVEIntel

// ExtractCVEs scans the risk's title, explanation, and rating explanation
// fields for CVE-YYYY-NNNNN patterns and returns a deduplicated, uppercased list.
func ExtractCVEs(r *types.Risk) []string {
	seen := map[string]bool{}
	var result []string

	scan := func(s string) {
		for _, m := range cvePattern.FindAllString(s, -1) {
			upper := strings.ToUpper(m)
			if !seen[upper] {
				seen[upper] = true
				result = append(result, upper)
			}
		}
	}

	scan(r.Title)
	for _, s := range r.RiskExplanation {
		scan(s)
	}
	for _, s := range r.RatingExplanation {
		scan(s)
	}

	return result
}

// Client is a minimal GitHub Issues API client.
type Client struct {
	cfg  Config
	http *http.Client
}

// NewClient creates a GitHub sync client. Token is read from cfg.Token falling back to $GITHUB_TOKEN.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Token == "" {
		cfg.Token = os.Getenv("GITHUB_TOKEN")
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("github: GITHUB_TOKEN is not set")
	}
	if cfg.Owner == "" || cfg.Repo == "" {
		return nil, fmt.Errorf("github: owner and repo are required")
	}
	return &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: 15 * time.Second},
	}, nil
}

// Issue is a minimal GitHub issue representation.
type Issue struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
	State  string `json:"state"`
	Body   string `json:"body"`
	Labels []struct {
		Name string `json:"name"`
	} `json:"labels"`
}

// SyncResult captures per-finding sync outcomes.
type SyncResult struct {
	SyntheticID string
	Action      string // created | updated | closed | skipped
	IssueNumber int
	Error       error
}

// SyncFindings creates or updates GitHub Issues for each finding.
// Findings resolved since the last sync have their issues closed.
// intel provides optional KEV/EPSS enrichment keyed by SyntheticId.
func (c *Client) SyncFindings(model *types.Model, mitigatedIDs []string, intel IntelMap) ([]SyncResult, error) {
	// Index existing issues by threagile synthetic ID label
	existingIssues, err := c.listThreagileIssues()
	if err != nil {
		return nil, fmt.Errorf("github: list issues: %w", err)
	}

	mitigated := make(map[string]bool, len(mitigatedIDs))
	for _, id := range mitigatedIDs {
		mitigated[id] = true
	}

	var results []SyncResult

	// Sync current findings
	for _, risk := range model.GeneratedRisksBySyntheticId {
		label := labelPrefix + risk.SyntheticId
		existing, found := existingIssues[label]

		riskIntel := intel[risk.SyntheticId]
		sev        := CalculateSeverity(risk, model, riskIntel)
		title      := fmt.Sprintf("[%s] %s (score: %.2f)", strings.ToUpper(sev.Label), stripHTML(risk.Title), sev.Score)
		body       := formatIssueBody(risk, model, riskIntel)

		if mitigated[risk.SyntheticId] {
			if found && existing.State == "open" {
				result := c.closeIssue(existing.Number, risk.SyntheticId)
				results = append(results, result)
			}
			continue
		}

		if !found {
			result := c.createIssue(title, body, risk, label, sev.Label)
			results = append(results, result)
		} else if existing.State == "closed" {
			result := c.reopenIssue(existing.Number, risk.SyntheticId)
			results = append(results, result)
		} else {
			results = append(results, SyncResult{
				SyntheticID: risk.SyntheticId,
				Action:      "skipped",
				IssueNumber: existing.Number,
			})
		}
	}

	return results, nil
}

// listThreagileIssues fetches all open + closed issues with a threagile: label.
func (c *Client) listThreagileIssues() (map[string]*Issue, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/issues?labels=%s&state=all&per_page=100",
		baseURL, c.cfg.Owner, c.cfg.Repo, labelPrefix[:len(labelPrefix)-1])
	data, err := c.get(url)
	if err != nil {
		return nil, err
	}
	var issues []*Issue
	if err := json.Unmarshal(data, &issues); err != nil {
		return nil, fmt.Errorf("parse issues: %w", err)
	}

	result := make(map[string]*Issue, len(issues))
	for _, iss := range issues {
		for _, lbl := range iss.Labels {
			if strings.HasPrefix(lbl.Name, labelPrefix) {
				result[lbl.Name] = iss
			}
		}
	}
	return result, nil
}

func (c *Client) createIssue(title, body string, risk *types.Risk, synLabel, sevLabel string) SyncResult {
	if c.cfg.DryRun {
		fmt.Printf("[dry-run] would create issue: %s\n", title)
		return SyncResult{SyntheticID: risk.SyntheticId, Action: "dry-run-create"}
	}

	labels := []string{synLabel, "severity: " + sevLabel, "security", "threat-model"}
	payload := map[string]any{
		"title":  title,
		"body":   body,
		"labels": labels,
	}
	data, _ := json.Marshal(payload)
	url := fmt.Sprintf("%s/repos/%s/%s/issues", baseURL, c.cfg.Owner, c.cfg.Repo)
	resp, err := c.post(url, data)
	if err != nil {
		return SyncResult{SyntheticID: risk.SyntheticId, Action: "create-failed", Error: err}
	}
	var created Issue
	if unmarshalErr := json.Unmarshal(resp, &created); unmarshalErr != nil {
		// Issue was created (HTTP 2xx confirmed above); issue number is unavailable.
		return SyncResult{SyntheticID: risk.SyntheticId, Action: "created"}
	}
	return SyncResult{SyntheticID: risk.SyntheticId, Action: "created", IssueNumber: created.Number}
}

func (c *Client) closeIssue(number int, syntheticID string) SyncResult {
	if c.cfg.DryRun {
		fmt.Printf("[dry-run] would close issue #%d\n", number)
		return SyncResult{SyntheticID: syntheticID, Action: "dry-run-close", IssueNumber: number}
	}
	payload := map[string]any{"state": "closed"}
	data, _ := json.Marshal(payload)
	url := fmt.Sprintf("%s/repos/%s/%s/issues/%d", baseURL, c.cfg.Owner, c.cfg.Repo, number)
	_, err := c.patch(url, data)
	if err != nil {
		return SyncResult{SyntheticID: syntheticID, Action: "close-failed", IssueNumber: number, Error: err}
	}
	return SyncResult{SyntheticID: syntheticID, Action: "closed", IssueNumber: number}
}

func (c *Client) reopenIssue(number int, syntheticID string) SyncResult {
	if c.cfg.DryRun {
		fmt.Printf("[dry-run] would reopen issue #%d\n", number)
		return SyncResult{SyntheticID: syntheticID, Action: "dry-run-reopen", IssueNumber: number}
	}
	payload := map[string]any{"state": "open"}
	data, _ := json.Marshal(payload)
	url := fmt.Sprintf("%s/repos/%s/%s/issues/%d", baseURL, c.cfg.Owner, c.cfg.Repo, number)
	_, err := c.patch(url, data)
	if err != nil {
		return SyncResult{SyntheticID: syntheticID, Action: "reopen-failed", IssueNumber: number, Error: err}
	}
	return SyncResult{SyntheticID: syntheticID, Action: "reopened", IssueNumber: number}
}

// SeverityResult is the output of CalculateSeverity.
type SeverityResult struct {
	Score     float64  // 0–10
	Label     string   // critical | high | medium | low
	Reasoning []string // human-readable scoring steps
}

// CalculateSeverity computes an adjusted severity score for a risk using:
//
//	CVSS (NVD) → KEV boost → EPSS boost → RAA boost → impact/likelihood
//
// It mirrors the severity bands used by GitHub's native security scanning
// (Dependabot / CodeQL): critical ≥9.0, high ≥7.0, medium ≥4.0, low <4.0.
func CalculateSeverity(r *types.Risk, model *types.Model, intel []CVEIntel) SeverityResult {
	threagileBase := map[string]float64{
		"critical": 9.5, "high": 8.0, "elevated": 6.5, "medium": 5.0, "low": 2.5,
	}
	impactBonus := map[string]float64{
		"critical": 0.75, "high": 0.5, "medium": 0.25, "low": 0.0,
	}
	likelihoodBonus := map[string]float64{
		"very-likely": 0.75, "likely": 0.5, "possible": 0.25,
		"unlikely": 0.0, "very-unlikely": -0.5,
	}

	baseKey := strings.ToLower(r.Severity.String())
	score := threagileBase[baseKey]
	if score == 0 {
		score = 5.0
	}
	reasoning := []string{fmt.Sprintf("Base (threagile `%s`): %.1f", baseKey, score)}

	// 1. Override with CVSS when NVD data is available
	for _, ci := range intel {
		if ci.NVD != nil && ci.NVD.BaseScore > 0 {
			score = ci.NVD.BaseScore
			reasoning = []string{fmt.Sprintf(
				"Base (CVSS %s `%s`): %.1f — `%s`",
				ci.NVD.CVSSVersion, ci.NVD.Severity, score, ci.NVD.VectorString,
			)}
			break // use first CVE with CVSS
		}
	}

	// 2. KEV: actively exploited → floor at 8.5
	for _, ci := range intel {
		if ci.KEV != nil {
			if score < 8.5 {
				boost := math64round(8.5-score, 2)
				score = 8.5
				reasoning = append(reasoning,
					fmt.Sprintf("KEV boost (CISA active exploit): +%.2f → %.1f", boost, score))
			} else {
				reasoning = append(reasoning, "KEV: actively exploited (score already ≥ 8.5)")
			}
			break
		}
	}

	// 3. EPSS: exploitation probability
	for _, ci := range intel {
		if ci.EPSS != nil {
			p := ci.EPSS.Score
			var boost float64
			switch {
			case p >= 0.7:
				boost = 2.0
			case p >= 0.3:
				boost = 1.0
			case p >= 0.1:
				boost = 0.5
			}
			if boost > 0 {
				score = clamp(score+boost, 10.0)
				reasoning = append(reasoning,
					fmt.Sprintf("EPSS boost (%.1f%% probability): +%.1f → %.1f",
						p*100, boost, score))
			}
			break
		}
	}

	// 4. RAA: relative attacker attractiveness
	if r.MostRelevantTechnicalAssetId != "" {
		if asset, ok := model.TechnicalAssets[r.MostRelevantTechnicalAssetId]; ok {
			raa := asset.RAA
			var boost float64
			switch {
			case raa >= 75:
				boost = 1.0
			case raa >= 50:
				boost = 0.5
			}
			if boost > 0 {
				score = clamp(score+boost, 10.0)
				reasoning = append(reasoning,
					fmt.Sprintf("RAA boost (%.0f/100): +%.1f → %.1f", raa, boost, score))
			}
		}
	}

	// 5. Threagile impact + likelihood
	ib := impactBonus[strings.ToLower(r.ExploitationImpact.String())]
	lb := likelihoodBonus[strings.ToLower(r.ExploitationLikelihood.String())]
	if ib+lb != 0 {
		score = clamp(score+ib+lb, 10.0)
		reasoning = append(reasoning,
			fmt.Sprintf("Impact/likelihood (%s/%s): +%.2f → %.1f",
				r.ExploitationImpact, r.ExploitationLikelihood, ib+lb, score))
	}

	label := "low"
	switch {
	case score >= scoreCritical:
		label = "critical"
	case score >= scoreHigh:
		label = "high"
	case score >= scoreMedium:
		label = "medium"
	}

	return SeverityResult{Score: math64round(score, 2), Label: label, Reasoning: reasoning}
}

func clamp(v, max float64) float64 {
	if v > max {
		return max
	}
	return v
}

func math64round(v float64, decimals int) float64 {
	factor := 1.0
	for i := 0; i < decimals; i++ {
		factor *= 10
	}
	return float64(int(v*factor+0.5)) / factor
}

var sevBadge = map[string]string{
	"critical": "🔴 CRITICAL",
	"high":     "🟠 HIGH",
	"medium":   "🟡 MEDIUM",
	"low":      "🟢 LOW",
}

func formatIssueBody(r *types.Risk, model *types.Model, intel []CVEIntel) string {
	sev := CalculateSeverity(r, model, intel)
	badge := sevBadge[sev.Label]
	if badge == "" {
		badge = strings.ToUpper(sev.Label)
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("## %s — %s\n\n", badge, stripHTML(r.Title)))

	// Summary table
	b.WriteString("| Field | Value |\n|---|---|\n")
	b.WriteString(fmt.Sprintf("| **Adjusted Score** | `%.2f/10` |\n", sev.Score))
	b.WriteString(fmt.Sprintf("| **Category** | `%s` |\n", r.CategoryId))
	if r.MostRelevantTechnicalAssetId != "" {
		if asset, ok := model.TechnicalAssets[r.MostRelevantTechnicalAssetId]; ok {
			b.WriteString(fmt.Sprintf("| **Affected Asset** | `%s` |\n", asset.Title))
			b.WriteString(fmt.Sprintf("| **RAA (Attacker Attractiveness)** | `%.0f/100` |\n", asset.RAA))
		}
	}
	b.WriteString(fmt.Sprintf("| **Threagile Likelihood** | `%s` |\n", r.ExploitationLikelihood))
	b.WriteString(fmt.Sprintf("| **Threagile Impact** | `%s` |\n", r.ExploitationImpact))
	b.WriteString(fmt.Sprintf("| **Synthetic ID** | `%s` |\n\n", r.SyntheticId))

	// Scoring breakdown
	b.WriteString("### Severity Scoring Breakdown\n\n```\n")
	for _, line := range sev.Reasoning {
		b.WriteString("  " + line + "\n")
	}
	b.WriteString("```\n\n")

	// CVE intelligence
	if len(intel) > 0 {
		b.WriteString("### CVE Intelligence\n\n")
		for _, ci := range intel {
			b.WriteString(fmt.Sprintf("#### %s\n\n", ci.CVEID))

			if ci.NVD != nil && ci.NVD.BaseScore > 0 {
				b.WriteString(fmt.Sprintf("**CVSS %s:** `%.1f` (%s) — `%s`  \n",
					ci.NVD.CVSSVersion, ci.NVD.BaseScore, ci.NVD.Severity, ci.NVD.VectorString))
			}
			if ci.EPSS != nil {
				b.WriteString(fmt.Sprintf(
					"**EPSS:** %.2f%% exploitation probability in next 30 days (%.0fth percentile, %s)  \n",
					ci.EPSS.Score*100, ci.EPSS.Percentile*100, ci.EPSS.Date))
			}
			if ci.KEV != nil {
				b.WriteString("**KEV (CISA):** ⚠️ ACTIVELY EXPLOITED IN THE WILD  \n")
				b.WriteString(fmt.Sprintf("- Product: %s  \n", ci.KEV.Product))
				b.WriteString(fmt.Sprintf("- Added: %s | Patch due: %s  \n", ci.KEV.DateAdded, ci.KEV.DueDate))
				b.WriteString(fmt.Sprintf("- Required action: %s  \n", ci.KEV.RequiredAction))
				b.WriteString(fmt.Sprintf("- Known ransomware use: %s  \n", ci.KEV.KnownRansomware))
			} else {
				b.WriteString("**KEV (CISA):** Not in known-exploited catalog  \n")
			}

			if ci.NVD != nil && len(ci.NVD.ExploitURLs) > 0 {
				b.WriteString("\n**Proof of Concept / Exploit References:**\n\n")
				for _, u := range ci.NVD.ExploitURLs {
					b.WriteString(fmt.Sprintf("- [%s](%s)\n", u, u))
				}
			} else {
				b.WriteString("\n**PoC / Exploit:** No public exploit references in NVD  \n")
			}

			b.WriteString(fmt.Sprintf(
				"\n🔍 [ExploitDB search for %s](https://www.exploit-db.com/search?cve=%s)"+
					"  ·  [NVD entry](https://nvd.nist.gov/vuln/detail/%s)\n\n",
				ci.CVEID, strings.TrimPrefix(ci.CVEID, "CVE-"), ci.CVEID,
			))
		}
	} else {
		b.WriteString("### Threat Intelligence\n\n")
		b.WriteString("_No CVE IDs referenced — architectural risk pattern._  \n")
		b.WriteString("_Severity scored from threagile model attributes (likelihood, impact, RAA)._\n\n")
	}

	b.WriteString("---\n")
	b.WriteString("*Auto-generated by [better-threagile](https://github.com/Luv1881/better-threagile) ")
	b.WriteString("— severity adjusted via CVSS · KEV · EPSS · RAA.*\n")
	b.WriteString("*Add a `risk_tracking` entry in `threagile/threagile.yaml` to acknowledge this risk.*\n")
	return b.String()
}

func (c *Client) get(url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil) //nolint:noctx
	if err != nil {
		return nil, err
	}
	return c.do(req)
}

func (c *Client) post(url string, body []byte) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body)) //nolint:noctx
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req)
}

func (c *Client) patch(url string, body []byte) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPatch, url, bytes.NewReader(body)) //nolint:noctx
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req)
}

func (c *Client) do(req *http.Request) ([]byte, error) {
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github api: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("github api: read body: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("github api: HTTP %d: %s", resp.StatusCode, truncate(string(data), 200))
	}
	return data, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func stripHTML(s string) string {
	var result strings.Builder
	inTag := false
	for _, ch := range s {
		if ch == '<' {
			inTag = true
			continue
		}
		if ch == '>' {
			inTag = false
			continue
		}
		if !inTag {
			result.WriteRune(ch)
		}
	}
	return result.String()
}
