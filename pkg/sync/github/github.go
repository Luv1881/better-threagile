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
	baseURL       = "https://api.github.com"
	labelPrefix   = "threagile:"
	severityLabel = "threat-severity:"
	userAgent     = "threagile-sync/1.0"
)

// cvePattern matches CVE-YYYY-NNNNN identifiers in free-form text.
var cvePattern = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,7}`)

// Config holds GitHub sync configuration.
type Config struct {
	Token   string // GitHub personal access token (falls back to GITHUB_TOKEN env var)
	Owner   string // repo owner (user or org)
	Repo    string // repository name
	Project string // optional project label prefix (e.g. "sec" → label "sec:")
	DryRun  bool   // when true: print actions but don't make API calls
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

		title := fmt.Sprintf("[%s] %s", strings.ToUpper(risk.Severity.String()), stripHTML(risk.Title))
		body := formatIssueBody(risk, model, intel[risk.SyntheticId])

		if mitigated[risk.SyntheticId] {
			if found && existing.State == "open" {
				result := c.closeIssue(existing.Number, risk.SyntheticId)
				results = append(results, result)
			}
			continue
		}

		if !found {
			result := c.createIssue(title, body, risk, label)
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

func (c *Client) createIssue(title, body string, risk *types.Risk, synLabel string) SyncResult {
	if c.cfg.DryRun {
		fmt.Printf("[dry-run] would create issue: %s\n", title)
		return SyncResult{SyntheticID: risk.SyntheticId, Action: "dry-run-create"}
	}

	labels := []string{synLabel, severityLabel + risk.Severity.String()}
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
	_ = json.Unmarshal(resp, &created)
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

func formatIssueBody(r *types.Risk, model *types.Model, intel []CVEIntel) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("## Threat Finding: %s\n\n", r.CategoryId))
	b.WriteString(fmt.Sprintf("**Severity:** %s  \n", r.Severity.String()))
	b.WriteString(fmt.Sprintf("**Likelihood:** %s  \n", r.ExploitationLikelihood.String()))
	b.WriteString(fmt.Sprintf("**Impact:** %s  \n", r.ExploitationImpact.String()))
	b.WriteString(fmt.Sprintf("**Synthetic ID:** `%s`  \n\n", r.SyntheticId))

	if r.MostRelevantTechnicalAssetId != "" {
		if asset, ok := model.TechnicalAssets[r.MostRelevantTechnicalAssetId]; ok {
			b.WriteString(fmt.Sprintf("**Most Relevant Asset:** %s  \n\n", asset.Title))
		}
	}

	// KEV / EPSS section
	b.WriteString("### Threat Intelligence\n\n")
	if len(intel) == 0 {
		b.WriteString("_No CVE IDs referenced in this finding (architectural risk pattern)._  \n")
		b.WriteString("_To associate CVEs, add them to the finding's `risk_explanation` in the model._\n")
	} else {
		for _, ci := range intel {
			b.WriteString(fmt.Sprintf("**%s**\n\n", ci.CVEID))

			if ci.KEV != nil {
				b.WriteString(fmt.Sprintf("- **KEV (CISA):** YES — %s (%s)\n", ci.KEV.VulnerabilityName, ci.KEV.Product))
				b.WriteString(fmt.Sprintf("  - Date added: %s | Patch due: %s\n", ci.KEV.DateAdded, ci.KEV.DueDate))
				b.WriteString(fmt.Sprintf("  - Required action: %s\n", ci.KEV.RequiredAction))
				b.WriteString(fmt.Sprintf("  - Known ransomware use: %s\n", ci.KEV.KnownRansomware))
			} else {
				b.WriteString("- **KEV (CISA):** Not in known-exploited catalog\n")
			}

			if ci.EPSS != nil {
				b.WriteString(fmt.Sprintf("- **EPSS:** %.2f%% exploitation probability (%.0fth percentile, %s)\n",
					ci.EPSS.Score*100, ci.EPSS.Percentile*100, ci.EPSS.Date))
			} else {
				b.WriteString("- **EPSS:** Not in EPSS database\n")
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("---\n")
	b.WriteString("*Auto-generated by [threagile](https://github.com/threagile/threagile) — do not edit manually.*\n")
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
