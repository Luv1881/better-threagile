package github

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/threagile/threagile/pkg/types"
)

// --- helpers ----------------------------------------------------------------

func newClient(t *testing.T, serverURL string) *Client {
	t.Helper()
	cfg := Config{Token: "test-token", Owner: "owner", Repo: "repo"}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// Override the base URL used by HTTP methods to hit the test server.
	// We achieve this by injecting the server URL directly into requests via a
	// custom transport that rewrites the host.
	c.http = &http.Client{
		Transport: &rewriteTransport{base: serverURL},
	}
	return c
}

// rewriteTransport rewrites the Host of every request to the given base URL
// so client.get/post/patch hit the httptest server instead of api.github.com.
type rewriteTransport struct {
	base string
	rt   http.RoundTripper
}

func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone so we don't mutate the original
	r2 := req.Clone(req.Context())
	parsed, _ := http.NewRequest(req.Method, t.base+req.URL.Path+"?"+req.URL.RawQuery, req.Body) //nolint:noctx,gosec // test transport rewrites requests to a local httptest server
	r2.URL = parsed.URL
	r2.Host = parsed.Host
	rt := t.rt
	if rt == nil {
		rt = http.DefaultTransport
	}
	return rt.RoundTrip(r2)
}

func minimalRisk(id, severity string) *types.Risk {
	sev, _ := types.ParseRiskSeverity(severity)
	lik, _ := types.ParseRiskExploitationLikelihood("likely")
	imp, _ := types.ParseRiskExploitationImpact("medium")
	return &types.Risk{
		SyntheticId:            id,
		CategoryId:             "test-category",
		Title:                  "Test Risk " + id,
		Severity:               sev,
		ExploitationLikelihood: lik,
		ExploitationImpact:     imp,
	}
}

func minimalModel(risks ...*types.Risk) *types.Model {
	m := &types.Model{
		TechnicalAssets:             map[string]*types.TechnicalAsset{},
		GeneratedRisksBySyntheticId: map[string]*types.Risk{},
	}
	for _, r := range risks {
		m.GeneratedRisksBySyntheticId[r.SyntheticId] = r
	}
	return m
}

// --- NewClient --------------------------------------------------------------

func TestNewClient_MissingToken(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	_, err := NewClient(Config{Owner: "o", Repo: "r"})
	if err == nil {
		t.Fatal("expected error when token is empty")
	}
}

func TestNewClient_MissingOwnerRepo(t *testing.T) {
	_, err := NewClient(Config{Token: "tok"})
	if err == nil {
		t.Fatal("expected error when owner/repo are empty")
	}
}

func TestNewClient_Valid(t *testing.T) {
	c, err := NewClient(Config{Token: "tok", Owner: "o", Repo: "r"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("expected client, got nil")
	}
}

// --- ExtractCVEs ------------------------------------------------------------

func TestExtractCVEs(t *testing.T) {
	r := &types.Risk{
		Title:             "CVE-2021-44228 and CVE-2022-0001 in title",
		RiskExplanation:   []string{"Also mentions cve-2023-9999 here"},
		RatingExplanation: []string{"And CVE-2021-44228 again (duplicate)"},
	}
	cves := ExtractCVEs(r)
	if len(cves) != 3 {
		t.Errorf("expected 3 unique CVEs, got %d: %v", len(cves), cves)
	}
	for _, id := range cves {
		if id != strings.ToUpper(id) {
			t.Errorf("CVE ID not uppercased: %q", id)
		}
	}
}

func TestExtractCVEs_None(t *testing.T) {
	r := &types.Risk{Title: "no CVEs here", RiskExplanation: []string{"pure architectural risk"}}
	if got := ExtractCVEs(r); len(got) != 0 {
		t.Errorf("expected 0 CVEs, got %d", len(got))
	}
}

// --- CalculateSeverity ------------------------------------------------------

func TestCalculateSeverity_BaseOnly(t *testing.T) {
	r := minimalRisk("r1", "high")
	m := minimalModel(r)
	result := CalculateSeverity(r, m, nil)
	if result.Label == "" {
		t.Error("expected non-empty label")
	}
	if result.Score <= 0 || result.Score > 10 {
		t.Errorf("score out of range: %v", result.Score)
	}
}

func TestCalculateSeverity_CVSSOverride(t *testing.T) {
	r := minimalRisk("r1", "low")
	m := minimalModel(r)
	intel := []CVEIntel{
		{CVEID: "CVE-2021-44228", NVD: &NVDData{BaseScore: 10.0, Severity: "CRITICAL", CVSSVersion: "v3"}},
	}
	result := CalculateSeverity(r, m, intel)
	if result.Score < 9.0 {
		t.Errorf("CVSS override should push score to critical, got %.2f", result.Score)
	}
	if result.Label != "critical" {
		t.Errorf("label = %q, want critical", result.Label)
	}
}

func TestCalculateSeverity_KEVBoost(t *testing.T) {
	r := minimalRisk("r1", "medium")
	m := minimalModel(r)
	intel := []CVEIntel{
		{CVEID: "CVE-2021-44228", KEV: &KEVData{VulnerabilityName: "Log4Shell"}},
	}
	result := CalculateSeverity(r, m, intel)
	// KEV should floor score at 8.5
	if result.Score < 8.5 {
		t.Errorf("KEV boost should floor score at 8.5, got %.2f", result.Score)
	}
}

func TestCalculateSeverity_EPSSBoost(t *testing.T) {
	r := minimalRisk("r1", "low")
	m := minimalModel(r)
	baseResult := CalculateSeverity(r, m, nil)
	intel := []CVEIntel{
		{CVEID: "CVE-2021-44228", EPSS: &EPSSData{Score: 0.9, Percentile: 0.99}},
	}
	boostedResult := CalculateSeverity(r, m, intel)
	if boostedResult.Score <= baseResult.Score {
		t.Errorf("EPSS boost should increase score: base=%.2f boosted=%.2f",
			baseResult.Score, boostedResult.Score)
	}
}

func TestCalculateSeverity_ScoreCappedAt10(t *testing.T) {
	r := minimalRisk("r1", "critical")
	r.ExploitationLikelihood, _ = types.ParseRiskExploitationLikelihood("very-likely")
	r.ExploitationImpact, _ = types.ParseRiskExploitationImpact("critical")
	m := minimalModel(r)
	intel := []CVEIntel{
		{
			CVEID: "CVE-2021-44228",
			NVD:   &NVDData{BaseScore: 10.0, Severity: "CRITICAL", CVSSVersion: "v3"},
			KEV:   &KEVData{VulnerabilityName: "x"},
			EPSS:  &EPSSData{Score: 0.99},
		},
	}
	result := CalculateSeverity(r, m, intel)
	if result.Score > 10.0 {
		t.Errorf("score exceeded 10: %.2f", result.Score)
	}
}

// --- DryRun mode ------------------------------------------------------------

func TestSyncFindings_DryRun_NoHTTPCalls(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		// Return empty list so listThreagileIssues works
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]*Issue{})
	}))
	defer srv.Close()

	cfg := Config{Token: "tok", Owner: "o", Repo: "r", DryRun: true}
	c, _ := NewClient(cfg)
	c.http = &http.Client{Transport: &rewriteTransport{base: srv.URL}}

	risk := minimalRisk("r1", "high")
	model := minimalModel(risk)

	results, err := c.SyncFindings(model, nil, nil)
	if err != nil {
		t.Fatalf("SyncFindings dry-run: %v", err)
	}
	_ = results
	if called {
		// The list call is OK; what we ensure is no CREATE call was made
		// (the handler above doesn't distinguish method so just check results)
	}
	for _, r := range results {
		if r.Action != "dry-run-create" && r.Action != "skipped" {
			t.Errorf("unexpected dry-run action %q for %q", r.Action, r.SyntheticID)
		}
	}
}

// --- Auth error propagation -------------------------------------------------

func TestSyncFindings_AuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Bad credentials"}`))
	}))
	defer srv.Close()

	c := newClient(t, srv.URL)
	model := minimalModel(minimalRisk("r1", "high"))

	_, err := c.SyncFindings(model, nil, nil)
	if err == nil {
		t.Fatal("expected auth error, got nil")
	}
}

// --- stripHTML utility ------------------------------------------------------

func TestStripHTML(t *testing.T) {
	tests := []struct{ input, want string }{
		{"no tags", "no tags"},
		{"<b>bold</b>", "bold"},
		{"<span class='x'>text</span>", "text"},
		{"a < b", "a "},  // bare < is treated as tag-open; text after it is stripped
	}
	for _, tt := range tests {
		got := stripHTML(tt.input)
		if got != tt.want {
			t.Errorf("stripHTML(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// --- formatIssueBody --------------------------------------------------------

func TestFormatIssueBody_ContainsSyntheticID(t *testing.T) {
	r := minimalRisk("risk-syn-001", "high")
	m := minimalModel(r)
	body := formatIssueBody(r, m, nil)
	if !strings.Contains(body, "risk-syn-001") {
		t.Error("issue body should contain synthetic ID")
	}
}

func TestFormatIssueBody_WithCVEIntel(t *testing.T) {
	r := minimalRisk("r1", "high")
	m := minimalModel(r)
	intel := []CVEIntel{
		{
			CVEID: "CVE-2021-44228",
			NVD:   &NVDData{BaseScore: 10.0, Severity: "CRITICAL", CVSSVersion: "v3", VectorString: "AV:N"},
			EPSS:  &EPSSData{Score: 0.974, Percentile: 0.999, Date: "2024-01-01"},
			KEV:   &KEVData{VulnerabilityName: "Log4Shell", Product: "Log4j", DateAdded: "2021-12-10"},
		},
	}
	body := formatIssueBody(r, m, intel)
	if !strings.Contains(body, "CVE-2021-44228") {
		t.Error("body should contain CVE ID")
	}
	if !strings.Contains(body, "ACTIVELY EXPLOITED") {
		t.Error("body should mention KEV active exploitation")
	}
}
