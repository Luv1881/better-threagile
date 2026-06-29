package report_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/threagile/threagile/pkg/report"
)

func TestBuildGitLabSAST_ValidStructure(t *testing.T) {
	parsedModel := loadFixtureModel(t)

	data, err := report.BuildGitLabSAST(parsedModel, "threagile.yaml", "1.2.3")
	if err != nil {
		t.Fatalf("BuildGitLabSAST: %v", err)
	}

	var rep struct {
		Version string `json:"version"`
		Scan    struct {
			Scanner struct {
				ID, Name, Version string
			} `json:"scanner"`
			Type      string `json:"type"`
			Status    string `json:"status"`
			StartTime string `json:"start_time"`
			EndTime   string `json:"end_time"`
		} `json:"scan"`
		Vulnerabilities []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Severity string `json:"severity"`
			Location struct {
				File      string `json:"file"`
				StartLine int    `json:"start_line"`
				EndLine   int    `json:"end_line"`
			} `json:"location"`
			Identifiers []struct {
				Type, Name, Value string
			} `json:"identifiers"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("GitLab SAST output is not valid JSON: %v", err)
	}

	if rep.Version != "15.0.6" {
		t.Errorf("unexpected schema version %q", rep.Version)
	}
	if rep.Scan.Type != "sast" || rep.Scan.Status != "success" {
		t.Errorf("scan block wrong: type=%q status=%q", rep.Scan.Type, rep.Scan.Status)
	}
	if rep.Scan.Scanner.Version != "1.2.3" || rep.Scan.Scanner.ID != "threagile" {
		t.Errorf("scanner identity wrong: %+v", rep.Scan.Scanner)
	}
	if rep.Scan.StartTime == "" || rep.Scan.EndTime == "" {
		t.Error("scan start/end time must be set")
	}
	// GitLab's date-time format requires RFC 3339 (with timezone designator).
	if _, err := time.Parse(time.RFC3339, rep.Scan.StartTime); err != nil {
		t.Errorf("scan start_time %q is not RFC3339: %v", rep.Scan.StartTime, err)
	}
	if len(rep.Vulnerabilities) == 0 {
		t.Fatal("expected at least one vulnerability for the demo model")
	}

	validSeverity := map[string]bool{"Unknown": true, "Info": true, "Low": true, "Medium": true, "High": true, "Critical": true}
	ids := map[string]bool{}
	for _, v := range rep.Vulnerabilities {
		if !validSeverity[v.Severity] {
			t.Errorf("vuln %s has severity %q outside the GitLab enum", v.ID, v.Severity)
		}
		// SAST location fingerprint requires file + start_line + end_line.
		if v.Location.File == "" || v.Location.StartLine == 0 || v.Location.EndLine == 0 {
			t.Errorf("vuln %s missing mandatory location fields: %+v", v.ID, v.Location)
		}
		if len(v.Identifiers) == 0 || v.Identifiers[0].Type != "threagile_risk_category" {
			t.Errorf("vuln %s primary identifier must be the threagile risk category, got %+v", v.ID, v.Identifiers)
		}
		if v.ID == "" {
			t.Error("vuln id must be non-empty")
		}
		if ids[v.ID] {
			t.Errorf("duplicate vulnerability id %s (GitLab requires unique ids)", v.ID)
		}
		ids[v.ID] = true
	}
}

// Output must be byte-for-byte deterministic across runs (except the scan
// timestamps), so it diffs cleanly in CI artifacts.
func TestBuildGitLabSAST_DeterministicVulns(t *testing.T) {
	parsedModel := loadFixtureModel(t)

	extractVulns := func() []byte {
		data, err := report.BuildGitLabSAST(parsedModel, "threagile.yaml", "v")
		if err != nil {
			t.Fatalf("BuildGitLabSAST: %v", err)
		}
		var rep struct {
			Vulnerabilities json.RawMessage `json:"vulnerabilities"`
		}
		if err := json.Unmarshal(data, &rep); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		return rep.Vulnerabilities
	}
	if !bytes.Equal(extractVulns(), extractVulns()) {
		t.Fatal("vulnerabilities array is not deterministic across runs")
	}
}
