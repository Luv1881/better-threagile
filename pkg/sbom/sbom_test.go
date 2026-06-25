package sbom

import (
	"strings"
	"testing"
)

const sampleSBOM = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    {"type":"library","name":"log4j-core","version":"2.14.1","bom-ref":"ref-log4j"},
    {"type":"library","name":"lodash","version":"4.17.20","bom-ref":"ref-lodash"},
    {"type":"library","name":"openssl","version":"3.0.0","bom-ref":"ref-openssl"}
  ],
  "vulnerabilities": [
    {"id":"CVE-2021-44228","ratings":[{"score":10.0,"severity":"critical"}],"affects":[{"ref":"ref-log4j"}]},
    {"id":"CVE-2021-23337","ratings":[{"score":7.2,"severity":"high"}],"affects":[{"ref":"ref-lodash"}]},
    {"id":"CVE-2022-3602","ratings":[{"score":7.5,"severity":"high"}],"affects":[{"ref":"ref-openssl"}],"analysis":{"state":"not_affected"}}
  ]
}`

func parse(t *testing.T) *BOM {
	t.Helper()
	b, err := Parse([]byte(sampleSBOM))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fakeKEV marks only Log4Shell as KEV.
func fakeKEV(cve string) bool { return cve == "CVE-2021-44228" }

// fakeEPSS returns high EPSS for Log4Shell, medium for lodash.
func fakeEPSS(cve string) (float64, bool) {
	switch cve {
	case "CVE-2021-44228":
		return 0.97, true
	case "CVE-2021-23337":
		return 0.22, true
	}
	return 0, false
}

func TestParseRejectsNonCycloneDX(t *testing.T) {
	if _, err := Parse([]byte(`{"foo":"bar"}`)); err == nil {
		t.Error("non-CycloneDX doc should error")
	}
	if _, err := Parse([]byte(`not json`)); err == nil {
		t.Error("invalid JSON should error")
	}
}

func TestCorrelatePrioritizesKEVThenEPSS(t *testing.T) {
	r := Correlate(parse(t), fakeKEV, fakeEPSS, Options{})

	// not_affected is suppressed by default -> 2 findings.
	if len(r.Findings) != 2 {
		t.Fatalf("expected 2 findings (1 suppressed), got %d", len(r.Findings))
	}
	if r.SuppressedCount != 1 {
		t.Fatalf("expected 1 suppressed, got %d", r.SuppressedCount)
	}
	// KEV-listed Log4Shell must be first.
	if r.Findings[0].CVE != "CVE-2021-44228" || !r.Findings[0].KEV {
		t.Fatalf("KEV finding should sort first, got %+v", r.Findings[0])
	}
	if r.KEVCount != 1 || !r.HasKEV() {
		t.Fatalf("KEVCount/HasKEV wrong: count=%d has=%v", r.KEVCount, r.HasKEV())
	}
	if r.Findings[0].EPSS != 0.97 || !r.Findings[0].HasEPSS {
		t.Fatalf("EPSS not attached: %+v", r.Findings[0])
	}
	if !contains(r.Findings[0].AffectedComponents, "log4j-core@2.14.1") {
		t.Fatalf("affected component label wrong: %v", r.Findings[0].AffectedComponents)
	}
}

func TestCorrelateIncludeSuppressed(t *testing.T) {
	r := Correlate(parse(t), fakeKEV, fakeEPSS, Options{IncludeSuppressed: true})
	if len(r.Findings) != 3 {
		t.Fatalf("with include-suppressed expected 3 findings, got %d", len(r.Findings))
	}
	var supp *Finding
	for i := range r.Findings {
		if r.Findings[i].CVE == "CVE-2022-3602" {
			supp = &r.Findings[i]
		}
	}
	if supp == nil || !supp.Suppressed || supp.SuppressionState != "not_affected" {
		t.Fatalf("suppressed finding not marked correctly: %+v", supp)
	}
}

func TestCorrelateNilFeeds(t *testing.T) {
	// No intel available -> still reports vulns, no KEV/EPSS, no panic.
	r := Correlate(parse(t), nil, nil, Options{})
	if len(r.Findings) != 2 || r.KEVCount != 0 || r.HasKEV() {
		t.Fatalf("nil feeds should yield findings without KEV: %+v", r)
	}
}

func TestCVEIDs(t *testing.T) {
	ids := parse(t).CVEIDs()
	if len(ids) != 3 {
		t.Fatalf("expected 3 CVE IDs, got %v", ids)
	}
	// sorted
	for i := 1; i < len(ids); i++ {
		if ids[i-1] > ids[i] {
			t.Fatal("CVE IDs not sorted")
		}
	}
}

func TestNonCVEVulnNotCorrelated(t *testing.T) {
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.5","vulnerabilities":[{"id":"GHSA-xxxx-yyyy-zzzz","ratings":[{"score":5}]}]}`
	b, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	// A KEV lookup that returns true for everything must NOT mark a non-CVE id.
	r := Correlate(b, func(string) bool { return true }, nil, Options{})
	if len(r.Findings) != 1 || r.Findings[0].KEV {
		t.Fatalf("non-CVE id must not be KEV-correlated: %+v", r.Findings)
	}
}

func TestFormats(t *testing.T) {
	r := Correlate(parse(t), fakeKEV, fakeEPSS, Options{})
	text := FormatText(r)
	if !strings.Contains(text, "CVE-2021-44228") || !strings.Contains(text, "KEV") {
		t.Fatalf("text format missing content:\n%s", text)
	}
	md := FormatMarkdown(r)
	if !strings.Contains(md, "| CVE | Severity") || !strings.Contains(md, "CVE-2021-44228") {
		t.Fatalf("markdown format missing content:\n%s", md)
	}
}

func TestParseRejectsOtherFormatWithComponents(t *testing.T) {
	// A non-CycloneDX bomFormat must be rejected even if it carries components.
	doc := `{"bomFormat":"SPDX","specVersion":"2.3","components":[{"name":"x"}]}`
	if _, err := Parse([]byte(doc)); err == nil {
		t.Error("SPDX document with components must be rejected")
	}
}

func TestHighestSeverityEdgeCases(t *testing.T) {
	// severity-only rating (no score) must not be "unknown".
	v := Vulnerability{Ratings: []Rating{{Severity: "High"}}}
	if sev, score := v.HighestSeverity(); sev != "high" || score != 0 {
		t.Fatalf("severity-only: got %s/%.1f", sev, score)
	}
	// higher-score rating with empty severity must not erase the labelled one.
	v = Vulnerability{Ratings: []Rating{{Score: 4, Severity: "medium"}, {Score: 9}}}
	if sev, score := v.HighestSeverity(); sev != "medium" || score != 9 {
		t.Fatalf("mixed: got %s/%.1f, want medium/9", sev, score)
	}
	// take the highest severity label across ratings.
	v = Vulnerability{Ratings: []Rating{{Score: 5, Severity: "medium"}, {Score: 3, Severity: "critical"}}}
	if sev, score := v.HighestSeverity(); sev != "critical" || score != 5 {
		t.Fatalf("rank: got %s/%.1f, want critical/5", sev, score)
	}
}

func TestKEVCountExcludesSuppressed(t *testing.T) {
	// A suppressed vuln that is KEV-listed must not inflate KEVCount, and must
	// not trigger HasKEV, even with --include-suppressed.
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.5","vulnerabilities":[
	  {"id":"CVE-2021-44228","ratings":[{"score":10,"severity":"critical"}],"analysis":{"state":"not_affected"}}
	]}`
	b, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	r := Correlate(b, fakeKEV, nil, Options{IncludeSuppressed: true})
	if r.KEVCount != 0 || r.HasKEV() {
		t.Fatalf("suppressed KEV must not count: KEVCount=%d HasKEV=%v", r.KEVCount, r.HasKEV())
	}
}

func contains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}
