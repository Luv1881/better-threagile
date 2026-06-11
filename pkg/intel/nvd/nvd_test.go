package nvd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func sampleNVDResponse(cveID string) nvdResponse {
	return nvdResponse{
		Vulnerabilities: []struct {
			CVE nvdCVE `json:"cve"`
		}{
			{
				CVE: nvdCVE{
					ID: cveID,
					Descriptions: []struct {
						Lang  string `json:"lang"`
						Value string `json:"value"`
					}{
						{Lang: "en", Value: "A test vulnerability."},
						{Lang: "es", Value: "Una vulnerabilidad de prueba."},
					},
					Metrics: struct {
						V31 []nvdMetric `json:"cvssMetricV31"`
						V30 []nvdMetric `json:"cvssMetricV30"`
						V2  []nvdMetric `json:"cvssMetricV2"`
					}{
						V31: []nvdMetric{
							{CVSSData: struct {
								BaseScore    float64 `json:"baseScore"`
								BaseSeverity string  `json:"baseSeverity"`
								VectorString string  `json:"vectorString"`
							}{BaseScore: 10.0, BaseSeverity: "CRITICAL", VectorString: "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}},
						},
					},
					References: []struct {
						URL  string   `json:"url"`
						Tags []string `json:"tags"`
					}{
						{URL: "https://example.com/exploit", Tags: []string{"Exploit"}},
						{URL: "https://example.com/patch", Tags: []string{"Patch"}},
					},
				},
			},
		},
	}
}

func newTestServer(t *testing.T, statusCode int, body any) *httptest.Server {
	t.Helper()
	data, _ := json.Marshal(body)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_, _ = w.Write(data)
	}))
}

func TestFetch(t *testing.T) {
	srv := newTestServer(t, 200, sampleNVDResponse("CVE-2021-44228"))
	defer srv.Close()

	cve, err := Fetch("CVE-2021-44228", srv.URL)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if cve == nil {
		t.Fatal("expected CVE, got nil")
	}
	if cve.ID != "CVE-2021-44228" {
		t.Errorf("ID = %q, want CVE-2021-44228", cve.ID)
	}
	if cve.Description != "A test vulnerability." {
		t.Errorf("Description = %q", cve.Description)
	}
	if cve.CVSS == nil {
		t.Fatal("expected CVSS data")
	}
	if cve.CVSS.BaseScore != 10.0 {
		t.Errorf("BaseScore = %v, want 10.0", cve.CVSS.BaseScore)
	}
	if cve.CVSS.Severity != "CRITICAL" {
		t.Errorf("Severity = %q, want CRITICAL", cve.CVSS.Severity)
	}
}

func TestFetch_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cve, err := Fetch("CVE-9999-9999", srv.URL)
	if err != nil {
		t.Fatalf("unexpected error on 404: %v", err)
	}
	if cve != nil {
		t.Fatal("expected nil CVE on 404")
	}
}

func TestFetch_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	_, err := Fetch("CVE-2021-44228", srv.URL)
	if err == nil {
		t.Fatal("expected error on HTTP 429")
	}
}

func TestFetch_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("{bad json"))
	}))
	defer srv.Close()

	_, err := Fetch("CVE-2021-44228", srv.URL)
	if err == nil {
		t.Fatal("expected error on malformed JSON")
	}
}

func TestFetch_EmptyVulnerabilities(t *testing.T) {
	srv := newTestServer(t, 200, nvdResponse{})
	defer srv.Close()

	cve, err := Fetch("CVE-2021-44228", srv.URL)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if cve != nil {
		t.Fatal("expected nil for empty vulnerabilities array")
	}
}

func TestFetchBatch(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		cveID := r.URL.Query().Get("cveId")
		data, _ := json.Marshal(sampleNVDResponse(cveID))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	ids := []string{"CVE-2021-44228", "CVE-2022-0001"}
	result := FetchBatch(ids, srv.URL, time.Millisecond)

	if len(result) != 2 {
		t.Errorf("FetchBatch returned %d entries, want 2", len(result))
	}
	if callCount != 2 {
		t.Errorf("expected 2 HTTP calls, got %d", callCount)
	}
}

func TestExploitRefs(t *testing.T) {
	cve := &CVE{
		References: []Reference{
			{URL: "https://example.com/exploit", Tags: []string{"Exploit"}},
			{URL: "https://example.com/patch", Tags: []string{"Patch"}},
			{URL: "https://example.com/exploit2", Tags: []string{"Exploit", "Third Party Advisory"}},
		},
	}
	exploits := cve.ExploitRefs()
	if len(exploits) != 2 {
		t.Errorf("ExploitRefs = %d, want 2", len(exploits))
	}
}

func TestReferenceIsExploit(t *testing.T) {
	r := Reference{Tags: []string{"Exploit"}}
	if !r.IsExploit() {
		t.Error("expected IsExploit true")
	}
	r2 := Reference{Tags: []string{"Patch"}}
	if r2.IsExploit() {
		t.Error("expected IsExploit false")
	}
}

func TestCVSSFallbackToV2(t *testing.T) {
	resp := nvdResponse{
		Vulnerabilities: []struct {
			CVE nvdCVE `json:"cve"`
		}{
			{
				CVE: nvdCVE{
					ID: "CVE-2005-0001",
					Metrics: struct {
						V31 []nvdMetric `json:"cvssMetricV31"`
						V30 []nvdMetric `json:"cvssMetricV30"`
						V2  []nvdMetric `json:"cvssMetricV2"`
					}{
						V2: []nvdMetric{
							{CVSSData: struct {
								BaseScore    float64 `json:"baseScore"`
								BaseSeverity string  `json:"baseSeverity"`
								VectorString string  `json:"vectorString"`
							}{BaseScore: 7.5, BaseSeverity: "HIGH", VectorString: "AV:N/AC:L/Au:N/C:P/I:P/A:P"}},
						},
					},
				},
			},
		},
	}

	srv := newTestServer(t, 200, resp)
	defer srv.Close()

	cve, err := Fetch("CVE-2005-0001", srv.URL)
	if err != nil || cve == nil {
		t.Fatalf("Fetch: %v", err)
	}
	if cve.CVSS == nil {
		t.Fatal("expected CVSS data from v2 fallback")
	}
	if cve.CVSS.Version != "v2" {
		t.Errorf("Version = %q, want v2", cve.CVSS.Version)
	}
}
