// Package nvd provides a client for the NIST National Vulnerability Database (NVD)
// CVE 2.0 REST API. It fetches per-CVE details including CVSS scores and
// exploit/PoC reference URLs.
//
// Rate limit (no API key): 5 requests per 30 seconds.
// Use FetchBatch which enforces a 700 ms inter-request delay.
//
// Reference: https://nvd.nist.gov/developers/vulnerabilities
package nvd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	DefaultAPIBase = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	// DefaultDelay keeps requests within the 5 req/30 s unauthenticated rate limit.
	DefaultDelay = 700 * time.Millisecond
)

// CVE is a minimal representation of an NVD CVE 2.0 object.
type CVE struct {
	ID          string
	Description string
	CVSS        *CVSSData
	References  []Reference
}

// CVSSData holds the best available CVSS score for a CVE.
type CVSSData struct {
	Version      string  // "v3" or "v2"
	BaseScore    float64
	Severity     string // CRITICAL / HIGH / MEDIUM / LOW
	VectorString string
}

// Reference is a single NVD reference link with optional tags.
type Reference struct {
	URL  string
	Tags []string
}

// IsExploit returns true if this reference is tagged as an exploit or PoC.
func (r Reference) IsExploit() bool {
	for _, t := range r.Tags {
		if t == "Exploit" {
			return true
		}
	}
	return false
}

// ExploitRefs returns the references tagged as exploits (capped at 5).
func (c *CVE) ExploitRefs() []Reference {
	var out []Reference
	for _, r := range c.References {
		if r.IsExploit() {
			out = append(out, r)
			if len(out) == 5 {
				break
			}
		}
	}
	return out
}

// raw NVD API shapes — only what we need
type nvdResponse struct {
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID          string `json:"id"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		V31 []nvdMetric `json:"cvssMetricV31"`
		V30 []nvdMetric `json:"cvssMetricV30"`
		V2  []nvdMetric `json:"cvssMetricV2"`
	} `json:"metrics"`
	References []struct {
		URL  string   `json:"url"`
		Tags []string `json:"tags"`
	} `json:"references"`
}

type nvdMetric struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
}

// Fetch retrieves the NVD CVE record for a single CVE ID.
// Returns (nil, nil) if the CVE is not found.
func Fetch(cveID, apiBase string) (*CVE, error) {
	if apiBase == "" {
		apiBase = DefaultAPIBase
	}
	reqURL := apiBase + "?cveId=" + url.QueryEscape(strings.ToUpper(cveID))
	client := &http.Client{Timeout: 15 * time.Second}

	resp, err := client.Get(reqURL) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("nvd: fetch %s: %w", cveID, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nvd: HTTP %d for %s", resp.StatusCode, cveID)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("nvd: read body: %w", err)
	}

	var raw nvdResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("nvd: parse response: %w", err)
	}
	if len(raw.Vulnerabilities) == 0 {
		return nil, nil
	}

	return parseCVE(&raw.Vulnerabilities[0].CVE), nil
}

// FetchBatch fetches NVD data for each CVE ID, sleeping delay between requests
// to respect the unauthenticated rate limit. If delay is 0, DefaultDelay is used.
// Errors for individual CVEs are silently skipped.
func FetchBatch(cveIDs []string, apiBase string, delay time.Duration) map[string]*CVE {
	if delay == 0 {
		delay = DefaultDelay
	}
	result := make(map[string]*CVE, len(cveIDs))
	for _, id := range cveIDs {
		cve, err := Fetch(id, apiBase)
		if err == nil && cve != nil {
			result[strings.ToUpper(id)] = cve
		}
		time.Sleep(delay)
	}
	return result
}

func parseCVE(raw *nvdCVE) *CVE {
	cve := &CVE{ID: raw.ID}

	// Pick English description
	for _, d := range raw.Descriptions {
		if d.Lang == "en" {
			cve.Description = d.Value
			break
		}
	}

	// Pick best CVSS (v3.1 > v3.0 > v2)
	type candidate struct {
		metrics []nvdMetric
		version string
	}
	for _, c := range []candidate{
		{raw.Metrics.V31, "v3"},
		{raw.Metrics.V30, "v3"},
		{raw.Metrics.V2, "v2"},
	} {
		if len(c.metrics) > 0 {
			d := c.metrics[0].CVSSData
			cve.CVSS = &CVSSData{
				Version:      c.version,
				BaseScore:    d.BaseScore,
				Severity:     strings.ToUpper(d.BaseSeverity),
				VectorString: d.VectorString,
			}
			break
		}
	}

	// References
	for _, r := range raw.References {
		cve.References = append(cve.References, Reference{URL: r.URL, Tags: r.Tags})
	}

	return cve
}
