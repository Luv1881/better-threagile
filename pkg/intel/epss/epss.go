// Package epss provides access to EPSS (Exploit Prediction Scoring System) scores.
// EPSS is a community-driven effort to estimate the probability that a CVE will be
// exploited in the wild within the next 30 days (0.0–1.0 probability).
// Reference: https://www.first.org/epss/
//
// The EPSS API endpoint provides per-CVE scores in JSON format.
//
// Usage:
//
//	score, err := epss.FetchScore("CVE-2021-44228", "")  // always fetches from API
//	scores, err := epss.LoadOrRefreshBatch(cveIDs, cacheDir, "")
package epss

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/threagile/threagile/pkg/intel/cache"
)

const (
	DefaultAPIBase = "https://api.first.org/data/v1/epss"
	CacheName      = "epss"
	DefaultTTL     = 24 * time.Hour
)

// Score is the EPSS score for a single CVE.
type Score struct {
	CVE        string  `json:"cve"`
	EPSS       float64 `json:"epss,string"` // probability 0.0–1.0
	Percentile float64 `json:"percentile,string"` // relative rank 0.0–1.0
	Date       string  `json:"date"`
}

// ScoreMap maps CVE IDs to their EPSS scores.
type ScoreMap map[string]*Score

// Get returns the EPSS score for a CVE ID (case-insensitive).
func (m ScoreMap) Get(cveID string) *Score {
	return m[strings.ToUpper(cveID)]
}

// EPSSResponse is the top-level EPSS API response.
type EPSSResponse struct {
	Status     string   `json:"status"`
	StatusCode int      `json:"status-code"`
	Data       []*Score `json:"data"`
	Total      int      `json:"total"`
}

// FetchScore fetches the EPSS score for a single CVE from the API.
// If apiBase is empty, DefaultAPIBase is used.
func FetchScore(cveID, apiBase string) (*Score, error) {
	if apiBase == "" {
		apiBase = DefaultAPIBase
	}

	reqURL := apiBase + "?cve=" + url.QueryEscape(cveID)
	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Get(reqURL) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("epss: failed to fetch score for %s: %w", cveID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // CVE not in EPSS database
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("epss: unexpected HTTP status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("epss: failed to read response: %w", err)
	}

	var result EPSSResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("epss: failed to parse response: %w", err)
	}

	if len(result.Data) == 0 {
		return nil, nil
	}
	return result.Data[0], nil
}

// FetchBatch fetches EPSS scores for up to 100 CVEs in a single API call.
// Returns a ScoreMap. CVEs not found in EPSS are absent from the map.
func FetchBatch(cveIDs []string, apiBase string) (ScoreMap, error) {
	if len(cveIDs) == 0 {
		return ScoreMap{}, nil
	}
	if apiBase == "" {
		apiBase = DefaultAPIBase
	}

	// API supports comma-separated CVE list
	reqURL := apiBase + "?cve=" + url.QueryEscape(strings.Join(cveIDs, ","))
	client := &http.Client{Timeout: 20 * time.Second}

	resp, err := client.Get(reqURL) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("epss: batch fetch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("epss: unexpected HTTP status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("epss: failed to read batch response: %w", err)
	}

	var result EPSSResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("epss: failed to parse batch response: %w", err)
	}

	scores := make(ScoreMap, len(result.Data))
	for _, s := range result.Data {
		scores[strings.ToUpper(s.CVE)] = s
	}
	return scores, nil
}

// LoadCached loads the cached EPSS score map. Returns (nil, nil) if no cache exists.
func LoadCached(cacheDir string) (ScoreMap, error) {
	entry, err := cache.Load(cacheDir, CacheName)
	if err != nil {
		return nil, fmt.Errorf("epss: %w", err)
	}
	if entry == nil {
		return nil, nil
	}
	var scores ScoreMap
	if err := json.Unmarshal(entry.Payload, &scores); err != nil {
		return nil, fmt.Errorf("epss: failed to parse cached scores: %w", err)
	}
	return scores, nil
}

// SaveCached saves a ScoreMap to the cache.
func SaveCached(cacheDir string, scores ScoreMap) error {
	return cache.Save(cacheDir, CacheName, DefaultAPIBase, scores)
}
