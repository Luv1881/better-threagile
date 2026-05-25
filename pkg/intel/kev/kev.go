// Package kev provides access to the CISA Known Exploited Vulnerabilities (KEV) catalog.
// The catalog is a free, daily-updated JSON feed listing CVEs confirmed exploited in the wild.
// Reference: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
//
// Usage:
//
//	catalog, err := kev.Load(cacheDir)            // load from cache (no network)
//	catalog, err := kev.Refresh(cacheDir, "")     // download and cache
//	entry, found := catalog.Lookup("CVE-2021-44228")
package kev

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/threagile/threagile/pkg/intel/cache"
)

const (
	DefaultFeedURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	CacheName      = "kev"
	DefaultTTL     = 24 * time.Hour
)

// Entry is a single KEV catalog entry.
type Entry struct {
	CVEID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	ShortDescription  string `json:"shortDescription"`
	RequiredAction    string `json:"requiredAction"`
	DueDate           string `json:"dueDate"`
	KnownRansomware   string `json:"knownRansomwareCampaignUse"`
}

// Catalog is the full KEV dataset indexed by CVE ID.
type Catalog struct {
	Title          string           `json:"title"`
	CatalogVersion string           `json:"catalogVersion"`
	DateReleased   string           `json:"dateReleased"`
	Count          int              `json:"count"`
	Vulnerabilities []*Entry        `json:"vulnerabilities"`
	index          map[string]*Entry // built on first Lookup call
}

// Lookup returns the KEV entry for the given CVE ID (case-insensitive), or nil if not found.
func (c *Catalog) Lookup(cveID string) *Entry {
	if c.index == nil {
		c.buildIndex()
	}
	return c.index[strings.ToUpper(cveID)]
}

// IsKEV returns true if the CVE ID is in the catalog.
func (c *Catalog) IsKEV(cveID string) bool {
	return c.Lookup(cveID) != nil
}

func (c *Catalog) buildIndex() {
	c.index = make(map[string]*Entry, len(c.Vulnerabilities))
	for _, v := range c.Vulnerabilities {
		c.index[strings.ToUpper(v.CVEID)] = v
	}
}

// Load loads the KEV catalog from the local cache. Returns (nil, nil) if no cache exists.
func Load(cacheDir string) (*Catalog, error) {
	entry, err := cache.Load(cacheDir, CacheName)
	if err != nil {
		return nil, fmt.Errorf("kev: %w", err)
	}
	if entry == nil {
		return nil, nil
	}
	var catalog Catalog
	if err := json.Unmarshal(entry.Payload, &catalog); err != nil {
		return nil, fmt.Errorf("kev: failed to parse cached catalog: %w", err)
	}
	return &catalog, nil
}

// Refresh downloads the KEV catalog, stores it in the cache, and returns it.
// If feedURL is empty, DefaultFeedURL is used.
func Refresh(cacheDir, feedURL string) (*Catalog, error) {
	if feedURL == "" {
		feedURL = DefaultFeedURL
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(feedURL) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("kev: failed to download catalog from %s: %w", feedURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kev: unexpected HTTP status %d from %s", resp.StatusCode, feedURL)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("kev: failed to read response body: %w", err)
	}

	var catalog Catalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("kev: failed to parse catalog JSON: %w", err)
	}

	if err := cache.Save(cacheDir, CacheName, feedURL, &catalog); err != nil {
		return nil, fmt.Errorf("kev: failed to cache catalog: %w", err)
	}

	return &catalog, nil
}

// LoadOrRefresh loads from cache if fresh (< ttl), otherwise refreshes.
// If ttl is 0, DefaultTTL is used.
func LoadOrRefresh(cacheDir, feedURL string, ttl time.Duration) (*Catalog, error) {
	if ttl == 0 {
		ttl = DefaultTTL
	}

	entry, err := cache.Load(cacheDir, CacheName)
	if err != nil {
		return nil, fmt.Errorf("kev: %w", err)
	}

	if entry != nil && entry.IsFresh(ttl) {
		var catalog Catalog
		if err := json.Unmarshal(entry.Payload, &catalog); err == nil {
			return &catalog, nil
		}
	}

	return Refresh(cacheDir, feedURL)
}
