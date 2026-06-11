package kev

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func sampleCatalog() *Catalog {
	return &Catalog{
		Title:          "CISA KEV Test",
		CatalogVersion: "2024.01.01",
		DateReleased:   "2024-01-01T00:00:00Z",
		Count:          2,
		Vulnerabilities: []*Entry{
			{CVEID: "CVE-2021-44228", VendorProject: "Apache", Product: "Log4j", VulnerabilityName: "Log4Shell"},
			{CVEID: "CVE-2022-0001", VendorProject: "Acme", Product: "Widget"},
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

func TestRefresh(t *testing.T) {
	srv := newTestServer(t, 200, sampleCatalog())
	defer srv.Close()

	dir := t.TempDir()
	catalog, err := Refresh(dir, srv.URL)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if catalog == nil {
		t.Fatal("expected catalog, got nil")
	}
	if catalog.Count != 2 {
		t.Errorf("Count = %d, want 2", catalog.Count)
	}
}

func TestRefreshHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := Refresh(t.TempDir(), srv.URL)
	if err == nil {
		t.Fatal("expected error on HTTP 500, got nil")
	}
}

func TestRefreshMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("{bad json"))
	}))
	defer srv.Close()

	_, err := Refresh(t.TempDir(), srv.URL)
	if err == nil {
		t.Fatal("expected error on malformed JSON")
	}
}

func TestLookupAndIsKEV(t *testing.T) {
	catalog := sampleCatalog()

	e := catalog.Lookup("CVE-2021-44228")
	if e == nil {
		t.Fatal("expected entry for CVE-2021-44228")
	}
	if e.Product != "Log4j" {
		t.Errorf("Product = %q, want Log4j", e.Product)
	}

	// case-insensitive
	e2 := catalog.Lookup("cve-2021-44228")
	if e2 == nil {
		t.Fatal("case-insensitive lookup failed")
	}

	if !catalog.IsKEV("CVE-2021-44228") {
		t.Error("IsKEV should return true")
	}
	if catalog.IsKEV("CVE-9999-9999") {
		t.Error("IsKEV should return false for unknown CVE")
	}
}

func TestLoad_NoCache(t *testing.T) {
	catalog, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if catalog != nil {
		t.Fatal("expected nil catalog when no cache exists")
	}
}

func TestLoadOrRefresh_UsesCachWhenFresh(t *testing.T) {
	var requestCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		data, _ := json.Marshal(sampleCatalog())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	dir := t.TempDir()
	// First call populates cache
	_, err := Refresh(dir, srv.URL)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got := atomic.LoadInt32(&requestCount); got != 1 {
		t.Fatalf("requests after Refresh = %d, want 1", got)
	}

	// Second call should use the fresh cache and make no additional HTTP requests.
	catalog, err := LoadOrRefresh(dir, srv.URL, 24*time.Hour)
	if err != nil {
		t.Fatalf("LoadOrRefresh: %v", err)
	}
	if catalog == nil {
		t.Fatal("expected catalog")
	}
	if got := atomic.LoadInt32(&requestCount); got != 1 {
		t.Fatalf("requests after LoadOrRefresh with fresh cache = %d, want 1 (no extra network call)", got)
	}
}

func TestLoadOrRefresh_RefreshesWhenStale(t *testing.T) {
	srv := newTestServer(t, 200, sampleCatalog())
	defer srv.Close()

	dir := t.TempDir()
	// Populate cache
	_, err := Refresh(dir, srv.URL)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	// Use a TTL that is already expired (1 ns) to force refresh
	catalog, err := LoadOrRefresh(dir, srv.URL, time.Nanosecond)
	if err != nil {
		t.Fatalf("LoadOrRefresh stale: %v", err)
	}
	if catalog == nil {
		t.Fatal("expected catalog after refresh")
	}
}
