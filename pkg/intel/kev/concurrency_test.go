package kev

import (
	"sync"
	"testing"
)

// TestRefreshThenConcurrentIsKEV verifies the index is built eagerly so
// concurrent Lookups don't race on lazy initialization (run with -race).
func TestRefreshThenConcurrentIsKEV(t *testing.T) {
	srv := newTestServer(t, 200, Catalog{
		Title: "test",
		Count: 2,
		Vulnerabilities: []*Entry{
			{CVEID: "CVE-2021-44228"},
			{CVEID: "CVE-2014-0160"},
		},
	})
	defer srv.Close()

	catalog, err := Refresh(t.TempDir(), srv.URL)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = catalog.IsKEV("CVE-2021-44228")
			_ = catalog.IsKEV("CVE-0000-0000")
		}()
	}
	wg.Wait()

	if !catalog.IsKEV("CVE-2021-44228") {
		t.Fatal("expected Log4Shell to be KEV")
	}
}
