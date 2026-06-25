package epss

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestFetchBatchChunks proves >100 CVEs are split into multiple requests (so the
// URL never overflows) and the per-chunk results are merged.
func TestFetchBatchChunks(t *testing.T) {
	var requests int32
	var oversized int32 // set if any chunk exceeded maxBatchSize

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		cves := strings.Split(r.URL.Query().Get("cve"), ",")
		if len(cves) > maxBatchSize {
			atomic.StoreInt32(&oversized, 1)
		}
		var data []*Score
		for _, c := range cves {
			data = append(data, &Score{CVE: c, EPSS: 0.5, Percentile: 0.5})
		}
		_ = json.NewEncoder(w).Encode(sampleResponse(data))
	}))
	defer srv.Close()

	// 250 CVEs -> 3 chunks of 100/100/50.
	var ids []string
	for i := 0; i < 250; i++ {
		ids = append(ids, fmt.Sprintf("CVE-2024-%04d", i))
	}

	scores, err := FetchBatch(ids, srv.URL)
	if err != nil {
		t.Fatalf("FetchBatch: %v", err)
	}
	if got := atomic.LoadInt32(&requests); got != 3 {
		t.Fatalf("expected 3 chunked requests, got %d", got)
	}
	if atomic.LoadInt32(&oversized) != 0 {
		t.Fatal("a chunk exceeded maxBatchSize")
	}
	if len(scores) != 250 {
		t.Fatalf("expected 250 merged scores, got %d", len(scores))
	}
}

func TestFetchBatchEmpty(t *testing.T) {
	scores, err := FetchBatch(nil, "")
	if err != nil || len(scores) != 0 {
		t.Fatalf("empty batch should be a no-op: %v / %d", err, len(scores))
	}
}
