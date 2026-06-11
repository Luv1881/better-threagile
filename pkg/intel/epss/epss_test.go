package epss

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func sampleResponse(scores []*Score) EPSSResponse {
	return EPSSResponse{
		Status:     "OK",
		StatusCode: 200,
		Data:       scores,
		Total:      len(scores),
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

func TestFetchScore(t *testing.T) {
	score := &Score{CVE: "CVE-2021-44228", EPSS: 0.974, Percentile: 0.999}
	srv := newTestServer(t, 200, sampleResponse([]*Score{score}))
	defer srv.Close()

	result, err := FetchScore("CVE-2021-44228", srv.URL)
	if err != nil {
		t.Fatalf("FetchScore: %v", err)
	}
	if result == nil {
		t.Fatal("expected score, got nil")
	}
	if result.EPSS != 0.974 {
		t.Errorf("EPSS = %v, want 0.974", result.EPSS)
	}
}

func TestFetchScore_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	result, err := FetchScore("CVE-9999-9999", srv.URL)
	if err != nil {
		t.Fatalf("unexpected error on 404: %v", err)
	}
	if result != nil {
		t.Fatal("expected nil score on 404")
	}
}

func TestFetchScore_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	_, err := FetchScore("CVE-2021-44228", srv.URL)
	if err == nil {
		t.Fatal("expected error on HTTP 503")
	}
}

func TestFetchScore_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("{bad"))
	}))
	defer srv.Close()

	_, err := FetchScore("CVE-2021-44228", srv.URL)
	if err == nil {
		t.Fatal("expected error on malformed JSON")
	}
}

func TestFetchScore_EmptyData(t *testing.T) {
	srv := newTestServer(t, 200, sampleResponse([]*Score{}))
	defer srv.Close()

	result, err := FetchScore("CVE-2021-44228", srv.URL)
	if err != nil {
		t.Fatalf("FetchScore: %v", err)
	}
	if result != nil {
		t.Fatal("expected nil for empty data array")
	}
}

func TestFetchBatch(t *testing.T) {
	scores := []*Score{
		{CVE: "CVE-2021-44228", EPSS: 0.974},
		{CVE: "CVE-2022-0001", EPSS: 0.1},
	}
	srv := newTestServer(t, 200, sampleResponse(scores))
	defer srv.Close()

	result, err := FetchBatch([]string{"CVE-2021-44228", "CVE-2022-0001"}, srv.URL)
	if err != nil {
		t.Fatalf("FetchBatch: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("len = %d, want 2", len(result))
	}
}

func TestFetchBatch_Empty(t *testing.T) {
	result, err := FetchBatch(nil, "")
	if err != nil {
		t.Fatalf("FetchBatch empty: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty map, got %d entries", len(result))
	}
}

func TestScoreMapGet(t *testing.T) {
	m := ScoreMap{
		"CVE-2021-44228": {CVE: "CVE-2021-44228", EPSS: 0.974},
	}
	// uppercase key
	if m.Get("CVE-2021-44228") == nil {
		t.Error("Get uppercase failed")
	}
	// lowercase key — ScoreMap.Get uppercases internally
	if m.Get("cve-2021-44228") == nil {
		t.Error("Get lowercase failed")
	}
	if m.Get("CVE-9999-0000") != nil {
		t.Error("Get unknown should return nil")
	}
}

func TestSaveAndLoadCached(t *testing.T) {
	dir := t.TempDir()
	scores := ScoreMap{
		"CVE-2021-44228": {CVE: "CVE-2021-44228", EPSS: 0.974},
	}

	if err := SaveCached(dir, scores); err != nil {
		t.Fatalf("SaveCached: %v", err)
	}

	loaded, err := LoadCached(dir)
	if err != nil {
		t.Fatalf("LoadCached: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected non-nil map")
	}
	if loaded["CVE-2021-44228"] == nil {
		t.Error("expected CVE entry after round-trip")
	}
}

func TestLoadCached_NoCache(t *testing.T) {
	result, err := LoadCached(t.TempDir())
	if err != nil {
		t.Fatalf("LoadCached empty dir: %v", err)
	}
	if result != nil {
		t.Fatal("expected nil for empty cache")
	}
}
