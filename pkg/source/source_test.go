package source

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEntityLinesFollowsIncludesAndKeysByTitleAndID(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "feature.yaml"),
		[]byte("technical_assets:\n  API Server:\n    id: api-server\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "threagile.yaml"),
		[]byte("title: T\nincludes:\n  - feature.yaml\n"), 0600); err != nil {
		t.Fatal(err)
	}

	locs := EntityLines(filepath.Join(dir, "threagile.yaml"))

	byTitle, okTitle := locs["API Server"]
	byID, okID := locs["api-server"]
	if !okTitle || !okID {
		t.Fatalf("want both title and id keys, got %v", locs)
	}
	if byTitle.File != "feature.yaml" || byTitle.Line != 2 {
		t.Errorf("title loc wrong: %+v (want feature.yaml:2)", byTitle)
	}
	if byID != byTitle {
		t.Errorf("id and title should resolve to the same location: %+v vs %+v", byID, byTitle)
	}
	if got := byTitle.String(); got != "feature.yaml:2" {
		t.Errorf("String() = %q, want feature.yaml:2", got)
	}
}

func TestEntityLinesSingleFileHasNoFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "threagile.yaml"),
		[]byte("title: T\ntechnical_assets:\n  Lonely:\n    id: lonely\n"), 0600); err != nil {
		t.Fatal(err)
	}
	locs := EntityLines(filepath.Join(dir, "threagile.yaml"))
	l, ok := locs["Lonely"]
	if !ok || l.File != "" || l.Line != 3 {
		t.Fatalf("single-file loc wrong: %+v ok=%v (want File:'' Line:3)", l, ok)
	}
	if got := l.String(); got != "line 3" {
		t.Errorf("String() = %q, want 'line 3'", got)
	}
}

func TestEntityLinesMissingFileIsEmpty(t *testing.T) {
	if locs := EntityLines("/no/such/model.yaml"); len(locs) != 0 {
		t.Errorf("expected empty map for missing file, got %v", locs)
	}
}
