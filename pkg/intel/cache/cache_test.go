package cache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	payload := map[string]string{"key": "value"}

	if err := Save(dir, "test", "http://example.com", payload); err != nil {
		t.Fatalf("Save: %v", err)
	}

	entry, err := Load(dir, "test")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if entry == nil {
		t.Fatal("expected entry, got nil")
	}
	if entry.Source != "http://example.com" {
		t.Errorf("Source = %q, want %q", entry.Source, "http://example.com")
	}

	var out map[string]string
	if err := json.Unmarshal(entry.Payload, &out); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if out["key"] != "value" {
		t.Errorf("payload key = %q, want %q", out["key"], "value")
	}
}

func TestLoadMissing(t *testing.T) {
	dir := t.TempDir()
	entry, err := Load(dir, "nonexistent")
	if err != nil {
		t.Fatalf("Load: unexpected error: %v", err)
	}
	if entry != nil {
		t.Fatal("expected nil entry for missing file")
	}
}

func TestLoadCorrupt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("not-json{{{"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(dir, "bad")
	if err == nil {
		t.Fatal("expected error for corrupt cache file")
	}
}

func TestIsFresh(t *testing.T) {
	e := &Entry{FetchedAt: time.Now().UTC()}
	if !e.IsFresh(time.Hour) {
		t.Error("expected fresh entry to be fresh")
	}

	old := &Entry{FetchedAt: time.Now().UTC().Add(-2 * time.Hour)}
	if old.IsFresh(time.Hour) {
		t.Error("expected stale entry to not be fresh")
	}
}

func TestAge(t *testing.T) {
	if Age(nil) != 0 {
		t.Error("Age(nil) should be 0")
	}
	e := &Entry{FetchedAt: time.Now().UTC().Add(-5 * time.Minute)}
	age := Age(e)
	if age < 4*time.Minute || age > 6*time.Minute {
		t.Errorf("Age unexpected: %v", age)
	}
}

func TestDefaultCacheDir(t *testing.T) {
	dir := DefaultCacheDir()
	if dir == "" {
		t.Error("DefaultCacheDir returned empty string")
	}
}
