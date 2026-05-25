// Package cache provides a simple file-based cache for threat-intel feed data.
// Each feed is stored as a single JSON file under CacheDir.
// Files older than the configured TTL are considered stale and trigger a refresh.
package cache

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// DefaultCacheDir returns the default cache directory (~/.config/threagile/intel).
func DefaultCacheDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config", "threagile", "intel")
	}
	return filepath.Join(os.TempDir(), "threagile-intel")
}

// Entry wraps a cached payload with metadata.
type Entry struct {
	FetchedAt time.Time       `json:"fetched_at"`
	Source    string          `json:"source"`
	Payload   json.RawMessage `json:"payload"`
}

// IsFresh returns true if the entry is younger than ttl.
func (e *Entry) IsFresh(ttl time.Duration) bool {
	return time.Since(e.FetchedAt) < ttl
}

// Load reads a cached entry from cacheDir/name.json.
// Returns (nil, nil) if the file does not exist.
func Load(cacheDir, name string) (*Entry, error) {
	path := filepath.Join(cacheDir, name+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("cache: failed to read %s: %w", path, err)
	}
	var entry Entry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("cache: failed to parse %s: %w", path, err)
	}
	return &entry, nil
}

// Save writes an entry to cacheDir/name.json, creating the directory if needed.
func Save(cacheDir, name, source string, payload any) error {
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return fmt.Errorf("cache: failed to create dir %s: %w", cacheDir, err)
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("cache: failed to marshal payload: %w", err)
	}

	entry := Entry{
		FetchedAt: time.Now().UTC(),
		Source:    source,
		Payload:   payloadBytes,
	}

	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return fmt.Errorf("cache: failed to marshal entry: %w", err)
	}

	path := filepath.Join(cacheDir, name+".json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("cache: failed to write %s: %w", path, err)
	}
	return nil
}

// Age returns how old the cached entry is. Returns a zero duration if nil.
func Age(e *Entry) time.Duration {
	if e == nil {
		return 0
	}
	return time.Since(e.FetchedAt)
}
