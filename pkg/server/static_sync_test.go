package server

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestStaticAssetsInSyncWithCanonical is a drift guard: every file embedded
// in the binary must be byte-identical to the canonical copy in the
// repository under server/static (which the Docker build ships). If this
// test fails, re-copy server/static into pkg/server/static:
//
//	cp -a server/static/. pkg/server/static/
func TestStaticAssetsInSyncWithCanonical(t *testing.T) {
	embeddedPaths := make(map[string][]byte)
	walkErr := fs.WalkDir(staticFS, "static", func(path string, dirEntry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if dirEntry.IsDir() {
			return nil
		}
		data, readErr := staticFS.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		embeddedPaths[path] = data
		return nil
	})
	if walkErr != nil {
		t.Fatalf("failed to walk embedded static assets: %v", walkErr)
	}

	if len(embeddedPaths) == 0 {
		t.Fatal("no embedded static assets found — pkg/server/static is empty")
	}

	for path, embeddedData := range embeddedPaths {
		canonicalPath := filepath.Join("..", "..", "server", filepath.FromSlash(path))
		canonicalData, readErr := os.ReadFile(canonicalPath)
		if readErr != nil {
			t.Errorf("canonical file %q missing or unreadable: %v — re-copy server/static into pkg/server/static", canonicalPath, readErr)
			continue
		}
		if !bytes.Equal(embeddedData, canonicalData) {
			t.Errorf("embedded static asset %q drifted from canonical %q — re-copy server/static into pkg/server/static", path, canonicalPath)
		}
	}

	// Also assert the reverse: no extra (or removed) files on the canonical side.
	canonicalRoot := filepath.Join("..", "..", "server", "static")
	walkErr = filepath.WalkDir(canonicalRoot, func(path string, dirEntry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if dirEntry.IsDir() {
			return nil
		}
		relPath, relErr := filepath.Rel(canonicalRoot, path)
		if relErr != nil {
			return relErr
		}
		embeddedPath := filepath.ToSlash(filepath.Join("static", relPath))
		if _, ok := embeddedPaths[embeddedPath]; !ok {
			t.Errorf("canonical static file %q is not embedded — re-copy server/static into pkg/server/static", path)
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("failed to walk canonical static folder %q: %v", canonicalRoot, walkErr)
	}
}
