package server

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestSeedServerStaticAssetsSeedsEmptyFolder(t *testing.T) {
	serverFolder := t.TempDir()

	seedErr := SeedServerStaticAssets(serverFolder)
	if seedErr != nil {
		t.Fatalf("seeding failed: %v", seedErr)
	}

	seedErr = fs.WalkDir(staticFS, "static", func(path string, dirEntry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if dirEntry.IsDir() {
			return nil
		}
		relPath, relErr := filepath.Rel("static", path)
		if relErr != nil {
			return relErr
		}
		destPath := filepath.Join(serverFolder, "static", relPath)
		wantData, readErr := staticFS.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		gotData, readErr := os.ReadFile(destPath)
		if readErr != nil {
			t.Errorf("seeded file %q missing: %v", destPath, readErr)
			return nil
		}
		if string(gotData) != string(wantData) {
			t.Errorf("seeded file %q differs from embedded content", destPath)
		}
		return nil
	})
	if seedErr != nil {
		t.Fatalf("failed to verify seeded files: %v", seedErr)
	}
}

func TestSeedServerStaticAssetsDoesNotOverwriteExistingFiles(t *testing.T) {
	serverFolder := t.TempDir()
	existingPath := filepath.Join(serverFolder, "static", "index.html")

	existingContent := []byte("DO NOT OVERWRITE")
	if mkDirErr := os.MkdirAll(filepath.Dir(existingPath), 0750); mkDirErr != nil {
		t.Fatalf("failed to create test folder: %v", mkDirErr)
	}
	if writeErr := os.WriteFile(existingPath, existingContent, 0o600); writeErr != nil {
		t.Fatalf("failed to write test file: %v", writeErr)
	}

	seedErr := SeedServerStaticAssets(serverFolder)
	if seedErr != nil {
		t.Fatalf("seeding failed: %v", seedErr)
	}

	gotData, readErr := os.ReadFile(existingPath)
	if readErr != nil {
		t.Fatalf("failed to read pre-existing file: %v", readErr)
	}
	if string(gotData) != string(existingContent) {
		t.Errorf("pre-existing file %q was overwritten: got %q, want %q", existingPath, gotData, existingContent)
	}
}

func TestSeedServerStaticAssetsIsIdempotent(t *testing.T) {
	serverFolder := t.TempDir()

	firstErr := SeedServerStaticAssets(serverFolder)
	if firstErr != nil {
		t.Fatalf("first seeding failed: %v", firstErr)
	}

	secondErr := SeedServerStaticAssets(serverFolder)
	if secondErr != nil {
		t.Fatalf("second seeding failed: %v", secondErr)
	}
}
