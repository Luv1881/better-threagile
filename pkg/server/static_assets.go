package server

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// staticFS embeds the static assets served by the web UI. The canonical copy
// of these files lives in the repository under server/static (referenced by
// the Docker build); the embedded copy is a snapshot kept in sync by the
// drift guard in static_sync_test.go.
//
//go:embed static
var staticFS embed.FS

// SeedServerStaticAssets writes every embedded static asset that is missing
// under <serverFolder>/static to disk. Existing files are never overwritten,
// so Docker layouts and custom --server-dir deployments keep whatever is
// already on disk. Missing parent directories are created with 0750, files
// are written with 0644. It is safe (and cheap) to call on every server
// start, including when the folder already exists.
func SeedServerStaticAssets(serverFolder string) error {
	return fs.WalkDir(staticFS, "static", func(path string, dirEntry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("failed to walk embedded static assets: %w", walkErr)
		}
		if dirEntry.IsDir() {
			return nil
		}

		// embed paths are always slash-separated, so strip the prefix here and
		// convert to the OS separator only when building the destination path
		relPath := strings.TrimPrefix(path, "static/")
		if relPath == path || strings.HasPrefix(relPath, "..") {
			return fmt.Errorf("embedded static asset %q has an unexpected path", path)
		}

		destPath := filepath.Join(serverFolder, "static", filepath.FromSlash(relPath))
		// Lstat instead of Stat: a symlink must never be written through,
		// so anything that already exists (file, dir, link) is left untouched.
		if _, lstatErr := os.Lstat(destPath); lstatErr == nil {
			return nil // never overwrite existing files
		} else if !os.IsNotExist(lstatErr) {
			return fmt.Errorf("failed to check static asset %q: %w", destPath, lstatErr)
		}

		data, readErr := staticFS.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("failed to read embedded static asset %q: %w", path, readErr)
		}

		if mkDirErr := os.MkdirAll(filepath.Dir(destPath), 0750); mkDirErr != nil {
			return fmt.Errorf("failed to create static asset folder %q: %w", filepath.Dir(destPath), mkDirErr)
		}
		// write to a temporary file first and rename into place, so a
		// concurrent reader never sees a half-written file
		tmpFile, tmpErr := os.CreateTemp(filepath.Dir(destPath), ".seed-*")
		if tmpErr != nil {
			return fmt.Errorf("failed to create temporary file for static asset %q: %w", destPath, tmpErr)
		}
		if _, writeErr := tmpFile.Write(data); writeErr != nil {
			_ = tmpFile.Close()
			_ = os.Remove(tmpFile.Name())
			return fmt.Errorf("failed to write static asset %q: %w", destPath, writeErr)
		}
		if closeErr := tmpFile.Close(); closeErr != nil {
			_ = os.Remove(tmpFile.Name())
			return fmt.Errorf("failed to close static asset %q: %w", destPath, closeErr)
		}
		// #nosec G302 -- static web assets are intentionally world-readable (same
		// 0644 as the Docker-shipped copies); they contain no secrets
		if chmodErr := os.Chmod(tmpFile.Name(), 0644); chmodErr != nil {
			_ = os.Remove(tmpFile.Name())
			return fmt.Errorf("failed to set permissions on static asset %q: %w", destPath, chmodErr)
		}
		if renameErr := os.Rename(tmpFile.Name(), destPath); renameErr != nil {
			_ = os.Remove(tmpFile.Name())
			return fmt.Errorf("failed to rename static asset %q: %w", destPath, renameErr)
		}
		return nil
	})
}
