package risks

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const ruleCacheTTL = 24 * time.Hour

// FetchAndCacheRules downloads a rules archive from rawURL and unpacks it into
// a subdirectory of cacheDir. Returns the local directory path containing .yaml files.
// If a cached copy younger than 24 hours exists it is reused without downloading.
func FetchAndCacheRules(rawURL, cacheDir string) (string, error) {
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(rawURL)))
	localDir := filepath.Join(cacheDir, hash)
	markerFile := filepath.Join(localDir, "fetched_at")

	if info, err := os.Stat(markerFile); err == nil {
		if time.Since(info.ModTime()) < ruleCacheTTL {
			return localDir, nil
		}
	}

	if err := os.MkdirAll(localDir, 0750); err != nil {
		return "", fmt.Errorf("failed to create rules cache dir: %w", err)
	}

	// #nosec G107 -- URL is supplied by the operator via config, not end-user input.
	resp, err := http.Get(rawURL) //nolint:noctx
	if err != nil {
		return "", fmt.Errorf("failed to fetch rules from %q: %w", rawURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected HTTP status fetching rules from %q: %s", rawURL, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read rules response body: %w", err)
	}

	lower := strings.ToLower(rawURL)
	switch {
	case strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz"):
		if err := extractTarGz(bytes.NewReader(body), localDir); err != nil {
			return "", fmt.Errorf("failed to extract tar.gz rules: %w", err)
		}
	case strings.HasSuffix(lower, ".zip"):
		if err := extractZip(body, localDir); err != nil {
			return "", fmt.Errorf("failed to extract zip rules: %w", err)
		}
	default:
		return "", fmt.Errorf("unsupported rules archive format for URL %q (expected .tar.gz, .tgz, or .zip)", rawURL)
	}

	if err := os.WriteFile(markerFile, []byte(time.Now().Format(time.RFC3339)), 0600); err != nil {
		return "", fmt.Errorf("failed to write cache marker: %w", err)
	}

	return localDir, nil
}

func extractTarGz(src io.Reader, destDir string) error {
	gz, err := gzip.NewReader(src)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar entry: %w", err)
		}

		if header.Typeflag == tar.TypeDir {
			continue
		}

		destPath, err := safeJoin(destDir, header.Name)
		if err != nil {
			return err
		}

		if err := os.MkdirAll(filepath.Dir(destPath), 0750); err != nil {
			return fmt.Errorf("failed to create directory for %q: %w", destPath, err)
		}

		f, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600) //nolint:gosec
		if err != nil {
			return fmt.Errorf("failed to create file %q: %w", destPath, err)
		}

		if _, err := io.Copy(f, tr); err != nil { //nolint:gosec
			f.Close()
			return fmt.Errorf("failed to write file %q: %w", destPath, err)
		}
		f.Close()
	}

	return nil
}

func extractZip(src []byte, destDir string) error {
	zr, err := zip.NewReader(bytes.NewReader(src), int64(len(src)))
	if err != nil {
		return fmt.Errorf("failed to open zip: %w", err)
	}

	for _, zf := range zr.File {
		if zf.FileInfo().IsDir() {
			continue
		}

		destPath, err := safeJoin(destDir, zf.Name)
		if err != nil {
			return err
		}

		if err := os.MkdirAll(filepath.Dir(destPath), 0750); err != nil {
			return fmt.Errorf("failed to create directory for %q: %w", destPath, err)
		}

		rc, err := zf.Open()
		if err != nil {
			return fmt.Errorf("failed to open zip entry %q: %w", zf.Name, err)
		}

		f, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600) //nolint:gosec
		if err != nil {
			rc.Close()
			return fmt.Errorf("failed to create file %q: %w", destPath, err)
		}

		if _, err := io.Copy(f, rc); err != nil { //nolint:gosec
			f.Close()
			rc.Close()
			return fmt.Errorf("failed to write zip entry %q: %w", zf.Name, err)
		}
		f.Close()
		rc.Close()
	}

	return nil
}

// safeJoin prevents zip-slip: ensures the resolved path stays within destDir.
func safeJoin(destDir, entryName string) (string, error) {
	abs, err := filepath.Abs(filepath.Join(destDir, filepath.Clean("/"+entryName)))
	if err != nil {
		return "", fmt.Errorf("failed to resolve path for entry %q: %w", entryName, err)
	}

	absBase, err := filepath.Abs(destDir)
	if err != nil {
		return "", fmt.Errorf("failed to resolve base dir: %w", err)
	}

	if !strings.HasPrefix(abs, absBase+string(filepath.Separator)) {
		return "", fmt.Errorf("zip-slip detected: entry %q would escape destination", entryName)
	}

	return abs, nil
}
