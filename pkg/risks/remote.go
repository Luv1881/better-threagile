package risks

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const ruleCacheTTL = 24 * time.Hour

// maxDownloadBytes caps the raw archive download to 100 MiB to prevent OOM from a runaway server.
const maxDownloadBytes = 100 * 1024 * 1024

// maxExtractBytes caps total bytes written during extraction to 500 MiB to prevent decompression bombs.
const maxExtractBytes = 500 * 1024 * 1024

var httpClient = &http.Client{Timeout: 60 * time.Second}

// FetchOptions controls fetching behavior for rule archives.
type FetchOptions struct {
	// TrustedKeys is the list of trusted Ed25519 public keys (base64-encoded, 32 bytes each)
	// used to verify .sig sidecar signatures.
	TrustedKeys []string
	// RequireSigned, when true, rejects any archive that does not have a valid signature
	// from one of TrustedKeys.
	RequireSigned bool
}

// FetchAndCacheRules downloads a rules archive from rawURL and unpacks it into a
// subdirectory of cacheDir. The URL may carry the following fragment hints:
//   - #sha256=<hex>   — verify the archive's SHA256 matches before extraction
//   - #ttl=24h        — override the default 24h cache lifetime
//
// If the URL has a sibling <URL>.sig file and TrustedKeys are configured,
// the signature is verified before extraction.
func FetchAndCacheRules(rawURL, cacheDir string) (string, error) {
	return FetchAndCacheRulesWithOptions(rawURL, cacheDir, FetchOptions{})
}

// FetchAndCacheRuleSources fetches and caches each configured rules archive.
func FetchAndCacheRuleSources(rawURLs []string, cacheDir string, opts FetchOptions) ([]string, error) {
	localDirs := make([]string, 0, len(rawURLs))
	for _, rawURL := range rawURLs {
		rawURL = strings.TrimSpace(rawURL)
		if rawURL == "" || strings.HasPrefix(rawURL, "#") {
			continue
		}
		localDir, err := FetchAndCacheRulesWithOptions(rawURL, cacheDir, opts)
		if err != nil {
			return localDirs, err
		}
		localDirs = append(localDirs, localDir)
	}
	return localDirs, nil
}

// ReadRulesURLFile reads a newline-delimited list of rules archive URLs.
// Blank lines and lines starting with "#" are ignored.
func ReadRulesURLFile(filename string) ([]string, error) {
	data, err := os.ReadFile(filepath.Clean(filename))
	if err != nil {
		return nil, fmt.Errorf("failed to read rules URL file %q: %w", filename, err)
	}
	urls := make([]string, 0)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		urls = append(urls, line)
	}
	return urls, nil
}

func FetchAndCacheRulesWithOptions(rawURL, cacheDir string, opts FetchOptions) (string, error) {
	expectedSHA, ttl, cleanURL, err := parseFetchURL(rawURL)
	if err != nil {
		return "", err
	}

	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(cleanURL)))
	localDir := filepath.Join(cacheDir, hash)
	markerFile := filepath.Join(localDir, "fetched_at")

	if info, statErr := os.Stat(markerFile); statErr == nil {
		if time.Since(info.ModTime()) < ttl {
			return localDir, nil
		}
	}

	if err := os.MkdirAll(localDir, 0750); err != nil {
		return "", fmt.Errorf("failed to create rules cache dir: %w", err)
	}

	body, err := httpGet(cleanURL)
	if err != nil {
		return "", err
	}

	if expectedSHA != "" {
		actual := fmt.Sprintf("%x", sha256.Sum256(body))
		if !strings.EqualFold(actual, expectedSHA) {
			return "", fmt.Errorf("sha256 mismatch for %q: expected %s, got %s", cleanURL, expectedSHA, actual)
		}
	}

	// Signature verification
	if opts.RequireSigned || len(opts.TrustedKeys) > 0 {
		sigBody, sigErr := httpGet(cleanURL + ".sig")
		if sigErr != nil {
			if opts.RequireSigned {
				return "", fmt.Errorf("signature required but .sig fetch failed for %q: %w", cleanURL, sigErr)
			}
		} else {
			if verifyErr := verifyEd25519Signature(body, sigBody, opts.TrustedKeys); verifyErr != nil {
				return "", fmt.Errorf("signature verification failed for %q: %w", cleanURL, verifyErr)
			}
		}
	}

	if err := extractArchive(cleanURL, body, localDir); err != nil {
		return "", err
	}

	if err := os.WriteFile(markerFile, []byte(time.Now().Format(time.RFC3339)), 0600); err != nil {
		return "", fmt.Errorf("failed to write cache marker: %w", err)
	}

	return localDir, nil
}

func httpGet(rawURL string) ([]byte, error) {
	// #nosec G107 -- URL is supplied by the operator via config, not end-user input.
	resp, err := httpClient.Get(rawURL) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %q: %w", rawURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status fetching %q: %s", rawURL, resp.Status)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDownloadBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body for %q: %w", rawURL, err)
	}
	if int64(len(data)) > maxDownloadBytes {
		return nil, fmt.Errorf("rules archive at %q exceeds maximum download size (%d MiB)", rawURL, maxDownloadBytes/(1024*1024))
	}
	return data, nil
}

// parseFetchURL extracts SHA256 and TTL hints from URL fragment.
// Returns expectedSHA (hex, empty if unset), TTL duration, the URL without fragment, and any error.
func parseFetchURL(rawURL string) (expectedSHA string, ttl time.Duration, cleanURL string, err error) {
	ttl = ruleCacheTTL

	u, parseErr := url.Parse(rawURL)
	if parseErr != nil {
		return "", ttl, rawURL, fmt.Errorf("invalid URL %q: %w", rawURL, parseErr)
	}

	if u.Fragment == "" {
		cleanURL = rawURL
		return "", ttl, cleanURL, nil
	}

	// Parse fragment as key=value pairs separated by &
	for _, part := range strings.Split(u.Fragment, "&") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key, val := strings.ToLower(kv[0]), kv[1]
		switch key {
		case "sha256":
			if _, decodeErr := hex.DecodeString(val); decodeErr != nil {
				return "", ttl, rawURL, fmt.Errorf("invalid sha256 hex in URL fragment: %w", decodeErr)
			}
			expectedSHA = val
		case "ttl":
			d, dErr := time.ParseDuration(val)
			if dErr != nil {
				return "", ttl, rawURL, fmt.Errorf("invalid ttl in URL fragment: %w", dErr)
			}
			ttl = d
		}
	}

	u.Fragment = ""
	cleanURL = u.String()
	return expectedSHA, ttl, cleanURL, nil
}

func extractArchive(cleanURL string, body []byte, destDir string) error {
	lower := strings.ToLower(cleanURL)
	switch {
	case strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz"):
		if err := extractTarGz(bytes.NewReader(body), destDir); err != nil {
			return fmt.Errorf("failed to extract tar.gz rules: %w", err)
		}
	case strings.HasSuffix(lower, ".zip"):
		if err := extractZip(body, destDir); err != nil {
			return fmt.Errorf("failed to extract zip rules: %w", err)
		}
	default:
		return fmt.Errorf("unsupported rules archive format for URL %q (expected .tar.gz, .tgz, or .zip)", cleanURL)
	}
	return nil
}

// verifyEd25519Signature verifies that a sigBody (base64-encoded Ed25519 signature) is a
// valid signature over data made by any of the trusted public keys (base64-encoded, 32 bytes).
// Comment lines (starting with "untrusted comment:" or "#") are skipped — this is
// minisign-legacy-compatible for plain Ed25519 signatures.
func verifyEd25519Signature(data, sigBody []byte, trustedKeys []string) error {
	if len(trustedKeys) == 0 {
		return fmt.Errorf("no trusted keys configured")
	}

	rawSig, err := extractBase64Block(sigBody)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}
	if len(rawSig) != ed25519.SignatureSize {
		// minisign signatures are prefixed with a 2-byte algorithm marker + 8-byte key ID
		// (total 74 bytes); strip them if present.
		if len(rawSig) == ed25519.SignatureSize+10 {
			rawSig = rawSig[10:]
		} else {
			return fmt.Errorf("unexpected signature length %d (expected %d)", len(rawSig), ed25519.SignatureSize)
		}
	}

	for _, keyB64 := range trustedKeys {
		keyBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(keyB64))
		if err != nil {
			continue
		}
		// minisign public keys may also be prefixed; strip if necessary.
		if len(keyBytes) == ed25519.PublicKeySize+10 {
			keyBytes = keyBytes[10:]
		}
		if len(keyBytes) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(keyBytes), data, rawSig) {
			return nil
		}
	}

	return fmt.Errorf("no trusted key matched the signature")
}

// extractBase64Block finds the first non-comment, non-empty line of base64 in body.
func extractBase64Block(body []byte) ([]byte, error) {
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") ||
			strings.HasPrefix(strings.ToLower(line), "untrusted comment:") ||
			strings.HasPrefix(strings.ToLower(line), "trusted comment:") {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(line)
		if err == nil {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("no base64 signature block found")
}

func extractTarGz(src io.Reader, destDir string) error {
	gz, err := gzip.NewReader(src)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gz.Close()

	var totalExtracted int64
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

		remaining := maxExtractBytes - totalExtracted
		n, copyErr := io.Copy(f, io.LimitReader(tr, remaining+1)) //nolint:gosec
		f.Close()
		if copyErr != nil {
			return fmt.Errorf("failed to write file %q: %w", destPath, copyErr)
		}
		totalExtracted += n
		if totalExtracted > maxExtractBytes {
			return fmt.Errorf("rules archive extraction exceeded maximum size (%d MiB); possible decompression bomb", maxExtractBytes/(1024*1024))
		}
	}

	return nil
}

func extractZip(src []byte, destDir string) error {
	zr, err := zip.NewReader(bytes.NewReader(src), int64(len(src)))
	if err != nil {
		return fmt.Errorf("failed to open zip: %w", err)
	}

	var totalExtracted int64
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

		remaining := maxExtractBytes - totalExtracted
		n, copyErr := io.Copy(f, io.LimitReader(rc, remaining+1)) //nolint:gosec
		f.Close()
		rc.Close()
		if copyErr != nil {
			return fmt.Errorf("failed to write zip entry %q: %w", zf.Name, copyErr)
		}
		totalExtracted += n
		if totalExtracted > maxExtractBytes {
			return fmt.Errorf("rules archive extraction exceeded maximum size (%d MiB); possible decompression bomb", maxExtractBytes/(1024*1024))
		}
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
