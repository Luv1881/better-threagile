// Package bootstrap provides zero-config onboarding: it scans a repository for
// infrastructure-as-code it understands (docker-compose, Kubernetes manifests,
// OpenAPI specs) and assembles a starter threat model from what already exists,
// so a team doesn't have to hand-transcribe their architecture to get started.
//
// It is deterministic and uses no AI. Detection and model assembly are pure
// functions of the filesystem contents, so results are reproducible.
package bootstrap

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/threagile/threagile/pkg/import/compose"
	"github.com/threagile/threagile/pkg/import/kubernetes"
	"github.com/threagile/threagile/pkg/import/openapi"
	"github.com/threagile/threagile/pkg/types"
)

// Kind identifies a detected infrastructure source.
type Kind string

const (
	Compose    Kind = "compose"
	Kubernetes Kind = "kubernetes"
	OpenAPI    Kind = "openapi"
	Terraform  Kind = "terraform"
)

// Source is one detected infrastructure descriptor.
type Source struct {
	Kind Kind
	Path string // path relative to the scanned root
}

// maxScanFileSize bounds how much of a candidate file we read for classification
// and import, so a stray multi-GB file can't blow up onboarding.
const maxScanFileSize = 8 << 20 // 8 MiB

// skipDirs are never descended into during the scan.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".terraform": true,
	"dist": true, "build": true, "target": true, ".idea": true, ".vscode": true,
}

// Detect walks root and classifies the infrastructure files it recognises. The
// returned slice is sorted (kind, then path) for deterministic output.
func Detect(root string) ([]Source, error) {
	var sources []Source
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries rather than aborting onboarding
		}
		if d.IsDir() {
			if path != root && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		if kind, ok := classify(path, d.Name()); ok {
			sources = append(sources, Source{Kind: kind, Path: rel})
		}
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("scan %q: %w", root, walkErr)
	}
	sort.Slice(sources, func(i, j int) bool {
		if sources[i].Kind != sources[j].Kind {
			return sources[i].Kind < sources[j].Kind
		}
		return sources[i].Path < sources[j].Path
	})
	return sources, nil
}

// classify decides whether a single file is a recognised infrastructure source.
func classify(path, name string) (Kind, bool) {
	lower := strings.ToLower(name)

	// Never treat our own outputs as inputs.
	if lower == "threagile.yaml" || lower == "policy.yaml" {
		return "", false
	}

	if strings.HasSuffix(lower, ".tf") {
		return Terraform, true
	}

	switch lower {
	case "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml":
		return Compose, true
	}

	isYAML := strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml")
	isJSON := strings.HasSuffix(lower, ".json")
	if !isYAML && !isJSON {
		return "", false
	}

	head := readHead(path)
	if head == "" {
		return "", false
	}
	// OpenAPI / Swagger specs declare their version near the top.
	if strings.Contains(head, "openapi:") || strings.Contains(head, "\"openapi\"") ||
		strings.Contains(head, "swagger:") || strings.Contains(head, "\"swagger\"") {
		return OpenAPI, true
	}
	// Kubernetes manifests carry both apiVersion and kind.
	if isYAML && strings.Contains(head, "apiVersion:") && strings.Contains(head, "kind:") {
		return Kubernetes, true
	}
	return "", false
}

func readHead(path string) string {
	f, err := os.Open(path) // #nosec G304 -- scanning operator-pointed repo files
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, 8192)
	n, _ := f.Read(buf)
	return string(buf[:n])
}

// BuildModel imports every auto-importable source and merges the fragments into
// one model. It returns the merged model plus advisory notes (e.g. Terraform,
// which must be imported from `terraform show -json` and so cannot be read
// directly from .tf files here).
func BuildModel(root string, sources []Source) (*types.Model, []string, error) {
	merged := &types.Model{
		Title:           "Bootstrapped threat model",
		TechnicalAssets: map[string]*types.TechnicalAsset{},
		DataAssets:      map[string]*types.DataAsset{},
		TrustBoundaries: map[string]*types.TrustBoundary{},
		SharedRuntimes:  map[string]*types.SharedRuntime{},
	}
	var notes []string
	var k8sManifests [][]byte
	sawTerraform := false

	for _, s := range sources {
		full := filepath.Join(root, s.Path)
		switch s.Kind {
		case Terraform:
			sawTerraform = true
		case Compose:
			data, err := readLimited(full)
			if err != nil {
				notes = append(notes, fmt.Sprintf("skipped %s: %v", s.Path, err))
				continue
			}
			frag, err := compose.Import(data, compose.ImportOptions{SourceLabel: "compose"})
			if err != nil {
				notes = append(notes, fmt.Sprintf("compose %s: %v", s.Path, err))
				continue
			}
			mergeInto(merged, frag)
		case OpenAPI:
			data, err := readLimited(full)
			if err != nil {
				notes = append(notes, fmt.Sprintf("skipped %s: %v", s.Path, err))
				continue
			}
			frag, err := openapi.Import(data, openapi.ImportOptions{SourceLabel: "api"})
			if err != nil {
				notes = append(notes, fmt.Sprintf("openapi %s: %v", s.Path, err))
				continue
			}
			mergeInto(merged, frag)
		case Kubernetes:
			data, err := readLimited(full)
			if err != nil {
				notes = append(notes, fmt.Sprintf("skipped %s: %v", s.Path, err))
				continue
			}
			k8sManifests = append(k8sManifests, data)
		}
	}

	// Import all Kubernetes manifests together so cross-manifest references
	// (services -> deployments, etc.) resolve.
	if len(k8sManifests) > 0 {
		blob := bytesJoin(k8sManifests, []byte("\n---\n"))
		frag, err := kubernetes.Import(blob, kubernetes.ImportOptions{SourceLabel: "k8s"})
		if err != nil {
			notes = append(notes, fmt.Sprintf("kubernetes: %v", err))
		} else {
			mergeInto(merged, frag)
		}
	}

	if sawTerraform {
		notes = append(notes, "Terraform files detected: run `terraform show -json | threagile import terraform` and merge the result (HCL can't be imported directly).")
	}

	// Drop the empty shared-runtimes map so it doesn't serialize as `{}`.
	if len(merged.SharedRuntimes) == 0 {
		merged.SharedRuntimes = nil
	}
	return merged, notes, nil
}

// mergeInto copies a fragment's assets/data/boundaries into dst, first-wins on
// ID collision so the result is deterministic.
func mergeInto(dst, src *types.Model) {
	for id, a := range src.TechnicalAssets {
		if _, ok := dst.TechnicalAssets[id]; !ok {
			dst.TechnicalAssets[id] = a
		}
	}
	for id, da := range src.DataAssets {
		if _, ok := dst.DataAssets[id]; !ok {
			dst.DataAssets[id] = da
		}
	}
	for id, tb := range src.TrustBoundaries {
		if _, ok := dst.TrustBoundaries[id]; !ok {
			dst.TrustBoundaries[id] = tb
		}
	}
	for id, sr := range src.SharedRuntimes {
		if _, ok := dst.SharedRuntimes[id]; !ok {
			dst.SharedRuntimes[id] = sr
		}
	}
	// Union the declared tag vocabulary so no merged asset references a tag that
	// isn't in tags_available (which would fail validation).
	existing := map[string]bool{}
	for _, t := range dst.TagsAvailable {
		existing[t] = true
	}
	for _, t := range src.TagsAvailable {
		if !existing[t] {
			dst.TagsAvailable = append(dst.TagsAvailable, t)
			existing[t] = true
		}
	}
}

func readLimited(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxScanFileSize {
		return nil, fmt.Errorf("file too large (%d bytes)", info.Size())
	}
	return os.ReadFile(path) // #nosec G304 -- scanning operator-pointed repo files
}

func bytesJoin(parts [][]byte, sep []byte) []byte {
	if len(parts) == 0 {
		return nil
	}
	total := 0
	for _, p := range parts {
		total += len(p) + len(sep)
	}
	out := make([]byte, 0, total)
	for i, p := range parts {
		if i > 0 {
			out = append(out, sep...)
		}
		out = append(out, p...)
	}
	return out
}
