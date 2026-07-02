package threagile

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/types"
)

// This file implements `threagile import <fmt> --merge existing-model.yaml`
// (improvement.md P7): reconciling a fresh diagram import against a model
// file that has already been hand-edited, instead of clobbering it.
//
// PROVENANCE / OWNERSHIP DESIGN — comments vs. tags:
//
// The original plan considered detecting "has the user finished reviewing
// this element" by diffing the TODO(review) head-comments the scaffold step
// (import_scaffold.go) attaches to fields. A quick round-trip prototype
// (parse -> mutate a sibling field -> re-marshal) showed gopkg.in/yaml.v3
// keeps a HeadComment attached to the correct node for that simple case.
// But that is not the failure mode that matters here: the merge workflow
// requires detecting "did a human remove/edit this specific comment", and
// humans edit YAML with real text editors, not through yaml.Node — deleting
// the commented field, reordering keys, or reflowing surrounding blank
// lines are all extremely common and every one of them either orphans the
// comment onto an unrelated following key or drops it silently. There is no
// reliable way to tell "comment was intentionally removed because the field
// was reviewed" apart from "comment vanished because of incidental
// reformatting". Comment-diffing is therefore not used.
//
// Instead, ownership uses the existing tag channel, which survives
// re-marshal because tags are real YAML data, not attached-by-position
// comments: an element is "importer-owned" (diagram is authoritative, safe
// to overwrite) exactly while it still carries a "review-<importer>" tag
// (see pkg/import/*/importer.go) or the "stub-data-asset" tag (see
// import_stubs.go) — i.e. nobody has removed the review tag, meaning nobody
// has confirmed/finished reviewing it yet (see review.go's isReviewTag,
// reused here). The moment a user deletes that tag, the element becomes
// "user-owned": merge never overwrites its fields again, and any
// disagreement from the diagram is surfaced as a new
// "merge-conflict:<field>=<value>" tag rather than an inline comment, so
// `threagile review`/`threagile gate` (already tag-driven) can find it.
//
// See docs/import-merge.md for the user-facing writeup of this mechanism.

const (
	// mergeAbsentTag flags an importer-owned element that used to come from
	// the diagram but is no longer produced by the current import.
	mergeAbsentTag = "merge-absent-from-diagram"
	// mergeConflictPrefix is followed by "<field>=<diagram-value>" and
	// applied to a user-owned element whose diagram value now differs from
	// what is in the YAML.
	mergeConflictPrefix = "merge-conflict:"
)

// mergeFile is one on-disk YAML file participating in a merge: the
// entry-point file passed via --merge, or one of the files it (transitively)
// includes via `includes:`.
type mergeFile struct {
	path  string
	model *input.Model
}

// mergeOutcome summarises what mergeDiagramImport did, for the CLI to report
// and for tests to assert against.
type mergeOutcome struct {
	MainPath         string
	ChangedFiles     map[string]*input.Model // path -> file content to write back
	NewElements      int
	UpdatedElements  int
	ConflictElements int
	AbsentElements   int
	Warnings         []string
}

// loadMergeFiles reads mainPath and every file it (transitively) includes
// via `includes:`, each parsed independently as its own *input.Model so an
// update can be written back to the exact file an element lives in. Cyclic
// or repeated includes are only visited once.
func loadMergeFiles(mainPath string) ([]*mergeFile, error) {
	visited := map[string]bool{}
	var files []*mergeFile

	var load func(path string) error
	load = func(path string) error {
		abs, err := filepath.Abs(path)
		if err != nil {
			abs = path
		}
		if visited[abs] {
			return nil
		}
		visited[abs] = true

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read %q: %w", path, err)
		}
		m := new(input.Model)
		if err := yaml.Unmarshal(data, m); err != nil {
			return fmt.Errorf("failed to parse %q: %w", path, err)
		}
		files = append(files, &mergeFile{path: path, model: m})

		dir := filepath.Dir(path)
		for _, inc := range m.Includes {
			if err := load(filepath.Join(dir, inc)); err != nil {
				return err
			}
		}
		return nil
	}

	if err := load(mainPath); err != nil {
		return nil, err
	}
	return files, nil
}

// elementLoc identifies where an element lives: which file, and the map key
// (title) it is stored under in that file's model.
type elementLoc struct {
	file *mergeFile
	key  string
}

// linkLoc additionally carries the owning technical asset's map key, since
// communication links are nested under their source technical asset.
type linkLoc struct {
	file    *mergeFile
	taKey   string
	linkKey string
}

// mergeIndex indexes every element across all merge files by its stable
// Threagile ID (technical/data assets, trust boundaries), and every
// communication link by (source technical asset ID, link title) — links
// carry no ID field in the authoring format, so title-within-source-asset is
// the best available deterministic key, matching the diagram importers'
// deterministic title generation (same source diagram + same edge => same
// title).
type mergeIndex struct {
	ta   map[string]elementLoc
	da   map[string]elementLoc
	tb   map[string]elementLoc
	link map[string]linkLoc

	anyReviewTag bool // true if ANY element anywhere carries a review-*/stub-data-asset tag
}

func buildMergeIndex(files []*mergeFile) *mergeIndex {
	idx := &mergeIndex{
		ta:   map[string]elementLoc{},
		da:   map[string]elementLoc{},
		tb:   map[string]elementLoc{},
		link: map[string]linkLoc{},
	}
	for _, f := range files {
		for key, da := range f.model.DataAssets {
			if da.ID != "" {
				idx.da[da.ID] = elementLoc{file: f, key: key}
			}
			if containsAnyReviewTag(da.Tags) {
				idx.anyReviewTag = true
			}
		}
		for key, tb := range f.model.TrustBoundaries {
			if tb.ID != "" {
				idx.tb[tb.ID] = elementLoc{file: f, key: key}
			}
			if containsAnyReviewTag(tb.Tags) {
				idx.anyReviewTag = true
			}
		}
		for key, ta := range f.model.TechnicalAssets {
			if ta.ID != "" {
				idx.ta[ta.ID] = elementLoc{file: f, key: key}
			}
			if containsAnyReviewTag(ta.Tags) {
				idx.anyReviewTag = true
			}
			for linkKey, link := range ta.CommunicationLinks {
				idx.link[ta.ID+"|"+linkKey] = linkLoc{file: f, taKey: key, linkKey: linkKey}
				if containsAnyReviewTag(link.Tags) {
					idx.anyReviewTag = true
				}
			}
		}
	}
	return idx
}

func containsAnyReviewTag(tags []string) bool {
	for _, t := range tags {
		if isReviewTag(t) {
			return true
		}
	}
	return false
}

// mergeDiagramImport reconciles fresh (the just-parsed diagram model, after
// mapping/stub-data-asset post-processing) against the model file(s) loaded
// from mergePath, per the ownership rules documented at the top of this
// file. It returns which files need to be (re)written and a summary.
func mergeDiagramImport(fresh *types.Model, importerName, mergePath string) (*mergeOutcome, error) {
	files, err := loadMergeFiles(mergePath)
	if err != nil {
		return nil, err
	}
	main := files[0]
	idx := buildMergeIndex(files)

	outcome := &mergeOutcome{
		MainPath:     mergePath,
		ChangedFiles: map[string]*input.Model{},
	}
	if !idx.anyReviewTag {
		outcome.Warnings = append(outcome.Warnings,
			fmt.Sprintf("no review-%s/stub-data-asset tags found anywhere in %s (or its includes) — "+
				"treating this as a purely additive merge: existing elements are left untouched, "+
				"only new-by-ID diagram elements are appended", importerName, mergePath))
	}

	freshIn := modelToInput(fresh)
	touch := func(f *mergeFile) { outcome.ChangedFiles[f.path] = f.model }

	seenTA := map[string]bool{}
	seenDA := map[string]bool{}
	seenTB := map[string]bool{}
	seenLink := map[string]bool{}

	// Data assets.
	for _, key := range sortedInputDataAssetKeys(freshIn.DataAssets) {
		da := freshIn.DataAssets[key]
		seenDA[da.ID] = true
		if loc, ok := idx.da[da.ID]; ok {
			existing := loc.file.model.DataAssets[loc.key]
			if containsAnyReviewTag(existing.Tags) {
				loc.file.model.DataAssets[loc.key] = da
				outcome.UpdatedElements++
			} else {
				changed := diffDataAsset(&existing, da)
				if len(changed) > 0 {
					existing.Tags = appendConflictTags(existing.Tags, changed)
					loc.file.model.DataAssets[loc.key] = existing
					outcome.ConflictElements++
				}
			}
			touch(loc.file)
			continue
		}
		if main.model.DataAssets == nil {
			main.model.DataAssets = map[string]input.DataAsset{}
		}
		main.model.DataAssets[uniqueInputKey(key, main.model.DataAssets)] = da
		outcome.NewElements++
		touch(main)
	}

	// Technical assets (fields only — communication links handled below).
	for _, key := range sortedInputTechnicalAssetKeys(freshIn.TechnicalAssets) {
		ta := freshIn.TechnicalAssets[key]
		links := ta.CommunicationLinks
		ta.CommunicationLinks = nil
		seenTA[ta.ID] = true

		var taKey string
		var taFile *mergeFile
		if loc, ok := idx.ta[ta.ID]; ok {
			existing := loc.file.model.TechnicalAssets[loc.key]
			existingLinks := existing.CommunicationLinks
			if containsAnyReviewTag(existing.Tags) {
				ta.CommunicationLinks = existingLinks
				loc.file.model.TechnicalAssets[loc.key] = ta
				outcome.UpdatedElements++
			} else {
				changed := diffTechnicalAsset(&existing, ta)
				if len(changed) > 0 {
					existing.Tags = appendConflictTags(existing.Tags, changed)
					loc.file.model.TechnicalAssets[loc.key] = existing
					outcome.ConflictElements++
				}
			}
			taKey, taFile = loc.key, loc.file
			touch(loc.file)
		} else {
			if main.model.TechnicalAssets == nil {
				main.model.TechnicalAssets = map[string]input.TechnicalAsset{}
			}
			taKey = uniqueInputKey(key, main.model.TechnicalAssets)
			main.model.TechnicalAssets[taKey] = ta
			taFile = main
			outcome.NewElements++
			touch(main)
		}

		// Communication links nested under this technical asset.
		for linkKey, link := range links {
			idxKey := ta.ID + "|" + linkKey
			seenLink[idxKey] = true
			current := taFile.model.TechnicalAssets[taKey]
			if current.CommunicationLinks == nil {
				current.CommunicationLinks = map[string]input.CommunicationLink{}
			}
			if loc, ok := idx.link[idxKey]; ok && loc.file == taFile && loc.taKey == taKey {
				existingLink := current.CommunicationLinks[loc.linkKey]
				if containsAnyReviewTag(existingLink.Tags) {
					current.CommunicationLinks[loc.linkKey] = link
					outcome.UpdatedElements++
				} else {
					changed := diffCommunicationLink(&existingLink, link)
					if len(changed) > 0 {
						existingLink.Tags = appendConflictTags(existingLink.Tags, changed)
						current.CommunicationLinks[loc.linkKey] = existingLink
						outcome.ConflictElements++
					}
				}
			} else {
				current.CommunicationLinks[uniqueLinkTitle(linkKey, "", current.CommunicationLinks)] = link
				outcome.NewElements++
			}
			taFile.model.TechnicalAssets[taKey] = current
		}
	}

	// Trust boundaries.
	for _, key := range sortedInputTrustBoundaryKeys(freshIn.TrustBoundaries) {
		tb := freshIn.TrustBoundaries[key]
		seenTB[tb.ID] = true
		if loc, ok := idx.tb[tb.ID]; ok {
			existing := loc.file.model.TrustBoundaries[loc.key]
			if containsAnyReviewTag(existing.Tags) {
				loc.file.model.TrustBoundaries[loc.key] = tb
				outcome.UpdatedElements++
			} else {
				changed := diffTrustBoundary(&existing, tb)
				if len(changed) > 0 {
					existing.Tags = appendConflictTags(existing.Tags, changed)
					loc.file.model.TrustBoundaries[loc.key] = existing
					outcome.ConflictElements++
				}
			}
			touch(loc.file)
			continue
		}
		if main.model.TrustBoundaries == nil {
			main.model.TrustBoundaries = map[string]input.TrustBoundary{}
		}
		main.model.TrustBoundaries[uniqueInputKey(key, main.model.TrustBoundaries)] = tb
		outcome.NewElements++
		touch(main)
	}

	// Elements present in the existing YAML but absent from this diagram
	// pass: flag importer-owned ones, leave user-owned ones untouched.
	for id, loc := range idx.da {
		if seenDA[id] {
			continue
		}
		existing := loc.file.model.DataAssets[loc.key]
		if containsAnyReviewTag(existing.Tags) && !containsString(existing.Tags, mergeAbsentTag) {
			existing.Tags = append(existing.Tags, mergeAbsentTag)
			loc.file.model.DataAssets[loc.key] = existing
			outcome.AbsentElements++
			touch(loc.file)
		}
	}
	for id, loc := range idx.ta {
		if seenTA[id] {
			continue
		}
		existing := loc.file.model.TechnicalAssets[loc.key]
		if containsAnyReviewTag(existing.Tags) && !containsString(existing.Tags, mergeAbsentTag) {
			existing.Tags = append(existing.Tags, mergeAbsentTag)
			loc.file.model.TechnicalAssets[loc.key] = existing
			outcome.AbsentElements++
			touch(loc.file)
		}
	}
	for id, loc := range idx.tb {
		if seenTB[id] {
			continue
		}
		existing := loc.file.model.TrustBoundaries[loc.key]
		if containsAnyReviewTag(existing.Tags) && !containsString(existing.Tags, mergeAbsentTag) {
			existing.Tags = append(existing.Tags, mergeAbsentTag)
			loc.file.model.TrustBoundaries[loc.key] = existing
			outcome.AbsentElements++
			touch(loc.file)
		}
	}
	for idxKey, loc := range idx.link {
		if seenLink[idxKey] {
			continue
		}
		ta, ok := loc.file.model.TechnicalAssets[loc.taKey]
		if !ok {
			continue
		}
		existing, ok := ta.CommunicationLinks[loc.linkKey]
		if !ok || !containsAnyReviewTag(existing.Tags) || containsString(existing.Tags, mergeAbsentTag) {
			continue
		}
		existing.Tags = append(existing.Tags, mergeAbsentTag)
		ta.CommunicationLinks[loc.linkKey] = existing
		loc.file.model.TechnicalAssets[loc.taKey] = ta
		outcome.AbsentElements++
		touch(loc.file)
	}

	// Merge new tags_available (conflict/absent tags plus whatever the fresh
	// import declared) into the main file so the merged YAML still validates.
	main.model.TagsAvailable = new(input.Strings).MergeUniqueSlice(main.model.TagsAvailable, freshIn.TagsAvailable)
	main.model.TagsAvailable = new(input.Strings).MergeUniqueSlice(main.model.TagsAvailable, []string{mergeAbsentTag})
	touch(main)

	return outcome, nil
}

// diff* return the set of field names whose fresh-diagram value differs from
// the existing (user-owned, non-empty-tolerant) value. Only fields diagram
// importers actually set are compared — free-form fields a human might add
// (owner, justification_*, etc.) are never touched or conflict-flagged.

func diffTechnicalAsset(existing *input.TechnicalAsset, fresh input.TechnicalAsset) []string {
	var changed []string
	add := func(field string, same bool) {
		if !same {
			changed = append(changed, field)
		}
	}
	add("type", existing.Type == fresh.Type)
	add("technology", existing.Technology == fresh.Technology && stringsEqual(existing.Technologies, fresh.Technologies))
	add("machine", existing.Machine == fresh.Machine)
	add("encryption", existing.Encryption == fresh.Encryption)
	add("internet", existing.Internet == fresh.Internet)
	return changed
}

func diffDataAsset(existing *input.DataAsset, fresh input.DataAsset) []string {
	var changed []string
	if existing.Confidentiality != fresh.Confidentiality {
		changed = append(changed, "confidentiality")
	}
	return changed
}

func diffTrustBoundary(existing *input.TrustBoundary, fresh input.TrustBoundary) []string {
	var changed []string
	if existing.Type != fresh.Type {
		changed = append(changed, "type")
	}
	return changed
}

func diffCommunicationLink(existing *input.CommunicationLink, fresh input.CommunicationLink) []string {
	var changed []string
	if existing.Protocol != fresh.Protocol {
		changed = append(changed, "protocol")
	}
	if existing.Authentication != fresh.Authentication {
		changed = append(changed, "authentication")
	}
	return changed
}

func stringsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// appendConflictTags adds one "merge-conflict:<field>" tag per changed field
// (deduplicated), so review/gate tooling can find exactly which fields the
// diagram now disagrees with a user-finalised element about.
func appendConflictTags(tags []string, changedFields []string) []string {
	for _, field := range changedFields {
		tag := mergeConflictPrefix + field
		if !containsString(tags, tag) {
			tags = append(tags, tag)
		}
	}
	return tags
}

func uniqueInputKey[V any](base string, m map[string]V) string {
	key := base
	for n := 2; ; n++ {
		if _, ok := m[key]; !ok {
			return key
		}
		key = fmt.Sprintf("%s #%d", base, n)
	}
}

func sortedInputDataAssetKeys(m map[string]input.DataAsset) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedInputTechnicalAssetKeys(m map[string]input.TechnicalAsset) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedInputTrustBoundaryKeys(m map[string]input.TrustBoundary) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// writeMergedFile marshals a merged *input.Model back to YAML, annotating
// only importer-owned elements (still carrying a review-*/stub-data-asset
// tag) with the usual TODO(review) scaffold comments — user-owned elements
// are left with no injected comments at all, since merge never touches
// their fields.
func writeMergedFile(m *input.Model) ([]byte, error) {
	plain, err := yaml.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal merged model: %w", err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(plain, &doc); err != nil {
		return nil, fmt.Errorf("failed to re-parse merged YAML for annotation: %w", err)
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return plain, nil
	}
	root := doc.Content[0]
	annotateOwnedSection(root, "technical_assets", scaffoldTechnicalAssetReasons)
	annotateOwnedSection(root, "data_assets", scaffoldDataAssetReasons)
	annotateOwnedSection(root, "trust_boundaries", scaffoldTrustBoundaryReasons)

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal annotated merged YAML: %w", err)
	}
	return out, nil
}

// annotateOwnedSection is annotateSection (import_scaffold.go) restricted to
// elements that still carry a review-*/stub-data-asset tag — i.e. only
// importer-owned elements get TODO(review) comments in merge output.
func annotateOwnedSection(root *yaml.Node, sectionKey string, fieldReasons map[string]string) {
	section := mapValue(root, sectionKey)
	if section == nil || section.Kind != yaml.MappingNode {
		return
	}
	for i := 1; i < len(section.Content); i += 2 {
		element := section.Content[i]
		if element.Kind != yaml.MappingNode {
			continue
		}
		if !elementHasReviewTag(element) {
			continue
		}
		annotateFields(element, fieldReasons)
	}
}

// elementHasReviewTag reports whether a mapping node's "tags" sequence
// contains any review-*/stub-data-asset tag.
func elementHasReviewTag(element *yaml.Node) bool {
	tagsNode := mapValue(element, "tags")
	if tagsNode == nil || tagsNode.Kind != yaml.SequenceNode {
		return false
	}
	for _, t := range tagsNode.Content {
		if isReviewTag(t.Value) {
			return true
		}
	}
	return false
}

// summarizeMerge renders a one-line-per-file human-readable report.
func (o *mergeOutcome) summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Merge summary: %d new, %d updated (importer-owned), %d conflict-flagged (user-owned), %d flagged absent-from-diagram\n",
		o.NewElements, o.UpdatedElements, o.ConflictElements, o.AbsentElements)
	paths := make([]string, 0, len(o.ChangedFiles))
	for p := range o.ChangedFiles {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		b.WriteString("  " + p + "\n")
	}
	for _, w := range o.Warnings {
		fmt.Fprintf(&b, "warning: %s\n", w)
	}
	return b.String()
}
