// Package mapping implements the diagram-importer "mapping dictionary
// sidecar" (see improvement.md P3): a small, ordered rule engine that lets a
// user correct/override the built-in heuristics the diagram importers
// (drawio, threat-dragon, otm — and mermaid later) use to classify shapes,
// without touching Go code.
//
// A ruleset is loaded from a YAML file:
//
//	rules:
//	  - match:
//	      label: '(?i)minio|blob'
//	    set:
//	      technology: object-storage
//	      tags: [object-store]
//	  - match:
//	      edge: true
//	      color: '#FF0000'
//	      line_style: dashed
//	    set:
//	      encryption: none
//	      tags: [flagged-unencrypted]
//	  - match:
//	      fill_color: '#00AA00'
//	    set:
//	      trust_boundary: internal
//
// Rules are evaluated in file order against a generic mapping.Element (a
// label plus whatever raw style metadata the calling importer has on hand —
// drawio has style-derived color/line_style/fill_color, threatdragon/otm
// mostly don't and those matchers simply never fire for them). For each
// scalar `set` field the FIRST matching rule that sets it wins; `set.tags`
// instead accumulate (deduplicated union, in rule order) across every
// matching rule — see Resolve for the rationale.
package mapping

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// MatchCriteria are the optional matchers a rule can specify. A criterion
// that is empty/nil is not evaluated (matches anything); a rule must specify
// at least one non-empty criterion (enforced at load time) so a typo'd empty
// match block cannot silently match every element.
type MatchCriteria struct {
	// Label is a regular expression tested against the element's title/name.
	Label string `yaml:"label,omitempty"`
	// Edge, when set, requires the element to be an edge (true) or a
	// vertex/node (false). Importers that only ever call Resolve for one kind
	// of element (e.g. threat-dragon nodes) still populate Element.Edge so
	// this matcher behaves correctly.
	Edge *bool `yaml:"edge,omitempty"`
	// Color, LineStyle and FillColor are raw style metadata matchers. Only
	// importers that retain that information from the source format populate
	// them on the Element they resolve against (currently: drawio).
	Color     string `yaml:"color,omitempty"`
	LineStyle string `yaml:"line_style,omitempty"`
	FillColor string `yaml:"fill_color,omitempty"`
}

// SetFields are the model fields a matching rule assigns. Every field is
// optional; unset (empty string / nil slice) means "leave alone".
type SetFields struct {
	Type            string   `yaml:"type,omitempty"`
	Technology      string   `yaml:"technology,omitempty"`
	Technologies    []string `yaml:"technologies,omitempty"`
	Machine         string   `yaml:"machine,omitempty"`
	Encryption      string   `yaml:"encryption,omitempty"`
	Tags            []string `yaml:"tags,omitempty"`
	TrustBoundary   string   `yaml:"trust_boundary,omitempty"`
	Trust           string   `yaml:"trust,omitempty"` // alias for trust_boundary
	Confidentiality string   `yaml:"confidentiality,omitempty"`
	Integrity       string   `yaml:"integrity,omitempty"`
	Availability    string   `yaml:"availability,omitempty"`
}

// Rule is one ordered "match -> set" entry.
type Rule struct {
	Match MatchCriteria `yaml:"match"`
	Set   SetFields     `yaml:"set"`

	labelRe *regexp.Regexp // compiled at Load/Parse time
}

// Ruleset is a loaded, validated mapping file. A nil *Ruleset is a valid
// no-op (every Apply*/Resolve function treats it as "no rules configured"),
// so callers can pass it through unconditionally without a nil check at
// every call site.
type Ruleset struct {
	Rules []Rule
}

// ruleFile is the top-level YAML document shape.
type ruleFile struct {
	Rules []Rule `yaml:"rules"`
}

// Load reads and parses a mapping rules file from path.
func Load(path string) (*Ruleset, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("mapping: failed to read %s: %w", path, err)
	}
	rs, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("mapping: %s: %w", path, err)
	}
	return rs, nil
}

// Parse parses mapping rules from raw YAML bytes. Unknown top-level keys
// (typos in "match"/"set" field names) are rejected so mistakes surface
// immediately instead of silently doing nothing.
func Parse(data []byte) (*Ruleset, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var file ruleFile
	if err := dec.Decode(&file); err != nil {
		if err.Error() == "EOF" {
			// Empty document: a ruleset with zero rules is a legitimate no-op.
			return &Ruleset{}, nil
		}
		return nil, fmt.Errorf("failed to parse mapping rules: %w", err)
	}

	rs := &Ruleset{Rules: file.Rules}
	if err := rs.validate(); err != nil {
		return nil, err
	}
	return rs, nil
}

// validate compiles every label regex and rejects rules with no match
// criteria at all (which would otherwise match every element, almost
// certainly not what the author intended).
func (rs *Ruleset) validate() error {
	for i := range rs.Rules {
		r := &rs.Rules[i]
		m := r.Match
		if m.Label == "" && m.Edge == nil && m.Color == "" && m.LineStyle == "" && m.FillColor == "" {
			return fmt.Errorf("rule %d: match has no criteria (label/edge/color/line_style/fill_color) — it would match every element", i+1)
		}
		if m.Label != "" {
			re, err := regexp.Compile(m.Label)
			if err != nil {
				return fmt.Errorf("rule %d: invalid match.label regexp %q: %w", i+1, m.Label, err)
			}
			r.labelRe = re
		}
		if setFieldsEmpty(r.Set) {
			return fmt.Errorf("rule %d: set has no fields — rule has no effect", i+1)
		}
	}
	return nil
}

func setFieldsEmpty(s SetFields) bool {
	return s.Type == "" && s.Technology == "" && len(s.Technologies) == 0 && s.Machine == "" &&
		s.Encryption == "" && len(s.Tags) == 0 && s.TrustBoundary == "" && s.Trust == "" &&
		s.Confidentiality == "" && s.Integrity == "" && s.Availability == ""
}

// matches reports whether every non-empty criterion in r.Match matches el.
func (r *Rule) matches(el Element) bool {
	m := r.Match
	if r.labelRe != nil && !r.labelRe.MatchString(el.Label) {
		return false
	}
	if m.Edge != nil && *m.Edge != el.Edge {
		return false
	}
	if m.Color != "" && !equalFoldNonEmpty(m.Color, el.Color) {
		return false
	}
	if m.LineStyle != "" && !equalFoldNonEmpty(m.LineStyle, el.LineStyle) {
		return false
	}
	if m.FillColor != "" && !equalFoldNonEmpty(m.FillColor, el.FillColor) {
		return false
	}
	return true
}

// equalFoldNonEmpty reports whether got case-insensitively equals want,
// treating an empty got (the importer never populated that style field) as
// never matching — a rule that asks for a specific color should not match
// elements the source format simply has no color for.
func equalFoldNonEmpty(want, got string) bool {
	return got != "" && strings.EqualFold(want, got)
}
