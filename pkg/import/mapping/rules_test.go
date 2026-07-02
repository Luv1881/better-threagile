package mapping

import (
	"os"
	"strings"
	"testing"
)

func TestParseValidRuleset(t *testing.T) {
	data := []byte(`
rules:
  - match:
      label: '(?i)minio|blob'
    set:
      technology: object-storage
      tags: [object-store]
  - match:
      edge: true
      color: '#FF0000'
      line_style: dashed
    set:
      encryption: none
      tags: [flagged-unencrypted]
  - match:
      fill_color: '#00AA00'
    set:
      trust_boundary: internal
`)
	rs, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(rs.Rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(rs.Rules))
	}
	if rs.Rules[0].labelRe == nil {
		t.Fatalf("expected label regexp to be compiled")
	}
}

func TestParseEmptyDocument(t *testing.T) {
	rs, err := Parse([]byte(``))
	if err != nil {
		t.Fatalf("empty document should be a valid no-op ruleset: %v", err)
	}
	if rs == nil || len(rs.Rules) != 0 {
		t.Fatalf("expected empty ruleset, got %+v", rs)
	}
}

func TestParseNoOpRulesetIsNilSafe(t *testing.T) {
	var rs *Ruleset
	got := rs.Resolve(Element{Label: "anything"})
	if got.Type != "" || len(got.Tags) != 0 {
		t.Fatalf("expected zero-value Applied from nil ruleset, got %+v", got)
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	_, err := Parse([]byte(`
rules:
  - match:
      labl: 'typo'
    set:
      technology: x
`))
	if err == nil {
		t.Fatalf("expected an error for an unknown field (typo in match.labl)")
	}
}

func TestParseRejectsInvalidYAML(t *testing.T) {
	_, err := Parse([]byte("rules: [this is not: valid: yaml: at: all"))
	if err == nil {
		t.Fatalf("expected a parse error for malformed YAML")
	}
}

func TestParseRejectsRuleWithNoMatchCriteria(t *testing.T) {
	_, err := Parse([]byte(`
rules:
  - match: {}
    set:
      technology: x
`))
	if err == nil {
		t.Fatalf("expected an error for a rule with no match criteria")
	}
	if !strings.Contains(err.Error(), "no criteria") {
		t.Fatalf("expected 'no criteria' in error, got: %v", err)
	}
}

func TestParseRejectsRuleWithNoSetFields(t *testing.T) {
	_, err := Parse([]byte(`
rules:
  - match:
      label: 'x'
    set: {}
`))
	if err == nil {
		t.Fatalf("expected an error for a rule with no set fields")
	}
}

func TestParseRejectsInvalidLabelRegexp(t *testing.T) {
	_, err := Parse([]byte(`
rules:
  - match:
      label: '('
    set:
      technology: x
`))
	if err == nil {
		t.Fatalf("expected an error for an invalid regexp")
	}
	if !strings.Contains(err.Error(), "invalid match.label regexp") {
		t.Fatalf("expected regexp error, got: %v", err)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/path/does-not-exist.yaml")
	if err == nil {
		t.Fatalf("expected an error loading a missing file")
	}
}

func TestLoadValidFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/mapping.yaml"
	content := "rules:\n  - match:\n      label: 'minio'\n    set:\n      technology: object-storage\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	rs, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(rs.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rs.Rules))
	}
}
