package gate

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadPolicy(t *testing.T) {
	path := writeTemp(t, `
name: My gate
max_severity_counts:
  critical: 0
  high: 3
max_total_at_risk: 50
require_tracking_at_or_above: elevated
fail_on_expired_acceptance: true
forbid_new_at_or_above: high
framework_coverage:
  - {framework: owasp_top10_2021, min_percent: 70}
`)
	p, err := LoadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "My gate" || p.MaxSeverityCounts["high"] != 3 {
		t.Fatalf("unexpected parse: %+v", p)
	}
	if p.MaxTotalAtRisk == nil || *p.MaxTotalAtRisk != 50 {
		t.Fatal("max_total_at_risk not parsed")
	}
	if got := p.ReferencedFrameworks(); len(got) != 1 || got[0] != "owasp_top10_2021" {
		t.Fatalf("ReferencedFrameworks = %v", got)
	}
}

func TestLoadPolicyUnknownKeyRejected(t *testing.T) {
	// A typo in a rule name must fail loudly, not be silently ignored.
	path := writeTemp(t, "max_severity_count:\n  critical: 0\n")
	if _, err := LoadPolicy(path); err == nil {
		t.Fatal("unknown key should be rejected")
	}
}

func TestLoadPolicyMissingFile(t *testing.T) {
	if _, err := LoadPolicy("/no/such/policy.yaml"); err == nil {
		t.Fatal("missing file should error")
	}
}
