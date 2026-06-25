package threagile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/threagile/threagile/pkg/prioritize"
	"github.com/threagile/threagile/pkg/types"
)

func diffRisk(id string, sev types.RiskSeverity) *types.Risk {
	return &types.Risk{SyntheticId: id, Severity: sev}
}

func sampleDiff() *riskDiff {
	return &riskDiff{
		OldFile:     "old.yaml",
		NewFile:     "new.yaml",
		Methodology: "stride",
		Added: []*types.Risk{
			diffRisk("sql-injection@api", types.HighSeverity),
			diffRisk("missing-csp@web", types.MediumSeverity),
		},
		Removed:   []*types.Risk{diffRisk("old-risk@x", types.LowSeverity)},
		Unchanged: []*types.Risk{diffRisk("u1@a", types.MediumSeverity), diffRisk("u2@b", types.LowSeverity)},
	}
}

func TestDiffMarkdownShowsRemediation(t *testing.T) {
	d := &riskDiff{
		OldFile: "old.yaml", NewFile: "new.yaml", Methodology: "stride",
		Added: []*types.Risk{
			{SyntheticId: "missing-authentication@api", Severity: types.HighSeverity, CategoryId: "missing-authentication"},
			{SyntheticId: "missing-authentication@web", Severity: types.HighSeverity, CategoryId: "missing-authentication"},
		},
		Remediation: map[string]prioritize.Remediation{
			"missing-authentication": {Action: "Authenticate incoming requests", CWE: 306},
		},
		CategoryTitles: map[string]string{"missing-authentication": "Missing Authentication"},
	}
	out := d.formatMarkdown()
	if !strings.Contains(out, "**How to fix the new findings:**") {
		t.Fatalf("missing remediation section:\n%s", out)
	}
	if !strings.Contains(out, "Missing Authentication") || !strings.Contains(out, "Authenticate incoming requests") || !strings.Contains(out, "CWE-306") {
		t.Fatalf("remediation content missing:\n%s", out)
	}
	// deduped by category: only one fix line despite two findings
	if strings.Count(out, "Authenticate incoming requests") != 1 {
		t.Fatalf("remediation should dedupe by category:\n%s", out)
	}
}

func TestDiffFormatText(t *testing.T) {
	out := sampleDiff().formatText()
	if !strings.Contains(out, "+ 2 new risk(s)") || !strings.Contains(out, "- 1 resolved risk(s)") {
		t.Fatalf("text diff missing counts:\n%s", out)
	}
	if !strings.Contains(out, "Summary: +2 added, -1 resolved, ~0 changed, =2 unchanged") {
		t.Fatalf("text diff missing summary:\n%s", out)
	}
}

func TestDiffFormatTextNoChanges(t *testing.T) {
	d := &riskDiff{OldFile: "a", NewFile: "b", Methodology: "stride"}
	if !strings.Contains(d.formatText(), "No risk changes detected") {
		t.Fatal("expected no-change message")
	}
}

func TestDiffFormatMarkdown(t *testing.T) {
	out := sampleDiff().formatMarkdown()
	if !strings.Contains(out, "## Threat-model risk delta") {
		t.Fatalf("missing header:\n%s", out)
	}
	if !strings.Contains(out, "**+2 added, −1 resolved, ~0 changed, =2 unchanged**") {
		t.Fatalf("missing summary line:\n%s", out)
	}
	if !strings.Contains(out, "### ❌ 2 new risk(s)") || !strings.Contains(out, "### ✅ 1 resolved risk(s)") {
		t.Fatalf("missing sections:\n%s", out)
	}
	if !strings.Contains(out, "| High | `sql-injection@api` |") {
		t.Fatalf("missing risk table row:\n%s", out)
	}
}

func TestDiffSortBySeverity(t *testing.T) {
	// High must come before Medium in the added table.
	old := map[string]*types.Risk{}
	newR := map[string]*types.Risk{
		"med@x":  diffRisk("med@x", types.MediumSeverity),
		"high@y": diffRisk("high@y", types.HighSeverity),
	}
	added, _, _, _ := diffRisks(old, newR)
	if added[0].Severity != types.HighSeverity {
		t.Fatalf("expected High first, got %s", added[0].Severity)
	}
}

func TestDiffDetectsSeverityChange(t *testing.T) {
	old := map[string]*types.Risk{"r@x": diffRisk("r@x", types.MediumSeverity)}
	newR := map[string]*types.Risk{"r@x": diffRisk("r@x", types.CriticalSeverity)}
	added, removed, changed, unchanged := diffRisks(old, newR)
	if len(added) != 0 || len(removed) != 0 || len(unchanged) != 0 {
		t.Fatalf("escalation should not be added/removed/unchanged: a=%d r=%d u=%d", len(added), len(removed), len(unchanged))
	}
	if len(changed) != 1 || !changed[0].escalated() {
		t.Fatalf("expected 1 escalated change, got %+v", changed)
	}
	if changed[0].OldSeverity != types.MediumSeverity || changed[0].NewSeverity != types.CriticalSeverity {
		t.Fatalf("wrong severities: %+v", changed[0])
	}
}

func TestDiffMarkdownShowsChange(t *testing.T) {
	d := &riskDiff{
		OldFile: "a", NewFile: "b", Methodology: "stride",
		Changed: []riskChange{{Risk: diffRisk("r@x", types.HighSeverity), OldSeverity: types.MediumSeverity, NewSeverity: types.HighSeverity}},
	}
	out := d.formatMarkdown()
	if !strings.Contains(out, "### ⚠️ 1 severity change(s)") || !strings.Contains(out, "Medium ↑ High") {
		t.Fatalf("markdown missing change section:\n%s", out)
	}
}

func TestGenerateCIGatePRTarget(t *testing.T) {
	dir := t.TempDir()
	app := newTestAppWithArgs(GenerateCICommand, "--model", demoModelPath(t),
		"--target", "gate-pr", "--policy-path", "secpolicy.yaml", "--ci-output", dir)
	_, err := executeCmd(app, GenerateCICommand, "--model", demoModelPath(t),
		"--target", "gate-pr", "--policy-path", "secpolicy.yaml", "--ci-output", dir)
	if err != nil {
		t.Fatalf("generate-ci gate-pr failed: %v", err)
	}
	data, readErr := os.ReadFile(filepath.Join(dir, "threat-model-gate.yml"))
	if readErr != nil {
		t.Fatalf("gate-pr workflow not written: %v", readErr)
	}
	body := string(data)
	for _, want := range []string{"name: Threat-model Gate", "gate \\", "secpolicy.yaml", "createComment"} {
		if !strings.Contains(body, want) {
			t.Fatalf("gate-pr workflow missing %q:\n%s", want, body)
		}
	}
}

func TestDiffToJSON(t *testing.T) {
	j := sampleDiff().toJSON()
	if len(j.Added) != 2 || j.Added[0].SyntheticId != "sql-injection@api" || j.Added[0].Severity != "high" {
		t.Fatalf("unexpected json added: %+v", j.Added)
	}
	if j.UnchangedCount != 2 {
		t.Fatalf("unchanged count = %d, want 2", j.UnchangedCount)
	}
}
