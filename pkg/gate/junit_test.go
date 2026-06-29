package gate

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/threagile/threagile/pkg/types"
)

// failing gate -> well-formed JUnit with a failure on the offending rule,
// the offending finding id in the failure body, and accurate counts.
func TestFormatJUnitFailing(t *testing.T) {
	policy := &Policy{Name: "ci", MaxSeverityCounts: map[string]int{"critical": 0}}
	in := Input{Risks: riskMap(risk("a", types.CriticalSeverity, types.Unchecked))}
	r := Evaluate(policy, in)

	out := FormatJUnit(policy, r)
	if !strings.HasPrefix(out, xml.Header) {
		t.Fatalf("missing XML header:\n%s", out)
	}

	var suites junitTestsuites
	if err := xml.Unmarshal([]byte(out), &suites); err != nil {
		t.Fatalf("output is not valid XML: %v\n%s", err, out)
	}
	if suites.Tests != 1 || suites.Failures != 1 {
		t.Fatalf("want tests=1 failures=1, got tests=%d failures=%d", suites.Tests, suites.Failures)
	}
	if len(suites.Suites) != 1 || len(suites.Suites[0].Cases) != 1 {
		t.Fatalf("want one suite with one case, got %+v", suites.Suites)
	}
	tc := suites.Suites[0].Cases[0]
	if tc.Name != "max_severity_counts" || tc.Classname != "threagile.gate" {
		t.Fatalf("unexpected testcase identity: %+v", tc)
	}
	if tc.Failure == nil || tc.Failure.Type != "policy_violation" {
		t.Fatalf("expected a policy_violation failure, got %+v", tc.Failure)
	}
	if !strings.Contains(tc.Failure.Content, "a") {
		t.Fatalf("failure body should list the offending finding id:\n%s", tc.Failure.Content)
	}
}

// a policy that configures rules but passes -> one passing testcase per rule,
// zero failures.
func TestFormatJUnitPassing(t *testing.T) {
	policy := &Policy{Name: "ok", MaxSeverityCounts: map[string]int{"critical": 0}, MaxTotalAtRisk: ptr(100)}
	r := Evaluate(policy, Input{Risks: riskMap()})

	var suites junitTestsuites
	if err := xml.Unmarshal([]byte(FormatJUnit(policy, r)), &suites); err != nil {
		t.Fatalf("invalid XML: %v", err)
	}
	if suites.Failures != 0 {
		t.Fatalf("passing gate should have 0 failures, got %d", suites.Failures)
	}
	if suites.Tests != 2 { // max_severity_counts + max_total_at_risk
		t.Fatalf("want 2 testcases for 2 configured rules, got %d", suites.Tests)
	}
	for _, tc := range suites.Suites[0].Cases {
		if tc.Failure != nil {
			t.Fatalf("rule %q should pass, has failure %+v", tc.Name, tc.Failure)
		}
	}
}

// an empty policy gates on nothing but must still emit one (passing) testcase
// so CI parsers that reject empty suites are happy.
func TestFormatJUnitEmptyPolicy(t *testing.T) {
	r := Evaluate(&Policy{}, Input{Risks: riskMap()})
	out := FormatJUnit(&Policy{}, r)
	var suites junitTestsuites
	if err := xml.Unmarshal([]byte(out), &suites); err != nil {
		t.Fatalf("invalid XML: %v", err)
	}
	if suites.Tests != 1 || suites.Failures != 0 {
		t.Fatalf("empty policy: want tests=1 failures=0, got tests=%d failures=%d", suites.Tests, suites.Failures)
	}
}

// determinism: rule testcases follow the canonical evaluation order regardless
// of map iteration.
func TestFormatJUnitDeterministicOrder(t *testing.T) {
	policy := &Policy{
		MaxSeverityCounts:        map[string]int{"critical": 0},
		RequireTrackingAtOrAbove: "high",
		MinScore:                 ptr(80),
	}
	want := []string{"max_severity_counts", "require_tracking_at_or_above", "min_score"}
	for i := 0; i < 5; i++ {
		r := Evaluate(policy, Input{Risks: riskMap()})
		var suites junitTestsuites
		if err := xml.Unmarshal([]byte(FormatJUnit(policy, r)), &suites); err != nil {
			t.Fatalf("invalid XML: %v", err)
		}
		var got []string
		for _, tc := range suites.Suites[0].Cases {
			got = append(got, tc.Name)
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("rule order not deterministic: got %v want %v", got, want)
		}
	}
}

func ptr(i int) *int { return &i }
