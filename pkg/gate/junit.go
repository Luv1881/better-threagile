package gate

import (
	"encoding/xml"
	"fmt"
	"sort"
	"strings"
)

// JUnit XML output so a threat-model gate surfaces as test results in CI systems
// that natively render JUnit (Jenkins, GitLab CI, CircleCI, Azure DevOps,
// Buildkite, …). Each policy rule that the policy actually configures becomes a
// <testcase>; a rule that produced one or more violations is reported as a
// <failure>, so engineers see exactly which governance check broke — and which
// finding IDs caused it — in the same place they read their unit-test results.

type junitTestsuites struct {
	XMLName  xml.Name         `xml:"testsuites"`
	Name     string           `xml:"name,attr"`
	Tests    int              `xml:"tests,attr"`
	Failures int              `xml:"failures,attr"`
	Suites   []junitTestsuite `xml:"testsuite"`
}

type junitTestsuite struct {
	Name       string          `xml:"name,attr"`
	Tests      int             `xml:"tests,attr"`
	Failures   int             `xml:"failures,attr"`
	Properties []junitProperty `xml:"properties>property,omitempty"`
	Cases      []junitTestcase `xml:"testcase"`
}

type junitProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

type junitTestcase struct {
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr,omitempty"`
	Content string `xml:",chardata"`
}

// activeRules returns the policy's configured rule names in the canonical order
// Evaluate runs them, so the JUnit testcases are deterministic and only cover
// rules the team actually opted into (an empty policy gates on nothing).
func activeRules(policy *Policy) []string {
	var rules []string
	if policy == nil {
		return rules
	}
	if len(policy.MaxSeverityCounts) > 0 {
		rules = append(rules, "max_severity_counts")
	}
	if policy.MaxTotalAtRisk != nil {
		rules = append(rules, "max_total_at_risk")
	}
	if policy.RequireTrackingAtOrAbove != "" {
		rules = append(rules, "require_tracking_at_or_above")
	}
	if policy.FailOnExpiredAcceptance {
		rules = append(rules, "fail_on_expired_acceptance")
	}
	if policy.ForbidNewAtOrAbove != "" {
		rules = append(rules, "forbid_new_at_or_above")
	}
	if len(policy.FrameworkCoverage) > 0 {
		rules = append(rules, "framework_coverage")
	}
	if policy.MinScore != nil {
		rules = append(rules, "min_score")
	}
	return rules
}

// FormatJUnit renders the gate result as a JUnit XML report. policy may be nil
// (older callers): then one testcase per rule appearing in the violations is
// emitted instead, so no failure is ever silently dropped.
func FormatJUnit(policy *Policy, r *Result) string {
	byRule := map[string][]Violation{}
	for _, v := range r.Violations {
		byRule[v.Rule] = append(byRule[v.Rule], v)
	}

	// Testcase set = configured rules ∪ any rule that produced a violation
	// (defensive: covers nil policy and any rule not in activeRules).
	seen := map[string]bool{}
	var ruleOrder []string
	for _, rule := range activeRules(policy) {
		if !seen[rule] {
			seen[rule] = true
			ruleOrder = append(ruleOrder, rule)
		}
	}
	var extra []string
	for rule := range byRule {
		if !seen[rule] {
			seen[rule] = true
			extra = append(extra, rule)
		}
	}
	sort.Strings(extra) // deterministic for the (rare) non-configured rules
	ruleOrder = append(ruleOrder, extra...)

	cases := make([]junitTestcase, 0, len(ruleOrder))
	failures := 0
	for _, rule := range ruleOrder {
		tc := junitTestcase{Name: rule, Classname: "threagile.gate"}
		if vs := byRule[rule]; len(vs) > 0 {
			failures++
			msgs := make([]string, 0, len(vs))
			var detail strings.Builder
			for _, v := range vs {
				msgs = append(msgs, v.Message)
				fmt.Fprintf(&detail, "%s\n", v.Message)
				if len(v.Findings) > 0 {
					fmt.Fprintf(&detail, "  offending: %s\n", joinCapped(v.Findings, 50))
				}
			}
			tc.Failure = &junitFailure{
				Message: strings.Join(msgs, "; "),
				Type:    "policy_violation",
				Content: strings.TrimRight(detail.String(), "\n"),
			}
		}
		cases = append(cases, tc)
	}

	// A policy that configures no rules still gets one passing testcase so CI
	// parsers that reject empty suites stay happy.
	if len(cases) == 0 {
		cases = append(cases, junitTestcase{Name: "gate", Classname: "threagile.gate"})
	}

	name := r.PolicyName
	if name == "" {
		name = "threagile-gate"
	}

	props := []junitProperty{{Name: "at_risk_total", Value: fmt.Sprintf("%d", r.AtRiskTotal)}}
	for _, sev := range []string{"critical", "high", "elevated", "medium", "low"} {
		if n, ok := r.AtRiskBySeverity[sev]; ok {
			props = append(props, junitProperty{Name: "at_risk_" + sev, Value: fmt.Sprintf("%d", n)})
		}
	}

	suites := junitTestsuites{
		Name:     name,
		Tests:    len(cases),
		Failures: failures,
		Suites: []junitTestsuite{{
			Name:       name,
			Tests:      len(cases),
			Failures:   failures,
			Properties: props,
			Cases:      cases,
		}},
	}

	out, err := xml.MarshalIndent(&suites, "", "  ")
	if err != nil {
		// xml.Marshal of this fixed structure cannot realistically fail; degrade to
		// a well-formed empty document (a bare header has no root element, which
		// makes CI JUnit parsers fail with "premature end of file").
		return xml.Header + "<testsuites/>\n"
	}
	return xml.Header + string(out) + "\n"
}
