// Package gate implements a declarative policy-as-code quality gate over the
// risks generated for a threat model. It turns a model analysis into a CI
// pass/fail decision driven by a small, reviewable policy.yaml — the same role
// linters and coverage gates play for code.
//
// The package is deliberately decoupled from the CLI and the analysis engine:
// Evaluate consumes a fully-assembled Input (current risks, an optional
// baseline, coverage percentages, and the acceptance-expiry result) so it stays
// pure and table-testable. The CLI layer (internal/threagile/gate.go) is
// responsible for producing that Input.
package gate

import (
	"fmt"
	"sort"

	"github.com/threagile/threagile/pkg/types"
)

// Policy is the declarative gate configuration loaded from policy.yaml.
//
// Every field is optional; an empty policy passes everything. Each populated
// field becomes one independently-evaluated rule, so teams can adopt the gate
// incrementally (start with "no new Critical", tighten over time).
type Policy struct {
	// Name is a human-readable label echoed in the gate report.
	Name string `yaml:"name,omitempty" json:"name,omitempty"`

	// MaxSeverityCounts caps the number of still-at-risk findings per severity.
	// Keys are severity names (low/medium/elevated/high/critical); the value is
	// the maximum allowed. A finding counts if its status is still at risk
	// (unchecked/in-discussion/accepted/in-progress) — mitigated and
	// false-positive findings never count against a cap.
	MaxSeverityCounts map[string]int `yaml:"max_severity_counts,omitempty" json:"max_severity_counts,omitempty"`

	// MaxTotalAtRisk caps the total number of still-at-risk findings across all
	// severities. nil means no overall cap.
	MaxTotalAtRisk *int `yaml:"max_total_at_risk,omitempty" json:"max_total_at_risk,omitempty"`

	// RequireTrackingAtOrAbove demands that every still-at-risk finding at or
	// above this severity carries a tracking decision (i.e. is not "unchecked").
	// This is the governance rule auditors ask for: nothing serious may sit
	// silently un-triaged. Empty disables the check.
	RequireTrackingAtOrAbove string `yaml:"require_tracking_at_or_above,omitempty" json:"require_tracking_at_or_above,omitempty"`

	// FailOnExpiredAcceptance fails the gate if any risk acceptance has passed
	// its accepted_until date (see Input.ExpiredAcceptanceErr).
	FailOnExpiredAcceptance bool `yaml:"fail_on_expired_acceptance,omitempty" json:"fail_on_expired_acceptance,omitempty"`

	// ForbidNewAtOrAbove fails the gate if any finding that is NOT present in the
	// baseline (Input.BaselineRiskIDs) is at or above this severity. This is the
	// "no new Critical/High in this PR" rule. Requires a baseline; if no baseline
	// is supplied the rule reports an error rather than silently passing.
	ForbidNewAtOrAbove string `yaml:"forbid_new_at_or_above,omitempty" json:"forbid_new_at_or_above,omitempty"`

	// FrameworkCoverage requires minimum control-coverage percentages for named
	// compliance frameworks.
	FrameworkCoverage []CoverageThreshold `yaml:"framework_coverage,omitempty" json:"framework_coverage,omitempty"`
}

// CoverageThreshold is a minimum control-coverage requirement for one framework.
type CoverageThreshold struct {
	Framework  string  `yaml:"framework" json:"framework"`
	MinPercent float64 `yaml:"min_percent" json:"min_percent"`
}

// Input is the fully-assembled evaluation context the CLI hands to Evaluate.
type Input struct {
	// Risks is the current analysis result keyed by lower-cased synthetic ID.
	Risks map[string]*types.Risk

	// Baseline maps the lower-cased synthetic ID of every finding that was
	// STILL AT RISK in the approved baseline to its baseline severity. nil means
	// "no baseline supplied". Storing severity (not just presence) lets
	// forbid_new_at_or_above catch severity escalations and reopened findings,
	// not only brand-new IDs.
	Baseline map[string]types.RiskSeverity

	// ExpiredAcceptanceErr is the (non-nil) result of Model.CheckAcceptanceExpiry
	// when one or more acceptances have expired; nil when none have.
	ExpiredAcceptanceErr error

	// CoveragePercents maps framework name -> achieved coverage percent (0–100)
	// for every framework referenced by the policy.
	CoveragePercents map[string]float64
}

// Violation is a single failed policy rule.
type Violation struct {
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

// Result is the outcome of evaluating a policy against an Input.
type Result struct {
	PolicyName       string         `json:"policy_name,omitempty"`
	Violations       []Violation    `json:"violations"`
	AtRiskTotal      int            `json:"at_risk_total"`
	AtRiskBySeverity map[string]int `json:"at_risk_by_severity"`
}

// Passed reports whether the gate passes (no violations).
func (r *Result) Passed() bool { return len(r.Violations) == 0 }

// Evaluate applies the policy to the input and returns the result. It never
// returns an error: a misconfigured rule (e.g. an unknown severity name, or a
// baseline-dependent rule with no baseline) is reported as a violation so CI
// fails loudly rather than silently passing.
func Evaluate(policy *Policy, in Input) *Result {
	result := &Result{
		PolicyName:       policy.Name,
		AtRiskBySeverity: map[string]int{},
	}

	atRisk := stillAtRiskSorted(in.Risks)
	bySeverity := map[types.RiskSeverity]int{}
	for _, r := range atRisk {
		bySeverity[r.Severity]++
	}
	result.AtRiskTotal = len(atRisk)
	for sev, n := range bySeverity {
		result.AtRiskBySeverity[sev.String()] = n
	}

	evalMaxSeverityCounts(policy, bySeverity, result)
	evalMaxTotal(policy, len(atRisk), result)
	evalRequireTracking(policy, in.Risks, result)
	evalExpiredAcceptance(policy, in.ExpiredAcceptanceErr, result)
	evalForbidNew(policy, in, result)
	evalFrameworkCoverage(policy, in.CoveragePercents, result)

	return result
}

func evalMaxSeverityCounts(policy *Policy, bySeverity map[types.RiskSeverity]int, result *Result) {
	// Normalize keys to their canonical (lower-case) severity name so a policy
	// written as "Critical: 0" is honoured, not silently ignored. Validation
	// (below) is case-insensitive via ParseRiskSeverity, so the lookup must be too.
	normalized := make(map[string]int, len(policy.MaxSeverityCounts))
	for key, val := range policy.MaxSeverityCounts {
		if sev, err := types.ParseRiskSeverity(key); err == nil {
			normalized[sev.String()] = val
		}
	}
	// Deterministic order: iterate the severities, not the map.
	for _, sev := range []types.RiskSeverity{
		types.CriticalSeverity, types.HighSeverity, types.ElevatedSeverity,
		types.MediumSeverity, types.LowSeverity,
	} {
		max, ok := normalized[sev.String()]
		if !ok {
			continue
		}
		if got := bySeverity[sev]; got > max {
			result.Violations = append(result.Violations, Violation{
				Rule:    "max_severity_counts",
				Message: fmt.Sprintf("%d %s finding(s) still at risk, policy allows at most %d", got, sev.String(), max),
			})
		}
	}
	// Surface any unknown severity keys as a configuration violation.
	for key := range policy.MaxSeverityCounts {
		if _, err := types.ParseRiskSeverity(key); err != nil {
			result.Violations = append(result.Violations, Violation{
				Rule:    "max_severity_counts",
				Message: fmt.Sprintf("unknown severity %q in max_severity_counts", key),
			})
		}
	}
}

func evalMaxTotal(policy *Policy, total int, result *Result) {
	if policy.MaxTotalAtRisk == nil {
		return
	}
	if total > *policy.MaxTotalAtRisk {
		result.Violations = append(result.Violations, Violation{
			Rule:    "max_total_at_risk",
			Message: fmt.Sprintf("%d findings still at risk, policy allows at most %d", total, *policy.MaxTotalAtRisk),
		})
	}
}

func evalRequireTracking(policy *Policy, risks map[string]*types.Risk, result *Result) {
	if policy.RequireTrackingAtOrAbove == "" {
		return
	}
	threshold, err := types.ParseRiskSeverity(policy.RequireTrackingAtOrAbove)
	if err != nil {
		result.Violations = append(result.Violations, Violation{
			Rule:    "require_tracking_at_or_above",
			Message: fmt.Sprintf("unknown severity %q", policy.RequireTrackingAtOrAbove),
		})
		return
	}
	var untracked []string
	for _, r := range risks {
		if r.Severity >= threshold && r.RiskStatus == types.Unchecked {
			untracked = append(untracked, r.SyntheticId)
		}
	}
	if len(untracked) > 0 {
		sort.Strings(untracked)
		result.Violations = append(result.Violations, Violation{
			Rule: "require_tracking_at_or_above",
			Message: fmt.Sprintf("%d finding(s) at or above %s have no tracking decision (status unchecked): %v",
				len(untracked), threshold.String(), untracked),
		})
	}
}

func evalExpiredAcceptance(policy *Policy, expiredErr error, result *Result) {
	if !policy.FailOnExpiredAcceptance || expiredErr == nil {
		return
	}
	result.Violations = append(result.Violations, Violation{
		Rule:    "fail_on_expired_acceptance",
		Message: expiredErr.Error(),
	})
}

func evalForbidNew(policy *Policy, in Input, result *Result) {
	if policy.ForbidNewAtOrAbove == "" {
		return
	}
	threshold, err := types.ParseRiskSeverity(policy.ForbidNewAtOrAbove)
	if err != nil {
		result.Violations = append(result.Violations, Violation{
			Rule:    "forbid_new_at_or_above",
			Message: fmt.Sprintf("unknown severity %q", policy.ForbidNewAtOrAbove),
		})
		return
	}
	if in.Baseline == nil {
		result.Violations = append(result.Violations, Violation{
			Rule:    "forbid_new_at_or_above",
			Message: "rule requires a baseline (--baseline) but none was supplied",
		})
		return
	}
	var newOnes []string
	for id, r := range in.Risks {
		// Only currently-at-risk findings at or above the threshold can violate;
		// a new finding that is already mitigated/false-positive is not a problem.
		if !r.RiskStatus.IsStillAtRisk() || r.Severity < threshold {
			continue
		}
		// A finding is "new at or above threshold" unless the baseline already had
		// it at risk at or above the same threshold. This catches brand-new IDs,
		// severity escalations (was medium, now high), and reopened findings (was
		// mitigated, now at risk again — so absent from the at-risk baseline).
		baseSev, inBaseline := in.Baseline[id]
		if !inBaseline || baseSev < threshold {
			newOnes = append(newOnes, r.SyntheticId)
		}
	}
	if len(newOnes) > 0 {
		sort.Strings(newOnes)
		result.Violations = append(result.Violations, Violation{
			Rule: "forbid_new_at_or_above",
			Message: fmt.Sprintf("%d new/escalated finding(s) at or above %s vs baseline: %v",
				len(newOnes), threshold.String(), newOnes),
		})
	}
}

func evalFrameworkCoverage(policy *Policy, coverage map[string]float64, result *Result) {
	for _, threshold := range policy.FrameworkCoverage {
		got, ok := coverage[threshold.Framework]
		if !ok {
			result.Violations = append(result.Violations, Violation{
				Rule:    "framework_coverage",
				Message: fmt.Sprintf("coverage for framework %q was not computed", threshold.Framework),
			})
			continue
		}
		if got < threshold.MinPercent {
			result.Violations = append(result.Violations, Violation{
				Rule: "framework_coverage",
				Message: fmt.Sprintf("%s coverage is %.0f%%, policy requires at least %.0f%%",
					threshold.Framework, got, threshold.MinPercent),
			})
		}
	}
}

// stillAtRiskSorted returns the still-at-risk findings sorted by synthetic ID
// for deterministic counting/output.
func stillAtRiskSorted(risks map[string]*types.Risk) []*types.Risk {
	var out []*types.Risk
	for _, r := range risks {
		if r.RiskStatus.IsStillAtRisk() {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SyntheticId < out[j].SyntheticId })
	return out
}
