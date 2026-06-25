package threagile

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/coverage"
	"github.com/threagile/threagile/pkg/gate"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/types"
)

func (what *Threagile) initGate() *Threagile {
	var policyFile string
	var baselineFile string
	var format string
	var outputFile string

	cmd := &cobra.Command{
		Use:   "gate",
		Short: "Evaluate a declarative policy against the model and fail CI on violations",
		Long: `Analyze the model, then evaluate a declarative policy.yaml as a CI quality gate.
The command exits non-zero (code 3) when any policy rule is violated, so it can
drive a pipeline directly.

Example policy.yaml:

  name: "Production security gate"
  max_severity_counts:
    critical: 0          # no still-at-risk Critical findings
    high: 2              # at most two High
  max_total_at_risk: 60
  require_tracking_at_or_above: elevated   # nothing Elevated+ may stay unchecked
  fail_on_expired_acceptance: true
  forbid_new_at_or_above: high             # needs --baseline: no new High+ vs baseline
  framework_coverage:
    - {framework: owasp_top10_2021, min_percent: 70}

Examples:
  # Fail the build if the policy is violated
  threagile gate --model threagile.yaml --policy policy.yaml

  # Block only NEW High+ findings introduced since an approved baseline
  threagile gate --model threagile.yaml --policy policy.yaml --baseline risks.json

  # Emit a Markdown summary to post as a PR comment
  threagile gate --model threagile.yaml --policy policy.yaml --format markdown --output gate.md`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)
			progressReporter := DefaultProgressReporter{Verbose: what.config.GetVerbose()}

			policy, err := gate.LoadPolicy(policyFile)
			if err != nil {
				return fmt.Errorf("gate: %w", err)
			}

			// The gate, not the analysis pass, owns the expired-acceptance
			// decision (via the policy's fail_on_expired_acceptance). Force the
			// analysis to ignore expiry so it doesn't hard-fail before the policy
			// is evaluated; we re-check expiry ourselves below to feed the policy.
			what.config.IgnoreExpiredRiskAcceptanceValue = true

			builtinRules := what.loadRiskRules(progressReporter)
			r, err := model.ReadAndAnalyzeModel(what.config, builtinRules, progressReporter)
			if err != nil {
				return fmt.Errorf("gate: failed to read and analyze model: %w", err)
			}
			parsedModel := r.ParsedModel

			in := gate.Input{Risks: parsedModel.GeneratedRisksBySyntheticId}

			// Re-check expiry in fail mode (ignore=false) so CheckAcceptanceExpiry
			// returns the descriptive error; the policy decides whether it fails.
			in.ExpiredAcceptanceErr = parsedModel.CheckAcceptanceExpiry(
				types.Date{Time: time.Now()}, false, silentReporter{})

			if baselineFile != "" {
				in.Baseline, err = loadBaseline(baselineFile)
				if err != nil {
					return fmt.Errorf("gate: %w", err)
				}
			}

			if frameworks := policy.ReferencedFrameworks(); len(frameworks) > 0 {
				// Compute coverage from the SAME ruleset used to analyze the model,
				// so the gate never claims coverage from rules that weren't run.
				in.CoveragePercents, err = computeCoveragePercents(builtinRules, frameworks)
				if err != nil {
					return fmt.Errorf("gate: %w", err)
				}
			}

			result := gate.Evaluate(policy, in)

			var rendered string
			switch strings.ToLower(format) {
			case "", "text":
				rendered = gate.FormatText(result)
			case "markdown", "md":
				rendered = gate.FormatMarkdown(result)
			case "json":
				jsonBytes, marshalErr := json.MarshalIndent(result, "", "  ")
				if marshalErr != nil {
					return fmt.Errorf("gate: marshal result: %w", marshalErr)
				}
				rendered = string(jsonBytes) + "\n"
			default:
				return fmt.Errorf("gate: unknown --format %q (want text, markdown, or json)", format)
			}

			if outputFile != "" {
				if writeErr := os.WriteFile(outputFile, []byte(rendered), 0600); writeErr != nil {
					return fmt.Errorf("gate: write %q: %w", outputFile, writeErr)
				}
			}
			fmt.Fprint(cmd.OutOrStdout(), rendered)

			if !result.Passed() {
				// Distinct exit code so CI can tell a gate failure from a usage error.
				return &exitCodeError{code: 3, msg: fmt.Sprintf("gate failed: %d policy violation(s)", len(result.Violations))}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&policyFile, "policy", "", "policy YAML file (required)")
	cmd.Flags().StringVar(&baselineFile, "baseline", "", "baseline risks.json to diff against (for forbid_new_at_or_above)")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text, markdown, or json")
	cmd.Flags().StringVar(&outputFile, "output", "", "also write the rendered report to this file")
	_ = cmd.MarkFlagRequired("policy")

	what.rootCmd.AddCommand(cmd)
	return what
}

// loadBaseline reads a risks.json (an array of risk objects) and returns, for
// every finding that was still at risk in the baseline, its severity keyed by
// lower-cased synthetic ID. Malformed entries (missing synthetic_id) are
// rejected so a truncated/hand-edited baseline fails loudly rather than
// degrading into spurious "new finding" gate failures.
func loadBaseline(path string) (map[string]types.RiskSeverity, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied baseline path
	if err != nil {
		return nil, fmt.Errorf("read baseline %q: %w", path, err)
	}
	var risks []struct {
		SyntheticId string `json:"synthetic_id"`
		Severity    string `json:"severity"`
		RiskStatus  string `json:"risk_status"`
	}
	if err := json.Unmarshal(data, &risks); err != nil {
		return nil, fmt.Errorf("parse baseline %q (expected risks.json array): %w", path, err)
	}
	baseline := make(map[string]types.RiskSeverity, len(risks))
	for i, r := range risks {
		if strings.TrimSpace(r.SyntheticId) == "" {
			return nil, fmt.Errorf("baseline %q: entry %d has an empty synthetic_id (corrupt risks.json?)", path, i)
		}
		severity, sevErr := types.ParseRiskSeverity(r.Severity)
		if sevErr != nil {
			return nil, fmt.Errorf("baseline %q: entry %q has invalid severity %q: %w", path, r.SyntheticId, r.Severity, sevErr)
		}
		// risk_status carries omitempty, so an unchecked finding (the zero value)
		// is absent from the JSON; treat the empty string as unchecked.
		status := types.Unchecked
		if strings.TrimSpace(r.RiskStatus) != "" {
			parsed, statusErr := types.ParseRiskStatus(r.RiskStatus)
			if statusErr != nil {
				return nil, fmt.Errorf("baseline %q: entry %q has invalid risk_status %q: %w", path, r.SyntheticId, r.RiskStatus, statusErr)
			}
			status = parsed
		}
		// Only findings that were at risk in the baseline form the comparison set;
		// already-mitigated baseline findings reappearing at risk must count as new.
		if status.IsStillAtRisk() {
			baseline[strings.ToLower(r.SyntheticId)] = severity
		}
	}
	return baseline, nil
}

// computeCoveragePercents computes the achieved control-coverage percent for
// each requested framework using the supplied ruleset (the same rules used to
// analyze the model), so the gate never reports coverage from rules it didn't run.
func computeCoveragePercents(rules types.RiskRules, frameworks []string) (map[string]float64, error) {
	var categories []*types.RiskCategory
	for _, rule := range rules {
		if cat := rule.Category(); cat != nil {
			categories = append(categories, cat)
		}
	}
	out := make(map[string]float64, len(frameworks))
	for _, framework := range frameworks {
		report, analyzeErr := coverage.Analyze(framework, categories)
		if analyzeErr != nil {
			return nil, analyzeErr
		}
		out[framework] = report.CoveragePercent()
	}
	return out, nil
}

// silentReporter discards progress output; gate decides what to surface.
type silentReporter struct{}

func (silentReporter) Info(...any)           {}
func (silentReporter) Infof(string, ...any)  {}
func (silentReporter) Warn(...any)           {}
func (silentReporter) Warnf(string, ...any)  {}
func (silentReporter) Error(...any)          {}
func (silentReporter) Errorf(string, ...any) {}
