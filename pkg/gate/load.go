package gate

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadPolicy reads and parses a policy.yaml file. Unknown keys are rejected so
// typos in a policy (e.g. "max_severity_count" without the trailing s) fail
// loudly instead of being silently ignored — a silently-ignored gate rule is
// worse than no gate at all.
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is an operator-supplied policy file
	if err != nil {
		return nil, fmt.Errorf("read policy %q: %w", path, err)
	}
	var policy Policy
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&policy); err != nil {
		return nil, fmt.Errorf("parse policy %q: %w", path, err)
	}
	return &policy, nil
}

// ReferencedFrameworks returns the set of compliance frameworks the policy
// needs coverage data for, so the CLI only computes what is required.
func (p *Policy) ReferencedFrameworks() []string {
	var out []string
	for _, t := range p.FrameworkCoverage {
		out = append(out, t.Framework)
	}
	return out
}
