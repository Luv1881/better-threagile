package profile_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/threagile/threagile/pkg/profile"
)

func TestDefault(t *testing.T) {
	p := profile.Default()
	if p.ConfidentialityWeight() != 1.0 {
		t.Errorf("want 1.0, got %.2f", p.ConfidentialityWeight())
	}
	if p.AvailabilityWeight() != 1.0 {
		t.Errorf("want 1.0, got %.2f", p.AvailabilityWeight())
	}
}

func TestLoad_BusinessDrivers(t *testing.T) {
	yaml := `
business_drivers:
  regulatory_pressure: high
  uptime_requirement: high
  reputational_sensitivity: medium
`
	path := filepath.Join(t.TempDir(), "profile.yaml")
	os.WriteFile(path, []byte(yaml), 0o644) //nolint:errcheck

	p, err := profile.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if p.ConfidentialityWeight() != 1.5 {
		t.Errorf("confidentiality: want 1.5, got %.2f", p.ConfidentialityWeight())
	}
	if p.AvailabilityWeight() != 2.0 {
		t.Errorf("availability: want 2.0, got %.2f", p.AvailabilityWeight())
	}
	if p.IntegrityWeight() != 1.3 {
		t.Errorf("integrity: want 1.3, got %.2f", p.IntegrityWeight())
	}
}

func TestLoad_ExplicitWeights(t *testing.T) {
	yaml := `
weights:
  confidentiality: 3.0
  integrity: 0.5
  availability: 1.8
`
	path := filepath.Join(t.TempDir(), "profile.yaml")
	os.WriteFile(path, []byte(yaml), 0o644) //nolint:errcheck

	p, err := profile.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if p.ConfidentialityWeight() != 3.0 {
		t.Errorf("confidentiality: want 3.0, got %.2f", p.ConfidentialityWeight())
	}
	if p.IntegrityWeight() != 0.5 {
		t.Errorf("integrity: want 0.5, got %.2f", p.IntegrityWeight())
	}
	if p.AvailabilityWeight() != 1.8 {
		t.Errorf("availability: want 1.8, got %.2f", p.AvailabilityWeight())
	}
}

func TestLoad_ClampExtremes(t *testing.T) {
	yaml := `
weights:
  confidentiality: 99.0
  integrity: -5.0
  availability: 0.0
`
	path := filepath.Join(t.TempDir(), "profile.yaml")
	os.WriteFile(path, []byte(yaml), 0o644) //nolint:errcheck

	p, err := profile.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if p.ConfidentialityWeight() > 5.0 {
		t.Errorf("should clamp to 5.0, got %.2f", p.ConfidentialityWeight())
	}
	if p.IntegrityWeight() < 0.1 {
		t.Errorf("should clamp to 0.1, got %.2f", p.IntegrityWeight())
	}
}

func TestWeightForSTRIDECategory(t *testing.T) {
	p := &profile.SeverityProfile{}
	p.Weights.Confidentiality = 1.5
	p.Weights.Integrity = 1.0
	p.Weights.Availability = 2.0

	tests := []struct {
		cat  string
		want float64
	}{
		{"spoofing", 1.5},
		{"tampering", 1.0},
		{"denial-of-service", 2.0},
		{"information-disclosure", 1.5},
		{"elevation-of-privilege", 2.0}, // max(1.5, 1.0, 2.0)
	}
	for _, tt := range tests {
		got := p.WeightForSTRIDECategory(tt.cat)
		if got != tt.want {
			t.Errorf("category %s: want %.1f, got %.1f", tt.cat, tt.want, got)
		}
	}
}

func TestNilProfile(t *testing.T) {
	var p *profile.SeverityProfile
	if p.ConfidentialityWeight() != 1.0 {
		t.Error("nil profile should return 1.0")
	}
	if p.WeightForSTRIDECategory("spoofing") != 1.0 {
		t.Error("nil profile should return 1.0 for any category")
	}
	if p.FormatSummary() == "" {
		t.Error("nil profile summary should not be empty")
	}
}
